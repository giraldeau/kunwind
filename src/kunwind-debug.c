#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/hashtable.h>
#include <linux/stacktrace.h>

#include <proc_info.h>
#include <kunwind.h>

#include "debug.h"
#include "modules.h"

static const u32 entries_limit = 128;
#define PROC_FILENAME "kunwind_debug"

DEFINE_HASHTABLE(kunw_map, 3);

struct kunw_map_key {
	pid_t tgid;
} __attribute__((__packed__));

struct kunw_map_val {
	pid_t tgid;
	struct kunwind_proc_modules *mods;
	struct hlist_node hlist;
	struct rcu_head rcu;
};

static void kunwind_map_free_rcu(struct rcu_head *rcu)
{
	struct kunw_map_val *val = container_of(rcu, struct kunw_map_val, rcu);
	release_unwind_info(val->mods);
}

static
struct kunw_map_val* kunwind_process_find(struct kunw_map_key *key, u32 hash)
{
        struct kunw_map_val *val;

        hash_for_each_possible_rcu(kunw_map, val, hlist, hash) {
                if (key->tgid == val->tgid) {
                        return val;
                }
        }
        return NULL;
}

void kunwind_process_register(struct kunwind_proc_modules *mods, pid_t tgid)
{
	u32 hash;
	struct kunw_map_key key;
	struct kunw_map_val *val;

	key.tgid = tgid;
	hash = jhash(&key, sizeof(key), 0);

	/*
	 * FIXME: two threads could theoretically register at the same time.
	 * Registration should be protected with a lock.
	 */
	rcu_read_lock();
	val = kunwind_process_find(&key, hash);
	if (val) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();
	val = kzalloc(sizeof(struct kunw_map_val), GFP_KERNEL);
	val->tgid = tgid;
	val->mods = mods;
	hash_add_rcu(kunw_map, &val->hlist, hash);
}

void kunwind_process_unregister(pid_t tgid)
{
	u32 hash;
	struct kunw_map_key key;
	struct kunw_map_val *val;

	key.tgid = tgid;
	hash = jhash(&key, sizeof(key), 0);

	rcu_read_lock();
	val = kunwind_process_find(&key, hash);
	if (val) {
		hash_del_rcu(&val->hlist);
		call_rcu(&val->rcu, kunwind_map_free_rcu);
	}
	rcu_read_unlock();
}


static int kunwind_debug_open(struct inode *inode, struct file *file)
{
	int ret;
	int compat;
	int hash;
	struct kunwind_proc_modules *mods;
	struct kunw_map_key key;

	key.tgid = current->pid;
	hash = jhash(&key, sizeof(key), 0);
	if (kunwind_process_find(&key, hash)) {
		return -EBUSY;
	}

	mods = kmalloc(sizeof(*mods), GFP_KERNEL);
	if (!mods)
		return -ENOMEM;

	compat = _stp_is_compat_task();
	ret = init_proc_unwind_info(mods, compat);
	if (ret) {
		kfree(mods);
		return ret;
	}
	hash_init(mods->unw_cache);

	unw_cache_test(mods);

	/* register process */
	kunwind_process_register(mods, current->pid);

	/* shortcut: keep mods pointer in the file */
	file->private_data = mods;
	return ret;
}

static int kunwind_debug_release(struct inode *inode, struct file *file)
{
	kunwind_process_unregister(current->pid);
	file->private_data = NULL;
	return 0;
}


static long kunwind_init_ioctl(struct file *file)
{
	struct kunwind_proc_modules *mods = file->private_data;

	return init_modules_from_task(current, mods);
}


static long kunwind_proc_info_ioctl(struct file *file,
		const struct proc_info __user *upinfo)
{
	struct kunwind_proc_modules *mods = file->private_data;
	struct proc_info *pinfo;
	int res, err;
	u32 size;

	// This is a small hack to go through the slowpath for the
	// unwinding ioctls that need all the registers, but it
	// probably adds unnecessary overhead. lttng has
	// TIF_KERNEL_TRACE, see
	// http://lkml.iu.edu/hypermail/linux/kernel/0903.1/03592.html
	current_thread_info()->flags |= _TIF_SYSCALL_AUDIT;

	if (!upinfo)
		return kunwind_init_ioctl(file);

	if (get_user(size, (typeof(size)*) upinfo))
		return -EFAULT;

	pinfo = kmalloc(size, GFP_KERNEL);
	if (!pinfo)
		return -ENOMEM;

	if (copy_from_user(pinfo, upinfo, size)) {
		err = -EFAULT;
		goto KUNWIND_PROC_INFO_IOCTL_ERR;
	}

	res = init_modules_from_proc_info(pinfo, current, mods);
	kfree(pinfo);
	return res;

KUNWIND_PROC_INFO_IOCTL_ERR:
	kfree(pinfo);
	return err;
}

static long kunwind_backtrace_ioctl(struct file *file,
		struct kunwind_backtrace __user *uback)
{
	struct kunwind_proc_modules *mods = file->private_data;
	struct kunwind_backtrace bt;
	int ret;

	dbug_unwind(1, "kunwind_backtrace_ioctl entry\n");

	memset(&bt, 0, sizeof(bt));
	if (get_user(bt.max_entries, &uback->max_entries))
		return -EFAULT;

	dbug_unwind(1, "max_entries=%d\n", bt.max_entries);
	if (bt.max_entries == 0)
		return -EINVAL;

	/* Clamp memory usage */
	bt.max_entries = min(bt.max_entries, entries_limit);
	bt.entries = kmalloc(bt.max_entries * sizeof(*bt.entries), GFP_KERNEL);
	if (!bt.entries)
		return -ENOMEM;

	ret = do_current_unwind(&bt, mods);
	if (ret) {
		dbug_unwind(1, "kunwind_backtrace unwind failed %d\n", ret);
		ret = -EFAULT;
		goto out;
	}

	if (put_user(bt.nr_entries, &uback->nr_entries)) {
		ret = -EFAULT;
		goto out;
	}

	if (copy_to_user(uback->entries, bt.entries,
			bt.nr_entries * sizeof(*bt.entries))) {
		ret = -EFAULT;
		goto out;
	}

out:
	kfree(bt.entries);
	dbug_unwind(1, "kunwind_backtrace_ioctl end %d\n", ret);
	return ret;
}

void save_stack_trace_kunwind(struct stack_trace *trace)
{
	int ret;
	int hash;
	struct kunw_map_key key;
	struct kunw_map_val *val;
	struct kunwind_backtrace bt = {
		.max_entries = trace->max_entries,
		.nr_entries = trace->nr_entries,
		.entries = (u64 *) trace->entries,
	};

	key.tgid = current->pid;
	hash = jhash(&key, sizeof(key), 0);

	rcu_read_lock();
	val = kunwind_process_find(&key, hash);
	if (!val) {
		rcu_read_unlock();
		dbug_unwind(1, "process not registered pid=%d\n", key.tgid);
		return;
	}
	ret = do_current_unwind(&bt, val->mods);
	rcu_read_unlock();
	trace->nr_entries = bt.nr_entries;
}

long kunwind_debug_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	dbug_unwind(1, "ioctl file=%p cmd=%x arg=%lx\n", file, cmd, arg);

	switch (cmd) {
	case KUNWIND_PROC_INFO_IOCTL:
		dbug_unwind(1, "kunwind init process\n");
		return kunwind_proc_info_ioctl(file,
		                (struct proc_info __user *) arg);
	case KUNWIND_UNWIND_IOCTL:
		dbug_unwind(1, "kunwind backtrace\n");
		return kunwind_backtrace_ioctl(file,
		                (struct kunwind_backtrace __user *) arg);
	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}

static struct file_operations fops = {
	.open = kunwind_debug_open,
	.release = kunwind_debug_release,
	.unlocked_ioctl = kunwind_debug_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = kunwind_debug_ioctl,
#endif
};

static struct proc_dir_entry *proc_entry;

static int __init kunwind_debug_init(void)
{
	printk(KERN_INFO "kunwind_debug init\n");
	proc_entry = proc_create(PROC_FILENAME, 0666, NULL, &fops);
	return 0;
}

module_init(kunwind_debug_init);

static void __exit kunwind_debug_exit(void)
{
	printk(KERN_INFO "kunwind_debug exit\n");
	proc_remove(proc_entry);
}

module_exit(kunwind_debug_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Jean-Alexandre Barszcz <jalex_b@hotmail.com>");
MODULE_DESCRIPTION("Kernel Unwind Debugging");
