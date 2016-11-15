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

#include <proc_info.h>
#include <kunwind.h>

#include "debug.h"
#include "modules.h"

static const u32 entries_limit = 128;
#define PROC_FILENAME "kunwind_debug"

static int kunwind_debug_open(struct inode *inode, struct file *file)
{
	int ret;
	int compat;
	struct kunwind_proc_modules *mods;

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

	file->private_data = mods;
	return ret;
}

static int kunwind_debug_release(struct inode *inode, struct file *file)
{
	int err = release_unwind_info(file->private_data);
	file->private_data = NULL;
	return err;
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
