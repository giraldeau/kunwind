#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <proc_info.h>
#include <kunwind.h>

#include "debug.h"
#include "modules.h"

#define PROC_FILENAME "kunwind_debug"

static int kunwind_debug_open(struct inode *inode, struct file *file)
{
	int err, compat = 0;
	struct kunwind_proc_modules *mods =
			kmalloc(sizeof(struct kunwind_proc_modules), GFP_KERNEL);
	if (!mods)
		return -EFAULT;

	compat = _stp_is_compat_task();
	err = init_proc_unwind_info(mods, compat);
	if (err) {
		kfree(mods);
	} else {
		file->private_data = mods;
	}
	return err;
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

	res = init_modules_from_proc_info(pinfo, mods);
	kfree(pinfo);
	return res;

KUNWIND_PROC_INFO_IOCTL_ERR:
	kfree(pinfo);
	return err;
}

static long kunwind_unwind_ioctl(struct file *file,
		struct kunwind_backtrace __user *uback)
{
	struct kunwind_proc_modules *mods = file->private_data;
	struct kunwind_backtrace *back;
	int err;
	u32 capacity, struct_size;

	dbug_unwind(1, "Starting kunwind unwinding\n");

	if (get_user(capacity, (typeof(capacity)*) uback))
		return -EFAULT;

	struct_size = sizeof(struct kunwind_backtrace) +
		capacity * sizeof(__u64);
	back = kmalloc(struct_size, GFP_KERNEL);
	if (!back)
		return -ENOMEM;

	back->capacity = capacity;
	err = do_current_unwind(back, mods);
	if (err)
		printk("Error happened while unwinding\n");

	if (copy_to_user(uback, back, struct_size)) {
		err = -EFAULT;
		goto KUNWIND_UNWIND_IOCTL_ERR;
	}

	dbug_unwind(1, "Ending kunwind unwinding\n");

	kfree(back);
	return 0;

KUNWIND_UNWIND_IOCTL_ERR:
	kfree(back);
	return err;
}

long kunwind_debug_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	dbug_unwind(1, "ioctl file=%p cmd=%x arg=%lx\n", file, cmd, arg);

	switch (cmd) {
	case KUNWIND_PROC_INFO_IOCTL:
		return kunwind_proc_info_ioctl(file,
		                (struct proc_info __user *) arg);
	case KUNWIND_UNWIND_IOCTL:
		return kunwind_unwind_ioctl(file,
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
