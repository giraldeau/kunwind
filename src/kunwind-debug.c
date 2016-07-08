#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/errno.h>

#include <proc_info.h>

#include "kunwind-eh-frame.h"
#include "unwind/unwind.h"

#define PROC_FILENAME "kunwind_debug"

static proc_info_t *pinfo = NULL;

static ssize_t kunwind_debug_write(struct file *fp, const char __user *buf,
				   size_t size, loff_t *off)
{
	pinfo = krealloc(pinfo, size, GFP_KERNEL);
	if (!pinfo)
		return -ENOMEM;

	if (copy_from_user(pinfo, buf, size)) {
		kfree(pinfo);
		pinfo = NULL;
		return -EFAULT;
	}

	printk("pinfo is %p\n", pinfo);

	int i;
	for (i = 0; i < pinfo->nr_eh_frames; ++i) {
		struct eh_frame_info *einfo = &pinfo->eh_frames[i];
		struct eh_frame_hdr hdr;
		int ret = parse_eh_frame_hdr_section(einfo->start, &hdr);
	}

	return size;
}

static ssize_t kunwind_debug_read(struct file *fp, char __user *buf,
				  size_t size, loff_t *off)
{
	// Unwind userspace using last given pinfo

	return -ENOSYS; // Not implemented yet
}

static long kunwind_debug_ioctl(struct file *fp,
		unsigned int cmd, unsigned long arg)
{

	int ret = unwind(NULL, 1);
	(void) ret;
	return -ENOSYS;
}

static struct file_operations fops = {
	.write = kunwind_debug_write,
	.read = kunwind_debug_read,
	.unlocked_ioctl = kunwind_debug_ioctl,
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
