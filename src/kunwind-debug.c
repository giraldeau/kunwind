#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/errno.h>

#define PROC_NAME "kunwind_debug"

static ssize_t device_read(struct file *fp, char __user *buf, size_t size, loff_t *off)
{
	static const char *str = "Bonjour.";
	printk(KERN_INFO "%s %p %ld\n", str, buf, size);
	if (!size)
		return 0;
	size = max(size, strlen(str));
	if (copy_to_user(buf, str, size)) {
		return -EFAULT;
	}
	return size;
}

static struct file_operations fops = {
	.read = device_read,
};

static struct proc_dir_entry *proc_entry;

static int __init kunwind_debug_init(void)
{
	printk(KERN_INFO "kunwind_debug init\n");
	proc_entry = proc_create(PROC_NAME, 0666, NULL, &fops);
	printk("%p\n", proc_entry);
	return 0;
}

module_init(kunwind_debug_init);

static void __exit kunwind_debug_exit(void)
{
	printk(KERN_INFO "kunwind_debug exit\n");
}

module_exit(kunwind_debug_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Jean-Alexandre Barszcz <jalex_b@hotmail.com>");
MODULE_DESCRIPTION("Kernel Unwind Debugging");

