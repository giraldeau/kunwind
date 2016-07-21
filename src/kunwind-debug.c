#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <proc_info.h>
#include <kunwind.h>

#include "kunwind-bug.h"
#include "unwind/unwind.h"

#define PROC_FILENAME "kunwind_debug"

struct kunwind_proc_modules {
	struct list_head *stp_modules;
};

struct kunwind_stp_module {
	struct _stp_module stp_mod;
	struct list_head list;
	void *base;
	unsigned long vma_start;
	struct page **pages;
	int npages;
};

static int init_kunwind_stp_module(struct task_struct *task,
		struct eh_frame_info *einfo,
		struct kunwind_stp_module *mod)
{
	void *base;//, *hdr, *eh;
	int res;
	unsigned long npages;
	struct page **pages;
	struct vm_area_struct *vma;
	unsigned long test;

	// Get vma for this module
	// (executable phdr with eh_frame and eh_frame_hdr section)
	vma = find_vma(task->mm, einfo->start);

	// Get the vma pages
	npages = vma_pages(vma);
	pages = kmalloc(sizeof(struct page *) * npages, GFP_KERNEL);
	if (!pages)
		return -ENOMEM;
	res = __get_user_pages_unlocked(task, task->mm, vma->vm_start,
			npages, 0, 0, pages, FOLL_REMOTE | FOLL_TOUCH);
	if (res < 0)
		return res;
	npages = res;

	// vmap the pages so that we can access eh_frame directly
	base = vmap(pages, npages, vma->vm_flags, vma->vm_page_prot);

	mod->base = base;
	mod->vma_start = vma->vm_start;
	mod->pages = pages;
	mod->npages = npages;
	mod->stp_mod.unwind_hdr_addr = einfo->start;
	mod->stp_mod.unwind_hdr_len = einfo->size;
	mod->stp_mod.unwind_hdr = einfo->start - mod->vma_start + mod->base;

	// debug
	printk("npages %ld, flags %lx, prot %lx\n", npages, vma->vm_flags, vma->vm_page_prot);
	res = get_user(test, (unsigned long *)einfo->start);
	if (res < 0) return res;
	if (test != *((unsigned long *) mod->stp_mod.unwind_hdr))
		KUNWIND_BUGM("Bad eh_frame virtual kernel address.");
	else
		printk("SUCCESS!\n");

	return 0;
}

static void close_kunwind_stp_module(struct kunwind_stp_module *mod)
{
	int i;
	vunmap(mod->base);
	mod->base = NULL;
	for (i = 0; i < mod->npages; ++i) {
		put_page(mod->pages[i]);
	}
	kfree(mod->pages);
	mod->npages = 0;
	mod->pages = NULL;
	mod->vma_start = 0;
}

static int refresh_unwind_info(struct kunwind_proc_modules **modsp)
{
	struct kunwind_proc_modules *mods;
	if (!modsp)
		return -EINVAL;
	if (!(mods = *modsp)){
		mods = *modsp = kmalloc(sizeof(struct kunwind_proc_modules), GFP_KERNEL);
		INIT_LIST_HEAD(mods->stp_modules);
	}

	// TODO

	return 0;
}

static int release_unwind_info(struct kunwind_proc_modules *mods)
{
	struct kunwind_stp_module *mod, *other;
	list_for_each_entry_safe(mod, other, mods->stp_modules, list) {
		close_kunwind_stp_module(mod);
		kfree(mod);
		list_del(&(mod->list));
	}
	kfree(mods);
	return 0;
}

static int kunwind_debug_open(struct inode *inode, struct file *file)
{
	int err;
	file->private_data = NULL;
	err = refresh_unwind_info((struct kunwind_proc_modules **)&(file->private_data));
	return err;
}

static int kunwind_debug_release(struct inode *inode, struct file *file)
{
	int err = release_unwind_info(file->private_data);
	file->private_data = NULL;
	return err;
}

static ssize_t kunwind_debug_write(struct file *file, const char __user *buf,
				   size_t size, loff_t *off)
{
	// THIS IS A TEMPORARY FUNCTION THAT TAKES THE UNWIND INFO
	// FROM USERSPACE BUT WE SHOULD FIND ALL PROCESS INFO FROM THE
	// IOCTL FILE OP
	struct kunwind_proc_modules *mods = file->private_data;
	struct proc_info *pinfo = kmalloc(size, GFP_KERNEL);
	int i, err;

	if (!pinfo)
		return -ENOMEM;

	if (copy_from_user(pinfo, buf, size)) {
		err = -EFAULT;
		goto KUNWIND_DEBUG_WRITE_ERR;
	}

	for (i = 0; i < pinfo->nr_eh_frames; ++i) {
		struct eh_frame_info *einfo = &pinfo->eh_frames[i];
		struct kunwind_stp_module *mod =
				kmalloc(sizeof(struct kunwind_stp_module), GFP_KERNEL);

		err = init_kunwind_stp_module(current, einfo, mod);
		if (err) {
			kfree(mod); // Free the module not added to the list
			goto KUNWIND_DEBUG_WRITE_ERR;
		}
		list_add_tail(&(mod->list), mods->stp_modules);
	}

	kfree(pinfo);
	return size;

KUNWIND_DEBUG_WRITE_ERR:
	kfree(pinfo);
	return err;
}

long kunwind_debug_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct kunwind_debug_info info;
	void __user *uinfo = (void *) arg;

	if (cmd != KUNWIND_DEBUG_IOCTL)
		return -ENOIOCTLCMD;

	printk("file=%p cmd=%x arg=%lx\n", file, cmd, arg);

	if (copy_from_user(&info, uinfo, sizeof(struct kunwind_debug_info)))
		return -EFAULT;

	info.y = info.x;

	if (copy_to_user(uinfo, &info, sizeof(struct kunwind_debug_info)))
		return -EFAULT;

	return 0;
}

static struct file_operations fops = {
	.open = kunwind_debug_open,
	.release = kunwind_debug_release,
	.write = kunwind_debug_write,
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
