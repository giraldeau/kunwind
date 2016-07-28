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
	int compat :1;
};

struct kunwind_stp_module {
	struct _stp_module stp_mod;
	struct list_head list;
	void *base;
	unsigned long vma_start;
	struct page **pages;
	int npages;
};

static int complete_load_info(struct load_info *linfo,
		struct kunwind_stp_module *mod,
		struct kunwind_proc_modules *proc)
{
	bool incomplete = false;

	if (!linfo->eh_frame_hdr_addr || !linfo->eh_frame_hdr_size) {
		// Do the equivalent of dl_iterate_phdr using the Ehdr
		// see http://stackoverflow.com/a/38618657/2041995
		// Except we already have the executable vma

		incomplete = true;
	}

	if (!linfo->eh_frame_addr || !linfo->eh_frame_size || incomplete) {
		u8 *eh, *hdr, *ptr;
		const u8 *pos;
		unsigned long eh_addr, eh_len, hdr_addr, hdr_len, cie_fde_size = 0;

		// Use the .eh_frame_hdr pointer to find the .eh_frame section
		hdr = mod->stp_mod.unwind_hdr;
		hdr_addr = mod->stp_mod.unwind_hdr_addr;
		hdr_len = mod->stp_mod.unwind_hdr_len;

		// FIXME -1 tablesize might not right in following call
		pos = hdr + 4;
		eh_addr = read_ptr_sect(&pos, hdr + hdr_len, hdr[1], mod->vma_start,
				hdr_addr, 1, proc->compat, -1);
		if ((hdr[1] & DW_EH_PE_ADJUST) == DW_EH_PE_pcrel)
			eh_addr = eh_addr - (unsigned long)hdr + hdr_addr;
		eh = (void *)(eh_addr - mod->vma_start + mod->base);
		ptr = eh;
		do {
			cie_fde_size = *((u32 *) ptr);
			ptr += 4;
			if (cie_fde_size == 0xffffffff) {
				cie_fde_size = *((u64 *) ptr);
				ptr += 8;
			}
			ptr += cie_fde_size;
		} while (cie_fde_size);
		eh_len = (unsigned long) ptr - (unsigned long) eh;

		mod->stp_mod.eh_frame_addr = linfo->eh_frame_addr = eh_addr;
		mod->stp_mod.eh_frame_len = linfo->eh_frame_size = eh_len;
		mod->stp_mod.eh_frame = eh;
	}

	return 0;
}

static int init_kunwind_stp_module(struct task_struct *task,
		struct load_info *linfo,
		struct kunwind_stp_module *mod,
		struct kunwind_proc_modules *proc)
{
	void *base;
	int res;
	unsigned long npages;
	struct page **pages;
	struct vm_area_struct *vma;
	unsigned long test;

	// Get vma for this module
	// (executable phdr with eh_frame and eh_frame_hdr section)
	vma = find_vma(task->mm, linfo->eh_frame_hdr_addr);

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
	printk("vmap kernel addr: %p\n", base);

	// bookkeeping info
	mod->base = base;
	mod->vma_start = vma->vm_start;
	mod->pages = pages;
	mod->npages = npages;
	// eh_frame_hdr info
	mod->stp_mod.unwind_hdr_addr = linfo->eh_frame_hdr_addr;
	mod->stp_mod.unwind_hdr_len = linfo->eh_frame_hdr_size;
	mod->stp_mod.unwind_hdr = linfo->eh_frame_hdr_addr - mod->vma_start + mod->base;
	// eh_frame info
	mod->stp_mod.eh_frame_addr = linfo->eh_frame_addr;
	mod->stp_mod.eh_frame_len = linfo->eh_frame_size;
	mod->stp_mod.eh_frame = linfo->eh_frame_addr - mod->vma_start + mod->base;

	res = complete_load_info(linfo, mod, proc);
	if (res) return res;

	printk("Eh frame hdr addr = %#lx, len = %#lx\n", linfo->eh_frame_addr, linfo->eh_frame_size);

	// debug
	printk("npages %ld, flags %lx, prot %lx\n", npages, vma->vm_flags, vma->vm_page_prot);
	res = get_user(test, (unsigned long *)linfo->eh_frame_hdr_addr);
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
	printk("vunmap kernel addr: %p\n", mod->base);
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
	printk("Starting to release file\n");
	int err = release_unwind_info(file->private_data);
	file->private_data = NULL;
	return err;
}

static long kunwind_proc_info_ioctl(struct file *file,
		const struct proc_info __user *upinfo)
{
	struct kunwind_proc_modules *mods = file->private_data;
	struct proc_info *pinfo;
	int i, err;
	u32 size;

	if (get_user(size, (typeof(size)*) upinfo))
		return -EFAULT;

	pinfo = kmalloc(size, GFP_KERNEL);
	if (!pinfo)
		return -ENOMEM;

	if (copy_from_user(pinfo, upinfo, size)) {
		err = -EFAULT;
		goto KUNWIND_PROC_INFO_IOCTL_ERR;
	}

	for (i = 0; i < pinfo->nr_load_segments; ++i) {
		struct load_info *linfo = &pinfo->load_segments[i];
		struct kunwind_stp_module *mod =
				kmalloc(sizeof(struct kunwind_stp_module), GFP_KERNEL);
		err = init_kunwind_stp_module(current, linfo, mod, mods);
		if (err) {
			kfree(mod); // Free the module not added to the list
			goto KUNWIND_PROC_INFO_IOCTL_ERR;
		}
		list_add_tail(&(mod->list), mods->stp_modules);
	}

	kfree(pinfo);
	return 0;

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
	u32 capacity, size = 0;

	if (get_user(capacity, (typeof(capacity)*) uback))
		return -EFAULT;

	back = kmalloc(capacity, GFP_KERNEL);
	if (!back)
		return -ENOMEM;

	back->capacity = capacity;

	while (size < capacity) {
	// TODO unwind() iteratively until error, end of stack, or full cap
		++size;
	}
	back->size = size;

	if (copy_to_user(uback, back, size)) {
		err = -EFAULT;
		goto KUNWIND_UNWIND_IOCTL_ERR;
	}

	kfree(back);
	return 0;

KUNWIND_UNWIND_IOCTL_ERR:
	kfree(back);
	return err;
}

long kunwind_debug_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	printk("file=%p cmd=%x arg=%lx\n", file, cmd, arg);

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
