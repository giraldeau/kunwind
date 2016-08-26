#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <proc_info.h>
#include <kunwind.h>

#include "kunwind-debug.h"
#include "kunwind-bug.h"
#include "unwind/unwind.h"
#include "debug.h"
#include "vma_file_path.h"
#include "iterate_phdr.h"

#define PROC_FILENAME "kunwind_debug"


static int fill_eh_frame_info(struct kunwind_stp_module *mod,
				struct kunwind_proc_modules *proc)
{
	u8 *eh, *hdr;
	unsigned long eh_addr, eh_len, hdr_addr, hdr_len;
	int err;

	// Use the .eh_frame_hdr pointer to find the .eh_frame section
	hdr = mod->stp_mod.unwind_hdr;
	hdr_addr = mod->stp_mod.unwind_hdr_addr;
	hdr_len = mod->stp_mod.unwind_hdr_len;

	err =  eh_frame_from_hdr(mod->base, mod->vma_start,
				 mod->vma_end, proc->compat,
				 hdr, hdr_addr, hdr_len,
				 &eh, &eh_addr, &eh_len);

	if (err) return err;

	mod->stp_mod.eh_frame_addr = eh_addr;
	mod->stp_mod.eh_frame_len = eh_len;
	mod->stp_mod.eh_frame = eh;

	return 0;
}

static int fill_mod_path(struct kunwind_stp_module *mod)
{
	char *path, *buf = kmalloc(LINFO_PATHLEN, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	path = vma_file_path(mod->vma, buf, LINFO_PATHLEN);
	if (path) {
		kfree(mod->stp_mod.buf);
		mod->stp_mod.buf = buf;
		mod->stp_mod.path = path;
	} else {
		kfree(buf);
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
	char *path = 0;

	memset(&mod->stp_mod, 0, sizeof(mod->stp_mod));
	mod->stp_mod.name = ""; // TODO fill if necessary or remove

	// Get vma for this module
	// (executable phdr with eh_frame and eh_frame_hdr section)
	vma = mod->vma = find_vma(task->mm, linfo->eh_frame_hdr_addr);

	// Get the vma pages
	npages = vma_pages(vma);
	pages = kmalloc(sizeof(struct page *) * npages, GFP_KERNEL);
	if (!pages) {
		res = -ENOMEM;
		goto FREEPATH;
	}

	res = __get_user_pages_unlocked(task, task->mm, vma->vm_start,
			npages, 0, 0, pages, FOLL_TOUCH);
	if (res < 0) goto FREEPAGES;
	npages = res;

	// Vmap the pages so that we can access eh_frame directly.  We
	// map the full vma because it was easier to write, but we
	// should only vmap the pages containing unwinding info. TODO
	base = vmap(pages, npages, vma->vm_flags, vma->vm_page_prot);
	dbug_unwind(1, "vmap kernel addr: %p\n", base);

	// bookkeeping info
	mod->base = base;
	mod->vma_start = vma->vm_start;
	mod->vma_end = vma->vm_end;
	mod->pages = pages;
	mod->npages = npages;
	// eh_frame_hdr info
	mod->stp_mod.unwind_hdr_addr = linfo->eh_frame_hdr_addr - mod->vma_start;
	mod->stp_mod.unwind_hdr_len = linfo->eh_frame_hdr_size;
	mod->stp_mod.unwind_hdr = mod->base + mod->stp_mod.unwind_hdr_addr;
	//  dynamic/absolute
	mod->stp_mod.is_dynamic = linfo->dynamic;
	mod->stp_mod.static_addr = vma->vm_start;

	// eh_frame info
	if (!linfo->eh_frame_addr || !linfo->eh_frame_size) {
		res = fill_eh_frame_info(mod, proc);
		if (res) goto FREEPAGES;
	} else {
		mod->stp_mod.eh_frame_addr = linfo->eh_frame_addr - mod->vma_start;
		mod->stp_mod.eh_frame_len = linfo->eh_frame_size;
		mod->stp_mod.eh_frame = mod->base + mod->stp_mod.eh_frame_addr;
	}

	// Module path
	if (strnlen(linfo->path, LINFO_PATHLEN)) {
		path = kmalloc(LINFO_PATHLEN, GFP_KERNEL);
		if (!path)
			return -ENOMEM;
		strncpy(path, linfo->path, LINFO_PATHLEN);
		mod->stp_mod.buf = mod->stp_mod.path = path;
	} else {
		res = fill_mod_path(mod);
		if (res) return res;
	}

	dbug_unwind(1, "Loaded module from %s\n", mod->stp_mod.path);

	res = get_user(test, (unsigned long *)linfo->eh_frame_hdr_addr);
	if (res < 0) goto FREEPAGES;
	if (test != *((unsigned long *) mod->stp_mod.unwind_hdr))
		KUNWIND_BUGM("Bad eh_frame virtual kernel address.");

	return 0;
FREEPAGES:
	kfree(pages);
FREEPATH:
	kfree(path);
	mod->stp_mod.buf = mod->stp_mod.path = NULL;
	return res;
}

static void close_kunwind_stp_module(struct kunwind_stp_module *mod)
{
	int i;
	dbug_unwind(1, "vunmap kernel addr: %p\n", mod->base);
	kfree(mod->stp_mod.buf);
	mod->stp_mod.buf = mod->stp_mod.path = NULL;
	vunmap(mod->base);
	mod->base = NULL;
	for (i = 0; i < mod->npages; ++i) {
		put_page(mod->pages[i]);
	}
	kfree(mod->pages);
	mod->npages = 0;
	mod->pages = NULL;
	mod->vma_start = 0;
	mod->vma_end = 0;
}

static int init_proc_unwind_info(struct kunwind_proc_modules *mods,
				 int compat)
{
	if (!mods)
		return -EINVAL;
	memset(mods, 0, sizeof(struct kunwind_proc_modules));
	INIT_LIST_HEAD(&(mods->stp_modules));
	mods->compat = compat;

	return 0;
}

static int release_unwind_info(struct kunwind_proc_modules *mods)
{
	struct kunwind_stp_module *mod, *other;
	list_for_each_entry_safe(mod, other, &(mods->stp_modules), list) {
		close_kunwind_stp_module(mod);
		list_del(&(mod->list));
		kfree(mod);
	}
	kfree(mods);
	return 0;
}

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

#define ElfW(smt) Elf64_##smt
static int add_module(struct phdr_info *info, struct task_struct *task,
		      void *data)
{
	struct kunwind_proc_modules *mods = data;
	struct load_info linfo = { 0 };
	const ElfW(Phdr) *eh_phdr = NULL;
	bool dynamic = false;
	ElfW(Phdr) *phdr_arr = info->phdr;
	int i, err = 0;
	struct kunwind_stp_module *mod;

	for (i = 0; i < info->phnum; ++i) {
		if (phdr_arr[i].p_type == PT_GNU_EH_FRAME) {
			eh_phdr = &phdr_arr[i];
		} else if (phdr_arr[i].p_type == PT_DYNAMIC) {
			dynamic = true;
		}
		if (eh_phdr && dynamic)
			break;
	}

	if (!eh_phdr)
		// No module added but we can still try to unwind
		return 0;

	// Fill linfo
	linfo.obj_addr = info->addr;
	linfo.eh_frame_hdr_addr = info->addr + eh_phdr->p_vaddr;
	linfo.eh_frame_hdr_size = eh_phdr->p_memsz;
	linfo.dynamic = dynamic;

	mod = kmalloc(sizeof(struct kunwind_stp_module), GFP_KERNEL);
	if (!mod)
		return -ENOMEM;
	err = init_kunwind_stp_module(task, &linfo, mod, mods);
	if (err) {
		kfree(mod); // Free the module not added to the list
		return err;
	}

	list_add_tail(&(mod->list), &(mods->stp_modules));
	return 0;
}
#undef ElfW

static long kunwind_init_ioctl(struct file *file)
{
	struct kunwind_proc_modules *mods = file->private_data;

	return iterate_phdr(&add_module, current, mods);
}


static long kunwind_proc_info_ioctl(struct file *file,
		const struct proc_info __user *upinfo)
{
	struct kunwind_proc_modules *mods = file->private_data;
	struct proc_info *pinfo;
	int i, err;
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

	for (i = 0; i < pinfo->nr_load_segments; ++i) {
		struct load_info *linfo = &pinfo->load_segments[i];
		struct kunwind_stp_module *mod =
				kmalloc(sizeof(struct kunwind_stp_module), GFP_KERNEL);
		err = init_kunwind_stp_module(current, linfo, mod, mods);
		if (err) {
			kfree(mod); // Free the module not added to the list
			goto KUNWIND_PROC_INFO_IOCTL_ERR;
		}
		list_add_tail(&(mod->list), &(mods->stp_modules));
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
	u32 capacity, struct_size;
	struct unwind_context context;
	struct pt_regs regs;

	dbug_unwind(1, "Starting kunwind unwinding\n");

	if (get_user(capacity, (typeof(capacity)*) uback))
		return -EFAULT;

	struct_size = sizeof(struct kunwind_backtrace) +
		capacity * sizeof(__u64);
	back = kmalloc(struct_size, GFP_KERNEL);
	if (!back)
		return -ENOMEM;

	memset(&context, 0, sizeof(context));
	regs = *current_pt_regs();
	arch_unw_init_frame_info(&context.info, &regs, 0);
	back->capacity = capacity;
	err = unwind_full(&context, mods, back->backtrace, back->capacity, &(back->size));

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
