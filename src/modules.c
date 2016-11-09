#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "modules.h"

#include "debug.h"
#include "iterate_phdr.h"
#include "vma_file_path.h"
#include "unwind/unwind.h"

/*
 * linfo must at least have eh_frame_hdr_addr and eh_frame_hdr_len
 */
static int init_kunwind_stp_module(struct task_struct *task,
		struct load_info *linfo,
		struct kunwind_module *mod,
		struct kunwind_proc_modules *proc)
{
	int i;
	int res;
	unsigned long npages;
	struct page **pages;
	unsigned long test;

	// Get vma for this module
	// (executable phdr with eh_frame and eh_frame_hdr section)
	mod->elf_vma = find_vma(task->mm, linfo->eh_frame_hdr_ubuf);

	// Get the vma pages
	npages = vma_pages(mod->elf_vma);
	pages = kmalloc(sizeof(struct page *) * npages, GFP_KERNEL);
	if (!pages) {
		res = -ENOMEM;
		goto out;
	}

	/*
	 * FIXME: add missing put_page() and check pinned size
	 * See example: drivers/infiniband/hw/hfi1/user_pages.c
	 */
	res = __get_user_pages_unlocked(task, task->mm, mod->elf_vma->vm_start,
			npages, 0, 0, pages, FOLL_TOUCH);
	if (res < 0)
		goto out_free_pages;
	npages = res;

	/*
	 * vmap the pages containing the eh_frame for direct
	 * access without copy_from_user.
	 */
	mod->elf_vmap = vmap(pages, npages, mod->elf_vma->vm_flags, mod->elf_vma->vm_page_prot);
	dbug_unwind(1, "vmap kernel addr: %p\n", mod->elf_vmap);

	if (!mod->elf_vmap)
		goto out_put_pages;

	mod->pages = pages;
	mod->npages = npages;

	/* eh_frame_hdr */
	mod->ehf_hdr.ubuf = (void *) linfo->eh_frame_hdr_ubuf;
	mod->ehf_hdr.size = linfo->eh_frame_hdr_size;
	mod->ehf_hdr.offset = linfo->eh_frame_hdr_ubuf - mod->elf_vma->vm_start;
	mod->ehf_hdr.kbuf = mod->elf_vmap + mod->ehf_hdr.offset;
	mod->is_dynamic = linfo->dynamic;

	/* eh_frame */
	if (linfo->eh_frame_addr && linfo->eh_frame_size) {
		/* the userspace provides eh_frame location */
		mod->ehf.ubuf = (void *) linfo->eh_frame_addr;
		mod->ehf.size = linfo->eh_frame_size;
		mod->ehf.offset = linfo->eh_frame_addr - mod->elf_vma->vm_start;
		mod->ehf.kbuf = mod->elf_vmap + mod->ehf.offset;
	} else {
		/* find the eh_frame location ourselves */
		res = eh_frame_from_hdr(mod->elf_vmap, mod->elf_vma->vm_start,
				mod->elf_vma->vm_end, proc->compat,
				&mod->ehf_hdr, &mod->ehf);

		dbug_unwind(1, "fill_eh_frame_info %d\n", res);
		if (res)
			goto out_vunmap;
	}

	dbug_unwind(1, "Loaded module from %pD1\n", mod->elf_vma->vm_file);

	res = get_user(test, (unsigned long *)linfo->eh_frame_hdr_ubuf);
	if (res < 0)
		goto out_vunmap;
	if (test != *((unsigned long *) mod->ehf_hdr.kbuf)) {
		WARN_ON_ONCE("Bad eh_frame virtual kernel address.");
		goto out_vunmap;
	}
	return 0;


out_vunmap:
	vunmap(mod->elf_vmap);
out_put_pages:
	for (i = 0; i < npages; ++i) {
		put_page(pages[i]);
	}
out_free_pages:
	kfree(pages);
out:
	dbug_unwind(1, "Failed to load module at virtual address %lx\n", mod->elf_vma->vm_start);
	return res;
}

static void close_kunwind_stp_module(struct kunwind_module *mod)
{
	int i;
	dbug_unwind(1, "vunmap kernel addr: %p\n", mod->elf_vmap);
	vunmap(mod->elf_vmap);
	mod->elf_vmap = NULL;
	for (i = 0; i < mod->npages; ++i) {
		put_page(mod->pages[i]);
	}
	kfree(mod->pages);
	mod->npages = 0;
	mod->pages = NULL;
}

int init_proc_unwind_info(struct kunwind_proc_modules *mods,
			  int compat)
{
	if (!mods)
		return -EINVAL;
	memset(mods, 0, sizeof(*mods));
	INIT_LIST_HEAD(&(mods->stp_modules));
	mods->compat = compat;

	return 0;
}

int release_unwind_info(struct kunwind_proc_modules *mods)
{
	struct kunwind_module *mod, *other;
	list_for_each_entry_safe(mod, other, &(mods->stp_modules), list) {
		close_kunwind_stp_module(mod);
		list_del(&(mod->list));
		kfree(mod);
	}
	kfree(mods);
	return 0;
}

// TODO generalize this function for compat tasks with Elf32 structures
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
	struct kunwind_module *mod;

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
	linfo.eh_frame_hdr_ubuf = info->addr + eh_phdr->p_vaddr;
	linfo.eh_frame_hdr_size = eh_phdr->p_memsz;
	linfo.dynamic = dynamic;

	mod = kmalloc(sizeof(struct kunwind_module), GFP_KERNEL);
	if (!mod)
		return -ENOMEM;
	err = init_kunwind_stp_module(task, &linfo, mod, mods);
	if (err) {
		kfree(mod); // Free the module not added to the list
		return 0;
	}

	list_add_tail(&(mod->list), &(mods->stp_modules));
	return 0;
}
#undef ElfW

int init_modules_from_task(struct task_struct *task,
			   struct kunwind_proc_modules *mods)
{
	return iterate_phdr(add_module, task, mods);
}

int init_modules_from_proc_info(struct proc_info *pinfo,
				struct task_struct *task,
				struct kunwind_proc_modules *mods)
{
	int i, err;
	for (i = 0; i < pinfo->nr_load_segments; ++i) {
		struct load_info *linfo = &pinfo->load_segments[i];
		struct kunwind_module *mod =
			kmalloc(sizeof(struct kunwind_module),
				GFP_KERNEL);
		err = init_kunwind_stp_module(task, linfo, mod, mods);
		if (err) {
			kfree(mod); // Free the module not added to
				    // the list
			return err;
		}
		list_add_tail(&(mod->list), &(mods->stp_modules));
	}
	return 0;
}

int do_current_unwind(struct kunwind_backtrace *bt,
		      struct kunwind_proc_modules *mods)
{
	struct unwind_context context;
	struct pt_regs *regs = current_pt_regs();

	memset(&context, 0, sizeof(context));
	arch_unw_init_frame_info(&context.info, regs, 0);
	arch_unw_init_frame_info(&context.stub, regs, 0);
	return unwind_full(&context, mods, bt);
}
