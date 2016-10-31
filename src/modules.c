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

int fill_eh_frame_info(struct kunwind_stp_module *mod,
		       struct kunwind_proc_modules *proc)
{
	u8 *eh, *hdr;
	unsigned long eh_addr, eh_len, hdr_addr, hdr_len;
	int err;

	// Use the .eh_frame_hdr pointer to find the .eh_frame section
	hdr = mod->stp_mod.unwind_hdr;
	hdr_addr = mod->stp_mod.unwind_hdr_addr;
	hdr_len = mod->stp_mod.unwind_hdr_len;

	err =  eh_frame_from_hdr(mod->kvmap, mod->uvma->vm_start,
				 mod->uvma->vm_end, proc->compat,
				 hdr, hdr_addr, hdr_len,
				 &eh, &eh_addr, &eh_len);

	if (err)
		return err;

	mod->stp_mod.eh_frame_addr = eh_addr;
	mod->stp_mod.eh_frame_len = eh_len;
	mod->stp_mod.eh_frame = eh;

	return 0;
}

int fill_mod_path(struct kunwind_stp_module *mod)
{
	char *path, *buf = kmalloc(LINFO_PATHLEN, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	path = vma_file_path(mod->uvma, buf, LINFO_PATHLEN);
	if (path) {
		kfree(mod->stp_mod.path_buf);
		mod->stp_mod.path_buf = buf;
		mod->stp_mod.path = path;
	} else {
		kfree(buf);
	}
	return 0;
}

/*
 * linfo must at least have eh_frame_hdr_addr and eh_frame_hdr_len
 */
static int init_kunwind_stp_module(struct task_struct *task,
		struct load_info *linfo,
		struct kunwind_stp_module *mod,
		struct kunwind_proc_modules *proc)
{
	int res;
	unsigned long npages;
	struct page **pages;
	unsigned long test;
	char *path = 0;

	memset(&mod->stp_mod, 0, sizeof(mod->stp_mod));
	mod->stp_mod.name = ""; // TODO fill if necessary or remove

	// Get vma for this module
	// (executable phdr with eh_frame and eh_frame_hdr section)
	mod->uvma = find_vma(task->mm, linfo->eh_frame_hdr_addr);

	// Get the vma pages
	npages = vma_pages(mod->uvma);
	pages = kmalloc(sizeof(struct page *) * npages, GFP_KERNEL);
	if (!pages) {
		res = -ENOMEM;
		goto FREEPATH;
	}

	res = __get_user_pages_unlocked(task, task->mm, mod->uvma->vm_start,
			npages, 0, 0, pages, FOLL_TOUCH);
	if (res < 0) goto FREEPAGES;
	npages = res;

	// Vmap the pages so that we can access eh_frame directly.  We
	// map the full vma because it was easier to write, but we
	// should only vmap the pages containing unwinding info. TODO
	mod->kvmap = vmap(pages, npages, mod->uvma->vm_flags, mod->uvma->vm_page_prot);
	dbug_unwind(1, "vmap kernel addr: %p\n", mod->kvmap);

	// bookkeeping info
	mod->pages = pages;
	mod->npages = npages;
	// eh_frame_hdr info
	mod->stp_mod.unwind_hdr_addr = linfo->eh_frame_hdr_addr - mod->uvma->vm_start;
	mod->stp_mod.unwind_hdr_len = linfo->eh_frame_hdr_size;
	mod->stp_mod.unwind_hdr = mod->kvmap + mod->stp_mod.unwind_hdr_addr;
	//  dynamic/absolute
	mod->stp_mod.is_dynamic = linfo->dynamic;
	mod->stp_mod.static_addr = mod->uvma->vm_start;

	// eh_frame info
	if (!linfo->eh_frame_addr || !linfo->eh_frame_size) {
		res = fill_eh_frame_info(mod, proc);
		dbug_unwind(1, "fill_eh_frame_info %d\n", res);
		if (res)
			goto FREEPAGES;
	} else {
		mod->stp_mod.eh_frame_addr = linfo->eh_frame_addr - mod->uvma->vm_start;
		mod->stp_mod.eh_frame_len = linfo->eh_frame_size;
		mod->stp_mod.eh_frame = mod->kvmap + mod->stp_mod.eh_frame_addr;
	}

	// Module path
	if (strnlen(linfo->path, LINFO_PATHLEN)) {
		path = kmalloc(LINFO_PATHLEN, GFP_KERNEL);
		if (!path)
			return -ENOMEM;
		strncpy(path, linfo->path, LINFO_PATHLEN);
		mod->stp_mod.path_buf = mod->stp_mod.path = path;
	} else {
		res = fill_mod_path(mod);
		if (res)
			return res;
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
	mod->stp_mod.path_buf = mod->stp_mod.path = NULL;
	dbug_unwind(1, "Failed to load module at virtual address %lx\n", mod->uvma->vm_start);
	return res;
}

static void close_kunwind_stp_module(struct kunwind_stp_module *mod)
{
	int i;
	dbug_unwind(1, "vunmap kernel addr: %p\n", mod->kvmap);
	kfree(mod->stp_mod.path_buf);
	mod->stp_mod.path_buf = mod->stp_mod.path = NULL;
	vunmap(mod->kvmap);
	mod->kvmap = NULL;
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
	struct kunwind_stp_module *mod, *other;
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
		struct kunwind_stp_module *mod =
			kmalloc(sizeof(struct kunwind_stp_module),
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
	return unwind_full(&context, mods, bt);
}
