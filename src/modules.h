#ifndef _MODULES_H_
#define _MODULES_H_

#include <proc_info.h>
#include <kunwind.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>

#include "unwind/unwind.h"

#define UNW_CACHE_BITS 10

struct unw_cache_key {
        unsigned long pc;
} __attribute__((__packed__));

struct unw_cache_entry {
	struct tdep_frame frame;
        struct hlist_node hlist;
        struct rcu_head rcu;
};

struct kunwind_proc_modules {
	struct list_head stp_modules;
	DECLARE_HASHTABLE(unw_cache, UNW_CACHE_BITS);
	int compat :1;
};

struct kunwind_module {
	struct list_head list;
	struct vm_area_struct *elf_vma;	/* ELF userspace vma */
	void *elf_vmap;			/* ELF vmap in kernel */
	struct page **pages;		/* ELF pages for kernel vmap */
	int npages;
	struct section ehf_hdr;		/* eh_frame_hdr */
	struct section ehf;		/* eh_frame */
	int is_dynamic;
};

struct unw_cache_entry* unw_cache_find_entry(struct kunwind_proc_modules *mods,
		struct unw_cache_key *key);
void unw_cache_add_entry(struct kunwind_proc_modules *mods,
		struct tdep_frame *frame);
void unw_cache_del_entry(struct kunwind_proc_modules *mods,
		struct unw_cache_key *key);
void unw_cache_clear(struct kunwind_proc_modules *mods);
void unw_cache_test(struct kunwind_proc_modules *mods);
void unw_cache_dump(struct kunwind_proc_modules *mods);

int fill_mod_path(struct kunwind_module *mod);

int init_proc_unwind_info(struct kunwind_proc_modules *mods,
			  int compat);

int release_unwind_info(struct kunwind_proc_modules *mods);

int init_modules_from_task(struct task_struct *task,
			   struct kunwind_proc_modules *mods);

int init_modules_from_proc_info(struct proc_info *info,
				struct task_struct *task,
				struct kunwind_proc_modules *mods);

int do_current_unwind(struct kunwind_backtrace *bt,
		      struct kunwind_proc_modules *mods);

#endif // _MODULES_H_
