#ifndef _KUNWIND_DEBUG_H_
#define _KUNWIND_DEBUG_H_

#include "unwind/unwind.h"

struct kunwind_proc_modules {
	struct list_head stp_modules;
	int compat :1;
};

struct kunwind_stp_module {
	struct _stp_module stp_mod;
	struct list_head list;
	void *base;
	unsigned long vma_start;
	unsigned long vma_end; // TODO set this
	struct page **pages;
	int npages;
};

#endif // _KUNWIND_DEBUG_H_
