#ifndef LIBKUNWIND_H
#define LIBKUNWIND_H

#include "kunwind.h"
#include "proc_info.h"

#include <stdio.h>

struct kunwind_handle;

#ifdef __cplusplus
extern "C" {
#endif

struct kunwind_backtrace *kunwind_backtrace_new(int max_entries);
void kunwind_backtrace_free(struct kunwind_backtrace *backtrace);

int kunwind_open(struct kunwind_handle **handle);

int kunwind_init_proc_info(struct kunwind_handle **handle,
		struct proc_info *proc_info);

int kunwind_backtrace(struct kunwind_handle *handle,
	   struct kunwind_backtrace *backtrace);

void kunwind_close(struct kunwind_handle *handle);

#ifdef __cplusplus
}
#endif

#endif // LIBKUNWIND_H
