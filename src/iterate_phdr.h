#ifndef _ITERATE_PHDR_H_
#define _ITERATE_PHDR_H_

#include <linux/sched.h>

#define NAME_BUFLEN 60

struct phdr_info {
	unsigned long addr;  /* Base address of object */
	char *name; /* (Null-terminated) name of object */
	void *phdr; /* Pointer to array of ELF program headers for
		       this object */
	unsigned int phnum; /* # of items in phdr */
};

int iterate_phdr(int (*cb) (struct phdr_info *info,
			    struct task_struct *task,
			    void *data),
		 struct task_struct *task, void *data);

#endif // _ITERATE_PHDR_H_
