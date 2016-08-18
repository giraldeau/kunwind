#ifndef _UAPI_KUNWIND_H_
#define _UAPI_KUNWIND_H_

#include <linux/ioctl.h>
#include <linux/types.h>

struct kunwind_backtrace {
	__u32 capacity;
	__u32 size;
	__u64 backtrace[0];
};

static
unsigned int kunwind_backtrace_struct_size(unsigned int depth)
{
	struct kunwind_backtrace* p = ((void *)0);
	return sizeof(*p) + depth * sizeof(p->backtrace[0]);
}

static
void kunwind_backtrace_init(struct kunwind_backtrace* backtrace,
			    unsigned int depth)
{
	backtrace->capacity = depth;
	backtrace->size = 0;
}

#define KUNWIND_UNWIND_IOCTL _IO(0xF6, 0x92)

#endif // _UAPI_KUNWIND_H_
