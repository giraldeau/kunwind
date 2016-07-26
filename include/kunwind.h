#ifndef _UAPI_KUNWIND_H_
#define _UAPI_KUNWIND_H_

#include <linux/ioctl.h>
#include <linux/types.h>

struct kunwind_backtrace {
	__u32 capacity;
	__u32 size;
	__u64 backtrace[0];
};

#define KUNWIND_UNWIND_IOCTL _IO(0xF6, 0x92)

#endif // _UAPI_KUNWIND_H_
