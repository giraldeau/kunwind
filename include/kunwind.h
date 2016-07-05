#ifndef _UAPI_KUNWIND_H_
#define _UAPI_KUNWIND_H_

#include <linux/ioctl.h>
#include <linux/types.h>

struct kunwind_debug_info {
    int x;
    int y;
};

#define KUNWIND_DEBUG_IOCTL _IO(0xF6, 0x90)

#endif // _UAPI_KUNWIND_H_
