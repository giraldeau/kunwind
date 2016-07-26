#ifndef _UAPI_PROC_INFO_H_
#define _UAPI_PROC_INFO_H_

#include <linux/ioctl.h>
#include <linux/types.h>

/*
 * Location of the unwind info of the program or a dynamically
 * loaded/linked library.
 */
struct load_info {
	__u64 obj_addr;
	__u64 eh_frame_hdr_addr;
	__u64 eh_frame_hdr_size;
	__u64 eh_frame_addr;
	__u64 eh_frame_size;
	// TODO .dynamic etc to adjust for relocation
};

struct proc_info {
	__u32 size;
	__u32 nr_load_segments;
	struct load_info load_segments[0];
};

#define KUNWIND_PROC_INFO_IOCTL _IO(0xF6, 0x91)

#endif // _UAPI_PROC_INFO_H_
