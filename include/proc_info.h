#ifndef PROC_INFO_H_
#define PROC_INFO_H_

#include <stddef.h>
#include <link.h> // for ElfW

typedef struct eh_frame_info {
	ElfW(Addr) start;
        ElfW(Word) size;
	ElfW(Addr) obj_addr;
	// TODO Add other necessary info here
} eh_frame_info_t;

typedef struct proc_info {
	size_t size;
	size_t nr_eh_frames;
	eh_frame_info_t eh_frames[0];
} proc_info_t;

#endif // PROC_INFO_H_
