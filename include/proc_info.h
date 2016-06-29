#ifndef PROC_INFO_H_
#define PROC_INFO_H_

typedef struct eh_frame_info {
	unsigned long start; // ElfW(Addr)
	unsigned long size; // ElfW(Word)
	unsigned long obj_addr; // ElfW(Addr)
} eh_frame_info_t;

typedef struct proc_info {
	unsigned int size;
	unsigned int nr_eh_frames;
	eh_frame_info_t eh_frames[0];
} proc_info_t;

#endif // PROC_INFO_H_
