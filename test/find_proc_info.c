#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>

#include "find_proc_info.h"

typedef struct eh_frame_list {
	eh_frame_info_t info;
	struct eh_frame_list *next;
} eh_frame_list_t;

typedef struct extract_eh_frame_info_data {
	eh_frame_list_t *list_head;
	eh_frame_list_t *list_tail;
	size_t nr_eh_frames;
} extract_eh_frame_info_data_t;

static int extract_eh_frame_info(struct dl_phdr_info *info,
				 size_t size, void * data)
{
	extract_eh_frame_info_data_t *extract_data =
		(extract_eh_frame_info_data_t *) data;

	// Find eh_frame program header
	const ElfW(Phdr) *eh_phdr = NULL;
	for (size_t i = 0; i < info->dlpi_phnum; ++i) {
		if (info->dlpi_phdr[i].p_type == PT_GNU_EH_FRAME) {
			eh_phdr = &info->dlpi_phdr[i];
			break;
		}
	}

	if (!eh_phdr)
		return -ERR_NO_EH_PHDR;

	// Fill data
	eh_frame_list_t *elem = malloc(sizeof(eh_frame_list_t));
	ElfW(Addr) addr;
	elem->info.obj_addr = addr = info->dlpi_addr;
	elem->info.start = addr + eh_phdr->p_vaddr;
	elem->info.size = eh_phdr->p_memsz;
	elem->next = NULL;

	// Add to list
	if (!extract_data->list_head) {
		extract_data->list_head =
			extract_data->list_tail = elem;
		extract_data->nr_eh_frames = 1;
	} else {
		extract_data->list_tail->next = elem;
		extract_data->list_tail = elem;
		extract_data->nr_eh_frames++;
	}

	return 0;
}

static void free_eh_frame_list(eh_frame_list_t *list)
{
	eh_frame_list_t *next = list;
	do {
		list = next;
		next = list->next;
		free(list);
	} while (next);
}

proc_info_t *find_proc_info(void)
{
	extract_eh_frame_info_data_t data = { 0 };
	int err = dl_iterate_phdr(extract_eh_frame_info, (void *) &data);

	if (err) {
		free_eh_frame_list(data.list_head);
		return NULL;
	}

	size_t proc_info_size = sizeof(proc_info_t) +
		data.nr_eh_frames * sizeof(eh_frame_info_t);
	proc_info_t *proc_info = malloc(proc_info_size);

	// Fill info
	proc_info->size = proc_info_size;
	proc_info->nr_eh_frames = data.nr_eh_frames;
	eh_frame_list_t *elem = data.list_head;
	eh_frame_info_t *proc_eh = proc_info->eh_frames;
	for (; elem; elem = elem->next, ++proc_eh) {
		*proc_eh = elem->info;
	}

	free_eh_frame_list(data.list_head);
	return proc_info;
}
