#define _GNU_SOURCE

#include <link.h>
#include <stdlib.h>
#include <stdbool.h>

#include "find_proc_info.h"

struct load_info_list {
	struct load_info info;
	struct load_info_list *next;
};

struct extract_unwind_info_data {
	struct load_info_list *list_head;
	struct load_info_list *list_tail;
	size_t nr_load_segments;
};

static int extract_unwind_info(struct dl_phdr_info *info,
				 size_t size, void * data)
{
	struct extract_unwind_info_data *extract_data =
		(struct extract_unwind_info_data *) data;

	// Find eh_frame program header and check for dynamic
	const ElfW(Phdr) *eh_phdr = NULL;
	bool dynamic = false;
	unsigned features = 0;
	for (size_t i = 0; i < info->dlpi_phnum; ++i) {
		if (info->dlpi_phdr[i].p_type == PT_GNU_EH_FRAME) {
			eh_phdr = &info->dlpi_phdr[i];
			features++;
		} else if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
			dynamic = true;
			features++;
		}
		if (features >= 2)
			break;
	}

	if (!eh_phdr)
		return -ERR_NO_EH_PHDR;

	// Fill data
	struct load_info_list *elem = malloc(sizeof(struct load_info_list));
	ElfW(Addr) addr;
	elem->info.obj_addr = addr = info->dlpi_addr;
	elem->info.eh_frame_hdr_offset = addr + eh_phdr->p_vaddr;
	elem->info.eh_frame_hdr_size = eh_phdr->p_memsz;
	elem->info.dynamic = dynamic;
	elem->next = NULL;

	// Add to list
	if (!extract_data->list_head) {
		extract_data->list_head =
			extract_data->list_tail = elem;
		extract_data->nr_load_segments = 1;
	} else {
		extract_data->list_tail->next = elem;
		extract_data->list_tail = elem;
		extract_data->nr_load_segments++;
	}

	return 0;
}

static void free_load_info_list(struct load_info_list *list)
{
	struct load_info_list *next = list;
	do {
		list = next;
		next = list->next;
		free(list);
	} while (next);
}

struct proc_info *find_proc_info(void)
{
	struct extract_unwind_info_data data = { 0 };
	int err = dl_iterate_phdr(extract_unwind_info, (void *) &data);

	if (err) {
		free_load_info_list(data.list_head);
		return NULL;
	}

	size_t proc_info_size = sizeof(struct proc_info) +
		data.nr_load_segments * sizeof(struct load_info);
	struct proc_info *proc_info = malloc(proc_info_size);

	// Fill info
	proc_info->size = proc_info_size;
	proc_info->nr_load_segments = data.nr_load_segments;
	struct load_info_list *elem = data.list_head;
	struct load_info *linfo = proc_info->load_segments;
	for (; elem; elem = elem->next, ++linfo) {
		*linfo = elem->info;
	}

	free_load_info_list(data.list_head);
	return proc_info;
}
