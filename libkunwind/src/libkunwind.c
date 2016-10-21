#define _GNU_SOURCE

#include "autoconf.h"

#include "libkunwind.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ioctl.h>

struct kunwind_handle {
	FILE *fd;
};

struct kunwind_backtrace *kunwind_backtrace_new(int max_entries)
{
	struct kunwind_backtrace *bt;

	if (max_entries == 0)
		return NULL;

	bt = calloc(sizeof(*bt), 1);
	if (bt == NULL) {
		return NULL;
	}
	bt->entries = calloc(sizeof(*bt->entries), max_entries);
	if (bt->entries == NULL) {
		free(bt);
		return NULL;
	}
	bt->max_entries = max_entries;
	return bt;
}

void kunwind_backtrace_free(struct kunwind_backtrace *bt)
{
	if (bt) {
		free(bt->entries);
	}
	free(bt);
}

int kunwind_open(struct kunwind_handle **handle)
{
	return kunwind_init_proc_info(handle, NULL);
}

int kunwind_init_proc_info(struct kunwind_handle **handle,
			  struct proc_info *proc_info)
{
	int ret = 0;

	FILE *fd = fopen("/proc/kunwind_debug", "r+");
	if (fd == NULL) {
		printf("errno=%d\n", errno);
		return errno;
	}

	ret = ioctl(fileno(fd), KUNWIND_PROC_INFO_IOCTL, proc_info);
	if (ret < 0) {
		return ret;
	}

	*handle = calloc(1, sizeof(struct kunwind_handle));
	if (*handle == NULL) {
		fclose(fd);
		return -ENOMEM;
	}
	(*handle)->fd = fd;
	return ret;
}

int kunwind_backtrace(struct kunwind_handle *handle,
	   struct kunwind_backtrace* backtrace)
{
	return ioctl(fileno(handle->fd), KUNWIND_UNWIND_IOCTL,
		     backtrace);
}

void kunwind_close(struct kunwind_handle *handle)
{
	if (handle != NULL) {
		fclose(handle->fd);
		free(handle);
	}
}
