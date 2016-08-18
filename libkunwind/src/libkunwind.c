#define _GNU_SOURCE

#include "autoconf.h"

#include "libkunwind.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/ioctl.h>

struct unwind_handle {
	FILE *fd;
};

unsigned int unwind_handle_struct_size(void)
{
	return sizeof(struct unwind_handle);
}

int init_unwind(struct unwind_handle *handle)
{
	init_unwind_proc_info(handle, NULL);
}

int init_unwind_proc_info(struct unwind_handle *handle,
			  struct proc_info *proc_info)
{
	int err;
	
	handle->fd = fopen("/proc/kunwind_debug", "r+");
	if (!handle->fd)
		return -EIO;

	err = ioctl(fileno(handle->fd), KUNWIND_PROC_INFO_IOCTL,
		    proc_info);

	return err;
}

int unwind(struct unwind_handle *handle,
	   struct kunwind_backtrace* backtrace)
{
	return ioctl(fileno(handle->fd), KUNWIND_UNWIND_IOCTL,
		     backtrace);
}

void release_handle(struct unwind_handle *handle)
{
	fclose(handle->fd);
}
