#define _GNU_SOURCE
#include <assert.h>
#include <execinfo.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/time.h>

#include <libkunwind.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#define DEPTH_MAX 10
#define noinline __attribute((noinline))

static struct unwind_handle *handle;

/*
 * Save in the current directory the virtual memory map of the process
 * for debugging purposes.
 */
void save_maps(void)
{
	static const int size = 1024;
	int towrite;
	char *name;
	char *data = malloc(size);

	if (asprintf(&name, "/proc/%d/maps", getpid()) < 0)
		return;

	int maps_fd = open(name, O_RDONLY);
	int dest_fd = open("maps.snapshot",
			O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (maps_fd < 0 || dest_fd < 0)
		return;
	while ((towrite = read(maps_fd, data, size)) > 0) {
		char *buf = data;
		do {
			int written = write(dest_fd, buf, towrite);
			if (written < 0)
				break;
			towrite -= written;
			buf += written;
		} while (towrite > 0);
	}
	close(maps_fd);
	close(dest_fd);
	free(data);
}

void print_backtrace(char *msg, void **backtrace, int depth)
{
	printf("%10s depth=%d ", msg, depth);
	for (int i = 0; i < depth; i++) {
		printf("%p ", backtrace[i]);
	}
	printf("\n");
}

noinline void foo3()
{
	void *addr[DEPTH_MAX];
	struct kunwind_backtrace *bt;

	bt = malloc(kunwind_backtrace_struct_size(DEPTH_MAX));
	kunwind_backtrace_init(bt, DEPTH_MAX);
	assert(unwind(handle, bt) == 0);

	int depth = unw_backtrace((void **)&addr, DEPTH_MAX);

	print_backtrace("kunwind", (void **)&bt->backtrace, bt->size);
	print_backtrace("libunwind", addr, depth);

	free(bt);
}

noinline void foo2(void)
{
	foo3();
}

noinline void foo1(void)
{
	foo2();
}

noinline void foo(void)
{
	foo1();
}

int main(int argc, char **argv)
{
	save_maps();
	assert(init_unwind(&handle) == 0);
	foo();
	return 0;
}
