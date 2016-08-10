#include <execinfo.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/param.h>

#include "find_proc_info.h"
#include "kunwind.h"

#define DEPTH 10
static FILE *out;

void foo3(void)
{
	unsigned int size = sizeof(struct kunwind_backtrace) + DEPTH * 8;
	struct kunwind_backtrace *back = malloc(size);
	back->capacity = DEPTH;
	back->size = 0;
	printf("Calling unwinding from userspace\n");
	int err = ioctl(fileno(out), KUNWIND_UNWIND_IOCTL, back);
	if (err) perror("Error while unwinding");
	for (int i = 0; i < back->size && i < DEPTH; ++i) {
		printf("stack frame with ip at %p\n", back->backtrace[i]);
		backtrace_symbols_fd((void* const *)(&back->backtrace[i]),
				     1, STDOUT_FILENO);
	}
	backtrace_symbols_fd((void* const *)back->backtrace,
			     MIN(back->size, DEPTH),
			     STDOUT_FILENO);
	printf("End of unwinding from userspace\n");

}

void foo2(void)
{
  for (int i = 0; i < 2; ++i) foo3();
}

void foo1(void)
{
	foo2();
}

void foo(void)
{
	foo1();
}

int main(int argc, char **argv)
{
	// Write proc info to file
	out = fopen("/proc/kunwind_debug", "r+");
	if (!out) {
		perror("Failed to open file");
		return 1;
	}

	struct proc_info *proc_info = find_proc_info();
	ioctl(fileno(out), KUNWIND_PROC_INFO_IOCTL, proc_info);

	foo();

	return 0;
}
