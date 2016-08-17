#include <execinfo.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/time.h>

#include "find_proc_info.h"
#include "kunwind.h"

#define DEPTH 10
static FILE *out;
static struct kunwind_backtrace bt;

void foo3(int print)
{
	unsigned int size = sizeof(struct kunwind_backtrace) + DEPTH * 8;
	struct kunwind_backtrace *back = &bt; // Or do a malloc or pass the struct
	back->capacity = DEPTH;
	back->size = 0;
	if (print) printf("Calling unwinding from userspace\n");
	int err = ioctl(fileno(out), KUNWIND_UNWIND_IOCTL, back);
	if (err) perror("Error while unwinding");
	if (print)
		backtrace_symbols_fd((void* const *)back->backtrace,
				     MIN(back->size, DEPTH),
				     STDOUT_FILENO);
	if (print) printf("End of unwinding from userspace\n");

}

#define TOP 1000
#define PRINT_SET 0

void foo2(void)
{
	struct timeval start, end, res;
	int err = gettimeofday(&start, NULL);
	if (err) exit(1);
	for (int i = 0; i < TOP; ++i) foo3(PRINT_SET);
	err = gettimeofday(&end, NULL);
	if (err) exit(1);
	timersub(&end, &start, &res);
	printf("Timer for %d iterations is %d seconds and %d microseconds\n", TOP, res.tv_sec, res.tv_usec);
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
