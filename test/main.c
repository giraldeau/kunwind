#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/time.h>

#include "find_proc_info.h"
#include "libkunwind.h"

#define DEPTH 10

static struct unwind_handle *handle;
static struct kunwind_backtrace *bt;

void foo3(int print)
{
	kunwind_backtrace_init(bt, DEPTH);

	if (print) printf("Calling unwinding from userspace\n");
	int err = unwind(handle, bt);
	if (err) perror("Error while unwinding");
	if (print)
		backtrace_symbols_fd((void* const *)bt->backtrace,
				     MIN(bt->size, bt->capacity),
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
	struct proc_info *proc_info = find_proc_info();
	handle = malloc(unwind_handle_struct_size());
	int err = init_unwind_proc_info(handle, proc_info);

	if (err) {
		perror("Unwinding initialization");
		return 1;
	}

	bt = malloc(kunwind_backtrace_struct_size(DEPTH));

	foo();

	return 0;
}
