#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include <sys/param.h>
#include <sys/time.h>

#include <libkunwind.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#define DEPTH_MAX 10
#define noinline __attribute((noinline))

static struct unwind_handle *handle;

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
	assert(init_unwind(&handle) == 0);
	foo();
	return 0;
}
