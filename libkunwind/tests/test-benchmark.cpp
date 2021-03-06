#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include <cassert>
#include <chrono>
#include <cmath>

#include <execinfo.h>
#include <libkunwind.h>

#define DEPTH_MAX 128
#define noinline __attribute((noinline))

static struct kunwind_handle *handle;
static struct kunwind_backtrace *bt;

using namespace std;

noinline void foo(int rec, function<void ()> fn)
{
	volatile int x = 0;
	if (rec > 0) {
		foo(rec - 1, fn);
	} else {
		fn();
	}
}

int main(int argc, char **argv)
{
	int repeat = 1000;
	int depth_min = 1;
	int depth_max = DEPTH_MAX;
	int verbose = 0;

	/* positional arguments overloads the defaults */

	if (argc > 1)
		repeat = atoi(argv[1]);
	if (argc > 2)
		depth_min = atoi(argv[2]);
	if (argc > 3)
		depth_max = min(atoi(argv[3]), DEPTH_MAX);

	printf("repeat=%d depth_min=%d depth_max=%d\n", repeat, depth_min, depth_max);

	assert(kunwind_open(&handle) == 0);
	bt = kunwind_backtrace_new(depth_max);
	assert(bt);

	for (int i = depth_min; i <= depth_max; i *= 2) {

		/*
		 * Check that the depth matches
		 */
		foo(i, [&](){
			void *buf[depth_max + 1];
			int depth = backtrace(buf, depth_max);
			kunwind_backtrace(handle, bt);

			int diff = depth - bt->nr_entries;
			if (diff < 0)
				diff *= -1;
			if (verbose)
				printf("%-5d %-5d %-5d %-5d\n", i, depth, bt->nr_entries, diff);
			assert(diff <= 1);
		});

		auto t1 = chrono::system_clock::now();
		for (int j = 0; j < repeat; j++) {
			foo(i, [&]() {
				assert(kunwind_backtrace(handle, bt) == 0);
				assert(bt->nr_entries >= i);
			});
		}
		auto t2 = chrono::system_clock::now();
		chrono::duration<double> diff = t2 - t1;
		auto avg = diff.count() / repeat;
		auto unit = avg / i;
		printf("%-5d %6.3f us (%6.3f us)\n", i, avg * 1E6, unit * 1E6);
	}

	kunwind_backtrace_free(bt);
	kunwind_close(handle);
	return 0;
}
