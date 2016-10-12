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

static struct unwind_handle *handle;
struct kunwind_backtrace *bt;

using namespace std;

noinline void foo(int rec, function<void ()> fn)
{
	volatile int x = 0;
	if (rec > 0) {
		auto rec_lambda = [&](){
			foo(rec - 1, fn);
		};
		rec_lambda();
	} else {
		fn();
	}
}

int main(int argc, char **argv)
{
	int repeat = 1000;
	int verbose = 0;

	assert(init_unwind(&handle) == 0);
	bt = (struct kunwind_backtrace *) malloc(kunwind_backtrace_struct_size(DEPTH_MAX));
	kunwind_backtrace_init(bt, DEPTH_MAX);

	for (int i = 1; i <= DEPTH_MAX; i *= 2) {

		/*
		 * Check that the depth matches
		 */
		foo(i, [&](){
			void *buf[DEPTH_MAX + 1];
			int depth = backtrace(buf, DEPTH_MAX);
			unwind(handle, bt);
			int diff = depth >= bt->size ? depth - bt->size : bt->size - depth;
			if (verbose)
				printf("%-5d %-5d %-5d %-5d\n", i, depth, bt->size, diff);
			assert(diff <= 1);
		});

		auto t1 = chrono::system_clock::now();
		for (int j = 0; j < repeat; j++) {
			foo(i, [&]() {
				assert(unwind(handle, bt) == 0);
				assert(bt->size >= i);
			});
		}
		auto t2 = chrono::system_clock::now();
		chrono::duration<double> diff = t2 - t1;
		auto avg = diff.count() / repeat;
		auto unit = avg / i;
		printf("%-5d %6.3f us (%6.3f us)\n", i, avg * 1E6, unit * 1E6);
	}

	free(bt);
	return 0;
}
