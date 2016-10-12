#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <execinfo.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/personality.h>
#include <sys/time.h>

#include <libkunwind.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#define DEPTH_MAX 10
#define noinline __attribute((noinline))

#include <iostream>
#include <vector>
#include <string>

static struct unwind_handle *handle;

using namespace std;

/*
 * Save in the current directory the virtual memory map of the process
 * for debugging purposes.
 */
void save_maps(void)
{
	static const int size = 1024;
	int towrite;
	char *name;
	char *data = (char *) malloc(size);

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

void print_backtrace(const string &msg, vector<string> &result)
{
	cout << msg << ": ";
	for (int i = 0; i < result.size(); i++) {
		cout << result[i] << " ";
	}
	cout << endl;
}

void get_symbols(vector<string> &syms, void **backtrace, int from, int to)
{
	for (int i = from; i < to; i++) {
		Dl_info info;
		dladdr(backtrace[i], &info);
		syms.push_back(info.dli_sname);
	}
}

noinline void foo3()
{
	void *addr[DEPTH_MAX];
	struct kunwind_backtrace *bt;

	bt = (struct kunwind_backtrace *) malloc(kunwind_backtrace_struct_size(DEPTH_MAX));
	kunwind_backtrace_init(bt, DEPTH_MAX);
	assert(unwind(handle, bt) == 0);

	int depth = unw_backtrace((void **)&addr, DEPTH_MAX);

	vector<string> syms_kunwind;
	vector<string> syms_libunwind;

	get_symbols(syms_kunwind, (void **)&bt->backtrace, 1, bt->size);
	get_symbols(syms_libunwind, (void **)&addr, 0, depth - 1);

	print_backtrace("kunwind  ", syms_kunwind);
	print_backtrace("libunwind", syms_libunwind);

	assert(syms_kunwind.size() == syms_libunwind.size());
	for (int i = 0; i < syms_kunwind.size(); i++) {
		assert(syms_kunwind[i].compare(syms_libunwind[i]) == 0);
	}

	free(bt);
}

noinline void foo2(void)
{
	volatile int x = 0;
	foo3();
}

noinline void foo1(void)
{
	volatile int x = 0;
	foo2();
}

noinline void foo(void)
{
	volatile int x = 0;
	foo1();
}

int main(int argc, char **argv)
{
	/*
	 * Re-execute without address randomization to get
	 * deterministic results.
	 */
	if (!getenv("NO_RANDOMIZE")) {
		setenv("NO_RANDOMIZE", "1", 1);
		personality(ADDR_NO_RANDOMIZE);
		execle(argv[0], argv[0], NULL, environ);
	}

	save_maps();
	assert(init_unwind(&handle) == 0);
	foo();
	return 0;
}
