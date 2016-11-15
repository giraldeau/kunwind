/*
 * Small program to unwind with libunwind for debugging purpose
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <sys/personality.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#define DEPTH_MAX 10

#include <iostream>
#include <vector>
#include <string>

#include "foo.h"
#include "util.h"


using namespace std;

void do_backtrace()
{
	void *addr[DEPTH_MAX];
	int depth = unw_backtrace((void **)&addr, DEPTH_MAX);
	for (int i = 0; i < depth; i++) {
		cout << addr[i];
		if (i < depth - 1)
			cout << ", ";
	}
	cout << endl;
}

int main(int argc, char **argv)
{
	disable_aslr(argc, argv);
	Foo foo([](){
		cout << "end of recursion" << endl;
		do_backtrace();
	}, true);
	foo.foo(0);
	return 0;
}
