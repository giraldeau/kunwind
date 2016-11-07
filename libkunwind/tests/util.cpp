/*
 * util.cpp
 *
 *  Created on: Nov 8, 2016
 *      Author: francis
 */

#include <unistd.h>
#include <sys/personality.h>

#include <iostream>

using namespace std;

/*
 * Re-execute without address randomization to get deterministic results. This
 * function calls exec on the first call and does not return. When called for
 * the second time, it returns immediately.
 */
void disable_aslr(int argc, char **argv)
{
	if (!getenv("NO_RANDOMIZE")) {
		cout << "exec without aslr" << endl;
		setenv("NO_RANDOMIZE", "1", 1);
		personality(ADDR_NO_RANDOMIZE);
		execve(argv[0], argv, environ);
	}
	cout << "aslr disabled" << endl;
}

