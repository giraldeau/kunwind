#include <stdlib.h>
#include <stdio.h>

#include "find_proc_info.h"

int main(int argc, char **argv)
{
	// Write proc info to file
	FILE *out = fopen("/proc/kunwind_debug", "r+");
	if (!out) {
		perror("Failed to open file");
		return 1;
	}

	proc_info_t *proc_info = find_proc_info();
	fwrite(proc_info, proc_info->size, 1, out);

	return 0;
}
