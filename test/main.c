#include <stdlib.h>
#include <stdio.h>

#include "find_proc_info.h"

int hello(void)
{
	printf("hello!\n");
	FILE *f = fopen("/proc/kunwind_debug", "rw");
	if (!f) {
		printf("Failed to open file\n");
		return 1;
	}

	char buf[20] = "";
	size_t ret = fread(buf, sizeof(char), 20, f);

	printf("kunwind dit : %s\n", buf);
	return 0;
}

int main(int argc, char **argv)
{
	hello();

	// Write proc info to file
	FILE *out = fopen("./out.bin", "w");
	if (!out) {
		perror("Failed to open file");
		return 1;
	}

	proc_info_t *proc_info = find_proc_info();
	fwrite(proc_info, proc_info->size, 1, out);

	return 0;
}
