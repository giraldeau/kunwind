#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
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
