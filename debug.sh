#!/bin/sh -x

cat <<EOF > main.c 
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	printf("hello!\n");
	return 0;
}
EOF

gcc main.c

sudo mount linux.img mnt/
mkdir -p mnt/opt
sudo chown $USER mnt/opt
cp a.out mnt/opt
sudo umount linux.img

qemu-system-x86_64 \
    -hda linux.img \
    -serial stdio \
    -kernel ../linux/arch/x86/boot/bzImage \
    -virtfs local,path=/home/francis,mount_tag=host0,security_model=passthrough,id=host0 \
    -append "root=/dev/sda init=/opt/a.out console=ttyS0"
