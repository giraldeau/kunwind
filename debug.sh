#!/usr/bin/env bash

function usage {
    echo "Usage : $0 kernel_image_path [ virtfs_path ]"
}

if [[ "$#" -lt 1 ]]; then
    usage
    echo "Looking for images :"
    RES=$(find .. -name bzImage -type f 2> /dev/null)
    if [[ -z $RES ]]; then
	echo "    none found"
    else
	echo $RES
    fi
    exit 1
elif [[ "$#" -gt 2 ]]; then
    usage
    exit 1
elif [[ "$#" -eq 2 ]]; then
    QEMU_VIRTFS_ARGS="-virtfs local,path=$2,mount_tag=host0,security_model=passthrough,id=host0"
fi

KERNEL_IMAGE_PATH=$1

set -x

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
    -no-reboot \
    -nographic \
    -kernel $KERNEL_IMAGE_PATH \
    $QEMU_VIRTFS_ARGS \
    -append "root=/dev/sda init=/opt/a.out console=ttyS0 panic=1" \
    -s

# starts gdb server on localhost:1234
# hook from client with: target remote localhost:1234
