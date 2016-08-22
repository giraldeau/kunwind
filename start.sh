#!/bin/bash

mount -t proc none /proc
mount -t sysfs none /sys
insmod /opt/kunwind-debug.ko

echo 0 | tee /proc/sys/kernel/randomize_va_space
export LD_LIBRARY_PATH=/usr/local/lib/:$LD_LIBRARY_PATH
/opt/test

sync
