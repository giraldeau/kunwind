#!/bin/bash

mount -t proc none /proc
mount -t sysfs none /sys
insmod /opt/kunwind-debug.ko

echo 0 | tee /proc/sys/kernel/randomize_va_space
/opt/test

sync
