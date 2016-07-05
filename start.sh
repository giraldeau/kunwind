#!/bin/bash

mount -t proc none /proc
mount -t sysfs none /sys
insmod /opt/kunwind-debug.ko

/opt/test

sync
