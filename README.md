KUnwind: Fast user-space backtrace for Linux
============================================

This module aims at performing call stack unwind of user-space program from the kernel efficiently, both in time and space. It is similar to libunwind, but at the kernel level. One application is to obtain the call site of system calls in a program.

## Compile for user-mode linux

For development purpose, it is useful to compile and run the module with user-mode linux.

```
# add kunwind to the kernel tree
cd kunwind/
./built-in.sh <path to linux sources>

# configure the kernel
cd <path to linux sources>
make ARCH=um defconfig

# modify the config to set CONFIG_KUNWIND=y
make ARCH=um menuconfig

# compile
make ARCH=um

# run
./linux rootfstype=hostfs rw init=/bin/bash

```

## About backtrace methods

Backtrace can be achieved with other techniques, but have some limitations:

* Frame pointers: Native code containing prologue for each function to save the frame pointer on the stack. The stack frames forms a linked list. This method is fast, simple and reliable, but most programs are compiled without frame pointers (`-fomit-frame-pointer`), which means that this method does not work in practice. Backtrace of a program without frame pointer requires to unwind the frames.
* [WAMS](https://github.com/giraldeau/wams): Using libunwind and ptrace, the child process is stopped at each system call. The monitor (parent) process unwinds the stack by peeking into the memory of child. This technique works but is terribly slow, each unwind takes miliseconds to complete.
* Last branch record (LBR) and processor trace (Intel PT, ARM CoreSight): These solution are hardware dependent.
* Offline unwind: The top of the stack is copied in a buffer for offline unwind. Requires to reconstrut the layout of libraries in memory after the execution. While the copy by itself may be fast, the resulting trace size is large and may contain sensitive information.
* Online unwind: The unwind is done while the program runs. The library libunwind is an implementation for user-space. The current project implements this technique, but at the kernel level.
