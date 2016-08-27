KUnwind: Fast user-space backtrace for Linux
============================================

This module aims at performing call stack unwind of user-space program from the kernel efficiently, both in time and space. It is similar to libunwind, but at the kernel level. One application is to obtain the call site of system calls in any program, transparently to the application. The unwinding is done from the kernel uniquely by examination of the process memory.

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

Otherwise, it can be tested with qemu + gdb. The script `debug.sh` helps for this purpose.

## About backtrace methods

Backtrace can be achieved with other techniques, but have some limitations:

* Frame pointers: Native code containing prologue for each function to save the frame pointer on the stack. The stack frames forms a linked list. This method is fast, simple and reliable, but most programs are compiled without frame pointers (`-fomit-frame-pointer`), which means that this method does not work in practice. Backtrace of a program without frame pointer requires to unwind the frames.
* [WAMS](https://github.com/giraldeau/wams): Using libunwind and ptrace, the child process is stopped at each system call. The monitor (parent) process unwinds the stack by peeking into the memory of child. This technique works but is terribly slow, each unwind takes miliseconds to complete.
* Last branch record (LBR) and processor trace (Intel PT, ARM CoreSight): These solution are hardware dependent.
* Offline unwind: The top of the stack is copied in a buffer for offline unwind. Requires to reconstrut the layout of libraries in memory after the execution. While the copy by itself may be fast, the resulting trace size is large and may contain sensitive information.
* Online unwind: The unwind is done while the program runs. The library libunwind is an implementation for user-space. The current project implements this technique, but at the kernel level.

## Todo

* To make it possible to unwind a program transparently to the application, a system to trigger the unwinding must be implemented. Right now, it is started by a system call from the unwinded application. Care must be taken to insure that the task's pt_regs struct is valid (esp. rbp), thus it can't be currently running or in a syscall fastpath. The current code assumes that the unwinded task is the "current" one.
* For system-wide profiling, sharing of module mappings must be implemented to avoid mapping every module multiple times in the kernel.
* A possible optimisation is to avoid restoring probably useless registers. This has been experimented [on this branch](https://github.com/fdoray/libunwind/commits/minimal_regs) of libunwind.
* Some of the code assumes 64 bit Elf structures and has to be generalized for portability (see [here](https://github.com/jabarszcz/kunwind/commit/6cb74be0128fb9115192f2f532a79d5d7b6550e5#diff-9a2cb919e6ea1bccb3346550a26ce2e9R199)).
* The module has only been tested on recent kernels on x86_64 machines. Further testing has to be done to ensure portability.
* The module cannot yet decide whether an unwinding has successfully reached the bottom of the stack. It reports success whether the backtrace is full or partial.