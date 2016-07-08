EXTRA_CFLAGS := -I$(src)/include

obj-$(CONFIG_KUNWIND) := kunwind.o
kunwind-y := src/kunwind.o

obj-$(CONFIG_KUNWIND_DEBUG) += kunwind-debug.o
kunwind-debug-y := src/kunwind-debug.o \
	src/kunwind-eh-frame.o \
	src/unwind.o

src/kunwind-eh-frame.o : src/kunwind-eh-frame.h src/kunwind-bug.h

$(src)/src/kunwind-debug.o : $(src)/include/proc_info.h
