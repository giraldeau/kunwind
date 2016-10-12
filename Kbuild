#EXTRA_CFLAGS := -I$(src)/include -DDEBUG_UNWIND=20
EXTRA_CFLAGS := -I$(src)/include

obj-$(CONFIG_KUNWIND) := kunwind.o
kunwind-y := src/kunwind.o

obj-$(CONFIG_KUNWIND_DEBUG) += kunwind-debug.o
kunwind-debug-y := src/kunwind-debug.o \
	src/modules.o \
	src/unwind.o \
	src/iterate_phdr.o

# TODO add deps on .h
