CC=gcc
CFLAGS=-g -I../include
SRCS=main.c find_proc_info.c
OBJS := ${SRCS:.c=.o}
PROGNAME=test

all : $(PROGNAME)

$(PROGNAME) : $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

clean:
	rm -f $(PROGNAME) $(OBJS) .depend

%.o: %.c
	$(CC) $(CFLAGS) -c $<

depend: .depend

.depend: $(SRCS)
	$(CC) $(CFLAGS) -MM $^ > .depend

include .depend
