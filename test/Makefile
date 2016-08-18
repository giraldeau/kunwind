CC=gcc
CFLAGS=-g -I../libkunwind/include -I../include -rdynamic
LDFLAGS=-lkunwind
SRCS=main.c
OBJS := ${SRCS:.c=.o}
PROGNAME=test

all : $(PROGNAME)

$(PROGNAME) : $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $@

clean:
	rm -f $(PROGNAME) $(OBJS) .depend

%.o: %.c
	$(CC) $(CFLAGS) -c $<

depend: .depend

.depend: $(SRCS)
	$(CC) $(CFLAGS) -MM $^ > .depend

include .depend
