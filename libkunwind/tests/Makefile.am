AM_CFLAGS = -I$(top_builddir)/include -I$(top_builddir)/../include

check_PROGRAMS = test-basic

test_basic_SOURCES = test-basic.c
test_basic_LDADD = $(top_srcdir)/src/libkunwind.la -lunwind

TESTS = $(check_PROGRAMS)
