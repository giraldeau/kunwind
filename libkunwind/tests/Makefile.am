AM_CXXFLAGS = -I$(top_builddir)/include -I$(top_builddir)/../include -rdynamic -std=c++14

check_PROGRAMS = test-basic
noinst_PROGRAMS = $(check_PROGRAMS) test-benchmark test-unwind

test_basic_SOURCES = test-basic.cpp
test_basic_LDADD = $(top_srcdir)/src/libkunwind.la -lunwind -ldl

test_benchmark_SOURCES = test-benchmark.cpp
test_benchmark_LDADD = $(top_srcdir)/src/libkunwind.la

test_unwind_SOURCES = test-unwind.cpp 
test_unwind_LDADD = -lunwind -ldl libtest.a

noinst_LIBRARIES = libtest.a
libtest_a_SOURCES = foo.cpp foo.h util.cpp util.h

TESTS = $(check_PROGRAMS)
