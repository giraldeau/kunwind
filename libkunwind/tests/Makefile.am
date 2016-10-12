AM_CXXFLAGS = -I$(top_builddir)/include -I$(top_builddir)/../include -rdynamic -std=c++14

check_PROGRAMS = test-basic
noinst_PROGRAMS = test-benchmark

test_basic_SOURCES = test-basic.cpp
test_basic_LDADD = $(top_srcdir)/src/libkunwind.la -lunwind -ldl

test_benchmark_SOURCES = test-benchmark.cpp
test_benchmark_LDADD = $(top_srcdir)/src/libkunwind.la

TESTS = $(check_PROGRAMS)
