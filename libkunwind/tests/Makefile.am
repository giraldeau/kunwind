AM_CXXFLAGS = -I$(top_builddir)/include -I$(top_builddir)/../include -rdynamic -std=c++14

check_PROGRAMS = test-basic

test_basic_SOURCES = test-basic.cpp
test_basic_LDADD = $(top_srcdir)/src/libkunwind.la -lunwind -ldl

TESTS = $(check_PROGRAMS)
