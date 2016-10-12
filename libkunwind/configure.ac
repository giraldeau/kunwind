AC_PREREQ([2.69])
AC_INIT([kunwind], [0.0.0], [jalex_b at hotmail dot com])

AC_CONFIG_SRCDIR([src/libkunwind.c])
AC_CONFIG_HEADERS([src/autoconf.h])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([config])

AM_INIT_AUTOMAKE([foreign -Wall -Werror -Wno-extra-portability])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MAKE_SET

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdio.h unistd.h sys/ioctl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_MALLOC

AC_CONFIG_FILES([Makefile
    src/Makefile
    tests/Makefile
])

LT_INIT
AC_OUTPUT
