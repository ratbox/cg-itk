dnl configure.ac: autoconf input script
dnl
dnl  Copyright (C) 2017-2018 Aleksey Gerasimov
dnl
AC_PREREQ([2.69])

AC_INIT([cg-itk], [1.0], [enclaved@vanillablood.art])
AC_COPYRIGHT([Copyright (C) 2017-2018 Aleksey Gerasimov])

AM_INIT_AUTOMAKE([foreign])
AM_CONFIG_HEADER([config.h])

AC_LANG([C])
AC_PROG_CC

AC_CANONICAL_HOST
AC_CONFIG_SRCDIR([cg_itk.c])
AC_CONFIG_FILES([Makefile])

AX_WITH_APXS([apxs])

AC_CHECK_FUNCS([setproctitle], [], [
	AC_CHECK_LIB([bsd], [setproctitle])
])
AC_CHECK_LIB([cap], [cap_set_proc])

AC_FUNC_GETPGRP
AC_FUNC_SETPGRP

AX_GCC_FUNC_ATTRIBUTE([noreturn])
AX_GCC_FUNC_ATTRIBUTE([nonnull])
AX_GCC_FUNC_ATTRIBUTE([hot])
AX_GCC_FUNC_ATTRIBUTE([cold])
AX_GCC_FUNC_ATTRIBUTE([always_inline])

AC_OUTPUT

AC_MSG_RESULT([
$PACKAGE_STRING
Report bugs to <$PACKAGE_BUGREPORT>

Source configured.  Run 'make' to build.])
