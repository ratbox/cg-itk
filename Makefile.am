# vim: ts=4 sw=4
#
#	Copyright (C) 2017-2018 Aleksey Gerasimov
#
APXS=@APXS@
LIBS=@LIBS@

ACLOCAL_AMFLAGS=-I m4
CLEANFILES=*.la *.o *.slo

all:cg_itk.la

cg_itk.la:cg_itk.c
	$(APXS) -c $^ $(LIBS)

install-exec-local:cg_itk.la
	$(APXS) -i $^
