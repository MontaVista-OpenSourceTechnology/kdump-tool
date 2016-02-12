bin_PROGRAMS = kdump-tool
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS=-Wall
kdump_tool_SOURCES = elfc.c kdump-tool.c list.c oldmem.c \
	kdump-x86_64.c kdump-i386.c kdump-mips.c kdump-arm.c kdump-ppc32.c
noinst_HEADERS = elfc.h kdump-tool.h list.h
man_MANS = kdump-tool.1
EXTRA_DIST = $(man_MANS)
