# Unified Trust Anchor API
#
# Copyright (c) Siemens Mobility GmbH, 2020
#
# Authors:
#  Thomas Zeschg <thomas.zeschg@siemens.com>
#
# This work is licensed under the terms of the Apache Software License 2.0. See
# the COPYING file in the top-level directory.
#
# SPDX-License-Identifier: Apache-2.0

AM_CPPFLAGS = -I$(top_srcdir)/include -Wall

if TOOLS
bin_PROGRAMS = uta_reg_test
# "relative" paths needed, because mbedtls is not part of the libuta
# distribution (otherwise 'make distcheck' would fail)
AM_CPPFLAGS += -I../../mbedtls/include
uta_reg_test_SOURCES = uta_reg_test_main.c ../../mbedtls/library/md.c \
	../../mbedtls/library/sha256.c ../../mbedtls/library/md_wrap.c \
	../../mbedtls/library/platform_util.c ../../mbedtls/library/ripemd160.c \
	../../mbedtls/library/sha1.c ../../mbedtls/library/md5.c \
	../../mbedtls/library/sha512.c
uta_reg_test_LDADD = ../../lib/libuta.la
endif

AUTOMAKE_OPTIONS = subdir-objects no-dependencies

