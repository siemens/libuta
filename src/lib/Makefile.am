# Unified Trust Anchor API
#
# Copyright (c) Siemens Mobility GmbH, 2020
#
# Authors:
#  Thomas Zeschg <thomas.zeschg@siemens.com>
#
# This work is licensed under the terms of the Apache Software License 2.0. See
# the LICENSE file in the top-level directory.
#
# SPDX-License-Identifier: Apache-2.0

AM_CPPFLAGS = -I$(top_srcdir)/include -Wall
lib_LTLIBRARIES = libuta.la
include_HEADERS = $(top_srcdir)/include/uta.h
noinst_HEADERS =  $(top_srcdir)/include/tpm_ibm.h \
	$(top_srcdir)/include/uta_sim.h $(top_srcdir)/include/tpm_tcg.h
libuta_la_SOURCES = uta.c
# -no-undefined needed for Cygwin
libuta_la_LDFLAGS = -version-number $(LT_VERSION_INFO) -no-undefined

if HW_BACKEND_UTA_SIM
# "relative" paths needed, because mbedtls is not part of the libuta
# distribution (otherwise 'make distcheck' would fail)
AM_CPPFLAGS += -I../mbedtls/include
libuta_la_SOURCES += uta_sim.c ../mbedtls/library/md.c \
	../mbedtls/library/sha256.c ../mbedtls/library/md_wrap.c \
	../mbedtls/library/platform_util.c ../mbedtls/library/ripemd160.c \
	../mbedtls/library/sha1.c ../mbedtls/library/md5.c \
	../mbedtls/library/sha512.c
endif

if HW_BACKEND_TPM_IBM
# include_HEADERS +=
libuta_la_SOURCES += tpm_ibm.c
endif

if HW_BACKEND_TPM_TCG
# include_HEADERS += 
libuta_la_SOURCES += tpm_tcg.c 
endif

AUTOMAKE_OPTIONS = subdir-objects no-dependencies


