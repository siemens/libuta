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

if TOOLS
bin_PROGRAMS = uta_get_passphrase
uta_get_passphrase_SOURCES = uta_get_passphrase_main.c
uta_get_passphrase_LDADD = ../../lib/libuta.la
endif

AUTOMAKE_OPTIONS = subdir-objects no-dependencies
