#!/bin/bash

# Uninstall the IBM stack
#
# Copyright (c) Siemens Mobility GmbH, 2020
# 
# Authors:
#  Thomas Zeschg <thomas.zeschg@siemens.com>
#
# This work is licensed under the terms of the Apache Software License 2.0.  See
# the LICENSE file in the top-level directory.           
#               
# SPDX-License-Identifier: Apache-2.0

echo "Uninstalling TPM IBM stack ..."

rm -r -f /var/lib/tpm_ibm
rm -r -f /usr/local/include/tss2
rm -f /usr/local/lib/libtss.so*
rm -f /etc/udev/rules.d/80-tpm-2.rules

echo "Uninstallation successful"
