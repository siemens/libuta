#!/bin/bash

# Install the IBM stack
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

echo "Installing TPM IBM stack ..."

mkdir -p /var/lib/tpm_ibm
chown root:tpm /var/lib/tpm_ibm
chmod 0770 /var/lib/tpm_ibm
cp -r tss2 /usr/local/include
cp -P libtss.so* /usr/local/lib

cat <<EOF >/etc/udev/rules.d/80-tpm-2.rules
KERNEL=="tpm[0-9]*", MODE="0660", OWNER="root", GROUP="tpm"
EOF

echo "Installation successful"
