#!/bin/bash

# TPM IBM Provisioning script
#
# Copyright (c) Siemens Mobility GmbH, 2020
# 
# Authors:
#  Thomas Zeschg <thomas.zeschg@siemens.com>
#
# This work is licensed under the terms of the Apache Software License 2.0.  See
# the COPYING file in the top-level directory.           
#               
# SPDX-License-Identifier: Apache-2.0

# DEFINES
# Hierarchy endorsment e, platform p, owner o, null n
readonly HIERARCHY=o

# Key slots
readonly HMAC_KEY0=81000000
readonly HMAC_KEY1=81000001
readonly ECC=81000002

# MS TPM Simulator
readonly TPM_SIMULATOR=0

echo "########################################"
echo "###   Provisioning  of the TPM       ###"
echo "########################################"

echo ""
echo "------------ PROVISIONING ------------"

if [ $TPM_SIMULATOR = 1 ]; then
echo ""
echo "# Powering TPM up..."
tsspowerup

echo ""
echo "# Starting TPM..."
tssstartup
fi

# Define a key for the session state encryption
export TPM_SESSION_ENCKEY=`tssgetrandom -by 16 -ns`
export TPM_DEVICE="/dev/tpm0"

# Try to clear the needed key slots
echo ""
echo "# Removing possible persistent keys..."
tssevictcontrol -ho $HMAC_KEY0 -hp $HMAC_KEY0 -hi $HIERARCHY
tssevictcontrol -ho $HMAC_KEY1 -hp $HMAC_KEY1 -hi $HIERARCHY
tssevictcontrol -ho $ECC -hp $ECC -hi $HIERARCHY

# Create a TPM key hierarchy
echo ""
echo "# Creating storage primary key..."
tsscreateprimary -hi $HIERARCHY -ecc nistp256

# Create an ECC key and make it persistent
echo ""
echo "# Creating an ECC key under the storage key..."
tsscreate -hp 80000000 -ecc nistp256 -den -kt f -kt p -opu ecc_pub_key.bin -opr ecc_priv_key.bin

echo ""
echo "# Loading ECC key..."
tssload -hp 80000000 -ipr ecc_priv_key.bin -ipu ecc_pub_key.bin

echo ""
echo "# Making ECC key persistent..."
tssevictcontrol -ho 80000001 -hp $ECC -hi $HIERARCHY

echo ""
echo "# Flushing the transient ECC key..."
tssflushcontext -ha 80000001

# Load the HMAC Key0 into the TPM and make it persistent
echo ""
echo "# Create random seed for HMAC key hash..."
tssgetrandom -by 32 -of hmac_seed.bin

echo ""
echo "# Calculate sha256(SEED||KEY)..."
cat hmac_seed.bin key0.bin | openssl dgst -sha256 -binary > hmac_key_hash.bin

echo ""
echo "# Loading custom HMAC key..."
uta_custom_hmac_key key0.bin

echo ""
echo "# Starting policy session..."
tssstartauthsession -se p

echo ""
echo "# Limiting authorization to duplication command..."
tsspolicycommandcode -ha 03000000 -cc 14b

echo ""
echo "# Getting random AES encryption key..."
tssgetrandom -by 16 -of tmp_aes_rnd.bin

echo ""
echo "# Duplicating HMAC key to storage key..."
tssduplicate -ho 80000001 -hp 80000000 -od tmp_dup_priv.bin -oss tmp_dup_seed.bin -salg aes -ik tmp_aes_rnd.bin -se0 03000000 1

echo ""
echo "# Flushing HMAC key context to free object slot for import..."
tssflushcontext -ha 80000001

echo ""
echo "# Importing duplicated HMAC key under storage key..."
tssimport -hp 80000000 -ipu hmac_key_pub.bin -id tmp_dup_priv.bin -iss tmp_dup_seed.bin -salg aes -ik tmp_aes_rnd.bin -opr hmac_key_priv.bin

echo ""
echo "# Loading duplicated HMAC key..."
tssload -hp 80000000 -ipr hmac_key_priv.bin -ipu hmac_key_pub.bin

echo ""
echo "# Making duplicated HMAC key persistent..."
tssevictcontrol -ho 80000001 -hp $HMAC_KEY0 -hi $HIERARCHY

echo ""
echo "# Flushing the transient HMAC key0..."
tssflushcontext -ha 80000001

echo ""
echo "# Flushing Policy Session..."
tssflushcontext -ha 03000000

# Load the HMAC Key1 into the TPM and make it persistent
echo ""
echo "# Create random seed for HMAC key hash..."
tssgetrandom -by 32 -of hmac_seed.bin

echo ""
echo "# Calculate sha256(SEED||KEY)..."
cat hmac_seed.bin key1.bin | openssl dgst -sha256 -binary > hmac_key_hash.bin

echo ""
echo "# Loading custom HMAC key..."
uta_custom_hmac_key key1.bin

echo ""
echo "# Starting policy session..."
tssstartauthsession -se p

echo ""
echo "# Limiting authorization to duplication command..."
tsspolicycommandcode -ha 03000000 -cc 14b

echo ""
echo "# Getting random AES encryption key..."
tssgetrandom -by 16 -of tmp_aes_rnd.bin

echo ""
echo "# Duplicating HMAC key to storage key..."
tssduplicate -ho 80000001 -hp 80000000 -od tmp_dup_priv.bin -oss tmp_dup_seed.bin -salg aes -ik tmp_aes_rnd.bin -se0 03000000 1

echo ""
echo "# Flushing HMAC key context to free object slot for import..."
tssflushcontext -ha 80000001

echo ""
echo "# Importing duplicated HMAC key under storage key..."
tssimport -hp 80000000 -ipu hmac_key_pub.bin -id tmp_dup_priv.bin -iss tmp_dup_seed.bin -salg aes -ik tmp_aes_rnd.bin -opr hmac_key_priv.bin

echo ""
echo "# Loading duplicated HMAC key..."
tssload -hp 80000000 -ipr hmac_key_priv.bin -ipu hmac_key_pub.bin

echo ""
echo "# Making duplicated HMAC key persistent..."
tssevictcontrol -ho 80000001 -hp $HMAC_KEY1 -hi $HIERARCHY

echo ""
echo "# Flushing the transient HMAC key1..."
tssflushcontext -ha 80000001

echo ""
echo "# Flushing Storage Key..."
tssflushcontext -ha 80000000

echo ""
echo "# Flushing Policy Session..."
tssflushcontext -ha 03000000

if [ $TPM_SIMULATOR = 1 ]; then
echo ""
echo "# Shutting TPM down..."
tssshutdown
fi

echo ""
echo "# Removing temporary files..."
rm -f tmp_aes_rnd.bin tmp_dup_priv.bin tmp_dup_seed.bin ecc_priv_key.bin
rm -f hmac_key_hash.bin hmac_seed.bin
rm -f hmac_key_priv.bin hmac_key_pub.bin ecc_pub_key.bin storage_key_priv.bin storage_key_pub.bin

echo ""
echo "# Remove key0.bin and key1.bin? (Y/n)"
read answer

if echo "$answer" | grep -iq "^n" ;then
	echo "# ATTENTION: key0.bin and key1.bin not removed!"
else
	echo "# Removing key0.bin and key1.bin..."
    rm -f key0.bin key1.bin
fi

