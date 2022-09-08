#!/bin/bash

# TPM IBM Provisioning script
#
# Copyright (c) Siemens Mobility GmbH, 2022
# 
# Authors:
#  Tugrul Yanik <tugrul.yanik@siemens.com>
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

# Configure IBM TSS (interface type and data dir must match
# the configuration of libuta).
export TPM_DEVICE="/dev/tpm0"
export TPM_DATA_DIR="/var/lib/tpm_ibm"
export TPM_INTERFACE_TYPE="dev"

# MS TPM Simulator
readonly TPM_SIMULATOR=0

# Function to print out error message and exit
by_error_print() {
  if [ $? -ne 0 ]
  then
    echo "$1"
    exit 1
  fi
}

NUMBER_OF_ARGUMENTS=$#

if [ $NUMBER_OF_ARGUMENTS -eq 0 ]; then
  echo "#############################"
  echo "TPM Provisioning:"
  echo "Key Slot 0: random"
  echo "Key Slot 1: random"
elif [ $NUMBER_OF_ARGUMENTS -eq 1 ]; then
  echo "#############################"
  echo "TPM Provisioning:"
  echo "Key Slot 0: $1"
  echo "Key Slot 1: random"
elif [ $NUMBER_OF_ARGUMENTS -eq 2 ]; then
  echo "#############################"
  echo "TPM Provisioning:"
  echo "Key Slot 0: $1"
  echo "Key Slot 1: $2"
else
  echo "Usage:"
  echo "TPM provisioning with random keys for slot0 and slot1:"
  echo "$0"
  echo ""
  echo "TPM provisioning with external key for slot0 and random key for slot1"
  echo "$0 <key0_file.bin>"
  echo ""
  echo "TPM provisioning with external keys for slot0 and slot1"
  echo "$0 <key0_file.bin> <key1_file.bin>"
  exit 1
fi
echo "#############################"

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

# Try to clear the needed key slots
echo ""
echo "# Removing possible persistent keys..."
tssevictcontrol -ho $HMAC_KEY0 -hp $HMAC_KEY0 -hi $HIERARCHY
tssevictcontrol -ho $HMAC_KEY1 -hp $HMAC_KEY1 -hi $HIERARCHY
tssevictcontrol -ho $ECC -hp $ECC -hi $HIERARCHY

# Create a TPM key hierarchy
echo ""
echo "# Creating storage primary key..."
FUNC_OUTPUT=$(tsscreateprimary -hi $HIERARCHY -ecc nistp256)
by_error_print "Failed to create the storage primary key, exit..."

# Parse out the handle address
STORAGE_PKEY_HANDLE=$(echo $FUNC_OUTPUT |tr -cd '[[:digit:]]')

echo "Handle $STORAGE_PKEY_HANDLE"

# Create an ECC key and make it persistent
echo ""
echo "# Creating an ECC key under the storage key..."
tsscreate -hp $STORAGE_PKEY_HANDLE -ecc nistp256 -den -kt f -kt p -opu ecc_pub_key.bin -opr ecc_priv_key.bin
by_error_print "Failed to create the ECC key, exit..."

echo ""
echo "# Loading ECC key..."
FUNC_OUTPUT=$(tssload -hp $STORAGE_PKEY_HANDLE -ipr ecc_priv_key.bin -ipu ecc_pub_key.bin)
by_error_print "Failed to load the ECC key, exit..."

# Parse out the handle address for the ECC key
GENERAL_KEY_HANDLE=$(echo $FUNC_OUTPUT |tr -cd '[[:digit:]]')

echo "Handle $GENERAL_KEY_HANDLE"
echo ""
echo "# Making ECC key persistent..."
tssevictcontrol -ho $GENERAL_KEY_HANDLE -hp $ECC -hi $HIERARCHY
by_error_print "Failed in making the ECC key persistent, exit..."

echo ""
echo "# Flushing the transient ECC key..."
tssflushcontext -ha $GENERAL_KEY_HANDLE
by_error_print "Failed to flush the transient ECC key, exit..."

# Load the HMAC Key0 into the TPM and make it persistent
# If the key0.bin file is present the key will be constructed from this file and loaded as an external key
if [ $NUMBER_OF_ARGUMENTS -gt 0 ]
then
  if [ -s "$1" ]
  then
     echo ""
     echo "# Create random seed for HMAC key hash..."
     tssgetrandom -by 32 -of hmac_seed.bin
     by_error_print "Failed to create random seed for HMAC key hash, exit..."
  
     echo ""
     echo "# Calculate sha256(SEED||KEY)..."
     cat hmac_seed.bin $1 | openssl dgst -sha256 -binary > hmac_key_hash.bin

     echo ""
     echo "# Loading custom HMAC key..."
     uta_custom_hmac_key $1
     by_error_print "Failed to load custom HMAC key, exit..."

     echo ""
     echo "# Starting policy session..."
     FUNC_OUTPUT=$(tssstartauthsession -se p)
     by_error_print "Failed to start policy session, exit..."

     # Parse out handle address for policy session
     POLICY_HANDLE=$(echo $FUNC_OUTPUT |tr -cd '[[:digit:]]')

     echo "Handle $POLICY_HANDLE"
     echo ""
     echo "# Limiting authorization to duplication command..."
     tsspolicycommandcode -ha $POLICY_HANDLE -cc 14b
     by_error_print "Failed to restrict authorization to duplication command, exit..."

     echo ""
     echo "# Getting random AES encryption key..."
     tssgetrandom -by 16 -of tmp_aes_rnd.bin
     by_error_print "Failed to create random AES encryption key, exit..."

     echo ""
     echo "# Duplicating HMAC key to storage key..."
     tssduplicate -ho $GENERAL_KEY_HANDLE -hp $STORAGE_PKEY_HANDLE -od tmp_dup_priv.bin -oss tmp_dup_seed.bin -salg aes -ik tmp_aes_rnd.bin -se0 $POLICY_HANDLE 1
     by_error_print "Failed to duplicate HMAC key to storage key, exit..."

     echo ""
     echo "# Flushing HMAC key context to free object slot for import..."
     tssflushcontext -ha $GENERAL_KEY_HANDLE
     by_error_print "Failed to flush HMAC key context to free object slot, exit..."

     echo ""
     echo "# Importing duplicated HMAC key under storage key..."
     tssimport -hp $STORAGE_PKEY_HANDLE -ipu hmac_key_pub.bin -id tmp_dup_priv.bin -iss tmp_dup_seed.bin -salg aes -ik tmp_aes_rnd.bin -opr hmac_key_priv.bin
     by_error_print "Failed to import duplicated HMAC key, exit..."

     echo ""
     echo "# Loading duplicated HMAC key..."
     FUNC_OUTPUT=$(tssload -hp $STORAGE_PKEY_HANDLE -ipr hmac_key_priv.bin -ipu hmac_key_pub.bin)
     by_error_print "Failed to load duplicated HMAC key, exit..."

     # Parse out handle address for loaded key
     GENERAL_KEY_HANDLE=$(echo $FUNC_OUTPUT |tr -cd '[[:digit:]]')

     echo "Handle $GENERAL_KEY_HANDLE"
     echo ""
     echo "# Making duplicated HMAC key persistent..."
     tssevictcontrol -ho $GENERAL_KEY_HANDLE -hp $HMAC_KEY0 -hi $HIERARCHY
     by_error_print "Failed to make duplicated HMAC key persistent, exit..."
  
     echo ""
     echo "# Flushing the transient HMAC key0..."
     tssflushcontext -ha $GENERAL_KEY_HANDLE
     by_error_print "Failed to flush transient HMAC key0, exit..."

     echo ""
     echo "# Flushing Policy Session..."
     tssflushcontext -ha $POLICY_HANDLE
     by_error_print "Failed to flush policy session, exit..."

     echo ""
     echo "# Removing temporary files..."
     rm -f tmp_aes_rnd.bin tmp_dup_priv.bin tmp_dup_seed.bin 
     rm -f hmac_key_hash.bin hmac_seed.bin
   else
     echo ""
     echo "invalid key file $1 was given as argument, exit..."
     exit 1
   fi
else #the key0.bin file is not given, the TPM generates a HMAC key by itself 

  echo ""
  echo "# Creating HMAC key0..."

  tsscreate -hp $STORAGE_PKEY_HANDLE -kh -kt f -kt p -opu hmac_key_pub.bin -opr hmac_key_priv.bin
  by_error_print "Failed to create the HMAC key, exit..."

  echo ""
  echo "# Loading HMAC key0..."
  FUNC_OUTPUT=$(tssload -hp $STORAGE_PKEY_HANDLE -ipr hmac_key_priv.bin -ipu hmac_key_pub.bin)
  by_error_print "Failed to load the HMAC key0, exit..."

  # Parse out the handle address for the ECC key
  HMAC_KEY_HANDLE=$(echo $FUNC_OUTPUT |tr -cd '[[:digit:]]')

  echo "Handle $HMAC_KEY_HANDLE"


  echo ""
  echo "# Making HMAC key0 persistent..."
  tssevictcontrol -ho $HMAC_KEY_HANDLE -hp $HMAC_KEY0 -hi $HIERARCHY
  by_error_print "Failed in making the HMAC key0 persistent, exit..."

  echo ""
  echo "# Flushing the transient HMAC key0..."
  tssflushcontext -ha $HMAC_KEY_HANDLE
  by_error_print "Failed to flush the transient HMAC key0, exit..."
fi

# Load the HMAC Key1 into the TPM and make it persistent
# If the key1.bin file is present the key will be constructed from this file and loaded as an external key
if [ $NUMBER_OF_ARGUMENTS -eq 2 ]
then
  if [ -s "$2" ]
  then
     echo ""
     echo "# Create random seed for HMAC key hash..."
     tssgetrandom -by 32 -of hmac_seed.bin
     by_error_print "Failed to create random seed for HMAC key hash, exit..."

     echo ""
     echo "# Calculate sha256(SEED||KEY)..."
     cat hmac_seed.bin $2 | openssl dgst -sha256 -binary > hmac_key_hash.bin

     echo ""
     echo "# Loading custom HMAC key..."
     uta_custom_hmac_key $2
     by_error_print "Failed to load custom HMAC key, exit..."

     echo ""
     echo "# Starting policy session..."
     FUNC_OUTPUT=$(tssstartauthsession -se p)
     by_error_print "Failed to start policy session, exit..."

     # Parse out handle address for policy session
     POLICY_HANDLE=$(echo $FUNC_OUTPUT |tr -cd '[[:digit:]]')

     echo "Handle $POLICY_HANDLE"
     echo ""
     echo "# Limiting authorization to duplication command..."
     tsspolicycommandcode -ha $POLICY_HANDLE -cc 14b
     by_error_print "Failed to restrict authorization to duplication command, exit..."

     echo ""
     echo "# Getting random AES encryption key..."
     tssgetrandom -by 16 -of tmp_aes_rnd.bin
     by_error_print "Failed to create random AES encryption key, exit..."

     echo ""
     echo "# Duplicating HMAC key to storage key..."
     tssduplicate -ho $GENERAL_KEY_HANDLE -hp $STORAGE_PKEY_HANDLE -od tmp_dup_priv.bin -oss tmp_dup_seed.bin -salg aes -ik tmp_aes_rnd.bin -se0 $POLICY_HANDLE 1
     by_error_print "Failed to duplicate HMAC key to storage key, exit..."

     echo ""
     echo "# Flushing HMAC key context to free object slot for import..."
     tssflushcontext -ha $GENERAL_KEY_HANDLE
     by_error_print "Failed to flush HMAC key context to free object slot, exit..."

     echo ""
     echo "# Importing duplicated HMAC key under storage key..."
     tssimport -hp $STORAGE_PKEY_HANDLE -ipu hmac_key_pub.bin -id tmp_dup_priv.bin -iss tmp_dup_seed.bin -salg aes -ik tmp_aes_rnd.bin -opr hmac_key_priv.bin
     by_error_print "Failed to import duplicated HMAC key, exit..."

     echo ""
     echo "# Loading duplicated HMAC key..."
     FUNC_OUTPUT=$(tssload -hp $STORAGE_PKEY_HANDLE -ipr hmac_key_priv.bin -ipu hmac_key_pub.bin)
     by_error_print "Failed to load duplicated HMAC key, exit..."

     # Parse out handle address for loaded key
     GENERAL_KEY_HANDLE=$(echo $FUNC_OUTPUT |tr -cd '[[:digit:]]')

     echo "Handle $GENERAL_KEY_HANDLE"
     echo ""
     echo "# Making duplicated HMAC key persistent..."
     tssevictcontrol -ho $GENERAL_KEY_HANDLE -hp $HMAC_KEY1 -hi $HIERARCHY
     by_error_print "Failed to make duplicated HMAC key persistent, exit..."

     echo ""
     echo "# Flushing the transient HMAC key1..."
     tssflushcontext -ha $GENERAL_KEY_HANDLE
     by_error_print "Failed to flush transient HMAC key1, exit..."

     echo ""
     echo "# Flushing Policy Session..."
     tssflushcontext -ha $POLICY_HANDLE
     by_error_print "Failed to flush policy session, exit..."

     echo ""
     echo "# Removing temporary files..."
     rm -f tmp_aes_rnd.bin tmp_dup_priv.bin tmp_dup_seed.bin 
     rm -f hmac_key_hash.bin hmac_seed.bin
  else
     echo ""
     echo "invalid key file $2 was given as argument, exit..."
     exit 1
  fi
else #the key1.bin file is not given, the TPM generates a HMAC key by itself 

  echo ""
  echo "# Creating HMAC key1..."

  tsscreate -hp $STORAGE_PKEY_HANDLE -kh -kt f -kt p -opu hmac_key_pub.bin -opr hmac_key_priv.bin
  by_error_print "Failed to create the HMAC key, exit..."

  echo ""
  echo "# Loading HMAC key1..."
  FUNC_OUTPUT=$(tssload -hp $STORAGE_PKEY_HANDLE -ipr hmac_key_priv.bin -ipu hmac_key_pub.bin)
  by_error_print "Failed to load the HMAC key1, exit..."

  # Parse out the handle address for the ECC key
  HMAC_KEY_HANDLE=$(echo $FUNC_OUTPUT |tr -cd '[[:digit:]]')

  echo "Handle $HMAC_KEY_HANDLE"


  echo ""
  echo "# Making HMAC key1 persistent..."
  tssevictcontrol -ho $HMAC_KEY_HANDLE -hp $HMAC_KEY1 -hi $HIERARCHY
  by_error_print "Failed in making the HMAC key1 persistent, exit..."

  echo ""
  echo "# Flushing the transient HMAC key1..."
  tssflushcontext -ha $HMAC_KEY_HANDLE
  by_error_print "Failed to flush the transient HMAC key1, exit..."
fi

echo ""
echo "# Flushing Storage Key..."
tssflushcontext -ha $STORAGE_PKEY_HANDLE
by_error_print "Failed to flush storage key, exit..."

if [ $TPM_SIMULATOR = 1 ]; then
  echo ""
  echo "# Shutting TPM down..."
  tssshutdown
  by_error_print "Failed to shutdown, exit..."
fi

echo ""
echo "# Removing temporary files..."
rm -f ecc_priv_key.bin ecc_pub_key.bin storage_key_priv.bin storage_key_pub.bin
rm -f hmac_key_priv.bin hmac_key_pub.bin


if [ $NUMBER_OF_ARGUMENTS -eq 1 ]
then
  echo ""
  echo "# Remove $1 from file system? (Y/n)"
  read answer

  if echo "$answer" | grep -iq "^n" ;then
	echo "# ATTENTION: $1 not removed!"
  else
	echo "# Removing $1..."
    rm -f $1
  fi
elif [ $NUMBER_OF_ARGUMENTS -eq 2 ]
then
  echo ""
  echo "# Remove $1 and $2 from file system? (Y/n)"
  read answer

  if echo "$answer" | grep -iq "^n" ;then
	echo "# ATTENTION: $1 and $2 not removed!"
  else
	echo "# Removing $1 and $2..."
    rm -f $1 $2
  fi
fi
