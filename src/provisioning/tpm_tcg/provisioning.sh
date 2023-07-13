#!/bin/bash

# TPM TCG Provisioning script
#
# Copyright (c) Siemens Mobility GmbH, 2023
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
readonly HMAC_KEY0=0x81000000
readonly HMAC_KEY1=0x81000001
readonly ECC=0x81000002

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

# Try to clear the needed key slots
echo ""
echo "# Removing possible persistent keys..."

PERSISTENT_HANDLES=$(tpm2_getcap handles-persistent)
echo $PERSISTENT_HANDLES


if [[ "$PERSISTENT_HANDLES" == *"$HMAC_KEY0"* ]]; then
   tpm2_evictcontrol -C $HIERARCHY -c $HMAC_KEY0
fi
if [[ "$PERSISTENT_HANDLES" == *"$HMAC_KEY1"* ]]; then
   tpm2_evictcontrol -C $HIERARCHY -c $HMAC_KEY1
fi
if [[ "$PERSISTENT_HANDLES" == *"$ECC"* ]]; then
   tpm2_evictcontrol -C $HIERARCHY -c $ECC
fi

# Create a TPM key hierarchy
echo ""
echo "# Creating storage primary key..."
tpm2_createprimary -C $HIERARCHY -G ecc256 -c primaryKey
by_error_print "Failed to create the storage primary key, exit..."

# Create an ECC key and make it persistent
echo ""
echo "# Creating an ECC key under the storage key..."

CREATELOADEDSUPPORT=$(tpm2_getcap commands | grep -i createloaded)

if [ ! -z $CREATELOADEDSUPPORT ]
then
   echo ""
   echo "# TPM2_CC_CreateLoaded command supported..."
   tpm2_create -G ecc256 -C primaryKey -u ecc_pub_key.bin -r ecc_priv_key.bin -c loadedKey
   by_error_print "Failed to create the ECC key, exit..."
else  #TPM2_CC_CreateLoaded command not supported, need to load with load command
   tpm2_create -G ecc256 -C primaryKey -u ecc_pub_key.bin -r ecc_priv_key.bin
   by_error_print "Failed to create the ECC key, exit..."

   echo ""
   echo "# Loading ECC key..."
   tpm2_load -C primaryKey -u ecc_pub_key.bin -r ecc_priv_key.bin -c loadedKey
   by_error_print "Failed to load the ECC key, exit..."
fi

echo ""
echo "# Making ECC key persistent..."
tpm2_evictcontrol -C $HIERARCHY -c loadedKey $ECC
by_error_print "Failed in making the ECC key persistent, exit..."


# Load the HMAC Key0 into the TPM and make it persistent
# If the key0.bin file is present the key will be constructed from this file and loaded as an external key
if [ $NUMBER_OF_ARGUMENTS -gt 0 ]
then
   if [ -s "$1" ]
   then
      echo ""
      echo "# Importing custom HMAC key0..."
      tpm2_import -C primaryKey -G hmac -i $1 -u hmac.pub -r hmac.priv
      by_error_print "Failed to load custom HMAC key, exit..."

      echo ""
      echo "Loading custom HMAC key..."
      tpm2_load -C primaryKey -u hmac.pub -r hmac.priv -c loadedHMACKey0

      echo ""
      echo "# Making HMAC key0 persistent..."
      tpm2_evictcontrol -C $HIERARCHY -c loadedHMACKey0 $HMAC_KEY0
      by_error_print "Failed in making the HMAC key0 persistent, exit.."

      echo ""
      echo "# Removing temporary files..."
      rm -f hmac.pub hmac.priv
   else
      echo ""
      echo "invalid key file $1 was given as argument, exit..."
      exit 1
   fi
else #the key0.bin file is not given, the TPM generates a HMAC key by itself

   echo ""
   echo "# Creating HMAC key0..."
   if [ ! -z $CREATELOADEDSUPPORT ]
   then
      tpm2_create -G hmac -C primaryKey -u hmac_key_pub.bin -r hmac_key_priv.bin -c loadedHMACKey0
      by_error_print "Failed to create the HMAC key, exit..."
   else
      tpm2_create -G hmac -C primaryKey -u hmac_key_pub.bin -r hmac_key_priv.bin
      by_error_print "Failed to create the HMAC key, exit..."
      echo ""
      echo "# Loading HMAC key0..."
      tpm2_load -C primaryKey -u hmac_key_pub.bin -r hmac_key_priv.bin -c loadedHMACKey0
      by_error_print "Failed to load the HMAC key, exit..."
   fi

   echo ""
   echo "# Making HMAC key0 persistent..."
   tpm2_evictcontrol -C $HIERARCHY -c loadedHMACKey0 $HMAC_KEY0
   by_error_print "Failed in making the HMAC key0 persistent, exit..."
fi

# Load the HMAC Key1 into the TPM and make it persistent
# If the key1.bin file is present the key will be constructed from this file and loaded as an external key
if [ $NUMBER_OF_ARGUMENTS -eq 2 ]
then
   if [ -s "$2" ]
   then
      echo ""
      echo "# Importing custom HMAC key1..."
      tpm2_import -C primaryKey -G hmac -i $2 -u hmac.pub -r hmac.priv
      by_error_print "Failed to load custom HMAC key, exit..."

      echo ""
      echo "Loading custom HMAC key..."
      tpm2_load -C primaryKey -u hmac.pub -r hmac.priv -c loadedHMACKey1

      echo ""
      echo "# Making HMAC key0 persistent..."
      tpm2_evictcontrol -C $HIERARCHY -c loadedHMACKey1 $HMAC_KEY1
      by_error_print "Failed in making the HMAC key0 persistent, exit.."

      echo ""
      echo "# Removing temporary files..."
      rm -f hmac.pub hmac.priv
   else
      echo ""
      echo "invalid key file $1 was given as argument, exit..."
      exit 1
   fi

else #the key1.bin file is not given, the TPM generates a HMAC key by itself

   echo ""
   echo "# Creating HMAC key1..."

   if [ ! -z $CREATELOADEDSUPPORT ]
   then
      tpm2_create -G hmac -C primaryKey -u hmac_key_pub.bin -r hmac_key_priv.bin -c loadedHMACKey1
      by_error_print "Failed to create the HMAC key, exit..."
   else
      tpm2_create -G hmac -C primaryKey -u hmac_key_pub.bin -r hmac_key_priv.bin
      by_error_print "Failed to create the HMAC key, exit..."
      echo ""
      echo "# Loading HMAC key1..."
      tpm2_load -C primaryKey -u hmac_key_pub.bin -r hmac_key_priv.bin -c loadedHMACKey1
      by_error_print "Failed to load the HMAC key, exit..."
   fi

   echo ""
   echo "# Making HMAC key1 persistent..."
   tpm2_evictcontrol -C $HIERARCHY -c loadedHMACKey1 $HMAC_KEY1
   by_error_print "Failed in making the HMAC key1 persistent, exit..."
fi

echo ""
echo "# Flushing all transient objects..."
tpm2_flushcontext -t
by_error_print "Failed to flush transient objects, exit..."

echo ""
echo "# Removing temporary files..."
rm -f primaryKey loadedKey loadedHMACKey0 loadedHMACKey1
rm -f ecc_priv_key.bin ecc_pub_key.bin hmac_key_priv.bin hmac_key_pub.bin
