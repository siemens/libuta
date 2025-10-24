/** @file uta_sim.c
* 
* @brief Unified Trust Anchor (UTA) Software Simulator for development purposes
*
* @copyright Copyright (c) Siemens Mobility GmbH, 2020
*
* @author Thomas Zeschg <thomas.zeschg@siemens.com>
*
* @license This work is licensed under the terms of the Apache Software License 
* 2.0. See the COPYING file in the top-level directory.
*
* SPDX-License-Identifier: Apache-2.0
*/

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <config.h>
#include <uta_sim.h>
#include <mbedtls/md.h>

/*******************************************************************************
 * Data types
 ******************************************************************************/
struct _uta_context_v1_t
{
    /* dummy added so that the struct does not have size 0 */
    int dummy;
};

/*******************************************************************************
 * Defines
 ******************************************************************************/
#define KEY_LEN           32
#define DERIV_VAL_LEN     8
#define USED_KEY_SLOTS    2

/*******************************************************************************
 * Constants
 ******************************************************************************/
const uint8_t KEY_SLOTS[USED_KEY_SLOTS][KEY_LEN]={KEY_SLOT_0,KEY_SLOT_1};

/*******************************************************************************
 * Public function bodies
 ******************************************************************************/
/**
 * @brief Return the size of the opaque struct uta_context_v1_t.
 * @return Size of the opaque struct uta_context_v1_t .
 */
size_t sim_context_v1_size(void)
{
   return(sizeof(uta_context_v1_t));
}
 
/**
 * @brief Opens a simulation session.
 * @param[in,out] sim_context Pointer to the internal context struct.
 * @return UTA return code.
 */
uta_rc sim_open(const uta_context_v1_t *sim_context)
{
    /* Initialize the PRNG */
    time_t t;
    srand((unsigned) time(&t));

    return UTA_SUCCESS;
}

/**
 * @brief Closes a simulation session.
 * @param[in,out] sim_context Pointer to the internal context struct.
 * @return UTA return code.
 */
uta_rc sim_close(const uta_context_v1_t *sim_context)
{
    return UTA_SUCCESS;
}

/**
 * @brief Derives a key using the mbedtls HMAC function.
 * @param[in,out] sim_context Pointer to the internal context struct.
 * @param[out] key Pointer to the buffer where the derived key is written to.
 * @param[in] len_key Defines the number of bytes, which should be written to
 *      the key buffer.
 * @param[in] dv Pointer to the buffer in which the derivation value is handed
 *      over.
 * @param[in] len_dv Specifies the length in bytes of the derivation value.
 * @param[in] key_slot Defines which master key is used for the HMAC function.
 * @return UTA return code.
 */
uta_rc sim_derive_key(const uta_context_v1_t *sim_context, uint8_t *key,
    size_t len_key, const uint8_t *dv,size_t len_dv, uint8_t key_slot)
{
    uint8_t key_buffer[KEY_LEN];
    const mbedtls_md_info_t *sha256_hmac =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if(key_slot > (USED_KEY_SLOTS-1))
    {
        return UTA_INVALID_KEY_SLOT;
    }

    if(len_dv != DERIV_VAL_LEN)
    {
        return UTA_INVALID_DV_LENGTH;
    }

    if(len_key > KEY_LEN)
    {
        return UTA_INVALID_KEY_LENGTH;
    }

    mbedtls_md_hmac(sha256_hmac, KEY_SLOTS[key_slot], KEY_LEN,
        dv, len_dv, key_buffer);
    memcpy(key,key_buffer,len_key);

    return UTA_SUCCESS;
}

/**
 * @brief Gets random numbers using the rand() function.
 * @param[in,out] sim_context Pointer to the internal context struct.
 * @param[out] random Pointer to the buffer where the random numbers are written
 *      to.
 * @param[in] len_random Defines the desired number of random bytes.
 * @return UTA return code.
 */
uta_rc sim_get_random(const uta_context_v1_t *sim_context, uint8_t *random,
    size_t len_random)
{
    for(int i=0; i<len_random; i++)
    {
        random[i]=rand() % 256;
    }

    return UTA_SUCCESS;
}

/**
 * @brief Gets the UUID of the Linux machine by reading /etc/machine-id.
 * @param[in,out] sim_context Pointer to the internal context struct.
 * @param[out] uuid Pointer to the buffer where the UUID should be written to.
 * @return UTA return code.
 */
uta_rc sim_get_device_uuid(const uta_context_v1_t *sim_context, uint8_t *uuid)
{
    FILE *fileptr;
    char machine_id[32];
    uint8_t tmp_uuid[16];
    int ret;
    int i;
    
    fileptr = fopen("/etc/machine-id", "rb");  // Open the file in binary mode
    if(fileptr == NULL)
    {
        return UTA_TA_ERROR;
    }
    
    /* Read the UUID from file */
    ret = (int)fread(machine_id, 1, 32, fileptr); 
    if(ret != 32)
    {
        (void)fclose(fileptr); // Close the file
        return UTA_TA_ERROR;
    }
    (void)fclose(fileptr); // Close the file

    /* Convert the ASCII UUID to hex */
    for(i=0;i<16;i++)
    {
        ret = sscanf(&machine_id[i*2],"%02hhX", &tmp_uuid[i]);
        if(ret != 1)
        {
            return UTA_TA_ERROR;
        }
    }
    
    /* Copy tmp_uuid to uuid */
    memcpy(uuid, tmp_uuid, 16);

    return UTA_SUCCESS;
}

/**
 * @brief Prototype of the self test function. (Not used in simulation)
 * @param[in,out] sim_context Pointer to the internal context struct.
 * @return UTA return code.
 */
uta_rc sim_self_test(const uta_context_v1_t *sim_context)
{
    return UTA_SUCCESS;
}
