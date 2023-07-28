/** @file tpm_ibm.c
* 
* @brief Unified Trust Anchor (UTA) TPM based on the IBM TSS
*
* @copyright Copyright (c) Siemens Mobility GmbH, 2023
*
* @author Christian P. Feist <christian.feist@siemens.com>
* @author Thomas Zeschg <thomas.zeschg@siemens.com>
*
* @license This work is licensed under the terms of the Apache Software License 
* 2.0. See the COPYING file in the top-level directory.
*
* SPDX-License-Identifier: Apache-2.0
* 
* Portions Copyright IBM Corporation 2016, see below for details:  
*
* SPDX-License-Identifier: BSD-3-Clause
*
* All rights reserved.							
* 									
* Redistribution and use in source and binary forms, with or without	
* modification, are permitted provided that the following conditions are
* met:									
* 									
* Redistributions of source code must retain the above copyright notice,
* this list of conditions and the following disclaimer.		
* 									
* Redistributions in binary form must reproduce the above copyright	
* notice, this list of conditions and the following disclaimer in the	
* documentation and/or other materials provided with the distribution.	
* 									
* Neither the names of the IBM Corporation nor the names of its	
* contributors may be used to endorse or promote products derived from	
* this software without specific prior written permission.		
* 									
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS	
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT	
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT	
* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT	
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT	
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
* 	
* --------------------------------------------------------------------
* 			    
* A portion of the source code is derived from the TPM specification,
* which has a TCG copyright.  It is reproduced here for reference.
* 
* --------------------------------------------------------------------
* 
* Licenses and Notices
* Copyright Licenses:
* 
* * Trusted Computing Group (TCG) grants to the user of the source code
* in this specification (the "Source Code") a worldwide, irrevocable,
* nonexclusive, royalty free, copyright license to reproduce, create
* derivative works, distribute, display and perform the Source Code and
* derivative works thereof, and to grant others the rights granted
* herein.
* 
* * The TCG grants to the user of the other parts of the specification
* (other than the Source Code) the rights to reproduce, distribute,
* display, and perform the specification solely for the purpose of
* developing products based on such documents.  
* 
* Source Code Distribution Conditions:
* 
* * Redistributions of Source Code must retain the above copyright
* licenses, this list of conditions and the following disclaimers.
* 
* * Redistributions in binary form must reproduce the above copyright
* licenses, this list of conditions and the following disclaimers in the
* documentation and/or other materials provided with the distribution.
* 
* Disclaimers:
* 
* * THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF
* LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH
* RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)
* THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR
* OTHERWISE. Contact TCG Administration
* (admin@trustedcomputinggroup.org) for information on specification
* licensing rights available through TCG membership agreements.
* 
* * THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED
* WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR
* FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR
* NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY
* OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.
* 
* * Without limitation, TCG and its members and licensors disclaim all
* liability, including liability for infringement of any proprietary
* rights, relating to use of information in this specification and to
* the implementation of this specification, and TCG disclaims all
* liability for cost of procurement of substitute goods or services,
* lost profits, loss of use, loss of data or any incidental,
* consequential, direct, indirect, or special damages, whether under
* contract, tort, warranty or otherwise, arising in any way out of use
* or reliance upon this specification or any information herein.
* 
* Any marks and brands contained herein are the property of their
* respective owners.
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
#include <stdint.h>
#include <pthread.h>

#include <config.h>
#include <tpm_ibm.h>

#include <tss2/tss.h>

/*******************************************************************************
 * Data types
 ******************************************************************************/
struct _uta_context_v1_t
{
    TSS_CONTEXT *tssContext;
    TPMI_SH_AUTH_SESSION authSessionHandle;
    pthread_mutex_t accesslock;
};

/*******************************************************************************
 * Defines
 ******************************************************************************/
#define DERIV_STR_LEN   8     /* 8 Bytes */
#define USED_KEY_SLOTS  2

/*******************************************************************************
 * Private function prototypes
 ******************************************************************************/
static uint32_t tpm_start_hmac_session(const uta_context_v1_t *tpm_context);
static uint32_t tpm_flush_context(const uta_context_v1_t *tpm_context,
        uint32_t handle_number);
static uint32_t tpm_calc_hmac(const uta_context_v1_t *tpm_context,
        uint8_t *hmac, const uint8_t *deriv_val, uint32_t hmacKeyHandle);
static uint32_t tpm_get_rand(const uta_context_v1_t *tpm_context,
        uint8_t *randomNumber, size_t len_random);
static uint32_t tpm_create_endosement_key(const uta_context_v1_t *tpm_context,
        uint32_t *handle);
static uint32_t tpm_start_selftest(const uta_context_v1_t *tpm_context);
static uint32_t tpm_get_test_result(const uta_context_v1_t *tpm_context,
        TPM_RC *testResult);
        
/*******************************************************************************
 * Public function bodies
 ******************************************************************************/        
/**
 * @brief Return the size of the opaque struct uta_context_v1_t.
 * @return Size of the opaque struct uta_context_v1_t .
 */
size_t tpm_context_v1_size(void)
{
    return(sizeof(uta_context_v1_t));
}

/**
 * @brief Opens the connection to the TPM.
 * @param[in,out] tpm_context Pointer to the internal context struct.
 * @return UTA return code.
 */
uta_rc tpm_open(const uta_context_v1_t *tpm_context)
{
    /* This function needs writing access to the context */
    uta_context_v1_t *tpm_context_w = (uta_context_v1_t*)tpm_context;

    TPM_RC rc = 0;
    int ret;

    /* Initialization of the accesslock mutex */
    ret = pthread_mutex_init(&tpm_context_w->accesslock, NULL);
    if (ret != 0)
    {
        return UTA_TA_ERROR;
    }
    
    /* Lock the device access with the accesslock mutex */
    ret = pthread_mutex_lock(&tpm_context_w->accesslock);
    if (ret != 0)
    {
        return UTA_TA_ERROR;
    }

    /* Change debug level, return value is ignored */
    (void)TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "0");

    /* Create context */
    rc = TSS_Create(&(tpm_context_w->tssContext));
    if(rc != 0) 
    {
        return UTA_TA_ERROR;
    }

    /* Set device type */
    rc = TSS_SetProperty(tpm_context_w->tssContext, TPM_INTERFACE_TYPE, CONFIGURED_TPM_INTERFACE_TYPE);
    if(rc != 0)
    {
        rc = TSS_Delete(tpm_context->tssContext);
        return UTA_TA_ERROR;
    }

    /* Set data directory */
    rc = TSS_SetProperty(tpm_context_w->tssContext, TPM_DATA_DIR, CONFIGURED_TPM_DATA_DIR);
    if(rc != 0)
    {
        rc = TSS_Delete(tpm_context->tssContext);
        return UTA_TA_ERROR;
    }

    /* Set tpm device file */
    rc = TSS_SetProperty(tpm_context_w->tssContext, TPM_DEVICE, CONFIGURED_TPM_DEVICE);
    if(rc != 0)
    {
        rc = TSS_Delete(tpm_context->tssContext);
        return UTA_TA_ERROR;
    }

    /* Starting HMAC session */
    rc = tpm_start_hmac_session(tpm_context);
    if(rc != 0) 
    {
        rc = TSS_Delete(tpm_context->tssContext);
        return UTA_TA_ERROR;
    }
    
    /* Release the accesslock mutex (ignore return code) */
    (void)pthread_mutex_unlock(&tpm_context_w->accesslock);

    return UTA_SUCCESS;
}

/**
 * @brief Closes the connection to the TPM.
 * @param[in,out] tpm_context Pointer to the internal context struct.
 * @return UTA return code.
 */
uta_rc tpm_close(const uta_context_v1_t *tpm_context)
{
    /* This function needs writing access to the context */
    uta_context_v1_t *tpm_context_w = (uta_context_v1_t*)tpm_context;

    TPM_RC    rc = 0;
    int ret_val;
    
    /* Lock the device access with the accesslock mutex */
    ret_val = pthread_mutex_lock(&tpm_context_w->accesslock);
    if (ret_val != 0)
    {
        return UTA_TA_ERROR;
    }

    /* Close open HMAC-Session */
    if(tpm_context->authSessionHandle != 0)
    {
        /* Try to close the HMAC session handle */
        (void)tpm_flush_context(tpm_context, tpm_context->authSessionHandle);
    }
    
    /* Remove the TSS context */
    rc = TSS_Delete(tpm_context->tssContext);
    if (rc != 0)
    {
        return UTA_TA_ERROR;
    }
    
    /* Release the accesslock mutex (ignore return code) */
    (void)pthread_mutex_unlock(&tpm_context_w->accesslock);
    
    /* Destroy the accesslog mutex (ignore return code) */
    (void)pthread_mutex_destroy(&tpm_context_w->accesslock);

    return UTA_SUCCESS;
}

/**
 * @brief Derives a key using the TPMs HMAC function.
 * @param[in,out] tpm_context Pointer to the internal context struct.
 * @param[out] key Pointer to the buffer where the derived key is written to.
 * @param[in] len_key Defines the number of bytes, which should be written to
 *      the key buffer.
 * @param[in] dv Pointer to the buffer in which the derivation value is handed
 *      over.
 * @param[in] len_dv Specifies the length in bytes of the derivation value.
 * @param[in] key_slot Defines which master key is used for the HMAC function.
 * @return UTA return code.
 */
uta_rc tpm_derive_key(const uta_context_v1_t *tpm_context, uint8_t *key,
        size_t len_key, const uint8_t *dv, size_t len_dv, uint8_t key_slot)
{
    /* This function needs writing access to the context */
    uta_context_v1_t *tpm_context_w = (uta_context_v1_t*)tpm_context;
    
    TPM_RC    rc = 0;
    TPMI_DH_OBJECT hmacKeyHandle;
    uint8_t key_buffer[32];
    int ret_val;
    
    /* Check key_slot */
    if(key_slot > (USED_KEY_SLOTS-1))
    {
        return UTA_INVALID_KEY_SLOT;
    }
    
    switch(key_slot)
    {
        case 0x00:
            hmacKeyHandle = TPM_KEY0_HANDLE;
        break;
            
        case 0x01:
            hmacKeyHandle = TPM_KEY1_HANDLE;
        break;
            
        default:
            return UTA_INVALID_KEY_SLOT;
    }
    
    if(len_dv != 8)
    {
        return UTA_INVALID_DV_LENGTH;
    }
    
    if(len_key > 32)
    {
        return UTA_INVALID_KEY_LENGTH;
    }
    
    /* Lock the device access with the accesslock mutex */
    ret_val = pthread_mutex_lock(&tpm_context_w->accesslock);
    if (ret_val != 0)
    {
        return UTA_TA_ERROR;
    }

    /* Calculate HMAC using TPM key */
    rc = tpm_calc_hmac(tpm_context, key_buffer, dv, hmacKeyHandle);
    
    /* Release the accesslock mutex (ignore return code) */
    (void)pthread_mutex_unlock(&tpm_context_w->accesslock);
    
    if(rc != 0)
    {
        return UTA_TA_ERROR;
    }
    memcpy(key,key_buffer,len_key);

    return UTA_SUCCESS;
}

/**
 * @brief Gets random numbers from the TPM.
 * @param[in,out] tpm_context Pointer to the internal context struct.
 * @param[out] random Pointer to the buffer where the random numbers are written
 *      to.
 * @param[in] len_random Defines the desired number of random bytes.
 * @return UTA return code.
 */
uta_rc tpm_get_random(const uta_context_v1_t *tpm_context, uint8_t *random,
        size_t len_random)
{
    /* This function needs writing access to the context */
    uta_context_v1_t *tpm_context_w = (uta_context_v1_t*)tpm_context;
    
    TPM_RC    rc = 0;
    int ret_val;
    
    /* Lock the device access with the accesslock mutex */
    ret_val = pthread_mutex_lock(&tpm_context_w->accesslock);
    if (ret_val != 0)
    {
        return UTA_TA_ERROR;
    }
    
    /* Get Random numbers from TPM */
    rc = tpm_get_rand(tpm_context, random, len_random);
    
    /* Release the accesslock mutex (ignore return code) */
    (void)pthread_mutex_unlock(&tpm_context_w->accesslock);

    if(rc != 0)
    {
        return UTA_TA_ERROR;
    }

    return UTA_SUCCESS;
}

/**
 * @brief Gets the UUID of the device.
 * @param[in,out] tpm_context Pointer to the internal context struct.
 * @param[out] uuid Pointer to the buffer where the UUID should be written to.
 * @return UTA return code.
 */
uta_rc tpm_get_device_uuid(const uta_context_v1_t *tpm_context, uint8_t *uuid)
{
    /* This function needs writing access to the context */
    uta_context_v1_t *tpm_context_w = (uta_context_v1_t*)tpm_context;
    
    TPM_RC    rc = 0;
    uint32_t handle = 0;
    /* "DEVICEID" in hexadecimal representation */
    uint8_t derive_value[] = {0x44, 0x45, 0x56, 0x49, 0x43, 0x45, 0x49, 0x44};
    uint8_t hmac_output[32];
    int ret_val;
    
    /* Lock the device access with the accesslock mutex */
    ret_val = pthread_mutex_lock(&tpm_context_w->accesslock);
    if (ret_val != 0)
    {
        return UTA_TA_ERROR;
    }
    
    /* Create an endorsement key */
    rc = tpm_create_endosement_key(tpm_context, &handle);
    if(rc != 0)
    {
        /* Release the accesslock mutex (ignore return code) */
        (void)pthread_mutex_unlock(&tpm_context_w->accesslock);
        return UTA_TA_ERROR;
    }
    
    /* Calculate HMAC using TPM endorsement key */
    rc = tpm_calc_hmac(tpm_context, hmac_output, derive_value, handle);
    
    /* Try to flush the EK, ignore the return value */
    (void)tpm_flush_context(tpm_context, handle);
    
    /* Release the accesslock mutex (ignore return code) */
    (void)pthread_mutex_unlock(&tpm_context_w->accesslock);
        
    if(rc != 0)
    {
        return UTA_TA_ERROR;
    }
    
    /* Copy the first 16 bytes to uuid */
    memcpy(uuid, hmac_output, 16);
    
    /* Format UUID as described in RFC 4122 */
    uuid[6] &= 0x0F;    // 0b00001111;
    uuid[6] |= 0x40;    // 0b01000000;
    
    uuid[8] &= 0x3F;    // 0b00111111;
    uuid[8] |= 0x80;    // 0b10000000;

    return UTA_SUCCESS;
}

/**
 * @brief Performs the TPM self test.
 * @param[in,out] tpm_context Pointer to the internal context struct.
 * @return UTA return code.
 */
uta_rc tpm_self_test(const uta_context_v1_t *tpm_context)
{
    /* This function needs writing access to the context */
    uta_context_v1_t *tpm_context_w = (uta_context_v1_t*)tpm_context;
    
    TPM_RC    rc = 0;
    TPM_RC  testResult;
    int ret_val;
    
    /* Lock the device access with the accesslock mutex */
    ret_val = pthread_mutex_lock(&tpm_context_w->accesslock);
    if (ret_val != 0)
    {
        return UTA_TA_ERROR;
    }
    
    rc = tpm_start_selftest(tpm_context);
    if(rc != 0)
    {
        /* Release the accesslock mutex (ignore return code) */
        (void)pthread_mutex_unlock(&tpm_context_w->accesslock);
        return UTA_TA_ERROR;
    }
    
    rc = tpm_get_test_result(tpm_context, &testResult);
    
    /* Release the accesslock mutex (ignore return code) */
    (void)pthread_mutex_unlock(&tpm_context_w->accesslock);
    
    if(rc != 0)
    {
        return UTA_TA_ERROR;
    }
    
    if(testResult != 0)
    {
        return UTA_TA_ERROR;
    }
    
    return UTA_SUCCESS;
}
        
/*******************************************************************************
 * Private function bodies
 ******************************************************************************/ 
/**
 * @brief Starts an HMAC session with the TPM.
 * @param[in,out] tpm_context Pointer to the internal context struct.
 * @return IBM TSS return code.
 */
static uint32_t tpm_start_hmac_session(const uta_context_v1_t *tpm_context)
{
    /* This function needs writing access to the context */
    uta_context_v1_t *tpm_context_w = (uta_context_v1_t*)tpm_context;
    
    TPM_RC rc = 0;
    StartAuthSession_In in;
    StartAuthSession_Out out;
    StartAuthSession_Extra extra;
    TPMI_DH_OBJECT tpmKey = TPM_SALT_HANDLE;
    TPMI_DH_ENTITY bindHandle = TPM_RH_NULL;
    const char *bindPassword = NULL;
    TPMI_ALG_HASH halg = TPM_ALG_SHA256;
    TPMI_ALG_SYM algorithm = TPM_ALG_AES;

    // Set up TPM input data structure
    in.sessionType = TPM_SE_HMAC;
    /* salt key */
    in.tpmKey = tpmKey;
    /* encryptedSalt (not required) */
    in.encryptedSalt.b.size = 0;
    /* bind handle */
    in.bind = bindHandle;
    /* nonceCaller (not required) */
    in.nonceCaller.t.size = 0;
    /* for parameter encryption */
    in.symmetric.algorithm = algorithm;
    /* authHash */
    in.authHash = halg;
    
    /* Table 61 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type */
    /* Table 125 - Definition of TPMU_SYM_KEY_BITS Union */
    in.symmetric.keyBits.aes = 128;
    /* Table 126 - Definition of TPMU_SYM_MODE Union */
    /* Table 63 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_MODE Type */
    in.symmetric.mode.aes = TPM_ALG_CFB;
    
    /* 
     * pass the bind password to the TSS post processor for the session key
     * calculation 
     */
    extra.bindPassword = bindPassword;

    // Execute the command
    rc = TSS_Execute(tpm_context->tssContext,
             (RESPONSE_PARAMETERS *)&out, 
             (COMMAND_PARAMETERS *)&in,
             (EXTRA_PARAMETERS *)&extra,
             TPM_CC_StartAuthSession,
             TPM_RH_NULL, NULL, 0);

    if(rc == 0)
    {
        tpm_context_w->authSessionHandle = out.sessionHandle;
    }

    return rc;
}

/**
 * @brief Closes an HMAC session with the TPM.
 * @param[in,out] tpm_context Pointer to the internal context struct.
 * @param[in] handle_number Specifies the session to close.
 * @return IBM TSS return code.
 */
static uint32_t tpm_flush_context(const uta_context_v1_t *tpm_context,
        uint32_t handle_number)
{
    TPM_RC rc = 0;
    FlushContext_In in;
    in.flushHandle = handle_number;

    /* call TSS to execute the command */
    rc = TSS_Execute(tpm_context->tssContext,
             NULL, 
             (COMMAND_PARAMETERS *)&in,
             NULL,
             TPM_CC_FlushContext,
             TPM_RH_NULL, NULL, 0);

    return rc;
}

/**
 * @brief Calculates an HMAC-SHA256 on the TPM.
 * @param[in,out] tpm_context Pointer to the internal context struct.
 * @param[out] hmac Pointer to the output buffer.
 * @param[in] deriv_val Pointer to the buffer containing the derivation value.
 * @param[in] hmacKeyHandle Specifies the master key of the HMAC function.
 * @return IBM TSS return code.
 */
static uint32_t tpm_calc_hmac(const uta_context_v1_t *tpm_context,
        uint8_t *hmac, const uint8_t *deriv_val, uint32_t hmacKeyHandle)
{
    TPM_RC rc = 0;
    HMAC_In in;
    HMAC_Out out;
    TPMI_DH_OBJECT keyHandle = hmacKeyHandle;
    TPMI_ALG_HASH halg = TPM_ALG_SHA256;
    const char *keyPassword = NULL;
    TPMI_SH_AUTH_SESSION sessionHandle0 = tpm_context->authSessionHandle;
     /* Command/Response encryption */
    unsigned int sessionAttributes0 = 0x61;
    TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
    unsigned int sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
    unsigned int sessionAttributes2 = 0;

    // Set up TPM input data structure
    in.handle = keyHandle;
    in.buffer.t.size = DERIV_STR_LEN; 
    memcpy(in.buffer.t.buffer, deriv_val, DERIV_STR_LEN);
    in.hashAlg = halg;

    // Execute the command
    rc = TSS_Execute(tpm_context->tssContext,
                     (RESPONSE_PARAMETERS *)&out,
                     (COMMAND_PARAMETERS *)&in,
                     NULL,
                     TPM_CC_HMAC,
                     sessionHandle0, keyPassword, sessionAttributes0,
                     sessionHandle1, NULL, sessionAttributes1,
                     sessionHandle2, NULL, sessionAttributes2,
                     TPM_RH_NULL, NULL, 0);

    if(rc == 0)
    {
        // Copy HMAC to output buffer
        memcpy(hmac, out.outHMAC.t.buffer, out.outHMAC.t.size);
    }

    return rc;
}

/**
 * @brief Requests random numbers from the TPM.
 * @param[in,out] tpm_context Pointer to the internal context struct.
 * @param[out] randomValue Pointer to the output buffer.
 * @param[in] len_random Desired number of random bytes.
 * @return IBM TSS return code.
 */
static uint32_t tpm_get_rand(const uta_context_v1_t *tpm_context,
        uint8_t *randomValue, size_t len_random)
{
    TPM_RC rc = 0;
    GetRandom_In in;
    GetRandom_Out out;
    uint32_t bytesRequested = len_random;
    uint32_t bytesCopied;
    TPMI_SH_AUTH_SESSION sessionHandle0 = tpm_context->authSessionHandle;
    unsigned int sessionAttributes0 = 0x41; /* Response encryption */
    TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
    unsigned int sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
    unsigned int sessionAttributes2 = 0;
    
    /* Get random bytes from TPM */
    for (bytesCopied = 0; (rc == 0) && (bytesCopied < bytesRequested) ; )
    {
        /* Request whatever is left */
        if (rc == 0)
        {
            in.bytesRequested = bytesRequested - bytesCopied;
        }
        /* call TSS to execute the command */
        if (rc == 0)
        {
            rc = TSS_Execute(tpm_context->tssContext,
                     (RESPONSE_PARAMETERS *)&out, 
                     (COMMAND_PARAMETERS *)&in,
                     NULL,
                     TPM_CC_GetRandom,
                     sessionHandle0, NULL, sessionAttributes0,
                     sessionHandle1, NULL, sessionAttributes1,
                     sessionHandle2, NULL, sessionAttributes2,
                     TPM_RH_NULL, NULL, 0);
        }
        if (rc == 0)
        {
            size_t br;
            /* copy as many bytes as were received or until bytes requested */
            for (br = 0 ; (br < out.randomBytes.t.size) &&
                    (bytesCopied < bytesRequested) ; br++)
            {
                randomValue[bytesCopied] = out.randomBytes.t.buffer[br];
                bytesCopied++;
            }
        }
    }
    
    return rc;
}

/**
 * @brief Creates a new primary key under the endorsement hierarchy.
 * @param[in,out] tpm_context Pointer to the internal context struct.
 * @param[out] handle Handle number of the created key.
 * @return IBM TSS return code.
 */
static uint32_t tpm_create_endosement_key(const uta_context_v1_t *tpm_context,
        uint32_t *handle)
{
    TPM_RC rc = 0;
    CreatePrimary_In in;
    CreatePrimary_Out out;

    TPMA_OBJECT addObjectAttributes;
    TPMA_OBJECT deleteObjectAttributes;
    
    TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
    unsigned int sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
    unsigned int sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
    unsigned int sessionAttributes2 = 0;

    /* command line argument defaults */
    addObjectAttributes.val = 0;
    addObjectAttributes.val |= TPMA_OBJECT_NODA;
    addObjectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
    addObjectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
    deleteObjectAttributes.val = 0;

    in.primaryHandle = TPM_RH_ENDORSEMENT;
    in.inSensitive.sensitive.userAuth.t.size = 0;
    in.inSensitive.sensitive.data.t.size = 0;
    
    in.inPublic.publicArea.objectAttributes = addObjectAttributes;
    in.inPublic.publicArea.type = TPM_ALG_KEYEDHASH;
    in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    /* Table 32 - TPMA_OBJECT objectAttributes */
    in.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
    in.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
    in.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
    in.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    in.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
    in.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
    in.inPublic.publicArea.objectAttributes.val &= ~deleteObjectAttributes.val;

    in.inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    in.inPublic.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA256;

    in.inPublic.publicArea.unique.sym.t.size = 0; 
    in.inPublic.publicArea.authPolicy.t.size = 0;  
    in.inPublic.publicArea.unique.rsa.t.size = 0;
    in.outsideInfo.t.size = 0;
    in.creationPCR.count = 0;
    
    /* call TSS to execute the command */
    rc = TSS_Execute(tpm_context->tssContext,
        (RESPONSE_PARAMETERS *)&out,
        (COMMAND_PARAMETERS *)&in,
        NULL,
        TPM_CC_CreatePrimary,
        sessionHandle0, NULL, sessionAttributes0,
        sessionHandle1, NULL, sessionAttributes1,
        sessionHandle2, NULL, sessionAttributes2,
        TPM_RH_NULL, NULL, 0);

    if (rc == 0)
    {
        *handle = out.objectHandle;
    }
    
    return rc;
}

/**
 * @brief Starts the TPM self test.
 * @param[in,out] tpm_context Pointer to the internal context struct.
 * @return IBM TSS return code.
 */
static uint32_t tpm_start_selftest(const uta_context_v1_t *tpm_context)
{
    TPM_RC rc = 0;
    SelfTest_In in;

    /* call TSS to execute the command */
    in.fullTest = YES;

    rc = TSS_Execute(tpm_context->tssContext,
        NULL, 
        (COMMAND_PARAMETERS *)&in,
        NULL,
        TPM_CC_SelfTest,
        TPM_RH_NULL, NULL, 0);

    return rc;
}

/**
 * @brief Reads the output of the TPM self test.
 * @param[in,out] tpm_context Pointer to the internal context struct.
 * @param[out] testResult Output of the TPM self test.
 * @return IBM TSS return code.
 */
static uint32_t tpm_get_test_result(const uta_context_v1_t *tpm_context,
        TPM_RC *testResult)
{
    TPM_RC rc = 0;
    GetTestResult_Out out;

    /* call TSS to execute the command */
    rc = TSS_Execute(tpm_context->tssContext,
        (RESPONSE_PARAMETERS *)&out,
        NULL,
        NULL,
        TPM_CC_GetTestResult,
        TPM_RH_NULL, NULL, 0);

    if(rc == 0)
    {
        *testResult = out.testResult;
    }

    return rc;
}
