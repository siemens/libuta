/** @file tpm_tcg.c
* 
* @brief Unified Trust Anchor (UTA) TPM
*
* @copyright Copyright (c) Siemens Mobility GmbH, 2020
*
* @author Thomas Zeschg <thomas.zeschg@siemens.com>
*
* @license This work is licensed under the terms of the Apache Software License 
* 2.0. See the LICENSE file in the top-level directory.
*
* SPDX-License-Identifier: Apache-2.0
*
* Portions Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon
* Technologies AG, see below for details:  
*
* SPDX-License-Identifier: BSD-2-Clause
*
********************************************************************************
* Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
* All rights reserved.
********************************************************************************
*
*	Redistribution and use in source and binary forms, with or without
*	modification, are permitted provided that the following conditions are met:
*	
*	1. Redistributions of source code must retain the above copyright notice,
*	this list of conditions and the following disclaimer.
*	
*	2. Redistributions in binary form must reproduce the above copyright notice,
*	this list of conditions and the following disclaimer in the documentation
*	and/or other materials provided with the distribution.
*	
*	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
*	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
*	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
*	ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
*	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
*	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
*	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
*	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
*	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
*	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
*	THE POSSIBILITY OF SUCH DAMAGE.
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

#include <config.h>
#include <tpm_tcg.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_mssim.h>
#include <tss2/tss2_tcti_device.h>

//#define SIM

/*******************************************************************************
 * Data types
 ******************************************************************************/
struct _uta_context_v1_t
{
    ESYS_CONTEXT *esys_context;
    TSS2_TCTI_CONTEXT *tcti_ctx;
    ESYS_TR session;
};

/*******************************************************************************
 * Defines
 ******************************************************************************/
#define DERIV_STR_LEN   8     /* 8 Bytes */
#define USED_KEY_SLOTS  2

/*******************************************************************************
 * Private function prototypes
 ******************************************************************************/
        
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

    TSS2_RC ret;
    size_t size;

#ifdef SIM
    char *conf_str = "host=127.0.0.1,port=2321";
    
    ret = Tss2_Tcti_Mssim_Init(NULL, &size, conf_str);
    if(ret != TSS2_RC_SUCCESS){
        printf("Tss2_Tcti_Mssim_Init failed\n");
        return UTA_TA_ERROR;
    }
    tpm_context_w->tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc(1, size);
    if(tpm_context_w->tcti_ctx == NULL){
        printf("TCTI memory allocation failed\n");
        return UTA_TA_ERROR;
    }
    
    ret = Tss2_Tcti_Mssim_Init(tpm_context_w->tcti_ctx, &size, conf_str);
    if(ret != TSS2_RC_SUCCESS){
        printf("Tss2_Tcti_Mssim_Init failed\n");
        return UTA_TA_ERROR;
    }

#else
    char *conf_str = "/dev/tpm0";
    
    ret = Tss2_Tcti_Device_Init(NULL, &size, 0);
    if(ret != TSS2_RC_SUCCESS){
        printf("Tss2_Tcti_Device_Init failed\n");
        return UTA_TA_ERROR;
    }
    tpm_context_w->tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc(1, size);
    if(tpm_context_w->tcti_ctx == NULL){
        printf("TCTI memory allocation failed\n");
        return UTA_TA_ERROR;
    }
    
    ret = Tss2_Tcti_Device_Init(tpm_context_w->tcti_ctx, &size, conf_str);
    if(ret != TSS2_RC_SUCCESS){
        printf("Tss2_Tcti_Device_Init failed\n");
        return UTA_TA_ERROR;
    }

#endif

    ret = Esys_Initialize(&tpm_context_w->esys_context, tpm_context->tcti_ctx, NULL);
    if(ret != TSS2_RC_SUCCESS){
        printf("Esys_Initialize failed\n");
        return UTA_TA_ERROR;
    }

    /* Starting HMAC session */

    const TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128},
        .mode = {.aes = TPM2_ALG_CFB}
    };

    ret = Esys_StartAuthSession(tpm_context->esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                              &tpm_context_w->session);
                              
    if(ret != TSS2_RC_SUCCESS){
        printf("Esys_StartAuthSession failed\n");
        return UTA_TA_ERROR;
    }

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
    
    TSS2_RC ret;
    
    /* Close open HMAC-Session */
    ret = Esys_FlushContext(tpm_context->esys_context, tpm_context->session);
    if(ret != TSS2_RC_SUCCESS){
        printf("Esys_FlushContext failed\n");
    }

    /* Remove the TSS context */
    Esys_Finalize(&tpm_context_w->esys_context);
    
    /* Remove the TSS context */
    Tss2_Tcti_Finalize(tpm_context_w->tcti_ctx);
    free(tpm_context_w->tcti_ctx);
    
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
    TSS2_RC ret;
    TPM2_HANDLE TPMhmacKeyHandle = ESYS_TR_NONE;
    ESYS_TR hmacKeyHandle = ESYS_TR_NONE;
    TPM2B_MAX_BUFFER test_buffer = { .size = len_dv,
                                     .buffer={0}} ;
    TPM2B_DIGEST *outHMAC;
	
	/* Check key_slot */
	if(key_slot > (USED_KEY_SLOTS-1))
	{
		return UTA_INVALID_KEY_SLOT;
	}
	
	switch(key_slot)
	{
		case 0x00:
			hmacKeyHandle = TPM_IBM_KEY0_HANDLE;
        break;
			
		case 0x01:
			hmacKeyHandle = TPM_IBM_KEY1_HANDLE;
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

	/* Calculate HMAC using TPM key */
    memcpy(test_buffer.buffer, dv, len_dv);
    
    ret = Esys_TR_FromTPMPublic(
            tpm_context->esys_context,
            TPMhmacKeyHandle, /* required */
            ESYS_TR_NONE, /* optional (ESYS_TR_NONE) */ //TODO: CHECK
            ESYS_TR_NONE, /* optional (ESYS_TR_NONE) */
            ESYS_TR_NONE, /* optional (ESYS_TR_NONE) */
            &hmacKeyHandle /* required (non-NULL) */
    );
    if(ret != 0)
    {
        printf("Esys_TR_FromTPMPublic failed\n");
		return UTA_TA_ERROR;
	}

    TPMA_SESSION sessionAttributes = TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_ENCRYPT | TPMA_SESSION_DECRYPT;

    ret = Esys_TRSess_SetAttributes(tpm_context->esys_context, tpm_context->session, sessionAttributes, 0xff);
    if(ret != TSS2_RC_SUCCESS){
        printf("Esys_TRSess_SetAttributes failed\n");
        return UTA_TA_ERROR;
    }


    ret = Esys_HMAC(
        tpm_context->esys_context,
        hmacKeyHandle,
        ESYS_TR_PASSWORD,
        tpm_context->session,       //TODO: CHECK
        ESYS_TR_NONE,
        &test_buffer,
        TPM2_ALG_SHA256,
        &outHMAC);
    
	if(ret != 0)
    {
        printf("Esys_HMAC failed\n");
		return UTA_TA_ERROR;
	}
    
    if(outHMAC->size < len_key){
        printf("Output not long enough\n");
        return UTA_TA_ERROR;
    }
    
	memcpy(key,outHMAC->buffer,len_key);
    free(outHMAC);

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
	TSS2_RC ret;
    TPM2B_DIGEST *randomBytes;

    TPMA_SESSION sessionAttributes = TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_ENCRYPT;

    ret = Esys_TRSess_SetAttributes(tpm_context->esys_context, tpm_context->session, sessionAttributes, 0xff);
    if(ret != TSS2_RC_SUCCESS){
        printf("Esys_TRSess_SetAttributes failed\n");
        return UTA_TA_ERROR;
    }
    
    /* Get Random numbers from TPM */
    ret = Esys_GetRandom(tpm_context->esys_context,
                       tpm_context->session,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE, len_random, &randomBytes);
                       
    if(ret != TSS2_RC_SUCCESS){
        printf("Esys_GetRandom failed\n");
        free(randomBytes);
        return UTA_TA_ERROR;
    }
    
    if(randomBytes->size != len_random){
        printf("Esys_GetRandom: returned not enough random bytes\n");
        return UTA_TA_ERROR;
    }
    
    memcpy(random, &randomBytes->buffer[0], len_random);

    free(randomBytes);
    
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
    TSS2_RC ret;
    ESYS_TR primaryHandle = ESYS_TR_NONE;

    TPM2B_AUTH authValuePrimary = {
        .size = 0,
        .buffer = {}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 4,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0 },
             },
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };
    inSensitivePrimary.sensitive.userAuth = authValuePrimary;
    TPM2B_PUBLIC inPublic = { 0 };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };
    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;
    inPublic.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM2_ALG_SHA256;

    ret = Esys_CreatePrimary(tpm_context->esys_context, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
                           &inPublic, &outsideInfo, &creationPCR,
                           &primaryHandle, &outPublic, &creationData,
                           &creationHash, &creationTicket);
    if(ret != TSS2_RC_SUCCESS){
        printf("Esys_CreatePrimary failed\n");
        return UTA_TA_ERROR;
    }

    ret = Esys_TR_SetAuth(tpm_context->esys_context, primaryHandle, &authValuePrimary);
    if(ret != TSS2_RC_SUCCESS){
        printf("Esys_TR_SetAuth failed\n");
        return UTA_TA_ERROR;
    }

    TPM2B_MAX_BUFFER test_buffer = { .size = 8,
                                     .buffer={0x44, 0x45, 0x56, 0x49, 0x43, 0x45, 0x49, 0x44}} ;
    TPM2B_DIGEST *outHMAC;


    TPMA_SESSION sessionAttributes = TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_ENCRYPT | TPMA_SESSION_DECRYPT;

    ret = Esys_TRSess_SetAttributes(tpm_context->esys_context, tpm_context->session, sessionAttributes, 0xff);
    if(ret != TSS2_RC_SUCCESS){
        printf("Esys_TRSess_SetAttributes failed\n");
        return UTA_TA_ERROR;
    }

    ret = Esys_HMAC(
        tpm_context->esys_context,
        primaryHandle,
        ESYS_TR_PASSWORD,
        tpm_context->session,
        ESYS_TR_NONE,
        &test_buffer,
        TPM2_ALG_SHA256,
        &outHMAC);
        
    if(ret != TSS2_RC_SUCCESS){
        printf("Esys_HMAC failed\n");
        return UTA_TA_ERROR;
    }
    
    if(outHMAC->size < 16){
        printf("Output not long enough\n");
        return UTA_TA_ERROR;
    }

    ret = Esys_FlushContext(tpm_context->esys_context, primaryHandle);
    if(ret != TSS2_RC_SUCCESS){
        printf("Esys_FlushContext failed\n");
        return UTA_TA_ERROR;
    }
    
	/* Copy the first 16 bytes to uuid */
	memcpy(uuid, outHMAC->buffer, 16);
    
    free(outHMAC);
	
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
    TSS2_RC ret;
	TPM2B_MAX_BUFFER *outData;
    TPM2_RC testResult;
    
    ret = Esys_SelfTest(tpm_context->esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 1);
	if(ret != TSS2_RC_SUCCESS){
        printf("Esys_SelfTest failed\n");
        return UTA_TA_ERROR;
    }
    
    ret = Esys_GetTestResult(tpm_context->esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &outData, &testResult);
	if(ret != TSS2_RC_SUCCESS){
        printf("Esys_GetTestResult failed\n");
        return UTA_TA_ERROR;
    }
    
    if(testResult != TSS2_RC_SUCCESS){
        printf("Wrong test result\n");
        free(outData);
        return UTA_TA_ERROR;
    }
    free(outData);
	
	return UTA_SUCCESS;
}
