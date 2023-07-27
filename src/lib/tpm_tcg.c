/** @file tpm_tcg.c
*
* @brief Unified Trust Anchor (UTA) TPM
*
* @copyright Copyright (c) Siemens Mobility GmbH, 2023
*
* @author Tugrul Yanik <tugrul.yanik@siemens.com>
* @author Thomas Zeschg <thomas.zeschg@siemens.com>
*
* @license This work is licensed under the terms of the Apache Software License
* 2.0. See the COPYING file in the top-level directory.
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
*    Redistribution and use in source and binary forms, with or without
*    modification, are permitted provided that the following conditions are met:
*
*    1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
*    2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
*    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
*    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
*    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
*    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
*    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
*    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
*    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
*    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
*    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
*    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
*    THE POSSIBILITY OF SUCH DAMAGE.
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
#include <tpm_tcg.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_device.h>

/*******************************************************************************
 * Data types
 ******************************************************************************/
struct _uta_context_v1_t
{
    ESYS_CONTEXT *esys_context;
    TSS2_TCTI_CONTEXT *tcti_ctx;
    ESYS_TR session;
    pthread_mutex_t accesslock;
};

/*******************************************************************************
 * Defines
 ******************************************************************************/
#define DERIV_STR_LEN   8     /* 8 Bytes */
#define USED_KEY_SLOTS  2

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

    TPM2_HANDLE TPMKeyHandle = TPM_SALT_HANDLE;
    ESYS_TR tpmKey_handle = ESYS_TR_NONE;

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

    ret = Tss2_Tcti_Device_Init(NULL, &size, 0);
    if(ret != TSS2_RC_SUCCESS)
    {
        return UTA_TA_ERROR;
    }
    tpm_context_w->tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc(1, size);
    if(tpm_context_w->tcti_ctx == NULL)
    {
        return UTA_TA_ERROR;
    }

    ret = Tss2_Tcti_Device_Init(tpm_context_w->tcti_ctx, &size, CONFIGURED_TPM_DEVICE);
    if(ret != TSS2_RC_SUCCESS)
    {
        return UTA_TA_ERROR;
    }

    ret = Esys_Initialize(&tpm_context_w->esys_context,
        tpm_context->tcti_ctx,
        NULL);

    if(ret != TSS2_RC_SUCCESS)
    {
        return UTA_TA_ERROR;
    }

    /* Starting HMAC session */
    const TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128},
        .mode = {.aes = TPM2_ALG_CFB}
    };

    /* get a ESYS_TR handle for tpmKey */
    ret = Esys_TR_FromTPMPublic(
        tpm_context->esys_context,
        TPMKeyHandle, /* required */
        ESYS_TR_NONE, /* optional (ESYS_TR_NONE) */
        ESYS_TR_NONE, /* optional (ESYS_TR_NONE) */
        ESYS_TR_NONE, /* optional (ESYS_TR_NONE) */
        &tpmKey_handle /* required (non-NULL) */
    );
    if(ret != 0)
    {
        return UTA_TA_ERROR;
    }

    ret = Esys_StartAuthSession(
        tpm_context->esys_context,
        tpmKey_handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        NULL,
        TPM2_SE_HMAC,
        &symmetric,
        TPM2_ALG_SHA256,
        &tpm_context_w->session);

    if(ret != TSS2_RC_SUCCESS)
    {
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

    int ret_val;

    /* Lock the device access with the accesslock mutex */
    ret_val = pthread_mutex_lock(&tpm_context_w->accesslock);
    if (ret_val != 0)
    {
        return UTA_TA_ERROR;
    }

    /* Close open HMAC-Session */
    Esys_FlushContext(tpm_context->esys_context, tpm_context->session);

    /* Remove the TSS context */
    Esys_Finalize(&tpm_context_w->esys_context);

    /* Remove the TSS context */
    Tss2_Tcti_Finalize(tpm_context_w->tcti_ctx);
    free(tpm_context_w->tcti_ctx);

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
    TSS2_RC ret;

    int ret_val;

    TPM2_HANDLE TPMhmacKeyHandle = 0;
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
            TPMhmacKeyHandle = TPM_KEY0_HANDLE;
        break;

        case 0x01:
            TPMhmacKeyHandle = TPM_KEY1_HANDLE;
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
    memcpy(test_buffer.buffer, dv, len_dv);

    ret = Esys_TR_FromTPMPublic(
        tpm_context->esys_context,
        TPMhmacKeyHandle, /* required */
        ESYS_TR_NONE, /* optional (ESYS_TR_NONE) */
        ESYS_TR_NONE, /* optional (ESYS_TR_NONE) */
        ESYS_TR_NONE, /* optional (ESYS_TR_NONE) */
        &hmacKeyHandle /* required (non-NULL) */
    );
    if(ret != 0)
    {
        return UTA_TA_ERROR;
    }

    TPMA_SESSION sessionAttributes = TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_ENCRYPT | TPMA_SESSION_DECRYPT;

    ret = Esys_TRSess_SetAttributes(tpm_context->esys_context,
        tpm_context->session,
        sessionAttributes,
        0xff);

    if(ret != TSS2_RC_SUCCESS)
    {
        return UTA_TA_ERROR;
    }

    ret = Esys_HMAC(
        tpm_context->esys_context,
        hmacKeyHandle,
        ESYS_TR_PASSWORD,
        tpm_context->session,
        ESYS_TR_NONE,
        &test_buffer,
        TPM2_ALG_SHA256,
        &outHMAC);

    if(ret != 0)
    {
        return UTA_TA_ERROR;
    }

    if(outHMAC->size < len_key)
    {
        return UTA_TA_ERROR;
    }

    /* Release the accesslock mutex (ignore return code) */
    (void)pthread_mutex_unlock(&tpm_context_w->accesslock);

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
    /* This function needs writing access to the context */
    uta_context_v1_t *tpm_context_w = (uta_context_v1_t*)tpm_context;

    TSS2_RC ret;
    int ret_val;
    TPM2B_DIGEST *randomBytes;
    uint32_t bytesRequested = len_random;
    uint32_t bytesCopied;

    /* Lock the device access with the accesslock mutex */
    ret_val = pthread_mutex_lock(&tpm_context_w->accesslock);
    if (ret_val != 0)
    {
        return UTA_TA_ERROR;
    }

    TPMA_SESSION sessionAttributes = TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_ENCRYPT;

    ret = Esys_TRSess_SetAttributes(
        tpm_context->esys_context,
        tpm_context->session,
        sessionAttributes,
        0xff);

    if(ret != TSS2_RC_SUCCESS)
    {
        return UTA_TA_ERROR;
    }

    for(bytesCopied = 0; bytesCopied < len_random ; )
    {
        bytesRequested = len_random - bytesCopied;

        /* Get Random numbers from TPM */
        ret = Esys_GetRandom(
            tpm_context->esys_context,
            tpm_context->session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            bytesRequested,
            &randomBytes);

        if(ret != TSS2_RC_SUCCESS)
        {
            free(randomBytes);
            return UTA_TA_ERROR;
        }

        size_t br;
        /* copy as many bytes as were received or until bytes requested */
        for (br = 0 ; (br < randomBytes->size) && (bytesCopied < len_random) ; br++)
        {
            random[bytesCopied] = randomBytes->buffer[br];
            bytesCopied++;
        }
        free(randomBytes);
    }

    /* Release the accesslock mutex (ignore return code) */
    (void)pthread_mutex_unlock(&tpm_context_w->accesslock);

    if(ret != 0)
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

    TSS2_RC ret;
    int ret_val;

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

    /* Lock the device access with the accesslock mutex */
    ret_val = pthread_mutex_lock(&tpm_context_w->accesslock);
    if (ret_val != 0)
    {
        return UTA_TA_ERROR;
    }

    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;
    inPublic.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM2_ALG_SHA256;

    ret = Esys_CreatePrimary(
        tpm_context->esys_context,
        ESYS_TR_RH_ENDORSEMENT,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &inSensitivePrimary,
        &inPublic,
        &outsideInfo,
        &creationPCR,
        &primaryHandle,
        &outPublic,
        &creationData,
        &creationHash,
        &creationTicket);

    if(ret != TSS2_RC_SUCCESS)
    {
        /* Release the accesslock mutex (ignore return code) */
        (void)pthread_mutex_unlock(&tpm_context_w->accesslock);
        return UTA_TA_ERROR;
    }

    ret = Esys_TR_SetAuth(
        tpm_context->esys_context,
        primaryHandle,
        &authValuePrimary);

    if(ret != TSS2_RC_SUCCESS)
    {
        return UTA_TA_ERROR;
    }

    TPM2B_MAX_BUFFER test_buffer = { .size = 8,
                                     .buffer={0x44, 0x45, 0x56, 0x49, 0x43, 0x45, 0x49, 0x44}} ;
    TPM2B_DIGEST *outHMAC;


    TPMA_SESSION sessionAttributes = TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_ENCRYPT | TPMA_SESSION_DECRYPT;

    ret = Esys_TRSess_SetAttributes(
        tpm_context->esys_context,
        tpm_context->session,
        sessionAttributes,
        0xff);

    if(ret != TSS2_RC_SUCCESS)
    {
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

    if(ret != TSS2_RC_SUCCESS)
    {
        return UTA_TA_ERROR;
    }

    if(outHMAC->size < 16)
    {
        return UTA_TA_ERROR;
    }

    ret = Esys_FlushContext(tpm_context->esys_context, primaryHandle);
    if(ret != TSS2_RC_SUCCESS)
    {
        return UTA_TA_ERROR;
    }

    /* Release the accesslock mutex (ignore return code) */
    (void)pthread_mutex_unlock(&tpm_context_w->accesslock);

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
    /* This function needs writing access to the context */
    uta_context_v1_t *tpm_context_w = (uta_context_v1_t*)tpm_context;
    int ret_val;

    TSS2_RC ret;
    TPM2B_MAX_BUFFER *outData;
    TPM2_RC testResult;

    /* Lock the device access with the accesslock mutex */
    ret_val = pthread_mutex_lock(&tpm_context_w->accesslock);
    if (ret_val != 0)
    {
        return UTA_TA_ERROR;
    }

    ret = Esys_SelfTest(tpm_context->esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        1);

    if(ret != TSS2_RC_SUCCESS)
    {
        /* Release the accesslock mutex (ignore return code) */
        (void)pthread_mutex_unlock(&tpm_context_w->accesslock);
        return UTA_TA_ERROR;
    }

    ret = Esys_GetTestResult(
        tpm_context->esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &outData,
        &testResult);

    if(ret != TSS2_RC_SUCCESS)
    {
        return UTA_TA_ERROR;
    }

    /* Release the accesslock mutex (ignore return code) */
    (void)pthread_mutex_unlock(&tpm_context_w->accesslock);

    if(testResult != TSS2_RC_SUCCESS)
    {
        free(outData);
        return UTA_TA_ERROR;
    }
    free(outData);

    return UTA_SUCCESS;
}
