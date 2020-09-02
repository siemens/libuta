/** @file uta.c
* 
* @brief Unified Trust Anchor (UTA) API
*
* @copyright Copyright (c) Siemens Mobility GmbH, 2020
*
* @author Hermann Seuschek <hermann.seuschek@siemens.com>
* @author Thomas Zeschg <thomas.zeschg@siemens.com>
*
* \license This work is licensed under the terms of the Apache Software License 
* 2.0. See the LICENSE file in the top-level directory.
*
* SPDX-License-Identifier: Apache-2.0
*/

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include <config.h>
#include <stdio.h>
#include <stdint.h>
#include <uta.h>
#include <tpm_ibm.h>
#include <uta_sim.h>
#include <tpm_tcg.h>

/*******************************************************************************
 * Public function bodies
 ******************************************************************************/
/**
 * @brief Returns the version of the library.
 * @param[in,out] uta_context Pointer to the internal context struct.
 * @param[out] version Version struct filled with the current library version.
 * @return UTA return code.
 */
uta_rc uta_get_version(const uta_context_v1_t *uta_context,
    uta_version_t *version)
{
    #ifdef HW_BACKEND_TPM_IBM
    version->uta_type=TPM_IBM;
    #endif

    #ifdef HW_BACKEND_UTA_SIM
    version->uta_type=UTA_SIM;
    #endif
    
    #ifdef HW_BACKEND_TPM_TCG
    version->uta_type=TPM_TCG;
    #endif

    (void)sscanf(VERSION,"%u.%u.%u",&(version->major), &(version->minor),
        &(version->patch));

    return UTA_SUCCESS;
}

/**
 * @brief Get the highest key length (in Bytes), which derive key can provide.
 *      For version 1 of the API it is the same for all trust anchors.
 * @return Highest key length (in Bytes), which derive key can provide.
 */
size_t uta_len_key_max(void)
{
    return 32;
}

/**
 * @brief Returns a struct containing the function pointers of UTA v1.
 * @param[out] uta Struct with the v1 function pointers.
 * @return UTA return code.
 */
uta_rc uta_init_v1(uta_api_v1_t *uta)
{
// Pointer to the TPM_IBM functions
#if HW_BACKEND_TPM_IBM
    uta->context_v1_size=&tpm_context_v1_size;
    uta->open=&tpm_open;
    uta->close=&tpm_close;
    uta->derive_key=&tpm_derive_key;
    uta->get_random=&tpm_get_random;
    uta->self_test=&tpm_self_test;
    uta->get_device_uuid=&tpm_get_device_uuid;

// Pointer to the UTA_SIM functions
#elif HW_BACKEND_UTA_SIM
    uta->context_v1_size=&sim_context_v1_size;
    uta->open=&sim_open;
    uta->close=&sim_close;
    uta->derive_key=&sim_derive_key;
    uta->get_random=&sim_get_random;
    uta->self_test=&sim_self_test;
    uta->get_device_uuid=&sim_get_device_uuid;
    
// Pointer to the TPM_TCG functions
#elif HW_BACKEND_TPM_TCG
	uta->context_v1_size=&tpm_context_v1_size;
	uta->open=&tpm_open;
	uta->close=&tpm_close;
	uta->derive_key= &tpm_derive_key;
	uta->get_random=&tpm_get_random;
	uta->self_test= &tpm_self_test;
	uta->get_device_uuid= &tpm_get_device_uuid;
    
#else
#error "No valid HARDWARE defined!"
#endif
// Hardware independent function
    uta->get_version=&uta_get_version;
    uta->len_key_max=&uta_len_key_max;
    
    return UTA_SUCCESS;
}
