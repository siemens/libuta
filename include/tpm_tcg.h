/** @file tpm_tcg.h
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
*/

#ifndef TPM_TCG_H
#define TPM_TCG_H

#include <uta.h>
#include <stdint.h>

/*******************************************************************************
 * Function Prototypes
 ******************************************************************************/
size_t tpm_context_v1_size(void);
uta_rc tpm_open(const uta_context_v1_t *tpm_context);
uta_rc tpm_close(const uta_context_v1_t *tpm_context);
uta_rc tpm_derive_key(const uta_context_v1_t *tpm_context, uint8_t *key,
        size_t len_key, const uint8_t *dv, size_t len_dv, uint8_t key_slot);
uta_rc tpm_get_random(const uta_context_v1_t *tpm_context, uint8_t *random,
        size_t len_random);
uta_rc tpm_get_device_uuid(const uta_context_v1_t *tpm_context, uint8_t *uuid);
uta_rc tpm_self_test(const uta_context_v1_t *tpm_context);

#endif /* TPM_TCG_H */
