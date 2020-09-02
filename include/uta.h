/** @file uta.h
* 
* @brief Unified Trust Anchor (UTA) API
*
* @copyright Copyright (c) Siemens Mobility GmbH, 2020
*
* @author Hermann Seuschek <hermann.seuschek@siemens.com>
* @author Thomas Zeschg <thomas.zeschg@siemens.com>
*
* @license This work is licensed under the terms of the Apache Software License 
* 2.0. See the LICENSE file in the top-level directory.
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _UTA_H_
#define _UTA_H_

#include <stdlib.h>
#include <stdint.h>

/**
 * @brief Typedef for the UTA return values.
 */
typedef uint32_t uta_rc;

/**
 * Different return values of the UTA API.
 */
#define UTA_SUCCESS            0x00 /**< @brief Function execution successful */
#define UTA_INVALID_KEY_LENGTH 0x01 /**< @brief Invalid len_key parameter */
#define UTA_INVALID_DV_LENGTH  0x02 /**< @brief Invalid len_dv parameter */
#define UTA_INVALID_KEY_SLOT   0x03 /**< @brief Invalid key_slot parameter */
#define UTA_TA_ERROR           0x10 /**< @brief General trust anchor error */

/**
 * @brief Return value of the get_version function.
 */
typedef struct{
	/**
	 * Type of the trust anchor used by the library.
	 */
	enum{
		UTA_SIM=0, /**< UTA Software Simulator for development purposes */
		TPM_IBM=1, /**< TPM based on the IBM TSS */
        TPM_TCG=2  /**< TPM based on the TCG TSS */
	} uta_type;    	  
	uint32_t major; /**< Major version number of the library. */
	uint32_t minor; /**< Minor version number of the library. */
	uint32_t patch; /**< Patch number of the library. */
} uta_version_t;  

/**
 * @brief Opaque struct to store the library context.
 */
typedef struct _uta_context_v1_t uta_context_v1_t;

/**
 * @brief Struct containing pointers to functions implemented
 * in version 1 of the library.
 */
typedef struct {
	/**
	 * Returns the size of uta_context_v1_t. This function is
	 * needed to allocate memory for the context.
	 */
	size_t (*context_v1_size)(void);
	
	/**
	 * Returns the highest key length in Bytes, which the derive_key
	 * function can provide.
	 */
	size_t (*len_key_max)(void);
	
	/**
	 * Opens the connection to the trust anchor and blocks the
	 * device file.
	 */
	uta_rc (*open)(const uta_context_v1_t *uta_context);
	
	/**
	 * Closes the connection and frees the device file.
	 */
	uta_rc (*close)(const uta_context_v1_t *uta_context);
	
	/**
	 * Derives a key from the trust anchor using the derivation
	 * value given in dv and it's length len_dv. The trust anchor uses
	 * the key specified by the parameter key_slot. Currently the trust anchor
     * uses SHA256 as the HMAC hash function. The user can request a number of
     * bytes between 0 and 32 given in len_key. The number of bytes are
	 * written to key. The currently implemented dv length is 8 Bytes.
	 * If key_slot, len_key or len_dv are outside their defined range, the
	 * function returns the corresponding uta_rc error value.
	 */
	uta_rc (*derive_key)(const uta_context_v1_t *uta_context, uint8_t *key,
            size_t len_key, const uint8_t *dv, size_t len_dv, uint8_t key_slot);
	
	/**
	 * Writes len_random number of random bytes to random.
	 */
	uta_rc (*get_random)(const uta_context_v1_t *uta_context, uint8_t *random,
            size_t len_random);
	
	/**
	 * Returns a 16 Byte uuid which is formatted as defined by
	 * RFC4122. It is a version 4 UUID calculated by HMACing the 8 Byte
	 * string "DEVICEID" using key_slot 1 and returning the first 16
	 * Bytes.
	 */
	uta_rc (*get_device_uuid)(const uta_context_v1_t *uta_context,
            uint8_t *uuid);
	
	/**
	 * Performs a self test on the trust anchor and returns the
	 * result as uta_rc.
	 */
	uta_rc (*self_test)(const uta_context_v1_t *uta_context);
	
	/**
	 * Returns a struct uta_version_t containing the used trust
	 * anchor and version number.
	 */
	uta_rc (*get_version)(const uta_context_v1_t *uta_context, 
            uta_version_t *version);
	
} uta_api_v1_t;

/**
 * @brief Makro for the implemented DV length in version 1 of the API.
 * (8 Bytes)
 */
#define UTA_LEN_DV_V1	8

/**
 * @brief Entry point to UTA version 1. This function returns the struct
 * uta_api_v1_t, containing pointers to the functions explained above.
 */
extern uta_rc uta_init_v1(uta_api_v1_t *uta);

#endif /* _UTA_H_ */

