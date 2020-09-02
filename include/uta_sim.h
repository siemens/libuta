/** @file uta_sim.h
* 
* @brief Unified Trust Anchor (UTA) Software Simulator for development purposes
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
 
#ifndef _UTA_SIM_H
#define _UTA_SIM_H

#include <uta.h>

/*******************************************************************************
 * Defines
 ******************************************************************************/
 /* 32 Byte Keys for Key Slot 0 and 1 used for the TA Software Simulation */
 #define KEY_SLOT_0 {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, \
                     0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f, \
                     0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17, \
                     0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f}
 #define KEY_SLOT_1 {0x1f,0x1e,0x1d,0x1c,0x1b,0x1a,0x19,0x18, \
                     0x17,0x16,0x15,0x14,0x13,0x12,0x11,0x10, \
                     0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08, \
                     0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00}

/*******************************************************************************
 * Function prototypes
 ******************************************************************************/
size_t sim_context_v1_size(void);
uta_rc sim_open(const uta_context_v1_t *sim_context);
uta_rc sim_close(const uta_context_v1_t *sim_context);
uta_rc sim_derive_key(const uta_context_v1_t *sim_context, uint8_t *key, \
        const size_t len_key, const uint8_t *dv, size_t len_dv, \
        uint8_t key_slot);
uta_rc sim_get_random(const uta_context_v1_t *sim_context, uint8_t *random, \
        size_t len_random);
uta_rc sim_get_device_uuid(const uta_context_v1_t *sim_context, uint8_t *uuid);
uta_rc sim_self_test(const uta_context_v1_t *sim_context);

#endif /* _UTA_SIM_H */
