/** @file uta_sim.h
* 
* @brief Unified Trust Anchor (UTA) Software Simulator for development purposes
*
* @copyright Copyright (c) Siemens Mobility GmbH, 2020-2026
*
* @author Thomas Zeschg <thomas.zeschg@siemens.com>
*
* @license This work is licensed under the terms of the Apache Software License 
* 2.0. See the COPYING file in the top-level directory.
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
 #define KEY_SLOT_0 {0x80,0x6d,0x42,0x7c,0xfd,0x33,0x7f,0xcf, \
                     0xa3,0xe9,0xf1,0xa9,0xf9,0x20,0x27,0x27, \
                     0x91,0xc0,0x03,0x60,0x33,0x90,0xdd,0x26, \
                     0xed,0x54,0x6c,0x45,0x14,0x42,0x49,0x70}
 #define KEY_SLOT_1 {0x94,0x2a,0x25,0xb1,0x2d,0xab,0xcb,0xc8, \
                     0x05,0xb6,0x48,0x75,0x5b,0xeb,0x04,0xb1, \
                     0xa0,0xa3,0x69,0x4f,0x8e,0x70,0x19,0xaa, \
                     0x5c,0xd8,0x3a,0x15,0xfb,0x48,0x08,0xea}

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
