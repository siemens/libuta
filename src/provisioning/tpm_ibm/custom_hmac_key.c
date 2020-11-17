/** @file custom_hmac_key.c
* 
* @brief Load a custom external HMAC key
*
* @copyright Copyright (c) Siemens Mobility GmbH, 2020
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "tss2/tss.h"
#include "tss2/tssutils.h"
#include "tss2/tssresponsecode.h"
#include "tss2/tssmarshal.h"

/*******************************************************************************
 * Defines
 ******************************************************************************/
#define HMAC_KEY_SIZE        32
#define HMAC_KEY_HASH_SIZE   32
#define HMAC_SEED_SIZE   	 32
#define AUTH_POLICY_BIN_SIZE 32

/*******************************************************************************
 * Private function prototypes
 ******************************************************************************/
static int loadexternal_hmac_key(char *key_path);

/*******************************************************************************
 * Public function bodies
 ******************************************************************************/        
/**
 * @brief Loads a custom HMAC key into the TPM.
 * @param[in] argc Number of parameters.
 * @param[in] argv List of parameters. argv[1] gives the path to the files.
 * @return Linux return code.
 */
int main(int argc, char **argv)
{
    /* Set debug level */
    (void)TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "0");

    if(argc == 2)
    {
        loadexternal_hmac_key(argv[1]);
    }
    else
    {
        printf("Wrong number of arguments!");
        return 1;
    }

    return 0;
}

/*******************************************************************************
 * Private function bodies
 ******************************************************************************/ 
/**
 * @brief Loads an external HMAC key to the TPM.
 * @param[in] key_path Path to the files.
 * @return IBM TSS return code.
 */
static int loadexternal_hmac_key(char *key_path)
{
    int i;

    TPM_RC           rc = 0;
    TSS_CONTEXT      *tssContext = NULL;
    LoadExternal_In  in;
    LoadExternal_Out out;

    char hmac_key_pub_file[] = "hmac_key_pub.bin";
    char* key_password     = NULL;
    
    FILE *fileptr;
    BYTE hmac_key[HMAC_KEY_SIZE];
    BYTE hmac_seed[HMAC_SEED_SIZE];
    BYTE hmac_key_hash[HMAC_KEY_HASH_SIZE];
    

	// Load hmac_key from file
	fileptr = fopen(key_path, "rb");  // Open the file in binary mode
	fread(hmac_key, HMAC_KEY_SIZE, 1, fileptr); // Read in the entire file
	(void)fclose(fileptr); // Close the file
	
	// Load hmac_seed from file
	fileptr = fopen("hmac_seed.bin", "rb");  // Open the file in binary mode
	fread(hmac_seed, HMAC_SEED_SIZE, 1, fileptr); // Read in the entire file
	(void)fclose(fileptr); // Close the file
	
	// Load hmac_key_hash from file
	fileptr = fopen("hmac_key_hash.bin", "rb");  // Open the file in binary mode
	fread(hmac_key_hash, HMAC_KEY_HASH_SIZE, 1, fileptr); // Read in the entire file
	(void)fclose(fileptr); // Close the file

    BYTE auth_policy_bin[AUTH_POLICY_BIN_SIZE] = {0xbe, 0xf5, 0x6b, 0x8c, 0x1c, 0xc8, 0x4e, 0x11,
                                                  0xed, 0xd7, 0x17, 0x52, 0x8d, 0x2c, 0xd9, 0x93,
                                                  0x56, 0xbd, 0x2b, 0xbf, 0x8f, 0x01, 0x52, 0x09,
                                                  0xc3, 0xf8, 0x4a, 0xee, 0xab, 0xa8, 0xe8, 0xa2};

    printf("INFO: Using TPM2_LoadExternal() to load custom HMAC key...\n");

    in.inPrivate.t.size = 1; /* size != 0 means that there is private data */
    in.inPrivate.t.sensitiveArea.sensitiveType = TPM_ALG_KEYEDHASH;
    /* in.inPrivate.t.sensitiveArea.authValue.t.size = 0; */
    rc = TSS_TPM2B_StringCopy(&in.inPrivate.t.sensitiveArea.authValue.b, key_password, sizeof(TPMU_HA));
    
    in.inPrivate.t.sensitiveArea.seedValue.t.size = HMAC_SEED_SIZE; 
    memcpy(&in.inPrivate.t.sensitiveArea.seedValue.t.buffer, hmac_seed, HMAC_SEED_SIZE);
    
    in.inPrivate.t.sensitiveArea.sensitive.bits.t.size = HMAC_KEY_SIZE;
    memcpy(&in.inPrivate.t.sensitiveArea.sensitive.bits.t.buffer, hmac_key, HMAC_KEY_SIZE);

    in.inPublic.publicArea.type = TPM_ALG_KEYEDHASH;
    in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    in.inPublic.publicArea.objectAttributes.val = TPMA_OBJECT_SIGN | TPMA_OBJECT_USERWITHAUTH;
    in.inPublic.publicArea.authPolicy.t.size = AUTH_POLICY_BIN_SIZE;
    memcpy(&in.inPublic.publicArea.authPolicy.t.buffer, auth_policy_bin, AUTH_POLICY_BIN_SIZE);
    in.inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    in.inPublic.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA256;
    in.inPublic.publicArea.unique.keyedHash.t.size = HMAC_KEY_HASH_SIZE;
    memcpy(&in.inPublic.publicArea.unique.keyedHash.t.buffer, hmac_key_hash, HMAC_KEY_HASH_SIZE);

    in.hierarchy = TPM_RH_NULL; /* has to be null hierarchy for external sensitive data */

    /* write public structure to file */
    rc = TSS_File_WriteStructure(&in.inPublic,
                                 (MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshal,
                                 hmac_key_pub_file);
    printf("INFO: TSS_File_WriteStructure: rc = %08x\n", rc);

    /* create TSS context */
    rc = TSS_Create(&tssContext);
    printf("INFO: TSS_Create: rc = %08x\n", rc);

    /* execute LoadExternal command */
    if (rc == 0) {
        rc = TSS_Execute(tssContext,
                         (RESPONSE_PARAMETERS *) &out, 
                         (COMMAND_PARAMETERS *) &in,
                         NULL,
                         TPM_CC_LoadExternal,
                         TPM_RH_NULL, NULL, 0,
                         TPM_RH_NULL, NULL, 0,
                         TPM_RH_NULL, NULL, 0,
                         TPM_RH_NULL, NULL, 0);
        printf("INFO: TSS_Execute: rc = %08x\n", rc);
    }
    
    /* delete TSS context */
    if (rc == 0) {
        rc = TSS_Delete(tssContext);
        printf("INFO: TSS_Delete: rc = %08x\n", rc);
    }

    if (rc == 0) {
        printf("INFO: out.objectHandle = %08x\n", out.objectHandle);
        printf("INFO: out.name.t.size  = %08x\n", out.name.t.size);
        printf("INFO: out.name.t.name  =\n");
        for (i = 0; i < out.name.t.size; i++) {
          printf("%02x", out.name.t.name[i]);
          if ((i+1)%4 == 0) printf(" ");
          if ((i+1)%16 == 0) printf("\n");
        }
        printf("\n");
    }
    else {
        const char *msg;
        const char *submsg;
        const char *num;
        TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
        printf("%s%s%s\n", msg, submsg, num);
        rc = EXIT_FAILURE;
    }

    return rc;
}

