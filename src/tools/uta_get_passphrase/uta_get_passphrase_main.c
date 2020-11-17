/** @file uta_get_passphrase_main.c
* 
* @brief Derive passphrase from TA and print it to stdout
*
* @copyright Copyright (c) Siemens Mobility GmbH, 2020
*
* @author Hermann Seuschek <hermann.seuschek@siemens.com>
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
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <uta.h>

/*******************************************************************************
 * Defines
 ******************************************************************************/
#define TA_KEY_BYTES 32

/*******************************************************************************
 * Enums
 ******************************************************************************/
typedef enum {BASE64_ENCODING, HEX_ENCODING} string_encoding_t;

/*******************************************************************************
 * Static data declaration
 ******************************************************************************/
static uta_api_v1_t uta;
static uta_context_v1_t *uta_context;

/*******************************************************************************
 * Private function prototypes
 ******************************************************************************/
static int bytes2hexstr(const char *bin_in, size_t input_length,
                        char *hex_out, size_t output_length);
static int bytes2base64(const char *input_data, size_t input_length,
                        char *base64_data, size_t output_length);
static int get_passphrase_from_ta(char **passphrase,
           const char *derivation_string, uint8_t key_slot,
           string_encoding_t string_encoding);

/*******************************************************************************
 * Private function bodies
 ******************************************************************************/

/**
 * @brief Converts bytes to a string with hexadecimal values.
 * @param[in] bin_in Buffer with the input bytes.
 * @param[in] input_length Number of bytes to convert.
 * @param[out] key_out Buffer with the string output.
 * @param[in] output_length Size of output buffer 'hex_out'.
 * @return Always returns 0 -> indicate a successful run
 */
static int bytes2hexstr(const char *bin_in, size_t input_length,
                        char *hex_out, size_t output_length)
{
    const char hex_str[] = "0123456789abcdef";

    if (output_length < (input_length*2)+1)
    {
        return 1;
    }

    // generate hex string from bytes
    for (int i=0; i < input_length; i++)
    {
        hex_out[i*2]   = hex_str[(bin_in[i]>>4) & 0xf];
        hex_out[i*2+1] = hex_str[ bin_in[i]     & 0xf];
    }
    hex_out[input_length*2] = '\0';

    return 0;
}

/**
* @brief Converts bytes to a base64 encoded string.
* @param[in] input_data Buffer with the input bytes.
* @param[in] input_length Length of input data in bytes.
* @param[out] base64_data Buffer for the base64 string
*             output allocated by caller.
* @param[in] output_length Length of base64_data buffer
* @return returns 0 on success,
*         returns 1 in case of insufficient output buffer length.
*/
static int bytes2base64(const char *input_data, size_t input_length,
                        char *base64_data, size_t output_length)
{
    const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // max_output_length includes padding and null string termination
    int max_output_length = (4 * ((input_length + 2) / 3)) + 1;
    if (output_length < max_output_length)
    {
       return 1;
    }

    /* Actual conversion from binary data to base64 encoding takes place in
     * this loop. */
    int j = 0;
    for (int i = 0; i < input_length && j < max_output_length;)
    {
        uint32_t a = i < input_length ? (uint8_t)input_data[i++] : 0;
        uint32_t b = i < input_length ? (uint8_t)input_data[i++] : 0;
        uint32_t c = i < input_length ? (uint8_t)input_data[i++] : 0;
        uint32_t t = (a << 0x10) + (b << 0x08) + c;
 
        base64_data[j++] = base64_table[(t >> 18) & 0x3F];
        base64_data[j++] = base64_table[(t >> 12) & 0x3F];
        base64_data[j++] = base64_table[(t >>  6) & 0x3F];
        base64_data[j++] = base64_table[(t      ) & 0x3F];
    }

    /* Perform padding step with \0 termination characters. The
     * standard '='-padding is omitted. */
    for (int i = 0; i < ((3 - (input_length%3)) % 3); i++)
    {
        base64_data[max_output_length - 2 - i] = '\0';
    }
    /* If there is no padding required, we have to terminate the string anyway.
     * Here this termination is done by default for simplicity */
    base64_data[max_output_length - 1] = '\0';

    return 0;
}

/**
 * @brief Get passphrase from trust anchor.
 * @param[out] passphrase Buffer containing the derived passphrase.
 * @param[in]  derivation_string Buffer containing the derivation value
 * @return returns 0 on success,
 *         returns 1 in case of an error
 */
static int get_passphrase_from_ta(char **passphrase,
                                  const char *derivation_string,
                                  uint8_t key_slot,
                                  string_encoding_t string_encoding)
{
    uta_rc rc;
    char key[TA_KEY_BYTES] = {0};
    char dv_padded[UTA_LEN_DV_V1];

    /* The 'derivation_string' is a variable length C-string while the
     * UTA-library requires a fixed length (UTA_LEN_DV_V1) byte string. This
     * loop copies the first UTA_LEN_DV_V1 bytes and pads the resulting byte
     * string if necessary */
    int padding = 0;
    for(int i=0; i < UTA_LEN_DV_V1; i++)
    {
        if (0 == derivation_string[i])
        {
           padding=1;
        }
        dv_padded[i] = padding==1 ? '=' : derivation_string[i];
    }

    rc = uta_init_v1(&uta);
    if (UTA_SUCCESS != rc)
    {
        return 1;
    }

    /* Allocate memory for the context */
    uta_context = malloc(uta.context_v1_size());
    if (NULL == uta_context)
    {
        return 1;
    }

    rc = uta.open(uta_context);
    if (UTA_SUCCESS != rc)
    {
        free(uta_context);
        return 1;
    }

    // Derive key from TA using derivation string
    rc = uta.derive_key(uta_context,
                        (unsigned char *) key,
                        TA_KEY_BYTES,
                        (unsigned char *) dv_padded,
                        UTA_LEN_DV_V1,
                        key_slot);
    if (UTA_SUCCESS != rc)
    {
        free(uta_context);
        return 1;

    }

    rc = uta.close(uta_context);
    if (UTA_SUCCESS != rc)
    {
        free(uta_context);
        return 1;
    }

    free(uta_context);
    uta_context=NULL;

    // convert binary key data into a printable string (passphrase)
    if (BASE64_ENCODING == string_encoding)
    {
        *passphrase = malloc((4 * ((TA_KEY_BYTES + 2) / 3)) + 1 );
        if (NULL != *passphrase)
        {
            if(0 != bytes2base64(key, TA_KEY_BYTES, *passphrase, (4 * ((TA_KEY_BYTES + 2) / 3)) + 1 ))
            {
                return 1;
            }
        }
        else
        {
           return 1;
        }
    }
    else if (HEX_ENCODING == string_encoding)
    {
        *passphrase = malloc(TA_KEY_BYTES * 2 + 1);
        if (NULL != *passphrase)
        {
            if(0 != bytes2hexstr(key, TA_KEY_BYTES, *passphrase, TA_KEY_BYTES * 2 + 1))
            {
                return 1;
            }
        }
        else
        {
            return 1;
        }
    }
    else
    {
       return 1;
    }
    return 0;
}

/**
 * @brief Basic command line interface to retrieve a passphrase from the
 *         HW trust anchor.
 * @param[in] derivation_string: character string used in passphrase
 *         derivation. Only the first eight characters are considered.
 * @return exit status 0 on success,
 *         exit status 1 in case of an error
 */
int main(int argc, char *argv[])
{
   char *passphrase=NULL;
   int dflag = 0;
   int eflag = 0;
   int kflag = 0;
   char *dval = NULL;
   char *eval = NULL;
   char *kval = NULL;
   int key_slot = 0;
   string_encoding_t encoding = BASE64_ENCODING;
   int c;

   while ((c = getopt (argc, argv, "d:e:k:h")) != -1)
   {
       switch(c)
       {
       case 'd':
          dflag = 1;
          dval = optarg;
          break;
       case 'e':
          eflag = 1;
          eval = optarg;
          break;
       case 'k':
          kflag = 1;
          kval = optarg;
          break;
       case '?':
       case 'h':
          fprintf(stderr, "### Retrieve passphrase from the UTA trust anchor ### \n\n");
          fprintf(stderr, "Usage: uta_get_passphrase [-d <derivation_string>] [-e <encoding>] [-k <key_slot>] [-h]\n\n");
          fprintf(stderr, "-d <derivation_string>: string used in the computation of passphrase,\n");
          fprintf(stderr, "   maximum length is %d characters; (default value: 'default!')\n", UTA_LEN_DV_V1);
          fprintf(stderr, "-e <encoding>: select encoding of the passphrase from\n");
          fprintf(stderr, "   'base64' and 'hex'; (default: 'base64')\n");
          fprintf(stderr, "-k <key_slot>: select key_slot from 0 and 1;\n");
          fprintf(stderr, "   (default: 1, key_slot containing device specific key)\n");
          fprintf(stderr, "-h This help message\n");
          return 1;
       }
   }

   if(1 == dflag)
   {
      if (UTA_LEN_DV_V1 < strnlen(dval, UTA_LEN_DV_V1+1))
      {
         fprintf(stderr, "ERROR: Derivation string must be %d or less characters long\n", UTA_LEN_DV_V1);
         return 1;
      }
   }
   else
   {
      dval = malloc(9);
      if (NULL == dval)
      {
         return 1;
      }
      snprintf(dval, 9, "default!");
   }

   if(1 == eflag)
   {
      if (0 == strncmp(eval, "base64", 6))
      {
         encoding = BASE64_ENCODING;
      }
      else if (0 == strncmp(eval, "hex", 3))
      {
         encoding = HEX_ENCODING;
      }
      else
      {
         fprintf(stderr, "ERROR: Wrong encoding, specify either 'base64' or 'hex'\n");
         return 1;
      }
   }
   else
   {
      encoding = BASE64_ENCODING;
   }

   if(1 == kflag)
   {
      if (0 == strncmp(kval, "0", 1))
      {
         key_slot = 0;
      }
      else if (0 == strncmp(kval, "1", 1))
      {
         key_slot = 1;
      }
      else
      {
         fprintf(stderr, "ERROR: Wrong key_slot, specify either 0 or 1\n");
         return 1;
      }
   }
   else
   {
      key_slot = 1;
   }

   if (0 != get_passphrase_from_ta(&passphrase, dval, key_slot, encoding))
   {
       return 1;
   }
   printf("%s\n", passphrase);

   free(passphrase);
   if(0 == dflag)
   {
      free(dval);
   }

   return 0;
}
