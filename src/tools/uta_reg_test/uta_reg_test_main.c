/** @file uta_reg_test_main.c
* 
* @brief Unified Trust Anchor (UTA) regression tests. The test environment is
* inspired by minunit: http://www.jera.com/techinfo/jtns/jtn002.html
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
 
/*******************************************************************************
 * Includes
 ******************************************************************************/
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <config.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>

#include <uta.h>
#include <mbedtls/md.h>

/*******************************************************************************
 * Data types
 ******************************************************************************/
typedef int(*test_case_t)(uta_context_v1_t *uta_context);

/*******************************************************************************
 * Defines
 ******************************************************************************/
/* Parameters for the derive_key regression test */
#define KEYLEN           32
#define DVLEN            8
#define NR_VEC           10
#define USED_KEY_SLOTS   2

/* 
 * Parameters for the RNG regression test 
 * NOTE: This statistical test is designed to find critical errors, such as
 * implementation errors. If the test passes, it does NOT automatically mean
 * that the random numbers have a high quality! Please refer to the NIST for
 * details about testing random number generators.
 */
#define CHI2_LOWER       7.24628
#define CHI2_UPPER       25.0295
#define CHI2_NUM_REPEATS 5
#define CHI2_N_SAMPLES   128      // Samplesize is 4 bit
   
/*******************************************************************************
 * Static data declaration
 ******************************************************************************/
static uint8_t *key_slots[USED_KEY_SLOTS]={NULL};
/* Global declaration of variable sto store reference values */
static uint8_t ref_uuid[16];
static uint8_t ref_uuid_set=0;
static uint8_t print_version=1;
/* Global declaration of uta struct */
static uta_api_v1_t uta;

/*******************************************************************************
 * Private function prototypes
 ******************************************************************************/
static int run_self_test(uta_context_v1_t *uta_context);
static int test_trng(uta_context_v1_t *uta_context);
static int test_derive_key(uta_context_v1_t *uta_context);
static int test_read_uuid(uta_context_v1_t *uta_context);
static int test_read_version(uta_context_v1_t *uta_context);
static int read_keys(char **key_files, int num);
static void print_usage(char *name);
static void *thread_test_1(void *uta_context);
static void *thread_test_2();

/* Define the test cases */
test_case_t test_cases[] = {\
                                 test_read_version, \
                                 test_read_uuid, \
                                 run_self_test, \
                                 test_trng, \
                                 test_derive_key, \
                                 0 };

/*******************************************************************************
 * Public function bodies
 ******************************************************************************/
/**
 * @brief Performs a set of regression tests.
 * @param[in] argc Number of parameters.
 * @param[in] argv List of parameters. argv[1] Can optional provide the key for
 *      key_slot 0 and argv[2] the key for key slot 1.
 * @return Linux return code.
 */
int main(int argc, char **argv)
{
    int success = 1;
    int ret;
    int i;
    uta_rc rc;
    time_t t;
    uta_context_v1_t *uta_context;
#ifdef MULTIPROCESSING
    int cpid;
#endif
    if(argc == 1)
    {
        printf("Running regression tests without reference keys. Only the return codes are verified.\n\n");
    }
    else if(argc == 2)
    {
        ret = read_keys(&argv[1], (argc - 1));
        if(ret != 0)
        {
            printf("Error while reading the key from file\n");
            print_usage(argv[0]);
            return 1;
        }
        printf("Running regression tests with reference key of key slot 0. For key slot 1 only the return codes are verified.\n\n");
    }
    else if(argc == 3)
    {
        ret = read_keys(&argv[1], (argc - 1));
        if(ret != 0)
        {
            printf("Error while reading the keys from files\n");
            print_usage(argv[0]);
            return 1;
        }
        printf("Running regression tests with reference keys.\n\n");
    }
    else
    {
        printf("Error: Wrong number of arguments!\n");
        print_usage(argv[0]);
        return 1;
    }

#ifndef MULTIPROCESSING
    printf("NOTE: Multiprocessing has been disabled during configure. Only multithreading with one single open call is tested\n\n");
#endif

    srand((unsigned) time(&t));

    rc = uta_init_v1(&uta);
    if (rc != UTA_SUCCESS)
    {
        printf("ERROR during uta_init_v1!\n");
        return 1;
    }
    
    /* Allocate memory for the context */
    uta_context = malloc(uta.context_v1_size());
    if (uta_context == NULL)
    {
        printf("Failed to allocate memory!\n");
        return 1;
    }
    
    printf("Run all the tests once (single thread/process)\n");

    for(i = 0; test_cases[i]; i++)
    {
        rc = uta.open(uta_context);
        if (rc != UTA_SUCCESS)
        {
            printf("ERROR during uta.open!\n");
            return 1;
        }
        
        ret = test_cases[i](uta_context);
        if(ret != 0)
        {
            success = 0;
        }
        
        rc = uta.close(uta_context);
        if (rc != UTA_SUCCESS)
        {
            printf("ERROR during uta.close!\n");
            return 1;
        }
    }
#ifdef MULTIPROCESSING
    printf("\nFork the process and start multiple threads\n");
    /* Fork the program here */
    cpid = fork();
#else
    printf("\nStart multiple threads with the same context\n");
#endif

    /* Start multiple threads and give them the same context */
    pthread_t tr1, tr2, tr3, tr4;
    int tr1_ret, tr2_ret, tr3_ret, tr4_ret;
    
    rc = uta.open(uta_context);
    if (rc != UTA_SUCCESS)
    {
        printf("ERROR during uta.open!\n");
        return 1;
    }

    pthread_create(&tr1, NULL, thread_test_1, (void*)uta_context);
    pthread_create(&tr2, NULL, thread_test_1, (void*)uta_context);
    pthread_create(&tr3, NULL, thread_test_1, (void*)uta_context);
    pthread_create(&tr4, NULL, thread_test_1, (void*)uta_context);
    
    pthread_join(tr1, (void*)&tr1_ret);
    pthread_join(tr2, (void*)&tr2_ret);
    pthread_join(tr3, (void*)&tr3_ret);
    pthread_join(tr4, (void*)&tr4_ret);
    
    if((tr1_ret != 0)||(tr2_ret != 0)||(tr3_ret != 0)||(tr4_ret != 0))
    {
        success = 0;
    }
    
    rc = uta.close(uta_context);
    if (rc != UTA_SUCCESS)
    {
        printf("ERROR during uta.close!\n");
        return 1;
    }

    free(uta_context);

#ifdef MULTIPROCESSING

    /* Start multiple threads and they handle the context themself */
    pthread_create(&tr1, NULL, thread_test_2, NULL);
    pthread_create(&tr2, NULL, thread_test_2, NULL);
    pthread_create(&tr3, NULL, thread_test_2, NULL);
    pthread_create(&tr4, NULL, thread_test_2, NULL);
    
    pthread_join(tr1, (void*)&tr1_ret);
    pthread_join(tr2, (void*)&tr2_ret);
    pthread_join(tr3, (void*)&tr3_ret);
    pthread_join(tr4, (void*)&tr4_ret);
    
    if((tr1_ret != 0)||(tr2_ret != 0)||(tr3_ret != 0)||(tr4_ret != 0))
    {
        success = 0;
    }
    
    /* Distinguish between parent and child process */
    if (cpid == 0)
    {
        /* Child process */
        if (success == 1)
        {
            exit(0);
        }
        exit(1);
    }
    
    /* Wait for the termination of the child process and grep exit code */
    int stat;
    wait(&stat);
    
    if (WEXITSTATUS(stat) != 0)
    {
        success = 0;
    }

#endif
    
    if(success != 0)
    {
        printf("\x1b[1;42mPASS\x1b[0m\n");
        return 0;
    }
    else
    {
        printf("\x1b[93;41mFAIL\x1b[0m\n");
        return 1;
    }
}

/*******************************************************************************
 * Private function bodies
 ******************************************************************************/
/**
 * @brief Helper function to print the usage information.
 */
static void print_usage(char *name)
{
    printf("Usage: %s <key file for key slot 0> <key file for key slot 1>\n",name);
}

/**
 * @brief Runs the self test of the underlying trust anchor and reports the
 *      result.
 * 
 * @param[in,out] uta_context Pointer to the uta_context struct.
 *
 * @return In case of success the function returns 0, 1 otherwise. 
 */
#pragma GCC diagnostic ignored "-Wunused-function"
static int run_self_test(uta_context_v1_t *uta_context)
{
    uta_rc rc;
    
    printf("Executing %s\n",__FUNCTION__);

    // function call to be evaluated
    rc = uta.self_test(uta_context);
    if (rc != UTA_SUCCESS)
    {
        printf("uta.self_test() returned error code %x\n",
        (unsigned int)rc);
        return 1;
    }
    return 0;
}

/**
 * @brief Test the RNG using a chi-squared test.
 *
 * NOTE: This statistical test is designed to find critical errors, such as
 * implementation errors. If the test passes, it does NOT automatically mean
 * that the random numbers have a high quality! Please refer to the NIST for
 * details about testing random number generators.
 * 
 * @param[in,out] uta_context Pointer to the uta_context struct.
 *
 * @return In case of success the function returns 0, 1 otherwise. 
 */
#pragma GCC diagnostic ignored "-Wunused-function"
static int test_trng(uta_context_v1_t *uta_context)
{
    uint8_t random_bytes[CHI2_N_SAMPLES/2];
    uint8_t random_value; // 4 bit random value
    uint8_t histogram[16];
    double chisquared=0;
    int i;
    int j;
    uta_rc rc;
    
    printf("Executing %s\n",__FUNCTION__);

    for(j=0; j<CHI2_NUM_REPEATS; j++){
        /* Set histogram values and chisquared value to zero */
        chisquared = 0;
        for(i=0; i<16; i++){
            histogram[i] = 0;
        }

        /* Fill the buffer with random values */
	    rc = uta.get_random(uta_context, random_bytes, CHI2_N_SAMPLES/2);
	    if (rc != UTA_SUCCESS)
	    {
	    	printf("uta.get_random failed\n");
		    return 1;
	    }

        /* Calculate the chi-squared value of the buffer */
        for (i=0; i<(CHI2_N_SAMPLES/2); i++){
            /* extract the 4 lower bits */
            random_value = random_bytes[i] & 0x0F;
            histogram[random_value]++;
            /* extract the 4 higher bits */
            random_value = random_bytes[i] >> 4;
            histogram[random_value]++;
        }
        for (i=0; i<16; i++){
            chisquared += (histogram[i]-CHI2_N_SAMPLES/16.0)*(histogram[i]-CHI2_N_SAMPLES/16.0)/(CHI2_N_SAMPLES/16.0);
        }

        /* Compare the calculated value with the lower and upper limits */
        if ((chisquared > CHI2_LOWER) && (chisquared < CHI2_UPPER)){
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Test the derive key command using the different key slots.
 * 
 * If no reference keys are provided, only the return code of the calls are
 * checked. Otherwise, the key derivation is calculated in software using the
 * provided keys and compared to the trust anchor output.
 * 
 * @param[in,out] uta_context Pointer to the uta_context struct.
 * @return In case of success the function returns 0, 1 otherwise. 
 */
#pragma GCC diagnostic ignored "-Wunused-function"
static int test_derive_key(uta_context_v1_t *uta_context)
{
    int i;
    int j;
    int ret;
    uta_rc rc;
    uint8_t deriv_value[DVLEN];
    uint8_t ta_output[KEYLEN];
    unsigned char ref_output[KEYLEN];

    printf("Executing %s\n",__FUNCTION__);

    const mbedtls_md_info_t *sha256_hmac = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    for(i=0; i<NR_VEC; i++)
    {
        // Get a random derivation value
        for(j=0; j<DVLEN; j++)
        {
            deriv_value[j] = (uint8_t)(rand() % 256);
        }
    
        for(j=0; j<USED_KEY_SLOTS; j++)
        {
            /* Call derive key using key_slot j */
            rc = uta.derive_key(uta_context, ta_output, 32, deriv_value,
                UTA_LEN_DV_V1, j);
            if (rc != UTA_SUCCESS)
            {
                printf("uta.derive_key using key slot %d failed\n", j);
                return 1;
            }

            if(key_slots[j] != NULL)
            {
                /* 
                 * If a reference key is provided, the key derivation is
                 * calculated in software as well and the two outputs values are
                 * compared.
                 */
                (void)mbedtls_md_hmac(sha256_hmac, key_slots[j], KEYLEN,
                    (unsigned char *)deriv_value, DVLEN, ref_output);

                ret = memcmp(ta_output, ref_output, KEYLEN);
                if (ret != 0)
                {
                    printf("Wrong key derivation using key slot %d\n", j);
                    return 1;
                }
            }
        }
    }
    return 0;
}

/**
 * @brief Test the read UUID function.
 * @param[in,out] uta_context Pointer to the uta_context struct.
 * @return In case of success the function returns 0, 1 otherwise. 
 */
#pragma GCC diagnostic ignored "-Wunused-function"
static int test_read_uuid(uta_context_v1_t *uta_context)
{
    uta_rc rc;
    int ret;
    uint8_t uuid[16];

    printf("Executing %s\n",__FUNCTION__);

    // Get Universally Unique Identifier (UUID) from TA
    rc = uta.get_device_uuid(uta_context, uuid);
    if (rc != UTA_SUCCESS)
    {
        printf("uta.get_device_uuid failed\n");
        return 1;
    }
    
    if(ref_uuid_set == 0)
    {
        printf("Setting reference UUID: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",\
        (unsigned int)uuid[0], (unsigned int)uuid[1], (unsigned int)uuid[2],\
        (unsigned int)uuid[3], (unsigned int)uuid[4], (unsigned int)uuid[5],\
        (unsigned int)uuid[6], (unsigned int)uuid[7], (unsigned int)uuid[8],\
        (unsigned int)uuid[9], (unsigned int)uuid[10], (unsigned int)uuid[11],\
        (unsigned int)uuid[12], (unsigned int)uuid[13], (unsigned int)uuid[14],\
        (unsigned int)uuid[15]);
        memcpy(ref_uuid, uuid, 16);
        ref_uuid_set=1;
    }
    else
    {
        /* Compare the UUID with the referenced set during the first call */
        ret = memcmp(uuid, ref_uuid, 16);
        if (ret != 0)
        {
            printf("UUID does not match the reference UUID set during the first call\n");
            return 1;
        }
    }
    
    return 0;
}

/**
 * @brief Test the read version function.
 * @param[in,out] uta_context Pointer to the uta_context struct.
 * @return In case of success the function returns 0, 1 otherwise. 
 */
#pragma GCC diagnostic ignored "-Wunused-function"
static int test_read_version(uta_context_v1_t *uta_context)
{
    uta_rc rc;
    uta_version_t version;

    printf("Executing %s\n",__FUNCTION__);

    // Get the library version
    rc = uta.get_version(uta_context, &version);
    if (rc != UTA_SUCCESS)
    {
        printf("uta.get_version failed\n");
        return 1;
    }
    
    if(print_version == 1)
    {
        printf("HARDWARE: %u, VERSION: %u.%u.%u\n", \
            (unsigned int)version.uta_type, (unsigned int)version.major, \
            (unsigned int)version.minor, (unsigned int)version.patch);
        print_version=0;
    }

    return 0;
}

/**
 * @brief Reads the provided keys from files.
 * @param[in] array with path to the key files.
 * @param[in] number of provided key files.
 * @return Linux return code. 
 */
int read_keys(char **key_files, int num)
{
    FILE *fileptr;
    int ret;
    
    for(int i=0; i<num; i++)
    {
        /* Allocate memory for the key */
        key_slots[i]=malloc(sizeof(uint8_t)*KEYLEN);
        if(key_slots[i] == NULL)
        {
            if(i == 1)
            {
                free(key_slots[0]);
            }
            return 1;
        }
        /* Load key from file */
        fileptr = fopen(key_files[i], "rb");  // Open the file in binary mode
        if(fileptr == NULL)
        {
            free(key_slots[0]);
            if(i == 1)
            {
                free(key_slots[1]);
            }
            return 1;
        }
        /* Read in the entire file */
        ret = (int)fread(key_slots[i], 1, KEYLEN, fileptr); 
        if(ret != KEYLEN)
        {
            free(key_slots[0]);
            if(i == 1)
            {
                free(key_slots[1]);
            }
            (void)fclose(fileptr); // Close the file
            return 1;
        }
        (void)fclose(fileptr); // Close the file
    }
    return 0;
}

/**
 * @brief Perform all the defined tests using the already opened UTA session
 * with the given UTA context.
 * @param[in,out] uta_context Pointer to the uta_context struct.
 * @return 0 if the tests completed successfully, 1 otherwise. 
 */
static void *thread_test_1(void *uta_context)
{
    int ret;
    int i;
    
    for(i = 0; test_cases[i]; i++)
    {
        ret = test_cases[i]((uta_context_v1_t *)uta_context);
        if(ret != 0)
        {
            pthread_exit((void *)1);
        }
    }
    pthread_exit((void *)0);
}
/**
 * @brief Perform all the defined tests in an own thread, creating an individual
 * UTA context.
 * @param[in,out] uta_context Pointer to the uta_context struct.
 * @return return 0 if the tests completed successfully, 1 otherwise. 
 */
static void *thread_test_2()
{
    uta_context_v1_t *uta_context;
    int ret;
    int i;
    uta_rc rc;
    
    /* Allocate memory for the context */
    uta_context = malloc(uta.context_v1_size());
    if (uta_context == NULL)
    {
        printf("Failed to allocate memory!\n");
        pthread_exit((void *)1);
    }
    
    for(i = 0; test_cases[i]; i++)
    {
        rc = uta.open(uta_context);
        if (rc != UTA_SUCCESS)
        {
            printf("ERROR during uta.open!\n");
            pthread_exit((void *)1);
        }
        
        ret = test_cases[i](uta_context);
        if(ret != 0)
        {
            pthread_exit((void *)1);
        }
        
        rc = uta.close(uta_context);
        if (rc != UTA_SUCCESS)
        {
            printf("ERROR during uta.close!\n");
            pthread_exit((void *)1);
        }
    }
    free(uta_context);
    pthread_exit((void *)0);
}
