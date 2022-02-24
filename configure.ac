# Unified Trust Anchor API
#
# Copyright (c) Siemens Mobility GmbH, 2020
#
# Authors:
#  Thomas Zeschg <thomas.zeschg@siemens.com>
#
# This work is licensed under the terms of the Apache Software License 2.0.  See
# the COPYING file in the top-level directory.
#
# SPDX-License-Identifier: Apache-2.0

# Define the desired mbedtls tag to checkout
# m4_define([mbedtls_ref], [mbedtls-2.7.15])
m4_define([mbedtls_ref], [mbedtls-2.16.6])

# Versioning
m4_define([major_version], [1])
m4_define([minor_version], [0])
m4_define([patch_version], [1])

AC_PREREQ([2.69])
AC_INIT([unified_trust_anchor_api], [major_version.minor_version.patch_version], [thomas.zeschg@siemens.com])
AM_INIT_AUTOMAKE([-Wall -Werror])

# Pass the Version to the Makefile for the shared library
LT_VERSION_INFO="major_version:minor_version:patch_version"
AC_SUBST(LT_VERSION_INFO)

# Call before LT_INIT (Prevent autotools warning)
AM_PROG_AR

# Don't build a static library
AC_DISABLE_STATIC(yes)

LT_INIT
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# propagate configure arguments to distcheck
AC_SUBST([DISTCHECK_CONFIGURE_FLAGS],[$ac_configure_args])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_CC_C99
# AC_FUNC_MALLOC

# Define the environment variables
AC_ARG_VAR([HARDWARE], [Define the desired hardware: TPM_IBM, UTA_SIM])
AC_ARG_VAR([TPM_IBM_KEY0_HANDLE], [Only for TPM_IBM: Define the key handle for key slot 0 (default 0x81000000)])
AC_ARG_VAR([TPM_IBM_KEY1_HANDLE], [Only for TPM_IBM: Define the key handle for key slot 1 (default 0x81000001)])
AC_ARG_VAR([TPM_IBM_SALT_HANDLE], [Only for TPM_IBM: Define the key handle for the salt key (default 0x81000002)])
AC_ARG_VAR([TPM_IBM_INTERFACE_TYPE], [Only for TPM_IBM: Override interface type used for IBM TSS API (TSS library default if not set, possibly "sim")])
AC_ARG_VAR([TPM_IBM_DATA_DIR], [Only for TPM_IBM: Override directory to store dynamic data used for IBM TSS API (TSS library default if not set, possibly .)])
AC_ARG_VAR([TPM_IBM_DEVICE], [Only for TPM_IBM: Override tpm device path used for IBM TSS API (TSS library default if not set, possibly /dev/tpm0)])

# Define the environment flag to enable the build and installation of the tools
TOOLS=0
AC_ARG_ENABLE([tools],AS_HELP_STRING([--enable-tools], [Enable the installation of the command line tools]))
AS_IF([test "x$enable_tools" = "xyes"], [
   TOOLS=1
])
AM_CONDITIONAL([TOOLS],[test "$TOOLS" -eq 1])

# Define the environment flag to disable multiple open calls during the regression tests of TPM IBM without resource manager
AC_ARG_WITH([multiprocessing],AS_HELP_STRING([--without-multiprocessing], [Disable the multiprocessing in the regression tests (e.g. if TPM is used without resource manager)]),[],[multiprocessing=yes])
AS_IF([test "x$multiprocessing" = "xyes"], [
   AC_DEFINE([MULTIPROCESSING],[1],[Enable multiprocessing in the regression tests (default)])
])

# IBM TPM TSS library presets
AS_IF([test "x$TPM_IBM_INTERFACE_TYPE" != "x"],AC_DEFINE_UNQUOTED([CONFIGURED_TPM_INTERFACE_TYPE],["$TPM_IBM_INTERFACE_TYPE"],[Interface type for IBM TSS]))
AS_IF([test "x$TPM_IBM_DATA_DIR" != "x"],AC_DEFINE_UNQUOTED([CONFIGURED_TPM_DATA_DIR],["$TPM_IBM_DATA_DIR"],[data dir for variable data storage of IBM TSS]))
AS_IF([test "x$TPM_IBM_DEVICE" != "x"],AC_DEFINE_UNQUOTED([CONFIGURED_TPM_DEVICE],["$TPM_IBM_DEVICE"],[Interface used for TPM access by IBM TSS]))

# Read out key handle inputs
AS_IF([test "x$TPM_IBM_KEY0_HANDLE" = "x"],AC_DEFINE([TPM_IBM_KEY0_HANDLE],[0x81000000],[Handle number of the key in key slot 0]),AC_DEFINE_UNQUOTED([TPM_IBM_KEY0_HANDLE],[$TPM_IBM_KEY0_HANDLE],[Handle number of the key in key slot 0]))
AS_IF([test "x$TPM_IBM_KEY1_HANDLE" = "x"],AC_DEFINE([TPM_IBM_KEY1_HANDLE],[0x81000001],[Handle number of the key in key slot 1]),AC_DEFINE_UNQUOTED([TPM_IBM_KEY1_HANDLE],[$TPM_IBM_KEY1_HANDLE],[Handle number of the key in key slot 1]))
AS_IF([test "x$TPM_IBM_SALT_HANDLE" = "x"],AC_DEFINE([TPM_IBM_SALT_HANDLE],[0x81000002],[Handle number of the salt key]),AC_DEFINE_UNQUOTED([TPM_IBM_SALT_HANDLE],[$TPM_IBM_SALT_HANDLE],[Handle number of the salt key]))

# Read out HARDWARE and make an input validation
AS_IF([test "x$HARDWARE" = "xTPM_IBM"],AC_DEFINE([HW_BACKEND_TPM_IBM],[1],[Use the TPM IBM API]),
	[test "x$HARDWARE" = "xUTA_SIM"],AC_DEFINE([HW_BACKEND_UTA_SIM],[1],[Use the UTA Software Simulator]),
    [test "x$HARDWARE" = "xTPM_TCG"],AC_DEFINE([HW_BACKEND_TPM_TCG],[1],[Use the TPM TCG API]),
	AC_MSG_ERROR([No hardware specified! Use ./configure HARDWARE=TPM_IBM/UTA_SIM/...]))

# Set the hardware define, using the HARDWARE variable
AM_CONDITIONAL([HW_BACKEND_TPM_IBM],[test "x$HARDWARE" = "xTPM_IBM"])
AM_CONDITIONAL([HW_BACKEND_UTA_SIM],[test "x$HARDWARE" = "xUTA_SIM"])
AM_CONDITIONAL([HW_BACKEND_TPM_TCG],[test "x$HARDWARE" = "xTPM_TCG"])

# Clone mbedtls only if nedded
AS_IF([test "x$HARDWARE" = "xUTA_SIM" || test "x$enable_tools" = "xyes" ],AS_IF([test -d ./src/mbedtls],
	git -C ./src/mbedtls fetch --tags && git -C ./src/mbedtls checkout mbedtls_ref,
	git clone -b mbedtls_ref --depth 1 https://github.com/ARMmbed/mbedtls.git ./src/mbedtls))

# Checks for libraries.
AS_IF([test "x$HARDWARE" = "xTPM_IBM"],AC_SEARCH_LIBS([TSS_Create], [tss], [], [AC_MSG_ERROR([unable to find the IBM software stack])]))
AS_IF([test "x$HARDWARE" = "xTPM_TCG"],AC_SEARCH_LIBS([Esys_Create], [tss2-esys], [], [AC_MSG_ERROR([unable to find the TSS libraries])]))
AC_SEARCH_LIBS([pthread_create], [pthread], [], [AC_MSG_ERROR([unable to find the pthread library])])

# Checks for header files.
# Check always
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h stddef.h])
# Check only for TPM
AS_IF([test "x$HARDWARE" = "xTPM_IBM"],AC_CHECK_HEADERS([tss2/tss.h]))

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MMAP
AC_CHECK_FUNCS([memset munmap])

AC_CONFIG_FILES([Makefile
                 src/tools/uta_get_passphrase/Makefile
                 src/tools/uta_reg_test/Makefile
                 src/provisioning/tpm_ibm/Makefile
                 src/lib/Makefile])
AC_OUTPUT

# Print a warning for UTA_SIM
AS_IF([test "x$HARDWARE" = "xUTA_SIM"],AC_MSG_WARN([UTA_SIM is an insecure software simulation and should be used for development only!]))
