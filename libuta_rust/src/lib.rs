//! Rust Bindings for the Unified Trust Anchor API
//!
//! This crate is part of the Unified Trust Anchor API (libuta) and provides
//! lightweight idiomatic Rust bindings for the C implementation of the library.
//!
//! For code examples please refer to the example directory in the root of the repository.
//
// Copyright (c) Siemens Mobility GmbH, 2026
//
// Authors:
//    Christian P. Feist <christian.feist@siemens.com>
//    Hermann Seuschek <hermann.seuschek@siemens.com>
//
// This work is licensed under the terms of the Apache Software License
// 2.0. See the COPYING file in the top-level directory.
//
// SPDX-FileCopyrightText: Copyright 2026 Siemens
// SPDX-License-Identifier: Apache-2.0

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

mod bindings;

pub use crate::api::UtaApiV1;

pub mod api {
    // Note: Here we only use the necessary symbols from the low-level wrapper
    use crate::bindings::{UTA_SUCCESS,
                          UTA_INVALID_KEY_LENGTH,
                          UTA_INVALID_DV_LENGTH,
                          UTA_INVALID_KEY_SLOT,
                          uta_version_t,
                          uta_context_v1_t,
                          uta_api_v1_t,
                          uta_rc,
                          uta_init_v1 };
    use std::error::Error;
    use std::fmt;

    pub const UUID_SZ: usize = 16;
    pub type DeviceUuid = [u8; UUID_SZ];
    pub type UtaVersion = uta_version_t;

    // Return codes from UTA operations
    #[derive(Debug, PartialEq, Copy, Clone)]
    pub enum UtaRc {
        SUCCESS,
        INVALID_KEY_LENGTH,
        INVALID_DV_LENGTH,
        INVALID_KEY_SLOT,
        TA_ERROR,
        UNINITIALIZED_FUNCTION
    }

    fn encode_uta_rc(rc: uta_rc) -> UtaRc {
        match rc {
            UTA_SUCCESS => UtaRc::SUCCESS,
            UTA_INVALID_KEY_LENGTH => UtaRc::INVALID_KEY_LENGTH,
            UTA_INVALID_DV_LENGTH => UtaRc::INVALID_DV_LENGTH,
            UTA_INVALID_KEY_SLOT => UtaRc::INVALID_KEY_SLOT,
            _ => UtaRc::TA_ERROR
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct UtaError {
        rc: UtaRc
    }

    impl UtaError {
        fn new(err_rc: uta_rc) -> UtaError {
            UtaError {rc: encode_uta_rc(err_rc)}
        }

        fn uninitialized() -> UtaError {
            UtaError {rc: UtaRc::UNINITIALIZED_FUNCTION}
        }

        pub fn get_rc(&self) -> UtaRc {
            self.rc
        }
    }

    impl fmt::Display for UtaError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self.rc {
                UtaRc::SUCCESS => write!(f, "Operation succeeded"),
                UtaRc::INVALID_KEY_LENGTH => write!(f, "Invalid key length specified"),
                UtaRc::INVALID_DV_LENGTH => write!(f, "Invalid derivation value length"),
                UtaRc::INVALID_KEY_SLOT => write!(f, "Invalid key slot specified"),
                UtaRc::TA_ERROR => write!(f, "Trust anchor error occurred"),
                UtaRc::UNINITIALIZED_FUNCTION => write!(f, "Function pointer not initialized"),
            }
        }
    }

    impl Error for UtaError {
    }

    /// RAII guard that ensures the UTA context is always closed.
    ///
    /// This guard automatically calls close() when dropped, ensuring
    /// proper resource cleanup even if an error occurs.
    struct ContextGuard {
        context_ptr: *const uta_context_v1_t,
        close_fn: unsafe extern "C" fn(*const uta_context_v1_t) -> uta_rc,
    }

    impl ContextGuard {
        fn new(
            context_ptr: *const uta_context_v1_t,
            close_fn: unsafe extern "C" fn(*const uta_context_v1_t) -> uta_rc,
        ) -> Self {
            ContextGuard {
                context_ptr,
                close_fn,
            }
        }
    }

    impl Drop for ContextGuard {
        fn drop(&mut self) {
            // SAFETY: The context was successfully opened and close_fn is a valid
            // function pointer obtained from the initialized API. The context_ptr
            // remains valid for the lifetime of the guard.
            unsafe { (self.close_fn)(self.context_ptr) };
        }
    }

    /// Main interface to the Unified Trust Anchor API version 1.
    ///
    /// This struct provides safe, idiomatic Rust access to trust anchor functionality
    pub struct UtaApiV1 {
        api: uta_api_v1_t,
        context: Vec<u8>,
    }

    impl UtaApiV1 {

        /// Helper method that handles context open/close with RAII pattern.
        ///
        /// # Safety
        ///
        /// The context pointer is valid and properly allocated.
        fn with_open_context<F, T>(&mut self, f: F) -> Result<T, UtaError>
        where
            F: FnOnce(*const uta_context_v1_t) -> Result<T, UtaError>,
        {
            let open_fn = self.api.open.ok_or_else(|| UtaError::uninitialized())?;
            let close_fn = self.api.close.ok_or_else(|| UtaError::uninitialized())?;
            let context_ptr = self.context.as_mut_ptr() as *mut uta_context_v1_t;

            // SAFETY: context_ptr is valid for the lifetime of self.context, properly
            // aligned, and initialized. The open_fn was obtained from the successfully
            // initialized API structure and is safe to call with a valid context pointer.
            let rc = unsafe { open_fn(context_ptr) };
            if rc != UTA_SUCCESS {
                return Err(UtaError::new(rc));
            }

            // Create guard to ensure close is called even on error
            let _guard = ContextGuard::new(context_ptr, close_fn);

            // Execute the provided closure
            f(context_ptr)
        }

        /// Creates a new UTA API instance.
        ///
        /// Initializes the UTA library and allocates the necessary context.
        ///
        /// # Returns
        ///
        /// * `Ok(UtaApiV1)` - Successfully initialized API instance
        /// * `Err(UtaError)` - Initialization failed
        ///
        pub fn new() -> Result<UtaApiV1, UtaError> {
            let mut api = uta_api_v1_t {
                context_v1_size: None,
                len_key_max: None,
                open: None,
                close: None,
                derive_key: None,
                get_device_uuid: None,
                get_random: None,
                get_version: None,
                self_test: None
            };

            // SAFETY: We pass a valid mutable pointer to a properly initialized
            // uta_api_v1_t structure. The C function uta_init_v1 is designed to
            // initialize this structure and is safe to call.
            let rc = unsafe { uta_init_v1(&mut api as *mut uta_api_v1_t) };
            if rc != UTA_SUCCESS {
                return Err(UtaError::new(rc));
            }

            // SAFETY: The api.context_v1_size function pointer was initialized by uta_init_v1
            // and returns the required context size.
            let context_size_fn = api.context_v1_size.ok_or_else(|| UtaError::uninitialized())?;
            let context_size = unsafe { (context_size_fn)() };
            Ok(UtaApiV1{api, context: vec![0u8; context_size]})
        }

        /// Derives a cryptographic key from device-specific secrets.
        ///
        /// # Arguments
        ///
        /// * `len_key` - Length of the key to derive in bytes
        /// * `dv` - Derivation value (label) used to derive the key
        /// * `key_slot` - Slot number for key derivation (hardware-specific)
        ///
        /// # Returns
        ///
        /// * `Ok(Vec<u8>)` - The derived key as a byte vector
        /// * `Err(UtaError)` - Key derivation failed (invalid length, slot, or TA error)
        ///
        pub fn derive_key(&mut self, len_key: usize, dv: &[u8], key_slot: u8) -> Result<Vec<u8>, UtaError> {
            let derive_key_fn = self.api.derive_key.ok_or_else(|| UtaError::uninitialized())?;

            self.with_open_context(|context_ptr| {
                let mut key: Vec<u8> = vec![0; len_key];

                // SAFETY: context_ptr is valid and the context is open. key.as_mut_ptr()
                // points to a valid, initialized buffer of len_key bytes. dv.as_ptr() points
                // to a valid slice of dv.len() bytes. All pointers and lengths are valid.
                let rc = unsafe {
                    derive_key_fn(context_ptr, key.as_mut_ptr(), len_key, dv.as_ptr(), dv.len(), key_slot)
                };

                if rc != UTA_SUCCESS {
                    return Err(UtaError::new(rc));
                }
                Ok(key)
            })
        }

        /// Generates random bytes using the trust anchor's random number generator.
        ///
        /// # Arguments
        ///
        /// * `len_random` - Number of random bytes to generate
        ///
        /// # Returns
        ///
        /// * `Ok(Vec<u8>)` - Random bytes generated by the trust anchor
        /// * `Err(UtaError)` - Random generation failed
        ///
        pub fn get_random(&mut self, len_random: usize) -> Result<Vec<u8>, UtaError> {
            let get_random_fn = self.api.get_random.ok_or_else(|| UtaError::uninitialized())?;

            self.with_open_context(|context_ptr| {
                let mut random: Vec<u8> = vec![0; len_random];

                // SAFETY: context_ptr is valid and the context is open. random.as_mut_ptr()
                // points to a valid, initialized buffer of random.len() bytes.
                let rc = unsafe { get_random_fn(context_ptr, random.as_mut_ptr(), random.len()) };

                if rc != UTA_SUCCESS {
                    return Err(UtaError::new(rc));
                }
                Ok(random)
            })
        }

        /// Retrieves the unique device identifier (UUID).
        ///
        /// The UUID is a 16-byte identifier unique to the device. In simulation mode,
        /// this is typically derived from `/etc/machine-id`.
        ///
        /// # Returns
        ///
        /// * `Ok(DeviceUuid)` - 16-byte device UUID
        /// * `Err(UtaError)` - UUID retrieval failed
        ///
        pub fn get_device_uuid(&mut self) -> Result<DeviceUuid, UtaError> {
            let get_device_uuid_fn = self.api.get_device_uuid.ok_or_else(|| UtaError::uninitialized())?;

            self.with_open_context(|context_ptr| {
                let mut uuid = [0u8; UUID_SZ];

                // SAFETY: context_ptr is valid and the context is open. uuid.as_mut_ptr()
                // points to a valid, initialized buffer of UUID_SZ (16) bytes.
                let rc = unsafe { get_device_uuid_fn(context_ptr, uuid.as_mut_ptr()) };

                if rc != UTA_SUCCESS {
                    return Err(UtaError::new(rc));
                }
                Ok(uuid)
            })
        }

        /// Performs a self-test of the trust anchor.
        ///
        /// Verifies that the trust anchor is functioning correctly.
        ///
        /// # Returns
        ///
        /// * `Ok(())` - Self-test passed
        /// * `Err(UtaError)` - Self-test failed
        ///
        pub fn self_test(&mut self) -> Result<(), UtaError> {
            let self_test_fn = self.api.self_test.ok_or_else(|| UtaError::uninitialized())?;

            self.with_open_context(|context_ptr| {
                // SAFETY: context_ptr is valid and the context is open. The self_test
                // function only requires a valid open context pointer.
                let rc = unsafe { self_test_fn(context_ptr) };

                if rc != UTA_SUCCESS {
                    return Err(UtaError::new(rc));
                }
                Ok(())
            })
        }

        /// Retrieves version information for the UTA library and device.
        ///
        /// Returns information about the trust anchor type and version numbers.
        ///
        /// # Returns
        ///
        /// * `Ok(UtaVersion)` - Version information including type, major, minor, and patch
        /// * `Err(UtaError)` - Version retrieval failed
        ///
        pub fn get_version(&mut self) -> Result<UtaVersion, UtaError> {
            let get_version_fn = self.api.get_version.ok_or_else(|| UtaError::uninitialized())?;

            self.with_open_context(|context_ptr| {
                let mut version = UtaVersion {
                    uta_type: 0,
                    major: 0,
                    minor: 0,
                    patch: 0,
                };

                // SAFETY: context_ptr is valid and the context is open. The version pointer
                // points to a valid, properly aligned uta_version_t structure that will be
                // written to by the C function.
                let rc = unsafe { get_version_fn(context_ptr, &mut version as *mut uta_version_t) };

                if rc != UTA_SUCCESS {
                    return Err(UtaError::new(rc));
                }
                Ok(version)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::api::*;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn get_key_ok() {
        let mut uta = UtaApiV1::new();
        match uta {
            Ok(ref mut api) => {
                let dv = vec![1u8; 8];
                let ref_key = vec![ 141, 243,   3,  60,
                                    242, 217, 255, 175,
                                    133,  63, 236, 185,
                                    124,  72, 113,  96,
                                     25,  85,  33, 157,
                                     11,  96,  53, 225,
                                    189,  46, 160, 242,
                                    172,  53,  62, 102 ];
                let res = api.derive_key(32, &dv, 0);

                match res {
                    Ok(res_key) => assert_eq!(res_key, ref_key),
                    Err(e) => panic!("Error in get_key, returned {:?}", e)
                }
            },
            Err(e) => panic!("Error getting UTA API, returned {:?}", e)
        }
    }

    #[test]
    fn get_random_ok() {
        let mut uta = UtaApiV1::new();
        match uta {
            Ok(ref mut api) => {
                let res_rnd = api.get_random(32);
                match res_rnd {
                    Ok(rnd) => {
                        assert_eq!(rnd.len(), 32);
                        let first = rnd[0];
                        // Check that not all bytes are the same (very basic randomness check)
                        assert!(rnd.iter().any(|&b| b != first));

                    },
                    Err(e) => panic!("Error in get_random, returned {:?}", e)
                }
            },
            Err(e) => panic!("Error getting UTA API, returned {:?}", e)
        }
    }

    #[test]
    fn get_device_uuid_ok() {
        let mut uta = UtaApiV1::new();
        match uta {
            Ok(ref mut api) => {
                // The UTA_SIM implementation retrieves the device UUID from /etc/machine-id.
                // Accordingly, this test reads the same file and compares the resulting value.
                let mut file = match File::open("/etc/machine-id") {
                    Ok(f) => f,
                    Err(e) => panic!("Error opening /etc/machine-id: {}", e)
                };

                let mut machine_id = String::new();
                if let Err(e) = file.read_to_string(&mut machine_id) {
                    panic!("Error reading /etc/machine-id: {}", e)
                }
                machine_id = machine_id.trim().to_string();

                if machine_id.len() != UUID_SZ * 2 {
                    panic!("Invalid machine-id length: expected 32 hex characters, got {}", machine_id.len());
                }

                let mut expected_uuid: DeviceUuid = [0u8; UUID_SZ];
                for i in 0..UUID_SZ {
                    let byte_str = &machine_id[i * 2..i * 2 + 2];
                    match u8::from_str_radix(byte_str, 16) {
                        Ok(b) => expected_uuid[i] = b,
                        Err(e) => panic!("Failed to parse hex at position {}: {}", i, e)
                    }
                }

                let res_uuid = api.get_device_uuid();
                match res_uuid {
                    Ok(uuid) => assert_eq!(uuid, expected_uuid),
                    Err(e) => panic!("Error in get_device_uuid, returned {:?}", e)
                }
            },
            Err(e) => panic!("Error getting UTA API, returned {:?}", e)
        }
    }

    #[test]
    fn self_test_ok() {
        let mut uta = UtaApiV1::new();
        match uta {
            Ok(ref mut api) => api.self_test().expect("Error in get_self_test"),
            Err(e) => panic!("Error getting UTA API, returned {:?}", e)
        }
    }

    #[test]
    fn get_version_ok() {
        let mut uta = UtaApiV1::new();
        match uta {
            Ok(ref mut api) => {
                let ref_version = UtaVersion {
                    uta_type: 0,
                    major: 1,
                    minor: 2,
                    patch: 0,
                };
                let res_ver = api.get_version();

                match res_ver {
                    Ok(ver) => {
                        assert_eq!(ver.uta_type, ref_version.uta_type);
                        assert_eq!(ver.major, ref_version.major);
                        assert_eq!(ver.minor, ref_version.minor);
                        assert_eq!(ver.patch, ref_version.patch);
                    },
                    Err(e) => panic!("Error in get_version, returned {:?}", e)
                }
            },
            Err(e) => panic!("Error getting UTA API, returned {:?}", e)
        }
    }
}
