/* Unified Trust Anchor API Rust Wrapper
*
* This code wraps the low-level C-bindings to make it more accessible
* for Rust
*
* Copyright (c) Siemens Mobility GmbH, 2025
*
* Authors:
*    Christian P. Feist <christian.feist@siemens.com>
*    Hermann Seuschek <hermann.seuschek@siemens.com>
*
* This work is licensed under the terms of the Apache Software License
* 2.0. See the COPYING file in the top-level directory.
*
* SPDX-FileCopyrightText: Copyright 2025 Siemens
* SPDX-License-Identifier: Apache-2.0
*/
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
    use std::result::Result;
    use std::error::Error;
    use std::fmt;

    const UUID_SZ: usize = 16;

    pub type UtaVersion = uta_version_t;

    #[derive(Debug, PartialEq, Copy, Clone)]
    pub enum UtaRc {
        SUCCESS,
        INVALID_KEY_LENGTH,
        INVALID_DV_LENGTH,
        INVALID_KEY_SLOT,
        TA_ERROR
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

    #[derive(Debug)]
    pub struct UtaError {
        rc: UtaRc
    }

    impl UtaError {
        fn new(err_rc: uta_rc) -> UtaError {
            UtaError {rc: encode_uta_rc(err_rc)}
        }

        pub fn get_rc(&self) -> UtaRc {
            self.rc
        }
    }

    impl fmt::Display for UtaError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{:?}", self.rc)
        }
    }

    impl Error for UtaError {
        fn description(&self) -> &str {
            "An UTA error occurred, got error code {:?}"
        }
    }

    pub struct UtaApiV1 {
        api: uta_api_v1_t,
        context: Vec<u8>,
    }

    impl UtaApiV1 {
        // Constructor: Here we translate the libuta methods
        // and the libuta context to an appropriate Rust struct/object.
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
            let rc = unsafe { uta_init_v1(&mut api as *mut uta_api_v1_t) };
            if rc != UTA_SUCCESS {
                return Err(UtaError::new(rc));
            }

            let context_size = unsafe { (api.context_v1_size.unwrap())() };
            Ok(UtaApiV1{api, context: vec![0u8; context_size]})
        }

        pub fn derive_key(&mut self, len_key: usize, dv: &[u8], key_slot: u8) -> Result<Vec<u8>, UtaError> {
            let context_ptr = self.context.as_mut_ptr() as *const uta_context_v1_t;
            let mut rc = unsafe { (self.api.open.unwrap())(context_ptr) };
            if rc != UTA_SUCCESS {
                return Err(UtaError::new(rc));
            }

            let mut key: Vec<u8> = vec![0; len_key];
            rc = unsafe { (self.api.derive_key.unwrap())(context_ptr, (key).as_mut_ptr(),
                          len_key, dv.as_ptr(), dv.len(), key_slot) };
            unsafe { (self.api.close.unwrap())(context_ptr) };

            if rc != UTA_SUCCESS {
                return Err(UtaError::new(rc));
            }
            Ok(key)
        }

        pub fn get_random(&mut self, len_random: u32) -> Result<Vec<u8>, UtaError> {
            let context_ptr = self.context.as_mut_ptr() as *const uta_context_v1_t;
            let mut rc = unsafe { (self.api.open.unwrap())(context_ptr) };
            if rc != UTA_SUCCESS {
                return Err(UtaError::new(rc));
            }
            let mut random: Vec<u8> = vec![0;len_random as usize];
            rc = unsafe { (self.api.get_random.unwrap())(context_ptr,
                          (random).as_mut_ptr(), random.len()) };
            unsafe { (self.api.close.unwrap())(context_ptr) };

            if rc != UTA_SUCCESS {
                return Err(UtaError::new(rc));
            }
            Ok(random)
        }

        pub fn get_device_uuid(&mut self) -> Result<Vec<u8>, UtaError> {
            let context_ptr = self.context.as_mut_ptr() as *const uta_context_v1_t;
            let mut rc = unsafe { (self.api.open.unwrap())(context_ptr) };
            if rc != UTA_SUCCESS {
                return Err(UtaError::new(rc));
            }

            let mut uuid = vec![0u8; UUID_SZ];
            rc = unsafe { (self.api.get_device_uuid.unwrap())(context_ptr, uuid.as_mut_ptr()) }; 
            unsafe { (self.api.close.unwrap())(context_ptr) };

            if rc != UTA_SUCCESS {
                return Err(UtaError::new(rc));
            }
            Ok(uuid)
        }

        pub fn self_test(&mut self) -> Result<(), UtaError> {
            let context_ptr = self.context.as_mut_ptr() as *const uta_context_v1_t;
            let mut rc = unsafe { (self.api.open.unwrap())(context_ptr) };
            if rc != UTA_SUCCESS {
                return Err(UtaError::new(rc));
            }
            rc = unsafe { (self.api.self_test.unwrap())(context_ptr) }; 
            unsafe { (self.api.close.unwrap())(context_ptr) };

            if rc != UTA_SUCCESS {
                return Err(UtaError::new(rc));
            }
            Ok(())

        }

        pub fn get_version(&mut self) -> Result<UtaVersion, UtaError> {
            let context_ptr = self.context.as_mut_ptr() as *const uta_context_v1_t;
            let mut rc = unsafe { (self.api.open.unwrap())(context_ptr) };
            if rc != UTA_SUCCESS {
                return Err(UtaError::new(rc));
            }
            let mut version = UtaVersion {
                uta_type: 0,
                major: 0,
                minor: 0,
                patch: 0,
            };
            rc = unsafe { (self.api.get_version.unwrap())(context_ptr, &mut version as *mut uta_version_t) }; 
            unsafe { (self.api.close.unwrap())(context_ptr) };

            if rc != UTA_SUCCESS {
                return Err(UtaError::new(rc));
            }
            Ok(version)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::api::*;
    use std::fs::File;
    use std::io::{Read};

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
                    Ok(rnd) => assert_ne!(rnd, vec![0u8, 32]),
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

                if machine_id.len() != 32 {
                    panic!("Invalid machine-id length: expected 32 hex characters, got {}", machine_id.len());
                }

                let mut machine_id_vec: Vec<u8> = Vec::with_capacity(16);
                for i in 0..16 {
                    let byte_str = &machine_id[i * 2..i * 2 + 2];
                    match u8::from_str_radix(byte_str, 16) {
                        Ok(b) => machine_id_vec.push(b),
                        Err(e) => panic!("Failed to parse hex at position {}: {}", i, e)
                    }
                }

                let res_uuid = api.get_device_uuid();
                match res_uuid {
                    Ok(uuid) => assert_eq!(uuid, machine_id_vec),
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
