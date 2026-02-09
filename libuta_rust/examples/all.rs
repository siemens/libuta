/* Unified Trust Anchor API Rust Wrapper
*
* Example code that demonstrates the use of the libuta Rust wrapper.
*
* Copyright (c) Siemens Mobility GmbH, 2026
*
* Authors:
*    Christian P. Feist <christian.feist@siemens.com>
*    Hermann Seuschek <hermann.seuschek@siemens.com>
*
* This work is licensed under the terms of the Apache Software License
* 2.0. See the COPYING file in the top-level directory.
*
* SPDX-FileCopyrightText: Copyright 2026 Siemens
* SPDX-License-Identifier: Apache-2.0
*/
extern crate libuta_rust;
use libuta_rust::UtaApiV1;

fn main() {

    match UtaApiV1::new() {
        Ok(ref mut uta) => {

            println!("Execute uta.get_version() ...");
            match uta.get_version() {
                Ok(uuid) => println!("Library version: {:?}\n", uuid),
                Err(e) => println!("Error calling uta.get_version(), got error code {:?}\n", e.get_rc())
            }

            println!("Execute uta.self_test() ...");
            match uta.self_test() {
                Ok(()) => println!("Success!\n"),
                Err(e) => println!("Error calling uta.self_test(), got error code {:?}\n", e.get_rc())
            }

            println!("Execute uta.get_device_uuid() ...");
            match uta.get_device_uuid() {
                Ok(uuid) => println!("Device UUID bytes: {:?}\n", uuid),
                Err(e) => println!("Error calling uta.get_device_uuid(), got error code {:?}\n", e.get_rc())
            }

            println!("Execute uta.derive_key(32, &dv, 0) ...");
            let dv = vec![1u8; 8];
            match uta.derive_key(32, &dv, 0)  {
                Ok(key) => println!("Derived key: {:?}\n", key),
                Err(e) => println!("Error calling uta.derive_key(), got error code {:?}\n", e.get_rc())
            }

            println!("Execute uta.get_random(32) ...");
            match uta.get_random(32) {
                Ok(random) => println!("Random bytes: {:?}\n", random),
                Err(e) => println!("Error calling uta.get_random(), got error code {:?}\n", e.get_rc())
            }
        },
        Err(e) => println!("Error on uta.init(), got error code {:?}", e.get_rc())
    }
}
