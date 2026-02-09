/** @file build.rs
*
* @brief This code orchestrates the bindgen tool to create Rust-bindings.
*
* @copyright Copyright (c) Siemens Mobility GmbH, 2026
*
* @author Christian P. Feist <christian.feist@siemens.com>
* @author Hermann Seuschek <hermann.seuschek@siemens.com>
*
* @license This work is licensed under the terms of the Apache Software License
* 2.0. See the COPYING file in the top-level directory.
*
* SPDX-FileCopyrightText: Copyright 2026 Siemens
* SPDX-License-Identifier: Apache-2.0
*/
extern crate bindgen;
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src/bindings.h");

    // The bindgen::Builder is the main entry point to bindgen
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate bindings for.
        .header("src/bindings.h")
        // Invalidate the built crate whenever included header files change.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to file $OUT_DIR/bindings.rs
    let out_path = PathBuf::from(
        env::var("OUT_DIR").expect("OUT_DIR environment variable not set by cargo")
    );
    bindings
        .write_to_file(out_path.join("bindgen_bindings.rs"))
        .expect("Couldn't write bindings!");

    // Ensure the crate links against the libuta C library
    println!("cargo:rustc-link-lib=uta");
}
