# Rust Wrapper for the Unified Trust Anchor API

This crate provides a lightweight Rust wrapper around the C implementation of
the Unified Trust Anchor API (libuta). The underlying C bindings are generated
using [bindgen](https://rust-lang.github.io/rust-bindgen/introduction.html),
while additional Rust code exposes these low-level interfaces through a more
idiomatic Rust API.

## Licensing

This work is licensed under the terms of the Apache License, Version 2.0.
Copyright (c) 2025 Siemens Mobility GmbH.

* SPDX-FileCopyrightText: Copyright 2025 Siemens
* SPDX-License-Identifier: Apache-2.0

## Prerequisites

* Proper installation of libuta
   * The header file `uta.h` must be available in the compiler’s include
    path (e.g., `/usr/local/include/uta.h`)
   * The shared library must be accessible in the system library path (e.g.,
    `/usr/lib` or `/lib`). **Note:** `/usr/local/lib` is not included in
    the default search path on Debian-based systems. To add it manually,
    use: `export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH`
* Installation of Rust envionment (On Debian-based systems: `apt install rustc`)
   * Tested with the following Rust toolchain: `rustc 1.85.0 (4d91de4e4 2025-02-17)`
* LLVM installed (required by bindgen). For details, see [bindgen requirements](https://rust-lang.github.io/rust-bindgen/requirements.html)

## Architecture of the Rust bindings

The Rust bindings for libuta are structured in two layers. The lower layer
(mod bindings) provides a direct mapping of the C API to Rust and is primarily
generated using bindgen, exposing all available symbols. The upper layer (mod api)
builds on top of bindings, importing only the necessary components and
presenting them through an idiomatic Rust interface. This high-level wrapper
enhances usability by incorporating Rust-style error handling and memory
management. The following diagram illustrates the architecture from the native
libuta library up to its integration in a Rust application:

```
          +--------------------+
          |    application     |
          |   e.g., examples   |
          |       (Rust)       |
          +--------------------+
          | crate: libuta_rust |
          |    mod api         |
          |    mod bindings    |
          |       (Rust)       |
          +--------------------+
          |       libuta       |
          |         (C)        |
          +--------------------+
```

## Wrapper library (`libuta_rust`)

The directory `libuta_rust` contains the primary wrapper crate designed for use in
Rust applications through an idiomatic Rust interface. Its purpose is to
encapsulate the data structures, types, and functions defined in the low-level
C implementation exposed by the generated bindings. This includes replacing
patterns such as "output parameters" with Rust-native constructs like
`Result<T>` for error handling, and managing context within an instance of the
`UtaApiV1` structure. These design choices significantly reduce the risk of
misuse and provide a safer, more ergonomic API for developers.

Basic unit tests have been implemented to verify the core functionality of the
library. Please note that the expected outputs for certain functions rely on
default keys provided by the software simulation embedded in libuta. When
executed against a real hardware secure element, these keys differ, resulting
in mismatches between actual and expected values. Consequently, some unit tests
may fail under hardware conditions even though the underlying functionality is
correct. Since the keys used by hardware implementations are unknown in
advance, the test code cannot be adapted to produce matching results.

**Note:** An `UtaApiV1` instance must always be declared as mutable because
most methods require `&mut self`. While this may initially seem
counterintuitive, it reflects the fact that the object’s internal state changes
frequently, particularly when managing context, such as acquiring or releasing
locks. This behavior is mandated by the underlying C library interface, and
therefore cannot be avoided.

The file structure of crate `libuta_rust` is as follows:

```
├── Cargo.toml
├── build.rs
├── README.md
└── src
    ├── lib.rs
    ├── bindings.h
    └── bindings.rc
```

Building and testing the library:

```
cargo build
cargo test
```

### Low-level bindings (mod bindings)

The file bindings.rc includes the low-level Rust bindings for the libuta
library. These bindings are generated using bindgen and supplemented
with additional code to suppress warnings caused by Rust naming conventions.
The bindgen tool is invoked automatically by Cargo during the build process, so
manual execution is not required. The build steps are implemented in build.rs,
which translates the input header file bindings.h (including the main libuta
header) into Rust bindings accessible through src/bindings.rs. Because this
layer is a direct one-to-one mapping of the C API, it is not intended for
direct use in Rust applications. Instead, it serves as the foundation for the
higher-level wrapper located in the lib.rs file.

**Note:** The Rust compiler emits warnings regarding the use of 128-bit integers
because **bindings for this data type are not yet fully stable and may break
compatibility in future releases.** These warnings are explicitly suppressed in
the code. Additional warnings related to naming conventions are also
suppressed, as the original libuta naming is preserved to maintain consistency
with the underlying C API. Since this low-level binding layer is not intended
for direct use in Rust applications, but rather serves as the foundation for
the higher-level wrapper, these warnings do not pose a practical issue.

**Note:** Rust introduces several C-based dependencies through libuta.
Vulnerabilities in any of these linked C libraries could potentially be
exploited, even when accessed via a Rust abstraction layer. At present, these
dependencies cannot be removed because they are integral to libuta.
