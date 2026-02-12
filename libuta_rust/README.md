# Rust Bindings for the Unified Trust Anchor API

This crate is part of the Unified Trust Anchor API (libuta) and provides
lightweight Rust bindings for the C implementation of the library. The
low-level C bindings are generated using
[bindgen](https://rust-lang.github.io/rust-bindgen/introduction.html), while
additional Rust code exposes these low-level interfaces through a more
idiomatic Rust API.

## Licensing

This work is licensed under the terms of the Apache License, Version 2.0.
Copyright (c) 2026 Siemens Mobility GmbH.

* SPDX-FileCopyrightText: Copyright 2026 Siemens
* SPDX-License-Identifier: Apache-2.0

## Prerequisites

* **libuta C library** properly installed:
   * Header file `uta.h` must be in the compiler's include path (e.g., `/usr/local/include/uta.h`)
   * Shared library must be in the system library path (e.g., `/usr/lib` or `/lib`)
   * **Note:** On Debian-based systems, `/usr/local/lib` is not in the default search path. Add it with: `export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH`
* **Rust toolchain** installed (on Debian-based systems: `apt install rustc`)
   * Tested with Rust `1.85.0 (4d91de4e4 2025-02-17)` or later
* **LLVM** installed (required by bindgen), see [bindgen requirements](https://rust-lang.github.io/rust-bindgen/requirements.html)

## Architecture

.The Rust bindings for libuta use a two-layer architecture. The **lower layer**
(`mod bindings`) provides a direct mapping of the C API to Rust and is primarily
generated using bindgen, exposing all available symbols. The **upper layer** (`mod api`)
builds on top of the lower layer bindings, importing only the necessary components and
presenting them through an idiomatic Rust interface. These high-level bindings
enhance usability by incorporating Rust-style error handling and memory
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

## Wrapper Library

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

### File Structure

```
├── Cargo.toml        # Crate configuration and dependencies
├── build.rs          # Build script (invokes bindgen)
├── README.md         # This file
├── examples
│   └── all.rs        # Example code
└── src/
    ├── lib.rs        # High-level idiomatic Rust API
    ├── bindings.h    # C header input for bindgen
    └── bindings.rs   # Imports auto-generated C bindings
```

### Building and Testing

```bash
cargo build
cargo test
```

### Example Code

The example code can be found in the examples directory and serves as a starting point for
integrating `libuta_rust` into your own projects. Build and run the example code as follows:

```
cargo run --example all
```

### Low-Level Bindings

The file bindings.rc imports the low-level Rust bindings for the libuta
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
