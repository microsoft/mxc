// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generates the C# P/Invoke layer for the C# SDK from this crate's `extern
//! "C"` surface, using csbindgen. The generated file is gitignored rather than
//! committed, so it is regenerated rather than diffed.
//!
//! Code generation is gated behind the **`dotnetsdk`** cargo feature so that
//! normal builds — including the whole-workspace backend build matrix — do
//! **not** compile csbindgen or write into the source tree. Two callers pass
//! that feature: the C# csproj's `GenerateNativeBindings` target, which keeps
//! the bindings current for each C# compile, and
//! `scripts/check-dotnet-bindings-codegen.js`, which regenerates and asserts
//! the expected entry points are produced.

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/error_detail.rs");
    println!("cargo:rerun-if-changed=src/streaming.rs");
    println!("cargo:rerun-if-changed=src/state_aware.rs");
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(all(windows, feature = "isolation_session"))]
    stage_isolation_session_runtime();

    #[cfg(feature = "dotnetsdk")]
    generate_csharp_bindings();
}

#[cfg(all(windows, feature = "isolation_session"))]
fn stage_isolation_session_runtime() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let sdk_dir = manifest_dir
        .join("..")
        .join("..")
        .join("..")
        .join("external")
        .join("windows-sdk")
        .join("isolation-session");
    let _ = mxc_build_common::stage_isolation_session_runtime(&sdk_dir);
}

#[cfg(feature = "dotnetsdk")]
fn generate_csharp_bindings() {
    use std::path::Path;

    // `sdk/dotnet/` project (this crate lives at `src/ffi/mxc_ffi`).
    let out_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../sdk/dotnet/Microsoft.Mxc.Sdk/Native/NativeMethods.g.cs");

    // Re-run when the generated file changes or is deleted, so a missing output
    // (it is gitignored, not committed) forces regeneration even when the FFI
    // source is otherwise unchanged.
    println!("cargo:rerun-if-changed={}", out_path.display());

    if let Some(parent) = out_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            println!("cargo:warning=mxc_ffi: could not create {parent:?}: {e}");
            return;
        }
    }

    if let Err(e) = csbindgen::Builder::default()
        .input_extern_file("src/lib.rs")
        .input_extern_file("src/error_detail.rs")
        .input_extern_file("src/streaming.rs")
        .input_extern_file("src/state_aware.rs")
        .csharp_dll_name("mxc_ffi")
        .csharp_namespace("Microsoft.Mxc.Sdk.Native")
        .csharp_class_name("NativeMethods")
        .generate_csharp_file(&out_path)
    {
        println!("cargo:warning=mxc_ffi: csbindgen generation failed: {e}");
    }
}
