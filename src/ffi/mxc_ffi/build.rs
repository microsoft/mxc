// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generates the C# P/Invoke layer for the C# SDK from this crate's `extern
//! "C"` surface, using csbindgen. The generated file is gitignored rather than
//! committed, so it is regenerated rather than diffed.
//!
//! Code generation is gated behind the **`dotnetsdk`** cargo feature so normal
//! builds do not compile csbindgen or write into the source tree. Callers that
//! need generated bindings opt in explicitly: local C# builds through the
//! csproj's `GenerateNativeBindings` target, the Windows x64 pipeline build
//! that publishes bindings for downstream managed jobs, and
//! `scripts/check-dotnet-bindings-codegen.js`, which regenerates and asserts
//! the expected entry points are produced.

#[path = "../../mxc-sdk/build/build_mxc_build_common.rs"]
mod mxc_build_common;

fn main() {
    mxc_build_common::embed_version_info("MXC native SDK library", "mxc_ffi.dll");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/error_detail.rs");
    println!("cargo:rerun-if-changed=src/pty.rs");
    println!("cargo:rerun-if-changed=src/streaming.rs");
    println!("cargo:rerun-if-changed=src/state_aware.rs");
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(all(windows, feature = "isolation_session"))]
    reconcile_isolation_session_runtime();

    #[cfg(feature = "dotnetsdk")]
    generate_csharp_bindings();
}

#[cfg(all(windows, feature = "isolation_session"))]
fn reconcile_isolation_session_runtime() {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let target_dir = out_dir
        .parent()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .expect("could not determine target directory from OUT_DIR");

    #[cfg(feature = "isolation_session_lifted")]
    mxc_build_common::isolation_session_sdk::stage_runtime()
        .unwrap_or_else(|error| panic!("IsolationSession SDK staging failed: {error}"));

    #[cfg(not(feature = "isolation_session_lifted"))]
    for file_name in [
        "IsoSessionApp.dll",
        "IsoSession.manifest",
        "IsoSessionApp.runtimeversion",
    ] {
        let path = target_dir.join(file_name);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove stale lifted payload {}: {error}", path.display()),
        }
    }
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
        .input_extern_file("src/pty.rs")
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
