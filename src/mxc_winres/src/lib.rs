// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build-time helper for embedding a Windows version info resource into
//! MXC executables.
//!
//! When a Cargo build script for a binary crate calls
//! [`embed_version_info`], this crate uses the [`winresource`] crate to
//! generate and compile a Windows `VERSIONINFO` resource and link it into
//! the resulting `.exe`. (This metadata can be seen in Explorer's "Properties >
//! Details" tab.)
//!
//! The shared Microsoft branding (`CompanyName`, `ProductName`,
//! `LegalCopyright`) is centralised here so individual binary crates only
//! need to declare the bits that vary per binary: the human-readable
//! file description and the canonical original file name.
//!
//! This crate is intentionally a no-op on non-Windows targets: it does
//! nothing when the binary is being built for Linux, macOS, or any other
//! non-Windows platform. That keeps cross-compilation simple — the same
//! `build.rs` snippet works on all hosts.

/// Microsoft branding shared by every MXC executable.
const COMPANY_NAME: &str = "Microsoft Corporation";
const PRODUCT_NAME: &str = "Microsoft Execution Containers";
/// `\u{00A9}` is the copyright symbol (©). Embedding it as an escape
/// keeps the source file pure ASCII so editors and tools never have to
/// guess the encoding.
const LEGAL_COPYRIGHT: &str = "\u{00A9} Microsoft Corporation. All rights reserved.";

/// Embed a standard Windows version info resource into the executable
/// currently being built.
///
/// Intended to be called from a binary crate's `build.rs`.
///
/// # Arguments
///
/// * `file_description` — the human-readable string shown as
///   "File description" in Explorer's Properties dialog. Typically
///   something like `"MXC Executor"`.
/// * `original_filename` — the canonical file name of the produced
///   binary, including the `.exe` suffix (for example
///   `"wxc-exec.exe"`). This is used both for `OriginalFilename` and
///   `InternalName` in the resource.
///
/// # Behaviour
///
/// * On Windows targets, generates and compiles a `VERSIONINFO`
///   resource and links it into the binary. `FileVersion` and
///   `ProductVersion` default to the depending crate's
///   `CARGO_PKG_VERSION`.
/// * On non-Windows targets, returns immediately without doing
///   anything.
/// * If the resource compiler (`rc.exe` from the Windows SDK, or
///   `llvm-rc` / `windres` when cross-compiling) fails for any reason,
///   the failure is reported as a `cargo:warning=` so the build still
///   succeeds — the binary just ships without embedded version info,
///   matching the behaviour before this helper was introduced.
pub fn embed_version_info(file_description: &str, original_filename: &str) {
    // CARGO_CFG_TARGET_OS is the *target* OS, which is what we care
    // about here: Windows resources only make sense in PE binaries.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    let mut res = winresource::WindowsResource::new();
    res.set("FileDescription", file_description);
    res.set("ProductName", PRODUCT_NAME);
    res.set("CompanyName", COMPANY_NAME);
    res.set("LegalCopyright", LEGAL_COPYRIGHT);
    res.set("OriginalFilename", original_filename);
    res.set("InternalName", original_filename);

    if let Err(e) = res.compile() {
        println!(
            "cargo:warning=mxc_winres: failed to embed version info for {original_filename}: {e}"
        );
    }
}
