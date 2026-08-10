// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared build-time helpers for embedding Windows VersionInfo metadata in MXC binaries.
//!
//! Used as a `[build-dependencies]` crate — call [`embed_version_info`] from each
//! binary crate's `build.rs` to stamp `ProductName`, `FileDescription`,
//! `OriginalFilename`, and `ProductVersion` (with the git commit hash) into the
//! resulting PE executable.

use std::path::Path;
use std::process::Command;

/// Embed Windows VersionInfo resource metadata into the binary being compiled.
///
/// On non-Windows hosts and when building non-Windows targets on a Windows host
/// this is a no-op.
/// The `ProductVersion` field is set to `<cargo-pkg-version>+<short-git-hash>`
/// so that every build encodes the exact source commit.
pub fn embed_version_info(file_description: &str, original_filename: &str) {
    embed_version_info_with_manifest(file_description, original_filename, None);
}

/// Like [`embed_version_info`], but also fuses a side-by-side application
/// manifest into the binary in the **same** resource compile.
///
/// `manifest_xml`, when `Some`, is the full text of an application manifest
/// (e.g. an assembly manifest carrying `<comClass>` reg-free COM redirections).
/// It MUST be embedded in the same `winresource` compile as the version info:
/// two separate `.compile()` calls each emit a `.res` and the second linker
/// input silently clobbers the first, so the manifest and the version info have
/// to share one invocation.
///
/// On non-Windows hosts / targets the manifest is ignored (there is no PE
/// manifest resource to fuse), matching [`embed_version_info`]'s no-op shape.
pub fn embed_version_info_with_manifest(
    file_description: &str,
    original_filename: &str,
    manifest_xml: Option<&str>,
) {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");

    // Track git HEAD so the embedded commit hash updates on new commits.
    track_git_head();

    #[cfg(windows)]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            embed_version_info_windows(file_description, original_filename, manifest_xml);
        }
    }

    // Suppress unused-variable warnings on non-Windows.
    #[cfg(not(windows))]
    {
        let _ = (file_description, original_filename, manifest_xml);
    }
}

#[cfg(windows)]
fn embed_version_info_windows(
    file_description: &str,
    original_filename: &str,
    manifest_xml: Option<&str>,
) {
    const PRODUCT_NAME: &str = "Microsoft Execution Containers";

    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let commit = git_short_hash();

    let mut resource = winresource::WindowsResource::new();
    resource
        .set("ProductName", PRODUCT_NAME)
        .set("FileDescription", file_description)
        .set("OriginalFilename", original_filename)
        .set("ProductVersion", &format!("{version}+{commit}"))
        .set(
            "LegalCopyright",
            "\u{00a9} Microsoft Corporation. All rights reserved.",
        );

    // Fuse the reg-free COM manifest in the SAME compile as the version info.
    if let Some(xml) = manifest_xml {
        resource.set_manifest(xml);
    }

    resource
        .compile()
        .expect("failed to embed Windows version info");
}

/// Return the short git commit hash, or `"unknown"` when git is unavailable.
#[cfg(windows)]
fn git_short_hash() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Emit `cargo:rerun-if-changed` directives for `.git/HEAD` and the ref it
/// points to, so Cargo re-runs the build script when the commit changes.
fn track_git_head() {
    let git_dir = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    let git_dir = match git_dir {
        Some(d) => d,
        None => return,
    };

    let git_dir_path = Path::new(&git_dir);
    let head = git_dir_path.join("HEAD");
    if head.exists() {
        println!("cargo:rerun-if-changed={}", head.display());

        if let Ok(content) = std::fs::read_to_string(&head) {
            if let Some(ref_path) = content.strip_prefix("ref: ") {
                let ref_file = git_dir_path.join(ref_path.trim());
                if ref_file.exists() {
                    println!("cargo:rerun-if-changed={}", ref_file.display());
                } else {
                    // When refs are packed, the loose ref file doesn't exist
                    // and changes are tracked in packed-refs instead.
                    let packed_refs = git_dir_path.join("packed-refs");
                    if packed_refs.exists() {
                        println!("cargo:rerun-if-changed={}", packed_refs.display());
                    }
                }
            }
        }
    }
}
