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
/// On non-Windows targets this is a no-op.  The `ProductVersion` field is set
/// to `<cargo-pkg-version>+<short-git-hash>` so that every build encodes the
/// exact source commit.
pub fn embed_version_info(file_description: &str, original_filename: &str) {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");

    // Track git HEAD so the embedded commit hash updates on new commits.
    track_git_head();

    #[cfg(windows)]
    embed_version_info_windows(file_description, original_filename);

    // Suppress unused-variable warnings on non-Windows.
    #[cfg(not(windows))]
    {
        let _ = (file_description, original_filename);
    }
}

#[cfg(windows)]
fn embed_version_info_windows(file_description: &str, original_filename: &str) {
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
        )
        .compile()
        .expect("failed to embed Windows version info");
}

/// Return the short git commit hash, or `"unknown"` when git is unavailable.
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

    let head = Path::new(&git_dir).join("HEAD");
    if head.exists() {
        println!("cargo:rerun-if-changed={}", head.display());

        if let Ok(content) = std::fs::read_to_string(&head) {
            if let Some(ref_path) = content.strip_prefix("ref: ") {
                let ref_file = Path::new(&git_dir).join(ref_path.trim());
                if ref_file.exists() {
                    println!("cargo:rerun-if-changed={}", ref_file.display());
                }
            }
        }
    }
}
