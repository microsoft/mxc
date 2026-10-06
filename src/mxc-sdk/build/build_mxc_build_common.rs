// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared build-time helpers for embedding Windows VersionInfo metadata in MXC binaries.
//!
//! Stamps `ProductName`, `FileDescription`, `OriginalFilename`, and
//! `ProductVersion` (with the git commit hash) into MXC PE executables and libraries.

use std::io;
use std::path::Path;
use std::process::Command;

/// Embed Windows VersionInfo resource metadata into the binary being compiled.
///
/// On non-Windows hosts and when building non-Windows targets on a Windows host
/// this is a no-op.
/// The `ProductVersion` field is set to `<cargo-pkg-version>+<short-git-hash>`
/// so that every build encodes the exact source commit.
pub fn embed_version_info(file_description: &str, original_filename: &str) {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");

    // Track git HEAD so the embedded commit hash updates on new commits.
    track_git_head();

    #[cfg(windows)]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            embed_version_info_windows(file_description, original_filename);
        }
    }

    // Suppress unused-variable warnings on non-Windows.
    #[cfg(not(windows))]
    {
        let _ = (file_description, original_filename);
    }
}

/// Embed Windows VersionInfo metadata into one binary target in this package.
#[allow(dead_code)]
pub fn embed_version_info_for_binary(
    binary_name: &str,
    file_description: &str,
    original_filename: &str,
) -> io::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    track_git_head();

    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        return embed_version_info_for_binary_windows(
            binary_name,
            file_description,
            original_filename,
        );
    }

    #[cfg(not(windows))]
    let _ = (binary_name, file_description, original_filename);

    Ok(())
}

#[cfg(windows)]
fn embed_version_info_windows(file_description: &str, original_filename: &str) {
    let resource = version_resource(file_description, original_filename);
    resource
        .compile()
        .expect("failed to embed Windows version info");
}

#[cfg(windows)]
#[allow(dead_code)]
fn embed_version_info_for_binary_windows(
    binary_name: &str,
    file_description: &str,
    original_filename: &str,
) -> io::Result<()> {
    let output_dir = Path::new(
        &std::env::var_os("OUT_DIR")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "OUT_DIR is not set"))?,
    )
    .join(format!("{binary_name}-resource"));
    std::fs::create_dir_all(&output_dir)?;

    let resource_path = output_dir.join("resource.rc");
    let compiled_path = output_dir.join("resource.res");
    version_resource(file_description, original_filename).write_resource_file(&resource_path)?;

    let target =
        std::env::var("TARGET").map_err(|error| io::Error::new(io::ErrorKind::NotFound, error))?;
    let mut compiler = if let Some(path) = std::env::var_os("RC_PATH") {
        Command::new(path)
    } else {
        cc::windows_registry::find(&target, "rc.exe").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("could not locate rc.exe for target {target}"),
            )
        })?
    };
    let output = compiler
        .arg("/nologo")
        .arg(format!("/fo{}", compiled_path.display()))
        .arg(&resource_path)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "rc.exe failed for {binary_name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    println!(
        "cargo:rustc-link-arg-bin={binary_name}={}",
        compiled_path.display()
    );
    Ok(())
}

#[cfg(windows)]
fn version_resource(
    file_description: &str,
    original_filename: &str,
) -> winresource::WindowsResource {
    const PRODUCT_NAME: &str = "Microsoft Execution Containers";

    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let commit = git_short_hash();

    let mut resource = winresource::WindowsResource::new();
    if original_filename.to_ascii_lowercase().ends_with(".dll") {
        resource.set_version_info(winresource::VersionInfo::FILETYPE, 2);
    }
    resource
        .set("CompanyName", "Microsoft Corporation")
        .set("ProductName", PRODUCT_NAME)
        .set("FileDescription", file_description)
        .set("OriginalFilename", original_filename)
        .set("ProductVersion", &format!("{version}+{commit}"))
        .set(
            "LegalCopyright",
            "\u{00a9} Microsoft Corporation. All rights reserved.",
        );
    resource
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
