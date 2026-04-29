// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script that downloads NanVix binaries from GitHub releases.
//!
//! Uses system tools (`curl.exe`, `tar.exe`, `certutil`) instead of Rust
//! crates. Zero HTTP/zip/crypto build-dependencies — only `nanvix_common`
//! for shared constants and serde-based config parsing.
//!
//! ## Configuration files
//!
//! - `versions.json` — pinned release tags and exact asset names
//! - `checksums.json` — SHA256 hashes for integrity verification
//!
//! ## Environment variables
//!
//! - `GITHUB_TOKEN` / `GH_TOKEN` — optional; increases API rate limit
//!
//! ## Caching
//!
//! Binaries are cached in OUT_DIR. Checksums are verified whenever this
//! build script runs (triggered by changes to build.rs, versions.json,
//! or checksums.json) to catch corrupted or truncated files.
//!
//! # TODO(security): NanVix binaries are not ESRP-signed. Before shipping in
//! # official MXC releases, either extend ESRP to cover these binaries or
//! # establish an internal mirror with supply-chain controls.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use nanvix_common::{github_download_url, load_checksums, load_json, ReleaseConfig, RepoConfig};

fn main() {
    // Check the TARGET platform (not host). NanVix binaries are only needed when
    // the output binary will run on Windows. This build script runs on the host,
    // but CARGO_CFG_TARGET_OS reflects the cross-compilation target.
    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target != "windows" {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        println!("cargo:rustc-env=NANVIX_BIN_DIR={}", out_dir);
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let bin_dir = out_dir.join("nanvix-binaries");
    fs::create_dir_all(&bin_dir).expect("failed to create nanvix-binaries dir");

    let versions: ReleaseConfig = load_json("versions.json");
    let checksums: HashMap<String, String> = load_checksums("checksums.json");

    let all_binaries: Vec<&str> = versions
        .nanvix
        .binaries
        .iter()
        .chain(versions.cpython.binaries.iter())
        .map(|s| s.as_str())
        .collect();

    let needs_nanvix = needs_download(&versions.nanvix, &bin_dir, &checksums);
    let needs_cpython = needs_download(&versions.cpython, &bin_dir, &checksums);

    if needs_nanvix {
        eprintln!(
            "nanvix_binaries: downloading nanvix/nanvix {}...",
            versions.nanvix.tag
        );
        download_and_extract(&versions.nanvix, "nanvix/nanvix", &bin_dir);
    }

    if needs_cpython {
        eprintln!(
            "nanvix_binaries: downloading nanvix/cpython {}...",
            versions.cpython.tag
        );
        download_and_extract(&versions.cpython, "nanvix/cpython", &bin_dir);
    }

    if !needs_nanvix && !needs_cpython {
        eprintln!("nanvix_binaries: all binaries cached and verified");
    }

    verify_checksums(&all_binaries, &bin_dir, &checksums);

    println!("cargo:rustc-env=NANVIX_BIN_DIR={}", bin_dir.display());
    println!("cargo:BIN_DIR={}", bin_dir.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=versions.json");
    println!("cargo:rerun-if-changed=checksums.json");
    println!("cargo:rerun-if-env-changed=GITHUB_TOKEN");
    println!("cargo:rerun-if-env-changed=GH_TOKEN");
}

// -- Download logic ----------------------------------------------------------

fn needs_download(
    config: &RepoConfig,
    bin_dir: &Path,
    checksums: &HashMap<String, String>,
) -> bool {
    config.binaries.iter().any(|name| {
        let path = bin_dir.join(name);
        if !path.exists() {
            return true;
        }
        if let Some(expected) = checksums.get(name.as_str()) {
            certutil_sha256(&path) != *expected
        } else {
            false
        }
    })
}

fn download_and_extract(config: &RepoConfig, repo: &str, bin_dir: &Path) {
    let url = github_download_url(repo, &config.tag, &config.asset);
    let zip_path = bin_dir.join(&config.asset);
    let binary_paths: Vec<PathBuf> = config.binaries.iter().map(|b| bin_dir.join(b)).collect();

    // Cleanup helper: remove zip + any partially extracted binaries.
    // Called before panicking so the filesystem isn't left in a dangling state.
    let cleanup = |bin_dir_paths: &[PathBuf], zip: &Path| {
        let _ = fs::remove_file(zip);
        for p in bin_dir_paths {
            let _ = fs::remove_file(p);
        }
    };

    eprintln!("  downloading {}...", config.asset);
    if let Err(msg) = try_curl_download(&url, &zip_path) {
        cleanup(&binary_paths, &zip_path);
        panic!("nanvix_binaries: {}", msg);
    }

    let size = zip_path.metadata().map(|m| m.len()).unwrap_or(0);
    eprintln!("  downloaded {} bytes, extracting...", size);

    let binaries: Vec<&str> = config.binaries.iter().map(|s| s.as_str()).collect();
    if let Err(msg) = try_tar_extract(&zip_path, bin_dir, &binaries) {
        cleanup(&binary_paths, &zip_path);
        panic!("nanvix_binaries: {}", msg);
    }

    let _ = fs::remove_file(&zip_path);
}

// -- curl.exe ----------------------------------------------------------------

fn try_curl_download(url: &str, dest: &Path) -> Result<(), String> {
    let mut cmd = Command::new("curl");
    cmd.args([
        "--silent",
        "--show-error",
        "--fail",
        "--location",
        "--retry",
        "5",
        "--retry-delay",
        "5",
        "--retry-all-errors",
        "--output",
    ]);
    cmd.arg(dest);
    cmd.args(["--header", "User-Agent: mxc-nanvix-build/0.1"]);

    if let Some(token) = github_token() {
        cmd.arg("--header");
        cmd.arg(format!("Authorization: Bearer {}", token));
    }

    cmd.arg(url);

    let output = cmd.output().map_err(|e| {
        format!(
            "curl.exe not found: {}\n\
             curl.exe ships with Windows 10 1803+. Ensure it's in PATH.",
            e
        )
    })?;

    if !output.status.success() {
        return Err(format!(
            "curl failed for {}\n  exit code: {}\n  stderr: {}",
            url,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

// -- tar.exe -----------------------------------------------------------------

fn try_tar_extract(zip_path: &Path, dest_dir: &Path, files: &[&str]) -> Result<(), String> {
    let mut cmd = Command::new("tar");
    cmd.arg("-xf");
    cmd.arg(zip_path);
    cmd.arg("-C");
    cmd.arg(dest_dir);
    for f in files {
        cmd.arg(f);
    }

    let output = cmd.output().map_err(|e| {
        format!(
            "tar.exe not found: {}\n\
             tar.exe ships with Windows 10 1803+. Ensure it's in PATH.",
            e
        )
    })?;

    if !output.status.success() {
        return Err(format!(
            "tar extraction failed\n  exit code: {}\n  stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    for f in files {
        let path = dest_dir.join(f);
        if path.exists() {
            let size = path.metadata().map(|m| m.len()).unwrap_or(0);
            eprintln!("  {} -- extracted ({} bytes)", f, size);
        } else {
            return Err(format!("'{}' not found in zip after extraction", f));
        }
    }

    Ok(())
}

// -- Helpers -----------------------------------------------------------------

fn github_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .ok()
}

// -- certutil SHA256 ---------------------------------------------------------

fn certutil_sha256(path: &Path) -> String {
    let output = Command::new("certutil")
        .args(["-hashfile"])
        .arg(path)
        .arg("SHA256")
        .output()
        .unwrap_or_else(|e| {
            panic!("nanvix_binaries: failed to run certutil: {}", e);
        });

    if !output.status.success() {
        panic!(
            "nanvix_binaries: certutil -hashfile failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // certutil output format:
    //   SHA256 hash of <file>:
    //   <hex hash>
    //   CertUtil: -hashfile command completed successfully.
    let stdout = String::from_utf8(output.stdout).expect("certutil output not UTF-8");
    stdout
        .lines()
        .nth(1)
        .unwrap_or_else(|| panic!("nanvix_binaries: unexpected certutil output: {}", stdout))
        .trim()
        .replace(' ', "")
        .to_lowercase()
}

fn verify_checksums(binaries: &[&str], bin_dir: &Path, checksums: &HashMap<String, String>) {
    for name in binaries {
        let path = bin_dir.join(name);
        if !path.exists() {
            panic!("nanvix_binaries: {} not found after download/extract", name);
        }

        if let Some(expected) = checksums.get(*name) {
            let actual = certutil_sha256(&path);
            if actual != *expected {
                panic!(
                    "nanvix_binaries: SHA256 mismatch for '{}'!\n\
                     \x20 expected: {}\n\
                     \x20 actual:   {}\n\
                     This may indicate a corrupted download or a NanVix version update.\n\
                     Update checksums.json with the new hashes.",
                    name, expected, actual
                );
            }
            eprintln!("  {} -- checksum OK", name);
        } else {
            panic!(
                "nanvix_binaries: '{}' has no entry in checksums.json — \
                 every binary must be hash-verified",
                name
            );
        }
    }
}
