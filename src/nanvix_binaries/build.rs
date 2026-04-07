// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script that downloads NanVix binaries from the latest GitHub releases.
//!
//! Uses system tools (`curl.exe`, `tar.exe`) instead of Rust
//! crates. Zero HTTP/zip build-dependencies — only `nanvix_common`
//! for shared constants and serde-based config parsing.
//!
//! ## How it works
//!
//! 1. Queries GitHub API (`/releases/latest`) for each upstream repo
//! 2. Finds the Windows zip asset matching the configured prefix
//! 3. Downloads and extracts the required binaries
//!
//! ## Configuration files
//!
//! - `versions.json` — repo names, asset prefixes, and binary lists
//!
//! ## Environment variables
//!
//! - `GITHUB_TOKEN` / `GH_TOKEN` — optional; increases API rate limit
//!
//! ## Caching
//!
//! Binaries are cached in OUT_DIR. If all required binaries exist,
//! downloads are skipped.
//!
//! # TODO(security): NanVix binaries are not ESRP-signed. Before shipping in
//! # official MXC releases, either extend ESRP to cover these binaries or
//! # establish an internal mirror with supply-chain controls.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use nanvix_common::{github_latest_release_url, load_json, ReleaseConfig, RepoConfig};

/// GitHub API release response — only the fields we need.
#[derive(serde::Deserialize)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<GitHubAsset>,
}

#[derive(serde::Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

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

    let all_binaries: Vec<&str> = versions
        .nanvix
        .binaries
        .iter()
        .chain(versions.cpython.binaries.iter())
        .map(|s| s.as_str())
        .collect();

    let needs_nanvix = needs_download(&versions.nanvix, &bin_dir);
    let needs_cpython = needs_download(&versions.cpython, &bin_dir);

    if needs_nanvix {
        eprintln!("nanvix_binaries: fetching latest nanvix/nanvix release...");
        download_latest(&versions.nanvix, &bin_dir);
    }

    if needs_cpython {
        eprintln!("nanvix_binaries: fetching latest nanvix/cpython release...");
        download_latest(&versions.cpython, &bin_dir);
    }

    if !needs_nanvix && !needs_cpython {
        eprintln!("nanvix_binaries: all binaries cached");
    }

    // Verify presence of all binaries
    for name in &all_binaries {
        if !bin_dir.join(name).exists() {
            panic!("nanvix_binaries: {} not found after download/extract", name);
        }
    }

    println!("cargo:rustc-env=NANVIX_BIN_DIR={}", bin_dir.display());
    println!("cargo:BIN_DIR={}", bin_dir.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=versions.json");
    println!("cargo:rerun-if-env-changed=GITHUB_TOKEN");
    println!("cargo:rerun-if-env-changed=GH_TOKEN");
}

// -- Download logic ----------------------------------------------------------

fn needs_download(config: &RepoConfig, bin_dir: &Path) -> bool {
    config
        .binaries
        .iter()
        .any(|name| !bin_dir.join(name).exists())
}

fn download_latest(config: &RepoConfig, bin_dir: &Path) {
    // Step 1: Query GitHub API for latest release
    let api_url = github_latest_release_url(&config.repo);
    let release_json = curl_fetch_string(&api_url);

    let release: GitHubRelease = serde_json::from_str(&release_json).unwrap_or_else(|e| {
        panic!(
            "nanvix_binaries: failed to parse release JSON from {}: {}",
            api_url, e
        );
    });

    eprintln!(
        "  latest release: {} ({} assets)",
        release.tag_name,
        release.assets.len()
    );

    // Step 2: Find the largest matching Windows zip asset
    let zip_asset = release
        .assets
        .iter()
        .filter(|a| a.name.starts_with(&config.asset_prefix) && a.name.ends_with(".zip"))
        .max_by_key(|a| a.size);

    let zip_asset = zip_asset.unwrap_or_else(|| {
        panic!(
            "nanvix_binaries: no zip asset matching '{}*.zip' in {} release {}.\n\
             Available: {:?}",
            config.asset_prefix,
            config.repo,
            release.tag_name,
            release.assets.iter().map(|a| &a.name).collect::<Vec<_>>()
        );
    });

    // Step 3: Download and extract
    let zip_path = bin_dir.join(&zip_asset.name);
    let binary_paths: Vec<PathBuf> = config.binaries.iter().map(|b| bin_dir.join(b)).collect();

    let cleanup = |paths: &[PathBuf], zip: &Path| {
        let _ = fs::remove_file(zip);
        for p in paths {
            let _ = fs::remove_file(p);
        }
    };

    eprintln!("  downloading {}...", zip_asset.name);
    if let Err(msg) = try_curl_download(&zip_asset.browser_download_url, &zip_path) {
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

/// Fetch a URL as a UTF-8 string via curl.exe (for GitHub API).
fn curl_fetch_string(url: &str) -> String {
    let mut cmd = Command::new("curl");
    cmd.args([
        "--silent",
        "--show-error",
        "--fail",
        "--location",
        "--retry",
        "2",
        "--retry-delay",
        "2",
        "--header",
        "User-Agent: mxc-nanvix-build/0.1",
        "--header",
        "Accept: application/vnd.github.v3+json",
    ]);

    if let Some(token) = github_token() {
        cmd.arg("--header");
        cmd.arg(format!("Authorization: Bearer {}", token));
    }

    cmd.arg(url);

    let output = cmd.output().unwrap_or_else(|e| {
        panic!(
            "nanvix_binaries: curl.exe not found: {}\n\
             curl.exe ships with Windows 10 1803+. Ensure it's in PATH.",
            e
        );
    });

    if !output.status.success() {
        panic!(
            "nanvix_binaries: curl failed for {}\n  exit code: {}\n  stderr: {}\n\
             Hint: set GITHUB_TOKEN env var if you're hitting rate limits",
            url,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    String::from_utf8(output.stdout)
        .unwrap_or_else(|_| panic!("nanvix_binaries: non-UTF8 response from {}", url))
}

/// Download a file to disk via curl.exe with retry.
fn try_curl_download(url: &str, dest: &Path) -> Result<(), String> {
    let mut cmd = Command::new("curl");
    cmd.args([
        "--silent",
        "--show-error",
        "--fail",
        "--location",
        "--retry",
        "2",
        "--retry-delay",
        "2",
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
