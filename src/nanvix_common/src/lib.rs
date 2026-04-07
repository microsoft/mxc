// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared constants and configuration types for NanVix micro-VM binaries.
//!
//! This crate is the single source of truth for binary filenames, release
//! configuration, and checksum data. It is consumed as a `[build-dependency]`
//! by `nanvix_binaries` (download) and `wxc` (copy to output dir).

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

/// All required NanVix binary filenames.
pub const REQUIRED_BINARIES: &[&str] = &[
    "nanvixd.exe",
    "kernel.elf",
    "python.elf",
    "cpython-ramfs.img",
];

/// Binaries sourced from the `nanvix/nanvix` GitHub release.
pub const NANVIX_REPO_BINARIES: &[&str] = &["nanvixd.exe", "kernel.elf"];

/// Binaries sourced from the `nanvix/cpython` GitHub release.
pub const CPYTHON_REPO_BINARIES: &[&str] = &["python.elf", "cpython-ramfs.img"];

/// Release configuration loaded from `versions.json`.
#[derive(Debug, Deserialize)]
pub struct ReleaseConfig {
    /// Configuration for the `nanvix/nanvix` GitHub repo.
    pub nanvix: RepoConfig,
    /// Configuration for the `nanvix/cpython` GitHub repo.
    pub cpython: RepoConfig,
}

/// Configuration for a single upstream GitHub repo release.
#[derive(Debug, Deserialize)]
pub struct RepoConfig {
    /// Git tag of the pinned release (e.g., "v0.12.291").
    pub tag: String,
    /// Exact filename of the zip asset in the GitHub release.
    pub asset: String,
    /// List of binary filenames to extract from the zip.
    pub binaries: Vec<String>,
}

/// Load and deserialize a JSON file.
pub fn load_json<T: serde::de::DeserializeOwned>(path: &str) -> T {
    let content = std::fs::read_to_string(Path::new(path))
        .unwrap_or_else(|e| panic!("nanvix_common: failed to read {}: {}", path, e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("nanvix_common: failed to parse {}: {}", path, e))
}

/// Load checksums from `checksums.json`.
pub fn load_checksums(path: &str) -> HashMap<String, String> {
    load_json(path)
}

/// Construct a deterministic GitHub release download URL.
///
/// Format: `https://github.com/{repo}/releases/download/{tag}/{asset}`
pub fn github_download_url(repo: &str, tag: &str, asset: &str) -> String {
    format!(
        "https://github.com/{}/releases/download/{}/{}",
        repo, tag, asset
    )
}
