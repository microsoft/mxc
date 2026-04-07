// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared constants and configuration types for NanVix micro-VM binaries.
//!
//! This crate is the single source of truth for binary filenames and release
//! configuration. It is consumed as a `[build-dependency]` by
//! `nanvix_binaries` (download) and `wxc` (copy to output dir).

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
    /// GitHub org/repo (e.g., "nanvix/nanvix").
    pub repo: String,
    /// Prefix to match the Windows zip asset name (e.g., "nanvix-windows-microvm-standalone").
    pub asset_prefix: String,
    /// List of binary filenames to extract from the zip.
    pub binaries: Vec<String>,
}

/// GitHub API URL for the latest release of a repo.
pub fn github_latest_release_url(repo: &str) -> String {
    format!("https://api.github.com/repos/{}/releases/latest", repo)
}

/// Load and deserialize a JSON file.
pub fn load_json<T: serde::de::DeserializeOwned>(path: &str) -> T {
    let content = std::fs::read_to_string(Path::new(path))
        .unwrap_or_else(|e| panic!("nanvix_common: failed to read {}: {}", path, e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("nanvix_common: failed to parse {}: {}", path, e))
}
