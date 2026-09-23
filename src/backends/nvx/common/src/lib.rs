// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared artifact paths and release configuration for the NVX backend.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

/// Platform artifacts required to launch NVX with OpenVMM on Windows/WHP.
pub const WINDOWS_PLATFORM_ARTIFACTS: [&str; 3] = [
    "bin/openvmm.exe",
    "guest/vmlinux",
    "guest/initramfs.cpio.gz",
];

/// Optional workload image artifacts used by a complete NVX bundle.
pub const WORKLOAD_IMAGE_ARTIFACTS: [&str; 3] = [
    "images/distro.erofs",
    "images/runtime.erofs",
    "images/scratch.ext4",
];

/// Pinned upstream release configuration loaded from `versions.json`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ReleaseConfig {
    /// GitHub repository in `owner/name` form.
    pub repository: String,
    /// Published release tag.
    pub tag: String,
    /// Windows/WHP platform archive name.
    pub windows_whp_asset: String,
    /// Optional workload image archive name.
    #[serde(default)]
    pub workload_image_asset: Option<String>,
}

/// Loads and deserializes a JSON file, failing with path-specific context.
pub fn load_json<T: serde::de::DeserializeOwned>(path: &str) -> T {
    let content = std::fs::read_to_string(Path::new(path))
        .unwrap_or_else(|error| panic!("nvx_common: failed to read {path}: {error}"));
    serde_json::from_str(&content)
        .unwrap_or_else(|error| panic!("nvx_common: failed to parse {path}: {error}"))
}

/// Loads the artifact checksum map from `checksums.json`.
pub fn load_checksums(path: &str) -> HashMap<String, String> {
    load_json(path)
}

/// Constructs a deterministic GitHub release asset URL.
pub fn github_download_url(repository: &str, tag: &str, asset: &str) -> String {
    format!("https://github.com/{repository}/releases/download/{tag}/{asset}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_platform_artifacts_match_release_layout() {
        assert_eq!(
            WINDOWS_PLATFORM_ARTIFACTS,
            [
                "bin/openvmm.exe",
                "guest/vmlinux",
                "guest/initramfs.cpio.gz",
            ]
        );
    }

    #[test]
    fn workload_image_artifacts_match_staged_layout() {
        assert_eq!(
            WORKLOAD_IMAGE_ARTIFACTS,
            [
                "images/distro.erofs",
                "images/runtime.erofs",
                "images/scratch.ext4",
            ]
        );
    }
}
