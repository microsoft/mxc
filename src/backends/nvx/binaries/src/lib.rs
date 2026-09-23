// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build-time location and availability metadata for pinned NVX artifacts.

/// Directory containing the acquired NVX artifacts.
pub const NVX_BIN_DIR: &str = env!("NVX_BIN_DIR");

/// `"1"` when workload images are included in the configured release.
pub const NVX_WORKLOAD_IMAGES_AVAILABLE: &str = env!("NVX_WORKLOAD_IMAGES_AVAILABLE");

pub use nvx_common::{WINDOWS_PLATFORM_ARTIFACTS, WORKLOAD_IMAGE_ARTIFACTS};

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use nvx_common::ReleaseConfig;

    const VERSIONS_JSON: &str = include_str!("../versions.json");
    const CHECKSUMS_JSON: &str = include_str!("../checksums.json");

    #[test]
    fn pinned_release_manifest_is_complete_for_platform_archive() {
        let release: ReleaseConfig =
            serde_json::from_str(VERSIONS_JSON).expect("versions.json must be valid");

        assert_eq!(release.repository, "microsoft/nvx");
        assert_eq!(release.tag, "v0.1.0-dev.5c86da3dff02");
        assert_eq!(release.windows_whp_asset, "nvx-0.1.0-windows-whp.zip");
        assert_eq!(release.workload_image_asset, None);
    }

    #[test]
    fn checksums_cover_only_published_platform_artifacts() {
        let checksums: HashMap<String, String> =
            serde_json::from_str(CHECKSUMS_JSON).expect("checksums.json must be valid");

        assert_eq!(checksums.len(), WINDOWS_PLATFORM_ARTIFACTS.len());
        for relative_path in WINDOWS_PLATFORM_ARTIFACTS {
            let checksum = checksums
                .get(relative_path)
                .expect("platform artifact must have a checksum");
            assert_eq!(checksum.len(), 64);
            assert!(checksum
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        }
        for relative_path in WORKLOAD_IMAGE_ARTIFACTS {
            assert!(!checksums.contains_key(relative_path));
        }
    }

    #[test]
    fn release_without_workload_asset_reports_images_unavailable() {
        assert_eq!(NVX_WORKLOAD_IMAGES_AVAILABLE, "0");
    }
}
