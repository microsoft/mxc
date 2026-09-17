// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! LXC-specific configuration types.

/// Linux LXC distribution settings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Lxc {
    /// Linux distribution for the container rootfs.
    pub distribution: String,
    /// Distribution release version.
    pub release: String,
}

impl Default for Lxc {
    fn default() -> Self {
        Self {
            distribution: "alpine".to_string(),
            release: "3.23".to_string(),
        }
    }
}
