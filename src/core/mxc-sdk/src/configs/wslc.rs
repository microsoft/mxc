// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WSL Container configuration types.

/// WSL Container settings carried by [`crate::v1::Containment::Wslc`].
///
/// [`Default`] matches the native backend's defaults: the `alpine:latest`
/// image, host-determined CPU/memory, no GPU, and the default store.
///
/// # Network policy
///
/// WSLC accepts the v1 directional network posture. It supports either
/// all-deny isolation or all-allow bridged networking; filtering rules and
/// mixed directional defaults fail closed because the backend cannot enforce
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WslcConfig {
    /// Container image reference (e.g. `"alpine:latest"`, `"python:3.12"`).
    /// Pulled from its registry when the store misses, unless `image_tar_path`
    /// supplies it or the request declares no egress, which refuses the pull.
    pub image: String,
    /// Path to a local tar (a `docker save` archive or a rootfs) imported as
    /// the image.
    ///
    /// The image store is consulted **first**: if `image` is already cached the
    /// tar is skipped entirely, so supplying an updated tar under a name that
    /// is already present runs the stale cached content. Use a new `image` name
    /// (or clear the store) to pick up changed tar contents.
    pub image_tar_path: Option<String>,
    /// vCPUs for the session. `None` lets the host decide.
    pub cpu_count: Option<u32>,
    /// Memory for the session, in MB. `None` lets the host decide.
    pub memory_mb: Option<u64>,
    /// Enable GPU passthrough.
    pub gpu: bool,
    /// Override the WSLC session image-store path. `None` uses the SDK default.
    pub storage_path: Option<String>,
    /// Host → container TCP port forwards, as `(windows_port, container_port)`.
    /// Only TCP is supported (the WSLC runtime returns `E_NOTIMPL` for UDP).
    pub port_mappings: Vec<(u16, u16)>,
}

impl Default for WslcConfig {
    fn default() -> Self {
        Self {
            image: "alpine:latest".to_string(),
            image_tar_path: None,
            cpu_count: None,
            memory_mb: None,
            gpu: false,
            storage_path: None,
            port_mappings: Vec::new(),
        }
    }
}
