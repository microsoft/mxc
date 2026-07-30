// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host platform support detection — the Rust port of the SDK's
//! `getPlatformSupport`.
//!
//! Reports whether MXC can run on the current host and which containment
//! backends are available. This lets callers stop depending on the TypeScript
//! SDK for platform discovery.
//!
//! This host probing lives in the engine alongside the backend dispatch in
//! `dispatch.rs`, so both the public SDK and the executor binaries can share a
//! single implementation.

/// Platform support information — the Rust analogue of the SDK
/// `PlatformSupport` type.
#[derive(Debug, Clone, Default)]
pub struct PlatformSupport {
    /// Whether MXC is supported on the current host.
    pub is_supported: bool,
    /// Why the platform is unsupported, when `is_supported` is false.
    pub reason: Option<String>,
    /// Containment backends available on this host, by wire name
    /// (e.g. `"seatbelt"`, `"bubblewrap"`, `"processcontainer"`).
    pub available_methods: Vec<String>,
}

/// Detect MXC support on the current host.
///
/// Mirrors the SDK's `getPlatformSupport`, restricted to the backends the
/// `mxc-sdk` library can actually run. On Windows the isolation tier and UI
/// capabilities come from the in-process fallback probe rather than a
/// `wxc-exec --probe` subprocess.
pub fn platform_support() -> PlatformSupport {
    #[cfg(target_os = "macos")]
    {
        if std::path::Path::new("/usr/bin/sandbox-exec").exists() {
            PlatformSupport {
                is_supported: true,
                available_methods: vec!["seatbelt".to_string()],
                ..Default::default()
            }
        } else {
            PlatformSupport {
                reason: Some(
                    "/usr/bin/sandbox-exec not found; macOS install is incomplete".to_string(),
                ),
                ..Default::default()
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Presence alone is not enough: `bwrap` must also be new enough for
        // every flag the argument builder emits (see
        // `bwrap_common::bwrap_version::MIN_BWRAP_VERSION`).
        match bwrap_common::bwrap_version::probe_bwrap() {
            Ok(_) => PlatformSupport {
                is_supported: true,
                available_methods: vec!["bubblewrap".to_string()],
                ..Default::default()
            },
            Err(err) => PlatformSupport {
                reason: Some(err.to_string()),
                ..Default::default()
            },
        }
    }

    #[cfg(target_os = "windows")]
    {
        PlatformSupport {
            is_supported: true,
            available_methods: vec!["processcontainer".to_string()],
            ..Default::default()
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PlatformSupport {
            reason: Some("MXC is not supported on this platform".to_string()),
            ..Default::default()
        }
    }
}
