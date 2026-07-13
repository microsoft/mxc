// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host platform support detection — the Rust port of the SDK's
//! `getPlatformSupport`.
//!
//! Reports whether MXC can run on the current host and which containment
//! backends are available. This lets callers stop depending on the TypeScript
//! SDK for platform discovery.
//!
//! **Provisional.** Like the backend dispatch in `dispatch.rs`, this host
//! probing is a temporary home; it moves to the future `mxc` engine crate that
//! both `mxc-sdk` and the executor binaries will share.

#[cfg(target_os = "windows")]
use appcontainer_common::fallback_detector::{self, IsolationTier as BackendIsolationTier};
#[cfg(target_os = "windows")]
use wxc_common::models::ContainerPolicy;

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
    /// Isolation tier selected for the default Windows process-container policy.
    ///
    /// `None` on non-Windows hosts or when the Windows capability probe fails.
    pub isolation_tier: Option<IsolationTier>,
}

/// Windows process-container isolation tier selected by the runtime probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationTier {
    /// BaseContainer via `Experimental_CreateProcessInSandbox`.
    BaseContainer,
    /// AppContainer with BFS filesystem isolation.
    AppContainerBfs,
    /// AppContainer with host DACL augmentation.
    AppContainerDacl,
}

/// Detect MXC support on the current host.
///
/// Mirrors the SDK's `getPlatformSupport`. Available methods are restricted to
/// the backends this crate can run. On Windows the isolation tier comes from the
/// in-process fallback probe rather than a `wxc-exec --probe` subprocess.
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
        if command_succeeds("bwrap", &["--version"]) {
            PlatformSupport {
                is_supported: true,
                available_methods: vec!["bubblewrap".to_string()],
                ..Default::default()
            }
        } else {
            PlatformSupport {
                reason: Some("Bubblewrap is not available on this system".to_string()),
                ..Default::default()
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let isolation_tier = fallback_detector::detect(&ContainerPolicy::default(), true)
            .ok()
            .map(|decision| match decision.tier {
                BackendIsolationTier::BaseContainer => IsolationTier::BaseContainer,
                BackendIsolationTier::AppContainerBfs => IsolationTier::AppContainerBfs,
                BackendIsolationTier::AppContainerDacl => IsolationTier::AppContainerDacl,
            });

        PlatformSupport {
            is_supported: true,
            available_methods: vec!["processcontainer".to_string()],
            isolation_tier,
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

/// Returns true when `program args...` exits successfully — used to probe for
/// the presence of `bwrap` on Linux.
#[cfg(target_os = "linux")]
fn command_succeeds(program: &str, args: &[&str]) -> bool {
    use std::process::{Command, Stdio};
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
