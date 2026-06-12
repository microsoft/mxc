// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host platform support detection — the Rust port of the SDK's
//! `getPlatformSupport`.
//!
//! Reports whether MXC can run on the current host and which containment
//! backends are available, plus (on Windows) the isolation tier and UI
//! capabilities discovered by the in-process fallback probe. This lets
//! callers stop depending on the TypeScript SDK for platform discovery.

#[cfg(target_os = "windows")]
pub use appcontainer_common::probe::UiCapabilitySupport;

/// Host UI-restriction capabilities, mirrored from the Windows probe.
///
/// Only Windows populates this today (via the AppContainer probe); on Linux
/// and macOS it is always `None` on [`PlatformSupport`].
#[cfg(not(target_os = "windows"))]
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiCapabilitySupport {
    pub can_block_clipboard_read: bool,
    pub can_block_clipboard_write: bool,
    pub can_block_input_injection: bool,
    pub can_block_input_method_changes: bool,
    pub can_block_external_ui_objects: bool,
    pub can_block_global_ui_namespace: bool,
    pub can_block_desktop_switching: bool,
    pub can_block_logoff_or_shutdown: bool,
    pub can_block_system_parameter_changes: bool,
    pub can_block_display_settings_changes: bool,
}

/// Platform support information — the Rust analogue of the SDK
/// `PlatformSupport` type.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformSupport {
    /// Whether MXC is supported on the current host.
    pub is_supported: bool,
    /// Why the platform is unsupported, when `is_supported` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Containment backends available on this host, by wire name
    /// (e.g. `"seatbelt"`, `"bubblewrap"`, `"processcontainer"`).
    pub available_methods: Vec<String>,
    /// Tier selected for an empty policy (Windows only; `None` elsewhere or
    /// when the probe fails).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolation_tier: Option<String>,
    /// Tier-degradation warnings (Windows only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolation_warnings: Option<Vec<String>>,
    /// Host UI-restriction capabilities (Windows only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_capabilities: Option<UiCapabilitySupport>,
}

/// Detect MXC support on the current host.
///
/// Mirrors the SDK's `getPlatformSupport`, restricted to the backends the
/// `mxc` library can actually run. On Windows the isolation tier and UI
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
        let mut methods = Vec::new();
        if command_succeeds("lxc-ls", &["--version"]) {
            methods.push("lxc".to_string());
        }
        if command_succeeds("bwrap", &["--version"]) {
            methods.push("bubblewrap".to_string());
        }
        if methods.is_empty() {
            PlatformSupport {
                reason: Some("Neither LXC nor Bubblewrap is available on this system".to_string()),
                ..Default::default()
            }
        } else {
            PlatformSupport {
                is_supported: true,
                available_methods: methods,
                ..Default::default()
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let mut support = PlatformSupport {
            is_supported: true,
            available_methods: vec!["processcontainer".to_string()],
            ..Default::default()
        };
        populate_isolation_from_probe(&mut support);
        support
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
/// the presence of `lxc-ls` / `bwrap` on Linux.
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

/// Run the in-process AppContainer fallback probe and fold its tier, warnings,
/// and UI capabilities into `support`. Best-effort: a probe error leaves the
/// isolation fields unset (the same graceful-degradation contract the SDK has).
#[cfg(target_os = "windows")]
fn populate_isolation_from_probe(support: &mut PlatformSupport) {
    use wxc_common::models::ContainerPolicy;

    let probe = appcontainer_common::probe::run_probe(&ContainerPolicy::default());
    if let Some(tier) = probe.tier {
        support.isolation_tier = Some(tier.to_string());
    }
    if !probe.warnings.is_empty() {
        support.isolation_warnings = Some(probe.warnings);
    }
    support.ui_capabilities = Some(probe.probes.ui_capabilities);
}
