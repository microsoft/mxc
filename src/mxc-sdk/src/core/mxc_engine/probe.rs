// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host backend-availability probe — the read-only [`available_backends`] API.
//!
//! Reports only the containment backends the current host can run. Answers "what can I
//! use here?"; a backend's absence means "not currently usable, for any reason".
//! Separate from [`platform_support`](crate::mxc_engine::platform_support), which answers the
//! narrower "what can `mxc-sdk` itself launch?" question and reports no tier.

use crate::mxc_common::models::ContainmentBackend;
use serde::Serialize;

/// Optional feature supported by a containment backend on the current host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub enum BackendCapability {
    /// Windows ProcessContainer denial capture.
    CaptureDenials,
    /// Native `filesystem.deniedPaths` enforcement at the reported tier.
    FilesystemDeniedPaths,
    /// Native `processContainer.filesystem.enumeratePaths` enforcement.
    FilesystemEnumeratePaths,
    /// `network.ingress.hostLoopback = "allow"` at the reported tier.
    IngressHostLoopbackAllow,
    /// Bubblewrap proxy-only egress in a private network namespace.
    ProxyEnforcement,
    /// Identity-less proxy support on loopback.
    /// Requires explicit host-loopback allow; not general ingress support.
    IdentitylessLoopbackProxy,
}

/// One host-available backend, plus its effective isolation tier (if any).
///
/// Serializes to camelCase JSON such as `{"backend":"seatbelt"}` or
/// `{"backend":"processcontainer","tier":"base-container","capabilities":
/// ["captureDenials"]}`; empty optional fields are omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailableBackend {
    /// Canonical [`ContainmentBackend::wire_name`] value.
    pub backend: String,
    /// Highest-isolation tier the host supports for this backend (a canonical
    /// `IsolationTier::as_str()` name); `None`, and omitted from JSON, for
    /// backends with no tier ladder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// Optional features supported by the reported tier.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<BackendCapability>,
    /// Diagnostics for a capability this host cannot offer.
    ///
    /// Not a guarantee for every absent capability: only checks that produce a
    /// reason populate this. Bubblewrap's `ProxyEnforcement` does, since its
    /// dependency walk names what is missing; Windows omits `CaptureDenials`
    /// without a warning.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl AvailableBackend {
    fn tierless(backend: &str) -> Self {
        Self {
            backend: backend.to_string(),
            tier: None,
            capabilities: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

/// Probe the host and return only the backends it can currently run.
///
/// An empty `Vec` is a normal result (unsupported platform, or Linux with
/// neither `bwrap` nor `lxc`), not an error. Order is stable but callers should
/// match by `backend` name, not position.
///
/// Not cached — read once at startup, not in a hot loop.
pub fn available_backends() -> Vec<AvailableBackend> {
    #[cfg(target_os = "macos")]
    {
        macos_backends()
    }
    #[cfg(target_os = "linux")]
    {
        linux_backends()
    }
    #[cfg(target_os = "windows")]
    {
        use crate::process_container_common::base_container_runner::BaseContainerRunner;

        let mut support = ProcessContainerCapabilities {
            capture_denials: BaseContainerRunner::is_native_capture_available(),
            filesystem_denied_paths: BaseContainerRunner::supports_native_denied_paths(),
            filesystem_enumerate_paths: BaseContainerRunner::supports_enumerate_paths(),
            ingress_host_loopback_allow: BaseContainerRunner::supports_ingress_host_loopback_allow(
            ),
            ..Default::default()
        };
        match BaseContainerRunner::supports_identityless_loopback_proxy() {
            Ok(supported) => support.identityless_loopback_proxy = supported,
            Err(error) => support.warnings.push(format!(
                "failed to query identity-less loopback proxy support: {error}"
            )),
        }
        windows_backends(
            BaseContainerRunner::is_base_container_api_present(),
            support,
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Vec::new()
    }
}

/// Serialize [`available_backends`] for the `--available-backends` CLI surface.
///
/// Distinct from `wxc-exec --probe`, which emits ProcessContainer diagnostics
/// object; this is the backend-availability array.
pub fn to_json_pretty(backends: &[AvailableBackend]) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(backends)
}

#[cfg(target_os = "macos")]
fn macos_backends() -> Vec<AvailableBackend> {
    let mut backends = Vec::new();
    if std::path::Path::new("/usr/bin/sandbox-exec").exists() {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::Seatbelt.wire_name(),
        ));
    }
    backends
}

#[cfg(target_os = "linux")]
fn linux_backends() -> Vec<AvailableBackend> {
    let mut backends = Vec::new();
    if crate::bwrap_common::bwrap_version::probe_bwrap().is_ok() {
        backends.push(bubblewrap_backend(
            crate::bwrap_common::proxy_network::probe_proxy_enforcement(),
        ));
    }
    if crate::lxc_common::availability::is_lxc_available() {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::Lxc.wire_name(),
        ));
    }
    backends
}

/// Split from [`linux_backends`] so the reporting is testable without a host
/// that has (or lacks) the private-network dependencies.
#[cfg(target_os = "linux")]
fn bubblewrap_backend(proxy_enforcement: Result<(), String>) -> AvailableBackend {
    let mut backend = AvailableBackend::tierless(ContainmentBackend::Bubblewrap.wire_name());
    match proxy_enforcement {
        Ok(()) => backend
            .capabilities
            .push(BackendCapability::ProxyEnforcement),
        Err(reason) => backend.warnings.push(reason),
    }
    backend
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Default)]
struct ProcessContainerCapabilities {
    capture_denials: bool,
    filesystem_denied_paths: bool,
    filesystem_enumerate_paths: bool,
    ingress_host_loopback_allow: bool,
    identityless_loopback_proxy: bool,
    warnings: Vec<String>,
}

#[cfg(target_os = "windows")]
fn windows_backends(
    base_container_usable: bool,
    support: ProcessContainerCapabilities,
) -> Vec<AvailableBackend> {
    let mut capabilities = Vec::new();
    if support.capture_denials {
        capabilities.push(BackendCapability::CaptureDenials);
    }
    if support.filesystem_denied_paths {
        capabilities.push(BackendCapability::FilesystemDeniedPaths);
    }
    if support.filesystem_enumerate_paths {
        capabilities.push(BackendCapability::FilesystemEnumeratePaths);
    }
    if support.ingress_host_loopback_allow {
        capabilities.push(BackendCapability::IngressHostLoopbackAllow);
    }
    if support.identityless_loopback_proxy {
        capabilities.push(BackendCapability::IdentitylessLoopbackProxy);
    }
    let mut backends = Vec::new();
    if base_container_usable {
        backends.push(AvailableBackend {
            backend: ContainmentBackend::ProcessContainer.wire_name().to_string(),
            tier: Some("base-container".to_string()),
            capabilities,
            warnings: support.warnings,
        });
    }

    if crate::windows_sandbox_lifecycle::availability::is_windows_sandbox_available() {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::WindowsSandbox.wire_name(),
        ));
    }

    // Report WSLC only when the host can actually run it (WSL2 + the WSLC
    // runtime present), matching `platform_support()` and the runner preflight.
    // `WslcSdk::load()` alone only proves the DLL and its exports resolve.
    #[cfg(feature = "wslc")]
    if crate::wslc_common::is_available() {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::Wslc.wire_name(),
        ));
    }

    // Available when the `IsoSessionOps` WinRT class is registered on the OS.
    #[cfg(feature = "isolation_session")]
    if crate::isolation_session_common::availability::is_isolation_session_available() {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::IsolationSession.wire_name(),
        ));
    }

    // WHP is delay-loaded; check before setup boots a VM.
    #[cfg(all(feature = "hyperlight", target_arch = "x86_64"))]
    if crate::hyperlight_common::is_whp_available() {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::Hyperlight.wire_name(),
        ));
    }

    backends
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::ContainmentBackend;

    const CANONICAL_BACKEND_NAMES: &[(ContainmentBackend, &str)] = &[
        (ContainmentBackend::ProcessContainer, "processcontainer"),
        (ContainmentBackend::Wslc, "wslc"),
        (ContainmentBackend::Lxc, "lxc"),
        (ContainmentBackend::Vm, "vm"),
        (ContainmentBackend::MicroVm, "microvm"),
        (ContainmentBackend::Hyperlight, "hyperlight"),
        (ContainmentBackend::WindowsSandbox, "windows_sandbox"),
        (ContainmentBackend::IsolationSession, "isolation_session"),
        (ContainmentBackend::Seatbelt, "seatbelt"),
        (ContainmentBackend::Bubblewrap, "bubblewrap"),
    ];

    fn all_containment_names() -> Vec<String> {
        CANONICAL_BACKEND_NAMES
            .iter()
            .map(|(_, name)| (*name).to_string())
            .collect()
    }

    #[test]
    fn backend_wire_names_match_the_canonical_table() {
        for (backend, expected) in CANONICAL_BACKEND_NAMES {
            assert_eq!(backend.wire_name(), *expected, "{backend:?}");
        }
    }

    const CANONICAL_TIERS: [&str; 1] = ["base-container"];

    #[test]
    fn tier_is_omitted_from_json_when_none() {
        let backend = AvailableBackend::tierless("seatbelt");
        let json = serde_json::to_string(&backend).expect("serializes");
        assert_eq!(json, r#"{"backend":"seatbelt"}"#);
    }

    #[test]
    fn tier_is_serialized_in_camel_case_when_present() {
        let backend = AvailableBackend {
            backend: "processcontainer".to_string(),
            tier: Some("base-container".to_string()),
            capabilities: Vec::new(),
            warnings: Vec::new(),
        };
        let json = serde_json::to_string(&backend).expect("serializes");
        assert_eq!(
            json,
            r#"{"backend":"processcontainer","tier":"base-container"}"#
        );
    }

    #[test]
    fn capabilities_are_serialized_in_camel_case_when_present() {
        let backend = AvailableBackend {
            backend: "processcontainer".to_string(),
            tier: Some("base-container".to_string()),
            capabilities: vec![BackendCapability::CaptureDenials],
            warnings: Vec::new(),
        };
        let json = serde_json::to_string(&backend).expect("serializes");
        assert_eq!(
            json,
            r#"{"backend":"processcontainer","tier":"base-container","capabilities":["captureDenials"]}"#
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bubblewrap_reports_proxy_enforcement_capability_when_probe_succeeds() {
        let backend = bubblewrap_backend(Ok(()));
        assert_eq!(backend.backend, "bubblewrap");
        assert_eq!(
            backend.capabilities,
            vec![BackendCapability::ProxyEnforcement]
        );
        assert!(backend.warnings.is_empty());
        let json = serde_json::to_string(&backend).expect("serializes");
        assert_eq!(
            json,
            r#"{"backend":"bubblewrap","capabilities":["proxyEnforcement"]}"#
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bubblewrap_reports_reason_instead_of_capability_when_probe_fails() {
        let backend = bubblewrap_backend(Err("slirp4netns not found".to_string()));
        assert!(backend.capabilities.is_empty());
        assert_eq!(backend.warnings, vec!["slirp4netns not found".to_string()]);
        let json = serde_json::to_string(&backend).expect("serializes");
        assert_eq!(
            json,
            r#"{"backend":"bubblewrap","warnings":["slirp4netns not found"]}"#
        );
    }

    #[test]
    fn to_json_pretty_emits_an_array() {
        let rendered =
            to_json_pretty(&[AvailableBackend::tierless("seatbelt")]).expect("serializes");
        assert!(
            rendered.starts_with('['),
            "probe output must be a JSON array"
        );
        assert!(rendered.contains("\"seatbelt\""));
    }

    #[test]
    fn policy_capabilities_are_serialized_in_camel_case() {
        assert_eq!(
            serde_json::to_string(&BackendCapability::FilesystemDeniedPaths).expect("serializes"),
            r#""filesystemDeniedPaths""#
        );
        assert_eq!(
            serde_json::to_string(&BackendCapability::IngressHostLoopbackAllow)
                .expect("serializes"),
            r#""ingressHostLoopbackAllow""#
        );
        assert_eq!(
            serde_json::to_string(&BackendCapability::IdentitylessLoopbackProxy)
                .expect("serializes"),
            r#""identitylessLoopbackProxy""#
        );
    }

    #[test]
    fn every_reported_backend_uses_a_canonical_name() {
        let known = all_containment_names();
        for entry in available_backends() {
            assert!(
                known.contains(&entry.backend),
                "reported backend {:?} is not a canonical backend name",
                entry.backend
            );
        }
    }

    #[test]
    fn every_reported_tier_is_a_canonical_tier_string() {
        for entry in available_backends() {
            if let Some(tier) = entry.tier {
                assert!(
                    CANONICAL_TIERS.contains(&tier.as_str()),
                    "reported tier {tier:?} is not a canonical IsolationTier string"
                );
            }
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_reports_processcontainer_with_a_tier_when_available() {
        let backends = available_backends();
        let pc = backends.iter().find(|b| b.backend == "processcontainer");
        assert_eq!(
            pc.is_some(),
            crate::process_container_common::base_container_runner::BaseContainerRunner::is_base_container_api_present()
        );
        let Some(pc) = pc else {
            return;
        };
        let tier = pc.tier.as_deref().expect("processcontainer carries a tier");
        assert!(
            CANONICAL_TIERS.contains(&tier),
            "unexpected processcontainer tier: {tier:?}"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_reports_capture_denials_from_probe_result() {
        for capture_denials_usable in [false, true] {
            let backends = windows_backends(
                true,
                ProcessContainerCapabilities {
                    capture_denials: capture_denials_usable,
                    ..Default::default()
                },
            );
            let process_container = backends
                .iter()
                .find(|backend| backend.backend == "processcontainer")
                .expect("processcontainer must always be reported on Windows");
            assert_eq!(
                process_container
                    .capabilities
                    .contains(&BackendCapability::CaptureDenials),
                capture_denials_usable
            );
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_reports_policy_capabilities_for_base_container() {
        let backends = windows_backends(
            true,
            ProcessContainerCapabilities {
                filesystem_denied_paths: true,
                filesystem_enumerate_paths: true,
                ingress_host_loopback_allow: true,
                identityless_loopback_proxy: true,
                ..Default::default()
            },
        );
        let process_container = backends
            .iter()
            .find(|backend| backend.backend == "processcontainer")
            .expect("processcontainer must always be reported on Windows");

        assert_eq!(
            process_container.capabilities,
            vec![
                BackendCapability::FilesystemDeniedPaths,
                BackendCapability::FilesystemEnumeratePaths,
                BackendCapability::IngressHostLoopbackAllow,
                BackendCapability::IdentitylessLoopbackProxy,
            ]
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_omits_unavailable_processcontainer() {
        let backends = windows_backends(false, ProcessContainerCapabilities::default());
        assert!(backends
            .iter()
            .all(|backend| backend.backend != "processcontainer"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn processcontainer_never_appears_off_windows() {
        assert!(available_backends()
            .iter()
            .all(|b| b.backend != "processcontainer"));
    }
}
