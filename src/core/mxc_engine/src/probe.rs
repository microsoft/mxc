// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host backend-availability probe — the read-only [`available_backends`] API.
//!
//! Reports only the containment backends the current host can run, each with
//! its effective isolation tier when it has a tier ladder. Answers "what can I
//! use here?"; a backend's absence means "not currently usable, for any reason".
//! Separate from [`platform_support`](crate::platform_support), which answers the
//! narrower "what can `mxc-sdk` itself launch?" question and reports no tier.

use serde::Serialize;
use wxc_common::models::ContainmentBackend;

/// Optional feature supported by a containment backend on the current host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub enum BackendCapability {
    /// Windows ProcessContainer denial capture.
    CaptureDenials,
    /// Bubblewrap proxy-only egress in a private network namespace.
    ProxyEnforcement,
}

/// One host-available backend, plus its effective isolation tier (if any).
///
/// Serializes to camelCase JSON such as `{"backend":"seatbelt"}` or
/// `{"backend":"processcontainer","tier":"base-container","capabilities":
/// ["captureDenials"]}`; empty optional fields are omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailableBackend {
    /// Canonical [`wxc_common::wire::Containment`] wire name.
    pub backend: String,
    /// Highest-isolation tier the host supports for this backend (a canonical
    /// `IsolationTier::as_str()` name); `None`, and omitted from JSON, for
    /// backends with no tier ladder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// Optional backend features usable on this host.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<BackendCapability>,
    /// Why an optional capability is absent from `capabilities`.
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
/// Not cached — read once at startup, not in a hot loop. The reported `tier` is
/// a ceiling: policy can still force a weaker tier at dispatch.
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
        windows_backends(
            appcontainer_common::base_container_runner::BaseContainerRunner::is_capture_denials_usable(
            ),
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Vec::new()
    }
}

/// Serialize [`available_backends`] for the `--probe` CLI surface.
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
    if bwrap_common::bwrap_version::probe_bwrap().is_ok() {
        backends.push(bubblewrap_backend(
            bwrap_common::proxy_network::probe_proxy_enforcement(),
        ));
    }
    if lxc_common::availability::is_lxc_available() {
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
fn windows_backends(capture_denials_usable: bool) -> Vec<AvailableBackend> {
    use appcontainer_common::fallback_detector::is_base_container_usable;

    // `processcontainer` is always present and the only backend with a tier
    // ladder, so it carries its effective (highest-reachable) tier.
    let tier = select_tier(is_base_container_usable(), cfg!(feature = "tier2_bfs"));
    let capabilities = capture_denials_usable
        .then_some(BackendCapability::CaptureDenials)
        .into_iter()
        .collect();
    let process_container = AvailableBackend {
        backend: ContainmentBackend::ProcessContainer.wire_name().to_string(),
        tier: Some(tier.as_str().to_string()),
        capabilities,
        warnings: Vec::new(),
    };
    let mut backends = vec![process_container];

    if windows_sandbox_lifecycle::availability::is_windows_sandbox_available() {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::WindowsSandbox.wire_name(),
        ));
    }

    // Report WSLC only when the host can actually run it (WSL2 + the WSLC
    // runtime present), matching `platform_support()` and the runner preflight.
    // `WslcSdk::load()` alone only proves the DLL and its exports resolve.
    #[cfg(feature = "wslc")]
    if wslc_common::is_available() {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::Wslc.wire_name(),
        ));
    }

    // Available when the `IsoSessionOps` WinRT class is registered on the OS.
    #[cfg(feature = "isolation_session")]
    if isolation_session_common::availability::is_isolation_session_available() {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::IsolationSession.wire_name(),
        ));
    }

    backends
}

/// Effective process-container tier, strongest reachable rung first:
/// BaseContainer → AppContainerBfs → AppContainerDacl. Split from the host
/// detectors so precedence is testable without a real Windows host or the
/// `tier2_bfs` feature.
///
/// This reports the tier **ceiling** — the strongest tier the host can reach
/// for *some* request. On a `tier2_bfs` build that is `AppContainerBfs`
/// regardless of `bfscfg.exe`: a request with no filesystem policy reaches BFS
/// without it (`fallback_detector::detect`). `bfscfg.exe` only decides whether a
/// *policy-carrying* request stays at BFS or drops to DACL, so it belongs in
/// request-time dispatch, not in the ceiling.
#[cfg(target_os = "windows")]
fn select_tier(
    base_container_usable: bool,
    tier2_bfs_enabled: bool,
) -> appcontainer_common::fallback_detector::IsolationTier {
    use appcontainer_common::fallback_detector::IsolationTier;
    if base_container_usable {
        IsolationTier::BaseContainer
    } else if tier2_bfs_enabled {
        IsolationTier::AppContainerBfs
    } else {
        IsolationTier::AppContainerDacl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::wire::Containment;

    fn wire_name(containment: &Containment) -> String {
        serde_json::to_string(containment)
            .expect("Containment serializes")
            .trim_matches('"')
            .to_string()
    }

    fn all_wire_names() -> Vec<String> {
        [
            Containment::Process,
            Containment::ProcessContainer,
            Containment::Vm,
            Containment::WindowsSandbox,
            Containment::Lxc,
            Containment::Microvm,
            Containment::Hyperlight,
            Containment::Wslc,
            Containment::Seatbelt,
            Containment::IsolationSession,
            Containment::Bubblewrap,
        ]
        .iter()
        .map(wire_name)
        .collect()
    }

    const CANONICAL_TIERS: [&str; 3] = ["base-container", "appcontainer-bfs", "appcontainer-dacl"];

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
            tier: Some("appcontainer-dacl".to_string()),
            capabilities: Vec::new(),
            warnings: Vec::new(),
        };
        let json = serde_json::to_string(&backend).expect("serializes");
        assert_eq!(
            json,
            r#"{"backend":"processcontainer","tier":"appcontainer-dacl"}"#
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
    fn every_reported_backend_is_a_real_wire_name() {
        let known = all_wire_names();
        for entry in available_backends() {
            assert!(
                known.contains(&entry.backend),
                "reported backend {:?} is not a Containment wire name",
                entry.backend
            );
        }
    }

    /// Every backend the probe can emit, across all platforms/features — derived
    /// from `ContainmentBackend` (the same source as the `push` calls) so the
    /// emitted names can't be typo'd, and checked against the `wire::Containment`
    /// serde names so the two enums can't drift.
    const EMITTABLE_BACKENDS: [ContainmentBackend; 7] = [
        ContainmentBackend::Seatbelt,
        ContainmentBackend::Bubblewrap,
        ContainmentBackend::Lxc,
        ContainmentBackend::ProcessContainer,
        ContainmentBackend::WindowsSandbox,
        ContainmentBackend::Wslc,
        ContainmentBackend::IsolationSession,
    ];

    /// Complements [`every_reported_backend_is_a_real_wire_name`] (host subset)
    /// by checking every emittable backend unconditionally, so a mismatch for a
    /// backend this host or feature doesn't exercise (e.g. `wslc`) still can't
    /// drift between `ContainmentBackend::wire_name` and `wire::Containment`.
    #[test]
    fn all_emittable_backend_names_are_real_wire_names() {
        let known = all_wire_names();
        for backend in EMITTABLE_BACKENDS {
            assert!(
                known.contains(&backend.wire_name().to_string()),
                "emittable backend {backend:?} wire name {:?} is not a Containment wire name",
                backend.wire_name()
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

    /// Guards `CANONICAL_TIERS` against drift from `IsolationTier::as_str()`.
    #[cfg(target_os = "windows")]
    #[test]
    fn canonical_tier_strings_match_isolation_tier() {
        use appcontainer_common::fallback_detector::IsolationTier;
        assert_eq!(IsolationTier::BaseContainer.as_str(), CANONICAL_TIERS[0]);
        assert_eq!(IsolationTier::AppContainerBfs.as_str(), CANONICAL_TIERS[1]);
        assert_eq!(IsolationTier::AppContainerDacl.as_str(), CANONICAL_TIERS[2]);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_always_reports_processcontainer_with_a_tier() {
        let backends = available_backends();
        let pc = backends
            .iter()
            .find(|b| b.backend == "processcontainer")
            .expect("processcontainer must always be reported on Windows");
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
            let backends = windows_backends(capture_denials_usable);
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
    fn tier_precedence_prefers_the_strongest_reachable_rung() {
        use appcontainer_common::fallback_detector::IsolationTier;
        // BaseContainer wins whenever usable, regardless of tier2_bfs.
        assert_eq!(select_tier(true, false), IsolationTier::BaseContainer);
        assert_eq!(select_tier(true, true), IsolationTier::BaseContainer);
        // The ceiling is BFS on any tier2_bfs build (a no-policy request reaches
        // it without bfscfg.exe); bfscfg gating lives in request-time dispatch.
        assert_eq!(select_tier(false, true), IsolationTier::AppContainerBfs);
        assert_eq!(select_tier(false, false), IsolationTier::AppContainerDacl);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn processcontainer_never_appears_off_windows() {
        assert!(available_backends()
            .iter()
            .all(|b| b.backend != "processcontainer"));
    }
}
