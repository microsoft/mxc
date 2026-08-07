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

/// One host-available backend, plus its effective isolation tier (if any).
///
/// Serializes to camelCase JSON such as `{"backend":"seatbelt"}` or
/// `{"backend":"processcontainer","tier":"appcontainer-dacl"}`; `tier` is
/// omitted (never `null`) when the backend has no tier ladder.
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
}

impl AvailableBackend {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    fn tierless(backend: &str) -> Self {
        Self {
            backend: backend.to_string(),
            tier: None,
        }
    }

    #[cfg(target_os = "windows")]
    fn tiered(backend: &str, tier: &str) -> Self {
        Self {
            backend: backend.to_string(),
            tier: Some(tier.to_string()),
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
        windows_backends()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "macos")]
fn macos_backends() -> Vec<AvailableBackend> {
    let mut backends = Vec::new();
    if std::path::Path::new("/usr/bin/sandbox-exec").exists() {
        backends.push(AvailableBackend::tierless("seatbelt"));
    }
    backends
}

#[cfg(target_os = "linux")]
fn linux_backends() -> Vec<AvailableBackend> {
    let mut backends = Vec::new();
    if bwrap_common::bwrap_version::probe_bwrap().is_ok() {
        backends.push(AvailableBackend::tierless("bubblewrap"));
    }
    if lxc_common::availability::is_lxc_available() {
        backends.push(AvailableBackend::tierless("lxc"));
    }
    backends
}

#[cfg(target_os = "windows")]
fn windows_backends() -> Vec<AvailableBackend> {
    use appcontainer_common::fallback_detector::is_base_container_usable;

    // `processcontainer` is always present and the only backend with a tier
    // ladder, so it carries its effective (highest-reachable) tier.
    let tier = select_tier(is_base_container_usable(), cfg!(feature = "tier2_bfs"));
    let mut backends = vec![AvailableBackend::tiered("processcontainer", tier.as_str())];

    if windows_sandbox_lifecycle::availability::is_windows_sandbox_available() {
        backends.push(AvailableBackend::tierless("windows_sandbox"));
    }

    // Available when the `wslcsdk.dll` runtime loads and all exports resolve.
    #[cfg(feature = "wslc")]
    if wslc_common::wslc_bindings::WslcSdk::load().is_ok() {
        backends.push(AvailableBackend::tierless("wslc"));
    }

    // Available when the `IsoSessionOps` WinRT class is registered on the OS.
    #[cfg(feature = "isolation_session")]
    if isolation_session_common::availability::is_isolation_session_available() {
        backends.push(AvailableBackend::tierless("isolation_session"));
    }

    backends
}

/// Effective process-container tier, strongest reachable rung first:
/// BaseContainer → AppContainerBfs → AppContainerDacl. Split from the host
/// detectors so precedence is testable without a real Windows host or the
/// `tier2_bfs` feature.
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
        };
        let json = serde_json::to_string(&backend).expect("serializes");
        assert_eq!(
            json,
            r#"{"backend":"processcontainer","tier":"appcontainer-dacl"}"#
        );
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

    /// Every backend literal the probe can emit, across all platforms/features —
    /// must mirror the per-platform arms of `available_backends`.
    const EMITTABLE_BACKENDS: [&str; 7] = [
        "seatbelt",
        "bubblewrap",
        "lxc",
        "processcontainer",
        "windows_sandbox",
        "wslc",
        "isolation_session",
    ];

    /// Complements [`every_reported_backend_is_a_real_wire_name`] (host subset)
    /// by checking every literal unconditionally, so a typo in an arm this host
    /// or feature doesn't exercise (e.g. `"wslc"`) still can't drift.
    #[test]
    fn all_emittable_backend_literals_are_real_wire_names() {
        let known = all_wire_names();
        for literal in EMITTABLE_BACKENDS {
            assert!(
                known.contains(&literal.to_string()),
                "emittable backend literal {literal:?} is not a Containment wire name"
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
    fn tier_precedence_prefers_the_strongest_reachable_rung() {
        use appcontainer_common::fallback_detector::IsolationTier;
        // BaseContainer wins whenever usable, regardless of tier2_bfs.
        assert_eq!(select_tier(true, false), IsolationTier::BaseContainer);
        assert_eq!(select_tier(true, true), IsolationTier::BaseContainer);
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
