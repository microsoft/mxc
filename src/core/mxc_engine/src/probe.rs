// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host backend-availability probe — the read-only [`available_backends`] API.
//!
//! Answers **"what can I use here?"**, not "what is the full capability matrix
//! of this machine?". It reports only the containment backends the current host
//! can actually run, so a caller can pick a backend at startup without
//! attempting an execution. A backend's **absence** means "not currently
//! usable, for any reason" — for per-backend diagnostics and reasons the tool is
//! `wxc-exec --probe`, not this API.
//!
//! Each capability is detected once, in Rust, reusing the same detectors backend
//! dispatch uses (so there is a single source of truth the TypeScript SDK can
//! later project rather than re-checking). Backend names are the
//! [`wxc_common::wire::Containment`] wire names and tier names are the canonical
//! `IsolationTier::as_str()` strings, so both flow from serde rather than being
//! hand-re-encoded.
//!
//! This is intentionally **separate** from [`platform_support`](crate::platform_support):
//! that answers the narrower "which backends can `mxc-sdk` itself launch?"
//! question, whereas this answers the broader host-capability question and
//! additionally reports each backend's effective isolation tier.

use serde::Serialize;

/// One host-available backend, plus its effective isolation tier (if any).
///
/// Serializes to camelCase JSON such as `{"backend":"seatbelt"}` or
/// `{"backend":"processcontainer","tier":"appcontainer-dacl"}`. The `tier` field
/// is **omitted** (never serialized as `null`) when the backend has no tier
/// ladder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailableBackend {
    /// Canonical [`wxc_common::wire::Containment`] wire name, e.g.
    /// `"processcontainer"`, `"seatbelt"`, `"bubblewrap"`.
    pub backend: String,
    /// The highest-isolation tier the host supports for this backend, when the
    /// backend has a tier ladder; `None` for backends with no tiers. The string
    /// values are the canonical `IsolationTier::as_str()` names, and the field
    /// is omitted from JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
}

impl AvailableBackend {
    /// A backend with no tier ladder.
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    fn tierless(backend: &str) -> Self {
        Self {
            backend: backend.to_string(),
            tier: None,
        }
    }

    /// A backend reporting its effective (highest-reachable) isolation tier.
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
/// An empty `Vec` means "no backend this API can currently affirm on this host"
/// (e.g. an unsupported platform, Linux with neither `bwrap` nor `lxc`, or macOS
/// without `sandbox-exec`) — it is a normal result, not an error.
///
/// Results are returned in a stable order, but callers should **match by
/// `backend` name, not by position**, so the order is free to change.
///
/// This performs live host detection (subprocess spawns such as `bwrap`/`lxc-ls`
/// on Linux, DISM on Windows, a DLL load for `wslc`) and is **not cached**, so it
/// is intended to be read once at startup rather than polled in a hot loop. Some
/// underlying detectors cache their own result for the process lifetime.
///
/// The named `tier` is a **ceiling**, not a guarantee: it is the strongest
/// isolation the host is capable of for that backend. A real request can still
/// end up on a weaker tier when policy options force one (e.g. `deniedPaths` on
/// a host without native deny support). This walk performs none of those
/// policy-dependent checks.
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
    // Seatbelt is usable when the App Sandbox driver is installed. Mirrors the
    // `platform_support()` macOS check.
    if std::path::Path::new("/usr/bin/sandbox-exec").exists() {
        backends.push(AvailableBackend::tierless("seatbelt"));
    }
    backends
}

#[cfg(target_os = "linux")]
fn linux_backends() -> Vec<AvailableBackend> {
    let mut backends = Vec::new();
    // `bubblewrap` requires a new-enough `bwrap` for every flag the argument
    // builder emits; `lxc` is a shallow `lxc-ls --version` check. Neither has a
    // tier ladder.
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

    // `processcontainer` is the universal Windows floor, always reachable; it is
    // the only backend with a within-backend tier ladder, so it carries its
    // effective (highest-reachable) tier.
    let tier = select_tier(is_base_container_usable(), cfg!(feature = "tier2_bfs"));
    let mut backends = vec![AvailableBackend::tiered("processcontainer", tier.as_str())];

    // `windows_sandbox` is host-available when its optional feature is enabled;
    // it has no tier ladder.
    if windows_sandbox_lifecycle::availability::is_windows_sandbox_available() {
        backends.push(AvailableBackend::tierless("windows_sandbox"));
    }

    // `wslc` is available when its runtime SDK (`wslcsdk.dll`) loads and every
    // required export resolves. Only compiled when the `wslc` feature is on.
    #[cfg(feature = "wslc")]
    if wslc_common::wslc_bindings::WslcSdk::load().is_ok() {
        backends.push(AvailableBackend::tierless("wslc"));
    }

    backends
}

/// Select the effective process-container isolation tier from the reachability
/// of each rung, strongest first: BaseContainer → AppContainerBfs →
/// AppContainerDacl (the universal floor).
///
/// Split from the host detectors so the precedence is unit-testable without a
/// real Windows host or the `tier2_bfs` build feature.
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

    /// The wire name serde emits for a `Containment` variant, without the JSON
    /// quotes.
    fn wire_name(containment: &Containment) -> String {
        serde_json::to_string(containment)
            .expect("Containment serializes")
            .trim_matches('"')
            .to_string()
    }

    /// Every `Containment` wire name, so tests can assert a reported backend is a
    /// real backend rather than a hardcoded expectation.
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

    /// The canonical isolation-tier strings, mirrored from
    /// `IsolationTier::as_str()`. Kept in the test so a rename of the ladder's
    /// serialized names is caught here as well as at the source.
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

    /// Every backend-name literal the probe can *ever* emit — across all
    /// platforms and features, not just those this host exercises. Must mirror
    /// the string literals in the per-platform arms of `available_backends`.
    const EMITTABLE_BACKENDS: [&str; 6] = [
        "seatbelt",
        "bubblewrap",
        "lxc",
        "processcontainer",
        "windows_sandbox",
        "wslc",
    ];

    /// Complements [`every_reported_backend_is_a_real_wire_name`], which only
    /// sees the subset of backends detected on the current host. This checks the
    /// full literal set unconditionally, so a typo in an arm that this host or
    /// feature does not exercise (e.g. `"wslc"`, gated behind both Windows and
    /// the `wslc` feature) still can't drift from the canonical wire names.
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

    /// Guards against the `CANONICAL_TIERS` list above drifting from the actual
    /// `IsolationTier::as_str()` output.
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
        // BaseContainer wins whenever it is usable, regardless of tier2_bfs.
        assert_eq!(select_tier(true, false), IsolationTier::BaseContainer);
        assert_eq!(select_tier(true, true), IsolationTier::BaseContainer);
        // Otherwise AppContainerBfs is chosen only when the feature is compiled.
        assert_eq!(select_tier(false, true), IsolationTier::AppContainerBfs);
        // The DACL floor is the fallback when nothing higher is reachable.
        assert_eq!(select_tier(false, false), IsolationTier::AppContainerDacl);
    }

    /// `processcontainer` is a Windows-only tier ladder; it must never appear in
    /// the probe result on other platforms.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn processcontainer_never_appears_off_windows() {
        assert!(available_backends()
            .iter()
            .all(|b| b.backend != "processcontainer"));
    }
}
