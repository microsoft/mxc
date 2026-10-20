// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host backend-availability probe — the read-only [`available_backends`] API.
//!
//! Reports only the containment backends the current host can run, each with
//! its effective isolation tier when it has a tier ladder. Answers "what can I
//! use here?"; a backend's absence means "not currently usable, for any reason".
//! Separate from [`platform_support`](crate::mxc_engine::platform_support), which answers the
//! narrower "what can `mxc-sdk` itself launch?" question and reports no tier.

use crate::mxc_common::models::ContainmentBackend;
use serde::Serialize;

#[cfg(target_os = "windows")]
use crate::mxc_engine::guarded_capture;

/// Optional feature supported by a containment backend on the current host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub enum BackendCapability {
    /// Windows ProcessContainer denial capture.
    CaptureDenials,
    /// Native `filesystem.deniedPaths` enforcement at the reported tier.
    FilesystemDeniedPaths,
    /// Native `processContainer.filesystem.enumeratePaths` enforcement at the reported tier.
    FilesystemEnumeratePaths,
    /// With explicit host-loopback allow, the baseline is policy-permitted stateful outbound
    /// loopback. Native Windows ingress support adds bidirectional access, including
    /// container-hosted loopback servers.
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
    /// Backend identifier, such as `"seatbelt"` or `"processcontainer"`.
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
        use crate::process_container_common::base_container_runner::BaseContainerRunner;

        let tier = select_tier(
            BaseContainerRunner::is_base_container_api_present(),
            cfg!(feature = "tier2_bfs"),
        );
        let mut support = ProcessContainerCapabilities {
            capture_denials: capture_denials_available(
                BaseContainerRunner::is_native_capture_available(),
                guarded_capture::is_available(),
            ),
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
            tier,
            support,
            WindowsHostAvailability {
                windows_sandbox:
                    crate::windows_sandbox_lifecycle::availability::is_windows_sandbox_available(),
                wslc: wslc_host_available(),
                isolation_session: isolation_session_host_available(),
                hyperlight: hyperlight_host_available(),
                microvm: microvm_host_available(),
            },
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Vec::new()
    }
}

/// Serialize [`available_backends`] for the `--available-backends` CLI surface.
///
/// Distinct from `wxc-exec --probe`, which emits the AppContainer diagnostics
/// object; this is the backend-availability array.
pub fn to_json_pretty(backends: &[AvailableBackend]) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(backends)
}

#[cfg(target_os = "macos")]
fn macos_backends() -> Vec<AvailableBackend> {
    macos_backends_with(crate::seatbelt_common::seatbelt_runner::sandbox_init_available())
}

/// Split from [`macos_backends`] so the reporting is testable without
/// depending on what the test host has installed.
#[cfg(target_os = "macos")]
fn macos_backends_with(sandbox_init_available: bool) -> Vec<AvailableBackend> {
    let mut backends = Vec::new();
    if sandbox_init_available {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::Seatbelt.wire_name(),
        ));
    }
    backends
}

#[cfg(target_os = "linux")]
fn linux_backends() -> Vec<AvailableBackend> {
    linux_backends_with(
        LinuxHostAvailability {
            bubblewrap: crate::bwrap_common::bwrap_version::probe_bwrap().is_ok(),
            lxc: crate::lxc_common::availability::is_lxc_available(),
            hyperlight: hyperlight_host_available(),
        },
        crate::bwrap_common::proxy_network::probe_proxy_enforcement,
    )
}

/// Host checks for the Linux backends, resolved by [`available_backends`] and
/// injected so the reporting is testable without a host that has (or lacks)
/// them. Named fields so a detector cannot be wired to the wrong backend.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Default)]
struct LinuxHostAvailability {
    bubblewrap: bool,
    lxc: bool,
    hyperlight: bool,
}

/// Split from [`linux_backends`] so the reporting is testable without a host
/// that has (or lacks) the backends. `proxy_enforcement` stays a closure
/// because the dependency walk costs several subprocess spawns and is only
/// meaningful once `bwrap` itself is usable.
#[cfg(target_os = "linux")]
fn linux_backends_with(
    hosts: LinuxHostAvailability,
    proxy_enforcement: impl FnOnce() -> Result<(), String>,
) -> Vec<AvailableBackend> {
    let mut backends = Vec::new();
    if hosts.bubblewrap {
        backends.push(bubblewrap_backend(proxy_enforcement()));
    }
    if hosts.lxc {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::Lxc.wire_name(),
        ));
    }
    if hosts.hyperlight {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::Hyperlight.wire_name(),
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
fn capture_denials_available(native_capture: bool, guarded_capture: bool) -> bool {
    native_capture || guarded_capture
}

/// Host checks for the optional Windows backends, resolved by
/// [`available_backends`] and injected so the reporting is testable without a
/// host that has (or lacks) them. A field is `false` when its feature or
/// architecture gate is off.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, Default)]
struct WindowsHostAvailability {
    windows_sandbox: bool,
    wslc: bool,
    isolation_session: bool,
    hyperlight: bool,
    microvm: bool,
}

#[cfg(target_os = "windows")]
fn microvm_host_available() -> bool {
    #[cfg(all(feature = "microvm", target_arch = "x86_64"))]
    {
        crate::nvx::is_available()
    }
    #[cfg(not(all(feature = "microvm", target_arch = "x86_64")))]
    {
        false
    }
}

#[cfg(target_os = "windows")]
fn wslc_host_available() -> bool {
    // Requires the host to actually run it (WSL2 + the WSLC runtime present),
    // matching `platform_support()` and the runner preflight. `WslcSdk::load()`
    // alone only proves the DLL and its exports resolve.
    #[cfg(feature = "wslc")]
    {
        crate::wslc_common::is_available()
    }
    #[cfg(not(feature = "wslc"))]
    {
        false
    }
}

#[cfg(target_os = "windows")]
fn isolation_session_host_available() -> bool {
    // Available when the `IsoSessionOps` WinRT class is registered on the OS.
    #[cfg(feature = "isolation_session")]
    {
        crate::isolation_session_common::availability::is_isolation_session_available()
    }
    #[cfg(not(feature = "isolation_session"))]
    {
        false
    }
}

/// Hyperlight needs x86_64 and a hypervisor: WHP on Windows, KVM on Linux.
/// Both are checked here so a missing hypervisor never reaches the delay-loaded
/// WHP import or a VM boot.
#[cfg(any(target_os = "windows", target_os = "linux"))]
fn hyperlight_host_available() -> bool {
    #[cfg(all(feature = "hyperlight", target_arch = "x86_64", target_os = "windows"))]
    {
        crate::hyperlight_common::is_whp_available()
    }
    #[cfg(all(feature = "hyperlight", target_arch = "x86_64", target_os = "linux"))]
    {
        crate::hyperlight_common::is_kvm_available()
    }
    #[cfg(not(all(feature = "hyperlight", target_arch = "x86_64")))]
    {
        false
    }
}

#[cfg(target_os = "windows")]
fn windows_backends(
    tier: crate::process_container_common::fallback_detector::IsolationTier,
    support: ProcessContainerCapabilities,
    hosts: WindowsHostAvailability,
) -> Vec<AvailableBackend> {
    // `processcontainer` is always present and the only backend with a tier
    // ladder, so it carries its effective (highest-reachable) tier.
    let mut capabilities = Vec::new();
    if support.capture_denials {
        capabilities.push(BackendCapability::CaptureDenials);
    }
    if tier == crate::process_container_common::fallback_detector::IsolationTier::BaseContainer {
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
    }
    let process_container = AvailableBackend {
        backend: ContainmentBackend::ProcessContainer.wire_name().to_string(),
        tier: Some(tier.as_str().to_string()),
        capabilities,
        warnings: support.warnings,
    };
    let mut backends = vec![process_container];

    if hosts.windows_sandbox {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::WindowsSandbox.wire_name(),
        ));
    }

    if hosts.wslc {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::Wslc.wire_name(),
        ));
    }

    if hosts.isolation_session {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::IsolationSession.wire_name(),
        ));
    }

    if hosts.hyperlight {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::Hyperlight.wire_name(),
        ));
    }

    if hosts.microvm {
        backends.push(AvailableBackend::tierless(
            ContainmentBackend::MicroVm.wire_name(),
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
) -> crate::process_container_common::fallback_detector::IsolationTier {
    use crate::process_container_common::fallback_detector::IsolationTier;
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
    use crate::mxc_engine::backend_registry::{self, ProbeCoverage};

    /// Every tier the process-container ladder can name, derived from
    /// [`IsolationTier`] so a new rung cannot be missed here.
    #[cfg(target_os = "windows")]
    fn canonical_tiers() -> Vec<&'static str> {
        use crate::process_container_common::fallback_detector::IsolationTier;
        IsolationTier::ALL.iter().map(|t| t.as_str()).collect()
    }

    /// Runs the real platform reporting with every host check forced to pass,
    /// so the assertions below exercise production wiring rather than whatever
    /// this particular host happens to have installed.
    #[cfg(target_os = "windows")]
    fn backends_with_host_checks_passing() -> Vec<AvailableBackend> {
        windows_backends(
            select_tier(true, false),
            ProcessContainerCapabilities::default(),
            WindowsHostAvailability {
                windows_sandbox: true,
                wslc: true,
                isolation_session: true,
                hyperlight: true,
                microvm: true,
            },
        )
    }

    #[cfg(target_os = "linux")]
    fn backends_with_host_checks_passing() -> Vec<AvailableBackend> {
        linux_backends_with(
            LinuxHostAvailability {
                bubblewrap: true,
                lxc: true,
                hyperlight: true,
            },
            || Ok(()),
        )
    }

    #[cfg(target_os = "macos")]
    fn backends_with_host_checks_passing() -> Vec<AvailableBackend> {
        macos_backends_with(true)
    }

    fn reported_names(backends: &[AvailableBackend]) -> Vec<&str> {
        backends
            .iter()
            .map(|entry| entry.backend.as_str())
            .collect()
    }

    /// Enabling all host checks at once cannot tell one detector's wiring from
    /// another's, so each is enabled alone and must produce exactly its own
    /// backend. A detector wired to the wrong branch fails here.
    #[cfg(target_os = "linux")]
    #[test]
    fn each_linux_host_check_reports_only_its_own_backend() {
        let cases = [
            (
                "bubblewrap",
                LinuxHostAvailability {
                    bubblewrap: true,
                    ..Default::default()
                },
            ),
            (
                "lxc",
                LinuxHostAvailability {
                    lxc: true,
                    ..Default::default()
                },
            ),
            (
                "hyperlight",
                LinuxHostAvailability {
                    hyperlight: true,
                    ..Default::default()
                },
            ),
        ];
        for (expected, hosts) in cases {
            let reported = linux_backends_with(hosts, || Ok(()));
            assert_eq!(reported_names(&reported), vec![expected]);
        }
        assert!(linux_backends_with(LinuxHostAvailability::default(), || Ok(())).is_empty());
    }

    /// `processcontainer` has no host check and is always reported, so each
    /// optional backend's check must add exactly itself.
    #[cfg(target_os = "windows")]
    #[test]
    fn each_windows_host_check_reports_only_its_own_backend() {
        let cases = [
            (
                "windows_sandbox",
                WindowsHostAvailability {
                    windows_sandbox: true,
                    ..Default::default()
                },
            ),
            (
                "wslc",
                WindowsHostAvailability {
                    wslc: true,
                    ..Default::default()
                },
            ),
            (
                "isolation_session",
                WindowsHostAvailability {
                    isolation_session: true,
                    ..Default::default()
                },
            ),
            (
                "hyperlight",
                WindowsHostAvailability {
                    hyperlight: true,
                    ..Default::default()
                },
            ),
            (
                "microvm",
                WindowsHostAvailability {
                    microvm: true,
                    ..Default::default()
                },
            ),
        ];
        for (expected, hosts) in cases {
            let reported = windows_backends(
                select_tier(true, false),
                ProcessContainerCapabilities::default(),
                hosts,
            );
            assert_eq!(
                reported_names(&reported),
                vec!["processcontainer", expected]
            );
        }
        let reported = windows_backends(
            select_tier(true, false),
            ProcessContainerCapabilities::default(),
            WindowsHostAvailability::default(),
        );
        assert_eq!(reported_names(&reported), vec!["processcontainer"]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_host_check_reports_only_seatbelt() {
        assert_eq!(reported_names(&macos_backends_with(true)), vec!["seatbelt"]);
        assert!(macos_backends_with(false).is_empty());
    }

    /// Holds each backend in the real [`available_backends`] to its own
    /// detector, catching a disconnected or misassigned detector.
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    fn assert_probe_matches_detectors(detectors: &[(&str, bool)]) {
        let backends = available_backends();
        let reported = reported_names(&backends);
        for (name, detected) in detectors {
            assert_eq!(
                reported.contains(name),
                *detected,
                "{name}: the probe reported {}, but its detector returned {detected}",
                reported.contains(name)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_linux_probe_reports_what_its_detectors_found() {
        assert_probe_matches_detectors(&[
            (
                ContainmentBackend::Bubblewrap.wire_name(),
                crate::bwrap_common::bwrap_version::probe_bwrap().is_ok(),
            ),
            (
                ContainmentBackend::Lxc.wire_name(),
                crate::lxc_common::availability::is_lxc_available(),
            ),
            (
                ContainmentBackend::Hyperlight.wire_name(),
                hyperlight_host_available(),
            ),
        ]);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn the_windows_probe_reports_what_its_detectors_found() {
        assert_probe_matches_detectors(&[
            (
                ContainmentBackend::WindowsSandbox.wire_name(),
                crate::windows_sandbox_lifecycle::availability::is_windows_sandbox_available(),
            ),
            (ContainmentBackend::Wslc.wire_name(), wslc_host_available()),
            (
                ContainmentBackend::IsolationSession.wire_name(),
                isolation_session_host_available(),
            ),
            (
                ContainmentBackend::Hyperlight.wire_name(),
                hyperlight_host_available(),
            ),
            (
                ContainmentBackend::MicroVm.wire_name(),
                microvm_host_available(),
            ),
        ]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_probe_reports_what_its_detector_found() {
        assert_probe_matches_detectors(&[(
            ContainmentBackend::Seatbelt.wire_name(),
            crate::seatbelt_common::seatbelt_runner::sandbox_init_available(),
        )]);
    }

    /// The forward half of the probe-coverage gate: every backend the registry
    /// claims to detect on this target must actually be emitted by the real
    /// reporting function once its host check passes. Registering a backend as
    /// `Detected` without adding a branch to `available_backends()` fails here.
    #[test]
    fn every_detected_backend_is_reported_when_its_host_checks_pass() {
        let reported = backends_with_host_checks_passing();
        for name in backend_registry::detected_on_current_target() {
            assert!(
                reported.iter().any(|entry| entry.backend == name),
                "{name} is registered as detected on {}, but the probe never reports it even \
                 with every host check passing",
                std::env::consts::OS
            );
        }
    }

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
    fn policy_capabilities_are_serialized_in_camel_case() {
        assert_eq!(
            serde_json::to_string(&BackendCapability::FilesystemDeniedPaths).expect("serializes"),
            r#""filesystemDeniedPaths""#
        );
        assert_eq!(
            serde_json::to_string(&BackendCapability::FilesystemEnumeratePaths)
                .expect("serializes"),
            r#""filesystemEnumeratePaths""#
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
        let known = backend_registry::all_containment_names();
        let reported = backends_with_host_checks_passing();
        assert!(
            !reported.is_empty(),
            "every target reports at least one backend once its host checks pass"
        );
        for entry in reported {
            assert!(
                known.contains(&entry.backend),
                "reported backend {:?} is not a canonical backend name",
                entry.backend
            );
        }
    }

    /// The reverse half of the gate: a backend registered as having no host
    /// detector must stay absent even with every host check forced to pass.
    #[test]
    fn backends_without_a_host_detector_are_never_reported() {
        let reported = backends_with_host_checks_passing();
        for entry in backend_registry::all() {
            if let ProbeCoverage::NotDetected(reason) = &entry.probe_coverage {
                let name = entry.backend.wire_name();
                assert!(
                    !reported.iter().any(|entry| entry.backend == name),
                    "{name} is reported by available_backends() but registered as undetected: \
                     {reason}"
                );
            }
        }
    }

    /// Only the Windows process container has a tier ladder, so a tier
    /// appearing elsewhere means a new ladder landed without probe coverage.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn no_backend_reports_a_tier_off_windows() {
        let reported = backends_with_host_checks_passing();
        assert!(
            !reported.is_empty(),
            "every target reports at least one backend once its host checks pass"
        );
        for entry in reported {
            assert_eq!(
                entry.tier, None,
                "{} reported a tier, but no non-Windows backend has a tier ladder",
                entry.backend
            );
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn every_reported_tier_is_a_canonical_tier_string() {
        let canonical = canonical_tiers();
        for entry in backends_with_host_checks_passing() {
            if let Some(tier) = entry.tier {
                assert!(
                    canonical.contains(&tier.as_str()),
                    "reported tier {tier:?} is not a canonical IsolationTier string"
                );
            }
        }
    }

    /// Fails when a tier is added to [`IsolationTier`] without a rung in
    /// [`select_tier`], which would leave the probe unable to ever report it.
    #[cfg(target_os = "windows")]
    #[test]
    fn every_isolation_tier_is_reachable_from_select_tier() {
        use crate::process_container_common::fallback_detector::IsolationTier;
        let reachable: Vec<IsolationTier> =
            [(true, true), (true, false), (false, true), (false, false)]
                .into_iter()
                .map(|(base_container_usable, tier2_bfs_enabled)| {
                    select_tier(base_container_usable, tier2_bfs_enabled)
                })
                .collect();
        for tier in IsolationTier::ALL {
            assert!(
                reachable.contains(&tier),
                "select_tier can never report {:?}; the probe tier ladder is missing a rung",
                tier.as_str()
            );
        }
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
            canonical_tiers().contains(&tier),
            "unexpected processcontainer tier: {tier:?}"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn capture_denials_is_available_with_either_provider() {
        for (native, guarded, expected) in [
            (false, false, false),
            (true, false, true),
            (false, true, true),
            (true, true, true),
        ] {
            assert_eq!(capture_denials_available(native, guarded), expected);
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_reports_capture_denials_from_combined_provider_result() {
        use crate::process_container_common::fallback_detector::IsolationTier;

        for capture_denials_available in [false, true] {
            let backends = windows_backends(
                IsolationTier::BaseContainer,
                ProcessContainerCapabilities {
                    capture_denials: capture_denials_available,
                    ..Default::default()
                },
                WindowsHostAvailability::default(),
            );
            let process_container = backends
                .iter()
                .find(|backend| backend.backend == "processcontainer")
                .expect("processcontainer must always be reported on Windows");
            assert_eq!(
                process_container
                    .capabilities
                    .contains(&BackendCapability::CaptureDenials),
                capture_denials_available
            );
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_reports_policy_capabilities_for_base_container() {
        use crate::process_container_common::fallback_detector::IsolationTier;

        let backends = windows_backends(
            IsolationTier::BaseContainer,
            ProcessContainerCapabilities {
                filesystem_denied_paths: true,
                filesystem_enumerate_paths: true,
                ingress_host_loopback_allow: true,
                ..Default::default()
            },
            WindowsHostAvailability::default(),
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
            ]
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_omits_base_container_capabilities_from_lower_tiers() {
        use crate::process_container_common::fallback_detector::IsolationTier;

        for tier in [
            IsolationTier::AppContainerBfs,
            IsolationTier::AppContainerDacl,
        ] {
            let backends = windows_backends(
                tier,
                ProcessContainerCapabilities {
                    filesystem_denied_paths: true,
                    filesystem_enumerate_paths: true,
                    ingress_host_loopback_allow: true,
                    identityless_loopback_proxy: true,
                    ..Default::default()
                },
                WindowsHostAvailability::default(),
            );
            let process_container = backends
                .iter()
                .find(|backend| backend.backend == "processcontainer")
                .expect("processcontainer must always be reported on Windows");

            assert!(process_container.capabilities.is_empty());
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_reports_identityless_proxy_with_or_without_general_ingress_support() {
        use crate::process_container_common::fallback_detector::IsolationTier;

        for (supported, ingress_supported) in [(false, false), (true, false), (true, true)] {
            let backends = windows_backends(
                IsolationTier::BaseContainer,
                ProcessContainerCapabilities {
                    identityless_loopback_proxy: supported,
                    ingress_host_loopback_allow: ingress_supported,
                    ..Default::default()
                },
                WindowsHostAvailability::default(),
            );
            let process_container = &backends[0];
            assert_eq!(
                process_container
                    .capabilities
                    .contains(&BackendCapability::IdentitylessLoopbackProxy),
                supported
            );
            assert_eq!(
                process_container
                    .capabilities
                    .contains(&BackendCapability::IngressHostLoopbackAllow),
                ingress_supported
            );
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_preserves_capability_probe_warnings() {
        use crate::process_container_common::fallback_detector::IsolationTier;

        let warning = "failed to query identity-less loopback proxy support".to_string();
        let backends = windows_backends(
            IsolationTier::BaseContainer,
            ProcessContainerCapabilities {
                warnings: vec![warning.clone()],
                ..Default::default()
            },
            WindowsHostAvailability::default(),
        );
        assert_eq!(backends[0].warnings, vec![warning]);
        assert!(!backends[0]
            .capabilities
            .contains(&BackendCapability::IdentitylessLoopbackProxy));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn tier_precedence_prefers_the_strongest_reachable_rung() {
        use crate::process_container_common::fallback_detector::IsolationTier;
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
        assert!(backends_with_host_checks_passing()
            .iter()
            .all(|b| b.backend != "processcontainer"));
    }
}
