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
    /// Native ProcessContainer reports `"base-container"`; `None`, and omitted
    /// from JSON, for other backends.
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
            WindowsHostAvailability {
                windows_sandbox:
                    crate::windows_sandbox_lifecycle::availability::is_windows_sandbox_available(),
                wslc: wslc_host_available(),
                isolation_session: isolation_session_host_available(),
                hyperlight: hyperlight_host_available(),
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
/// Distinct from `wxc-exec --probe`, which emits ProcessContainer diagnostics
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
    base_container_usable: bool,
    support: ProcessContainerCapabilities,
    hosts: WindowsHostAvailability,
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

    backends
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_engine::backend_registry::{self, ProbeCoverage};

    #[cfg(target_os = "windows")]
    const CANONICAL_TIERS: [&str; 1] = ["base-container"];

    /// Runs the real platform reporting with every host check forced to pass,
    /// so the assertions below exercise production wiring rather than whatever
    /// this particular host happens to have installed.
    #[cfg(target_os = "windows")]
    fn backends_with_host_checks_passing() -> Vec<AvailableBackend> {
        windows_backends(
            true,
            ProcessContainerCapabilities::default(),
            WindowsHostAvailability {
                windows_sandbox: true,
                wslc: true,
                isolation_session: true,
                hyperlight: true,
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
        ];
        for (expected, hosts) in cases {
            for base_container_usable in [false, true] {
                let reported = windows_backends(
                    base_container_usable,
                    ProcessContainerCapabilities::default(),
                    hosts,
                );
                let mut expected_names = Vec::new();
                if base_container_usable {
                    expected_names.push("processcontainer");
                }
                expected_names.push(expected);
                assert_eq!(reported_names(&reported), expected_names);
            }
        }
        let reported = windows_backends(
            true,
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
        let _guard = crate::mxc_common::test_env::lock();
        assert_probe_matches_detectors(&[
            (
                ContainmentBackend::ProcessContainer.wire_name(),
                crate::process_container_common::base_container_runner::BaseContainerRunner::is_base_container_api_present(),
            ),
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

    /// Only Windows ProcessContainer reports a tier.
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
                "{} reported a tier, but no non-Windows backend has an isolation tier",
                entry.backend
            );
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn every_reported_tier_is_a_canonical_tier_string() {
        for entry in backends_with_host_checks_passing() {
            if let Some(tier) = entry.tier {
                assert!(
                    CANONICAL_TIERS.contains(&tier.as_str()),
                    "reported tier {tier:?} is not a supported ProcessContainer tier"
                );
            }
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_reports_processcontainer_with_a_tier_when_available() {
        let _guard = crate::mxc_common::test_env::lock();
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
                BackendCapability::IdentitylessLoopbackProxy,
            ]
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_omits_unavailable_processcontainer() {
        let backends = windows_backends(
            false,
            ProcessContainerCapabilities {
                capture_denials: true,
                filesystem_denied_paths: true,
                filesystem_enumerate_paths: true,
                ingress_host_loopback_allow: true,
                identityless_loopback_proxy: true,
                ..Default::default()
            },
            WindowsHostAvailability::default(),
        );
        assert!(backends.is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_reports_identityless_proxy_with_or_without_general_ingress_support() {
        for (supported, ingress_supported) in [(false, false), (true, false), (true, true)] {
            let backends = windows_backends(
                true,
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
        let warning = "failed to query identity-less loopback proxy support".to_string();
        let backends = windows_backends(
            true,
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

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn processcontainer_never_appears_off_windows() {
        assert!(backends_with_host_checks_passing()
            .iter()
            .all(|b| b.backend != "processcontainer"));
    }
}
