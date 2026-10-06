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

use serde::Serialize;

/// Whether the host can enforce Bubblewrap proxy-only egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProxyEnforcement {
    Supported,
    Unsupported,
}

/// Bubblewrap host network capability, with the reason when it is unsupported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BubblewrapNetworkSupport {
    pub proxy_enforcement: ProxyEnforcement,
    pub warnings: Vec<String>,
}

/// Platform support information — the Rust analogue of the SDK
/// `PlatformSupport` type.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformSupport {
    /// Whether MXC is supported on the current host.
    pub is_supported: bool,
    /// Why the platform is unsupported, when `is_supported` is false.
    pub reason: Option<String>,
    /// Containment backends available on this host, by wire name
    /// (e.g. `"seatbelt"`, `"bubblewrap"`, `"processcontainer"`).
    ///
    /// Reports that the backend's tooling is present and usable, not that the
    /// calling process is privileged enough to reach it. `"lxc"` in particular
    /// needs root for a system container, or a configured subuid/subgid
    /// delegation for an unprivileged one; neither is probed here.
    pub available_methods: Vec<String>,
    /// Bubblewrap host network capability. `None` off Linux, and when
    /// `bubblewrap` itself is unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bubblewrap_network: Option<BubblewrapNetworkSupport>,
}

/// The `bwrap --version` gate, injected so the reporting is testable without a
/// host that has (or lacks) a suitable `bwrap`.
#[cfg(target_os = "linux")]
struct BwrapProbe<F>(F);

/// The proxy-enforcement dependency walk, injected for the same reason.
/// A distinct type from [`BwrapProbe`] so the two adjacent arguments read as
/// themselves rather than positionally.
#[cfg(target_os = "linux")]
struct ProxyEnforcementProbe<G>(G);

/// The `lxc-ls` gate, injected for the same reason.
#[cfg(target_os = "linux")]
struct LxcProbe<H>(H);

#[cfg(target_os = "linux")]
fn linux_platform_support_with<F, G, H>(
    lxc: LxcProbe<H>,
    bwrap: BwrapProbe<F>,
    proxy_enforcement: ProxyEnforcementProbe<G>,
) -> PlatformSupport
where
    F: FnOnce() -> Result<
        crate::bwrap_common::bwrap_version::BwrapVersion,
        crate::bwrap_common::bwrap_version::BwrapUnavailable,
    >,
    G: FnOnce() -> Result<(), String>,
    H: FnOnce() -> bool,
{
    let lxc_available = (lxc.0)();
    let bwrap_probe = (bwrap.0)();

    // Listed in the TypeScript SDK's order, so a caller moving off
    // `getPlatformSupport` reads the same answer.
    let mut available_methods = Vec::new();
    if lxc_available {
        available_methods.push("lxc".to_string());
    }
    if bwrap_probe.is_ok() {
        available_methods.push("bubblewrap".to_string());
    }

    match bwrap_probe {
        Ok(_) => PlatformSupport {
            is_supported: true,
            available_methods,
            // Walked only once `bwrap` itself is usable: the network
            // dependencies say nothing on a host that cannot run the backend,
            // and the walk costs several subprocess spawns.
            bubblewrap_network: Some(bubblewrap_network_support((proxy_enforcement.0)())),
            ..Default::default()
        },
        // `reason` says why the platform is unsupported, and LXC alone makes it
        // supported, so the bwrap detail has nowhere to go here.
        Err(_) if lxc_available => PlatformSupport {
            is_supported: true,
            available_methods,
            ..Default::default()
        },
        Err(err) => PlatformSupport {
            reason: Some(format!(
                "Neither LXC nor Bubblewrap is available on this system ({err})"
            )),
            ..Default::default()
        },
    }
}

/// Detect MXC support on the current host.
///
/// Mirrors the SDK's `getPlatformSupport`, restricted to the backends the
/// `mxc-sdk` library can actually run. On Linux both `bubblewrap` and `lxc` are
/// reported when present, and either one alone makes the host supported. On
/// Windows the isolation tier and UI capabilities come from the in-process
/// fallback probe rather than a `wxc-exec --probe` subprocess, and `wslc` is
/// reported when the host has the WSL Container runtime (requires the `wslc`
/// feature). The broader host-capability set (backends the host can run but the
/// SDK cannot launch) is reported separately by
/// [`available_backends`](crate::available_backends).
///
/// Every probe here answers "is the tooling usable", not "may this process use
/// it" — see [`PlatformSupport::available_methods`].
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
        // Presence alone is not enough for `bwrap`: it must also be new enough
        // for every flag the argument builder emits (see
        // `crate::bwrap_common::bwrap_version::MIN_BWRAP_VERSION`). LXC has no such
        // floor, so a clean `lxc-ls --version` is its whole gate.
        linux_platform_support_with(
            LxcProbe(crate::lxc_common::availability::is_lxc_available),
            BwrapProbe(crate::bwrap_common::bwrap_version::probe_bwrap),
            ProxyEnforcementProbe(crate::bwrap_common::proxy_network::probe_proxy_enforcement),
        )
    }

    #[cfg(target_os = "windows")]
    {
        let mut available_methods = vec!["processcontainer".to_string()];
        // `windows_sandbox` is a host-capability backend the SDK can't launch,
        // so it is reported by `available_backends()` rather than here.
        //
        // WSLC and IsolationSession are additional explicit backends rather
        // than fallbacks: report each only when the host has it.
        if wslc_available() {
            available_methods.push("wslc".to_string());
        }
        if isolation_session_present() {
            available_methods.push("isolation_session".to_string());
        }
        PlatformSupport {
            is_supported: true,
            available_methods,
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

/// Split from [`platform_support`] so the reporting is testable without a host
/// that has (or lacks) the private-network dependencies.
#[cfg(target_os = "linux")]
fn bubblewrap_network_support(probe: Result<(), String>) -> BubblewrapNetworkSupport {
    match probe {
        Ok(()) => BubblewrapNetworkSupport {
            proxy_enforcement: ProxyEnforcement::Supported,
            warnings: Vec::new(),
        },
        Err(reason) => BubblewrapNetworkSupport {
            proxy_enforcement: ProxyEnforcement::Unsupported,
            warnings: vec![reason],
        },
    }
}

/// Whether this host can run the WSL Container backend, probing the WSLC
/// runtime the same way the runner's preflight does. Always `false` when the
/// backend isn't compiled in, so the caller needs no `cfg` of its own.
#[cfg(target_os = "windows")]
fn wslc_available() -> bool {
    #[cfg(feature = "wslc")]
    {
        crate::wslc_common::is_available()
    }
    #[cfg(not(feature = "wslc"))]
    {
        false
    }
}

/// Read-only activation probe of the in-process IsolationSession service.
///
/// Reports whether the isolation-session backend's OS-side service is
/// available on this host. Exposed from the engine so `wxc` reaches the
/// isolation-session backend through `mxc_engine` rather than depending on
/// `isolation_session_common` directly.
///
/// Delegates to the backend's own availability probe — the same one
/// [`available_backends`](crate::mxc_engine::available_backends) consults — so the CLI
/// `--probe` surface and the Rust SDK surface can never disagree about this
/// host.
#[cfg(all(target_os = "windows", feature = "isolation_session"))]
pub fn isolation_session_available() -> bool {
    crate::isolation_session_common::availability::is_isolation_session_available()
}

/// Whether this host has the IsolationSession backend. Always `false` when the
/// backend isn't compiled in, so the caller needs no `cfg` of its own.
#[cfg(target_os = "windows")]
fn isolation_session_present() -> bool {
    #[cfg(feature = "isolation_session")]
    {
        isolation_session_available()
    }
    #[cfg(not(feature = "isolation_session"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::linux_platform_support_with;
    use super::platform_support;
    #[cfg(target_os = "linux")]
    use super::{
        bubblewrap_network_support, BwrapProbe, LxcProbe, ProxyEnforcement, ProxyEnforcementProbe,
    };
    #[cfg(target_os = "linux")]
    use crate::bwrap_common::bwrap_version::{BwrapUnavailable, BwrapVersion, MIN_BWRAP_VERSION};
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

    #[cfg(target_os = "linux")]
    #[test]
    fn bubblewrap_network_is_supported_when_probe_succeeds() {
        let support = bubblewrap_network_support(Ok(()));
        assert_eq!(support.proxy_enforcement, ProxyEnforcement::Supported);
        assert!(support.warnings.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bubblewrap_network_is_unsupported_with_reason_when_probe_fails() {
        let support = bubblewrap_network_support(Err("slirp4netns not found".to_string()));
        assert_eq!(support.proxy_enforcement, ProxyEnforcement::Unsupported);
        assert_eq!(support.warnings, vec!["slirp4netns not found".to_string()]);
    }

    /// `bubblewrap_network` is a Linux-only fact. Off Linux the field must be
    /// *absent* rather than `unsupported`, which would claim the host was
    /// evaluated and found wanting. Nothing else pins the non-Linux shape.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_hosts_report_no_bubblewrap_network() {
        let support = platform_support();
        assert!(
            support.bubblewrap_network.is_none(),
            "bubblewrap_network must be absent off Linux, got: {:?}",
            support.bubblewrap_network
        );

        let json = serde_json::to_string(&support).expect("PlatformSupport serializes");
        assert!(
            !json.contains("bubblewrapNetwork"),
            "the field must be omitted from the wire form off Linux, got: {json}"
        );
    }

    fn all_containment_names() -> Vec<String> {
        CANONICAL_BACKEND_NAMES
            .iter()
            .map(|(_, name)| (*name).to_string())
            .collect()
    }

    /// Guards the reported string literals against drift from canonical runtime
    /// backend names.
    #[test]
    fn reported_method_names_match_the_containment_wire_names() {
        for (backend, expected) in CANONICAL_BACKEND_NAMES {
            assert_eq!(backend.wire_name(), *expected, "{backend:?}");
        }
    }

    /// Exercises the live per-target arm, catching a typo'd literal (e.g.
    /// `"wsb"`) that the assertions above would miss.
    #[test]
    fn every_reported_method_is_a_real_wire_name() {
        let known = all_containment_names();
        for method in platform_support().available_methods {
            assert!(
                known.contains(&method),
                "reported method {method:?} is not a Containment wire name"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_support_reports_bubblewrap_when_probe_succeeds() {
        let support = linux_platform_support_with(
            LxcProbe(|| false),
            BwrapProbe(|| Ok(MIN_BWRAP_VERSION)),
            ProxyEnforcementProbe(|| Ok(())),
        );
        assert!(support.is_supported);
        assert_eq!(support.reason, None);
        assert_eq!(support.available_methods, ["bubblewrap"]);
        assert_eq!(
            support
                .bubblewrap_network
                .expect("network support is reported alongside a usable bwrap")
                .proxy_enforcement,
            ProxyEnforcement::Supported
        );
    }

    /// Both Linux backends are SDK-launchable, so a host carrying both must
    /// advertise both.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_support_reports_lxc_alongside_bubblewrap() {
        let support = linux_platform_support_with(
            LxcProbe(|| true),
            BwrapProbe(|| Ok(MIN_BWRAP_VERSION)),
            ProxyEnforcementProbe(|| Ok(())),
        );
        assert!(support.is_supported);
        assert_eq!(support.available_methods, ["lxc", "bubblewrap"]);
    }

    /// An LXC-only host can launch a sandbox, so reporting it unsupported would
    /// send every discovery caller away from a backend that works.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_support_stands_on_lxc_alone() {
        let support = linux_platform_support_with(
            LxcProbe(|| true),
            BwrapProbe(|| Err(BwrapUnavailable::TooOld(BwrapVersion::new(0, 4, 1)))),
            ProxyEnforcementProbe(|| {
                panic!("the network walk must not run without a usable bwrap")
            }),
        );
        assert!(support.is_supported);
        assert_eq!(support.reason, None);
        assert_eq!(support.available_methods, ["lxc"]);
        assert!(support.bubblewrap_network.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_support_preserves_probe_failure_reason() {
        let failure = BwrapUnavailable::TooOld(BwrapVersion::new(0, 4, 1));
        let expected = failure.to_string();
        let support = linux_platform_support_with(
            LxcProbe(|| false),
            BwrapProbe(|| Err(failure)),
            ProxyEnforcementProbe(|| {
                panic!("the network walk must not run without a usable bwrap")
            }),
        );
        assert!(!support.is_supported);
        let reason = support.reason.expect("an unsupported host explains itself");
        assert!(reason.contains(&expected), "got: {reason}");
        assert!(reason.contains("LXC"), "got: {reason}");
        assert!(support.available_methods.is_empty());
        assert!(support.bubblewrap_network.is_none());
    }

    /// A host with `bwrap` but without the private-network tooling is still a
    /// supported platform: only the proxy-enforcement capability is absent.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_support_reports_bubblewrap_without_proxy_enforcement() {
        let support = linux_platform_support_with(
            LxcProbe(|| false),
            BwrapProbe(|| Ok(MIN_BWRAP_VERSION)),
            ProxyEnforcementProbe(|| Err("slirp4netns not found".to_string())),
        );
        assert!(support.is_supported);
        assert_eq!(support.available_methods, ["bubblewrap"]);
        let network = support
            .bubblewrap_network
            .expect("network support is reported alongside a usable bwrap");
        assert_eq!(network.proxy_enforcement, ProxyEnforcement::Unsupported);
        assert_eq!(network.warnings, ["slirp4netns not found".to_string()]);
    }
}
