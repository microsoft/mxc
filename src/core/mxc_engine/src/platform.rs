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
    pub available_methods: Vec<String>,
}

/// Detect MXC support on the current host.
///
/// Mirrors the SDK's `getPlatformSupport`, restricted to the backends the
/// `mxc-sdk` library can actually run. On Windows the isolation tier and UI
/// capabilities come from the in-process fallback probe rather than a
/// `wxc-exec --probe` subprocess, and `wslc` is reported when the host has the
/// WSL Container runtime (requires the `wslc` feature). The broader
/// host-capability set (backends the host can run but the SDK cannot launch,
/// e.g. `lxc`, `windows_sandbox`, `isolation_session`) is reported separately by
/// [`available_backends`](crate::available_backends).
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
        // `bwrap_common::bwrap_version::MIN_BWRAP_VERSION`). `lxc` is a
        // host-capability backend the SDK can't launch, so it is reported by
        // `available_backends()` rather than here.
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
        let mut available_methods = vec!["processcontainer".to_string()];
        // `windows_sandbox` and `isolation_session` are host-capability backends
        // the SDK can't launch, so they are reported by `available_backends()`
        // rather than here.
        //
        // WSLC is an additional, opt-in backend rather than a fallback: report
        // it only when the host can actually run it (WSL2 + the WSLC runtime),
        // which is the same preflight the runner performs.
        if wslc_available() {
            available_methods.push("wslc".to_string());
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

/// Whether this host can run the WSL Container backend, probing the WSLC
/// runtime the same way the runner's preflight does. Always `false` when the
/// backend isn't compiled in, so the caller needs no `cfg` of its own.
#[cfg(target_os = "windows")]
fn wslc_available() -> bool {
    #[cfg(feature = "wslc")]
    {
        wslc_common::is_available()
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
/// [`available_backends`](crate::available_backends) consults — so the CLI
/// `--probe` surface and the Rust SDK surface can never disagree about this
/// host. That probe owns its COM apartment, so this is callable regardless of
/// whether the caller has initialized COM.
#[cfg(all(target_os = "windows", feature = "isolation_session"))]
pub fn isolation_session_available() -> bool {
    isolation_session_common::availability::is_isolation_session_available()
}

#[cfg(test)]
mod tests {
    use super::platform_support;
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

    /// Guards the reported string literals against drift from the `Containment`
    /// serde wire names.
    #[test]
    fn reported_method_names_match_the_containment_wire_names() {
        assert_eq!(wire_name(&Containment::Lxc), "lxc");
        assert_eq!(wire_name(&Containment::WindowsSandbox), "windows_sandbox");
        assert_eq!(
            wire_name(&Containment::ProcessContainer),
            "processcontainer"
        );
        assert_eq!(wire_name(&Containment::Bubblewrap), "bubblewrap");
        assert_eq!(wire_name(&Containment::Seatbelt), "seatbelt");
    }

    /// Exercises the live per-target arm, catching a typo'd literal (e.g.
    /// `"wsb"`) that the assertions above would miss.
    #[test]
    fn every_reported_method_is_a_real_wire_name() {
        let known = all_wire_names();
        for method in platform_support().available_methods {
            assert!(
                known.contains(&method),
                "reported method {method:?} is not a Containment wire name"
            );
        }
    }
}
