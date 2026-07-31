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

/// Platform support information — the Rust analogue of the SDK
/// `PlatformSupport` type.
#[derive(Debug, Clone, Default)]
pub struct PlatformSupport {
    /// Whether MXC is supported on the current host.
    pub is_supported: bool,
    /// Why the platform is unsupported, when `is_supported` is false.
    pub reason: Option<String>,
    /// Containment backends the current host can run, by wire name
    /// (e.g. `"seatbelt"`, `"bubblewrap"`, `"lxc"`, `"processcontainer"`,
    /// `"windows_sandbox"`).
    ///
    /// This is a **host-capability** signal — the backends the host can run —
    /// not the narrower "backends `mxc-sdk` can launch" subset. For example it
    /// reports `lxc` (a separate `lxc-exec` binary) and `windows_sandbox` when
    /// the host supports them, even though `mxc-sdk`'s own run/stream paths do
    /// not drive those backends.
    pub available_methods: Vec<String>,
}

/// Detect MXC support on the current host.
///
/// Reports every containment backend the current host can run — a
/// host-capability signal, not the narrower "backends `mxc-sdk` can launch"
/// subset. On Linux `lxc` is included when `lxc-ls` is runnable (alongside
/// `bubblewrap`); on Windows `windows_sandbox` is included when its optional
/// feature is enabled (alongside `processcontainer`). Backend names are the
/// `wxc_common::wire::Containment` wire names.
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
        // Report every Linux backend the host can run. `lxc` availability is a
        // shallow `lxc-ls --version` check; `bubblewrap` additionally requires a
        // new-enough `bwrap` for every flag the argument builder emits (see
        // `bwrap_common::bwrap_version::MIN_BWRAP_VERSION`).
        let mut methods: Vec<String> = Vec::new();
        if lxc_common::availability::is_lxc_available() {
            methods.push("lxc".to_string());
        }
        let bwrap = bwrap_common::bwrap_version::probe_bwrap();
        if bwrap.is_ok() {
            methods.push("bubblewrap".to_string());
        }

        if methods.is_empty() {
            // No backend is usable. Surface why `bwrap` failed — `lxc`'s probe
            // has no structured reason, and `bwrap` is the historical default.
            let reason = match bwrap {
                Err(err) => err.to_string(),
                // Unreachable: an `Ok` would have pushed `bubblewrap` above.
                Ok(_) => "No Linux containment backend is available".to_string(),
            };
            PlatformSupport {
                reason: Some(reason),
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
        // `processcontainer` is the universal Windows floor; `windows_sandbox`
        // is additionally host-available when its optional feature is enabled.
        let mut available_methods = vec!["processcontainer".to_string()];
        if windows_sandbox_lifecycle::availability::is_windows_sandbox_available() {
            available_methods.push("windows_sandbox".to_string());
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

#[cfg(test)]
mod tests {
    use super::platform_support;
    use wxc_common::wire::Containment;

    /// The wire name serde emits for a `Containment` variant, without the JSON
    /// quotes.
    fn wire_name(containment: &Containment) -> String {
        serde_json::to_string(containment)
            .expect("Containment serializes")
            .trim_matches('"')
            .to_string()
    }

    /// The full set of `Containment` wire names, so tests can assert reported
    /// methods are real backend names rather than a hardcoded expectation.
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

    /// Guards against drift between the string literals `platform_support`
    /// reports in `available_methods` and the canonical `Containment` wire
    /// names. If a rename lands on the enum without updating the probe (or vice
    /// versa), this fails.
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

    /// Every method `platform_support` actually reports on this host must be a
    /// real `Containment` wire name. Unlike the assertions above (which pin the
    /// enum's serde output), this exercises the live `platform_support()` arm
    /// for the current target, so a typo'd literal in the probe (e.g. `"wsb"`)
    /// is caught even though its expected string is not hardcoded here.
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
