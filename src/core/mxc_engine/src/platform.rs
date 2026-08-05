// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host platform support detection — the Rust port of the SDK's
//! `getPlatformSupport`, shared by the public SDK and the executor binaries.

/// Platform support information — the Rust analogue of the SDK
/// `PlatformSupport` type.
#[derive(Debug, Clone, Default)]
pub struct PlatformSupport {
    /// Whether MXC is supported on the current host.
    pub is_supported: bool,
    /// Why the platform is unsupported, when `is_supported` is false.
    pub reason: Option<String>,
    /// Containment backends detected as runnable on this host, by wire name
    /// (e.g. `"seatbelt"`, `"lxc"`, `"processcontainer"`, `"windows_sandbox"`).
    ///
    /// A **host-capability** signal (broader than the "backends `mxc-sdk` can
    /// launch" subset), and only the **currently detected** slice of it:
    /// backends without a Rust detector yet (notably `isolation_session`) are
    /// omitted even when the host could run them, so absence means "not affirmed
    /// here", not "cannot run".
    pub available_methods: Vec<String>,
}

/// Detect MXC support on the current host — see [`PlatformSupport::available_methods`]
/// for what the reported set does and does not promise.
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
        // `lxc` is a shallow `lxc-ls --version` check; `bubblewrap` additionally
        // needs a new-enough `bwrap` (see `bwrap_common::bwrap_version`).
        let mut methods: Vec<String> = Vec::new();
        if lxc_common::availability::is_lxc_available() {
            methods.push("lxc".to_string());
        }
        let bwrap = bwrap_common::bwrap_version::probe_bwrap();
        if bwrap.is_ok() {
            methods.push("bubblewrap".to_string());
        }

        if methods.is_empty() {
            // Surface why `bwrap` failed — `lxc`'s probe has no structured reason.
            let reason = match bwrap {
                Err(err) => err.to_string(),
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
