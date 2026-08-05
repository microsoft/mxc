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
    /// Containment backends available on this host, by wire name
    /// (e.g. `"seatbelt"`, `"bubblewrap"`, `"processcontainer"`).
    pub available_methods: Vec<String>,
}

/// Minimum Windows build the `processcontainer` backend supports — 26100
/// (Windows 11 24H2). This is the product floor documented in the README and
/// in `docs/process-container/os-version-support.md`.
#[cfg(any(target_os = "windows", test))]
const MIN_WINDOWS_BUILD: u32 = 26100;

/// Detect MXC support on the current host.
///
/// Mirrors the SDK's `getPlatformSupport`, restricted to the backends the
/// `mxc-sdk` library can actually run. On Windows the isolation tier and UI
/// capabilities come from the in-process fallback probe rather than a
/// `wxc-exec --probe` subprocess, and `wslc` is reported when the host has the
/// WSL Container runtime (requires the `wslc` feature).
///
/// Each arm probes the dependency that actually fails at spawn time: the
/// Seatbelt binary on macOS, a real namespace-creating `bwrap` run on Linux,
/// and the host's OS build on Windows.
///
/// Memoized for the process lifetime, matching the SDK's `getPlatformSupport`
/// — host capability is not expected to change at runtime, and the Linux arm
/// forks `bwrap`.
pub fn platform_support() -> PlatformSupport {
    static CACHED: std::sync::OnceLock<PlatformSupport> = std::sync::OnceLock::new();
    CACHED.get_or_init(detect_platform_support).clone()
}

fn detect_platform_support() -> PlatformSupport {
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
        // Two independent things can be wrong, so both are checked. `bwrap`
        // must be new enough for every flag the argument builder emits (see
        // `bwrap_common::bwrap_version::MIN_BWRAP_VERSION`), and — since
        // `--version` never creates a namespace — it must also actually be
        // able to build a sandbox on this host.
        let unavailable = bwrap_common::bwrap_version::probe_bwrap()
            .map_err(|err| err.to_string())
            .and_then(|_| probe_bubblewrap());
        match unavailable {
            Ok(()) => PlatformSupport {
                is_supported: true,
                available_methods: vec!["bubblewrap".to_string()],
                ..Default::default()
            },
            Err(reason) => PlatformSupport {
                reason: Some(reason),
                ..Default::default()
            },
        }
    }

    #[cfg(target_os = "windows")]
    {
        windows_platform_support(
            appcontainer_common::job_object::os_build_number(),
            wslc_available(),
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PlatformSupport {
            reason: Some("MXC is not supported on this platform".to_string()),
            ..Default::default()
        }
    }
}

/// Windows support decision for a given OS build number.
///
/// Split out from [`platform_support`] as a pure function so the build gate is
/// unit-testable on every host. `os_build_number` reports [`u32::MAX`] when
/// `RtlGetVersion` fails, which lands here as "modern" — a detection failure
/// must not silently declare a supported host unsupported.
///
/// WSLC is an additional, opt-in backend rather than a fallback, so it is
/// reported when the host can run it but does not carry `is_supported`: that
/// flag guards the default `processcontainer` spawn.
#[cfg(any(target_os = "windows", test))]
fn windows_platform_support(build: u32, wslc: bool) -> PlatformSupport {
    let mut available_methods = Vec::new();
    if build >= MIN_WINDOWS_BUILD {
        available_methods.push("processcontainer".to_string());
    }
    if wslc {
        available_methods.push("wslc".to_string());
    }

    if build >= MIN_WINDOWS_BUILD {
        PlatformSupport {
            is_supported: true,
            available_methods,
            ..Default::default()
        }
    } else {
        PlatformSupport {
            reason: Some(format!(
                "Windows build {build} is below {MIN_WINDOWS_BUILD}, the minimum \
                 supported build (Windows 11 24H2)"
            )),
            available_methods,
            ..Default::default()
        }
    }
}

/// Arguments for a minimal end-to-end containment probe.
///
/// `bwrap --version` only prints a banner — it never creates a namespace — so
/// it passes on hosts where unprivileged user namespaces are disabled
/// (`kernel.unprivileged_userns_clone=0`) or where AppArmor denies `bwrap`
/// (Ubuntu 23.10+), both of which then fail at every spawn.
///
/// The shape mirrors a real run: the same namespaces
/// `bwrap_command::build_args` unshares (pinned by
/// `probe_unshares_every_production_namespace`), plus `--proc` / `--dev`, and
/// `--clearenv` so the payload is resolved through `execvp`'s built-in
/// `/bin:/usr/bin` default rather than the caller's `PATH`. Binds use
/// `--ro-bind-try` on the few directories a shell needs — binding `/` instead
/// would make the probe fail on any host with an awkward submount, since
/// `bwrap` treats a failed submount remount as fatal.
#[cfg(any(target_os = "linux", test))]
const BWRAP_PROBE_ARGS: &[&str] = &[
    "--unshare-user",
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-net",
    "--ro-bind-try",
    "/bin",
    "/bin",
    "--ro-bind-try",
    "/usr/bin",
    "/usr/bin",
    "--ro-bind-try",
    "/lib",
    "/lib",
    "--ro-bind-try",
    "/lib64",
    "/lib64",
    "--ro-bind-try",
    "/usr/lib",
    "/usr/lib",
    "--ro-bind-try",
    "/usr/lib64",
    "/usr/lib64",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--clearenv",
    "--",
    "sh",
    "-c",
    "exit 0",
];

/// Run [`BWRAP_PROBE_ARGS`], reporting why the host cannot sandbox on failure.
///
/// Bounded by the same deadline as the version probe: this one mounts and
/// forks, so it can block on a wedged filesystem.
#[cfg(target_os = "linux")]
fn probe_bubblewrap() -> Result<(), String> {
    use bwrap_common::bwrap_version::{wait_with_deadline, PROBE_TIMEOUT};
    use std::io::ErrorKind;
    use std::process::{Command, Stdio};

    let child = Command::new("bwrap")
        .args(BWRAP_PROBE_ARGS)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match child {
        Ok(child) => child,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Err("Bubblewrap is not available on this system".to_string())
        }
        Err(e) => return Err(format!("Bubblewrap could not be executed: {e}")),
    };

    let output = match wait_with_deadline(&mut child, PROBE_TIMEOUT) {
        Some(Ok(output)) => output,
        Some(Err(e)) => return Err(format!("Bubblewrap could not be executed: {e}")),
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "Bubblewrap did not finish a trivial sandbox within {}s on this host",
                PROBE_TIMEOUT.as_secs()
            ));
        }
    };

    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "Bubblewrap is installed but cannot create a sandbox on this host: {}",
        bwrap_failure_detail(&output.stderr)
    ))
}

/// Reduce `bwrap`'s stderr to a single length-capped line for a `reason`.
#[cfg(any(target_os = "linux", test))]
fn bwrap_failure_detail(stderr: &[u8]) -> String {
    const MAX_LEN: usize = 200;

    let text = String::from_utf8_lossy(stderr);
    let Some(line) = text.lines().map(str::trim).find(|l| !l.is_empty()) else {
        return "no diagnostic output".to_string();
    };
    match line.char_indices().nth(MAX_LEN) {
        Some((end, _)) => format!("{}…", &line[..end]),
        None => line.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `is_supported`, `reason`, and `available_methods` must agree on every
    /// host: a supported host names its backends and gives no reason, an
    /// unsupported one does the opposite.
    #[test]
    fn support_fields_are_consistent() {
        let support = platform_support();
        assert_eq!(support.is_supported, support.reason.is_none());
        if support.is_supported {
            assert!(!support.available_methods.is_empty());
        }
    }

    #[test]
    fn windows_build_at_or_above_floor_is_supported() {
        for build in [MIN_WINDOWS_BUILD, 26200, u32::MAX] {
            let support = windows_platform_support(build, false);
            assert!(support.is_supported, "build {build}");
            assert_eq!(support.available_methods, ["processcontainer"]);
            assert!(support.reason.is_none());
        }
    }

    #[test]
    fn windows_build_below_floor_is_unsupported() {
        // 19045 = Windows 10 22H2, 22631 = Windows 11 23H2.
        for build in [0, 19045, 22631, MIN_WINDOWS_BUILD - 1] {
            let support = windows_platform_support(build, false);
            assert!(!support.is_supported, "build {build}");
            assert!(support.available_methods.is_empty());
            let reason = support.reason.expect("unsupported build needs a reason");
            assert!(reason.contains(&build.to_string()), "reason: {reason}");
        }
    }

    /// WSLC has its own runtime requirements, so it is reported wherever it is
    /// present — but it is opt-in, and must not make a below-floor host look
    /// ready for the default `processcontainer` spawn.
    #[test]
    fn wslc_is_reported_but_does_not_carry_support() {
        let below = windows_platform_support(22631, true);
        assert!(!below.is_supported);
        assert_eq!(below.available_methods, ["wslc"]);

        let above = windows_platform_support(MIN_WINDOWS_BUILD, true);
        assert!(above.is_supported);
        assert_eq!(above.available_methods, ["processcontainer", "wslc"]);
    }

    /// The probe is only a precondition worth trusting if it unshares
    /// everything a real spawn does — a namespace type the host disables
    /// (`user.max_uts_namespaces=0` and friends) must fail here, not at spawn.
    #[cfg(target_os = "linux")]
    #[test]
    fn probe_unshares_every_production_namespace() {
        use wxc_common::models::ExecutionRequest;

        let request = ExecutionRequest {
            script_code: "exit 0".to_string(),
            ..Default::default()
        };
        let production = bwrap_common::bwrap_command::build_args(&request, None);
        let unshares: Vec<&String> = production
            .iter()
            .filter(|a| a.starts_with("--unshare-"))
            .collect();

        assert!(
            !unshares.is_empty(),
            "production emits no --unshare-* flags"
        );
        for flag in unshares {
            assert!(
                BWRAP_PROBE_ARGS.contains(&flag.as_str()),
                "probe is missing {flag}, which every production spawn uses"
            );
        }
    }

    /// `--clearenv` is what keeps the probe's verdict independent of the
    /// caller's `PATH`: `execvp` then falls back to its built-in
    /// `/bin:/usr/bin`, both of which the probe binds.
    #[test]
    fn probe_clears_the_environment_and_binds_the_paths_it_execs_from() {
        assert!(BWRAP_PROBE_ARGS.contains(&"--clearenv"));
        for dir in ["/bin", "/usr/bin"] {
            assert!(BWRAP_PROBE_ARGS.contains(&dir), "probe does not bind {dir}");
        }
    }

    /// Binding `/` makes the probe fail on any host with an awkward submount,
    /// because `bwrap` treats a failed submount remount as fatal.
    #[test]
    fn probe_never_binds_the_host_root() {
        let root_bind = BWRAP_PROBE_ARGS
            .windows(3)
            .any(|w| w[0].starts_with("--ro-bind") && w[1] == "/" && w[2] == "/");
        assert!(!root_bind, "probe must not bind-mount host /");
    }

    #[test]
    fn bwrap_failure_detail_reports_first_nonempty_line() {
        let stderr = b"\n  \nbwrap: No permissions to creating new namespace\nsecond line\n";
        assert_eq!(
            bwrap_failure_detail(stderr),
            "bwrap: No permissions to creating new namespace"
        );
    }

    #[test]
    fn bwrap_failure_detail_handles_silence() {
        assert_eq!(bwrap_failure_detail(b""), "no diagnostic output");
        assert_eq!(bwrap_failure_detail(b"\n \n"), "no diagnostic output");
    }

    /// Truncation must land on a character boundary, not inside a multi-byte
    /// sequence — `bwrap` echoes back paths that may not be ASCII.
    #[test]
    fn bwrap_failure_detail_truncates_on_char_boundary() {
        let detail = bwrap_failure_detail("é".repeat(300).as_bytes());
        assert!(detail.ends_with('…'));
        assert_eq!(detail.chars().count(), 201);
    }
}
