// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows Sandbox host-availability probe.
//!
//! Ports the TypeScript SDK's `isWindowsSandboxAvailable()` into Rust so
//! backend detection lives in one place (see
//! `docs/backend-support-probe-api-plan.md`). This is a faithful port of the
//! SDK's *existing* behavior, not the deeper optional-feature detector tracked
//! as follow-up work: it asks DISM whether the `Containers-DisposableClientVM`
//! optional feature is `Enabled`, and — when DISM cannot be run (typically
//! because the caller is not elevated) — falls back to checking for
//! `WindowsSandbox.exe` under `System32`, which Windows installs only when the
//! feature is enabled.
//!
//! The decision half is pure (no I/O), so it is unit-tested directly; only
//! [`run_dism`] and [`sandbox_exe_exists`] touch the host.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// How long to wait for DISM before giving up and falling back to the
/// executable-presence check. Mirrors the 10s timeout the TypeScript
/// `isWindowsSandboxAvailable()` passes to `execSync`.
const DISM_TIMEOUT: Duration = Duration::from_secs(10);

/// Cached result — DISM is a subprocess spawn, so the host is probed at most
/// once per process. A cached value can go stale if the optional feature is
/// toggled mid-process; that is accepted and matches the SDK's module-level
/// cache.
static AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Whether the Windows Sandbox backend looks available on this host.
///
/// Mirrors the SDK's `isWindowsSandboxAvailable()`: DISM `State : Enabled` for
/// `Containers-DisposableClientVM`, else the presence of `WindowsSandbox.exe`.
/// Cached for the life of the process.
pub fn is_windows_sandbox_available() -> bool {
    *AVAILABLE.get_or_init(|| decide(run_dism(), sandbox_exe_exists))
}

/// Decide availability from the DISM result and an executable-presence probe.
///
/// `dism` is `Some(stdout)` when `dism /online /get-featureinfo` ran and exited
/// successfully, or `None` when it could not be run (e.g. non-elevated). When
/// DISM ran we trust its reported feature state; otherwise we fall back to the
/// executable check. Split out so the branching is testable without spawning
/// DISM or touching the filesystem.
fn decide(dism: Option<String>, exe_exists: impl FnOnce() -> bool) -> bool {
    match dism {
        Some(output) => dism_reports_enabled(&output),
        None => exe_exists(),
    }
}

/// Whether DISM's feature-info output reports the feature is enabled.
///
/// DISM prints one `Key : Value` pair per line; the feature state appears as
/// `State : Enabled`. We match `State` case- and spacing-insensitively and
/// require the value to be exactly `Enabled` (again case-insensitive). The
/// TypeScript port uses the looser regex `/State\s*:\s*Enabled/i`, but the DISM
/// feature-state vocabulary (`Enabled`, `Disabled`,
/// `Disabled with Payload Removed`, ...) never uses `Enabled` as a prefix of
/// another state, so exact-value matching yields the same verdict for every
/// real DISM output while rejecting an accidental `Enabled…` substring.
///
/// [`run_dism`] passes DISM's `/English` global option, so the `State` /
/// `Enabled` tokens parsed here are not localized on non-English Windows
/// installations.
fn dism_reports_enabled(output: &str) -> bool {
    output.lines().any(|line| {
        line.split_once(':').is_some_and(|(key, value)| {
            key.trim().eq_ignore_ascii_case("state") && value.trim().eq_ignore_ascii_case("enabled")
        })
    })
}

/// Absolute path to `dism.exe` under the Windows system directory. Invoking the
/// absolute path (rather than the bare `dism` name) avoids resolving a
/// same-named binary planted earlier on `PATH` — a hardening measure that
/// matters for a sandboxing product's own capability probe.
fn dism_path() -> PathBuf {
    system_directory().join("dism.exe")
}

/// Absolute path to the Windows **system directory** (e.g.
/// `C:\Windows\System32`), resolved via `GetSystemDirectoryW` and cached on
/// first use.
///
/// The kernel publishes this value at process creation and the environment
/// block cannot override it, so it is safe even when an unelevated parent set
/// `SystemRoot` to an attacker-controlled directory (UAC inherits the parent's
/// environment verbatim). Reading `%SystemRoot%` here would let a standard user
/// point this probe — and the `dism.exe` it launches — at a planted binary. See
/// `src/host/plm/src/wpr_path.rs` for the same requirement and its full
/// rationale.
///
/// Falls back to the well-known `C:\Windows\System32` literal only if
/// `GetSystemDirectoryW` fails outright (it does not on a real Windows install);
/// that fallback is a compile-time constant, not env-derived, so it preserves
/// the security property.
fn system_directory() -> &'static Path {
    static SYSTEM_DIR: OnceLock<PathBuf> = OnceLock::new();
    SYSTEM_DIR
        .get_or_init(|| {
            resolve_system_directory().unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32"))
        })
        .as_path()
}

/// Resolve the system directory via `GetSystemDirectoryW`, growing the buffer
/// once if it is reported too small. Returns `None` only on an outright Win32
/// failure (return value 0), which does not happen on a real Windows install.
fn resolve_system_directory() -> Option<PathBuf> {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buf = vec![0u16; 260];
    // SAFETY: `buf` is valid and owned for the duration of the call; we pass its
    // true length and read only the returned prefix.
    let mut n = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
    if n == 0 {
        return None;
    }
    // On success `n` excludes the terminating NUL and is strictly less than the
    // buffer size; if `n` >= buffer size the buffer was too small and `n` is the
    // required size including the NUL — grow and retry once.
    if n as usize >= buf.len() {
        buf = vec![0u16; n as usize];
        n = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
        if n == 0 || n as usize >= buf.len() {
            return None;
        }
    }
    Some(PathBuf::from(wxc_common::string_util::from_wide(
        &buf[..n as usize],
    )))
}

/// Run `dism /English /online /get-featureinfo`
/// `/featurename:Containers-DisposableClientVM` and return its stdout when it
/// exits successfully within [`DISM_TIMEOUT`], or `None` on any spawn failure,
/// non-zero exit, or timeout. DISM against `/online` typically requires
/// elevation, so a non-elevated caller lands in the `None` (fallback) branch.
/// The timeout guards against a wedged DISM hanging the probe indefinitely,
/// matching the TypeScript port's 10s `execSync` limit. The `/English` global
/// option forces the `State : Enabled` tokens to their invariant English form so
/// [`dism_reports_enabled`] parses correctly on localized Windows.
fn run_dism() -> Option<String> {
    let mut child = Command::new(dism_path())
        .args([
            "/English",
            "/online",
            "/get-featureinfo",
            "/featurename:Containers-DisposableClientVM",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Poll for completion up to the deadline. `get-featureinfo` emits only a few
    // hundred bytes — well under the OS pipe buffer — so leaving stdout undrained
    // until the child exits cannot deadlock it.
    let deadline = Instant::now() + DISM_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                let mut stdout = String::new();
                child.stdout.take()?.read_to_string(&mut stdout).ok()?;
                return Some(stdout);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
}

/// Whether `WindowsSandbox.exe` exists under the Windows system directory.
/// Windows installs it only when the `Containers-DisposableClientVM` feature is
/// enabled, and the path is readable without elevation. Uses the same
/// env-spoof-proof [`system_directory`] resolution as [`dism_path`].
fn sandbox_exe_exists() -> bool {
    system_directory().join("WindowsSandbox.exe").exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dism_enabled_state_is_detected() {
        let output = "\
Feature Information:

Feature Name : Containers-DisposableClientVM
State : Enabled
";
        assert!(dism_reports_enabled(output));
    }

    #[test]
    fn dism_disabled_or_absent_state_is_not_enabled() {
        assert!(!dism_reports_enabled("State : Disabled"));
        assert!(!dism_reports_enabled(
            "State : Disabled with Payload Removed"
        ));
        assert!(!dism_reports_enabled(
            "Feature Name : Containers-DisposableClientVM"
        ));
        assert!(!dism_reports_enabled(""));
    }

    #[test]
    fn dism_state_matching_ignores_case_and_spacing() {
        assert!(dism_reports_enabled("state:enabled"));
        assert!(dism_reports_enabled("   State    :    ENABLED   "));
    }

    #[test]
    fn when_dism_ran_the_exe_fallback_is_not_consulted() {
        // DISM present and Enabled → available, exe probe never runs.
        assert!(decide(Some("State : Enabled".to_string()), || panic!(
            "exe probe must not run when DISM produced a result"
        )));
        // DISM present and Disabled → not available, exe probe still skipped.
        assert!(!decide(Some("State : Disabled".to_string()), || panic!(
            "exe probe must not run when DISM produced a result"
        )));
    }

    #[test]
    fn when_dism_could_not_run_the_exe_fallback_decides() {
        assert!(decide(None, || true));
        assert!(!decide(None, || false));
    }
}
