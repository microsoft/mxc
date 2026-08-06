// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows ProcessContainer (AppContainer / BaseContainer) executor
//! **characterization** tests.
//!
//! These lock in the *current* run-to-completion behavior of the `wxc-exec.exe`
//! ProcessContainer path before the unified `SandboxBackend`/`Runner` refactor
//! lands. They assert what the code does **today**.
//!
//! ProcessContainer execution requires an elevated, host-prepped Windows host
//! (see `docs/host-prep.md`). Standard CI runners are **not** capable, so these
//! tests skip unless a prepared lane sets `MXC_E2E_HOST_PREPPED=1`
//! (`host_prepped_optin()`), and additionally skip if `wxc-exec.exe` has not
//! been built or the host is missing process prerequisites. They therefore
//! never red-fail on incapable CI, but lock in behavior on a prepared box.
//!
//! Scope note: env inheritance is intentionally not characterized here — the
//! AppContainer "clean environment" model differs from the Unix backends. cwd
//! *is* characterized (see the two `*_process_cwd*` tests below), because both
//! Windows runners resolve an empty `process.cwd` to a concrete directory
//! rather than passing `NULL` to the launch API.
//!
//! Tier note: the ProcessContainer tier (BaseContainer vs AppContainer+DACL) is
//! **not** independently selectable from a config — the dispatcher derives it
//! purely from host capability, and the `MXC_FORCE_TIER` seam is `cfg(test)`-only
//! so it has no effect on the production `wxc-exec.exe`. These tests therefore
//! exercise whichever tier the prepared lane resolves to; running them on both a
//! BaseContainer-capable and a downlevel host covers both tiers. Because that is
//! not enforceable in ordinary CI, the tier-independent guarantee — that neither
//! runner can resolve a `NULL` cwd — is additionally locked in by the unit tests
//! on the shared `appcontainer_common::working_directory` mapping both launch
//! sites call, which run on every lane with no host prerequisites.
#![cfg(target_os = "windows")]

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;
use wxc_e2e_tests::{
    has_platform_exec, host_prepped_optin, run_platform_config_value, CommandResult,
};

const SCHEMA_VERSION: &str = "0.7.0-alpha";

/// Whether the ProcessContainer characterization prerequisites are present.
fn ready() -> bool {
    has_platform_exec() && host_prepped_optin()
}

/// Build a one-shot config that omits `containment` so the binary selects its
/// OS-native backend (ProcessContainer on Windows).
fn config(label: &str, command_line: &str) -> serde_json::Value {
    json!({
        "version": SCHEMA_VERSION,
        "containerId": format!("char-pc-{label}"),
        "process": { "commandLine": command_line }
    })
}

/// Scope-bound temporary directory for cwd characterization.
///
/// Cleanup is tied to `Drop` rather than an explicit call before the
/// assertions, so the tree survives long enough to be inspected when an
/// assertion fails, and is still removed when a helper panics early.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("mxc-char-pc-{tag}-{nanos}"));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Whether `name` exists directly inside this directory.
    fn contains(&self, name: &str) -> bool {
        self.path.join(name).exists()
    }

    fn to_config_value(&self) -> serde_json::Value {
        json!(self.path.to_string_lossy())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Skip (rather than fail) when the local host cannot launch a sandboxed
/// process despite the opt-in being set (e.g. missing runtime prerequisites).
fn skip_if_missing_prereq(result: &CommandResult) -> bool {
    if result.is_missing_process_prerequisite() {
        println!(
            "SKIPPED: {} — host missing process prerequisites",
            result.label
        );
        return true;
    }
    false
}

#[test]
fn processcontainer_propagates_exit_code() {
    if !ready() {
        return;
    }
    let result = run_platform_config_value(
        "processcontainer exit code",
        &config("exit-code", "cmd /c exit 7"),
        &[],
        None,
    );
    if skip_if_missing_prereq(&result) {
        return;
    }
    assert_eq!(
        result.code,
        Some(7),
        "expected exit 7, got {:?}\n--- stderr ---\n{}",
        result.code,
        result.stderr
    );
}

#[test]
fn processcontainer_streams_stdout() {
    if !ready() {
        return;
    }
    let result = run_platform_config_value(
        "processcontainer stdout",
        &config("stdout", "cmd /c echo CHAR_PC_STDOUT_5d72e"),
        &[],
        None,
    );
    if skip_if_missing_prereq(&result) {
        return;
    }
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    assert!(
        result.combined_output().contains("CHAR_PC_STDOUT_5d72e"),
        "stdout missing sentinel:\n{}",
        result.combined_output()
    );
}

/// Characterizes that a `process.timeout` shorter than the workload kills the
/// child mid-run.
#[test]
fn processcontainer_timeout_kills_before_completion() {
    if !ready() {
        return;
    }
    let mut cfg = config(
        "timeout",
        "cmd /c \"echo CHAR_BEFORE & ping -n 8 127.0.0.1 >nul & echo CHAR_AFTER\"",
    );
    cfg["process"]["timeout"] = json!(1500);
    let result = run_platform_config_value("processcontainer timeout", &cfg, &[], None);
    if skip_if_missing_prereq(&result) {
        return;
    }
    let out = result.combined_output();
    assert!(
        out.contains("CHAR_BEFORE"),
        "expected pre-timeout output. Output:\n{out}"
    );
    assert!(
        !out.contains("CHAR_AFTER"),
        "workload should have been killed before completing. Output:\n{out}"
    );
    assert_ne!(result.code, Some(0), "timed-out run should not exit 0");
    assert!(
        result.wall_time_ms < 6000,
        "timeout should fire well before the workload finishes; took {}ms",
        result.wall_time_ms
    );
}

/// REGRESSION GUARD (both Windows runners).
///
/// With an empty `process.cwd`, neither ProcessContainer runner may pass a
/// `NULL` current directory to the launch API: the child would then inherit the
/// launcher's cwd, and when the sandbox token can't open it the kernel silently
/// resets the child to the drive root (`C:\`). Instead the runners resolve the
/// cwd via `appcontainer_common::working_directory::launch_working_directory()`
/// — here, the first `readwritePaths` entry.
///
/// The unit tests on that mapping cover selection and the never-`NULL`
/// guarantee, but not that the resolved value actually reaches the launch API.
/// This test observes the child's actual cwd by having it create a file through
/// a *relative* path and checking which directory it lands in.
///
/// `launch_dir` is the launcher's cwd and is *also* a granted readwrite path, so
/// a `NULL`-cwd regression would be openable by the token and the probe would
/// land there — making the two outcomes distinguishable.
#[test]
fn processcontainer_runs_in_first_readwrite_path_when_process_cwd_empty() {
    if !ready() {
        return;
    }
    let write_dir = TempDir::new("cwd-write");
    let launch_dir = TempDir::new("cwd-launch");
    let probe = "char_cwd_default_probe.txt";
    let mut cfg = config("cwd-default", &format!("cmd /c echo CHAR_OK> {probe}"));
    cfg["filesystem"] = json!({
        "readwritePaths": [write_dir.to_config_value(), launch_dir.to_config_value()]
    });
    let result = run_platform_config_value(
        "processcontainer cwd default",
        &cfg,
        &[],
        Some(launch_dir.path()),
    );
    if skip_if_missing_prereq(&result) {
        return;
    }
    assert_eq!(
        result.code,
        Some(0),
        "run failed:\n{}",
        result.combined_output()
    );
    let in_launch = launch_dir.contains(probe);
    let in_write = write_dir.contains(probe);
    assert!(
        in_write && !in_launch,
        "expected the probe in the first readwrite policy path {} (resolved cwd \
         with empty process.cwd); in_write={in_write} in_launch={in_launch}\n{}",
        write_dir.path().display(),
        result.combined_output()
    );
}

/// Locks in that an explicit `process.cwd` still wins over the policy-path
/// fallback in `working_directory::launch_working_directory()`.
#[test]
fn processcontainer_honors_explicit_process_cwd() {
    if !ready() {
        return;
    }
    let explicit_dir = TempDir::new("cwd-explicit");
    let other_dir = TempDir::new("cwd-other");
    let probe = "char_cwd_explicit_probe.txt";
    let mut cfg = config("cwd-explicit", &format!("cmd /c echo CHAR_OK> {probe}"));
    cfg["process"]["cwd"] = explicit_dir.to_config_value();
    // `other_dir` is listed first so the fallback would resolve to it; the
    // explicit cwd must take precedence.
    cfg["filesystem"] = json!({
        "readwritePaths": [other_dir.to_config_value(), explicit_dir.to_config_value()]
    });
    let result = run_platform_config_value("processcontainer cwd explicit", &cfg, &[], None);
    if skip_if_missing_prereq(&result) {
        return;
    }
    assert_eq!(
        result.code,
        Some(0),
        "run failed:\n{}",
        result.combined_output()
    );
    let in_explicit = explicit_dir.contains(probe);
    let in_other = other_dir.contains(probe);
    assert!(
        in_explicit && !in_other,
        "expected the probe file in the explicit process.cwd {}; \
         in_explicit={in_explicit} in_other={in_other}\n{}",
        explicit_dir.path().display(),
        result.combined_output()
    );
}
