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
//! Scope note: env/cwd inheritance is intentionally not characterized here —
//! the AppContainer "clean environment" model differs from the Unix backends,
//! and the PR's env/cwd regressions were Seatbelt-specific. These tests cover
//! the universally-meaningful contracts: exit-code propagation, stdout capture,
//! and timeout enforcement.
#![cfg(target_os = "windows")]

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
