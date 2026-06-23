// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bubblewrap (Linux) executor **characterization** tests.
//!
//! These lock in the *current* run-to-completion behavior of the `lxc-exec`
//! Bubblewrap path before the unified `SandboxBackend`/`Runner` refactor lands.
//! They assert what the code does **today**.
//!
//! Unlike Seatbelt, Bubblewrap already `--clearenv`s unconditionally and runs
//! the child with `stdin` closed, so the env/stdin contracts pinned here are
//! ones the refactor should *preserve*. (The stdin/`SIGTTIN` regression that the
//! refactor introduces is only observable under a real PTY, which the
//! `.output()`-based harness cannot provide — that needs a separate PTY harness
//! and is tracked as a follow-up.)
//!
//! They run in the existing Linux CI job (`cargo test`) **only when `bwrap` is
//! installed** — `has_bwrap()` skips them cleanly otherwise. Each test also
//! skips if `lxc-exec` has not been built.
#![cfg(target_os = "linux")]

use serde_json::json;
use wxc_e2e_tests::{has_bwrap, has_platform_exec, run_platform_config_value};

const SCHEMA_VERSION: &str = "0.7.0-alpha";

/// Whether the Bubblewrap characterization prerequisites are present.
fn ready() -> bool {
    has_platform_exec() && has_bwrap()
}

/// Build a one-shot config that omits `containment` so the binary selects its
/// OS-native backend (Bubblewrap on Linux).
fn config(label: &str, command_line: &str) -> serde_json::Value {
    json!({
        "version": SCHEMA_VERSION,
        "containerId": format!("char-bwrap-{label}"),
        "process": { "commandLine": command_line }
    })
}

#[test]
fn bubblewrap_propagates_exit_code() {
    if !ready() {
        return;
    }
    let result =
        run_platform_config_value("bwrap exit code", &config("exit-code", "exit 7"), &[], None);
    assert_eq!(
        result.code,
        Some(7),
        "expected exit 7, got {:?}\n--- stderr ---\n{}",
        result.code,
        result.stderr
    );
}

#[test]
fn bubblewrap_streams_stdout() {
    if !ready() {
        return;
    }
    let result = run_platform_config_value(
        "bwrap stdout",
        &config("stdout", "echo CHAR_BWRAP_STDOUT_71c4d"),
        &[],
        None,
    );
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    assert!(
        result.combined_output().contains("CHAR_BWRAP_STDOUT_71c4d"),
        "stdout missing sentinel:\n{}",
        result.combined_output()
    );
}

/// CHARACTERIZES CURRENT BEHAVIOR.
///
/// Bubblewrap runs with `--clearenv`, so the sandboxed child does *not* inherit
/// the launcher's environment even when `process.env` is empty. The refactor
/// should preserve this; if it ever turns RED the env model has drifted.
#[test]
fn bubblewrap_clears_host_env_by_default() {
    if !ready() {
        return;
    }
    let marker = "CHAR_BWRAP_SHOULD_NOT_APPEAR_8a02f";
    let result = run_platform_config_value(
        "bwrap env clear",
        &config("env-clear", "printf 'MARKER=[%s]\\n' \"$MXC_CHAR_MARKER\""),
        &[("MXC_CHAR_MARKER", marker)],
        None,
    );
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    let out = result.combined_output();
    assert!(
        out.contains("MARKER=[]"),
        "expected cleared env (MARKER=[]); current Bubblewrap --clearenv behavior. Output:\n{out}"
    );
    assert!(
        !out.contains(marker),
        "host env marker leaked into the sandbox. Output:\n{out}"
    );
}

/// Locks in that an explicitly requested `process.env` reaches the child.
#[test]
fn bubblewrap_applies_requested_env() {
    if !ready() {
        return;
    }
    let mut cfg = config("env-set", "printf 'SET=[%s]\\n' \"$MXC_CHAR_SET\"");
    cfg["process"]["env"] = json!(["MXC_CHAR_SET=from_config_c93b"]);
    let result = run_platform_config_value("bwrap env set", &cfg, &[], None);
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    assert!(
        result.combined_output().contains("SET=[from_config_c93b]"),
        "expected requested env var to reach the child. Output:\n{}",
        result.combined_output()
    );
}

/// Locks in that an explicit `process.cwd` is honored (Bubblewrap emits
/// `--chdir` for a non-empty working directory). `/` always exists inside the
/// sandbox, so it is a stable target.
#[test]
fn bubblewrap_honors_explicit_process_cwd() {
    if !ready() {
        return;
    }
    let mut cfg = config("cwd-explicit", "pwd -P");
    cfg["process"]["cwd"] = json!("/");
    let result = run_platform_config_value("bwrap cwd explicit", &cfg, &[], None);
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    assert_eq!(
        result.stdout.trim(),
        "/",
        "expected child cwd to honor explicit process.cwd=/"
    );
}

/// Characterizes that a `process.timeout` shorter than the workload is
/// enforced and surfaces as a non-zero exit.
///
/// NOTE: on current `main`, the Bubblewrap run-to-completion timeout kills only
/// the `bwrap` parent (`child.kill()`), so a forked descendant can survive,
/// keep the stdout pipe open, and have its post-timeout output captured (the
/// call can even block until the descendant exits). That tree-kill behavior is
/// something the unified `Runner` refactor changes, so this test deliberately
/// does NOT assert the absence of post-timeout output or a wall-clock bound —
/// only that the timeout fires and fails the run.
#[test]
fn bubblewrap_timeout_is_enforced() {
    if !ready() {
        return;
    }
    let mut cfg = config("timeout", "echo CHAR_BEFORE; /bin/sleep 5; echo CHAR_AFTER");
    cfg["process"]["timeout"] = json!(1500);
    let result = run_platform_config_value("bwrap timeout", &cfg, &[], None);
    let out = result.combined_output();
    assert!(
        out.contains("CHAR_BEFORE"),
        "expected pre-timeout output. Output:\n{out}"
    );
    assert_ne!(
        result.code,
        Some(0),
        "a timed-out run should exit non-zero. Output:\n{out}"
    );
}
