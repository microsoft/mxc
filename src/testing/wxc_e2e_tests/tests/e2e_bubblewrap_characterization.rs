// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bubblewrap (Linux) executor **characterization** tests.
//!
//! These lock in the run-to-completion behavior of the `lxc-exec` Bubblewrap
//! path. They assert what the code does **today**.
//!
//! Bubblewrap `--clearenv`s unconditionally, so the env contract pinned here is
//! deliberate rather than incidental. The harness captures via `.output()` and
//! so cannot provide a real PTY; the stdin/`SIGTTIN` behavior that needs one is
//! tracked separately.
//!
//! They run in the existing Linux CI job (`cargo test`) **only when `bwrap` is
//! installed** — `has_bwrap()` skips them cleanly otherwise. Each test also
//! skips if `lxc-exec` has not been built.
#![cfg(target_os = "linux")]

use serde_json::json;
use std::time::{Duration, Instant};
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
/// enforced, and that it takes a backgrounded descendant down with it.
///
/// The descendant is the load-bearing case: `bwrap` forks, so pid 1 of the
/// sandbox namespace is not the process the executor spawned. Killing that
/// handle tears the sandbox down only because `--die-with-parent` is set —
/// without it the descendant outlives the timeout, keeps writing to the
/// inherited stdout, and runs on after teardown has dropped its network
/// enforcement.
#[test]
fn bubblewrap_timeout_is_enforced() {
    if !ready() {
        return;
    }
    // Named so the assertion messages below cannot drift from the values they
    // describe when these are tuned.
    const TIMEOUT_MS: u64 = 1500;
    const DESCENDANT_SLEEP_SECS: u64 = 8;
    // Comfortably above the timeout and comfortably below the descendant's
    // lifetime, so a pass means teardown did not wait the descendant out.
    const MAX_ELAPSED: Duration = Duration::from_secs(6);

    let mut cfg = config(
        "timeout",
        &format!("echo CHAR_BEFORE; (/bin/sleep {DESCENDANT_SLEEP_SECS}; echo CHAR_AFTER) & wait"),
    );
    cfg["process"]["timeout"] = json!(TIMEOUT_MS);
    let started = Instant::now();
    let result = run_platform_config_value("bwrap timeout", &cfg, &[], None);
    let elapsed = started.elapsed();
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
    assert!(
        !out.contains("CHAR_AFTER"),
        "the descendant outlived the timeout and wrote post-timeout output. \
         Output:\n{out}"
    );
    assert!(
        elapsed < MAX_ELAPSED,
        "a {TIMEOUT_MS}ms timeout should not wait out the {DESCENDANT_SLEEP_SECS}s \
         descendant; took {elapsed:?}"
    );
}
