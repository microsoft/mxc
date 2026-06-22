// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Seatbelt (macOS) executor **characterization** tests.
//!
//! These pin the run-to-completion behavior of the `mxc-exec-mac` executor
//! under the unified `SandboxBackend`/`Runner` design, exercised end-to-end.
//!
//! Two of them — `clears_host_env_when_process_env_empty` and
//! `runs_in_first_readwrite_path_when_process_cwd_empty` — assert behaviors the
//! unification deliberately changed from the pre-refactor executor: Seatbelt now
//! unconditionally `env_clear()`s and resolves an empty working directory to a
//! policy path. If they turn RED, the env/cwd model has drifted.
//!
//! They run in the existing macOS CI job (`cargo test --target
//! aarch64-apple-darwin`) with no extra infrastructure: `sandbox-exec` needs no
//! elevation. Each test skips cleanly if `mxc-exec-mac` has not been built.
#![cfg(target_os = "macos")]

use std::fs;
use std::path::PathBuf;

use serde_json::json;
use wxc_e2e_tests::{has_platform_exec, run_platform_config_value};

const SCHEMA_VERSION: &str = "0.7.0-alpha";

/// Build a one-shot config that omits `containment` so the binary selects its
/// OS-native backend (Seatbelt on macOS). `cwd`/`env`/`timeout` are optional.
fn config(label: &str, command_line: &str) -> serde_json::Value {
    json!({
        "version": SCHEMA_VERSION,
        "containerId": format!("char-seatbelt-{label}"),
        "process": { "commandLine": command_line }
    })
}

/// Create a unique temporary directory for cwd characterization.
fn unique_tempdir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("mxc-char-{tag}-{nanos}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn seatbelt_propagates_exit_code() {
    if !has_platform_exec() {
        return;
    }
    let result = run_platform_config_value(
        "seatbelt exit code",
        &config("exit-code", "exit 7"),
        &[],
        None,
    );
    assert_eq!(
        result.code,
        Some(7),
        "expected exit 7, got {:?}\n--- stderr ---\n{}",
        result.code,
        result.stderr
    );
}

#[test]
fn seatbelt_streams_stdout() {
    if !has_platform_exec() {
        return;
    }
    let result = run_platform_config_value(
        "seatbelt stdout",
        &config("stdout", "echo CHAR_SEATBELT_STDOUT_9f31a"),
        &[],
        None,
    );
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    assert!(
        result
            .combined_output()
            .contains("CHAR_SEATBELT_STDOUT_9f31a"),
        "stdout missing sentinel:\n{}",
        result.combined_output()
    );
}

/// CHARACTERIZES CURRENT BEHAVIOR (regression guard).
///
/// With an empty `process.env`, the Seatbelt exec path starts the child from a
/// *cleared* environment (`env_clear()` plus a default `PATH`), so the
/// launcher's environment — which may hold cloud creds / API tokens — never
/// leaks into untrusted sandboxed code. This matches Bubblewrap's `--clearenv`
/// model (see `bubblewrap_clears_host_env_by_default`); if it ever turns RED the
/// env model has drifted.
#[test]
fn seatbelt_clears_host_env_when_process_env_empty() {
    if !has_platform_exec() {
        return;
    }
    let marker = "CHAR_SEATBELT_ENV_CLEAR_4b7c2";
    let result = run_platform_config_value(
        "seatbelt env clear",
        &config("env-clear", "printf 'MARKER=[%s]\\n' \"$MXC_CHAR_MARKER\""),
        &[("MXC_CHAR_MARKER", marker)],
        None,
    );
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    let out = result.combined_output();
    assert!(
        out.contains("MARKER=[]"),
        "expected a cleared env (MARKER=[]); the child must not inherit the \
         launcher's environment when process.env is empty. Output:\n{out}"
    );
    assert!(
        !out.contains(marker),
        "host env marker leaked into the sandbox. Output:\n{out}"
    );
}

/// Locks in that an explicitly requested `process.env` is honored (and, by
/// implication, that the env is scrubbed to exactly the request when set).
#[test]
fn seatbelt_applies_requested_env() {
    if !has_platform_exec() {
        return;
    }
    let mut cfg = config("env-set", "printf 'SET=[%s]\\n' \"$MXC_CHAR_SET\"");
    cfg["process"]["env"] = json!(["MXC_CHAR_SET=from_config_e21a"]);
    let result = run_platform_config_value("seatbelt env set", &cfg, &[], None);
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    assert!(
        result.combined_output().contains("SET=[from_config_e21a]"),
        "expected requested env var to reach the child. Output:\n{}",
        result.combined_output()
    );
}

/// CHARACTERIZES CURRENT BEHAVIOR (regression guard).
///
/// With an empty `process.cwd`, the Seatbelt exec path no longer inherits the
/// launcher's working directory (which the deny-by-default profile may forbid,
/// making the child's `getcwd()` fail and leak a "getcwd: Operation not
/// permitted" line). Instead it resolves the cwd to the first readwrite policy
/// path — a directory the profile is guaranteed to allow. `write_dir` is listed
/// first, so the relative-path probe lands there, not in the launcher cwd.
///
/// We observe the cwd by having the child create a file via a relative path
/// (a shell redirection) and checking which directory it lands in — this
/// avoids `pwd`/`realpath`, which the default Seatbelt profile denies for
/// arbitrary temp paths. `launch_dir` is a second writable policy path that is
/// *not* the resolved cwd, so the probe must not land there.
#[test]
fn seatbelt_runs_in_first_readwrite_path_when_process_cwd_empty() {
    if !has_platform_exec() {
        return;
    }
    let write_dir = fs::canonicalize(unique_tempdir("cwd-write")).expect("canonicalize");
    let launch_dir = fs::canonicalize(unique_tempdir("cwd-launch")).expect("canonicalize");
    let probe = "char_cwd_default_probe.txt";
    let mut cfg = config("cwd-default", &format!("echo CHAR_OK > {probe}"));
    cfg["filesystem"] = json!({
        "readwritePaths": [write_dir.to_string_lossy(), launch_dir.to_string_lossy()]
    });
    let result = run_platform_config_value("seatbelt cwd default", &cfg, &[], Some(&launch_dir));
    let in_launch = launch_dir.join(probe).exists();
    let in_write = write_dir.join(probe).exists();
    let _ = fs::remove_dir_all(&launch_dir);
    let _ = fs::remove_dir_all(&write_dir);
    assert_eq!(
        result.code,
        Some(0),
        "run failed:\n{}",
        result.combined_output()
    );
    assert!(
        in_write && !in_launch,
        "expected the probe in the first readwrite policy path {} (resolved cwd \
         with empty process.cwd); in_write={in_write} in_launch={in_launch}\n{}",
        write_dir.display(),
        result.combined_output()
    );
}

/// Locks in that an explicit `process.cwd` is honored.
#[test]
fn seatbelt_honors_explicit_process_cwd() {
    if !has_platform_exec() {
        return;
    }
    let dir = fs::canonicalize(unique_tempdir("cwd-explicit")).expect("canonicalize");
    let probe = "char_cwd_explicit_probe.txt";
    let mut cfg = config("cwd-explicit", &format!("echo CHAR_OK > {probe}"));
    cfg["process"]["cwd"] = json!(dir.to_string_lossy());
    cfg["filesystem"] = json!({ "readwritePaths": [dir.to_string_lossy()] });
    let result = run_platform_config_value("seatbelt cwd explicit", &cfg, &[], None);
    let exists = dir.join(probe).exists();
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(
        result.code,
        Some(0),
        "run failed:\n{}",
        result.combined_output()
    );
    assert!(
        exists,
        "expected the probe file in the explicit process.cwd {}\n{}",
        dir.display(),
        result.combined_output()
    );
}

/// Characterizes that a `process.timeout` shorter than the workload kills the
/// child mid-run: the pre-timeout marker is emitted, the post-timeout marker is
/// not, and the process exits non-zero well before the workload would finish.
#[test]
fn seatbelt_timeout_kills_before_completion() {
    if !has_platform_exec() {
        return;
    }
    let mut cfg = config("timeout", "echo CHAR_BEFORE; /bin/sleep 5; echo CHAR_AFTER");
    cfg["process"]["timeout"] = json!(1500);
    let result = run_platform_config_value("seatbelt timeout", &cfg, &[], None);
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
        result.wall_time_ms < 4500,
        "timeout should fire well before the 5s workload; took {}ms",
        result.wall_time_ms
    );
}
