// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native captureDenials "approve → restart → access" end-to-end test.
//!
//! This is the Rust port of `sdk/tests/functional/captureDenials-approval-
//! restart-e2e.mjs`. Since the SDK ships no learning-mode wrapper, a consumer
//! drives `wxc-exec` directly and owns the deny → consent → re-spawn loop. This
//! test plays that consumer using the `denial_consumer` helper module, so it
//! exercises the real native wire format with no SDK dependency.
//!
//! It covers the four paths the native captureDenials surface exposes:
//!   * Phase 1 (pipe mode)  — default-deny run, parse the 0x1E-framed NDJSON
//!     denial stream off **stderr**; assert per-denial records + the summary
//!     terminator's consolidated `deniedResources` list.
//!   * Phase 2 (approve+restart) — fold captured denials into an expanded
//!     readonly policy and re-spawn; assert the read now succeeds.
//!   * Phase 3 (side channel) — run with `--denials-fd` pointing at an
//!     inherited anonymous-pipe write handle; assert denials arrive on the
//!     **pipe handle** and stderr stays free of 0x1E sentinels. This is the
//!     redirect a PTY consumer relies on to keep the terminal clean (the
//!     native `open_writer` honours the handle regardless of mode).
//!   * Phase 4 (round loop) — drive a generic capture → approve → retry loop to
//!     convergence, exercising the multi-round cadence a real consumer owns.
//!
//! Prerequisites (why this is `#[ignore]`): a `processcontainer` host with the
//! BFS velocity key, plus the `MxcLearningModeShim` service installed (into
//! Program Files) **and running**. The test skips gracefully when `wxc-exec`
//! is absent or when capture never attaches (shim not running).

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use wxc_e2e_tests::denial_consumer::{
    expand_readonly_paths, matches_subtree, parse_denial_stream, DenialAnonPipe, DeniedResource,
    ParseResult,
};
use wxc_e2e_tests::find_binary;

const TARGET_DIR: &str = r"C:\Users\Public";

/// Build a captureDenials config for `cmd /c type "<target>"` with the given
/// readonly grants. Mirrors the validated `processcontainer` capture config.
fn build_config(container_id: &str, target: &str, readonly: &[String]) -> serde_json::Value {
    serde_json::json!({
        "version": "0.7.0-alpha",
        "containerId": container_id,
        "containment": "processcontainer",
        "captureDenials": true,
        "process": {
            "commandLine": format!("cmd /c type \"{target}\""),
            "timeout": 15000
        },
        "filesystem": { "readonlyPaths": readonly },
        "ui": { "disable": false }
    })
}

/// Write a config to a unique temp file and return its path.
fn write_temp_config(config: &serde_json::Value) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "mxc-e2e-capture-{}.json",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::write(&path, serde_json::to_vec_pretty(config).unwrap()).expect("write temp config");
    path
}

struct PipeAttempt {
    exit_code: Option<i32>,
    stdout: String,
    parsed: ParseResult,
}

/// Run `wxc-exec <config>` in pipe mode (stdio captured) and parse the denial
/// stream off stderr.
fn run_pipe_attempt(
    exe: &Path,
    container_id: &str,
    target: &str,
    readonly: &[String],
) -> PipeAttempt {
    let config = build_config(container_id, target, readonly);
    let config_path = write_temp_config(&config);

    let output = Command::new(exe)
        .arg(&config_path)
        .output()
        .expect("spawn wxc-exec");

    let _ = std::fs::remove_file(&config_path);

    PipeAttempt {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        parsed: parse_denial_stream(&output.stderr, true),
    }
}

/// Denials relevant to the self-created target (the file itself, its parent
/// dir, or anything under it).
fn target_denials(parsed: &ParseResult, target: &str) -> Vec<DeniedResource> {
    parsed
        .denials
        .iter()
        .filter(|d| matches_subtree(&d.path, target, TARGET_DIR))
        .cloned()
        .collect()
}

#[test]
#[ignore] // Requires velocity key 61714527 + MxcLearningModeShim running (run on the capture host)
fn test_capture_denials_approval_restart() {
    let Some(exe) = find_binary("wxc-exec.exe") else {
        println!("SKIPPED: wxc-exec.exe not found — build first");
        return;
    };

    // Self-create the target under C:\Users\Public so its parent dir is what
    // gets denied, approved, and re-granted.
    let sentinel = format!("mxc-approval-restart-{}", uuid::Uuid::new_v4().simple());
    let target = format!(
        r"{TARGET_DIR}\mxc-approval-restart-{}.txt",
        uuid::Uuid::new_v4().simple()
    );
    std::fs::write(&target, format!("{sentinel}\r\n")).expect("create target file");

    // Ensure cleanup even on assertion failure.
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(target.clone());

    println!("target: {target}");

    // ---- Phase 1: default-deny, capture the denial (pipe mode) ------------
    println!("--- PHASE 1: pipe mode, default-deny (expect denial) ---");
    let phase1 = run_pipe_attempt(&exe, "captureDenials-e2e-p1", &target, &[]);

    // Graceful skip when capture never attached (shim not installed/running).
    let active = phase1
        .parsed
        .summary
        .as_ref()
        .map(|s| s.capture_denials_active)
        .unwrap_or(false);
    if !active {
        println!(
            "SKIPPED: captureDenials inactive (is MxcLearningModeShim installed and running?) — \
             summary present: {}",
            phase1.parsed.summary.is_some()
        );
        return;
    }

    let p1_target = target_denials(&phase1.parsed, &target);
    assert!(
        !p1_target.is_empty(),
        "phase1: expected a denial under {TARGET_DIR}; captured none (total {})",
        phase1.parsed.denials.len()
    );
    assert_ne!(
        phase1.exit_code,
        Some(0),
        "phase1: expected non-zero exit (read denied)"
    );
    assert!(
        !phase1.stdout.contains(&sentinel),
        "phase1: target contents leaked to stdout despite being denied"
    );
    // Both delivery channels must be populated: live per-denial records AND the
    // consolidated summary list.
    assert!(
        !phase1.parsed.denials.is_empty(),
        "phase1: no live per-denial records parsed off stderr"
    );
    let summary = phase1.parsed.summary.as_ref().unwrap();
    assert!(
        !summary.denied_resources.is_empty(),
        "phase1: summary terminator did not carry a non-empty deniedResources list"
    );
    assert_eq!(
        phase1.parsed.parse_errors, 0,
        "phase1: unexpected parse errors"
    );

    // ---- User approval: expand the policy ---------------------------------
    println!("--- USER APPROVAL: expand policy with approved target denials ---");
    let approved = p1_target.clone();
    let expand = expand_readonly_paths(&[], &[], &approved);
    println!("[approval] added: {:?}", expand.added);
    assert!(
        !expand.added.is_empty(),
        "approval: expand step added no grants"
    );
    let granted_target_dir = expand
        .readonly_paths
        .iter()
        .any(|p| matches_subtree(p, &target, TARGET_DIR));
    assert!(
        granted_target_dir,
        "approval: expanded policy does not grant the target dir ({TARGET_DIR})"
    );

    // ---- Phase 2: restart with expanded policy (expect access) ------------
    println!("--- PHASE 2: pipe mode, restart with approved policy (expect access) ---");
    let phase2 = run_pipe_attempt(
        &exe,
        "captureDenials-e2e-p2",
        &target,
        &expand.readonly_paths,
    );
    assert_eq!(
        phase2.exit_code,
        Some(0),
        "phase2: expected exit 0 after approval"
    );
    assert!(
        phase2.stdout.contains(&sentinel),
        "phase2: expected the approved file contents on stdout; sentinel not found"
    );
    assert!(
        target_denials(&phase2.parsed, &target).is_empty(),
        "phase2: target subtree denied again after approval"
    );
    assert_eq!(
        phase2.parsed.parse_errors, 0,
        "phase2: unexpected parse errors"
    );

    // ---- Phase 3: side-channel pipe (--denials-fd) -----------------------
    println!("--- PHASE 3: denials routed to the --denials-fd side channel ---");
    run_phase3_pipe_side_channel(&exe, &target);

    // ---- Phase 4: capture → approve → retry loop to convergence -----------
    println!("--- PHASE 4: round loop (capture -> approve -> retry until access) ---");
    const MAX_ROUNDS: usize = 3;
    let mut readonly: Vec<String> = Vec::new();
    let mut rounds = 0usize;
    let last = loop {
        let attempt = run_pipe_attempt(&exe, "captureDenials-e2e-loop", &target, &readonly);
        let exit = attempt.exit_code;
        let approve = target_denials(&attempt.parsed, &target);
        println!(
            "[round{rounds}] exit={exit:?} denials={}",
            attempt.parsed.denials.len()
        );
        if exit == Some(0) || approve.is_empty() {
            break attempt;
        }
        let expanded = expand_readonly_paths(&readonly, &[], &approve);
        if expanded.added.is_empty() {
            break attempt;
        }
        readonly = expanded.readonly_paths;
        rounds += 1;
        if rounds > MAX_ROUNDS {
            break attempt;
        }
    };
    assert_eq!(
        last.exit_code,
        Some(0),
        "phase4: loop did not converge to success (rounds {rounds})"
    );
    assert!(
        rounds >= 1,
        "phase4: loop succeeded on the first attempt — no approve->retry round exercised"
    );
    assert!(
        last.stdout.contains(&sentinel),
        "phase4: expected the approved file contents on stdout after convergence"
    );

    println!("[functional-test] PASS");
}

/// Phase 3: run the workload with `--denials-fd` pointing at an inherited
/// anonymous-pipe write handle so denials are routed to that private handle
/// instead of stderr. Asserts denials land on the pipe and the workload's
/// stderr stays free of 0x1E sentinels.
///
/// This exercises the same native redirect path as PTY/console mode
/// (`open_writer` honours `--denials-fd` regardless of console mode) — the
/// inherited handle is the side channel a real PTY consumer uses to keep the
/// terminal clean. Driving it with piped stdio keeps the test deterministic
/// (no ConPTY teardown handshake) while still proving the redirect contract.
fn run_phase3_pipe_side_channel(exe: &Path, target: &str) {
    let config = build_config("captureDenials-e2e-p3", target, &[]);
    let config_path = write_temp_config(&config);

    let mut pipe = DenialAnonPipe::start().expect("start denial anon pipe");

    // The inheritable write handle is inherited because std spawns the child
    // with bInheritHandles=TRUE (piped stdio) and applies no handle-list
    // filter, so the value is valid in the child.
    let child = Command::new(exe)
        .arg(&config_path)
        .arg("--denials-fd")
        .arg(pipe.write_fd().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wxc-exec");

    // Drop our copy of the write end now that the child holds it, so the
    // reader observes EOF once the child closes its end / exits.
    pipe.close_write();

    let output = child.wait_with_output().expect("wait wxc-exec");
    let pipe_bytes = pipe.join_timeout(Duration::from_secs(20));
    let _ = std::fs::remove_file(&config_path);

    let parsed = parse_denial_stream(&pipe_bytes, true);
    let pipe_target = parsed
        .denials
        .iter()
        .filter(|d| matches_subtree(&d.path, target, TARGET_DIR))
        .count();

    println!(
        "[phase3] exit={:?} pipe denials={} parse errors={}",
        output.status.code(),
        parsed.denials.len(),
        parsed.parse_errors
    );

    assert!(
        pipe_target > 0,
        "phase3: expected a target-dir denial delivered on the anonymous pipe; got none"
    );
    // The 0x1E Record Separator must NOT have leaked onto stderr (it was
    // redirected to the inherited-handle side channel).
    assert!(
        !output.stderr.contains(&0x1E),
        "phase3: 0x1E denial sentinel leaked onto stderr (side channel not used)"
    );
    assert_eq!(
        parsed.parse_errors, 0,
        "phase3: expected 0 parse errors on the pipe"
    );
}
