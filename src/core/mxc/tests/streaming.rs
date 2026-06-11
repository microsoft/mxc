// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Streaming (handle-based) API tests: live stdio, kill, and wait-capture.
//! Seatbelt-specific cases run only on macOS.

use mxc::{spawn_sandbox, MxcErrorCode, SpawnOptions};

const SEATBELT_PREFIX: &str = r#"{
    "version": "0.7.0-alpha",
    "containment": "seatbelt",
    "filesystem": { "readwritePaths": ["/tmp"] },
    "seatbelt": { "mode": "exec" },
    "process": "#;

/// Build a seatbelt streaming config with the given commandLine and no timeout
/// (timeout 0 == run until exit; required for interactive/long-running cases).
#[cfg(target_os = "macos")]
fn seatbelt_config(command_line: &str) -> String {
    let escaped = command_line.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "{SEATBELT_PREFIX}{{ \"commandLine\": \"{escaped}\", \"timeout\": 0 }} }}",
        escaped = escaped
    )
}

#[test]
fn streaming_unsupported_backend_is_rejected() {
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "windows_sandbox",
        "process": { "commandLine": "echo hi" }
    }"#;
    let err = match spawn_sandbox(config, &SpawnOptions::default()) {
        Ok(_) => panic!("windows_sandbox streaming must be unsupported"),
        Err(e) => e,
    };
    assert_eq!(err.code, MxcErrorCode::UnsupportedContainment);
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_wait_captures_untaken_streams() {
    let mut proc = spawn_sandbox(
        &seatbelt_config("echo streamed-out"),
        &SpawnOptions::default(),
    )
    .expect("spawn should succeed");
    // Take nothing -> wait() drains and captures, like a run-to-completion.
    let result = proc.wait();
    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_out.contains("streamed-out"),
        "got: {:?}",
        result.standard_out
    );
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_bidirectional_stdio() {
    use std::io::{Read, Write};

    // `cat` echoes stdin to stdout until EOF, then exits.
    let mut proc = spawn_sandbox(&seatbelt_config("cat"), &SpawnOptions::default()).expect("spawn");

    let mut stdin = proc.take_stdin().expect("stdin available");
    let mut stdout = proc.take_stdout().expect("stdout available");

    stdin.write_all(b"ping-pong\n").expect("write stdin");
    drop(stdin); // close -> cat sees EOF and exits

    let mut out = String::new();
    stdout.read_to_string(&mut out).expect("read stdout");
    assert!(out.contains("ping-pong"), "got: {:?}", out);

    let result = proc.wait();
    assert_eq!(result.exit_code, 0);
    // stdout was taken by the caller, so wait() reports it empty.
    assert!(result.standard_out.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_kill_terminates_process() {
    let mut proc =
        spawn_sandbox(&seatbelt_config("sleep 30"), &SpawnOptions::default()).expect("spawn");

    // Still running shortly after spawn.
    assert!(proc.try_wait().expect("try_wait").is_none());

    proc.kill().expect("kill should succeed");

    // After kill, the process must be reapable and not report success.
    let result = proc.wait();
    assert_ne!(result.exit_code, 0, "killed process should not exit 0");
}
