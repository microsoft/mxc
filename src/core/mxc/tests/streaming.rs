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

#[cfg(target_os = "macos")]
fn pid_alive(pid: u32) -> bool {
    std::process::Command::new("ps")
        .arg("-p")
        .arg(pid.to_string())
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_kill_terminates_process_tree() {
    use std::io::{BufRead, BufReader};

    // The sandboxed shell backgrounds a `sleep` (a descendant), prints its
    // pid, then blocks. `kill()` must take the whole process group down,
    // including that descendant.
    let mut proc = spawn_sandbox(
        &seatbelt_config("sleep 300 & echo CHILD=$!; sleep 300"),
        &SpawnOptions::default(),
    )
    .expect("spawn");

    assert!(proc.id() > 0, "id() should expose the child pid");

    let stdout = proc.take_stdout().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read descendant pid");
    let descendant: u32 = line
        .trim()
        .strip_prefix("CHILD=")
        .expect("CHILD= prefix")
        .parse()
        .expect("descendant pid");

    assert!(
        pid_alive(descendant),
        "descendant {descendant} should be running before kill"
    );

    proc.kill().expect("kill");
    let _ = proc.wait();

    let mut gone = false;
    for _ in 0..60 {
        if !pid_alive(descendant) {
            gone = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        gone,
        "descendant {descendant} should be killed with the process tree"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_timeout_kills_process_tree() {
    use std::io::{BufRead, BufReader};

    // 1s timeout; the shell backgrounds a long sleep (descendant), prints its
    // pid, then blocks past the timeout. wait()'s timeout branch must group-
    // kill, taking the descendant down too.
    let config = format!(
        "{SEATBELT_PREFIX}{{ \"commandLine\": \"sleep 300 & echo CHILD=$!; sleep 300\", \"timeout\": 1000 }} }}"
    );
    let mut proc = spawn_sandbox(&config, &SpawnOptions::default()).expect("spawn");

    let stdout = proc.take_stdout().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read descendant pid");
    let descendant: u32 = line
        .trim()
        .strip_prefix("CHILD=")
        .expect("CHILD= prefix")
        .parse()
        .expect("descendant pid");

    let result = proc.wait();
    assert_ne!(result.exit_code, 0, "timed-out process should not exit 0");

    let mut gone = false;
    for _ in 0..60 {
        if !pid_alive(descendant) {
            gone = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(gone, "descendant {descendant} should be killed on timeout");
}
