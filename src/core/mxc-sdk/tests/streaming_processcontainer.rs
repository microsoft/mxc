// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows ProcessContainer streaming integration test, in its own
//! Windows-gated file. The sibling `streaming.rs` is `#![cfg(macos)]`, which
//! would otherwise make a `#[cfg(windows)]` test there impossible to compile.
//! Requires an elevated, host-prepped Windows host (see docs/host-prep.md), so
//! it is `#[ignore]`d.

#![cfg(target_os = "windows")]

use mxc_sdk::v1::{build_request, spawn_sandbox, spawn_with_pty, SandboxPolicy};
use mxc_sdk::{MxcPtySize, WaitOutcome};

#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn streaming_processcontainer_bidirectional_stdio() {
    use std::io::{Read, Write};

    let mut policy = SandboxPolicy::default();
    policy.filesystem = Some(mxc_sdk::v1::policy::FilesystemSection {
        readwrite_paths: vec!["C:\\Windows\\Temp".to_string()],
        readonly_paths: vec![],
        denied_paths: vec![],
        clear_policy_on_exit: None,
    });
    // `cmd /c more` echoes stdin to stdout until EOF, then exits.
    let request = build_request(&policy, "cmd /c more", None).expect("build_request");
    let mut proc = spawn_sandbox(request).expect("spawn");

    let mut stdin = proc.take_stdin().expect("stdin available");
    let mut stdout = proc.take_stdout().expect("stdout available");

    stdin.write_all(b"ping-pong\r\n").expect("write stdin");
    drop(stdin);

    let mut out = String::new();
    stdout.read_to_string(&mut out).expect("read stdout");
    assert!(out.contains("ping-pong"), "got: {:?}", out);

    assert_eq!(proc.wait().expect("wait"), WaitOutcome::Exited(0));
}

#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn processcontainer_pty_supports_io_resize_and_wait() {
    use std::io::{Read, Write};

    let request =
        build_request(&SandboxPolicy::default(), "cmd.exe /d /q", None).expect("build_request");
    let terminal = spawn_with_pty(request, MxcPtySize::default()).expect("spawn_with_pty");
    let resized = MxcPtySize {
        rows: 40,
        cols: 120,
        ..MxcPtySize::default()
    };
    terminal.resize(resized).expect("resize");
    assert_eq!(terminal.size().expect("size"), resized);

    let mut reader = terminal.try_clone_reader().expect("reader");
    let reader_thread = std::thread::spawn(move || {
        let mut output = String::new();
        reader.read_to_string(&mut output).expect("read output");
        output
    });
    let mut writer = terminal.take_writer().expect("writer");
    writer
        .write_all(b"echo MXC_PROCESSCONTAINER_PTY_OK\r\nexit\r\n")
        .expect("write input");
    drop(writer);

    assert_eq!(terminal.wait().expect("wait"), WaitOutcome::Exited(0));
    let output = reader_thread.join().expect("reader thread");
    assert!(
        output.contains("MXC_PROCESSCONTAINER_PTY_OK"),
        "got: {output:?}"
    );
}

#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn processcontainer_pty_enforces_script_timeout() {
    let mut policy = SandboxPolicy::default();
    policy.timeout_ms = Some(250);
    let request =
        build_request(&policy, "cmd.exe /d /q /c ping -t 127.0.0.1", None).expect("build_request");
    let terminal = spawn_with_pty(request, MxcPtySize::default()).expect("spawn_with_pty");

    assert_eq!(terminal.wait().expect("wait"), WaitOutcome::TimedOut);
}
