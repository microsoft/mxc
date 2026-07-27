// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Regression test for the stdin-EOF parent-lifetime watcher that replaced
//! Linux's `PR_SET_PDEATHSIG`.
//!
//! The proxy inherits a piped stdin whose write end the parent holds open;
//! when the parent disconnects (closes that write end) the watcher must read
//! EOF and shut the proxy down. Nothing else in the suite exercises this
//! path — the integration tests tear the proxy down with an explicit
//! `SIGTERM` — so a watcher that never fired would otherwise pass unnoticed.

#![cfg(unix)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Poll `path` until it exists or the deadline passes, failing fast if the
/// proxy exits early.
fn wait_for_ready_file(child: &mut Child, path: &Path, deadline: Instant) {
    while !path.exists() {
        if let Some(status) = child.try_wait().expect("poll proxy status") {
            panic!("proxy exited before writing ready file: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "proxy did not write ready file before deadline"
        );
        sleep(Duration::from_millis(25));
    }
}

/// Poll for the child to exit or the deadline to pass.
fn wait_for_exit(child: &mut Child, deadline: Instant) -> Option<std::process::ExitStatus> {
    loop {
        if let Some(status) = child.try_wait().expect("poll proxy status") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        sleep(Duration::from_millis(25));
    }
}

#[test]
fn exits_when_parent_closes_stdin() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let ready_file = dir.path().join("ready.port");

    // Spawn with a piped stdin we hold open — mirroring the coordinator — so
    // the watcher only observes EOF when we drop the handle below.
    let mut child = Command::new(env!("CARGO_BIN_EXE_unix-test-proxy"))
        .arg("--ready-file")
        .arg(&ready_file)
        .arg("--bind-address")
        .arg("127.0.0.1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn unix-test-proxy");

    wait_for_ready_file(
        &mut child,
        &ready_file,
        Instant::now() + Duration::from_secs(15),
    );

    // Simulate parent disconnect: closing the write end of the child's stdin
    // sends EOF, which must drive the proxy through its `parent_disconnected`
    // shutdown arm.
    drop(child.stdin.take().expect("child stdin handle present"));

    match wait_for_exit(&mut child, Instant::now() + Duration::from_secs(10)) {
        Some(status) => assert!(
            status.success(),
            "proxy exited unsuccessfully after stdin EOF: {status}"
        ),
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("proxy did not exit within 10s of stdin EOF");
        }
    }
}
