// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end IPC tests that drive the real `wxc-wslc-daemon` binary through the
//! [`DaemonClient`] over a live named pipe.
//!
//! [`ping_round_trip_over_pipe`] needs no WSL: `Ping` is served entirely by the
//! control server without touching the WSLc SDK, so it exercises spawn/discovery,
//! the ready-record rendezvous, pipe connect, and frame round-tripping on any
//! Windows host. The full lifecycle test is `#[ignore]`d because it boots a WSL2
//! utility VM.
//!
//! NOTE: both tests spawn a daemon that publishes the single global daemon
//! record, so running the ignored test alongside the default test requires
//! `--test-threads=1` to avoid the two daemons clobbering each other's record.

#![cfg(windows)]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use wslc_common::daemon_client::DaemonClient;
use wslc_common::daemon_record::{read_daemon_record, remove_daemon_record};

/// Owns a spawned daemon process and guarantees teardown (kill + record cleanup)
/// even if a test assertion panics.
struct DaemonProcess {
    child: Child,
}

impl DaemonProcess {
    /// Spawn the daemon binary and wait until it publishes a `ready` record that
    /// names this process, so a subsequent [`DaemonClient::connect`] fast-paths.
    fn spawn_ready() -> Self {
        let exe = env!("CARGO_BIN_EXE_wxc-wslc-daemon");
        let child = Command::new(exe)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn wxc-wslc-daemon");
        let this = Self { child };

        let pid = this.child.id();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(Some(record)) = read_daemon_record() {
                if record.pid == pid && record.ready {
                    return this;
                }
            }
            assert!(
                Instant::now() < deadline,
                "daemon (pid {pid}) did not publish a ready record in time"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The daemon was killed before it could clean up; drop the stale record
        // so it does not confuse a later run.
        let _ = remove_daemon_record();
    }
}

#[test]
fn ping_round_trip_over_pipe() {
    let _daemon = DaemonProcess::spawn_ready();

    let client = DaemonClient::connect().expect("connect to daemon");
    client.ping().expect("ping should return Pong");

    // A second connection proves the server re-armed the next pipe instance.
    client.ping().expect("second ping should also succeed");
}

/// Full state-aware lifecycle over the pipe: provision -> start -> exec -> stop
/// -> deprovision. Requires a WSL2 host with `alpine:latest` pre-pulled into the
/// daemon session cache (`%TEMP%\mxc-wslc-sessions`, e.g. via
/// `scripts\setup-wslc.ps1 -Image alpine:latest`). Run explicitly with
/// `cargo test -p wxc_wslc_daemon --test daemon_ipc -- --ignored`.
#[test]
#[ignore = "requires a WSL2 host with alpine:latest pre-pulled into the daemon session cache"]
fn full_lifecycle_over_pipe() {
    use wslc_common::daemon_protocol::{
        DeprovisionConfig, ExecConfig, ProvisionConfig, StartConfig, StopConfig,
    };

    let _daemon = DaemonProcess::spawn_ready();
    let client = DaemonClient::connect().expect("connect to daemon");

    let sandbox_id = client
        .provision(ProvisionConfig {
            image: "alpine:latest".to_string(),
            image_tar_path: None,
            volumes: Vec::new(),
            network: Default::default(),
        })
        .expect("provision");

    client
        .start(StartConfig {
            sandbox_id: sandbox_id.clone(),
        })
        .expect("start");

    let result = client
        .exec(ExecConfig {
            sandbox_id: sandbox_id.clone(),
            script_code: "echo hi".to_string(),
            working_directory: String::new(),
            env: Vec::new(),
            timeout_ms: 30_000,
        })
        .expect("first exec");
    assert_eq!(result.exit_code, 0, "echo hi should exit 0");

    // A second exec against the same started container proves the keepalive init
    // keeps it warm for repeated `WslcCreateContainerProcess` calls.
    let result = client
        .exec(ExecConfig {
            sandbox_id: sandbox_id.clone(),
            script_code: "exit 7".to_string(),
            working_directory: String::new(),
            env: Vec::new(),
            timeout_ms: 30_000,
        })
        .expect("second exec");
    assert_eq!(result.exit_code, 7, "exit 7 should propagate its exit code");

    client
        .stop(StopConfig {
            sandbox_id: sandbox_id.clone(),
        })
        .expect("stop");

    client
        .deprovision(DeprovisionConfig { sandbox_id })
        .expect("deprovision");
}
