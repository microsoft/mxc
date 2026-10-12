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
//! NOTE: each spawned daemon uses an isolated, throwaway record root (via
//! `MXC_WSLC_STATE_ROOT`) so it never touches a developer's real per-user
//! daemon. The override is process-wide, so running the ignored test alongside
//! the default one still requires `--test-threads=1` so the two harnesses do
//! not clobber each other's `MXC_WSLC_STATE_ROOT`.

#![cfg(all(windows, feature = "wslc"))]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mxc_sdk::wslc_common::container_steps::OutStream;
use mxc_sdk::wslc_common::daemon_client::{DaemonClient, DaemonError};
use mxc_sdk::wslc_common::daemon_protocol::{ErrKind, ExecConfig, ExecTerminal};
use mxc_sdk::wslc_common::daemon_record::{read_daemon_record, STATE_ROOT_ENV_VAR};
use mxc_sdk::wslc_common::process_env::EnvScope;

/// Owns a spawned daemon process and guarantees teardown (kill + isolated
/// record cleanup) even if a test assertion panics.
struct DaemonProcess {
    child: Child,
    // Drops after `child` (declaration order), removing the isolated record
    // tree only once the daemon that writes into it has been killed.
    _root: tempfile::TempDir,
}

impl DaemonProcess {
    /// Spawn the daemon binary and wait until it publishes a `ready` record that
    /// names this process, so a subsequent [`DaemonClient::connect`] fast-paths.
    fn spawn_ready() -> Self {
        // Isolate discovery from the developer's real per-user daemon: point the
        // record root at a throwaway dir, set both in-process (for the in-proc
        // `read_daemon_record` / `DaemonClient` below) and on the spawned daemon.
        let root = tempfile::tempdir().expect("create temp state root");
        std::env::set_var(STATE_ROOT_ENV_VAR, root.path());

        let exe = env!("CARGO_BIN_EXE_wxc-wslc-daemon");
        let child = Command::new(exe)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .env(STATE_ROOT_ENV_VAR, root.path())
            .spawn()
            .expect("spawn wxc-wslc-daemon");
        let this = Self { child, _root: root };

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
        // `_root` (a TempDir) removes the isolated record tree on drop; clear the
        // override so a later test in this binary falls back to the default root.
        std::env::remove_var(STATE_ROOT_ENV_VAR);
    }
}

/// Provision and start a sandbox over the pipe, returning its id.
fn provisioned_and_started(client: &DaemonClient) -> String {
    use mxc_sdk::wslc_common::daemon_protocol::{ProvisionConfig, StartConfig};

    let sandbox_id = client
        .provision(ProvisionConfig {
            image: "alpine:latest".to_string(),
            image_tar_path: None,
            volumes: Vec::new(),
            network: Default::default(),
            port_mappings: Vec::new(),
        })
        .expect("provision");
    client
        .start(StartConfig {
            sandbox_id: sandbox_id.clone(),
        })
        .expect("start");
    sandbox_id
}

/// A run that prints a marker, then an epoch second either side of a sleep.
fn stamped_exec(exec_id: &str, sandbox_id: &str, seconds: u32) -> ExecConfig {
    ExecConfig {
        exec_id: exec_id.to_string(),
        run_token: format!("{exec_id}-run"),
        sandbox_id: sandbox_id.to_string(),
        script_code: format!("echo marker-{exec_id}; date +%s; sleep {seconds}; date +%s"),
        working_directory: String::new(),
        env: Vec::new(),
        env_scope: EnvScope::Merge,
        timeout_ms: 60_000,
    }
}

/// The epoch seconds a stamped run reported either side of its sleep.
fn stamped_interval(stdout: &str) -> (i64, i64) {
    let stamps: Vec<i64> = stdout
        .lines()
        .filter_map(|line| line.trim().parse::<i64>().ok())
        .collect();
    assert!(
        stamps.len() >= 2,
        "a stamped run must report a start and an end, got {stdout:?}"
    );
    (stamps[0], stamps[stamps.len() - 1])
}

fn deprovision_all(client: &DaemonClient, sandbox_ids: Vec<String>) {
    use mxc_sdk::wslc_common::daemon_protocol::DeprovisionConfig;

    for sandbox_id in sandbox_ids {
        let _ = client.deprovision(DeprovisionConfig { sandbox_id });
    }
}

/// Two clients running against their own sandboxes share the daemon: both are
/// admitted, each sees only its own output, and the runs overlap in the guest.
#[test]
#[ignore = "requires a WSL2 host with alpine:latest already in the daemon session cache"]
fn two_clients_exec_concurrently_over_the_pipe() {
    let _daemon = DaemonProcess::spawn_ready();
    let client = DaemonClient::connect().expect("connect to daemon");

    let sandboxes = vec![
        provisioned_and_started(&client),
        provisioned_and_started(&client),
    ];

    let runs: Vec<_> = ["alpha", "beta"]
        .iter()
        .zip(sandboxes.iter())
        .map(|(tag, sandbox_id)| {
            let client = client.clone();
            let config = stamped_exec(tag, sandbox_id, 6);
            std::thread::spawn(move || {
                let mut stdout = Vec::new();
                let completion = client
                    .exec_streaming(config, |stream, data| {
                        if stream == OutStream::Stdout {
                            stdout.extend_from_slice(data);
                        }
                    })
                    .expect("both clients must be admitted");
                (completion, String::from_utf8_lossy(&stdout).into_owned())
            })
        })
        .collect();

    let results: Vec<_> = runs
        .into_iter()
        .map(|handle| handle.join().expect("run thread"))
        .collect();

    for ((completion, stdout), tag) in results.iter().zip(["alpha", "beta"]) {
        assert_eq!(completion.outcome, ExecTerminal::Exited(0));
        assert!(!completion.truncated, "{tag} reported dropped output");
        assert!(
            stdout.contains(&format!("marker-{tag}")),
            "{tag} did not receive its own output: {stdout:?}"
        );
    }
    assert!(
        !results[0].1.contains("marker-beta") && !results[1].1.contains("marker-alpha"),
        "each client must receive only its own stream"
    );

    // Both sandboxes share one utility VM, so their clocks agree.
    let (alpha_start, alpha_end) = stamped_interval(&results[0].1);
    let (beta_start, beta_end) = stamped_interval(&results[1].1);
    let overlap = alpha_end.min(beta_end) - alpha_start.max(beta_start);
    assert!(
        overlap >= 2,
        "the two 6s runs overlapped by {overlap}s, so they were serialized"
    );

    deprovision_all(&client, sandboxes);
}

/// The daemon's exec capacity is finite, so enough simultaneous clients are
/// refused before admission.
#[test]
#[ignore = "requires a WSL2 host with alpine:latest already in the daemon session cache"]
fn the_global_exec_cap_refuses_the_excess() {
    // The control server's own cap, which a client can observe only as the
    // number of simultaneous runs the daemon admits.
    const EXEC_CAP: usize = 8;
    const CLIENTS: usize = EXEC_CAP + 2;

    let _daemon = DaemonProcess::spawn_ready();
    let client = DaemonClient::connect().expect("connect to daemon");

    let sandboxes: Vec<String> = (0..CLIENTS)
        .map(|_| provisioned_and_started(&client))
        .collect();

    // Long enough that every client has had its admission answered before the
    // first run frees a slot.
    let runs: Vec<_> = sandboxes
        .iter()
        .enumerate()
        .map(|(n, sandbox_id)| {
            let client = client.clone();
            let config = stamped_exec(&format!("capacity-{n}"), sandbox_id, 6);
            std::thread::spawn(move || client.exec_streaming(config, |_, _| {}))
        })
        .collect();

    let results: Vec<_> = runs
        .into_iter()
        .map(|handle| handle.join().expect("run thread"))
        .collect();

    let admitted = results.iter().filter(|result| result.is_ok()).count();
    let refused = results
        .iter()
        .filter(|result| {
            matches!(
                result,
                Err(DaemonError::Daemon {
                    kind: ErrKind::Busy,
                    ..
                })
            )
        })
        .count();

    assert_eq!(
        admitted, EXEC_CAP,
        "the daemon must admit exactly its cap, got {admitted} of {CLIENTS}"
    );
    assert_eq!(
        refused,
        CLIENTS - EXEC_CAP,
        "every client past the cap must be refused as busy, got {refused} of {CLIENTS}"
    );

    deprovision_all(&client, sandboxes);
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
/// -> deprovision. Provisions with the default isolated posture, which refuses
/// a registry pull, so `alpine:latest` has to be in the daemon session cache
/// already (`%TEMP%\mxc-wslc-sessions`). Run explicitly with
/// `cargo test -p mxc-sdk --features wslc --test wslc_daemon_ipc -- --ignored`.
#[test]
#[ignore = "requires a WSL2 host with alpine:latest already in the daemon session cache"]
fn full_lifecycle_over_pipe() {
    use mxc_sdk::wslc_common::daemon_protocol::{
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
            port_mappings: Vec::new(),
        })
        .expect("provision");

    client
        .start(StartConfig {
            sandbox_id: sandbox_id.clone(),
        })
        .expect("start");

    let result = client
        .exec(ExecConfig {
            exec_id: "ipc-first".to_string(),
            run_token: "ipc-first-run".to_string(),
            sandbox_id: sandbox_id.clone(),
            script_code: "echo hi".to_string(),
            working_directory: String::new(),
            env: Vec::new(),
            env_scope: EnvScope::Merge,
            timeout_ms: 30_000,
        })
        .expect("first exec");
    assert_eq!(result.exit_code, 0, "echo hi should exit 0");

    // A second exec against the same started container proves the keepalive init
    // keeps it warm for repeated `WslcCreateContainerProcess` calls.
    let result = client
        .exec(ExecConfig {
            exec_id: "ipc-second".to_string(),
            run_token: "ipc-second-run".to_string(),
            sandbox_id: sandbox_id.clone(),
            script_code: "exit 7".to_string(),
            working_directory: String::new(),
            env: Vec::new(),
            env_scope: EnvScope::Merge,
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
