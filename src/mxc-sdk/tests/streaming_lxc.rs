// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! LXC streaming API tests: live stdio, exit-status fidelity, container-scoped
//! kill, timeout, and teardown after every terminal path.
//!
//! Linux-gated file, and a live one: every case creates, starts, and destroys a
//! real container, so it needs LXC installed and root. `lxc-exec` cannot stand
//! in for any of it — that binary runs through `mxc_engine::run`, which never
//! reaches `spawn`.
//!
//! Tests skip when LXC is missing or the runner is unprivileged, unless
//! `MXC_LXC_TESTS_REQUIRE_EXECUTION` turns a skip into a failure.

#![cfg(target_os = "linux")]

mod unix_pty_contract;

use std::io::{BufRead, BufReader, Read, Write};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use mxc_sdk::v1::WaitResult;
use mxc_sdk::v1::{spawn, NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy};
use mxc_sdk::v1::{ContainerRequest, Containment, FilesystemPolicy, NetworkPolicy};

/// The bound on a read or wait that should already have finished. Long enough
/// to create a container, start it, and destroy it again on a loaded CI runner.
const LIVE_TIMEOUT_MS: u32 = 180_000;
const LIVE_TIMEOUT: Duration = Duration::from_millis(LIVE_TIMEOUT_MS as u64);

/// Far past [`LIVE_TIMEOUT`], so a workload still holding a pipe or a wait open
/// at that deadline is one the sandbox failed to terminate.
const SLEEP_SECONDS: u64 = 600;

/// One case's containers at a time.
///
/// Every case here creates real root-owned containers on a shared runner, and
/// the networked one needs the bridge to itself. Cases that want two live
/// sandboxes run both inside one guard.
fn exclusive() -> MutexGuard<'static, ()> {
    static LIVE_SANDBOX: Mutex<()> = Mutex::new(());
    LIVE_SANDBOX.lock().unwrap_or_else(|e| e.into_inner())
}

/// Reports a skip, or fails when this lane was provisioned to execute the suite.
fn not_ready(reason: &str) -> bool {
    // A lane provisioned for this suite reports a skip as success, so the gate
    // would go green having tested nothing.
    if std::env::var("MXC_LXC_TESTS_REQUIRE_EXECUTION").is_ok_and(|value| value != "0") {
        panic!("strict mode: {reason}");
    }
    println!("SKIPPED: {reason}");
    false
}

/// Whether this host can run a live LXC sandbox. Reuses the backend's own
/// availability probe so this gate cannot drift from what discovery reports.
fn lxc_ready() -> bool {
    if !mxc_sdk::lxc_common::availability::is_lxc_available() {
        return not_ready("lxc-ls is not installed — this host cannot run a system container");
    }
    // SAFETY: `geteuid` is a thread-safe, side-effect-free libc call.
    if unsafe { libc::geteuid() } != 0 {
        return not_ready("LXC needs root to create, start, and attach to a container");
    }
    true
}

/// A container name unique to this test binary's process, so a leak audit can
/// name exactly the container the case created.
fn container_name(case: &str) -> String {
    format!("mxc-stream-{case}-{}", std::process::id())
}

/// Whether `lxc-ls` still lists `name`. Reads the same `lxcpath` the backend
/// writes to, which differs between a root and an unprivileged caller.
fn container_is_defined(name: &str) -> bool {
    let lxcpath = mxc_sdk::lxc_common::lxc_bindings::resolve_default_lxcpath();
    let output = Command::new("lxc-ls")
        .arg("-P")
        .arg(&lxcpath)
        .arg("-1")
        .output()
        .expect("lxc-ls runs on a host that passed the availability gate");
    // An `lxc-ls` that failed prints nothing, which would otherwise read as
    // "no containers" and pass every leak assertion in this file.
    assert!(
        output.status.success(),
        "lxc-ls -P {lxcpath} exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|listed| listed.trim() == name)
}

/// Fails when the sandbox left its container behind. Every terminal path —
/// `wait`, a timeout, a kill, and a bare drop — owes this.
fn assert_container_released(name: &str) {
    assert!(
        !container_is_defined(name),
        "container {name} is still defined, so the sandbox leaked it"
    );
}

#[test]
fn lxc_pty_supports_io_resize_and_merged_output() {
    if !lxc_ready() {
        return;
    }
    let _guard = exclusive();
    let name = container_name("pty-contract");
    unix_pty_contract::assert_round_trip(lxc_request(
        unix_pty_contract::ROUND_TRIP_COMMAND,
        &name,
        LIVE_TIMEOUT_MS,
    ));
    assert_container_released(&name);
}

#[test]
fn lxc_pty_enforces_script_timeout_and_tears_down() {
    if !lxc_ready() {
        return;
    }
    let _guard = exclusive();
    let name = container_name("pty-timeout");
    unix_pty_contract::assert_timeout(
        lxc_request(unix_pty_contract::TIMEOUT_COMMAND, &name, 2_000),
        LIVE_TIMEOUT,
    );
    assert_container_released(&name);
}

#[test]
fn lxc_pty_preserves_explicit_timeout_kill() {
    if !lxc_ready() {
        return;
    }
    let _guard = exclusive();
    let name = container_name("pty-explicit-timeout");
    unix_pty_contract::assert_explicit_timeout_kill(lxc_request(
        unix_pty_contract::TIMEOUT_COMMAND,
        &name,
        LIVE_TIMEOUT_MS,
    ));
    assert_container_released(&name);
}

#[test]
fn lxc_pty_transfers_native_stdio() {
    if !lxc_ready() {
        return;
    }
    let _guard = exclusive();
    let name = container_name("pty-native-stdio");
    unix_pty_contract::assert_native_stdio(lxc_request(
        unix_pty_contract::NATIVE_STDIO_COMMAND,
        &name,
        LIVE_TIMEOUT_MS,
    ));
    assert_container_released(&name);
}

#[test]
fn lxc_pty_closing_input_sends_canonical_eof() {
    if !lxc_ready() {
        return;
    }
    let _guard = exclusive();
    let name = container_name("pty-eof");
    let terminal = mxc_sdk::v1::spawn_with_pty(
        lxc_request(
            "cat >/dev/null; printf 'eof-observed\\n'",
            &name,
            LIVE_TIMEOUT_MS,
        ),
        Default::default(),
    )
    .expect("spawn_with_pty");
    let mut reader = terminal.try_clone_reader().expect("reader");
    let reader_thread = std::thread::spawn(move || {
        let mut output = String::new();
        reader.read_to_string(&mut output).expect("read output");
        output
    });
    let mut writer = terminal.take_writer().expect("writer");
    writer
        .write_all(b"input before eof\n")
        .expect("write input");
    drop(writer);

    assert_eq!(terminal.wait().expect("wait"), WaitResult::Exited(0));
    let output = reader_thread.join().expect("reader thread");
    assert!(output.contains("eof-observed"), "got: {output:?}");
    assert_container_released(&name);
}

/// Whether `lxc-ls` still lists `name` as started. Mirrors the backend's own
/// `LxcContainer::is_running`, so the test cannot disagree with it about what
/// running means.
fn container_is_running(name: &str) -> bool {
    let lxcpath = mxc_sdk::lxc_common::lxc_bindings::resolve_default_lxcpath();
    let output = Command::new("lxc-info")
        .arg("-P")
        .arg(&lxcpath)
        .arg("-n")
        .arg(name)
        .arg("-s")
        .output()
        .expect("lxc-info runs on a host that passed the availability gate");
    // A container that is gone reports no state at all, which is not running.
    output.status.success() && String::from_utf8_lossy(&output.stdout).contains("RUNNING")
}

/// An LXC streaming request (`/tmp` read-write, no network) with the given
/// command, container name, and timeout (ms; `0` == run until exit).
///
/// Cases that end in `wait()` pass [`LIVE_TIMEOUT_MS`] rather than `0`: with no
/// script timeout the backend waits on `lxc-attach` forever, so a wedged attach
/// would hold this file's mutex until the CI job's own cap. A healthy workload
/// here finishes in well under a second, so the bound only ever fires on a
/// failure, and it fires as a reported timeout with teardown rather than a hang.
fn lxc_request(command: &str, name: &str, timeout_ms: u32) -> mxc_sdk::v1::ContainerRequest {
    lxc_request_with_network(command, name, timeout_ms, isolated_network())
}

/// Permits nothing in either direction, which starts the container with no
/// interface at all and so skips the DHCP wait a networked run pays for.
///
/// Stated in the schema 0.8 directional form on purpose. A legacy policy that
/// names no network defaults to `enforcementMode: 'capabilities'`, which
/// selects Windows AppContainer capability SIDs; LXC has no mechanism for that
/// and refuses the request before it reaches a container.
fn isolated_network() -> NetworkPolicy {
    NetworkPolicy {
        egress: Some(NetworkEgressPolicy {
            default: Some(NetworkAction::Deny),
            ..Default::default()
        }),
        ingress: Some(NetworkIngressPolicy {
            default: Some(NetworkAction::Deny),
            host_loopback: Some(NetworkAction::Deny),
        }),
        ..Default::default()
    }
}

fn lxc_request_with_network(
    command: &str,
    name: &str,
    timeout_ms: u32,
    network: NetworkPolicy,
) -> mxc_sdk::v1::ContainerRequest {
    ContainerRequest {
        filesystem: Some(FilesystemPolicy {
            readwrite_paths: vec!["/tmp".to_string()],
            readonly_paths: vec![],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        network: Some(network),
        containment: Containment::Lxc(mxc_sdk::v1::configs::LxcConfig::default()),
        container_name: Some(name.to_string()),
        timeout_ms: (timeout_ms != 0).then_some(timeout_ms),
        ..ContainerRequest::new(command)
    }
}

/// Reads `stream` to EOF on its own thread, so a stream a killed workload
/// failed to close shows up as this deadline rather than a hung test run.
fn read_to_end_within(
    stream: Box<dyn Read + Send>,
    deadline: Duration,
    what: &str,
) -> std::io::Result<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut stream = stream;
        let mut text = String::new();
        let outcome = stream.read_to_string(&mut text).map(|_| text);
        let _ = tx.send(outcome);
    });
    rx.recv_timeout(deadline)
        .unwrap_or_else(|_| panic!("{what} never reached EOF within {deadline:?}"))
}

/// Blocks until the workload's first line arrives, proving the container is
/// live before the case does anything to it, and hands back the reader so the
/// rest of the stream can be drained.
///
/// Bounded on its own thread: a workload whose output never arrives would
/// otherwise hold this file's mutex until the whole CI job times out.
fn read_first_line_within(
    stream: Box<dyn Read + Send>,
    deadline: Duration,
    expected: &str,
) -> BufReader<Box<dyn Read + Send>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        let outcome = reader.read_line(&mut line).map(|_| (line, reader));
        let _ = tx.send(outcome);
    });
    let (line, reader) = rx
        .recv_timeout(deadline)
        .unwrap_or_else(|_| panic!("no {expected:?} line within {deadline:?}"))
        .expect("read stdout");
    assert!(
        line.contains(expected),
        "expected {expected:?} as the first line, got: {line:?}"
    );
    reader
}

#[test]
fn streaming_lxc_delivers_stdout_before_exit() {
    if !lxc_ready() {
        return;
    }
    let _guard = exclusive();
    let name = container_name("early");

    // Blocking on stdin rather than sleeping: the workload cannot reach its
    // exit until this test lets it, so the "still running" assertion below
    // cannot race a slow runner.
    let mut proc = spawn(
        lxc_request(
            "printf 'FIRST\\n'; IFS= read -r _; printf 'SECOND\\n'",
            &name,
            LIVE_TIMEOUT_MS,
        ),
        Default::default(),
    )
    .expect("spawn");
    let mut stdin = proc.take_stdin().expect("stdin available");
    let stdout = read_first_line_within(
        proc.take_stdout().expect("stdout available"),
        LIVE_TIMEOUT,
        "FIRST",
    );

    assert!(
        proc.try_wait().expect("try_wait").is_none(),
        "the first line arrived only after the workload exited, so it was not streamed"
    );

    stdin.write_all(b"continue\n").expect("write stdin");
    drop(stdin);

    let rest = read_to_end_within(Box::new(stdout), LIVE_TIMEOUT, "stdout").expect("read stdout");
    assert!(rest.contains("SECOND"), "got: {rest:?}");
    assert_eq!(proc.wait().expect("wait"), WaitResult::Exited(0));
    assert_container_released(&name);
}

#[test]
fn streaming_lxc_keeps_stdout_and_stderr_apart() {
    if !lxc_ready() {
        return;
    }
    let _guard = exclusive();
    let name = container_name("streams");

    let mut proc = spawn(
        lxc_request(
            "printf 'TO_STDOUT\\n'; printf 'TO_STDERR\\n' >&2",
            &name,
            LIVE_TIMEOUT_MS,
        ),
        Default::default(),
    )
    .expect("spawn");
    let stdout = proc.take_stdout().expect("stdout available");
    let stderr = proc.take_stderr().expect("stderr available");

    let out = read_to_end_within(stdout, LIVE_TIMEOUT, "stdout").expect("read stdout");
    let err = read_to_end_within(stderr, LIVE_TIMEOUT, "stderr").expect("read stderr");

    assert!(out.contains("TO_STDOUT"), "got: {out:?}");
    assert!(
        !out.contains("TO_STDERR"),
        "stderr leaked into stdout: {out:?}"
    );
    assert!(err.contains("TO_STDERR"), "got: {err:?}");
    assert!(
        !err.contains("TO_STDOUT"),
        "stdout leaked into stderr: {err:?}"
    );

    assert_eq!(proc.wait().expect("wait"), WaitResult::Exited(0));
    assert_container_released(&name);
}

#[test]
fn streaming_lxc_delivers_stdin_and_closing_it_sends_eof() {
    if !lxc_ready() {
        return;
    }
    let _guard = exclusive();
    let name = container_name("stdin");

    // `cat` runs until EOF, so it exits only because the writer was dropped.
    let mut proc = spawn(
        lxc_request("cat", &name, LIVE_TIMEOUT_MS),
        Default::default(),
    )
    .expect("spawn");
    let mut stdin = proc.take_stdin().expect("stdin available");
    let stdout = proc.take_stdout().expect("stdout available");

    stdin.write_all(b"ping-pong\n").expect("write stdin");
    drop(stdin);

    let out = read_to_end_within(stdout, LIVE_TIMEOUT, "stdout").expect("read stdout");
    assert!(out.contains("ping-pong"), "got: {out:?}");

    assert_eq!(proc.wait().expect("wait"), WaitResult::Exited(0));
    assert_container_released(&name);
}

#[test]
fn streaming_lxc_wait_reports_the_workloads_exit_code() {
    if !lxc_ready() {
        return;
    }
    let _guard = exclusive();

    // `lxc-attach` sits between the SDK and the workload: pins that the
    // workload's status propagates, not the attach process's own.
    for code in [0, 1, 42] {
        let name = container_name(&format!("exit{code}"));
        let mut proc = spawn(
            lxc_request(&format!("exit {code}"), &name, LIVE_TIMEOUT_MS),
            Default::default(),
        )
        .expect("spawn");
        assert_eq!(
            proc.wait().expect("wait"),
            WaitResult::Exited(code),
            "workload exited {code}"
        );
        assert_container_released(&name);
    }
}

#[test]
fn streaming_lxc_kill_stops_the_whole_container() {
    if !lxc_ready() {
        return;
    }
    let _guard = exclusive();
    let name = container_name("kill");

    // The backgrounded sleep stands in for a descendant the workload leaves
    // behind: it inherits stdout and outlives the foreground one, which keeps
    // the attach alive so the kill has something to reach.
    let mut proc = spawn(
        lxc_request(
            &format!("sleep {SLEEP_SECONDS} & printf 'READY\\n'; sleep {SLEEP_SECONDS}"),
            &name,
            LIVE_TIMEOUT_MS,
        ),
        Default::default(),
    )
    .expect("spawn");
    let stdout = read_first_line_within(
        proc.take_stdout().expect("stdout available"),
        LIVE_TIMEOUT,
        "READY",
    );

    assert!(
        proc.try_wait().expect("try_wait").is_none(),
        "the workload should still be running when it is killed"
    );
    assert!(
        container_is_running(&name),
        "the container must be running before the kill, or the kill proves nothing"
    );

    proc.kill().expect("kill");

    // A container cannot be stopped while a process of its own is alive, so
    // this is what proves the kill reached the workload and the descendant it
    // backgrounded, rather than stopping at the host `lxc-attach` process. The
    // workload lives in the container's PID namespace, where nothing aimed at
    // that host process or its group can follow it.
    assert!(
        !container_is_running(&name),
        "the container is still running after kill(), so the workload survived it"
    );

    // The descendant held the write end of this pipe, so EOF follows from the
    // same fact and is read before `wait()` can supply it through teardown.
    read_to_end_within(Box::new(stdout), LIVE_TIMEOUT, "stdout after kill").expect("read stdout");

    assert_ne!(
        proc.wait().expect("wait after kill"),
        WaitResult::Exited(0),
        "a killed workload should not report success"
    );
    assert_container_released(&name);
}

#[test]
fn streaming_lxc_timeout_reports_timed_out_and_tears_down() {
    if !lxc_ready() {
        return;
    }
    let _guard = exclusive();
    let name = container_name("timeout");

    let mut proc = spawn(
        lxc_request(
            &format!("printf 'READY\\n'; sleep {SLEEP_SECONDS}"),
            &name,
            2_000,
        ),
        Default::default(),
    )
    .expect("spawn");
    let _stdout = read_first_line_within(
        proc.take_stdout().expect("stdout available"),
        LIVE_TIMEOUT,
        "READY",
    );

    // `wait` starts the deadline clock and ends by destroying the container, so
    // the bound covers teardown too and only has to rule out the 600s sleep.
    let start = Instant::now();
    assert_eq!(
        proc.wait().expect("wait yields an outcome"),
        WaitResult::TimedOut,
        "a workload outliving its timeout should report a timeout"
    );
    assert!(
        start.elapsed() < LIVE_TIMEOUT,
        "the timeout should fire near 2s, not wait out the {SLEEP_SECONDS}s sleep (elapsed: {:?})",
        start.elapsed()
    );
    assert_container_released(&name);
}

#[test]
fn streaming_lxc_dropping_the_handle_tears_down() {
    if !lxc_ready() {
        return;
    }
    let _guard = exclusive();
    let name = container_name("drop");

    {
        let mut proc = spawn(
            lxc_request(
                &format!("printf 'READY\\n'; sleep {SLEEP_SECONDS}"),
                &name,
                LIVE_TIMEOUT_MS,
            ),
            Default::default(),
        )
        .expect("spawn");
        let _stdout = read_first_line_within(
            proc.take_stdout().expect("stdout available"),
            LIVE_TIMEOUT,
            "READY",
        );
        assert!(
            container_is_running(&name),
            "the container should be running while the sandbox is alive"
        );
    }

    // `Drop` kills, reaps, and tears down before it returns, so there is
    // nothing to wait for here.
    assert_container_released(&name);
}

#[test]
fn streaming_lxc_refuses_a_container_a_live_sandbox_holds() {
    if !lxc_ready() {
        return;
    }
    let _guard = exclusive();
    let name = container_name("shared");

    let mut held = spawn(
        lxc_request(
            &format!("printf 'READY\\n'; sleep {SLEEP_SECONDS}"),
            &name,
            LIVE_TIMEOUT_MS,
        ),
        Default::default(),
    )
    .expect("spawn");
    let _stdout = read_first_line_within(
        held.take_stdout().expect("stdout available"),
        LIVE_TIMEOUT,
        "READY",
    );

    // LXC applies a run's network section only when the container starts, so
    // serving a second sandbox on the same container would mean stopping this
    // workload to restart it under the other run's policy.
    let refusal = match spawn(
        lxc_request("true", &name, LIVE_TIMEOUT_MS),
        Default::default(),
    ) {
        Ok(_) => panic!("a second sandbox on a live container must be refused"),
        Err(e) => e,
    };
    assert!(
        refusal.message.contains(&name),
        "the refusal should name the container the caller asked for, got: {}",
        refusal.message
    );

    held.kill().expect("kill");
    let _ = held.wait();
    assert_container_released(&name);
    drop(held);

    // The refusal must not strand the name: the claim is released with the
    // handle, so the next sandbox can have it.
    let mut reused = spawn(
        lxc_request("true", &name, LIVE_TIMEOUT_MS),
        Default::default(),
    )
    .expect("spawn after release");
    assert_eq!(reused.wait().expect("wait"), WaitResult::Exited(0));
    assert_container_released(&name);
}

#[test]
fn streaming_lxc_tears_down_a_networked_container() {
    if !lxc_ready() {
        return;
    }
    let _guard = exclusive();
    let name = container_name("network");

    // Outbound access puts the container on the bridge and installs egress
    // chains, so this is the case whose teardown has firewall rules to remove.
    let network = NetworkPolicy {
        egress: Some(NetworkEgressPolicy {
            default: Some(NetworkAction::Allow),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut proc = spawn(
        lxc_request_with_network("printf 'NETWORKED\\n'", &name, LIVE_TIMEOUT_MS, network),
        Default::default(),
    )
    .expect("spawn");
    let stdout = proc.take_stdout().expect("stdout available");

    let out = read_to_end_within(stdout, LIVE_TIMEOUT, "stdout").expect("read stdout");
    assert!(out.contains("NETWORKED"), "got: {out:?}");

    assert_eq!(proc.wait().expect("wait"), WaitResult::Exited(0));
    // The chains live in the container's own network namespace, so destroying
    // the container is what proves they are gone.
    assert_container_released(&name);
}
