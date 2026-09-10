// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IsolationSession reachability from the Rust SDK.
//!
//! Host-dependent tests skip when the backend is unavailable, so this file is
//! safe to run on any host.

#![cfg(all(target_os = "windows", feature = "isolation_session"))]

use mxc_sdk::policy::{NetworkSection, SandboxPolicy};
use mxc_sdk::{build_request_with_containment, Containment, ErrorCode};

/// The network acknowledgment this backend requires; an absent policy is
/// refused.
fn iso_policy() -> SandboxPolicy {
    iso_policy_with_deadline(None)
}

/// The same policy with a workload deadline, for a test whose workload waits on
/// the harness: if the handshake never lands, the deadline is what ends the run
/// instead of the test waiting on a process that will not exit.
fn iso_policy_with_deadline(timeout_ms: Option<u32>) -> SandboxPolicy {
    let mut network = NetworkSection::default();
    network.allow_outbound = true;
    network.allow_local_network = true;

    SandboxPolicy {
        version: "0.9.0-alpha".to_string(),
        filesystem: None,
        network: Some(network),
        ui: None,
        timeout_ms,
    }
}

/// Safe to call before anything else has initialised COM: the backend's probe
/// owns its own apartment.
fn host_supports_isolation_session() -> bool {
    mxc_sdk::available_backends()
        .iter()
        .any(|b| b.backend == "isolation_session")
}

/// A skipped test reports as a pass, so a fully-skipped suite looks like one
/// that ran. `MXC_ISO_TESTS_REQUIRED=1` turns every skip into a failure.
fn skips_are_failures() -> bool {
    matches!(
        std::env::var("MXC_ISO_TESTS_REQUIRED").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Enters a single-threaded apartment, which the backend refuses.
///
/// libtest runs every test on its own thread and apartment membership is
/// per-thread, so a test that wants an STA enters one itself.
fn enter_sta() {
    // Declared here rather than taking a `windows` dev-dependency for one call.
    #[link(name = "ole32")]
    extern "system" {
        fn CoInitializeEx(reserved: *mut core::ffi::c_void, co_init: u32) -> i32;
    }
    const COINIT_APARTMENTTHREADED: u32 = 0x2;

    // SAFETY: standard COM init. Deliberately unbalanced — the test thread ends
    // with the test.
    let hr = unsafe { CoInitializeEx(core::ptr::null_mut(), COINIT_APARTMENTTHREADED) };
    assert!(hr >= 0, "CoInitializeEx failed: 0x{hr:08x}");
}

macro_rules! skip_unless_supported {
    () => {
        if !host_supports_isolation_session() {
            assert!(
                !skips_are_failures(),
                "MXC_ISO_TESTS_REQUIRED is set, but IsolationSession is not available on this host."
            );
            eprintln!(
                "skipping: IsolationSession is not available on this host \
                 (set MXC_ISO_TESTS_REQUIRED=1 to make skips fail)"
            );
            return;
        }
    };
}

#[test]
fn a_single_threaded_apartment_is_refused_before_the_service_is_reached() {
    enter_sta();

    let provision = r#"{"version":"0.9.0-alpha","phase":"provision","containment":"isolation_session",
        "network":{"defaultPolicy":"allow","allowLocalNetwork":true}}"#;
    let err = mxc_sdk::run_state_aware_json(provision, false, true)
        .expect_err("a single-threaded apartment must be refused");

    assert_eq!(
        err.code,
        ErrorCode::BackendError,
        "message: {}",
        err.message
    );
    assert_eq!(
        err.operation, None,
        "the apartment query succeeds, so the refusal has no call to name"
    );
    assert_eq!(err.native_code, None);
    assert!(
        err.remediation.is_some(),
        "the refusal must tell the caller what to do instead"
    );
}

/// The experimental gate fires before any host work, so this is
/// host-independent: it is the same refusal on a machine with no OS-side
/// service. Both entry points are checked because `run` is `spawn` plus a wait,
/// and a gate applied to only one of them would still read as covered.
#[test]
fn one_shot_requires_the_experimental_optin() {
    for (name, spawned) in [
        ("run", {
            let request = build_request_with_containment(
                &iso_policy(),
                &Containment::IsolationSession,
                "echo hi",
                None,
            )
            .expect("building the request must succeed — the gate is at dispatch");
            mxc_sdk::run(request).err().map(|e| e.code)
        }),
        ("spawn_sandbox", {
            let request = build_request_with_containment(
                &iso_policy(),
                &Containment::IsolationSession,
                "echo hi",
                None,
            )
            .expect("building the request must succeed — the gate is at dispatch");
            // `Sandbox` is not `Debug`, so map rather than `expect_err`.
            match mxc_sdk::spawn_sandbox(request) {
                Ok(_) => None,
                Err(err) => Some(err.code),
            }
        }),
    ] {
        assert_eq!(
            spawned,
            Some(ErrorCode::MalformedRequest),
            "{name} must refuse an experimental backend without the opt-in"
        );
    }
}

/// The one-shot surface reaches the backend and returns the workload's output.
/// A policy this backend cannot honor is reported as a policy rejection rather
/// than a generic backend failure.
///
/// The refusal is raised before any OS call, so this runs on any host — and the
/// classification is the point: the library boundary must not flatten a
/// caller-fixable refusal into an opaque backend error.
#[test]
fn one_shot_refuses_an_unhonorable_policy_as_policy_validation() {
    let policy = SandboxPolicy {
        version: "0.9.0-alpha".to_string(),
        filesystem: None,
        // The backend cannot filter the container's network, so it accepts only
        // an explicit acknowledgment; an absent policy reads as a deny it has no
        // way to enforce.
        network: None,
        ui: None,
        timeout_ms: None,
    };
    let mut request = build_request_with_containment(
        &policy,
        &Containment::IsolationSession,
        "echo unreachable",
        None,
    )
    .expect("building the request must succeed");
    request.set_experimental(true);

    let err = match mxc_sdk::spawn_sandbox(request) {
        Ok(_) => panic!("the policy must be refused"),
        Err(e) => e,
    };
    assert_eq!(
        err.code,
        ErrorCode::PolicyValidation,
        "a refusal raised before any OS call must keep its own code: {err:?}"
    );
}

#[test]
fn one_shot_run_captures_output() {
    skip_unless_supported!();
    let mut request = build_request_with_containment(
        &iso_policy(),
        &Containment::IsolationSession,
        "echo marker-oneshot",
        None,
    )
    .expect("building the request must succeed");
    request.set_experimental(true);

    let output = mxc_sdk::run(request).expect("one-shot run must reach the backend");
    assert_eq!(output.outcome, mxc_sdk::WaitOutcome::Exited(0));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("marker-oneshot"),
        "the workload's stdout must reach the caller, got: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// A one-shot exec's exit code reaches the caller unchanged. Paired with the
/// test above so a backend that always reported success could not satisfy both.
#[test]
fn one_shot_run_propagates_a_nonzero_exit() {
    skip_unless_supported!();
    let mut request = build_request_with_containment(
        &iso_policy(),
        &Containment::IsolationSession,
        "exit 7",
        None,
    )
    .expect("building the request must succeed");
    request.set_experimental(true);

    let output = mxc_sdk::run(request).expect("one-shot run must reach the backend");
    assert_eq!(output.outcome, mxc_sdk::WaitOutcome::Exited(7));
}

/// What a held sibling established. Kept apart so a failure names which one
/// broke.
struct Held {
    quiet: bool,
    released: bool,
    answered: bool,
    stream_ended: bool,
}

impl Held {
    /// Run 0 is never held, so it has nothing to establish.
    fn not_held() -> Self {
        Self {
            quiet: true,
            released: true,
            answered: true,
            stream_ended: false,
        }
    }
}

/// The cross-talk this guards is one run's teardown reaching a sibling that is
/// still executing, which one-shot invites because teardown is automatic rather
/// than caller-driven.
///
/// `whoami` makes the isolation claim checkable: identical accounts would mean a
/// shared identity that comparing markers could never reveal.
///
/// The overlap is ordered rather than assumed. Each sibling blocks *in its own
/// workload* on a line from stdin. Run 0 does not tear down until every sibling
/// is running, and no sibling is released until that teardown has returned — so
/// each was alive across it, not merely near it. A released sibling must then
/// answer, and nothing may have arrived while it was held, so the answer cannot
/// be a line produced earlier. A sibling whose session had been reached would
/// fall silent, lose its marker, or exit non-zero.
#[test]
fn concurrent_one_shot_runs_stay_isolated() {
    skip_unless_supported!();
    const RUNS: usize = 3;
    const BEAT: std::time::Duration = std::time::Duration::from_secs(90);
    /// Written to a held sibling to release it, and echoed back to prove the
    /// line arrived. Distinct from the variable's name on purpose.
    const RELEASE_TOKEN: &str = "PROCEED";
    /// Backstop for the workloads themselves. A sibling waits on the harness,
    /// so a handshake that never lands would otherwise leave it running and the
    /// wait for it unbounded. Far above any healthy run.
    const WORKLOAD_DEADLINE_MS: u32 = 300_000;

    let (started_tx, started_rx) = std::sync::mpsc::channel();
    // Run 0 is held until every sibling has announced, so its teardown happens
    // while they are known to be running, and it announces when that teardown
    // has returned so nothing releases a sibling before it has.
    let (tear_down_tx, tear_down_rx) = std::sync::mpsc::channel::<()>();
    let tear_down_rx = std::sync::Arc::new(std::sync::Mutex::new(tear_down_rx));
    let (torn_down_tx, torn_down_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = std::sync::Arc::new(std::sync::Mutex::new(release_rx));

    let threads: Vec<_> = (0..RUNS)
        .map(|i| {
            let started_tx = started_tx.clone();
            let torn_down_tx = torn_down_tx.clone();
            let tear_down_rx = std::sync::Arc::clone(&tear_down_rx);
            let release_rx = std::sync::Arc::clone(&release_rx);
            std::thread::spawn(move || {
                let marker = format!("marker-concurrent-{i}");
                // Run 0 finishes immediately so its teardown is what the others
                // are held across. A sibling announces, blocks on stdin, and
                // only identifies itself once released. `call echo` forces a
                // run-time expansion pass, so the echoed value is the one read
                // rather than the empty string cmd substitutes at parse time.
                let script = if i == 0 {
                    format!("echo started-{i} & whoami & echo {marker}")
                } else {
                    format!(
                        "echo started-{i} & set /p GO= & call echo released-%%GO%% \
                         & whoami & echo {marker}"
                    )
                };
                let mut request = build_request_with_containment(
                    &iso_policy_with_deadline(Some(WORKLOAD_DEADLINE_MS)),
                    &Containment::IsolationSession,
                    &script,
                    None,
                )
                .expect("building the request must succeed");
                request.set_experimental(true);

                let mut sandbox =
                    mxc_sdk::spawn_sandbox(request).expect("spawn must reach the backend");
                let mut stdin = sandbox.take_stdin();
                let stdout = sandbox.take_stdout().expect("stdout");

                // Read on its own thread so the hold can be shown to be silent:
                // an unread pipe cannot be distinguished from a quiet one.
                let (line_tx, line_rx) = std::sync::mpsc::channel::<String>();
                let pump = std::thread::spawn(move || {
                    use std::io::BufRead;
                    let mut reader = std::io::BufReader::new(stdout);
                    loop {
                        let mut line = String::new();
                        match reader.read_line(&mut line) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {
                                if line_tx.send(line).is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });

                let mut collected = String::new();
                let first = line_rx.recv_timeout(BEAT).expect("started marker");
                collected.push_str(&first);
                started_tx.send(i).expect("the harness must be listening");

                if i == 0 {
                    while let Ok(line) = line_rx.recv_timeout(BEAT) {
                        collected.push_str(&line);
                    }
                    // Held until every sibling has announced, so the teardown
                    // below lands while they are running rather than possibly
                    // before they exist.
                    tear_down_rx
                        .lock()
                        .expect("teardown gate")
                        .recv_timeout(BEAT)
                        .expect("every sibling must announce before run 0 tears down");
                    let outcome = sandbox.wait().expect("wait");
                    drop(sandbox);
                    for _ in 1..RUNS {
                        let _ = torn_down_tx.send(());
                    }
                    let _ = pump.join();
                    return (marker, outcome, collected, Held::not_held());
                }

                // Held in its own workload until run 0's teardown has returned.
                release_rx
                    .lock()
                    .expect("release channel")
                    .recv_timeout(BEAT)
                    .expect("run 0 must finish and tear down");

                // Silence proof: nothing may have arrived while held. Without
                // it, a sibling that ignored its gate would have produced its
                // answer early, and the read below would return that buffered
                // line rather than a live one.
                //
                // A disconnect is neither silence nor speech: the sibling's
                // stdout has closed, which is what a session reached by run 0's
                // teardown looks like. Recorded on its own so the report does
                // not accuse a dead sibling of speaking.
                use std::sync::mpsc::{RecvTimeoutError, TryRecvError};
                let (quiet, mut stream_ended) = match line_rx.try_recv() {
                    Err(TryRecvError::Empty) => (true, false),
                    Err(TryRecvError::Disconnected) => (true, true),
                    Ok(_) => (false, false),
                };

                use std::io::Write as _;
                let stdin = stdin.as_mut().expect("this backend forwards stdin");
                // A sibling whose session was reached has no reader left, so
                // this can fail. Recorded rather than raised: a panic here would
                // take the thread down and lose every diagnostic below.
                let released = writeln!(stdin, "{RELEASE_TOKEN}")
                    .and_then(|()| stdin.flush())
                    .is_ok();

                // The answer arrives only after the release, and the token
                // differs from the variable's name on purpose: an unset variable
                // echoes the name back, which would otherwise read as an answer.
                //
                // A timeout means the sibling is still blocked in its read and
                // will not exit on its own. End it before draining, so the drain
                // completes at EOF rather than waiting out its own timeout. A
                // disconnect means it is already gone and a reply means it is
                // past that read, so neither needs ending.
                let answered = match line_rx.recv_timeout(BEAT) {
                    Ok(line) => {
                        let ok = line.contains(RELEASE_TOKEN);
                        collected.push_str(&line);
                        ok
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        let _ = sandbox.kill();
                        false
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        stream_ended = true;
                        false
                    }
                };
                while let Ok(line) = line_rx.recv_timeout(BEAT) {
                    collected.push_str(&line);
                }
                let outcome = sandbox.wait().expect("wait");
                let _ = pump.join();
                (
                    marker,
                    outcome,
                    collected,
                    Held {
                        quiet,
                        released,
                        answered,
                        stream_ended,
                    },
                )
            })
        })
        .collect();

    // Every run is executing, not merely spawned. Only then is run 0 allowed to
    // tear down, so its teardown lands while the siblings are running.
    for _ in 0..RUNS {
        started_rx
            .recv_timeout(BEAT)
            .expect("every run must report that it started");
    }
    tear_down_tx
        .send(())
        .expect("run 0 must still be waiting to tear down");
    // Release only once run 0's teardown has returned, so every sibling was
    // held across it rather than merely near it.
    torn_down_rx
        .recv_timeout(BEAT)
        .expect("run 0 must tear its session down");
    for _ in 1..RUNS {
        release_tx
            .send(())
            .expect("every sibling must still be waiting");
    }

    let mut failures = Vec::new();
    let mut accounts = Vec::new();
    for thread in threads {
        let (marker, outcome, stdout, held) = thread.join().expect("a run thread must not panic");
        if outcome != mxc_sdk::WaitOutcome::Exited(0) {
            failures.push(format!("{marker}: outcome was {outcome:?}"));
        }
        if !stdout.contains(&marker) {
            failures.push(format!("{marker}: got back {stdout:?}"));
        }
        if !held.quiet {
            failures.push(format!(
                "{marker}: produced output while it was supposed to be held, so its later \
                 answer proves nothing"
            ));
        }
        if held.stream_ended {
            failures.push(format!("{marker}: its output ended before it answered"));
        }
        if !held.released {
            failures.push(format!("{marker}: could not be sent its release"));
        }
        if !held.answered {
            failures.push(format!(
                "{marker}: did not answer after run 0 tore its session down, got back {stdout:?}"
            ));
        }
        match stdout.lines().find(|l| l.contains('\\')) {
            Some(line) => accounts.push(account_of(line)),
            None => failures.push(format!("{marker}: no whoami line in {stdout:?}")),
        }
    }

    assert!(
        failures.is_empty(),
        "every concurrent run must return its own output: {failures:?}"
    );
    accounts.sort();
    accounts.dedup();
    assert_eq!(
        accounts.len(),
        RUNS,
        "each concurrent run must get its own agent account"
    );
}

/// A handle finished on a single-threaded apartment still tears its session
/// down.
///
/// The handle is `Send`, so a caller may hand it to a thread that has an
/// apartment — a UI thread is the obvious case. Teardown runs wherever the
/// handle is finished, and the platform refuses those calls from the wrong
/// apartment with `RPC_E_WRONG_THREAD` (`0x8001010e`), so it must not run
/// there. `kill` reports whether the session stopped, which is what that
/// refusal breaks.
#[test]
fn one_shot_finished_on_an_sta_thread_still_tears_down() {
    skip_unless_supported!();
    let mut request = build_request_with_containment(
        &iso_policy(),
        &Containment::IsolationSession,
        "ping -n 300 127.0.0.1",
        None,
    )
    .expect("building the request must succeed");
    request.set_experimental(true);

    let mut sandbox = mxc_sdk::spawn_sandbox(request).expect("spawn must reach the backend");

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        enter_sta();
        let _ = tx.send(sandbox.kill().map_err(|e| e.to_string()));
    });

    rx.recv_timeout(std::time::Duration::from_secs(120))
        .expect("kill on an STA thread must return rather than block")
        .expect("kill on an STA thread must still stop the session");
}

/// An abandoned handle's teardown completes without blocking.
///
/// A caller that drops the handle without waiting has still provisioned a real
/// OS account and left a workload running, and nothing else will reach either.
/// Teardown runs inside the drop, so a bounded return is the assertion. Whether
/// it *succeeded* is not observable here — the surface returns no identity to
/// attribute an account to.
#[test]
fn an_abandoned_one_shot_handle_completes_teardown() {
    skip_unless_supported!();
    let mut request = build_request_with_containment(
        &iso_policy(),
        &Containment::IsolationSession,
        "ping -n 300 127.0.0.1",
        None,
    )
    .expect("building the request must succeed");
    request.set_experimental(true);

    let sandbox = mxc_sdk::spawn_sandbox(request).expect("spawn must reach the backend");

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        drop(sandbox);
        let _ = tx.send(());
    });
    rx.recv_timeout(std::time::Duration::from_secs(120))
        .expect("dropping an abandoned handle must return rather than park");
}
/// `kill` ends the workload, and the workload is really gone afterwards.
///
/// A kill the platform *accepts* is not a kill that took effect, so the exit
/// code the handle reports cannot answer "did anything actually stop?". The
/// workload answers instead: it heartbeats to its own stdout, so a line proves
/// it was running and **EOF proves it stopped**. The handle is held across that
/// assertion, because dropping it would tear the session down and produce the
/// same EOF without `kill` having done anything.
#[test]
fn one_shot_kill_stops_the_workload() {
    skip_unless_supported!();
    // Long enough that a prompt EOF proves the kill worked, rather than racing
    // a workload that was about to exit anyway.
    let mut request = build_request_with_containment(
        &iso_policy(),
        &Containment::IsolationSession,
        "for /l %i in (1,1,300) do (echo beat & ping -n 2 127.0.0.1 >nul)",
        None,
    )
    .expect("building the request must succeed");
    request.set_experimental(true);

    let mut sandbox = mxc_sdk::spawn_sandbox(request).expect("spawn must reach the backend");
    let stdout = sandbox.take_stdout().expect("stdout must be available");

    let (tx, rx) = std::sync::mpsc::channel();
    let drain = std::thread::spawn(move || {
        use std::io::BufRead;
        let mut reader = std::io::BufReader::new(stdout);
        let mut first = String::new();
        let beat = reader
            .read_line(&mut first)
            .ok()
            .filter(|n| *n > 0)
            .is_some();
        let _ = tx.send(beat);
        // Runs to EOF, which only arrives once nothing holds the stream. A read
        // error is reported rather than collapsed to 0, which would end the
        // loop and read exactly like the EOF this test is waiting for.
        let mut rest = Vec::new();
        loop {
            match reader.read_until(b'\n', &mut rest) {
                Ok(0) => return Ok(()),
                Ok(_) => rest.clear(),
                Err(e) => return Err(e.to_string()),
            }
        }
    });

    assert!(
        rx.recv_timeout(std::time::Duration::from_secs(60))
            .expect("the workload must produce a heartbeat before the kill"),
        "the workload must be running before the kill, or this test cannot fail"
    );

    // Bounded, because teardown has been seen to block on a platform call that
    // never returns. The handle comes back so this test, not the worker, decides
    // when it drops.
    let (killed_tx, killed_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = sandbox.kill().map_err(|e| e.to_string());
        let _ = killed_tx.send((outcome, sandbox));
    });
    let (killed, sandbox) = killed_rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("kill must return rather than block");
    killed.expect("kill must be accepted and take effect");

    // A surviving workload keeps its stdout open, so this join is what would
    // never return; the bound turns that into a failure.
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done_tx.send(drain.join());
    });
    done_rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("the workload's stdout must reach EOF after the kill, proving it stopped")
        .expect("the drain thread must not panic")
        .expect("the workload's stdout must end in EOF, not a read error");

    drop(sandbox);
}

/// Provision mints a real OS account; a failure before deprovision leaks it onto
/// the host. `Drop` covers the unwind path a failed assertion skips.
struct Teardown(String);

impl Teardown {
    /// Gives up ownership after the test has deprovisioned itself. Deprovision
    /// is not idempotent — a second call fails `stale_id` — so without this the
    /// drop below would report a leak that did not happen.
    fn defuse(mut self) {
        self.0.clear();
    }
}

impl Drop for Teardown {
    fn drop(&mut self) {
        let id = &self.0;
        if id.is_empty() {
            return;
        }
        let stop = format!(r#"{{"version":"0.9.0-alpha","phase":"stop","sandboxId":"{id}"}}"#);
        let _ = mxc_sdk::run_state_aware_json(&stop, false, true);
        let deprovision =
            format!(r#"{{"version":"0.9.0-alpha","phase":"deprovision","sandboxId":"{id}"}}"#);
        if let Err(e) = mxc_sdk::run_state_aware_json(&deprovision, false, true) {
            eprintln!("WARNING: deprovision of {id} failed, the agent account may leak: {e:?}");
        }
    }
}

#[test]
fn state_aware_lifecycle_runs_end_to_end() {
    skip_unless_supported!();

    let provision = r#"{"version":"0.9.0-alpha","phase":"provision","containment":"isolation_session",
        "network":{"defaultPolicy":"allow","allowLocalNetwork":true}}"#;
    let response = mxc_sdk::run_state_aware_json(provision, false, true)
        .expect("provision must succeed on a supported host");
    let parsed: serde_json::Value =
        serde_json::from_str(&response).expect("provision response must be JSON");

    // Print the raw response if the id is missing: without it the sandbox
    // cannot be deprovisioned and the account must be recovered by hand.
    let sandbox_id = match parsed["result"]["sandboxId"].as_str() {
        Some(id) => id.to_string(),
        None => panic!("provision returned no result.sandboxId; raw response: {response}"),
    };
    // No assertion on the id's shape: it is contractually opaque. The phases
    // below accepting it is the proof.
    assert!(
        !sandbox_id.is_empty(),
        "provision returned an empty sandboxId"
    );
    let _teardown = Teardown(sandbox_id.clone());

    let start =
        format!(r#"{{"version":"0.9.0-alpha","phase":"start","sandboxId":"{sandbox_id}"}}"#);
    mxc_sdk::run_state_aware_json(&start, false, true).expect("start must succeed");

    let captured = exec_capture_stdout(&sandbox_id, "cmd.exe /c echo state-aware-marker");

    assert!(
        captured.contains("state-aware-marker"),
        "exec stdout did not carry the marker, got: {captured:?}"
    );
}

/// A provisioned, started sandbox, plus the provision metadata the tests assert
/// on. Holding it keeps the teardown armed.
struct Started {
    sandbox_id: String,
    agent_user_name: String,
    workspace: String,
    teardown: Teardown,
}

fn provision_and_start() -> Started {
    let provision = r#"{"version":"0.9.0-alpha","phase":"provision","containment":"isolation_session",
        "network":{"defaultPolicy":"allow","allowLocalNetwork":true}}"#;
    let response =
        mxc_sdk::run_state_aware_json(provision, false, true).expect("provision must succeed");
    let parsed: serde_json::Value =
        serde_json::from_str(&response).expect("provision response must be JSON");
    let sandbox_id = match parsed["result"]["sandboxId"].as_str() {
        Some(id) => id.to_string(),
        None => panic!("provision returned no result.sandboxId; raw response: {response}"),
    };
    let teardown = Teardown(sandbox_id.clone());

    let metadata = &parsed["result"]["metadata"];
    let agent_user_name = metadata["agentUserName"]
        .as_str()
        .unwrap_or_else(|| panic!("provision returned no agentUserName; raw response: {response}"))
        .to_string();
    let workspace = metadata["ephemeralWorkspacePath"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("provision returned no ephemeralWorkspacePath; raw response: {response}")
        })
        .to_string();

    let start =
        format!(r#"{{"version":"0.9.0-alpha","phase":"start","sandboxId":"{sandbox_id}"}}"#);
    mxc_sdk::run_state_aware_json(&start, false, true).expect("start must succeed");
    Started {
        sandbox_id,
        agent_user_name,
        workspace,
        teardown,
    }
}

fn exec_capture_stdout(sandbox_id: &str, command: &str) -> String {
    let request = serde_json::json!({
        "version": "0.9.0-alpha",
        "phase": "exec",
        "sandboxId": sandbox_id,
        "process": { "commandLine": command, "timeout": 30000 }
    })
    .to_string();

    let mut sandbox = mxc_sdk::exec_sandbox(&request, true).expect("exec must return a handle");
    let stdout = sandbox.take_stdout().expect("exec must expose stdout");
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut stdout = stdout;
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    sandbox.wait().expect("waiting on the exec must succeed");
    String::from_utf8_lossy(&reader.join().expect("reader thread")).to_string()
}

/// The account segment of a `whoami` line, which prints `machine\user`.
/// Compared alone so the machine name cannot satisfy an assertion.
fn account_of(whoami_output: &str) -> String {
    whoami_output
        .trim()
        .rsplit('\\')
        .next()
        .unwrap_or_default()
        .to_lowercase()
}

/// The workload must run as the isolated agent user. Every other host-gated test
/// here would also pass against an unsandboxed `cmd.exe`; this one would not.
#[test]
fn exec_runs_as_the_isolated_agent_user() {
    skip_unless_supported!();
    let started = provision_and_start();

    let captured = exec_capture_stdout(&started.sandbox_id, "cmd.exe /c whoami");

    assert_eq!(
        account_of(&captured),
        started.agent_user_name.to_lowercase(),
        "the workload ran as {captured:?}, not as agent user {:?}",
        started.agent_user_name
    );
}

/// The ephemeral workspace is readable and writable from both sides, and
/// deprovision removes it synchronously.
#[test]
fn the_workspace_is_shared_with_the_agent_and_removed_on_deprovision() {
    skip_unless_supported!();
    let started = provision_and_start();
    let workspace = std::path::PathBuf::from(&started.workspace);

    assert!(
        workspace.is_dir(),
        "provision reported a workspace that is not a directory: {workspace:?}"
    );

    let nonce = format!("nonce-{}", std::process::id());
    std::fs::write(workspace.join("from-caller.txt"), format!("{nonce}\r\n"))
        .expect("the caller must be able to write into the workspace");

    // Copying the caller's file proves the agent read it; appending `whoami`
    // proves the agent wrote, and names who did.
    let command = format!(
        r#"cmd.exe /c type "{ws}\from-caller.txt" > "{ws}\from-agent.txt" & whoami >> "{ws}\from-agent.txt""#,
        ws = started.workspace
    );
    exec_capture_stdout(&started.sandbox_id, &command);

    let produced = std::fs::read_to_string(workspace.join("from-agent.txt"))
        .expect("the agent must be able to write into the workspace");
    assert!(
        produced.contains(&nonce),
        "the agent could not read the caller's file, got: {produced:?}"
    );
    assert_eq!(
        account_of(produced.lines().last().unwrap_or_default()),
        started.agent_user_name.to_lowercase(),
        "the workspace was written by an unexpected account, got: {produced:?}"
    );

    let stop = format!(
        r#"{{"version":"0.9.0-alpha","phase":"stop","sandboxId":"{}"}}"#,
        started.sandbox_id
    );
    mxc_sdk::run_state_aware_json(&stop, false, true).expect("stop must succeed");
    let deprovision = format!(
        r#"{{"version":"0.9.0-alpha","phase":"deprovision","sandboxId":"{}"}}"#,
        started.sandbox_id
    );
    mxc_sdk::run_state_aware_json(&deprovision, false, true).expect("deprovision must succeed");
    started.teardown.defuse();

    assert!(
        !workspace.exists(),
        "deprovision returned but the workspace is still present: {workspace:?}"
    );
}

#[test]
fn exec_attached_rejects_a_non_exec_phase() {
    // `provision` is a real phase, so this exercises the guard rather than the
    // parser's unknown-phase rejection.
    let provision = r#"{"version":"0.9.0-alpha","phase":"provision","containment":"isolation_session",
        "network":{"defaultPolicy":"allow","allowLocalNetwork":true}}"#;
    let err = mxc_sdk::exec_attached(provision, true)
        .expect_err("an attached exec must reject a non-exec phase");
    assert_eq!(err.code, ErrorCode::MalformedRequest);
    assert!(
        err.message.contains("exec phase"),
        "the refusal should name the phase requirement, got: {}",
        err.message
    );
}

#[test]
fn state_aware_exec_propagates_a_non_zero_exit_code() {
    skip_unless_supported!();
    let started = provision_and_start();

    let exec = format!(
        r#"{{"version":"0.9.0-alpha","phase":"exec","sandboxId":"{}",
            "process":{{"commandLine":"cmd.exe /c exit 42","timeout":30000}}}}"#,
        started.sandbox_id
    );
    let mut sandbox = mxc_sdk::exec_sandbox(&exec, true).expect("exec must return a handle");
    let outcome = sandbox.wait().expect("waiting on the exec must succeed");

    assert_eq!(
        outcome,
        mxc_sdk::WaitOutcome::Exited(42),
        "the sandboxed process's exit code must reach the caller unchanged"
    );
}

#[test]
fn state_aware_exec_can_be_killed() {
    skip_unless_supported!();
    let started = provision_and_start();

    // Long enough that a prompt `wait` proves the kill worked rather than
    // racing a process that was about to exit.
    let exec = format!(
        r#"{{"version":"0.9.0-alpha","phase":"exec","sandboxId":"{}",
            "process":{{"commandLine":"cmd.exe /c ping -n 300 127.0.0.1","timeout":600000}}}}"#,
        started.sandbox_id
    );
    let mut sandbox = mxc_sdk::exec_sandbox(&exec, true).expect("exec must return a handle");

    // Killing a process that has not started yet would prove nothing.
    std::thread::sleep(std::time::Duration::from_millis(500));
    sandbox
        .kill()
        .expect("kill must be accepted by the backend");

    let started = std::time::Instant::now();
    let outcome = sandbox.wait().expect("waiting after a kill must succeed");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(60),
        "wait after kill took {:?} — the workload would have run for ~300s, so this did not die",
        started.elapsed()
    );
    // The exit code of a killed process is the platform's business; that it
    // terminated at all is the contract under test.
    let _ = outcome;
}

/// A workload that reads stdin to EOF must terminate once the caller drops its
/// writer. The caller holds a duplicate, so this only works if dropping it also
/// closes the end the session process itself holds.
///
/// Ignored: the platform keeps a stdin write handle open that this crate cannot
/// reach, so the workload never sees EOF. Tracked as an OS bug.
#[test]
#[ignore = "blocked on an OS fix: a platform-held stdin write handle prevents EOF"]
fn a_workload_reading_stdin_to_eof_terminates_when_the_writer_drops() {
    skip_unless_supported!();
    let started = provision_and_start();

    // `more` reads stdin to EOF and exits. Without EOF it runs until the
    // deadline, so the timeout below is the failure signal, not the pass.
    let exec = format!(
        r#"{{"version":"0.9.0-alpha","phase":"exec","sandboxId":"{}",
            "process":{{"commandLine":"cmd.exe /c more","timeout":60000}}}}"#,
        started.sandbox_id
    );
    let mut sandbox = mxc_sdk::exec_sandbox(&exec, true).expect("exec must return a handle");

    {
        use std::io::Write;
        let mut stdin = sandbox.take_stdin().expect("stdin must be exposed");
        stdin
            .write_all(b"line one\r\n")
            .expect("write must succeed");
        stdin.flush().expect("flush must succeed");
    } // dropped here — this is what must deliver EOF

    let began = std::time::Instant::now();
    let outcome = sandbox.wait().expect("waiting on the exec must succeed");
    assert!(
        began.elapsed() < std::time::Duration::from_secs(45),
        "wait took {:?} — the workload never saw EOF and ran to its deadline",
        began.elapsed()
    );
    assert_eq!(
        outcome,
        mxc_sdk::WaitOutcome::Exited(0),
        "the workload should exit cleanly once stdin reaches EOF"
    );
}

/// A workload that backgrounds a descendant must not hold the exec open for
/// that descendant's lifetime. The descendant inherits the agent's write ends,
/// so the output relays reach no EOF and must be ended by cancellation.
#[test]
fn a_backgrounded_descendant_does_not_hold_the_exec_open() {
    skip_unless_supported!();
    let started = provision_and_start();

    // The foreground command exits at once; the spawned child outlives it by
    // ~30s while holding the inherited stdout/stderr write ends.
    let exec = format!(
        r#"{{"version":"0.9.0-alpha","phase":"exec","sandboxId":"{}",
            "process":{{"commandLine":"cmd.exe /c start /b ping -n 31 127.0.0.1 > nul & echo done","timeout":120000}}}}"#,
        started.sandbox_id
    );
    let mut sandbox = mxc_sdk::exec_sandbox(&exec, true).expect("exec must return a handle");

    let began = std::time::Instant::now();
    let outcome = sandbox.wait().expect("waiting on the exec must succeed");
    assert!(
        began.elapsed() < std::time::Duration::from_secs(20),
        "wait took {:?} — the exec tracked the descendant's lifetime, not the workload's",
        began.elapsed()
    );
    let _ = outcome;
}
