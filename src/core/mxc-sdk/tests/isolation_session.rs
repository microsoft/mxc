// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IsolationSession reachability from the Rust SDK.
//!
//! Host-independent tests pin the refusals; host-dependent ones drive the
//! state-aware lifecycle against a real isolation session and skip when the
//! backend is unavailable, so this file is safe to run on any host.

#![cfg(all(target_os = "windows", feature = "isolation_session"))]

use mxc_sdk::policy::{NetworkSection, SandboxPolicy};
use mxc_sdk::{build_request_with_containment, Containment, ErrorCode};

/// The network acknowledgment this backend requires; an absent policy is
/// refused.
fn iso_policy() -> SandboxPolicy {
    SandboxPolicy {
        version: "0.7.0-alpha".to_string(),
        filesystem: None,
        network: Some(NetworkSection {
            allow_outbound: true,
            allow_local_network: true,
            ..Default::default()
        }),
        ui: None,
        timeout_ms: None,
        capture_denials: None,
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

    let provision = r#"{"phase":"provision","containment":"isolation_session",
        "network":{"defaultPolicy":"allow","allowLocalNetwork":true}}"#;
    let err = mxc_sdk::run_state_aware_json(provision, false, true)
        .expect_err("a single-threaded apartment must be refused");

    assert_eq!(
        err.code,
        ErrorCode::BackendError,
        "message: {}",
        err.message
    );
    assert_eq!(err.operation.as_deref(), Some("Com.CoGetApartmentType"));
    assert_eq!(err.native_code.as_deref(), Some("0x80010106"));
    assert!(
        err.remediation.is_some(),
        "the refusal must tell the caller what to do instead"
    );
}

#[test]
fn one_shot_run_refuses_the_backend() {
    let mut request =
        build_request_with_containment(&iso_policy(), &Containment::IsolationSession, None)
            .expect("building the request must succeed — the refusal is at dispatch, not build");
    request
        .set_script("cmd.exe /c echo hi")
        .set_experimental(true);

    let err = mxc_sdk::run(request).expect_err("one-shot run must refuse IsolationSession");
    assert_eq!(
        err.code,
        ErrorCode::UnsupportedContainment,
        "expected an unsupported-containment refusal, got {:?}: {}",
        err.code,
        err.message
    );
}

#[test]
fn one_shot_spawn_refuses_the_backend() {
    let mut request =
        build_request_with_containment(&iso_policy(), &Containment::IsolationSession, None)
            .expect("building the request must succeed — the refusal is at dispatch, not build");
    request
        .set_script("cmd.exe /c echo hi")
        .set_experimental(true);

    // `Sandbox` is not `Debug`, so match rather than `expect_err`.
    match mxc_sdk::spawn_sandbox(request) {
        Ok(_) => panic!("streaming spawn must refuse IsolationSession"),
        Err(err) => assert_eq!(
            err.code,
            ErrorCode::UnsupportedContainment,
            "expected an unsupported-containment refusal, got {:?}: {}",
            err.code,
            err.message
        ),
    }
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
        let stop = format!(r#"{{"phase":"stop","sandboxId":"{id}"}}"#);
        let _ = mxc_sdk::run_state_aware_json(&stop, false, true);
        let deprovision = format!(r#"{{"phase":"deprovision","sandboxId":"{id}"}}"#);
        if let Err(e) = mxc_sdk::run_state_aware_json(&deprovision, false, true) {
            eprintln!("WARNING: deprovision of {id} failed, the agent account may leak: {e:?}");
        }
    }
}

#[test]
fn state_aware_lifecycle_runs_end_to_end() {
    skip_unless_supported!();

    let provision = r#"{"phase":"provision","containment":"isolation_session",
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

    let start = format!(r#"{{"phase":"start","sandboxId":"{sandbox_id}"}}"#);
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
    let provision = r#"{"phase":"provision","containment":"isolation_session",
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

    let start = format!(r#"{{"phase":"start","sandboxId":"{sandbox_id}"}}"#);
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

    let stop = format!(r#"{{"phase":"stop","sandboxId":"{}"}}"#, started.sandbox_id);
    mxc_sdk::run_state_aware_json(&stop, false, true).expect("stop must succeed");
    let deprovision = format!(
        r#"{{"phase":"deprovision","sandboxId":"{}"}}"#,
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
    let provision = r#"{"phase":"provision","containment":"isolation_session",
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
        r#"{{"phase":"exec","sandboxId":"{}",
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
        r#"{{"phase":"exec","sandboxId":"{}",
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
        r#"{{"phase":"exec","sandboxId":"{}",
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
        r#"{{"phase":"exec","sandboxId":"{}",
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
