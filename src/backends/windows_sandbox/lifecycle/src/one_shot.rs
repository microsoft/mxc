// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Transient one-shot `ScriptRunner` for the Windows Sandbox backend.
//!
//! Each [`execute`](ScriptRunner::execute) launches a **fresh** Windows Sandbox
//! VM, runs the requested script exactly once, and guarantees teardown of that
//! VM on every exit path (see [`crate::teardown`]). Unlike the daemon-backed
//! runner there is no warm-VM reuse and no shared state between invocations:
//! one call == one disposable VM.
//!
//! Concurrency: the host allows only a single running Windows Sandbox
//! instance, so concurrent one-shot invocations are not supported. A second
//! invocation launched while a disposable VM is live is refused by
//! [`crate::teardown::reconcile_existing_vm`] only if it carries no marker; two
//! genuinely concurrent disposable runs would contend for the single-instance
//! slot. State-aware addressing (separate work) lifts this restriction.

use std::path::PathBuf;
use std::time::Duration;

use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use wxc_common::script_runner::{get_timeout_milliseconds, ScriptRunner};

use crate::error::OneShotError;
use crate::teardown::{self, Reconcile, VmTeardownGuard};
use crate::{bridge, rendezvous, vm};

/// Maximum time to wait for the guest agent's rendezvous file. First VM boot
/// can take several minutes; 360s covers worst-case cold starts.
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(360);

/// Polling interval when checking for the rendezvous file.
const RENDEZVOUS_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Maximum time to connect to the guest agent after rendezvous.
const GUEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Stateless marker type whose [`ScriptRunner`] impl drives a disposable
/// Windows Sandbox VM through launch → exec → teardown in a single process.
#[derive(Debug, Default)]
pub struct WindowsSandboxRunner;

impl WindowsSandboxRunner {
    /// Create a new transient one-shot runner.
    pub fn new() -> Self {
        Self
    }

    /// Run the full disposable lifecycle, returning a typed error on failure.
    ///
    /// The teardown guard is armed *before* the VM is launched and lives until
    /// this function returns, so the VM is torn down on both the success and
    /// the error paths (and on a panic unwinding through here).
    fn run_one_shot(
        &self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<ScriptResponse, OneShotError> {
        use std::fmt::Write;

        // Preflight: sandbox feature + host Python.
        if let Err(e) = check_sandbox_available() {
            return Err(OneShotError::SandboxUnavailable(e));
        }
        let python_dir =
            vm::find_host_python().map_err(|e| OneShotError::PythonNotFound(format!("{e:#}")))?;
        let guest_dir = current_exe_dir().map_err(OneShotError::Launch)?;

        // Reconcile the host single-instance slot (reclaim our own orphan, or
        // refuse a foreign VM).
        let markers_root = teardown::markers_root();
        let reclaim_note = match teardown::reconcile_existing_vm(&markers_root) {
            Reconcile::Proceed(note) => note,
            Reconcile::Busy(detail) => return Err(OneShotError::Busy(detail)),
        };

        // Best-effort sweep of markerless leftovers from prior runs. A finished
        // run cannot delete its own scratch dir (the lingering `vmmem*` residue
        // holds the mapped rendezvous folder open), so the litter is reclaimed
        // here once the OS has released those handles. Runs before our own dir
        // exists, so it can never touch the in-flight run.
        teardown::gc_orphan_scratch_dirs(&markers_root);

        // Per-run scratch directories so concurrent / successive runs never
        // share a rendezvous file or `.wsb`.
        let run_dir = markers_root.join(uuid::Uuid::new_v4().to_string());
        let rendezvous_dir = run_dir.join("rendezvous");
        let config_dir = run_dir.join("config");
        std::fs::create_dir_all(&rendezvous_dir)
            .map_err(|e| OneShotError::Launch(format!("create rendezvous dir: {e}")))?;
        std::fs::create_dir_all(&config_dir)
            .map_err(|e| OneShotError::Launch(format!("create config dir: {e}")))?;
        // The marker is a required pre-launch step: without it a parent
        // TerminateProcess / power loss would leave an unreclaimable VM.
        teardown::write_marker(&run_dir)
            .map_err(|e| OneShotError::Launch(format!("write run marker: {e}")))?;

        // Generate the `.wsb` before arming the guard so a generation failure
        // does not trigger a (no-op but global) teardown for a VM we never
        // launched.
        let wsb_path = vm::generate_wsb(&guest_dir, &rendezvous_dir, &python_dir, &config_dir)
            .map_err(|e| OneShotError::Launch(format!("{e:#}")))?;

        // Arm guaranteed teardown BEFORE launch so there is no window in which
        // a spawned VM can leak. From here, every return path tears the VM down.
        let _guard = VmTeardownGuard::arm(run_dir.clone());

        let _ = writeln!(logger, "Windows Sandbox: launching disposable VM");

        // The lifecycle primitives are async; bridge them with a dedicated
        // current-thread runtime. Declared after the guard so it is dropped
        // first, leaving the guard to run teardown once the runtime is gone.
        //
        // This must not be called from within an existing tokio runtime
        // (`block_on` would panic). `wxc-exec`'s `main` is plain sync with no
        // ambient runtime, which is the only supported caller.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| OneShotError::RuntimeSetup(format!("{e}")))?;

        let exec = runtime.block_on(drive(&wsb_path, &rendezvous_dir, request))?;

        let mut response = exec_to_response(exec);
        if let Some(note) = reclaim_note {
            response.extended_error = note;
        }
        Ok(response)
        // `runtime` then `_guard` drop here → VM torn down, scratch dir removed.
    }
}

impl ScriptRunner for WindowsSandboxRunner {
    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        match self.run_one_shot(request, logger) {
            Ok(response) => response,
            Err(err) => err.into_response(),
        }
    }
}

/// Drive the async portion of the lifecycle: launch → rendezvous → connect →
/// execute. Runs to completion inside a single `block_on`.
async fn drive(
    wsb_path: &std::path::Path,
    rendezvous_dir: &std::path::Path,
    request: &ExecutionRequest,
) -> Result<bridge::ExecResult, OneShotError> {
    vm::launch(wsb_path)
        .await
        .map_err(|e| OneShotError::Launch(format!("{e:#}")))?;

    let addr = rendezvous::wait_for_rendezvous(
        rendezvous_dir,
        RENDEZVOUS_TIMEOUT,
        RENDEZVOUS_POLL_INTERVAL,
    )
    .await
    .map_err(|e| OneShotError::Rendezvous(format!("{e:#}")))?;

    let mut conn = bridge::connect_to_guest(addr, GUEST_CONNECT_TIMEOUT)
        .await
        .map_err(|e| OneShotError::Connect(format!("{e:#}")))?;

    let exec_id = uuid::Uuid::new_v4().to_string();
    let timeout_ms = get_timeout_milliseconds(request.script_timeout);
    bridge::execute_on_guest(
        &mut conn,
        &exec_id,
        &request.script_code,
        &request.working_directory,
        timeout_ms,
        &[],
    )
    .await
    .map_err(|e| OneShotError::Exec(format!("{e:#}")))
}

/// Map a successful guest execution to a [`ScriptResponse`].
fn exec_to_response(exec: bridge::ExecResult) -> ScriptResponse {
    let stdout = String::from_utf8_lossy(&exec.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&exec.stderr).into_owned();
    let error_message = if exec.error_message.is_empty() {
        stderr.clone()
    } else {
        exec.error_message
    };
    let failure_phase = if exec.exit_code == 0 {
        FailurePhase::None
    } else {
        FailurePhase::ProcessExited
    };
    ScriptResponse {
        exit_code: exec.exit_code,
        standard_out: stdout,
        standard_err: stderr,
        error_message,
        failure_phase,
        ..Default::default()
    }
}

/// Directory containing the running `wxc-exec` binary, alongside which the
/// guest agent binary is mapped read-only into the sandbox.
fn current_exe_dir() -> Result<PathBuf, String> {
    std::env::current_exe()
        .map_err(|e| format!("current_exe: {e}"))?
        .parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| "current_exe has no parent directory".to_string())
}

/// Check whether Windows Sandbox is installed by probing for
/// `WindowsSandbox.exe`.
///
/// Detection is by binary presence rather than a DISM feature query, which
/// requires elevation and fails for ordinary users.
fn check_sandbox_available() -> Result<(), String> {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let sandbox_exe = std::path::Path::new(&system_root)
        .join("System32")
        .join("WindowsSandbox.exe");
    if sandbox_exe.exists() {
        Ok(())
    } else {
        Err(format!("{} not found", sandbox_exe.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_to_response_zero_exit_is_no_failure() {
        let exec = bridge::ExecResult {
            exit_code: 0,
            error_message: String::new(),
            stdout: b"hello\n".to_vec(),
            stderr: Vec::new(),
            control_residual: Vec::new(),
        };
        let resp = exec_to_response(exec);
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.standard_out, "hello\n");
        assert_eq!(resp.failure_phase, FailurePhase::None);
    }

    #[test]
    fn exec_to_response_nonzero_exit_is_process_exited() {
        let exec = bridge::ExecResult {
            exit_code: 42,
            error_message: String::new(),
            stdout: Vec::new(),
            stderr: b"boom\n".to_vec(),
            control_residual: Vec::new(),
        };
        let resp = exec_to_response(exec);
        assert_eq!(resp.exit_code, 42);
        assert_eq!(resp.failure_phase, FailurePhase::ProcessExited);
        // stderr is mirrored into error_message when the agent gave none.
        assert_eq!(resp.error_message, "boom\n");
    }
}
