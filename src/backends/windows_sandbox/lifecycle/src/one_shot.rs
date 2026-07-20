// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Transient one-shot `ScriptRunner` for the Windows Sandbox backend.
//!
//! Each execution gets a fresh VM and an ownership-scoped teardown guard. The
//! host VM-slot mutex serialises one-shot runs with each other and with the
//! state-aware daemon.

use std::path::PathBuf;
use std::time::Duration;

use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use wxc_common::script_runner::{get_timeout_milliseconds, ScriptRunner};

use crate::control_plane::{self, HostVmLock};
use crate::error::OneShotError;
use crate::rendezvous::{GUEST_CONNECT_TIMEOUT, RENDEZVOUS_POLL_INTERVAL, RENDEZVOUS_TIMEOUT};
use crate::teardown::{self, Reconcile, VmTeardownGuard};
use crate::{bridge, policy, vm};

use windows_sandbox_common::auth as wsb_auth;

const HOST_VM_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Stateless marker type whose [`ScriptRunner`] impl drives a disposable
/// Windows Sandbox VM through launch → exec → teardown in a single process.
#[derive(Debug, Default)]
pub struct WindowsSandboxRunner;

impl WindowsSandboxRunner {
    /// Create a new transient one-shot runner.
    pub fn new() -> Self {
        Self
    }

    /// Run the full disposable lifecycle.
    fn run_one_shot(
        &self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<ScriptResponse, OneShotError> {
        use std::fmt::Write;

        ensure_no_tokio_runtime()?;

        if let Err(e) = check_sandbox_available() {
            return Err(OneShotError::SandboxUnavailable(e));
        }
        let guest_dir = current_exe_dir().map_err(OneShotError::Launch)?;

        let plan = policy::plan_policy(request)?;

        let _vm_lock = HostVmLock::acquire(HOST_VM_LOCK_TIMEOUT).map_err(|e| {
            OneShotError::Busy(format!(
                "another Windows Sandbox VM owner holds the host slot: {e:#}"
            ))
        })?;

        teardown::secure_markers_root()
            .map_err(|e| OneShotError::Launch(format!("secure markers root: {e:#}")))?;

        let markers_root = teardown::markers_root();
        let reclaim_note = match teardown::reconcile_existing_vm(&markers_root) {
            Reconcile::Proceed(note) => note,
            Reconcile::Busy(detail) => return Err(OneShotError::Busy(detail)),
        };

        teardown::gc_orphan_scratch_dirs(&markers_root);

        let run_dir = markers_root.join(uuid::Uuid::new_v4().to_string());
        let rendezvous_dir = run_dir.join("rendezvous");
        let config_dir = run_dir.join("config");
        std::fs::create_dir_all(&run_dir)
            .map_err(|e| OneShotError::Launch(format!("create run dir: {e}")))?;
        control_plane::set_owner_only_dir(&run_dir)
            .map_err(|e| OneShotError::Launch(format!("secure run dir: {e:#}")))?;
        std::fs::create_dir_all(&rendezvous_dir)
            .map_err(|e| OneShotError::Launch(format!("create rendezvous dir: {e}")))?;
        std::fs::create_dir_all(&config_dir)
            .map_err(|e| OneShotError::Launch(format!("create config dir: {e}")))?;
        teardown::write_marker(&run_dir)
            .map_err(|e| OneShotError::Launch(format!("write run marker: {e}")))?;

        let wsb_path = vm::generate_wsb(
            &guest_dir,
            &rendezvous_dir,
            &config_dir,
            &plan.mapped_folders,
        )
        .map_err(|e| OneShotError::Launch(format!("{e:#}")))?;

        let _guard = VmTeardownGuard::arm(run_dir.clone());

        let _ = writeln!(logger, "Windows Sandbox: launching disposable VM");

        let stdin_handle = std::thread::Builder::new()
            .name("wxc-host-stdin-spool".into())
            .spawn(capture_host_stdin)
            .map_err(|e| {
                OneShotError::RuntimeSetup(format!("spawn host stdin spool thread: {e}"))
            })?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| OneShotError::RuntimeSetup(format!("{e}")))?;

        let exec = runtime.block_on(drive(
            &wsb_path,
            &rendezvous_dir,
            &run_dir,
            request,
            stdin_handle,
        ))?;

        let mut response = exec_to_response(exec);
        if let Some(note) = reclaim_note {
            response.extended_error = note;
        }
        Ok(response)
        // Drop order tears down the runtime before the VM guard.
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

fn ensure_no_tokio_runtime() -> Result<(), OneShotError> {
    if tokio::runtime::Handle::try_current().is_ok() {
        Err(OneShotError::RuntimeSetup(
            "Windows Sandbox one-shot runner cannot run inside an existing tokio runtime"
                .to_string(),
        ))
    } else {
        Ok(())
    }
}

/// Drive the async launch/rendezvous/connect/execute path.
async fn drive(
    wsb_path: &std::path::Path,
    rendezvous_dir: &std::path::Path,
    run_dir: &std::path::Path,
    request: &ExecutionRequest,
    host_stdin: std::thread::JoinHandle<Vec<u8>>,
) -> Result<bridge::ExecResult, OneShotError> {
    let nonce = wsb_auth::generate_nonce()
        .map_err(|e| OneShotError::RuntimeSetup(format!("generate launch nonce: {e}")))?;

    let mut observer = OneShotLaunchObserver { run_dir };
    let (mut conn, _addr) = vm::launch_managed_vm(
        wsb_path,
        rendezvous_dir,
        &nonce,
        RENDEZVOUS_TIMEOUT,
        RENDEZVOUS_POLL_INTERVAL,
        GUEST_CONNECT_TIMEOUT,
        &mut observer,
    )
    .await
    .map_err(|e| OneShotError::Launch(format!("{e:#}")))?;

    // Stdin capture overlaps VM boot; a capture panic degrades to empty stdin.
    let host_stdin_bytes = host_stdin.join().unwrap_or_else(|panic| {
        eprintln!(
            "[one-shot] WARNING: host stdin spool thread panicked: {panic:?}; continuing with \
             empty stdin"
        );
        Vec::new()
    });

    let exec_id = uuid::Uuid::new_v4().to_string();
    let timeout_ms = get_timeout_milliseconds(request.script_timeout);
    bridge::execute_on_guest(
        &mut conn,
        &exec_id,
        &request.script_code,
        &request.working_directory,
        timeout_ms,
        &host_stdin_bytes,
    )
    .await
    .map_err(|e| OneShotError::Exec(format!("{e:#}")))
}

/// One-shot's [`vm::LaunchObserver`] adapter.
struct OneShotLaunchObserver<'a> {
    run_dir: &'a std::path::Path,
}

impl<'a> vm::LaunchObserver for OneShotLaunchObserver<'a> {
    fn set_ownership(&mut self, state: control_plane::VmOwnership) {
        teardown::set_vm_ownership(state);
    }

    fn persist_proof(&mut self, proof: &[control_plane::VmProcId]) -> anyhow::Result<()> {
        teardown::rewrite_marker_with_proof(self.run_dir, proof)
            .map_err(|e| anyhow::anyhow!("record VM ownership proof: {e}"))
    }

    fn note_empty_proof(&self) {
        eprintln!(
            "[one-shot] WARNING: no WindowsSandbox* host processes appeared within \
             capture_launch_proof's budget; staying at LaunchSucceededNoProof. Teardown will \
             enumerate-kill if any host processes are visible at exit; the pre-launch marker \
             (with empty vm_processes) is preserved so reclaim of this VM by a later one-shot is \
             not possible by positive proof. If the launcher hard-dies before exit, the VM may \
             require manual cleanup."
        );
    }
}

/// Maximum buffered stdin for the one-shot, non-streaming protocol.
const MAX_HOST_STDIN_BYTES: usize = 64 * 1024 * 1024;

/// Capture wxc-exec's own stdin to a byte buffer for forwarding to the guest.
///
/// TTY input is skipped to avoid blocking. Piped input is capped at
/// [`MAX_HOST_STDIN_BYTES`] and captured on a thread that overlaps VM boot.
fn capture_host_stdin() -> Vec<u8> {
    use std::io::{IsTerminal, Read};
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    // Read one byte past the cap to detect overflow without buffering the rest.
    if let Err(e) = stdin
        .by_ref()
        .take((MAX_HOST_STDIN_BYTES as u64) + 1)
        .read_to_end(&mut buf)
    {
        eprintln!(
            "[one-shot] WARNING: failed to capture stdin for sandbox forwarding ({e}); \
             continuing with empty stdin"
        );
        return Vec::new();
    }
    if buf.len() > MAX_HOST_STDIN_BYTES {
        eprintln!(
            "[one-shot] WARNING: host stdin exceeds {MAX_HOST_STDIN_BYTES} bytes; truncating to \
             the cap and discarding the remainder. Use the state-aware backend (which streams \
             stdin) for large stdin workloads."
        );
        buf.truncate(MAX_HOST_STDIN_BYTES);
    }
    buf
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
    fn no_tokio_runtime_is_accepted() {
        assert!(ensure_no_tokio_runtime().is_ok());
    }

    #[tokio::test]
    async fn existing_tokio_runtime_is_rejected() {
        assert!(matches!(
            ensure_no_tokio_runtime(),
            Err(OneShotError::RuntimeSetup(message))
                if message.contains("existing tokio runtime")
        ));
    }

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
