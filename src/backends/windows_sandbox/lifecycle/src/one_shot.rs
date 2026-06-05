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
//! instance. Each one-shot run holds the host VM-slot mutex (`Local\wxc-wsb-vm`)
//! for its whole lifetime, which serialises one-shot against both a concurrent
//! one-shot run and a live state-aware daemon (which holds the same mutex). A
//! second invocation launched while a VM owner holds the slot is refused
//! promptly as busy. Teardown is ownership-scoped (see [`crate::teardown`]): a
//! run only ever kills the VM host processes it can positively prove it
//! launched, never a foreign or manually-opened sandbox.

use std::path::PathBuf;
use std::time::Duration;

use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use wxc_common::script_runner::{get_timeout_milliseconds, ScriptRunner};

use crate::control_plane::{HostVmLock, VmOwnership};
use crate::error::OneShotError;
use crate::teardown::{self, Reconcile, VmTeardownGuard};
use crate::{bridge, policy, rendezvous, vm};

/// Maximum time to wait for the guest agent's rendezvous file. First VM boot
/// can take several minutes; 360s covers worst-case cold starts.
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(360);

/// Polling interval when checking for the rendezvous file.
const RENDEZVOUS_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Maximum time to connect to the guest agent after rendezvous.
const GUEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Bounded wait to acquire the host VM-slot mutex. The host permits a single
/// running Windows Sandbox VM; if another VM owner (a concurrent one-shot or a
/// live state-aware daemon) holds the slot we refuse promptly as busy rather
/// than block.
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

        // Translate the request's policy into the primitives this backend can
        // enforce, rejecting anything it cannot. This has no side effects, so a
        // rejection here leaves the host untouched (no VM, no scratch dirs).
        let plan = policy::plan_policy(request)?;

        // Acquire the host VM-slot mutex for the WHOLE run. The host permits a
        // single running Windows Sandbox VM; holding this serialises one-shot
        // against both concurrent one-shot runs and a live state-aware daemon,
        // and closes the reconcile→write_marker TOCTOU. Declared first so it is
        // dropped LAST — only after the teardown guard has confirmed our VM is
        // gone — so the next VM owner cannot grab the slot while ours lingers.
        let _vm_lock = HostVmLock::acquire(HOST_VM_LOCK_TIMEOUT).map_err(|e| {
            OneShotError::Busy(format!(
                "another Windows Sandbox VM owner holds the host slot: {e:#}"
            ))
        })?;

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
        // Create the run dir first and lock it owner-only (inheritable) so the
        // rendezvous files and generated `.wsb` written underneath cannot be
        // read or tampered with cross-user on a shared temp dir.
        std::fs::create_dir_all(&run_dir)
            .map_err(|e| OneShotError::Launch(format!("create run dir: {e}")))?;
        wxc_common::filesystem_dacl::set_owner_only_dacl(&run_dir, true)
            .map_err(|e| OneShotError::Launch(format!("secure run dir: {e}")))?;
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
        let wsb_path = vm::generate_wsb(
            &guest_dir,
            &rendezvous_dir,
            &python_dir,
            &config_dir,
            &plan.mapped_folders,
        )
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

        let exec = runtime.block_on(drive(
            &wsb_path,
            &rendezvous_dir,
            &run_dir,
            request,
            &capture_host_stdin(),
        ))?;

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

/// Drive the async portion of the lifecycle: launch → capture ownership proof →
/// rendezvous → connect → execute. Runs to completion inside a single
/// `block_on`.
///
/// As the launch progresses it pushes the VM-ownership state into the teardown
/// slot (`LaunchInFlight` → `LaunchSucceededNoProof` → `Owned`) so the guard /
/// console handler tear down exactly — and only — the VM this run provably
/// owns. The marker is rewritten with positive process proof immediately after
/// launch (before the long rendezvous wait) so a crash during boot still leaves
/// a record the next run can reclaim.
async fn drive(
    wsb_path: &std::path::Path,
    rendezvous_dir: &std::path::Path,
    run_dir: &std::path::Path,
    request: &ExecutionRequest,
    host_stdin: &[u8],
) -> Result<bridge::ExecResult, OneShotError> {
    // Launch is in flight: a foreign VM could still win the single-instance
    // contest and fail our launch, so ownership is not yet provable.
    teardown::set_vm_ownership(VmOwnership::LaunchInFlight);

    vm::launch(wsb_path)
        .await
        .map_err(|e| OneShotError::Launch(format!("{e:#}")))?;

    // Launch returned Ok: by the OS single-instance invariant the running VM is
    // ours, even before we enumerate its host processes.
    teardown::set_vm_ownership(VmOwnership::LaunchSucceededNoProof);

    // Capture positive ownership proof (the VM host-process identities) and
    // record it both in the teardown slot and the durable marker.
    //
    // Review finding B2: if `capture_launch_proof` returns empty (slow Hyper-V
    // worker process spawn, AV scanning the bootstrap, loaded host), DO NOT
    // overwrite `LaunchSucceededNoProof` with `Owned(Vec::new())` and DO NOT
    // rewrite the pre-launch marker with an empty `vm_processes` field.
    // The previous design did both, with two bad consequences:
    //   1. `compute_kill_set(&[], snapshot)` (now `plan_kill_set(Owned(empty),
    //      snapshot)`) returned empty under intersection-only semantics,
    //      leaking the VM at teardown.
    //   2. The marker on disk lost its pre-launch state, bricking any later
    //      one-shot's reconcile (it saw an empty proof and refused as
    //      `ForeignUnprovable`).
    // Keeping `LaunchSucceededNoProof` lets `plan_kill_set` enumerate-kill on
    // a non-empty fresh snapshot at teardown (we provably hold the host VM-
    // slot mutex, so any live `WindowsSandbox*` is ours), and keeping the
    // pre-launch marker preserves the launcher-strongly-alive signal so a
    // later reconcile still has SOME information to act on.
    let proof = vm::capture_launch_proof().await;
    if proof.is_empty() {
        eprintln!(
            "[one-shot] WARNING: no WindowsSandbox* host processes appeared within \
             capture_launch_proof's budget; staying at LaunchSucceededNoProof. Teardown will \
             enumerate-kill if any host processes are visible at exit; the pre-launch marker \
             (with empty vm_processes) is preserved so reclaim of this VM by a later one-shot is \
             not possible by positive proof. If the daemon hard-dies before exit, the VM may \
             require manual cleanup."
        );
    } else {
        teardown::set_vm_ownership(VmOwnership::Owned(proof.clone()));
        teardown::rewrite_marker_with_proof(run_dir, &proof).map_err(|e| {
            // Fatal: without a durable proof a later run could not reclaim this VM.
            // Abort so the guard tears the VM down now rather than leak it.
            OneShotError::Launch(format!("record VM ownership proof: {e}"))
        })?;
    }

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
        host_stdin,
    )
    .await
    .map_err(|e| OneShotError::Exec(format!("{e:#}")))
}

/// Capture wxc-exec's own stdin to a byte buffer for forwarding to the guest.
///
/// Behaviour:
/// - **TTY-stdin** (interactive): returns an empty buffer. Reading from a TTY
///   would block forever waiting for the user's input; the one-shot exec
///   contract today is a non-interactive byte buffer (see `host_stdin: &[u8]`
///   in [`bridge::execute_on_guest`]), so an interactive caller gets nothing
///   forwarded — same as the previous (silently-dropping) behaviour.
/// - **Pipe-stdin** (SDK / shell redirect): reads to EOF and returns the
///   bytes. Errors are logged but never propagated — a failed stdin capture
///   is degraded UX, not a reason to abort an otherwise-valid exec.
///
/// Review finding C3: the previous one-shot `drive` hardcoded `&[]` for the
/// `host_stdin` argument to `execute_on_guest`, silently dropping any stdin
/// that an SDK caller piped in (e.g. `echo hi | wxc-exec ... config.json`
/// produced an empty stdin in the sandbox). The commit message claimed
/// "stdin forwarding"; this restores that promise for the one-shot path.
/// True streaming (rather than the buffered-byte-slice contract) is out of
/// scope for Phase C and would require widening
/// [`bridge::execute_on_guest`]'s signature.
fn capture_host_stdin() -> Vec<u8> {
    use std::io::{IsTerminal, Read};
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    if let Err(e) = stdin.read_to_end(&mut buf) {
        eprintln!(
            "[one-shot] WARNING: failed to capture stdin for sandbox forwarding ({e}); \
             continuing with empty stdin"
        );
        return Vec::new();
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
