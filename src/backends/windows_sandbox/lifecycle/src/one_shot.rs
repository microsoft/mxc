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

use crate::control_plane::{self, HostVmLock};
use crate::error::OneShotError;
use crate::rendezvous::{GUEST_CONNECT_TIMEOUT, RENDEZVOUS_POLL_INTERVAL, RENDEZVOUS_TIMEOUT};
use crate::teardown::{self, Reconcile, VmTeardownGuard};
use crate::{bridge, policy, vm};

use windows_sandbox_common::auth as wsb_auth;

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

        // Secure the markers root (owner-verify + owner-only DACL) BEFORE
        // reconcile reads any per-run marker. A marker's recorded VM-process
        // proof authorizes scoped teardown, so a cross-user attacker who
        // pre-plants a forged marker under the shared-temp root could otherwise
        // trick reconcile into tearing down a foreign VM. Fails closed if the
        // root was pre-created by another user.
        teardown::secure_markers_root()
            .map_err(|e| OneShotError::Launch(format!("secure markers root: {e:#}")))?;

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
        control_plane::set_owner_only_dir(&run_dir)
            .map_err(|e| OneShotError::Launch(format!("secure run dir: {e:#}")))?;
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

        // Spool host stdin on a dedicated thread BEFORE driving the boot
        // sequence so it overlaps with VM boot. Evaluating `capture_host_stdin()`
        // synchronously as an argument to `drive` would make `cat huge |
        // wxc-exec ...` fully drain the producer before the VM even started,
        // adding the producer's wall-clock to boot. `drive` joins this thread
        // just before invoking `bridge::execute_on_guest`.
        let stdin_handle = std::thread::Builder::new()
            .name("wxc-host-stdin-spool".into())
            .spawn(capture_host_stdin)
            .map_err(|e| {
                OneShotError::RuntimeSetup(format!("spawn host stdin spool thread: {e}"))
            })?;

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
            stdin_handle,
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
    host_stdin: std::thread::JoinHandle<Vec<u8>>,
) -> Result<bridge::ExecResult, OneShotError> {
    // Mint the per-launch nonce; the observer wires up one-shot's ownership +
    // marker bookkeeping while `vm::launch_managed_vm` runs the shared boot sequence.
    let nonce = wsb_auth::generate_nonce();

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

    // Boot and stdin spool run concurrently. Join the spool
    // here, just before the exec frame is sent: if the producer was
    // faster than boot, this is non-blocking; if it was slower, we wait
    // for it now but at least it overlapped with the boot we just
    // finished. A panicked spool falls back to empty stdin -- a stdin
    // capture failure is degraded UX, not a reason to abort.
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
///
/// * `set_ownership` -> pushes the state into the process-global
///   teardown slot ([`teardown::set_vm_ownership`]) so the
///   teardown guard / console handler tear down the right VM.
/// * `persist_proof` -> rewrites the per-run marker file with the
///   captured proof so a later one-shot run can reclaim this VM if
///   the current run hard-dies.
/// * `note_empty_proof` -> the one-shot-specific warning calling
///   out the loss of marker-based reclaim and the fallback to
///   enumerate-kill at exit.
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

/// Maximum host stdin we buffer before forwarding to the guest. The one-shot
/// protocol delivers stdin as a byte buffer (not a stream), so an unbounded
/// `read_to_end` would grow host memory linearly with the producer's output
/// for a `cat huge | wxc-exec ...` pattern. 64 MiB is well above what any
/// reasonable interactive / script-piped exec uses while still bounding the
/// damage when something accidentally pipes a multi-GB stream in.
///
/// Bytes beyond the cap are discarded (with a one-shot warning to stderr).
/// True streaming would lift this entirely and is the proper fix; see
/// [`capture_host_stdin`] for the scope note.
const MAX_HOST_STDIN_BYTES: usize = 64 * 1024 * 1024;

/// Capture wxc-exec's own stdin to a byte buffer for forwarding to the guest.
///
/// - **TTY-stdin** (interactive): returns an empty buffer — reading a TTY would
///   block forever, and the one-shot exec contract is a non-interactive byte
///   buffer (`host_stdin: &[u8]` in [`bridge::execute_on_guest`]).
/// - **Pipe-stdin** (SDK / shell redirect): reads up to
///   [`MAX_HOST_STDIN_BYTES`]; anything past the cap is dropped with a stderr
///   warning so a runaway producer cannot exhaust host memory. A capture error
///   is logged but never propagated — degraded UX, not a reason to abort.
///
/// Spawned on a dedicated host thread from
/// [`WindowsSandboxRunner::run_one_shot`] so a slow read overlaps with VM boot
/// instead of serializing before it. True streaming (vs. the buffered slice) is
/// out of scope and would require widening [`bridge::execute_on_guest`]'s signature.
fn capture_host_stdin() -> Vec<u8> {
    use std::io::{IsTerminal, Read};
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    // Read in chunks so we can short-circuit at the cap without first
    // materialising the whole stream. `take(MAX_HOST_STDIN_BYTES + 1)`
    // limits the read by one extra byte so we can detect overflow.
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
