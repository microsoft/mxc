// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `StatefulSandboxBackend` impl for the Windows Sandbox backend.
//!
//! Windows Sandbox has no OS-level session service to persist a sandbox across
//! the separate `wxc-exec` processes that drive each lifecycle phase. Instead a
//! detached **host-side daemon** (`wxc-windows-sandbox-daemon.exe`) holds the
//! single live VM — and crucially its single guest control connection (the
//! guest exits the moment that connection drops) — from `start` until `stop`.
//!
//! State lives in two durable records under `%TEMP%\wxc-wsb\state-aware` (see
//! [`crate::control_plane`]): a per-sandbox `record.json` (lifecycle state +
//! immutable filesystem-policy snapshot) and a global `daemon.json` (the live
//! daemon's pid, IPC port, and auth nonce). Each phase is a fresh process that
//! reads those records to find and command the daemon.
//!
//! Phase semantics:
//! - **provision**: pure bookkeeping. Validate + snapshot the filesystem
//!   policy, mint `wsb:<token>`, write the per-sandbox record. No VM, no daemon.
//! - **start**: spawn the detached daemon, which launches the VM and connects
//!   the guest, then writes `daemon.json`. Returns only once the daemon reports
//!   ready. Single-slot: rejected if another sandbox is already active.
//! - **exec**: connect to the held daemon, run the script on the guest control
//!   connection, and relay stdout/stderr live to this process's stdio.
//! - **stop**: command the daemon to tear down its VM and exit.
//! - **deprovision**: ensure the daemon is gone, then remove the per-sandbox
//!   scratch + record.
//!
//! A process-global named mutex ([`TransitionLock`]) serialises start / stop /
//! deprovision across phase processes so two concurrent transitions can never
//! double-spawn, kill the wrong target, or write contradictory records.

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wxc_common::id::mint_random_token;
use wxc_common::models::ExecutionRequest;
use wxc_common::mxc_error::MxcError;
use wxc_common::process_util::resolve_sibling_binary;
use wxc_common::script_runner::get_timeout_milliseconds;
use wxc_common::state_aware_backend::{
    DeprovisionResult, ExecHandle, ProvisionResult, StartResult, StatefulSandboxBackend, StopResult,
};

use windows::Win32::Foundation::HANDLE;

use crate::control_plane::{
    self, daemon_record_path, generate_nonce, live_daemon, read_daemon_record, read_sandbox_record,
    running_process_creation_time, sandbox_dir, sandbox_record_path, DaemonRecord,
    MappedFolderRecord, SandboxRecord, SandboxState, TransitionLock, IPC_ERR, IPC_ERR_BUSY,
    IPC_ERR_NOT_READY, IPC_EXEC, IPC_OK, IPC_STOP,
};
use crate::error::OneShotError;
use crate::ipc_exec::{self, ExecExit, ExecStart, FRAME_EXIT, FRAME_STDERR, FRAME_STDOUT};
use crate::policy;
use crate::WindowsSandboxRunner;

/// `DETACHED_PROCESS` — the spawned daemon gets no console.
const DETACHED_PROCESS: u32 = 0x0000_0008;
/// `CREATE_NEW_PROCESS_GROUP` — isolates the daemon from the caller's console
/// Ctrl-C / process-group signals so killing the caller cannot orphan a VM.
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// How long to wait for the cross-process transition mutex. A concurrent
/// `start` holds it for the whole VM boot, so a contending phase may wait
/// several minutes.
const TRANSITION_LOCK_TIMEOUT: Duration = Duration::from_secs(600);

/// How long to wait for the daemon to report ready (VM boot + guest rendezvous
/// + connect). First cold boot can take minutes.
const START_READY_TIMEOUT: Duration = Duration::from_secs(420);

/// Poll interval while waiting for the daemon to become ready.
const START_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How long to wait for the daemon process to exit after a STOP command.
const DAEMON_EXIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Poll interval while waiting for the daemon to exit.
const DAEMON_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Timeout for connecting to the daemon's localhost IPC port.
const IPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for an IPC request/response round-trip.
const IPC_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for the host VM-slot mutex during stop/deprovision orphan
/// cleanup. The mutex is held by any other VM owner (a concurrent one-shot
/// run, or the daemon while it lived). A modest wait covers a previous
/// owner's teardown but bails rather than block stop/deprovision indefinitely.
const ORPHAN_CLEANUP_VM_LOCK_TIMEOUT: Duration = Duration::from_secs(20);

/// Drive the stale-daemon orphan VM cleanup that `stop`/`deprovision` must
/// perform when [`live_daemon`] returns `None` but the sandbox state was
/// [`SandboxState::Started`]. Implements review BLOCKING-2 + B5 fix:
///
/// 1. Reads the stale [`DaemonRecord`] (the on-disk record whose live-daemon
///    check failed — its owner is dead, but the VM it launched may still be).
/// 2. Snapshots live `WindowsSandbox*` host processes.
/// 3. Classifies via the pure [`control_plane::classify_stale_daemon_cleanup`]:
///    - [`StaleDaemonCleanup::NoLiveVm`]: nothing to do; the phase may
///      advance, and the (now-irrelevant) stale daemon record is removed.
///    - [`StaleDaemonCleanup::Reclaim { proof }`]: acquire [`control_plane::HostVmLock`]
///      (BLOCKING-2: serialises against a concurrent one-shot's launch /
///      reconcile), then [`crate::vm::teardown_via_plan`] seeded with the
///      stale proof. Daemon record removed only on [`TeardownOutcome::ConfirmedGone`];
///      `StillRunning` / `ProbeFailed` preserves the record and refuses.
///    - [`StaleDaemonCleanup::RefuseForeign { live }`]: surface the live PIDs
///      so the operator can clean up manually (review NB-1).
///    - [`StaleDaemonCleanup::RefuseProbeFailed`]: refuse — unknown state.
///    - [`StaleDaemonCleanup::RefuseSandboxIdMismatch`]: refuse — cleanup of
///      sandbox A must never act on sandbox B's records (GPT catch).
fn cleanup_stale_daemon_orphan(sandbox_id: &str) -> Result<(), MxcError> {
    let stale = read_daemon_record()
        .map_err(|e| MxcError::backend_error(format!("read stale daemon record: {e}")))?;

    // Build a minimal current-thread tokio runtime for the OS-touching async
    // calls. cleanup is rare (only the stale-daemon path) and the OS
    // enumeration / kill / poll is short.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| MxcError::backend_error(format!("build cleanup runtime: {e}")))?;

    let live_result = rt.block_on(async { crate::vm::enumerate_sandbox_vm_processes().await.ok() });

    let plan = control_plane::classify_stale_daemon_cleanup(
        stale.as_ref(),
        sandbox_id,
        live_result.as_deref(),
    );

    match plan {
        control_plane::StaleDaemonCleanup::NoLiveVm => {
            // Stale record is irrelevant — its VM (if any) is gone. Remove it
            // so future phases (and a future start) start clean.
            let _ = std::fs::remove_file(daemon_record_path());
            Ok(())
        }
        control_plane::StaleDaemonCleanup::Reclaim { proof } => {
            // Acquire HostVmLock for the snapshot-to-kill window (BLOCKING-2):
            // a concurrent one-shot may reach `reconcile_existing_vm` between
            // our snapshot and our terminate_processes call. Without this
            // mutex, the one-shot could observe our orphan + launch its own
            // VM before we kill ours, and the two VM owners' kill sets could
            // race on the single-instance slot.
            let _vm_lock = control_plane::HostVmLock::acquire(ORPHAN_CLEANUP_VM_LOCK_TIMEOUT)
                .map_err(|e| {
                    MxcError::backend_error(format!(
                        "acquire host Windows Sandbox VM slot for orphan cleanup: {e}"
                    ))
                })?;
            // Re-snapshot under the lock so the kill set is consistent with
            // the post-lock world (the proof was captured before we held
            // HostVmLock; another VM owner could have launched and exited in
            // between).
            let snapshot = rt
                .block_on(async { crate::vm::enumerate_sandbox_vm_processes().await })
                .unwrap_or_default();
            let kill_set =
                control_plane::plan_kill_set(&control_plane::VmOwnership::Owned(proof), &snapshot)
                    .unwrap_or_default();
            let outcome = rt.block_on(crate::vm::teardown_via_plan(&kill_set));
            match outcome {
                control_plane::TeardownOutcome::ConfirmedGone => {
                    let _ = std::fs::remove_file(daemon_record_path());
                    Ok(())
                }
                control_plane::TeardownOutcome::StillRunning(remaining) => {
                    Err(MxcError::backend_error(format!(
                        "orphan WindowsSandbox VM teardown timed out with {} host process(es) \
                         still alive: {:?}. Preserving stale daemon record so a next stop/start \
                         can retry. If this persists, kill these PIDs manually and retry.",
                        remaining.len(),
                        remaining.iter().map(|p| p.pid).collect::<Vec<_>>()
                    )))
                }
                control_plane::TeardownOutcome::ProbeFailed => Err(MxcError::backend_error(
                    "orphan WindowsSandbox VM teardown could not confirm exit (Toolhelp32 probe \
                     failed). Preserving stale daemon record so a next stop/start can retry."
                        .to_string(),
                )),
            }
        }
        control_plane::StaleDaemonCleanup::RefuseForeign { live } => {
            Err(MxcError::backend_error(format!(
                "a foreign WindowsSandbox VM is running that this sandbox cannot prove it \
                 launched ({} live host process(es), PIDs: {:?}). Refusing to disturb it. Kill \
                 these PIDs manually and retry.",
                live.len(),
                live.iter().map(|p| p.pid).collect::<Vec<_>>()
            )))
        }
        control_plane::StaleDaemonCleanup::RefuseProbeFailed => Err(MxcError::backend_error(
            "could not enumerate WindowsSandbox host processes (Toolhelp32 probe failed); \
                 refusing to act on unknown VM state. Retry later."
                .to_string(),
        )),
        control_plane::StaleDaemonCleanup::RefuseSandboxIdMismatch { stale_active } => {
            Err(MxcError::backend_error(format!(
                "stale daemon record on disk belongs to sandbox {stale_active}, not {sandbox_id}; \
                 refusing to act on another sandbox's bookkeeping. Stop/deprovision \
                 {stale_active} first."
            )))
        }
    }
}

/// Parse the `wsb:<token>` form of a state-aware `sandbox_id`, returning the
/// bare token. Surfaces format mismatches as [`MxcError::malformed_id`].
///
/// The token grammar is **strict**: lowercase hex, 1-128 chars (`^[a-f0-9]{1,128}$`).
/// This forbids `.`, `/`, `\`, NUL, and any character that could be
/// interpreted as a path segment, closing the path-traversal surface a
/// permissive grammar opened on `sandbox_dir(token)` /
/// `sandbox_record_path(token)` / `remove_dir_all(sandbox_dir(token))`
/// (review finding C5). The grammar matches what `mint_random_token` and
/// `wxc_common::id::mint_random_token` produce, plus a generous tail so a
/// future widening (e.g. UUID v4 hex) does not break in-tree callers.
///
/// Defence-in-depth: callers that take the returned token straight into a
/// `PathBuf` (everything in this module does today) can rely on the grammar
/// alone; future callers should still prefer the path-containment check in
/// `sandbox_dir_under_root` over re-deriving paths by hand.
fn extract_token(sandbox_id: &str) -> Result<&str, MxcError> {
    let prefix = <WindowsSandboxRunner as StatefulSandboxBackend>::ID_PREFIX;
    let (p, rest) = sandbox_id.split_once(':').ok_or_else(|| {
        MxcError::malformed_id(format!("expected {}:<token>, got {:?}", prefix, sandbox_id))
    })?;
    if p != prefix {
        return Err(MxcError::malformed_id(format!(
            "expected {}:<token>, got {:?}",
            prefix, sandbox_id
        )));
    }
    if !is_valid_sandbox_token(rest) {
        return Err(MxcError::malformed_id(format!(
            "sandbox token must be 1-128 lowercase hex chars; got {:?}",
            rest
        )));
    }
    Ok(rest)
}

/// True iff `token` is 1-128 lowercase hex chars (`^[a-f0-9]{1,128}$`).
/// Extracted as a pure helper so the C5 grammar is unit-testable.
fn is_valid_sandbox_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 128
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Map a [`OneShotError`] from policy planning to the wire error model. Policy
/// rejections become `policy_validation`; anything else is a backend error.
fn map_policy_error(e: OneShotError) -> MxcError {
    match e {
        OneShotError::Policy(msg) => MxcError::policy_validation(msg),
        other => MxcError::backend_error(format!("{other:?}")),
    }
}

/// Reject any non-default policy on a post-provision phase. The filesystem
/// policy is captured once at provision and is immutable thereafter; the
/// backend has no primitive to change it (or to honor network/proxy policy)
/// after the fact, so surfacing it later is a `policy_validation` error rather
/// than a silent ignore. Mirrors isolation_session's post-provision rejection.
fn reject_post_provision_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    let p = &request.policy;
    if !p.readwrite_paths.is_empty()
        || !p.readonly_paths.is_empty()
        || !p.denied_paths.is_empty()
        || !p.allowed_hosts.is_empty()
        || !p.blocked_hosts.is_empty()
        || p.network_proxy.is_enabled()
    {
        return Err(MxcError::policy_validation(
            "Windows Sandbox filesystem/network policy is fixed at provision; it cannot be \
             supplied or changed on a later phase",
        ));
    }
    Ok(())
}

/// Map an `ERR <reason>` status line from the daemon's EXEC admission into the
/// wire error model. Only called when the status line was not `OK`.
fn map_exec_status_error(status: &str) -> MxcError {
    // Require the `ERR ` prefix (with the separating space) so a malformed
    // `ERRbusy` is not silently normalized to a recognized reason token.
    let reason = status
        .strip_prefix(IPC_ERR)
        .and_then(|r| r.strip_prefix(' '))
        .map(str::trim);
    match reason {
        Some(IPC_ERR_BUSY) => {
            MxcError::backend_error("sandbox is busy: another exec is already running")
        }
        Some(IPC_ERR_NOT_READY) => MxcError::not_started("sandbox is not ready for exec yet"),
        _ => MxcError::backend_error(format!("daemon rejected exec: {}", status.trim())),
    }
}

/// Connect to the daemon's IPC port and run one execution, relaying the guest's
/// stdout/stderr live to this process's stdio and returning the child exit
/// code. The auth line + framed [`ExecStart`] are sent, a status line is read,
/// and on `OK` the binary frame stream ([`crate::ipc_exec`]) is consumed until
/// the terminal exit frame.
fn run_exec_stream(daemon: &DaemonRecord, request: &ExecutionRequest) -> Result<i32, MxcError> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, daemon.ipc_port));
    let stream = TcpStream::connect_timeout(&addr, IPC_CONNECT_TIMEOUT)
        .map_err(|e| MxcError::backend_error(format!("connect daemon IPC on {addr}: {e}")))?;
    stream
        .set_write_timeout(Some(IPC_IO_TIMEOUT))
        .map_err(|e| MxcError::backend_error(format!("set IPC write timeout: {e}")))?;

    let exec_start = ExecStart {
        script_code: request.script_code.clone(),
        working_directory: request.working_directory.clone(),
        timeout_ms: get_timeout_milliseconds(request.script_timeout),
    };

    // Send the auth line followed immediately by the request frame.
    {
        let mut w = &stream;
        writeln!(w, "{IPC_EXEC} {}", daemon.nonce)
            .map_err(|e| MxcError::backend_error(format!("send EXEC line: {e}")))?;
        ipc_exec::write_exec_start(&mut w, &exec_start)
            .map_err(|e| MxcError::backend_error(format!("send ExecStart: {e}")))?;
        w.flush()
            .map_err(|e| MxcError::backend_error(format!("flush EXEC request: {e}")))?;
    }

    // Spawn a background thread that pipes wxc-exec's own stdin to the
    // daemon as FRAME_STDIN frames, so commands running in the sandbox
    // receive whatever the SDK / shell piped in. Review C4.
    //
    // - TTY-stdin: shutdown the IPC writer's write half (sends EOF to
    //   the daemon, which closes guest stdin) and skip the thread; an
    //   interactive caller does not pipe data anyway, and a blocking
    //   stdin read would never return.
    // - Pipe-stdin: spawn a detached thread that reads stdin to EOF and
    //   writes FRAME_STDIN frames. The thread holds its own try_clone of
    //   the IPC stream so it shares the underlying socket without
    //   contending with the read loop below.
    //
    // The thread is detached: when wxc-exec's main process exits shortly
    // after this function returns, the OS reaps the thread. For pipe
    // stdin the parent (SDK) closes its write end before reading the
    // response, so the thread exits naturally on EOF before that point.
    {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            // No data to forward; close the daemon's view of our stdin so
            // the guest sees EOF immediately and `read` calls don't block.
            let _ = stream.shutdown(std::net::Shutdown::Write);
        } else {
            let stdin_writer = stream
                .try_clone()
                .map_err(|e| MxcError::backend_error(format!("clone IPC for stdin: {e}")))?;
            std::thread::spawn(move || {
                use std::io::Read;
                let mut buf = [0u8; 8192];
                let mut writer = stdin_writer;
                let mut stdin = std::io::stdin().lock();
                loop {
                    match stdin.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let frame = ipc_exec::encode_frame(ipc_exec::FRAME_STDIN, &buf[..n]);
                            if writer.write_all(&frame).is_err() {
                                break;
                            }
                            let _ = writer.flush();
                        }
                        Err(_) => break,
                    }
                }
                // EOF / error: close our half so the daemon sees EOF on
                // its IPC reader and shuts down the guest's stdin.
                let _ = writer.shutdown(std::net::Shutdown::Write);
            });
        }
    }

    // Read the status line then the frame stream on a cloned handle so the
    // BufReader's look-ahead cannot strand frame bytes on the raw socket.
    let read_handle = stream
        .try_clone()
        .map_err(|e| MxcError::backend_error(format!("clone IPC stream: {e}")))?;
    read_handle
        .set_read_timeout(Some(IPC_IO_TIMEOUT))
        .map_err(|e| MxcError::backend_error(format!("set IPC read timeout: {e}")))?;
    let mut reader = BufReader::new(read_handle);

    let mut status = String::new();
    reader
        .read_line(&mut status)
        .map_err(|e| MxcError::backend_error(format!("read EXEC status: {e}")))?;
    let status = status.trim();
    if status != IPC_OK {
        return Err(map_exec_status_error(status));
    }

    // The command may run arbitrarily long with no output; switch to blocking
    // reads so a quiet command isn't mistaken for a stalled daemon. The guest
    // enforces the script timeout and the daemon always sends a terminal exit
    // frame, so this cannot block forever on a healthy daemon.
    reader
        .get_ref()
        .set_read_timeout(None)
        .map_err(|e| MxcError::backend_error(format!("clear IPC read timeout: {e}")))?;

    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    loop {
        match ipc_exec::read_frame(&mut reader)
            .map_err(|e| MxcError::backend_error(format!("read exec frame: {e}")))?
        {
            Some(frame) => match frame.kind {
                FRAME_STDOUT => {
                    stdout
                        .write_all(&frame.payload)
                        .map_err(|e| MxcError::backend_error(format!("write stdout: {e}")))?;
                    stdout
                        .flush()
                        .map_err(|e| MxcError::backend_error(format!("flush stdout: {e}")))?;
                }
                FRAME_STDERR => {
                    stderr
                        .write_all(&frame.payload)
                        .map_err(|e| MxcError::backend_error(format!("write stderr: {e}")))?;
                    stderr
                        .flush()
                        .map_err(|e| MxcError::backend_error(format!("flush stderr: {e}")))?;
                }
                FRAME_EXIT => {
                    let exit: ExecExit = serde_json::from_slice(&frame.payload)
                        .map_err(|e| MxcError::backend_error(format!("decode exit frame: {e}")))?;
                    // A negative exit code paired with a message indicates a
                    // guest-side failure (spawn error / timeout); surface it as
                    // an error. A plain non-zero exit is a normal exit code.
                    if exit.exit_code < 0 && !exit.error_message.is_empty() {
                        return Err(MxcError::backend_error(format!(
                            "execution failed: {}",
                            exit.error_message
                        )));
                    }
                    return Ok(exit.exit_code);
                }
                other => {
                    return Err(MxcError::backend_error(format!(
                        "unexpected exec frame kind {other}"
                    )));
                }
            },
            None => {
                return Err(MxcError::backend_error(
                    "daemon closed the connection before sending an exit frame",
                ));
            }
        }
    }
}

/// Send a single nonce-authenticated line command to the daemon and return its
/// trimmed response line.
fn ipc_command(port: u16, verb: &str, nonce: &str) -> Result<String, MxcError> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let stream = TcpStream::connect_timeout(&addr, IPC_CONNECT_TIMEOUT)
        .map_err(|e| MxcError::backend_error(format!("connect daemon IPC on {addr}: {e}")))?;
    stream
        .set_read_timeout(Some(IPC_IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IPC_IO_TIMEOUT)))
        .map_err(|e| MxcError::backend_error(format!("set IPC timeouts: {e}")))?;

    let mut writer = &stream;
    writeln!(writer, "{verb} {nonce}")
        .map_err(|e| MxcError::backend_error(format!("send {verb} to daemon: {e}")))?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| MxcError::backend_error(format!("read daemon response: {e}")))?;
    Ok(line.trim().to_string())
}

/// Spawn the detached daemon for `token`, handing it the auth `nonce` over
/// stdin (kept off the command line so it is not readable cross-process via the
/// PEB / `Win32_Process`). The parent writes `"<nonce>\n"` and closes the pipe;
/// the daemon reads a single bounded line at startup.
fn spawn_daemon(token: &str, nonce: &str) -> Result<std::process::Child, MxcError> {
    use std::io::Write;
    use std::os::windows::process::CommandExt;

    let daemon_path = resolve_sibling_binary("wxc-windows-sandbox-daemon.exe")
        .map_err(|e| MxcError::backend_error(format!("locate daemon binary: {e}")))?;

    let mut child = Command::new(&daemon_path)
        .arg("--token")
        .arg(token)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .map_err(|e| MxcError::backend_error(format!("spawn daemon {daemon_path:?}: {e}")))?;

    // Hand the nonce over stdin, then drop the pipe to deliver EOF. A one-line
    // write is far below the pipe buffer, so this never blocks on a daemon that
    // has not read yet. On any failure, kill the half-started daemon so it does
    // not linger waiting for input.
    let result = (|| {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| MxcError::backend_error("daemon stdin pipe unavailable"))?;
        stdin
            .write_all(format!("{nonce}\n").as_bytes())
            .map_err(|e| MxcError::backend_error(format!("write nonce to daemon stdin: {e}")))?;
        // `stdin` drops here, closing the write end (EOF for the daemon).
        Ok(())
    })();

    if let Err(e) = result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }

    Ok(child)
}

/// Wait for the daemon process described by `pid` / `creation_time` to exit,
/// up to [`DAEMON_EXIT_TIMEOUT`]. PID-reuse-safe: a recycled PID with a
/// different creation time counts as gone. Uses the liveness-aware
/// [`running_process_creation_time`] so a terminated daemon whose kernel object
/// lingers behind a handle this very process may still hold counts as gone
/// (otherwise the wait would spuriously time out).
fn wait_daemon_gone(pid: u32, creation_time: u64) -> Result<(), MxcError> {
    let deadline = Instant::now() + DAEMON_EXIT_TIMEOUT;
    loop {
        if running_process_creation_time(pid) != Some(creation_time) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(MxcError::backend_error(format!(
                "daemon pid {pid} did not exit within {:?} after STOP",
                DAEMON_EXIT_TIMEOUT
            )));
        }
        std::thread::sleep(DAEMON_EXIT_POLL_INTERVAL);
    }
}

impl StatefulSandboxBackend for WindowsSandboxRunner {
    const ID_PREFIX: &'static str = "wsb";
    const BACKEND_KEY: &'static str = "windows_sandbox";

    type ProvisionConfig = ();
    type StartConfig = ();
    type ExecConfig = ();
    type StopConfig = ();
    type DeprovisionConfig = ();
    type ProvisionMetadata = ();
    type StartMetadata = ();
    type StopMetadata = ();
    type DeprovisionMetadata = ();

    fn provision(
        &mut self,
        request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<ProvisionResult<()>, MxcError> {
        // Validate + snapshot the filesystem policy. No side effects on reject.
        let plan = policy::plan_policy(request).map_err(map_policy_error)?;

        let token = mint_random_token();
        let sandbox_id = format!("{}:{}", Self::ID_PREFIX, token);

        let dir = sandbox_dir(&token);
        std::fs::create_dir_all(&dir)
            .map_err(|e| MxcError::backend_error(format!("create sandbox dir {dir:?}: {e}")))?;
        // Lock the per-sandbox scratch dir down to owner-only (inheritable), so
        // the record.json (auth nonce) and any other state written inside are
        // not cross-user readable/tamperable when the temp dir is shared.
        wxc_common::filesystem_dacl::set_owner_only_dacl(&dir, true)
            .map_err(|e| MxcError::backend_error(format!("secure sandbox dir {dir:?}: {e}")))?;

        let mapped_folders: Vec<MappedFolderRecord> = plan
            .mapped_folders
            .iter()
            .map(|m| MappedFolderRecord {
                host: m.host.clone(),
                sandbox: m.sandbox.clone(),
                read_only: m.read_only,
            })
            .collect();

        let record = SandboxRecord::new_provisioned(sandbox_id.clone(), mapped_folders);
        control_plane::atomic_write_json(&sandbox_record_path(&token), &record)
            .map_err(|e| MxcError::backend_error(format!("write sandbox record: {e}")))?;

        Ok(ProvisionResult {
            sandbox_id,
            metadata: None,
        })
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StartResult<()>, MxcError> {
        let token = extract_token(sandbox_id)?;
        let _lock = TransitionLock::acquire(TRANSITION_LOCK_TIMEOUT)
            .map_err(|e| MxcError::backend_error(format!("{e}")))?;

        let mut record = read_sandbox_record(token)
            .map_err(|e| MxcError::backend_error(format!("{e}")))?
            .ok_or_else(|| {
                MxcError::not_provisioned(format!("sandbox {sandbox_id} is not provisioned"))
            })?;

        // Single-slot guard. A live daemon means a sandbox is already running.
        if let Some(d) = live_daemon().map_err(|e| MxcError::backend_error(format!("{e}")))? {
            if d.active_sandbox_id == sandbox_id {
                return Err(MxcError::already_started(format!(
                    "sandbox {sandbox_id} is already started"
                )));
            }
            return Err(MxcError::backend_unavailable(format!(
                "another Windows Sandbox ({}) is already active; only one is supported",
                d.active_sandbox_id
            )));
        }

        // Do NOT pre-delete a stale (dead) daemon record here: the daemon we are
        // about to spawn reads it as the `prior` record to decide whether a
        // running VM is its own reclaimable orphan. The readiness poll below
        // only matches a *live* daemon with our nonce, so leftover dead state
        // cannot fool it. The new daemon overwrites the record on success.

        let nonce = generate_nonce();
        let mut child = spawn_daemon(token, &nonce)?;

        // Wait for the daemon to publish a ready record matching our nonce and
        // sandbox, or to die trying.
        let deadline = Instant::now() + START_READY_TIMEOUT;
        loop {
            if let Some(d) = live_daemon().map_err(|e| MxcError::backend_error(format!("{e}")))? {
                if d.nonce == nonce && d.active_sandbox_id == sandbox_id && d.ready {
                    break;
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(MxcError::backend_error(format!(
                        "daemon exited during start ({status}); see daemon logs"
                    )));
                }
                Ok(None) => {}
                Err(e) => {
                    return Err(MxcError::backend_error(format!("poll daemon: {e}")));
                }
            }
            if Instant::now() >= deadline {
                // The daemon serves IPC throughout boot, so ask it to gracefully
                // tear down its (possibly half-launched) VM rather than orphaning
                // a live VM with a blind kill. On graceful STOP the daemon removes
                // its own record. We intentionally do NOT delete the record here:
                // if the kill fallback leaves an orphan, the record (with its
                // recorded VM process identities, when ready) is the proof a later
                // daemon needs to reclaim it instead of refusing.
                if let Ok(Some(d)) = read_daemon_record() {
                    if d.nonce == nonce && d.active_sandbox_id == sandbox_id {
                        let _ = ipc_command(d.ipc_port, IPC_STOP, &d.nonce);
                        if wait_daemon_gone(d.pid, d.pid_creation_time).is_err() {
                            eprintln!(
                                "[wsb] start timeout: daemon (pid {}) did not stop gracefully; \
                                 killing it (a leftover VM, if any, will be reclaimed on next start)",
                                d.pid
                            );
                        }
                    }
                }
                let _ = child.kill();
                return Err(MxcError::backend_error(format!(
                    "daemon did not become ready within {:?}",
                    START_READY_TIMEOUT
                )));
            }
            std::thread::sleep(START_POLL_INTERVAL);
        }

        record.state = SandboxState::Started;
        control_plane::atomic_write_json(&sandbox_record_path(token), &record)
            .map_err(|e| MxcError::backend_error(format!("update sandbox record: {e}")))?;

        Ok(StartResult { metadata: None })
    }

    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<ExecHandle, MxcError> {
        extract_token(sandbox_id)?;

        // Locate the live daemon holding this sandbox and confirm it is ready
        // to run (the VM booted and the guest connection is held).
        let daemon = live_daemon()
            .map_err(|e| MxcError::backend_error(format!("{e}")))?
            .ok_or_else(|| MxcError::not_started(format!("sandbox {sandbox_id} is not started")))?;
        if daemon.active_sandbox_id != sandbox_id {
            return Err(MxcError::not_started(format!(
                "sandbox {sandbox_id} is not the active started sandbox"
            )));
        }
        if !daemon.ready {
            return Err(MxcError::not_started(format!(
                "sandbox {sandbox_id} is still starting"
            )));
        }

        // Stream the execution synchronously, relaying stdout/stderr live to
        // this process's stdio. Mirrors isolation_session: the relay completes
        // inside this call, so the returned handle carries sentinel pipe
        // handles plus a waiter that yields the captured exit code, and the
        // dispatcher's `relay_exec_to_stdio` is a thin call-through.
        let exit_code = run_exec_stream(&daemon, request)?;

        let null = HANDLE(std::ptr::null_mut());
        Ok(ExecHandle {
            stdout: null,
            stderr: null,
            stdin: null,
            waiter: Box::new(move || Ok(exit_code)),
            terminator: Box::new(|| {}),
        })
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StopResult<()>, MxcError> {
        let token = extract_token(sandbox_id)?;
        let _lock = TransitionLock::acquire(TRANSITION_LOCK_TIMEOUT)
            .map_err(|e| MxcError::backend_error(format!("{e}")))?;

        let mut record = read_sandbox_record(token)
            .map_err(|e| MxcError::backend_error(format!("{e}")))?
            .ok_or_else(|| {
                MxcError::not_provisioned(format!("sandbox {sandbox_id} is not provisioned"))
            })?;

        match live_daemon().map_err(|e| MxcError::backend_error(format!("{e}")))? {
            Some(d) if d.active_sandbox_id == sandbox_id => {
                let resp = ipc_command(d.ipc_port, IPC_STOP, &d.nonce)?;
                if resp != IPC_OK {
                    return Err(MxcError::backend_error(format!(
                        "daemon rejected STOP: {resp}"
                    )));
                }
                wait_daemon_gone(d.pid, d.pid_creation_time)?;
                let _ = std::fs::remove_file(daemon_record_path());
            }
            Some(d) => {
                // A live daemon exists but is holding a different sandbox.
                // Refuse rather than silently no-op (which would let the
                // user think `stop` succeeded while another sandbox is
                // still active).
                return Err(MxcError::backend_error(format!(
                    "a different sandbox is currently active in the host slot: {}",
                    d.active_sandbox_id
                )));
            }
            None => {
                // No live daemon. If the record never reached Started this is
                // a no-op already-stopped; otherwise the daemon crashed and
                // may have left a live orphan VM. Reclaim per review B5:
                // pure classifier + HostVmLock + ConfirmedGone gate.
                if record.state != SandboxState::Started {
                    return Err(MxcError::already_stopped(format!(
                        "sandbox {sandbox_id} is not started"
                    )));
                }
                cleanup_stale_daemon_orphan(sandbox_id)?;
            }
        }

        record.state = SandboxState::Stopped;
        control_plane::atomic_write_json(&sandbox_record_path(token), &record)
            .map_err(|e| MxcError::backend_error(format!("update sandbox record: {e}")))?;

        Ok(StopResult { metadata: None })
    }

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<DeprovisionResult<()>, MxcError> {
        let token = extract_token(sandbox_id)?;
        let _lock = TransitionLock::acquire(TRANSITION_LOCK_TIMEOUT)
            .map_err(|e| MxcError::backend_error(format!("{e}")))?;

        let record = read_sandbox_record(token)
            .map_err(|e| MxcError::backend_error(format!("{e}")))?
            .ok_or_else(|| {
                MxcError::not_provisioned(format!("sandbox {sandbox_id} is not provisioned"))
            })?;

        // If a daemon still holds this sandbox, it owns a live VM that MUST be
        // torn down before we delete the records that let us find it again. A
        // failed stop here is fatal: deleting the records would orphan the VM
        // and strand the single-instance slot.
        match live_daemon().map_err(|e| MxcError::backend_error(format!("{e}")))? {
            Some(d) if d.active_sandbox_id == sandbox_id => {
                let resp = ipc_command(d.ipc_port, IPC_STOP, &d.nonce)?;
                if resp != IPC_OK {
                    return Err(MxcError::backend_error(format!(
                        "daemon rejected STOP during deprovision: {resp}"
                    )));
                }
                wait_daemon_gone(d.pid, d.pid_creation_time)?;
                let _ = std::fs::remove_file(daemon_record_path());
            }
            Some(d) => {
                return Err(MxcError::backend_error(format!(
                    "a different sandbox is currently active in the host slot: {}; deprovision \
                     {} first",
                    d.active_sandbox_id, d.active_sandbox_id
                )));
            }
            None => {
                // No live daemon. If the sandbox was ever started, a crashed
                // daemon may have left a live orphan VM that must be torn
                // down before we delete the per-sandbox records (else the
                // single-instance slot is stranded with no record to find
                // it). For sandboxes that never reached Started, there can
                // be no orphan, so skip the cleanup path entirely.
                if record.state == SandboxState::Started {
                    cleanup_stale_daemon_orphan(sandbox_id)?;
                }
            }
        }

        let dir = sandbox_dir(token);
        if let Err(e) = std::fs::remove_dir_all(&dir) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(MxcError::backend_error(format!(
                    "remove sandbox dir {dir:?}: {e}"
                )));
            }
        }

        Ok(DeprovisionResult { metadata: None })
    }

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        policy::plan_policy(request)
            .map(|_| ())
            .map_err(map_policy_error)
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_token(sandbox_id)?;
        reject_post_provision_policy(request)
    }

    fn validate_exec(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_token(sandbox_id)?;
        reject_post_provision_policy(request)
    }

    fn validate_stop(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_token(sandbox_id)?;
        reject_post_provision_policy(request)
    }

    fn validate_deprovision(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_token(sandbox_id)?;
        reject_post_provision_policy(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{ContainerPolicy, NetworkPolicy};
    use wxc_common::mxc_error::MxcErrorCode;

    #[test]
    fn backend_key_matches_wire_format() {
        assert_eq!(
            <WindowsSandboxRunner as StatefulSandboxBackend>::BACKEND_KEY,
            "windows_sandbox"
        );
    }

    #[test]
    fn id_prefix_matches_wire_format() {
        assert_eq!(
            <WindowsSandboxRunner as StatefulSandboxBackend>::ID_PREFIX,
            "wsb"
        );
    }

    #[test]
    fn extract_token_unwraps_wsb_prefix() {
        assert_eq!(extract_token("wsb:deadbeef").unwrap(), "deadbeef");
    }

    #[test]
    fn extract_token_rejects_other_prefix() {
        let err = extract_token("iso:abc").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_token_rejects_missing_colon() {
        let err = extract_token("wsbabc").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_token_rejects_empty_token() {
        let err = extract_token("wsb:").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_token_rejects_path_traversal_dots() {
        // The original permissive grammar allowed ".." in the token, which
        // fed straight into sandbox_dir() and (worst case) remove_dir_all()
        // outside state_aware_root() during deprovision. Strict
        // [a-f0-9]{1,128} forbids ".".
        let err = extract_token("wsb:..").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
        let err = extract_token("wsb:..\\..\\foo").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
        let err = extract_token("wsb:../../etc/passwd").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_token_rejects_absolute_path_form() {
        let err = extract_token("wsb:/etc/shadow").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
        let err = extract_token("wsb:C:\\Windows").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_token_rejects_uppercase_hex() {
        // Grammar is intentionally lowercase-only to match mint_random_token's
        // output. A future widening is fine but should happen via an explicit
        // grammar change, not via a permissive accept.
        let err = extract_token("wsb:DEADBEEF").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_token_rejects_non_hex_chars() {
        for s in [
            "wsb:dead beef",
            "wsb:dead\nbeef",
            "wsb:dead\0beef",
            "wsb:zzzz",
        ] {
            let err = extract_token(s).unwrap_err();
            assert_eq!(
                err.code,
                MxcErrorCode::MalformedId,
                "expected MalformedId for {s:?}"
            );
        }
    }

    #[test]
    fn extract_token_rejects_oversized_token() {
        // Hard cap at 128 chars so a hostile caller cannot grow the token
        // unboundedly. mint_random_token produces 8; UUID-hex would be 32.
        let too_long = "a".repeat(129);
        let err = extract_token(&format!("wsb:{too_long}")).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_token_accepts_8_to_128_lowercase_hex() {
        for n in [1usize, 8, 32, 128] {
            let token = "0".repeat(n);
            let s = format!("wsb:{token}");
            assert_eq!(extract_token(&s).unwrap(), token);
        }
    }

    #[test]
    fn is_valid_sandbox_token_rejects_each_meta_character() {
        for ch in [
            '.', '/', '\\', ' ', '\0', '\n', '\r', '\t', '*', '?', ':', '"',
        ] {
            let s = format!("dead{ch}beef");
            assert!(
                !is_valid_sandbox_token(&s),
                "is_valid_sandbox_token incorrectly accepted {s:?}"
            );
        }
    }

    #[test]
    fn reject_post_provision_policy_accepts_default() {
        let req = ExecutionRequest::default();
        reject_post_provision_policy(&req).unwrap();
    }

    #[test]
    fn reject_post_provision_policy_rejects_readwrite() {
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\work".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = reject_post_provision_policy(&req).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn reject_post_provision_policy_rejects_denied_paths() {
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                denied_paths: vec!["C:\\secret".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = reject_post_provision_policy(&req).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn map_policy_error_maps_policy_to_validation() {
        let err = map_policy_error(OneShotError::Policy("nope".into()));
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_start_rejects_non_default_network() {
        let backend = WindowsSandboxRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                allowed_hosts: vec!["example.com".into()],
                default_network_policy: NetworkPolicy::Block,
                ..Default::default()
            },
            ..Default::default()
        };
        let err = backend
            .validate_start("wsb:abcd1234", &req, None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn exec_without_live_daemon_is_not_started() {
        let mut backend = WindowsSandboxRunner::new();
        let err = backend
            .exec("wsb:abcd1234", &ExecutionRequest::default(), None)
            .unwrap_err();
        // With no daemon holding the sandbox, exec reports NotStarted rather
        // than running anything.
        assert_eq!(err.code, MxcErrorCode::NotStarted);
    }

    #[test]
    fn exec_rejects_malformed_id_first() {
        let mut backend = WindowsSandboxRunner::new();
        let err = backend
            .exec("iso:abc", &ExecutionRequest::default(), None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn map_exec_status_error_busy_is_backend_error() {
        let err = map_exec_status_error("ERR busy");
        assert_eq!(err.code, MxcErrorCode::BackendError);
        assert!(err.message.contains("busy"), "message: {}", err.message);
    }

    #[test]
    fn map_exec_status_error_not_ready_is_not_started() {
        let err = map_exec_status_error("ERR not ready");
        assert_eq!(err.code, MxcErrorCode::NotStarted);
    }

    #[test]
    fn map_exec_status_error_unknown_reason_is_backend_error_with_reason() {
        let err = map_exec_status_error("ERR something exploded");
        assert_eq!(err.code, MxcErrorCode::BackendError);
        assert!(
            err.message.contains("something exploded"),
            "message: {}",
            err.message
        );
    }

    #[test]
    fn map_exec_status_error_without_err_prefix_uses_whole_status() {
        // Defensive: a status line missing the `ERR` prefix is still surfaced
        // verbatim rather than swallowed.
        let err = map_exec_status_error("garbage");
        assert_eq!(err.code, MxcErrorCode::BackendError);
        assert!(err.message.contains("garbage"), "message: {}", err.message);
    }

    #[test]
    fn map_exec_status_error_requires_space_after_err_prefix() {
        // `ERRbusy` (no separating space) must NOT normalize to the busy token;
        // it is surfaced as an unrecognized status, not a single-flight error.
        let err = map_exec_status_error("ERRbusy");
        assert_eq!(err.code, MxcErrorCode::BackendError);
        assert!(err.message.contains("ERRbusy"), "message: {}", err.message);
    }
}
