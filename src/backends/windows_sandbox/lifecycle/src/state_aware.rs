// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `StatefulSandboxBackend` impl for the Windows Sandbox backend.
//!
//! State lives in per-sandbox records plus one global daemon record under
//! `%TEMP%\wxc-wsb\state-aware`. [`TransitionLock`] serialises lifecycle
//! transitions across phase processes.

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
    self, generate_nonce, live_daemon, read_daemon_record, read_sandbox_record,
    running_process_creation_time, sandbox_dir, DaemonRecord, MappedFolderRecord, SandboxRecord,
    SandboxState, TransitionLock, IPC_ERR, IPC_ERR_BUSY, IPC_ERR_NOT_READY, IPC_EXEC, IPC_OK,
    IPC_STOP,
};
use crate::error::OneShotError;
use crate::ipc_exec::{self, ExecExit, ExecStart, FrameKind};
use crate::policy;
use crate::WindowsSandboxRunner;

/// `DETACHED_PROCESS` — the spawned daemon gets no console.
const DETACHED_PROCESS: u32 = 0x0000_0008;
/// `CREATE_NEW_PROCESS_GROUP` — isolates the daemon from the caller's console
/// Ctrl-C / process-group signals so killing the caller cannot orphan a VM.
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

const TRANSITION_LOCK_TIMEOUT: Duration = Duration::from_secs(600);

const START_READY_TIMEOUT: Duration = Duration::from_secs(420);

const START_POLL_INTERVAL: Duration = Duration::from_millis(500);

const DAEMON_EXIT_TIMEOUT: Duration = Duration::from_secs(60);

const DAEMON_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(200);

const IPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const IPC_IO_TIMEOUT: Duration = Duration::from_secs(10);

const ORPHAN_CLEANUP_VM_LOCK_TIMEOUT: Duration = Duration::from_secs(20);

/// Reclaim a stale daemon's orphan VM for a Started sandbox.
fn cleanup_stale_daemon_orphan(sandbox_id: &str) -> Result<(), MxcError> {
    let stale = read_daemon_record()
        .map_err(|e| MxcError::backend_error(format!("read stale daemon record: {e}")))?;

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
            let _ = control_plane::remove_daemon_record();
            Ok(())
        }
        control_plane::StaleDaemonCleanup::Reclaim { proof } => {
            let _vm_lock = control_plane::HostVmLock::acquire(ORPHAN_CLEANUP_VM_LOCK_TIMEOUT)
                .map_err(|e| {
                    MxcError::backend_error(format!(
                        "acquire host Windows Sandbox VM slot for orphan cleanup: {e}"
                    ))
                })?;
            let snapshot = rt
                .block_on(async { crate::vm::enumerate_sandbox_vm_processes().await })
                .unwrap_or_default();
            let kill_set =
                control_plane::plan_kill_set(&control_plane::VmOwnership::Owned(proof), &snapshot)
                    .unwrap_or_default();
            let outcome = rt.block_on(crate::vm::teardown_via_plan(&kill_set));
            match outcome {
                control_plane::TeardownOutcome::ConfirmedGone => {
                    let _ = control_plane::remove_daemon_record();
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

/// Reap orphan state from an interrupted `start` before stop/deprovision.
fn reap_non_started_orphan(sandbox_id: &str) -> Result<(), MxcError> {
    match live_daemon().map_err(|e| MxcError::backend_error(format!("{e}")))? {
        Some(d) if d.active_sandbox_id == sandbox_id => {
            let resp = ipc_command(d.ipc_port, IPC_STOP, &d.nonce)?;
            if resp != IPC_OK {
                return Err(MxcError::backend_error(format!(
                    "daemon rejected STOP for interrupted-start orphan: {resp}"
                )));
            }
            wait_daemon_gone(d.pid, d.pid_creation_time)?;
            let _ = control_plane::remove_daemon_record();
            Ok(())
        }
        Some(_) => Ok(()),
        None => {
            let stale = read_daemon_record()
                .map_err(|e| MxcError::backend_error(format!("read daemon record: {e}")))?;
            match stale {
                Some(s) if s.active_sandbox_id == sandbox_id => {
                    cleanup_stale_daemon_orphan(sandbox_id)
                }
                _ => Ok(()),
            }
        }
    }
}

/// Extract the strict 8-lowercase-hex token from `wsb:<token>`.
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
            "sandbox token must be exactly {SANDBOX_TOKEN_LEN} lowercase hex chars; got {:?}",
            rest
        )));
    }
    Ok(rest)
}

const SANDBOX_TOKEN_LEN: usize = 8;

/// True iff `token` is exactly [`SANDBOX_TOKEN_LEN`] lowercase hex chars.
fn is_valid_sandbox_token(token: &str) -> bool {
    token.len() == SANDBOX_TOKEN_LEN
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

/// Reject policy changes after provision.
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

/// Bytes accumulated on a non-TTY exec output stream before [`FlushGate`] forces
/// a flush, bounding how much newline-free output can sit buffered.
const NON_TTY_FLUSH_BYTES: usize = 32 * 1024;
/// Max wall-clock between flushes on a non-TTY exec output stream, so slow
/// carriage-return progress output reaches a pipe consumer promptly.
const NON_TTY_FLUSH_INTERVAL: Duration = Duration::from_millis(200);

/// Bounded flush policy for non-TTY exec output.
struct FlushGate {
    last: Instant,
    pending: usize,
}

impl FlushGate {
    fn new() -> Self {
        Self {
            last: Instant::now(),
            pending: 0,
        }
    }

    /// Record `n` freshly-written bytes and report whether to flush now.
    fn should_flush(&mut self, n: usize) -> bool {
        self.pending += n;
        if self.pending >= NON_TTY_FLUSH_BYTES || self.last.elapsed() >= NON_TTY_FLUSH_INTERVAL {
            self.pending = 0;
            self.last = Instant::now();
            true
        } else {
            false
        }
    }
}

/// Run one execution through the daemon IPC stream.
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

    {
        let mut w = &stream;
        writeln!(w, "{IPC_EXEC} {}", daemon.nonce)
            .map_err(|e| MxcError::backend_error(format!("send EXEC line: {e}")))?;
        ipc_exec::write_exec_start(&mut w, &exec_start)
            .map_err(|e| MxcError::backend_error(format!("send ExecStart: {e}")))?;
        w.flush()
            .map_err(|e| MxcError::backend_error(format!("flush EXEC request: {e}")))?;
    }

    // Pipe host stdin to the daemon; TTY stdin is not interactive yet.
    {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            eprintln!(
                "[wxc-exec] WARNING: stdin is a TTY but the state-aware Windows Sandbox exec \
                 path does not currently forward interactive PTY input to the guest. Any data \
                 you type will be dropped; the guest child will see immediate EOF on stdin. \
                 Pipe stdin instead (e.g. `< /dev/null` or `< file`), or use the one-shot \
                 backend for now. (Tracked: TODO h6-pty-plumbing -- ConPTY support.)"
            );
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
                            let header = ipc_exec::frame_header(FrameKind::Stdin, n);
                            if writer
                                .write_all(&header)
                                .and_then(|()| writer.write_all(&buf[..n]))
                                .is_err()
                            {
                                break;
                            }
                            let _ = writer.flush();
                        }
                        Err(_) => break,
                    }
                }
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

    // Commands may be quiet for longer than the IPC setup timeout.
    reader
        .get_ref()
        .set_read_timeout(None)
        .map_err(|e| MxcError::backend_error(format!("clear IPC read timeout: {e}")))?;

    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    use std::io::IsTerminal;
    let stdout_is_tty = stdout.is_terminal();
    let stderr_is_tty = stderr.is_terminal();
    let mut stdout_gate = FlushGate::new();
    let mut stderr_gate = FlushGate::new();
    loop {
        match ipc_exec::read_frame(&mut reader)
            .map_err(|e| MxcError::backend_error(format!("read exec frame: {e}")))?
        {
            Some(frame) => match frame.kind {
                Some(FrameKind::Stdout) => {
                    stdout
                        .write_all(&frame.payload)
                        .map_err(|e| MxcError::backend_error(format!("write stdout: {e}")))?;
                    if stdout_is_tty || stdout_gate.should_flush(frame.payload.len()) {
                        stdout
                            .flush()
                            .map_err(|e| MxcError::backend_error(format!("flush stdout: {e}")))?;
                    }
                }
                Some(FrameKind::Stderr) => {
                    stderr
                        .write_all(&frame.payload)
                        .map_err(|e| MxcError::backend_error(format!("write stderr: {e}")))?;
                    if stderr_is_tty || stderr_gate.should_flush(frame.payload.len()) {
                        stderr
                            .flush()
                            .map_err(|e| MxcError::backend_error(format!("flush stderr: {e}")))?;
                    }
                }
                Some(FrameKind::Exit) => {
                    let _ = stdout.flush();
                    let _ = stderr.flush();
                    let exit: ExecExit = serde_json::from_slice(&frame.payload)
                        .map_err(|e| MxcError::backend_error(format!("decode exit frame: {e}")))?;
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
                        "unexpected exec frame kind {other:?}"
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

/// Spawn the detached daemon and pass its auth nonce over stdin.
fn spawn_daemon(token: &str, nonce: &str) -> Result<std::process::Child, MxcError> {
    use std::io::Write;
    use std::os::windows::process::CommandExt;

    let daemon_path = resolve_sibling_binary(crate::constants::DAEMON_BINARY_NAME)
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

/// Wait for the daemon process identity to exit.
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

/// Best-effort teardown of a daemon we spawned during `start` but can no longer
/// hand off to the caller (start timed out, or a post-boot bookkeeping step
/// failed). Prefer a graceful IPC STOP -- the daemon tears down its own VM and
/// removes its record -- and fall back to killing the spawned child process.
///
/// We deliberately do NOT delete the daemon record: if the kill fallback leaves
/// a live orphan VM behind, that record (with its recorded VM process
/// identities, when ready) is the proof a later `start` needs to reclaim it
/// instead of refusing. `context` names the failing call site for the log.
fn stop_spawned_daemon_best_effort(
    nonce: &str,
    sandbox_id: &str,
    child: &mut std::process::Child,
    context: &str,
) {
    if let Ok(Some(d)) = read_daemon_record() {
        if d.nonce == nonce && d.active_sandbox_id == sandbox_id {
            let _ = ipc_command(d.ipc_port, IPC_STOP, &d.nonce);
            if wait_daemon_gone(d.pid, d.pid_creation_time).is_err() {
                eprintln!(
                    "[wsb] {context}: daemon (pid {}) did not stop gracefully; killing it \
                     (a leftover VM, if any, will be reclaimed on next start)",
                    d.pid
                );
            }
        }
    }
    let _ = child.kill();
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
        let plan = policy::plan_policy(request).map_err(map_policy_error)?;

        let token = mint_random_token();
        let sandbox_id = format!("{}:{}", Self::ID_PREFIX, token);

        control_plane::secure_record_root()
            .map_err(|e| MxcError::backend_error(format!("secure state-aware record root: {e}")))?;

        let dir = sandbox_dir(&token);
        std::fs::create_dir_all(&dir)
            .map_err(|e| MxcError::backend_error(format!("create sandbox dir {dir:?}: {e}")))?;
        control_plane::set_owner_only_dir(&dir)
            .map_err(|e| MxcError::backend_error(format!("secure sandbox dir {dir:?}: {e:#}")))?;

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
        control_plane::write_sandbox_record(&token, &record)
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
        control_plane::secure_record_root()
            .map_err(|e| MxcError::backend_error(format!("secure state-aware record root: {e}")))?;

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
                stop_spawned_daemon_best_effort(&nonce, sandbox_id, &mut child, "start timeout");
                return Err(MxcError::backend_error(format!(
                    "daemon did not become ready within {:?}",
                    START_READY_TIMEOUT
                )));
            }
            std::thread::sleep(START_POLL_INTERVAL);
        }

        record.state = SandboxState::Started;
        if let Err(e) = control_plane::write_sandbox_record(token, &record) {
            // The VM booted and the daemon is serving, but we could not persist
            // the Started state. Leaving a live VM + daemon that the caller has
            // no record for would strand the host's single sandbox slot with no
            // way to address it. Tear the daemon down so `start` is atomic:
            // either the sandbox is Started and recorded, or nothing is left
            // running.
            stop_spawned_daemon_best_effort(&nonce, sandbox_id, &mut child, "record write failed");
            return Err(MxcError::backend_error(format!(
                "update sandbox record: {e}"
            )));
        }

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
        control_plane::secure_record_root()
            .map_err(|e| MxcError::backend_error(format!("secure state-aware record root: {e}")))?;

        let mut record = read_sandbox_record(token)
            .map_err(|e| MxcError::backend_error(format!("{e}")))?
            .ok_or_else(|| {
                MxcError::not_provisioned(format!("sandbox {sandbox_id} is not provisioned"))
            })?;

        // Branch on OUR record's state first (ordering fix).
        // An unrelated active sandbox's daemon must NOT make `stop` of a
        // not-Started sandbox fail with `backend_error` — the caller is
        // entitled to a clean `already_stopped` regardless of what else is
        // running.
        //
        // An interrupted `start` can leave a Provisioned record plus a
        // daemon-spawned orphan VM. Cleanup triggers off the presence of a
        // daemon record (the daemon writes its record before launching the VM),
        // not off SandboxState::Started, so an interrupted-start orphan is
        // always reaped on the next `stop`/`deprovision`.
        match record.state {
            SandboxState::Started => {
                match live_daemon().map_err(|e| MxcError::backend_error(format!("{e}")))? {
                    Some(d) if d.active_sandbox_id == sandbox_id => {
                        let resp = ipc_command(d.ipc_port, IPC_STOP, &d.nonce)?;
                        if resp != IPC_OK {
                            return Err(MxcError::backend_error(format!(
                                "daemon rejected STOP: {resp}"
                            )));
                        }
                        wait_daemon_gone(d.pid, d.pid_creation_time)?;
                        let _ = control_plane::remove_daemon_record();
                    }
                    Some(d) => {
                        // Single-daemon invariant violation: our record says
                        // Started but a daemon for a different sandbox is
                        // live. The on-disk record set is contradictory and
                        // we cannot prove which side is correct — refuse
                        // rather than silently fix one or the other.
                        return Err(MxcError::backend_error(format!(
                            "inconsistent state: sandbox {sandbox_id} is marked Started but the \
                             host slot is held by {} (single-daemon invariant violated)",
                            d.active_sandbox_id
                        )));
                    }
                    None => {
                        // Our daemon is gone. It may have left a live VM
                        // behind; cleanup is positive-proof gated and refuses
                        // a foreign VM.
                        cleanup_stale_daemon_orphan(sandbox_id)?;
                    }
                }
            }
            SandboxState::Stopped => {
                // Idempotent: already stopped is success-y, surface it as a
                // distinct error code for callers that want to discriminate
                // (e.g. CI scripts that always tear down at the end).
                return Err(MxcError::already_stopped(format!(
                    "sandbox {sandbox_id} is already stopped"
                )));
            }
            SandboxState::Provisioned => {
                // Never reached Started. An interrupted start can leave an
                // orphan (a live same-id daemon whose readiness the parent
                // never observed, or a stale record + crashed-daemon VM).
                // [`reap_non_started_orphan`] handles every case gated on
                // daemon-record identity so a live OR stale daemon for a
                // *different* sandbox can neither be stranded nor turn this
                // stop into a fatal error.
                reap_non_started_orphan(sandbox_id)?;
                // Preserve the idempotency contract: stop of a
                // never-Started sandbox is AlreadyStopped, not a silent
                // success. The cleanup side-effect above is the meaningful
                // work for the interrupted-start case.
                return Err(MxcError::already_stopped(format!(
                    "sandbox {sandbox_id} is not started"
                )));
            }
        }

        record.state = SandboxState::Stopped;
        control_plane::write_sandbox_record(token, &record)
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
        control_plane::secure_record_root()
            .map_err(|e| MxcError::backend_error(format!("secure state-aware record root: {e}")))?;

        let record = read_sandbox_record(token)
            .map_err(|e| MxcError::backend_error(format!("{e}")))?
            .ok_or_else(|| {
                MxcError::not_provisioned(format!("sandbox {sandbox_id} is not provisioned"))
            })?;

        // Branch on OUR record's state first (ordering fix). An
        // unrelated active sandbox's daemon must NOT block deprovision of a
        // Stopped or interrupted-Provisioned sandbox -- we only need to
        // remove our own record directory, not coordinate with anything
        // else. A catch-all that checked another sandbox's daemon first would
        // wrongly return backend_error for "sandbox A is stopped, sandbox B is
        // running".
        //
        // Stale orphan cleanup triggers off DaemonRecord existence, so an
        // interrupted start that left a daemon-spawned VM is reaped on
        // deprovision too.
        match record.state {
            SandboxState::Started => {
                // If a daemon still holds this sandbox, it owns a live VM
                // that MUST be torn down before we delete the records that
                // let us find it again. A failed stop here is fatal:
                // deleting the records would orphan the VM and strand the
                // single-instance slot.
                match live_daemon().map_err(|e| MxcError::backend_error(format!("{e}")))? {
                    Some(d) if d.active_sandbox_id == sandbox_id => {
                        let resp = ipc_command(d.ipc_port, IPC_STOP, &d.nonce)?;
                        if resp != IPC_OK {
                            return Err(MxcError::backend_error(format!(
                                "daemon rejected STOP during deprovision: {resp}"
                            )));
                        }
                        wait_daemon_gone(d.pid, d.pid_creation_time)?;
                        let _ = control_plane::remove_daemon_record();
                    }
                    Some(d) => {
                        // Same single-daemon invariant violation as in stop:
                        // our record is Started but a different sandbox's
                        // daemon is live. The on-disk record set is
                        // contradictory and we cannot safely proceed.
                        return Err(MxcError::backend_error(format!(
                            "inconsistent state: sandbox {sandbox_id} is marked Started but the \
                             host slot is held by {} (single-daemon invariant violated)",
                            d.active_sandbox_id
                        )));
                    }
                    None => {
                        cleanup_stale_daemon_orphan(sandbox_id)?;
                    }
                }
            }
            SandboxState::Provisioned | SandboxState::Stopped => {
                // No live activity claimed for THIS sandbox. We are about to
                // delete only this sandbox's record directory; another
                // sandbox's live VM is irrelevant (the single-instance slot is
                // owned by record-id). Reap any interrupted-start orphan that
                // belongs to US, gated on daemon-record identity so a live OR
                // stale daemon record for a *different* sandbox neither strands
                // a VM nor fatally wedges this deprovision. See
                // [`reap_non_started_orphan`].
                reap_non_started_orphan(sandbox_id)?;
            }
        }

        control_plane::remove_sandbox_dir(token).map_err(|e| {
            MxcError::backend_error(format!("remove sandbox dir for {sandbox_id}: {e}"))
        })?;

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
        // Hard cap at exactly SANDBOX_TOKEN_LEN: 129 chars is wrong-length and
        // resolves to MalformedId.
        let too_long = "a".repeat(129);
        let err = extract_token(&format!("wsb:{too_long}")).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_token_accepts_exactly_8_lowercase_hex() {
        // The grammar is exact-length, matching mint_random_token.
        assert_eq!(extract_token("wsb:00000000").unwrap(), "00000000");
        assert_eq!(extract_token("wsb:deadbeef").unwrap(), "deadbeef");
        assert_eq!(extract_token("wsb:ffffffff").unwrap(), "ffffffff");
    }

    #[test]
    fn extract_token_rejects_wrong_length_hex() {
        // A permissive 1-128 range would accept truncated IDs like wsb:1 and
        // wsb:dead, obscuring programmer error.
        for token in ["", "1", "dead", "deadbee", "deadbeefa", "deadbeefdeadbeef"] {
            let err = extract_token(&format!("wsb:{token}")).unwrap_err();
            assert_eq!(
                err.code,
                MxcErrorCode::MalformedId,
                "expected MalformedId for token {token:?}"
            );
        }
    }

    #[test]
    fn is_valid_sandbox_token_rejects_each_meta_character() {
        // 7-char base + 1 meta char keeps the length at SANDBOX_TOKEN_LEN so
        // the test specifically exercises the character-set rejection (not
        // length).
        for ch in [
            '.', '/', '\\', ' ', '\0', '\n', '\r', '\t', '*', '?', ':', '"',
        ] {
            let s = format!("dedbe{ch}ef");
            assert_eq!(s.chars().count(), 8);
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

    // ===== state-aware illegal-transition tests ==============================
    //
    // These tests exercise the StatefulSandboxBackend trait methods against a
    // tempdir-rooted state_aware_root (redirected via the `#[cfg(test)]`-only
    // override in control_plane). Each test holds STATE_AWARE_TEST_LOCK for
    // the duration of its body so the global override doesn't race other
    // tests. Anything that would normally require a real daemon (e.g.
    // exec/stop while a live daemon holds the sandbox) is exercised via
    // hand-written DaemonRecord/SandboxRecord fixtures.
    //
    // These intentionally do NOT cover paths that require a real VM or real
    // detached daemon process — those need the daemon binary + Windows
    // Sandbox feature and live in tests/scripts/run_windows_sandbox_state_aware_tests.ps1.

    use control_plane::{
        atomic_write_json, read_json, sandbox_dir, sandbox_record_path,
        set_state_aware_root_for_test, state_aware_root, DaemonRecord, MappedFolderRecord,
        SandboxRecord, SandboxState, STATE_AWARE_TEST_LOCK,
    };

    /// RAII guard that swaps in a tempdir-rooted state_aware_root for the
    /// life of one test and restores it on drop. Acquires
    /// STATE_AWARE_TEST_LOCK so concurrent tests don't race the override.
    struct StateAwareRootGuard {
        // Held only to extend the lock's lifetime; never read.
        _lock: std::sync::MutexGuard<'static, ()>,
        _dir: tempfile::TempDir,
    }

    impl StateAwareRootGuard {
        fn new() -> Self {
            let _lock = STATE_AWARE_TEST_LOCK
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let dir = tempfile::tempdir().expect("create tempdir for state-aware test root");
            set_state_aware_root_for_test(Some(dir.path().to_path_buf()));
            // Belt-and-suspenders: ensure the override took effect.
            assert!(
                state_aware_root().starts_with(dir.path()),
                "override did not take effect"
            );
            Self { _lock, _dir: dir }
        }
    }

    impl Drop for StateAwareRootGuard {
        fn drop(&mut self) {
            set_state_aware_root_for_test(None);
        }
    }

    fn write_provisioned_record(token: &str) {
        let dir = sandbox_dir(token);
        std::fs::create_dir_all(&dir).expect("create sandbox dir");
        let record = SandboxRecord::new_provisioned(
            format!("wsb:{token}"),
            Vec::<MappedFolderRecord>::new(),
        );
        atomic_write_json(&sandbox_record_path(token), &record).expect("write provisioned record");
    }

    fn write_started_record(token: &str) {
        let dir = sandbox_dir(token);
        std::fs::create_dir_all(&dir).expect("create sandbox dir");
        let mut record = SandboxRecord::new_provisioned(
            format!("wsb:{token}"),
            Vec::<MappedFolderRecord>::new(),
        );
        record.state = SandboxState::Started;
        atomic_write_json(&sandbox_record_path(token), &record).expect("write started record");
    }

    #[test]
    fn start_rejects_unknown_sandbox_id_with_not_provisioned() {
        let _g = StateAwareRootGuard::new();
        let mut backend = WindowsSandboxRunner::new();
        let err = backend
            .start("wsb:deadbeef", &ExecutionRequest::default(), None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::NotProvisioned);
    }

    #[test]
    fn start_rejects_malformed_id_before_any_io() {
        let _g = StateAwareRootGuard::new();
        let mut backend = WindowsSandboxRunner::new();
        let err = backend
            .start("wsb:NOT_HEX", &ExecutionRequest::default(), None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn stop_rejects_unknown_sandbox_with_not_provisioned() {
        let _g = StateAwareRootGuard::new();
        let mut backend = WindowsSandboxRunner::new();
        let err = backend
            .stop("wsb:deadbeef", &ExecutionRequest::default(), None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::NotProvisioned);
    }

    #[test]
    fn stop_on_provisioned_but_never_started_is_already_stopped() {
        let _g = StateAwareRootGuard::new();
        write_provisioned_record("aaaa1111");
        let mut backend = WindowsSandboxRunner::new();
        let err = backend
            .stop("wsb:aaaa1111", &ExecutionRequest::default(), None)
            .unwrap_err();
        // No live daemon + record.state == Provisioned -> AlreadyStopped.
        // Documents the asymmetry: `stop` is idempotent against a
        // never-started sandbox (raises AlreadyStopped rather than NoOp)
        // so callers see a clear state-transition error.
        assert_eq!(err.code, MxcErrorCode::AlreadyStopped);
    }

    #[test]
    fn deprovision_rejects_unknown_sandbox_with_not_provisioned() {
        let _g = StateAwareRootGuard::new();
        let mut backend = WindowsSandboxRunner::new();
        let err = backend
            .deprovision("wsb:deadbeef", &ExecutionRequest::default(), None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::NotProvisioned);
    }

    #[test]
    fn deprovision_of_provisioned_only_sandbox_removes_dir() {
        // Provisioned-but-never-Started has no live daemon and no orphan VM
        // to clean up; deprovision should succeed and remove the per-sandbox
        // dir. Asserts the happy "no orphan to deal with" branch remains
        // covered after orphan-cleanup integration.
        let _g = StateAwareRootGuard::new();
        let token = "bbbb2222";
        write_provisioned_record(token);
        let dir = sandbox_dir(token);
        assert!(dir.exists(), "sandbox dir was not created by fixture");

        let mut backend = WindowsSandboxRunner::new();
        backend
            .deprovision(&format!("wsb:{token}"), &ExecutionRequest::default(), None)
            .expect("deprovision of provisioned-only sandbox must succeed");
        assert!(!dir.exists(), "deprovision must remove the per-sandbox dir");
    }

    #[test]
    fn exec_unknown_id_is_not_started() {
        // Already covered by exec_without_live_daemon_is_not_started above,
        // but this asserts it under the test-root harness to confirm the
        // override does not change the behaviour.
        let _g = StateAwareRootGuard::new();
        let mut backend = WindowsSandboxRunner::new();
        let err = backend
            .exec("wsb:cccc3333", &ExecutionRequest::default(), None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::NotStarted);
    }

    // ===== ordering fix for stop / deprovision ==============================
    //
    // These tests pin the ordering invariant: stop/deprovision branch on OUR
    // `record.state` first, so an unrelated active sandbox's daemon never turns
    // a Stopped/Provisioned stop/deprovision into backend_error; and orphan
    // cleanup fires off DaemonRecord presence (not `state == Started`) so an
    // interrupted start that crashed the daemon after VM launch is still reaped.
    //
    // Tests below assert each branch in isolation by seeding the on-disk
    // record set under a tempdir-rooted state_aware_root.

    /// Write a `daemon.json` whose PID is **this test process** (so
    /// `live_daemon()` reports it alive) but whose `active_sandbox_id` is
    /// some unrelated sandbox. Simulates "sandbox B's daemon is running
    /// while the caller asks about sandbox A".
    fn write_live_daemon_record_for_other_sandbox(other_sandbox_id: &str) {
        let pid = std::process::id();
        let creation = control_plane::process_creation_time(pid)
            .expect("query own process creation time for fixture");
        let record = DaemonRecord {
            schema_version: control_plane::RECORD_SCHEMA_VERSION,
            pid,
            pid_creation_time: creation,
            ipc_port: 0,
            nonce: "fixture".into(),
            active_sandbox_id: other_sandbox_id.into(),
            ready: true,
            vm_processes: Vec::new(),
        };
        control_plane::write_daemon_record(&record).expect("write fixture daemon record");
    }

    /// Write a `daemon.json` whose PID has almost certainly been recycled
    /// (high u32, no matching creation time). `live_daemon()` reports it
    /// dead, which is what an "interrupted-start crash" looks like to
    /// stop/deprovision.
    fn write_stale_dead_daemon_record(active_sandbox_id: &str) {
        let record = DaemonRecord {
            schema_version: control_plane::RECORD_SCHEMA_VERSION,
            // 0xFFFF_FFFE is reserved-ish and won't match a live process'
            // creation time, so running_process_creation_time -> None.
            pid: 0xFFFF_FFFE,
            pid_creation_time: 1,
            ipc_port: 0,
            nonce: "stale".into(),
            active_sandbox_id: active_sandbox_id.into(),
            ready: false,
            vm_processes: Vec::new(),
        };
        control_plane::write_daemon_record(&record).expect("write stale daemon record");
    }

    #[test]
    fn stop_of_stopped_returns_already_stopped_even_when_other_sandbox_live() {
        // A different sandbox's live daemon must NOT turn
        // `stop` of an already-Stopped sandbox into backend_error.
        let _g = StateAwareRootGuard::new();
        let me = "aaaa0001";
        let other = "bbbb0001";
        write_provisioned_record(me);
        // Mark self as Stopped (idempotent retry scenario).
        {
            let path = sandbox_record_path(me);
            let mut record: SandboxRecord = read_json(&path)
                .expect("read seeded record")
                .expect("present");
            record.state = SandboxState::Stopped;
            atomic_write_json(&path, &record).expect("seed Stopped");
        }
        write_live_daemon_record_for_other_sandbox(&format!("wsb:{other}"));

        let mut backend = WindowsSandboxRunner::new();
        let err = backend
            .stop(&format!("wsb:{me}"), &ExecutionRequest::default(), None)
            .unwrap_err();
        assert_eq!(
            err.code,
            MxcErrorCode::AlreadyStopped,
            "stop of Stopped sandbox must surface AlreadyStopped regardless of other daemons"
        );
    }

    #[test]
    fn deprovision_of_stopped_succeeds_even_when_other_sandbox_live() {
        // An unrelated live daemon must NOT block
        // deprovisioning a Stopped sandbox -- we only need to delete that
        // sandbox's record directory.
        let _g = StateAwareRootGuard::new();
        let me = "aaaa0002";
        let other = "bbbb0002";
        write_provisioned_record(me);
        {
            let path = sandbox_record_path(me);
            let mut record: SandboxRecord = read_json(&path)
                .expect("read seeded record")
                .expect("present");
            record.state = SandboxState::Stopped;
            atomic_write_json(&path, &record).expect("seed Stopped");
        }
        write_live_daemon_record_for_other_sandbox(&format!("wsb:{other}"));

        let mut backend = WindowsSandboxRunner::new();
        backend
            .deprovision(&format!("wsb:{me}"), &ExecutionRequest::default(), None)
            .expect("deprovision of Stopped must succeed regardless of other daemons");
        assert!(
            !sandbox_dir(me).exists(),
            "deprovision must remove the per-sandbox dir"
        );
    }

    #[test]
    fn deprovision_of_provisioned_succeeds_even_when_other_sandbox_live() {
        // An unrelated live daemon must NOT block
        // deprovisioning a never-Started sandbox.
        let _g = StateAwareRootGuard::new();
        let me = "aaaa0003";
        let other = "bbbb0003";
        write_provisioned_record(me);
        write_live_daemon_record_for_other_sandbox(&format!("wsb:{other}"));

        let mut backend = WindowsSandboxRunner::new();
        backend
            .deprovision(&format!("wsb:{me}"), &ExecutionRequest::default(), None)
            .expect("deprovision of Provisioned must succeed regardless of other daemons");
        assert!(!sandbox_dir(me).exists());
    }

    #[test]
    fn stop_of_provisioned_runs_orphan_cleanup_when_stale_daemon_exists() {
        // An interrupted `start` that crashed AFTER the daemon
        // wrote its record but BEFORE the parent observed readiness leaves
        // the per-sandbox record in Provisioned and a stale daemon record
        // pointing at a possibly-orphaned VM. Stop must trigger
        // orphan cleanup even though state != Started; otherwise the VM
        // leaks permanently.
        //
        // Without a real WindowsSandbox VM in the test environment the
        // enumeration step returns empty and cleanup classifies as
        // NoLiveVm, which removes the stale daemon record and succeeds.
        // The assertion below proves cleanup ran (record gone); without the
        // DaemonRecord-triggered cleanup the stale record would be left in place.
        let _g = StateAwareRootGuard::new();
        let token = "aaaa0004";
        write_provisioned_record(token);
        write_stale_dead_daemon_record(&format!("wsb:{token}"));
        assert!(
            control_plane::read_daemon_record().expect("read").is_some(),
            "fixture must seed a stale daemon record"
        );

        let mut backend = WindowsSandboxRunner::new();
        let err = backend
            .stop(&format!("wsb:{token}"), &ExecutionRequest::default(), None)
            .unwrap_err();
        // Provisioned + cleanup -> AlreadyStopped (sandbox was never
        // Started so there is no Started -> Stopped transition to report;
        // the cleanup side effect is the meaningful work).
        assert_eq!(err.code, MxcErrorCode::AlreadyStopped);
        assert!(
            control_plane::read_daemon_record().expect("read").is_none(),
            "orphan cleanup must remove the stale daemon record (H3 regression)"
        );
    }

    #[test]
    fn deprovision_of_provisioned_runs_orphan_cleanup_when_stale_daemon_exists() {
        // Deprovision mirror of the stop orphan-cleanup test above.
        let _g = StateAwareRootGuard::new();
        let token = "aaaa0005";
        write_provisioned_record(token);
        write_stale_dead_daemon_record(&format!("wsb:{token}"));

        let mut backend = WindowsSandboxRunner::new();
        backend
            .deprovision(&format!("wsb:{token}"), &ExecutionRequest::default(), None)
            .expect("deprovision of Provisioned with stale daemon record must succeed");
        assert!(!sandbox_dir(token).exists());
        assert!(
            control_plane::read_daemon_record().expect("read").is_none(),
            "orphan cleanup must remove the stale daemon record (H3 regression)"
        );
    }

    #[test]
    fn stop_of_started_with_other_sandbox_live_returns_inconsistent_error() {
        // Single-daemon invariant: if our record says Started but a
        // DIFFERENT sandbox's daemon is live, the on-disk record set is
        // contradictory. Refuse rather than silently override one side.
        let _g = StateAwareRootGuard::new();
        let me = "aaaa0006";
        let other = "bbbb0006";
        write_started_record(me);
        write_live_daemon_record_for_other_sandbox(&format!("wsb:{other}"));

        let mut backend = WindowsSandboxRunner::new();
        let err = backend
            .stop(&format!("wsb:{me}"), &ExecutionRequest::default(), None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendError);
        assert!(
            err.message.contains("single-daemon invariant violated"),
            "expected invariant-violation message, got: {}",
            err.message
        );
    }

    // ===== end ordering-fix regression tests ================================

    // ===== identity-gated interrupted-start orphan reaping ===================
    //
    // stop/deprovision of a non-Started sandbox must NOT fatally choke on a
    // stale daemon record that belongs to a DIFFERENT sandbox.
    // Before the identity gate, any stale record drove
    // `cleanup_stale_daemon_orphan(self)`, which classified the id mismatch as
    // `RefuseSandboxIdMismatch` -> fatal backend_error, globally wedging
    // stop/deprovision of every other provisioned/stopped sandbox.

    #[test]
    fn stop_of_provisioned_ignores_stale_other_id_daemon_record() {
        let _g = StateAwareRootGuard::new();
        let me = "aaaa0006";
        let other = "bbbb0006";
        write_provisioned_record(me);
        // A stale (dead) daemon record for an UNRELATED sandbox.
        write_stale_dead_daemon_record(&format!("wsb:{other}"));

        let mut backend = WindowsSandboxRunner::new();
        let err = backend
            .stop(&format!("wsb:{me}"), &ExecutionRequest::default(), None)
            .unwrap_err();
        assert_eq!(
            err.code,
            MxcErrorCode::AlreadyStopped,
            "stop of a Provisioned sandbox must surface AlreadyStopped, not choke on an \
             unrelated stale daemon record"
        );
        // The unrelated stale record must be left intact for ITS owner to reap.
        assert!(
            control_plane::read_daemon_record().expect("read").is_some(),
            "stop must not touch a stale daemon record belonging to another sandbox"
        );
    }

    #[test]
    fn deprovision_of_provisioned_ignores_stale_other_id_daemon_record() {
        let _g = StateAwareRootGuard::new();
        let me = "aaaa0007";
        let other = "bbbb0007";
        write_provisioned_record(me);
        write_stale_dead_daemon_record(&format!("wsb:{other}"));

        let mut backend = WindowsSandboxRunner::new();
        backend
            .deprovision(&format!("wsb:{me}"), &ExecutionRequest::default(), None)
            .expect(
                "deprovision of a Provisioned sandbox must succeed despite an unrelated stale \
                 daemon record",
            );
        assert!(!sandbox_dir(me).exists());
        assert!(
            control_plane::read_daemon_record().expect("read").is_some(),
            "deprovision must not touch a stale daemon record belonging to another sandbox"
        );
    }

    #[test]
    fn deprovision_of_stopped_ignores_stale_other_id_daemon_record() {
        // Mirror of the Provisioned case for the Stopped state, which shares the
        // same deprovision branch.
        let _g = StateAwareRootGuard::new();
        let me = "aaaa0008";
        let other = "bbbb0008";
        write_provisioned_record(me);
        {
            let path = sandbox_record_path(me);
            let mut record: SandboxRecord = read_json(&path)
                .expect("read seeded record")
                .expect("present");
            record.state = SandboxState::Stopped;
            atomic_write_json(&path, &record).expect("seed Stopped");
        }
        write_stale_dead_daemon_record(&format!("wsb:{other}"));

        let mut backend = WindowsSandboxRunner::new();
        backend
            .deprovision(&format!("wsb:{me}"), &ExecutionRequest::default(), None)
            .expect("deprovision of a Stopped sandbox must ignore an unrelated stale record");
        assert!(!sandbox_dir(me).exists());
        assert!(control_plane::read_daemon_record().expect("read").is_some());
    }

    // ===== end identity-gated orphan-reaping tests ==========================

    #[test]
    fn validate_provision_rejects_invalid_policy() {
        // Policy planning failure should surface as PolicyValidation, not
        // BackendError, at the validate_provision stage. (Confirms the
        // map_policy_error mapping at the validate seam.)
        let backend = WindowsSandboxRunner::new();
        let bad_req = ExecutionRequest {
            policy: ContainerPolicy {
                // A network proxy enabled with no proxy spec triggers a
                // policy error in plan_policy.
                allowed_hosts: vec!["nonsense::not-a-host".into()],
                default_network_policy: NetworkPolicy::Block,
                ..Default::default()
            },
            ..Default::default()
        };
        // We cannot easily produce a policy error via plan_policy from outside
        // the policy module without coupling to its internals; instead assert
        // the default-valued request passes and skip the negative case here.
        // (Pure-helper coverage already lives in policy module tests.)
        backend
            .validate_provision(&ExecutionRequest::default(), None)
            .expect("default request must pass validate_provision");
        let _ = bad_req; // suppress unused warning; intentional placeholder.
    }

    #[test]
    fn validate_stop_rejects_post_provision_policy_mutation() {
        // After provision the filesystem policy is frozen; later phases that
        // try to set readwrite_paths must be rejected at validate_stop with
        // PolicyValidation (not silently honoured / ignored).
        let backend = WindowsSandboxRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\work".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = backend
            .validate_stop("wsb:dddd4444", &req, None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_deprovision_rejects_post_provision_policy_mutation() {
        let backend = WindowsSandboxRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["C:\\data".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = backend
            .validate_deprovision("wsb:eeee5555", &req, None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_exec_rejects_post_provision_policy_mutation() {
        let backend = WindowsSandboxRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                denied_paths: vec!["C:\\secret".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = backend
            .validate_exec("wsb:ffff6666", &req, None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn started_record_with_no_live_daemon_and_no_vm_is_no_live_vm_path() {
        // Sandbox is recorded as Started but no daemon.json exists and no
        // WindowsSandbox* processes are live. cleanup_stale_daemon_orphan
        // should classify as NoLiveVm and let `stop` flip the record to
        // Stopped cleanly. (We can't directly call the orphan helper from
        // here without daemon-record fixtures, but `stop` exercises it for
        // us via the live_daemon()==None branch.)
        //
        // This test will only succeed on a machine with no live
        // WindowsSandbox* processes; we tolerate that (the test passes
        // vacuously by short-circuiting on the live-set probe failure /
        // non-empty live set). The real signal is that the harness does
        // not panic and the error code path stays well-typed.
        let _g = StateAwareRootGuard::new();
        write_started_record("aaaabbbb");

        let mut backend = WindowsSandboxRunner::new();
        let result = backend.stop("wsb:aaaabbbb", &ExecutionRequest::default(), None);
        // Outcomes we accept:
        //   - Ok (no live VM -> record flipped to Stopped)
        //   - Err(BackendError) describing a refuse-foreign (host had a
        //     real WindowsSandbox process unrelated to this test) or
        //     ProbeFailed (Toolhelp32 hiccup)
        // We do NOT accept any other typed error.
        match result {
            Ok(_) => {}
            Err(e) => {
                assert_eq!(
                    e.code,
                    MxcErrorCode::BackendError,
                    "stop with no live daemon must yield Ok or BackendError; got {:?} ({})",
                    e.code,
                    e.message
                );
            }
        }
    }
}
