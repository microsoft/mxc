// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SeatbeltScriptRunner` — executes scripts inside Apple's Seatbelt
//! sandbox.
//!
//! The sandbox is applied via `sandbox_init()` inside `Command::pre_exec`,
//! then `/bin/sh` is exec'd directly. The child inherits the parent's
//! Mach bootstrap namespace so both CLI commands and GUI applications
//! (when `guiAccess = true`) work correctly. The exec path returns a
//! `SandboxProcess` whose stdio follows the requested `StdioMode`:
//! `Inherit` gives the child the host's own stdio (a real TTY when the
//! binary runs under a pty), while `Pipes` exposes stdout/stderr/stdin
//! handles the caller can stream and `Pty` exposes a caller-owned terminal.
//!
//! Compiled only on macOS — the rest of the workspace continues to build
//! on Windows / Linux unchanged.

use std::ffi::{CStr, CString};
use std::fmt::Write as FmtWrite;
use std::io::IsTerminal;
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::mxc_common::interruptible_reader::{wrap_pipe, InterruptibleReader, ReadCanceller};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, ProxyAddress, ScriptResponse};
use crate::mxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, duplicate_and_take_native_stdio, group_kill,
    spawn_discard, take_boxed_read, take_boxed_write, wait_with_timeout, NativeStdio, PtySize,
    SandboxBackend, SandboxProcess, StdioMode, StreamCloser, WaitError,
};
use crate::mxc_common::validator::{
    validate_common, validate_network_policy_support, NetworkPolicySupport,
};
use crate::mxc_pty::{LivePty, PtySize as UnixPtySize};

#[cfg(test)]
use crate::seatbelt_common::default_env::DEFAULT_SANDBOX_PATH;
use crate::seatbelt_common::default_env::{env_pairs, resolved_env};
#[cfg(test)]
use crate::seatbelt_common::profile_builder::build_profile_with_proxy;
use crate::seatbelt_common::profile_builder::build_profile_with_terminals;

#[link(name = "proc")]
unsafe extern "C" {
    fn proc_listallpids(buffer: *mut libc::c_void, buffersize: libc::c_int) -> libc::c_int;
    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
    fn proc_signal_with_audittoken(token: *mut AuditToken, signal: libc::c_int) -> libc::c_int;
}

#[repr(C)]
struct AuditToken {
    val: [u32; 8],
}

#[repr(C)]
#[derive(Default)]
struct ProcUniqueIdentifierInfo {
    uuid: [u8; 16],
    unique_id: u64,
    parent_unique_id: u64,
    id_version: i32,
    original_parent_id_version: i32,
    reserved: [u64; 2],
}

const PROC_PID_UNIQUE_IDENTIFIER_INFO: libc::c_int = 17;

/// Env var keys the cooperative proxy manages. When a proxy is active these
/// are stripped from the caller-supplied environment so sandboxed code cannot
/// override the `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` values we inject (or
/// re-enable a `NO_PROXY` bypass). `ALL_PROXY` is the catch-all curl/libcurl
/// and many HTTP clients honor for every scheme, so leaving it caller-settable
/// would let sandboxed code redirect or bypass the proxy. Mirrors the
/// Bubblewrap backend's `PROXY_ENV_KEYS`.
const PROXY_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

fn session_kill(child: &mut std::process::Child, session_id: libc::pid_t) -> std::io::Result<()> {
    let leader_result = match child.try_wait()? {
        Some(_) => Ok(()),
        None => child.kill(),
    };
    let session_result = kill_session_members(session_id);
    leader_result.and(session_result)
}

fn terminate_session_and_reap(
    child: &mut std::process::Child,
    session_id: libc::pid_t,
    timeout: Duration,
) -> std::io::Result<()> {
    session_kill(child, session_id)?;
    match wait_with_timeout(child, Some(timeout)) {
        Ok(_) => Ok(()),
        Err(WaitError::Timeout) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Seatbelt: killed process did not become reapable before the deadline",
        )),
        Err(WaitError::Io(error)) => Err(error),
    }
}

fn kill_session_members(session_id: libc::pid_t) -> std::io::Result<()> {
    const SESSION_SWEEPS: usize = 3;

    let mut first_error = None;
    // SAFETY: `getpid` has no preconditions.
    let current_pid = unsafe { libc::getpid() };
    for _ in 0..SESSION_SWEEPS {
        for pid in list_all_pids()? {
            if pid <= 0 || pid == current_pid {
                continue;
            }
            let Some(mut token) = process_audit_token(pid)? else {
                continue;
            };
            // The token is captured first. If the PID exits before this query,
            // a replacement's different session is rejected; if it exits after
            // the query, the token's pid-version prevents signaling a replacement.
            // SAFETY: `getsid` only queries the process identified by `pid`.
            if unsafe { libc::getsid(pid) } != session_id {
                continue;
            }
            // SAFETY: libproc validates the token's PID version atomically with
            // process lookup before signaling.
            let error = unsafe { proc_signal_with_audittoken(&mut token, libc::SIGKILL) };
            if error != 0 && error != libc::ESRCH && first_error.is_none() {
                first_error = Some(std::io::Error::from_raw_os_error(error));
            }
        }
        std::thread::yield_now();
    }
    first_error.map_or(Ok(()), Err)
}

fn process_audit_token(pid: libc::pid_t) -> std::io::Result<Option<AuditToken>> {
    let mut info = ProcUniqueIdentifierInfo::default();
    let size = libc::c_int::try_from(std::mem::size_of_val(&info))
        .map_err(|_| std::io::Error::other("macOS process identity is too large"))?;
    // SAFETY: `info` is writable for `size` bytes and libproc only fills the
    // requested identity record for `pid`.
    let copied = unsafe {
        proc_pidinfo(
            pid,
            PROC_PID_UNIQUE_IDENTIFIER_INFO,
            0,
            std::ptr::from_mut(&mut info).cast::<libc::c_void>(),
            size,
        )
    };
    if copied == 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(None),
            _ => Err(error),
        };
    }
    if copied != size {
        return Err(std::io::Error::other(format!(
            "macOS returned a truncated process identity for pid {pid}"
        )));
    }
    let mut token = AuditToken { val: [0; 8] };
    token.val[5] = pid as u32;
    token.val[7] = info.id_version as u32;
    Ok(Some(token))
}

fn list_all_pids() -> std::io::Result<Vec<libc::pid_t>> {
    // SAFETY: a null buffer asks libproc for the current process count.
    let count = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
    if count < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut pids = vec![0; count as usize + 128];
    let buffer_size = pids
        .len()
        .checked_mul(std::mem::size_of::<libc::pid_t>())
        .and_then(|size| libc::c_int::try_from(size).ok())
        .ok_or_else(|| std::io::Error::other("macOS process list is too large"))?;
    // SAFETY: `pids` is writable for exactly `buffer_size` bytes.
    let listed = unsafe { proc_listallpids(pids.as_mut_ptr().cast::<libc::c_void>(), buffer_size) };
    if listed < 0 {
        return Err(std::io::Error::last_os_error());
    }
    pids.truncate((listed as usize).min(pids.len()));
    Ok(pids)
}

/// Proxy env var keys injected (pointing at the resolved proxy URL) when a
/// proxy is active. `NO_PROXY` is intentionally absent — see the module docs
/// and [`resolve_environment`].
const PROXY_INJECT_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];

// ---------------------------------------------------------------------------
// FFI declarations for Apple's sandbox API (libsandbox.dylib).
//
// `sandbox_init` is declared in <sandbox.h> and marked deprecated since
// macOS 10.8, but is still shipped and used by first-party apps through
// macOS 15+.
// ---------------------------------------------------------------------------

/// Whether `sandbox_init` resolves in this process, as the exec path needs.
pub(crate) fn sandbox_init_available() -> bool {
    // SAFETY: `dlsym` only reads the NUL-terminated symbol name.
    !unsafe { libc::dlsym(libc::RTLD_SELF, c"sandbox_init".as_ptr()) }.is_null()
}

#[link(name = "sandbox")]
extern "C" {
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        errorbuf: *mut *mut libc::c_char,
    ) -> libc::c_int;

    fn sandbox_free_error(errorbuf: *mut libc::c_char);
}

/// Default shell used to execute `script_code`. `/bin/sh` is guaranteed
/// to exist and is on the SIP-protected path so it's always reachable
/// from inside the sandbox.
const DEFAULT_SHELL: &str = "/bin/sh";

/// Markers bracketing the generated profile in the log stream, so a reader can
/// slice it out. The `Seatbelt: ` prefix cannot collide with profile content:
/// rules start with `(` and profile comments with `;;`.
pub const PROFILE_LOG_BEGIN: &str = "Seatbelt: --- begin generated profile ---";
pub const PROFILE_LOG_END: &str = "Seatbelt: --- end generated profile ---";

#[derive(Default)]
pub struct SeatbeltScriptRunner;

impl SeatbeltScriptRunner {
    pub fn new() -> Self {
        Self
    }
}

impl SandboxBackend for SeatbeltScriptRunner {
    fn network_policy_support(&self) -> NetworkPolicySupport {
        // Seatbelt enforces a single outbound default (no CIDR/port/protocol
        // rules — `EGRESS_RULES` is intentionally omitted), a single inbound
        // default mapped to a local-IP inbound rule, and the
        // loopback-scoped runtime proxy. It has no per-peer proxy identity
        // concept (`PROXY_PEER_IDENTITY` is a ProcessContainer-only feature).
        NetworkPolicySupport::EGRESS_DEFAULT
            | NetworkPolicySupport::INGRESS_DEFAULT
            | NetworkPolicySupport::HOST_LOOPBACK
            | NetworkPolicySupport::RUNTIME_PROXY
    }

    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_network_policy_support(request, self.network_policy_support())?;

        // Seatbelt's own invariants — the only home for them, so a caller that
        // builds an ExecutionRequest directly gets the same rules.
        crate::seatbelt_common::seatbelt_policy::validate_seatbelt_network_policy(&request.policy)
            .map_err(error_response)?;
        crate::seatbelt_common::seatbelt_policy::validate_seatbelt_ui_policy(request)
            .map_err(error_response)?;

        Ok(())
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        validate_common(request)?;
        self.validate(request)?;

        // The caller manages the proxy. Scope the profile's reachability rule
        // to its address and inject HTTP_PROXY / HTTPS_PROXY. macOS has no
        // WinHTTP-style OS proxy policy,
        // so — like the Bubblewrap backend — enforcement is cooperative:
        // well-behaved HTTP clients honor the env vars; raw-socket clients
        // bypass them.
        let proxy_address = request.policy.network_proxy.address.as_ref();
        if let Some(address) = proxy_address {
            logger.log_line(&format!(
                "Unix network proxy active: {}",
                crate::mxc_common::proxy_env::redact_proxy_url(&address.to_url())
            ));
        }
        // Effective posture, not the raw flag: a `guiAccess` the UI policy
        // suppressed emits no GUI rules, so it must not cost the caller
        // streaming either.
        let gui_access = crate::seatbelt_common::seatbelt_policy::gui_access_effective(request);

        spawn_exec(request, gui_access, stdio, logger, proxy_address)
    }
}

/// Exec launch path: fork → sandbox_init → exec `/bin/sh -c <script>`. With
/// [`StdioMode::Pipes`] the child gets pipes and leads its own session (so the
/// caller can tree-terminate via the process group); with
/// [`StdioMode::Inherit`] it inherits the process's stdio (a TTY when the
/// binary has one) and stays in the binary's session; with [`StdioMode::Pty`]
/// it gets a caller-owned terminal and leads its own session. `gui_access`
/// apps require inherited stdio.
fn spawn_exec(
    request: &ExecutionRequest,
    gui_access: bool,
    stdio: StdioMode,
    logger: &mut Logger,
    proxy_address: Option<&ProxyAddress>,
) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
    if gui_access && stdio != StdioMode::Inherit {
        let mode = if stdio == StdioMode::Pipes {
            "pipes"
        } else {
            "a caller-owned PTY"
        };
        return Err(error_response(format!(
            "Seatbelt guiAccess requires inherited stdio and cannot use {mode}"
        )));
    }

    // Pipes → own session (setsid) so a process-group tree-kill never touches
    // the host. Inherit/GUI → keep the binary's session and controlling
    // terminal so the child sees a TTY exactly when the binary does.
    let new_session = stdio == StdioMode::Pipes;
    // Inherit mode with a finite timeout: put the child in its own process group
    // (same session, so it keeps the controlling terminal) so the timeout branch
    // can tree-kill its descendants instead of only the direct `/bin/sh`. A
    // backgrounded group reading the inherited TTY can be SIGTTIN-stopped, so
    // this is limited to timeout-bounded runs, which are inherently
    // non-interactive.
    let new_group = stdio == StdioMode::Inherit && timeout_from(request).is_some();
    let (mut command, pty) = build_sandbox_command(
        request,
        proxy_address,
        new_session,
        new_group,
        match stdio {
            StdioMode::Pty(size) => Some(size),
            _ => None,
        },
        logger,
    )?;

    // Always start from a cleared environment so untrusted sandboxed code never
    // inherits the host's env. When a proxy is active its HTTP_PROXY/HTTPS_PROXY
    // vars are injected here (and caller-supplied proxy vars stripped).
    //
    // The cwd is anchored first: `current_dir` resolves a relative value against
    // the launching process, so `HOME` must name that same absolute path.
    let resolved_cwd = resolved_working_directory_opt(request);
    let cwd = match absolute_working_directory(
        resolved_cwd
            .as_deref()
            .unwrap_or(UNRESOLVED_WORKING_DIRECTORY),
    ) {
        Ok(cwd) => cwd,
        Err(e) => {
            return Err(error_response(format!(
                "failed to read the current directory to anchor the relative seatbelt working directory: {e}"
            )))
        }
    };
    let home_dir = resolved_cwd.as_ref().map(|_| cwd.as_str());
    apply_clean_environment(&mut command, request, proxy_address, home_dir);

    // Also export `PWD` so the child's `getcwd()` uses its
    // fast `$PWD` path (a single stat) instead of walking parent directories
    // the sandbox may not let it read — which otherwise leaks
    // "getcwd: ... Operation not permitted" to stderr.
    command.current_dir(&cwd);
    command.env("PWD", &cwd);

    match stdio {
        StdioMode::Pipes => {
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }
        StdioMode::Inherit => {
            // The child inherits the binary's stdio directly (a TTY when the
            // binary has one) — no separate pty bridge.
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        }
        StdioMode::Pty(_) => {}
    }

    let mut child = command
        .spawn()
        .map_err(|error| error_response(spawn_error(&error)))?;

    let (stdin, stdout, stderr) = match stdio {
        StdioMode::Pipes => (child.stdin.take(), child.stdout.take(), child.stderr.take()),
        StdioMode::Inherit => (None, None, None),
        StdioMode::Pty(_) => (None, None, None),
    };

    // Wrap the pipe reads so the caller can abandon a stream a backgrounded
    // descendant is holding open (see `SandboxProcess::stdout_closer`), without
    // killing the child. On failure, don't orphan the already-spawned sandboxed
    // process — kill and reap it before returning the error.
    let (stdout, stdout_canceller, stderr, stderr_canceller) =
        match (wrap_pipe(stdout), wrap_pipe(stderr)) {
            (Ok((out, out_canceller)), Ok((err, err_canceller))) => {
                (out, out_canceller, err, err_canceller)
            }
            (out_result, err_result) => {
                let _ = child.kill();
                let _ = child.wait();
                let error = out_result.err().or(err_result.err());
                return Err(error_response(format!(
                    "Seatbelt: failed to wrap stdio pipes: {}",
                    error.map_or_else(|| "unknown error".to_string(), |e| e.to_string()),
                )));
            }
        };

    let started = Instant::now();
    let session_id =
        (new_session || matches!(stdio, StdioMode::Pty(_))).then_some(child.id() as libc::pid_t);
    Ok(Box::new(SeatbeltSandboxProcess {
        child,
        stdin,
        stdout,
        stderr,
        stdout_canceller,
        stderr_canceller,
        pty,
        timeout: timeout_from(request),
        started,
        timed_out: false,
        termination_error: None,
        group: new_session || new_group || stdio != StdioMode::Inherit,
        session_id,
    }))
}

/// A running Seatbelt-sandboxed process: the child plus, for the pipes path,
/// its parent-side pipe ends. See [`SandboxProcess`] for the contract.
struct SeatbeltSandboxProcess {
    child: std::process::Child,
    /// Pipe ends — `Some` only for [`StdioMode::Pipes`]; `None` for inherited
    /// stdio, where the streams are the binary's own. The
    /// reads are wrapped so they can be cancelled out-of-band (see the
    /// `*_canceller` fields).
    stdin: Option<std::process::ChildStdin>,
    stdout: Option<InterruptibleReader>,
    stderr: Option<InterruptibleReader>,
    /// Cancellers for the stdout/stderr reads (`Some` alongside the pipe ends),
    /// kept so [`stdout_closer`](SandboxProcess::stdout_closer) /
    /// [`stderr_closer`](SandboxProcess::stderr_closer) can mint closers even
    /// after the stream has been taken.
    stdout_canceller: Option<ReadCanceller>,
    stderr_canceller: Option<ReadCanceller>,
    /// Caller-owned primary PTY for direct exec mode.
    pty: Option<LivePty>,
    timeout: Option<Duration>,
    started: Instant,
    timed_out: bool,
    termination_error: Option<String>,
    /// The child leads its own process group, so termination can signal that
    /// group without touching the host process group.
    group: bool,
    /// The child leads an owned session, so job-control descendants in other
    /// process groups can be terminated without touching the host session.
    session_id: Option<libc::pid_t>,
}

impl SandboxProcess for SeatbeltSandboxProcess {
    fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
        if let Some(pty) = self.pty.as_ref() {
            let stdio = pty.take_native_stdio()?;
            return Ok(Some(NativeStdio {
                stdin: Some(stdio.stdin),
                stdout: Some(stdio.stdout),
                stderr: None,
            }));
        }
        let stdio = duplicate_and_take_native_stdio(
            &mut self.stdin,
            &mut self.stdout,
            &mut self.stderr,
            |stream| stream.as_fd().try_clone_to_owned(),
            InterruptibleReader::try_clone_owned_fd,
            InterruptibleReader::try_clone_owned_fd,
        )?;
        if stdio.is_some() {
            self.stdout_canceller.take();
            self.stderr_canceller.take();
        }
        Ok(stdio)
    }

    fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
        take_boxed_write(&mut self.stdin)
    }

    fn is_pty(&self) -> bool {
        self.pty.is_some()
    }

    fn pty_clone_reader(&self) -> std::io::Result<Box<dyn std::io::Read + Send>> {
        self.pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Seatbelt process has no PTY"))?
            .try_clone_reader()
    }

    fn pty_clone_reader_with_closer(
        &self,
    ) -> std::io::Result<crate::mxc_common::sandbox_process::PtyReaderWithCloser> {
        let (reader, closer) = self
            .pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Seatbelt process has no PTY"))?
            .try_clone_reader_with_canceller()?;
        Ok((reader, Some(Box::new(closer))))
    }

    fn pty_take_writer(&self) -> std::io::Result<Box<dyn std::io::Write + Send>> {
        self.pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Seatbelt process has no PTY"))?
            .take_writer()
    }

    fn pty_resize(&self, size: PtySize) -> std::io::Result<()> {
        self.pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Seatbelt process has no PTY"))?
            .resize(UnixPtySize {
                rows: size.rows,
                cols: size.cols,
                pixel_width: size.pixel_width,
                pixel_height: size.pixel_height,
            })
    }

    fn pty_size(&self) -> std::io::Result<PtySize> {
        let size = self
            .pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Seatbelt process has no PTY"))?
            .size();
        Ok(PtySize {
            rows: size.rows,
            cols: size.cols,
            pixel_width: size.pixel_width,
            pixel_height: size.pixel_height,
        })
    }

    fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        take_boxed_read(&mut self.stdout)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        take_boxed_read(&mut self.stderr)
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stdout_canceller)
    }

    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stderr_canceller)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        if let Some(error) = self.termination_error.as_ref() {
            return Err(std::io::Error::other(error.clone()));
        }
        if self.timed_out {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Seatbelt: process timed out",
            ));
        }
        if let Some(status) = self.child.try_wait()? {
            return Ok(Some(status.code().unwrap_or(-1)));
        }
        if self
            .timeout
            .is_some_and(|timeout| self.started.elapsed() >= timeout)
        {
            if let Err(error) = self.kill_for_timeout() {
                let error = format!(
                    "Seatbelt: process timed out, but its session could not be terminated: {error}"
                );
                self.termination_error = Some(error.clone());
                return Err(std::io::Error::other(error));
            }
            self.timed_out = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Seatbelt: process timed out",
            ));
        }
        Ok(None)
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        if let Some(session_id) = self.session_id {
            return session_kill(&mut self.child, session_id);
        }
        // No-op once the child has exited and been reaped: its pid/pgid can be
        // recycled, so signaling it could hit an unrelated process (group). A
        // reaped `Child` returns its cached status here without a syscall.
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }
        if self.group {
            // The child leads its own process group — signal the whole group so
            // sandboxed descendants are terminated too.
            group_kill(&mut self.child)
        } else {
            // Inherited stdio: a single process sharing the binary's
            // process group, so signal just it (a group-kill would hit the
            // binary itself).
            self.child.kill()
        }
    }

    fn kill_for_timeout(&mut self) -> std::io::Result<()> {
        const REAP_TIMEOUT: Duration = Duration::from_secs(5);

        let result = if let Some(session_id) = self.session_id {
            terminate_session_and_reap(&mut self.child, session_id, REAP_TIMEOUT)
        } else {
            self.kill()?;
            match wait_with_timeout(&mut self.child, Some(REAP_TIMEOUT)) {
                Ok(_) => Ok(()),
                Err(WaitError::Timeout) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Seatbelt: killed process did not become reapable within 5 seconds",
                )),
                Err(WaitError::Io(error)) => Err(error),
            }
        };
        result?;
        self.timed_out = true;
        Ok(())
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        // Close our copy of any not-taken stdin so the child sees EOF and is
        // not blocked waiting for input the caller never intends to send.
        self.stdin.take();
        if let Some(pty) = self.pty.as_ref() {
            pty.close_writer();
        }

        // Drain (and discard) any not-taken stdout/stderr concurrently so the
        // child can't block on a full pipe (taken streams are the caller's
        // responsibility).
        let stdout_thread = spawn_discard(self.stdout.take());
        let stderr_thread = spawn_discard(self.stderr.take());
        let (pty_thread, pty_canceller, pty_setup_error) = match self.pty.as_ref() {
            Some(pty) => match pty.take_unclaimed_reader() {
                Ok(Some((reader, canceller))) => {
                    (spawn_discard(Some(reader)), Some(canceller), None)
                }
                Ok(None) => (None, None, None),
                Err(error) => (None, None, Some(error)),
            },
            None => (None, None, None),
        };

        let remaining_timeout = self
            .timeout
            .map(|timeout| timeout.saturating_sub(self.started.elapsed()));
        let result = if let Some(error) = pty_setup_error {
            let _ = self.kill();
            let _ = wait_with_timeout(&mut self.child, Some(Duration::from_secs(5)));
            Err(std::io::Error::other(format!(
                "Seatbelt: failed to prepare PTY output draining: {error}"
            )))
        } else if let Some(error) = self.termination_error.as_ref() {
            Err(std::io::Error::other(error.clone()))
        } else if self.timed_out {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Seatbelt: process timed out",
            ))
        } else {
            match wait_with_timeout(&mut self.child, remaining_timeout) {
                Ok(status) => Ok(status.code().unwrap_or(-1)),
                Err(WaitError::Timeout) => {
                    if let Err(error) = self.kill_for_timeout() {
                        let error =
                            format!("Seatbelt: process timed out, but teardown failed: {error}");
                        self.termination_error = Some(error.clone());
                        Err(std::io::Error::other(error))
                    } else {
                        self.timed_out = true;
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Seatbelt: process timed out",
                        ))
                    }
                }
                Err(WaitError::Io(error)) => {
                    // The child may still be running: kill+reap it (don't orphan
                    // the sandbox) before returning.
                    let _ = self.kill();
                    let _ = wait_with_timeout(&mut self.child, Some(Duration::from_secs(5)));
                    Err(std::io::Error::other(format!("wait failed: {error}")))
                }
            }
        };

        cancel_and_join_discard(stdout_thread, &self.stdout_canceller);
        cancel_and_join_discard(stderr_thread, &self.stderr_canceller);
        if let Some(pty) = self.pty.as_ref() {
            pty.finish_native_bridge();
        }
        cancel_and_join_discard(pty_thread, &pty_canceller);
        result
    }
}

impl Drop for SeatbeltSandboxProcess {
    fn drop(&mut self) {
        // Don't leak a running sandboxed process (and its group) or a zombie if
        // the handle is dropped without `wait()`, but never block destruction
        // indefinitely when macOS does not make a signalled child reapable.
        const DROP_REAP_TIMEOUT: Duration = Duration::from_secs(5);
        if let Some(session_id) = self.session_id {
            let _ = terminate_session_and_reap(&mut self.child, session_id, DROP_REAP_TIMEOUT);
        } else {
            let _ = self.kill();
            let _ = wait_with_timeout(&mut self.child, Some(DROP_REAP_TIMEOUT));
        }
    }
}

/// Build a `Command` that applies the sandbox via `sandbox_init()` in
/// `pre_exec`, then execs `/bin/sh -c <script>`. The child inherits the
/// parent's Mach bootstrap namespace, so both CLI and GUI applications
/// work correctly under the sandbox.
///
/// # Safety
///
/// `pre_exec` runs between `fork()` and `exec()`. Session/PTY setup uses
/// async-signal-safe syscalls before the pre-allocated `sandbox_init` call.
/// `sandbox_init` is not formally async-signal-safe but is used in this
/// pattern by Chromium and other production macOS sandboxes.
fn build_sandbox_command(
    request: &ExecutionRequest,
    proxy_address: Option<&ProxyAddress>,
    new_session: bool,
    new_group: bool,
    pty_size: Option<PtySize>,
    logger: &mut Logger,
) -> Result<(Command, Option<LivePty>), ScriptResponse> {
    let mut command = Command::new(DEFAULT_SHELL);
    command.arg("-c").arg(&request.script_code);

    // When requested (streaming path), put the child in its own session /
    // process group via `setsid()` so a caller can tree-kill it with a single
    // `killpg` without touching the host's process group. This runs before
    // `sandbox_init` so the detach happens regardless of the profile.
    //
    // SAFETY: `setsid` is async-signal-safe and runs after fork(), before
    // exec(); the child is not a process-group leader at this point, so it
    // succeeds. Failure is non-fatal (the caller's negative-pid kill simply
    // targets a group that does not exist).
    if new_session {
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    } else if new_group {
        // Inherit-with-timeout: a new process group within the *existing*
        // session, so the child keeps the controlling terminal yet can be
        // tree-killed via `killpg(-pgid)` on timeout.
        //
        // SAFETY: `setpgid` is async-signal-safe and runs after fork(), before
        // exec(); the child is not yet a group leader, so it succeeds. Failure
        // is non-fatal (the timeout kill then targets the direct child only).
        unsafe {
            command.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
    }

    let pty = pty_size
        .map(|size| {
            LivePty::attach(
                &mut command,
                UnixPtySize {
                    rows: size.rows,
                    cols: size.cols,
                    pixel_width: size.pixel_width,
                    pixel_height: size.pixel_height,
                },
                &[],
            )
            .map_err(|error| error_response(format!("Seatbelt: failed to allocate PTY: {error}")))
        })
        .transpose()?;

    let terminal_paths = match &pty {
        Some(pty) => vec![pty.secondary_path().to_path_buf()],
        None if !new_session => inherited_terminal_paths().map_err(|error| {
            error_response(format!(
                "Seatbelt: failed to resolve inherited terminals: {error}"
            ))
        })?,
        None => Vec::new(),
    };
    let profile = build_profile_with_terminals(request, proxy_address, &terminal_paths)
        .map_err(error_response)?;
    log_generated_profile(&profile, logger);
    let profile_cstr = CString::new(profile)
        .map_err(|e| error_response(format!("seatbelt profile contains embedded NUL byte: {e}")))?;
    let _ = writeln!(logger, "Seatbelt: applying sandbox via sandbox_init");

    // SAFETY: The closure runs after fork(), before exec(). We only call
    // sandbox_init with a pre-allocated CString — no Rust allocations
    // happen inside the closure. sandbox_init is used in this fork+exec
    // pattern by Chromium and other production macOS software.
    unsafe {
        command.pre_exec(move || {
            let mut errorbuf: *mut libc::c_char = std::ptr::null_mut();
            let rc = sandbox_init(profile_cstr.as_ptr(), 0, &mut errorbuf);
            if rc != 0 {
                // Extract error message using only libc calls (no allocation).
                if !errorbuf.is_null() {
                    let msg = CStr::from_ptr(errorbuf);
                    let bytes = msg.to_bytes();
                    // Write directly to stderr fd — no Rust allocation.
                    let prefix = b"Seatbelt: sandbox_init failed: ";
                    libc::write(2, prefix.as_ptr().cast(), prefix.len());
                    libc::write(2, bytes.as_ptr().cast(), bytes.len());
                    libc::write(2, b"\n".as_ptr().cast(), 1);
                    sandbox_free_error(errorbuf);
                }
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        });
    }

    Ok((command, pty))
}

fn inherited_terminal_paths() -> std::io::Result<Vec<PathBuf>> {
    let (stdin, stdout, stderr) = (std::io::stdin(), std::io::stdout(), std::io::stderr());
    let mut paths = Vec::new();
    for fd in [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()] {
        if fd.is_terminal() {
            let path = nix::unistd::ttyname(fd).map_err(std::io::Error::from)?;
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

/// Emit the generated profile to `logger` for `--debug` / `--log-file`.
///
/// One `writeln!` per line, unprefixed: the file sink stamps each write, and
/// keeping the lines verbatim makes the block copy-pasteable into
/// `profileOverride` or `sandbox-exec -f`.
fn log_generated_profile(profile: &str, logger: &mut Logger) {
    let _ = writeln!(logger, "{PROFILE_LOG_BEGIN}");
    for line in profile.lines() {
        let _ = writeln!(logger, "{line}");
    }
    let _ = writeln!(logger, "{PROFILE_LOG_END}");
}

fn error_response(message: String) -> ScriptResponse {
    ScriptResponse {
        exit_code: -1,
        error_message: message,
        ..Default::default()
    }
}

/// The optional run timeout — `None` when `scriptTimeout` is 0 (wait forever).
fn timeout_from(request: &ExecutionRequest) -> Option<Duration> {
    if request.script_timeout == 0 {
        None
    } else {
        Some(Duration::from_millis(u64::from(request.script_timeout)))
    }
}

/// Message for a `Command::spawn` failure, calling out the likely cause
/// (`sandbox_init` rejecting the profile) when the OS reports a permission
/// error.
fn spawn_error(error: &std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        format!(
            "failed to spawn sandboxed process (sandbox_init likely rejected \
             the profile — check stderr for details): {error}"
        )
    } else {
        format!("failed to spawn sandboxed process: {error}")
    }
}

/// Where a child is started when the request resolves no directory. The
/// baseline profile always allows `/`, unlike the host process's cwd, which
/// under the deny-by-default profile may be unreadable and make `getcwd()`
/// fail, leaking a "getcwd: … Operation not permitted" line onto the child's
/// stderr. `HOME` deliberately does not follow it here: `/` is not writable.
const UNRESOLVED_WORKING_DIRECTORY: &str = "/";

/// Resolve the working directory for the sandboxed child, or `None` when the
/// request resolves none.
///
/// The same value feeds the environment, so the default `HOME` cannot name a
/// directory the child never entered.
fn resolved_working_directory_opt(request: &ExecutionRequest) -> Option<String> {
    let expand = |path: &str| {
        crate::seatbelt_common::profile_builder::expand_tilde(path)
            .unwrap_or_else(|_| path.to_string())
    };
    request
        .resolved_working_directory_with(|path| Path::new(&expand(path)).is_dir())
        .map(|resolved| expand(resolved.path))
}

/// Anchor a resolved working directory to the launcher's directory when it is
/// relative.
fn absolute_working_directory(path: &str) -> std::io::Result<String> {
    absolute_working_directory_with(path, std::env::current_dir)
}

/// [`absolute_working_directory`] with an injectable launch directory. Only
/// consulted for a relative value: `chdir` accepts an absolute path even when
/// the launcher's own directory has been removed, so querying it eagerly would
/// reject a request that launches fine.
fn absolute_working_directory_with(
    path: &str,
    launch_dir: impl FnOnce() -> std::io::Result<PathBuf>,
) -> std::io::Result<String> {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        return Ok(path.to_string());
    }
    Ok(launch_dir()?.join(candidate).to_string_lossy().into_owned())
}

/// Populate `command`'s environment from a cleared baseline: never inherit the
/// host environment (matching the bubblewrap `--clearenv` and AppContainer
/// clean-block behaviour). [`resolved_env`] supplies the complete child
/// environment. When a proxy is active its `HTTP_PROXY` / `HTTPS_PROXY` /
/// `ALL_PROXY` vars are injected and caller-supplied proxy vars stripped (see
/// [`resolve_environment`]). `PWD` is set separately alongside the cwd.
fn apply_clean_environment(
    command: &mut Command,
    request: &ExecutionRequest,
    proxy_address: Option<&ProxyAddress>,
    working_directory: Option<&str>,
) {
    command.env_clear();
    for (key, value) in resolve_environment(request, proxy_address, working_directory) {
        command.env(key, value);
    }
}

/// Compute the final `(key, value)` environment for the sandboxed child: the
/// request's env, followed by the injected proxy vars.
///
/// When `proxy_address` is `Some`, any caller-supplied proxy vars
/// ([`PROXY_ENV_KEYS`]) are dropped so sandboxed code cannot override or
/// bypass the proxy, then the injected keys ([`PROXY_INJECT_KEYS`]:
/// `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` and their lowercase forms) are
/// set to the proxy URL.
///
/// `working_directory` is the directory the caller will start the child in, so
/// the default `HOME` names it; see [`resolved_env`].
fn resolve_environment(
    request: &ExecutionRequest,
    proxy_address: Option<&ProxyAddress>,
    working_directory: Option<&str>,
) -> Vec<(String, String)> {
    let resolved = resolved_env(request, working_directory);
    let strip_caller_proxy = proxy_address.is_some();
    let mut pairs: Vec<(String, String)> = env_pairs(&resolved)
        .into_iter()
        .filter(|(key, _)| !strip_caller_proxy || !PROXY_ENV_KEYS.contains(key))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    if let Some(addr) = proxy_address {
        let url = addr.to_url();
        for key in PROXY_INJECT_KEYS {
            pairs.push((key.to_string(), url.clone()));
        }
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{
        ExecutionRequest, NetworkAction, NetworkEgressPolicy, ProxyAddress, SeatbeltConfig,
    };

    #[allow(clippy::field_reassign_with_default)]
    fn base_request() -> ExecutionRequest {
        let mut request = ExecutionRequest::default();
        request.experimental_enabled = true;
        request.seatbelt = Some(SeatbeltConfig::default());
        request
    }

    fn terminal_probe(
        request: &ExecutionRequest,
        code: &str,
        args: &[&str],
        with_pty: bool,
    ) -> std::process::Output {
        let mut request = request.clone();
        request.script_code = r#"exec /usr/bin/python3 -I -c "$@""#.to_string();
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let (mut command, _pty) = build_sandbox_command(
            &request,
            None,
            !with_pty,
            false,
            with_pty.then_some(PtySize::default()),
            &mut logger,
        )
        .expect("build probe command");
        command
            .arg("terminal-probe")
            .arg(code)
            .args(args)
            .current_dir("/")
            .env_clear()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if !with_pty {
            command.stdin(Stdio::null());
        }
        let mut child = command.spawn().expect("spawn terminal probe");
        if let Err(error) = wait_with_timeout(&mut child, Some(Duration::from_secs(20))) {
            let _ = child.kill();
            let _ = child.wait();
            match error {
                WaitError::Timeout => panic!("terminal probe timed out"),
                WaitError::Io(error) => panic!("terminal probe wait failed: {error}"),
            }
        }
        child.wait_with_output().expect("collect terminal probe")
    }

    fn assert_unrelated_terminal_denied(nested_pty: bool, gui_access: bool, with_pty: bool) {
        use std::os::fd::AsRawFd;

        use nix::fcntl::{fcntl, FcntlArg, FdFlag};

        let terminal = nix::pty::openpty(None, None).expect("allocate disposable host PTY");
        for fd in [&terminal.master, &terminal.slave] {
            fcntl(fd.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
                .expect("do not inherit the host PTY");
        }
        let path = nix::unistd::ttyname(&terminal.slave).expect("host PTY path");
        for (read, write) in [(true, false), (false, true), (true, true)] {
            std::fs::OpenOptions::new()
                .read(read)
                .write(write)
                .open(&path)
                .expect("host can open the disposable terminal");
        }
        let mut request = base_request();
        request.seatbelt = Some(SeatbeltConfig {
            nested_pty,
            gui_access,
            ..Default::default()
        });
        request.policy.ui.disable = !gui_access;
        let output = terminal_probe(
            &request,
            r#"
import errno, fcntl, os, sys, termios
for mode in (os.O_RDONLY, os.O_WRONLY, os.O_RDWR):
    try:
        fd = os.open(sys.argv[1], mode | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError as error:
        assert error.errno in (errno.EPERM, errno.EACCES), error
    else:
        os.close(fd)
        raise AssertionError("unrelated terminal opened")
if sys.argv[2] == "allow":
    master, slave = os.openpty()
    try:
        assert os.isatty(slave)
        termios.tcgetattr(slave)
        fcntl.ioctl(slave, termios.TIOCGETD, bytes(4))
    finally:
        os.close(slave)
        os.close(master)
else:
    try:
        master, slave = os.openpty()
    except OSError as error:
        assert error.errno in (errno.EPERM, errno.EACCES), error
    else:
        os.close(slave)
        os.close(master)
        raise AssertionError("nested PTY allocation allowed")
"#,
            &[
                path.to_str().expect("UTF-8 terminal path"),
                if nested_pty || gui_access {
                    "allow"
                } else {
                    "deny"
                },
            ],
            with_pty,
        );
        assert!(
            output.status.success(),
            "terminal isolation probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn nested_pty_cannot_open_unrelated_host_terminals() {
        assert_unrelated_terminal_denied(true, false, false);
    }

    #[test]
    fn nested_pty_disabled_cannot_open_unrelated_host_terminals() {
        assert_unrelated_terminal_denied(false, false, false);
    }

    #[test]
    fn gui_access_cannot_open_unrelated_host_terminals() {
        assert_unrelated_terminal_denied(false, true, false);
    }

    #[test]
    fn caller_owned_pty_cannot_open_unrelated_host_terminals() {
        assert_unrelated_terminal_denied(true, false, true);
    }

    #[test]
    fn preopened_terminal_keeps_stdio_and_controlling_tty() {
        let output = terminal_probe(
            &base_request(),
            r#"
import fcntl, os, termios
assert os.isatty(0)
termios.tcgetattr(0)
fcntl.ioctl(0, termios.TIOCGETD, bytes(4))
fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
termios.tcgetattr(fd)
os.close(fd)
"#,
            &[],
            true,
        );
        assert!(
            output.status.success(),
            "assigned terminal probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn gui_access_rejects_caller_owned_pty() {
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let error = spawn_exec(
            &base_request(),
            true,
            StdioMode::Pty(PtySize::default()),
            &mut logger,
            None,
        )
        .err()
        .expect("guiAccess PTY must be rejected");
        assert!(error.error_message.contains("caller-owned PTY"));
    }

    #[test]
    fn the_default_block_survives_the_proxy_rewrite() {
        // The 0.9 default block must not bypass the proxy stripping in
        // `resolve_environment`.
        let mut request = base_request();
        request.env = Some(vec!["HTTP_PROXY=http://attacker.example:9999".into()]);
        request.inherit_default_env = true;
        let addr = ProxyAddress::new("127.0.0.1".into(), 8888);
        let pairs = resolve_environment(&request, Some(&addr), None);

        assert!(pairs
            .iter()
            .any(|(k, v)| k == "PATH" && v == DEFAULT_SANDBOX_PATH));
        let proxies: Vec<_> = pairs
            .iter()
            .filter(|(k, _)| k == "HTTP_PROXY")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(proxies, vec!["http://127.0.0.1:8888"]);
    }

    /// Capture what `log_generated_profile` puts into a buffering logger.
    fn logged_profile(profile: &str) -> String {
        use crate::mxc_common::logger::Mode;
        let mut logger = Logger::new(Mode::Buffer);
        log_generated_profile(profile, &mut logger);
        logger.get_buffer().to_string()
    }

    /// Slice the profile back out from between the markers.
    fn extract_profile(log: &str) -> String {
        let body = log
            .split_once(PROFILE_LOG_BEGIN)
            .expect("begin marker missing")
            .1
            .split_once(PROFILE_LOG_END)
            .expect("end marker missing")
            .0;
        body.trim_matches('\n').to_string()
    }

    #[test]
    fn logs_the_profile_verbatim_between_markers() {
        let profile = "(version 1)\n(deny default)\n;; --- comment ---\n(allow file-read*\n    (subpath \"/tmp\")\n)\n";
        assert_eq!(
            extract_profile(&logged_profile(profile)),
            profile.trim_end()
        );
    }

    #[test]
    fn logs_the_profile_one_line_per_write() {
        let profile = "(version 1)\n(deny default)\n(allow process-exec)\n";
        let log = logged_profile(profile);
        assert_eq!(
            log.lines().count(),
            5,
            "expected 3 profile lines plus 2 markers, got: {log}"
        );
    }

    #[test]
    fn profile_markers_cannot_collide_with_profile_content() {
        // Slicing is only sound if no profile line can reproduce a marker.
        for marker in [PROFILE_LOG_BEGIN, PROFILE_LOG_END] {
            assert!(marker.starts_with("Seatbelt: "), "got: {marker}");
            assert!(!marker.starts_with('('), "got: {marker}");
            assert!(!marker.starts_with(";;"), "got: {marker}");
        }
        assert_ne!(PROFILE_LOG_BEGIN, PROFILE_LOG_END);
    }

    #[test]
    fn logs_an_empty_profile_without_losing_the_markers() {
        // `profileOverride: ""` is degenerate but reachable.
        let log = logged_profile("");
        assert!(log.contains(PROFILE_LOG_BEGIN), "got: {log}");
        assert!(log.contains(PROFILE_LOG_END), "got: {log}");
        assert_eq!(extract_profile(&log), "");
    }

    #[test]
    fn logs_the_profile_the_backend_actually_built() {
        // Guards the seam: a re-derived or stale profile must not be logged.
        let mut request = base_request();
        request.policy.readonly_paths = vec!["/tmp/mxc-profile-log-probe".into()];
        let profile = build_profile_with_proxy(&request, None).expect("profile builds");

        assert_eq!(
            extract_profile(&logged_profile(&profile)),
            profile.trim_end()
        );
        assert!(profile.contains("mxc-profile-log-probe"), "got: {profile}");
    }

    /// Directly constructed requests must receive the same rejection as parsed
    /// requests, before the profile or any proxy is created.
    #[test]
    fn rejects_proxy_with_egress_allow_bypassing_the_parser() {
        let runner = SeatbeltScriptRunner::new();
        let mut request = base_request();
        request.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        request.policy.network_proxy.address = Some(ProxyAddress::from_url(
            "http://127.0.0.1:8080",
            "127.0.0.1".into(),
            8080,
        ));
        let err = runner.validate(&request).unwrap_err();
        assert!(
            err.error_message
                .contains("requires network.egress.default='deny'"),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_remote_proxy_under_deny_bypassing_the_parser() {
        let mut request = base_request();
        request.policy.network_proxy.address = Some(ProxyAddress::from_url(
            "http://proxy.corp:3128",
            "proxy.corp".into(),
            3128,
        ));
        let runner = SeatbeltScriptRunner::new();
        let err = runner.validate(&request).unwrap_err();
        assert!(
            err.error_message
                .contains("runtimeConfig.networkProxy must name a loopback endpoint"),
            "{err:?}"
        );
    }

    #[test]
    fn accepts_loopback_proxy_under_deny_in_every_spelling() {
        let runner = SeatbeltScriptRunner::new();
        for host in ["127.0.0.1", "localhost", "[::1]", "::1"] {
            let mut request = base_request();
            request.policy.network_proxy.address = Some(ProxyAddress::from_url(
                "http://proxy:8080",
                host.into(),
                8080,
            ));
            assert!(runner.validate(&request).is_ok(), "rejected {host}");
        }
    }

    #[test]
    fn declares_directional_network_policy_support() {
        let runner = SeatbeltScriptRunner::new();
        let support = runner.network_policy_support();
        assert!(support.contains(NetworkPolicySupport::EGRESS_DEFAULT));
        assert!(support.contains(NetworkPolicySupport::INGRESS_DEFAULT));
        assert!(support.contains(NetworkPolicySupport::HOST_LOOPBACK));
        assert!(support.contains(NetworkPolicySupport::RUNTIME_PROXY));
        // No CIDR/port/protocol rule engine and no ProcessContainer-only
        // per-peer proxy identity concept.
        assert!(!support.contains(NetworkPolicySupport::EGRESS_RULES));
        assert!(!support.contains(NetworkPolicySupport::PROXY_PEER_IDENTITY));
    }

    #[test]
    fn rejects_host_loopback_allow_under_an_ingress_default_deny() {
        // The inexpressible pair: `hostLoopback: allow` promises inbound host
        // loopback, and the rule that would carry it is the blanket
        // `network-inbound` grant that `default: deny` withholds.
        let mut request = base_request();
        request.policy.network_egress =
            Some(crate::mxc_common::models::NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(crate::mxc_common::models::NetworkIngressPolicy {
            default: crate::mxc_common::models::NetworkAction::Deny,
            host_loopback: crate::mxc_common::models::NetworkAction::Allow,
        });
        let runner = SeatbeltScriptRunner::new();
        let response = runner.validate(&request).unwrap_err();
        assert!(response.error_message.contains("hostLoopback='allow'"));
        assert!(response.error_message.contains("default='deny'"));
        assert!(!response.error_message.contains("inherit 'default'"));
    }

    /// The other divergent pair is expressible and must be accepted: it is the
    /// only way to ask for a listener while keeping the container-to-host
    /// direction closed, which is what a runtime proxy's egress confinement
    /// rests on.
    #[test]
    fn accepts_host_loopback_deny_under_an_ingress_default_allow() {
        let mut request = base_request();
        request.policy.network_egress =
            Some(crate::mxc_common::models::NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(crate::mxc_common::models::NetworkIngressPolicy {
            default: crate::mxc_common::models::NetworkAction::Allow,
            host_loopback: crate::mxc_common::models::NetworkAction::Deny,
        });
        let runner = SeatbeltScriptRunner::new();
        assert!(runner.validate(&request).is_ok());
    }

    /// The two divergent-pair decisions must survive the exact-contract parse,
    /// not just a hand-built `ContainerPolicy`. An adapter that dropped
    /// `ingress` would leave other backend tests green while silently losing
    /// the posture the caller asked for.
    fn validate_parsed(json: &str) -> Result<(), String> {
        use crate::mxc_common::config_parser::load_mxc_request_from_json;
        use crate::mxc_common::logger::Mode;
        use crate::mxc_common::state_aware_request::MxcRequest;

        let mut logger = Logger::new(Mode::Buffer);
        let parsed = load_mxc_request_from_json(json, &mut logger).expect("config parses");
        let mut request = match parsed {
            MxcRequest::OneShot(request) => request,
            _ => panic!("expected a one-shot request"),
        };
        request.seatbelt.get_or_insert_with(SeatbeltConfig::default);
        SeatbeltScriptRunner::new()
            .validate(&request)
            .map_err(|response| response.error_message)
    }

    fn v09_ingress_config(default: &str, host_loopback: &str) -> String {
        format!(
            r#"{{
                "version": "0.9.0-alpha",
                "containment": "seatbelt",
                "process": {{"commandLine": "echo hi"}},
                "network": {{
                    "egress": {{"default": "deny"}},
                    "ingress": {{"default": "{default}", "hostLoopback": "{host_loopback}"}}
                }}
            }}"#
        )
    }

    #[test]
    fn schema_v09_host_loopback_deny_under_ingress_default_allow_is_accepted() {
        assert!(validate_parsed(&v09_ingress_config("allow", "deny")).is_ok());
    }

    #[test]
    fn schema_v09_host_loopback_allow_under_ingress_default_deny_is_rejected() {
        let message = validate_parsed(&v09_ingress_config("deny", "allow")).unwrap_err();
        assert!(message.contains("hostLoopback='allow'"));
        assert!(message.contains("default='deny'"));
    }

    #[test]
    fn accepts_matching_ingress_default_and_host_loopback() {
        let mut request = base_request();
        request.policy.network_egress =
            Some(crate::mxc_common::models::NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(crate::mxc_common::models::NetworkIngressPolicy {
            default: crate::mxc_common::models::NetworkAction::Allow,
            host_loopback: crate::mxc_common::models::NetworkAction::Allow,
        });
        let runner = SeatbeltScriptRunner::new();
        assert!(runner.validate(&request).is_ok());
    }

    /// Look up the last value set for `key` in a resolved env list.
    fn env_value<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
        pairs
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn resolve_environment_without_proxy_passes_through() {
        let mut request = base_request();
        request.env = Some(vec!["FOO=bar".into(), "BAZ=qux".into()]);
        let pairs = resolve_environment(&request, None, None);
        assert_eq!(env_value(&pairs, "FOO"), Some("bar"));
        assert_eq!(env_value(&pairs, "BAZ"), Some("qux"));
        // No proxy vars injected.
        assert!(env_value(&pairs, "HTTP_PROXY").is_none());
    }

    #[test]
    fn resolve_environment_injects_proxy_url() {
        let request = base_request();
        let addr = ProxyAddress::new("127.0.0.1".into(), 8888);
        let pairs = resolve_environment(&request, Some(&addr), None);
        for key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            assert_eq!(
                env_value(&pairs, key),
                Some("http://127.0.0.1:8888"),
                "{key} must point at the proxy"
            );
        }
    }

    #[test]
    fn resolve_environment_strips_caller_proxy_when_active() {
        let mut request = base_request();
        request.env = Some(vec![
            "HTTP_PROXY=http://attacker.example:9999".into(),
            "https_proxy=http://attacker.example:9999".into(),
            "ALL_PROXY=http://attacker.example:9999".into(),
            "NO_PROXY=localhost".into(),
            "KEEP=me".into(),
        ]);
        let addr = ProxyAddress::new("127.0.0.1".into(), 7777);
        let pairs = resolve_environment(&request, Some(&addr), None);
        // Legitimate non-proxy var is preserved.
        assert_eq!(env_value(&pairs, "KEEP"), Some("me"));
        // Caller-supplied proxy values are overridden with ours; NO_PROXY dropped.
        assert_eq!(
            env_value(&pairs, "HTTP_PROXY"),
            Some("http://127.0.0.1:7777")
        );
        assert_eq!(
            env_value(&pairs, "https_proxy"),
            Some("http://127.0.0.1:7777")
        );
        assert_eq!(
            env_value(&pairs, "ALL_PROXY"),
            Some("http://127.0.0.1:7777")
        );
        assert!(env_value(&pairs, "NO_PROXY").is_none());
        // The attacker's URL must not survive anywhere.
        assert!(!pairs.iter().any(|(_, v)| v.contains("attacker.example")));
    }

    #[test]
    fn resolve_environment_keeps_caller_proxy_when_inactive() {
        // With no proxy active the builder must not touch caller-supplied
        // vars whose keys happen to match PROXY_ENV_KEYS.
        let mut request = base_request();
        request.env = Some(vec!["HTTP_PROXY=http://caller.example:8080".into()]);
        let pairs = resolve_environment(&request, None, None);
        assert_eq!(
            env_value(&pairs, "HTTP_PROXY"),
            Some("http://caller.example:8080")
        );
    }

    /// An explicit directory wins; otherwise the first policy grant is used.
    #[test]
    fn working_directory_resolves_explicit_then_policy_grant() {
        let mut explicit = base_request();
        explicit.working_directory = "/tmp/explicit".into();
        assert_eq!(
            resolved_working_directory_opt(&explicit).as_deref(),
            Some("/tmp/explicit")
        );

        let mut policy_fallback = base_request();
        policy_fallback.policy.readwrite_paths = vec!["/tmp".into()];
        assert_eq!(
            resolved_working_directory_opt(&policy_fallback).as_deref(),
            Some("/tmp")
        );
    }

    /// With nothing to resolve, the child still has to start somewhere, but
    /// `HOME` must not follow it there: `/` is not writable.
    #[test]
    fn an_unresolved_working_directory_does_not_become_home() {
        let request = base_request();
        assert_eq!(resolved_working_directory_opt(&request), None);
        assert_eq!(UNRESOLVED_WORKING_DIRECTORY, "/");

        let pairs = resolve_environment(&request, None, None);
        assert_eq!(
            env_value(&pairs, "HOME"),
            None,
            "HOME stays unset when no directory resolves"
        );
    }

    /// `HOME` follows the directory the runner will actually `chdir` into,
    /// including the `~` expansion, rather than being re-derived from the
    /// request.
    #[test]
    fn home_follows_the_directory_the_child_starts_in() {
        let request = base_request();
        let pairs = resolve_environment(&request, None, Some("/Users/someone/work"));
        assert_eq!(env_value(&pairs, "HOME"), Some("/Users/someone/work"));
    }

    /// A relative `process.cwd` is relative to the launching process.
    #[test]
    fn relative_working_directory_is_anchored_to_the_launching_process() {
        let launcher = || Ok(PathBuf::from("/tmp/launcher"));
        assert_eq!(
            absolute_working_directory_with("work", launcher).unwrap(),
            "/tmp/launcher/work"
        );
    }

    /// An absolute directory is passed through spelled exactly as written —
    /// symlinks stay unresolved so `PWD` matches what `spawn_exec` exports —
    /// and needs no launch directory. `chdir` accepts it even from a launcher
    /// whose own directory has been removed, so a failure to read that
    /// directory must not fail the request: the panicking closure asserts it is
    /// never consulted.
    #[test]
    fn absolute_working_directory_is_left_untouched_without_querying_the_launcher() {
        let unused = || panic!("the launch directory must not be read for an absolute path");
        assert_eq!(
            absolute_working_directory_with("/tmp/mxc_work", unused).unwrap(),
            "/tmp/mxc_work"
        );
    }

    /// A relative value cannot be anchored without the launcher's directory, so
    /// that failure propagates rather than being silently left relative.
    #[test]
    fn relative_working_directory_propagates_a_missing_launch_directory() {
        let gone = || {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "launch directory removed",
            ))
        };
        let err = absolute_working_directory_with("work", gone).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }
}
