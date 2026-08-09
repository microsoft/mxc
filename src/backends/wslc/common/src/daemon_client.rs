// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase-process side of the state-aware WSLc control protocol.
//!
//! Each state-aware lifecycle phase (`provision` / `start` / `exec` / `stop` /
//! `deprovision`) runs as a short-lived process that drives the long-lived
//! `wxc-wslc-daemon` over an owner-only named pipe. This module is the client
//! half: it discovers (or spawns) the daemon, then issues one
//! [`DaemonRequest`] per connection and decodes the [`DaemonResponse`] (and, for
//! exec, the [`StreamFrame`] data phase).
//!
//! # Sync by design
//! The daemon server is async (tokio), but the client is deliberately
//! **blocking**: a phase process is otherwise synchronous, `wslc_common` has no
//! tokio dependency, and the framing (`[len: u32 LE][json]`) is trivial over
//! blocking `std::io`. A Windows named pipe opens as an ordinary synchronous
//! file handle, so `std::fs::File` read/write is all that is needed.
//!
//! # Discovery / spawn
//! [`DaemonClient::connect`] fast-paths onto a live, ready, protocol-compatible
//! daemon. Otherwise it takes the cross-process [`TransitionLock`] (so two phase
//! processes cannot both spawn a daemon), re-checks, spawns
//! `wxc-wslc-daemon.exe` (detached, co-located with the current executable) if
//! none exists, and waits for it to publish a `ready` record.
//!
//! Windows-only: the daemon and its named-pipe transport are a Windows feature
//! (`daemon_record` provides non-Windows stubs, but there is no daemon there).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::daemon_protocol::{
    encode_frame, DaemonRequest, DaemonResponse, DeprovisionConfig, ErrKind, ExecConfig,
    ProvisionConfig, StartConfig, StopConfig, StreamFrame, MAX_FRAME_SIZE, PROTOCOL_VERSION,
};
use crate::daemon_record::{live_daemon, DaemonRecord, TransitionLock};

/// Max wait for a freshly spawned (or concurrently starting) daemon to publish a
/// `ready` record.
const READY_TIMEOUT: Duration = Duration::from_secs(60);

/// Max wait to acquire the daemon spawn/teardown transition lock. Must exceed
/// [`READY_TIMEOUT`]: the lock holder retains it for the whole readiness wait, so
/// a second client has to be willing to wait at least that long — otherwise it
/// would give up while the first daemon is still validly starting and report a
/// spurious failure.
const SPAWN_LOCK_TIMEOUT: Duration = Duration::from_secs(75);

/// Poll cadence while waiting for the `ready` record.
const READY_POLL: Duration = Duration::from_millis(100);

/// Max wait when opening the daemon pipe, to ride out the brief window between
/// the server accepting one client and re-creating the next listening instance.
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Retry cadence for a transiently busy/absent pipe instance.
const OPEN_RETRY: Duration = Duration::from_millis(20);

// Win32 error codes for the transient pipe-open conditions worth retrying.
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PIPE_BUSY: i32 = 231;

/// The captured result of an exec run. Live stdout/stderr framing is a daemon
/// fill-in; today the daemon returns only the terminal exit code, so these
/// buffers are usually empty, but the client already accumulates any
/// [`StreamFrame::Stdout`] / [`StreamFrame::Stderr`] the daemon sends.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// A connected handle to the live daemon. Cheap to hold: it caches only the
/// resolved pipe name and opens a fresh pipe connection per request (one request
/// per connection, matching the server).
pub struct DaemonClient {
    pipe_name: String,
}

impl DaemonClient {
    /// Discover the live daemon, spawning it if necessary, and return a client
    /// bound to its pipe.
    pub fn connect() -> Result<Self> {
        // Fast path: a live, ready, compatible daemon already exists.
        if let Some(record) = ready_daemon()? {
            return Ok(Self::from_record(&record));
        }

        // Slow path: serialise spawn/teardown so two phase processes cannot both
        // spawn a daemon (or race a spawn against a teardown).
        let _lock = TransitionLock::acquire(SPAWN_LOCK_TIMEOUT)
            .context("acquire daemon spawn transition lock")?;

        let deadline = Instant::now() + READY_TIMEOUT;
        let mut spawned = false;
        loop {
            match live_daemon()? {
                Some(record) if !record.protocol_compatible() => {
                    bail!(
                        "a running wslc daemon speaks control protocol v{} but this build speaks \
                         v{}; refusing to drive it (stop the stale daemon and retry)",
                        record.protocol_version,
                        PROTOCOL_VERSION
                    );
                }
                Some(record) if record.ready => return Ok(Self::from_record(&record)),
                // A daemon is alive but still starting up: keep waiting for it to
                // flip `ready` rather than spawning a duplicate.
                Some(_) => {}
                None => {
                    if !spawned {
                        spawn_daemon()?;
                        spawned = true;
                    }
                    // Otherwise we already spawned; keep polling for its record.
                }
            }

            if Instant::now() >= deadline {
                bail!(
                    "timed out after {READY_TIMEOUT:?} waiting for the wslc daemon to become ready"
                );
            }
            std::thread::sleep(READY_POLL);
        }
    }

    fn from_record(record: &DaemonRecord) -> Self {
        Self {
            pipe_name: record.pipe_name.clone(),
        }
    }

    /// Liveness probe. Returns `Ok(())` iff the daemon answers with `Pong`.
    pub fn ping(&self) -> Result<()> {
        match self.call(&DaemonRequest::Ping)? {
            DaemonResponse::Pong => Ok(()),
            other => bail!("unexpected reply to ping: {other:?}"),
        }
    }

    /// Provision a container; returns the daemon-minted sandbox id.
    pub fn provision(&self, config: ProvisionConfig) -> Result<String> {
        match self.call(&DaemonRequest::Provision(config))? {
            DaemonResponse::Provisioned { sandbox_id } => Ok(sandbox_id),
            DaemonResponse::Err { kind, message } => Err(daemon_err(kind, &message)),
            other => bail!("unexpected reply to provision: {other:?}"),
        }
    }

    /// Start a provisioned container.
    pub fn start(&self, config: StartConfig) -> Result<()> {
        expect_ok(self.call(&DaemonRequest::Start(config))?)
    }

    /// Stop a running container (keeps it created for a later `start`).
    pub fn stop(&self, config: StopConfig) -> Result<()> {
        expect_ok(self.call(&DaemonRequest::Stop(config))?)
    }

    /// Deprovision (delete) a container.
    pub fn deprovision(&self, config: DeprovisionConfig) -> Result<()> {
        expect_ok(self.call(&DaemonRequest::Deprovision(config))?)
    }

    /// Run a command in a started container to completion, returning its exit
    /// code and any streamed output.
    ///
    /// After the daemon admits the exec with `Ok`, this reads the
    /// [`StreamFrame`] data phase — accumulating stdout/stderr — until the
    /// terminal [`StreamFrame::Exit`] (or [`StreamFrame::Error`]).
    pub fn exec(&self, config: ExecConfig) -> Result<ExecResult> {
        let mut pipe = self.open_pipe()?;
        write_frame(&mut pipe, &DaemonRequest::Exec(config))?;

        match read_frame::<DaemonResponse>(&mut pipe)? {
            DaemonResponse::Ok => {}
            DaemonResponse::Err { kind, message } => return Err(daemon_err(kind, &message)),
            other => bail!("unexpected exec admission reply: {other:?}"),
        }

        let mut result = ExecResult::default();
        loop {
            match read_frame::<StreamFrame>(&mut pipe)? {
                StreamFrame::Stdout { data } => result.stdout.extend_from_slice(&data),
                StreamFrame::Stderr { data } => result.stderr.extend_from_slice(&data),
                StreamFrame::Exit { code } => {
                    result.exit_code = code;
                    return Ok(result);
                }
                StreamFrame::Error { message } => bail!("exec failed: {message}"),
                StreamFrame::Stdin { .. } => {
                    bail!("protocol error: daemon sent a Stdin frame to the client")
                }
            }
        }
    }

    /// Issue a single non-streaming request on a fresh connection and return the
    /// daemon's reply.
    fn call(&self, request: &DaemonRequest) -> Result<DaemonResponse> {
        let mut pipe = self.open_pipe()?;
        write_frame(&mut pipe, request)?;
        read_frame(&mut pipe)
    }

    /// Open a fresh synchronous connection to the daemon pipe, retrying past the
    /// brief windows where every instance is momentarily busy or being recreated.
    fn open_pipe(&self) -> Result<File> {
        let deadline = Instant::now() + OPEN_TIMEOUT;
        loop {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.pipe_name)
            {
                Ok(file) => return Ok(file),
                Err(e) => {
                    let retryable = matches!(
                        e.raw_os_error(),
                        Some(ERROR_PIPE_BUSY) | Some(ERROR_FILE_NOT_FOUND)
                    );
                    if retryable && Instant::now() < deadline {
                        std::thread::sleep(OPEN_RETRY);
                        continue;
                    }
                    return Err(e).with_context(|| format!("open daemon pipe {}", self.pipe_name));
                }
            }
        }
    }
}

/// The live daemon iff it is ready and speaks this build's protocol version.
fn ready_daemon() -> Result<Option<DaemonRecord>> {
    match live_daemon()? {
        Some(record) if record.ready && record.protocol_compatible() => Ok(Some(record)),
        _ => Ok(None),
    }
}

/// Spawn `wxc-wslc-daemon.exe` (co-located with the current executable) as a
/// detached background process. It publishes its own discovery record; we do not
/// hold a handle to it.
fn spawn_daemon() -> Result<()> {
    let exe = daemon_exe_path()?;

    let mut cmd = Command::new(&exe);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: the daemon must outlive
        // this phase process and not share its console.
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    cmd.spawn()
        .with_context(|| format!("spawn wslc daemon {}", exe.display()))?;
    Ok(())
}

/// Resolve the daemon executable path: `wxc-wslc-daemon.exe` next to the current
/// executable (the build scripts stage it alongside `wxc-exec.exe`).
fn daemon_exe_path() -> Result<PathBuf> {
    let current = std::env::current_exe().context("resolve current executable path")?;
    let dir = current
        .parent()
        .context("current executable has no parent directory")?;
    let name = if cfg!(windows) {
        "wxc-wslc-daemon.exe"
    } else {
        "wxc-wslc-daemon"
    };
    Ok(dir.join(name))
}

/// Map a `DaemonResponse` expected to be a bare success into `Result<()>`.
fn expect_ok(response: DaemonResponse) -> Result<()> {
    match response {
        DaemonResponse::Ok => Ok(()),
        DaemonResponse::Err { kind, message } => Err(daemon_err(kind, &message)),
        other => bail!("unexpected reply (expected ok): {other:?}"),
    }
}

/// Build an error carrying the daemon's stable [`ErrKind`] token plus detail.
fn daemon_err(kind: ErrKind, message: &str) -> anyhow::Error {
    anyhow::anyhow!("daemon error [{kind:?}]: {message}")
}

/// Serialise `msg` and write it as one length-prefixed frame.
fn write_frame<T: Serialize>(pipe: &mut File, msg: &T) -> Result<()> {
    let frame = encode_frame(msg).context("encode frame")?;
    pipe.write_all(&frame).context("write frame")?;
    pipe.flush().context("flush frame")?;
    Ok(())
}

/// Read exactly one length-prefixed frame and deserialise it.
fn read_frame<T: DeserializeOwned>(pipe: &mut File) -> Result<T> {
    let mut len_buf = [0u8; 4];
    pipe.read_exact(&mut len_buf)
        .context("read frame length prefix")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        bail!("incoming frame length {len} exceeds maximum {MAX_FRAME_SIZE}");
    }
    let mut body = vec![0u8; len];
    pipe.read_exact(&mut body).context("read frame body")?;
    serde_json::from_slice(&body).context("deserialise frame body")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_exe_is_resolved_next_to_current_exe() {
        let path = daemon_exe_path().unwrap();
        let expected_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        assert_eq!(path.parent().unwrap(), expected_dir);
        assert!(path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("wxc-wslc-daemon"));
    }

    #[test]
    fn expect_ok_maps_variants() {
        assert!(expect_ok(DaemonResponse::Ok).is_ok());

        let err = expect_ok(DaemonResponse::Err {
            kind: ErrKind::NotStarted,
            message: "sandbox not started".to_string(),
        })
        .unwrap_err();
        assert!(err.to_string().contains("NotStarted"));
        assert!(err.to_string().contains("sandbox not started"));

        assert!(expect_ok(DaemonResponse::Pong).is_err());
    }

    #[test]
    fn daemon_err_carries_kind_and_message() {
        let err = daemon_err(ErrKind::Busy, "single-flight slot held");
        let text = err.to_string();
        assert!(text.contains("Busy"));
        assert!(text.contains("single-flight slot held"));
    }
}
