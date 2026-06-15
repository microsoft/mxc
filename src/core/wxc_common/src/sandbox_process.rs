// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Handle-based ("streaming") sandbox execution.
//!
//! [`ScriptRunner`](crate::script_runner::ScriptRunner) owns the whole
//! lifecycle (spawn → wait → drain → return), which is fine for fire-and-
//! forget runs but cannot expose the running child. This module adds the
//! interface for the other model: spawn the sandboxed process and hand the
//! caller a [`SandboxProcess`] handle they can write to, read from, wait on,
//! and kill while it runs.
//!
//! As with [`ScriptRunner`](crate::script_runner::ScriptRunner), the traits
//! live in `wxc_common` (the cross-platform foundation) while the
//! implementations live in the per-backend crates — `wxc_common` must not
//! depend on any `backends/*` crate.

use std::io::{Read, Write};

use crate::logger::Logger;
use crate::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use crate::script_runner::ScriptRunner;

/// A handle to a running sandboxed process.
///
/// Modelled on [`std::process::Child`]: the caller may `take_*` the std
/// streams to drive them directly (and is then responsible for draining any
/// stream they take, to avoid the child blocking on a full pipe), then
/// [`wait`](SandboxProcess::wait) for exit or [`kill`](SandboxProcess::kill)
/// it.
///
/// Any stdout/stderr stream the caller does **not** take is drained and
/// discarded internally by [`wait`](SandboxProcess::wait) so the child can
/// never block on a full pipe.
///
/// No pty is ever allocated; the streams are ordinary pipes.
///
/// # Pipe-deadlock contract (read both ends concurrently)
///
/// stdout and stderr are independent OS pipes with bounded kernel buffers. If
/// one is left undrained while the child keeps writing to it, the child blocks
/// on the full pipe — and if the reader is meanwhile blocked waiting on the
/// *other* stream (or on the child to exit), the two deadlock. So both ends
/// must be consumed **concurrently**, never one fully then the other:
///
/// - **Implementors** of [`wait`](SandboxProcess::wait) must drain the
///   not-taken stdout and stderr on separate threads (or non-blocking I/O)
///   before/while waiting on the child — not sequentially. The in-tree
///   backends spawn one reader thread per stream.
/// - **Callers** that `take_stdout()` *and* `take_stderr()` and read them to
///   EOF must likewise read them on separate threads; reading one to EOF
///   before touching the other can hang on output-heavy children. Taking only
///   one stream (leaving the other for `wait()` to drain) is always safe.
pub trait SandboxProcess: Send {
    /// Take ownership of the child's stdin so the caller can write to it.
    /// Returns `None` if already taken. Drop the writer to send EOF.
    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>>;

    /// Take ownership of the child's stdout for live reading. Returns `None`
    /// if already taken. A taken stream is **not** drained by
    /// [`wait`](SandboxProcess::wait).
    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>>;

    /// Take ownership of the child's stderr for live reading. Returns `None`
    /// if already taken. A taken stream is **not** drained by
    /// [`wait`](SandboxProcess::wait).
    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>>;

    /// Non-blocking exit check. `Ok(Some(code))` if the child has exited,
    /// `Ok(None)` if it is still running.
    fn try_wait(&mut self) -> std::io::Result<Option<i32>>;

    /// The OS process id of the sandboxed child (its PID on Unix, process id
    /// on Windows). Useful for external monitoring or a caller-driven process
    /// tree kill.
    ///
    /// Only meaningful while the child is alive. On Unix the PID may be reused
    /// by an unrelated process once the child has been reaped (by
    /// [`wait`](SandboxProcess::wait)), so do not act on it after waiting.
    fn id(&self) -> u32;

    /// Request termination of the sandboxed process **and its descendants**
    /// (a process-tree kill). On Unix the child leads its own process group
    /// and this signals the whole group (graceful `SIGTERM`, escalating to
    /// `SIGKILL` after a short grace period); on Windows it terminates the job
    /// object the child is assigned to. Reaping happens in
    /// [`wait`](SandboxProcess::wait).
    fn kill(&mut self) -> std::io::Result<()>;

    /// Block until the child exits (honouring the request's `scriptTimeout`,
    /// where `0` means wait forever) and return its exit code.
    ///
    /// Any stdout/stderr the caller did not `take_*` is drained and discarded
    /// while waiting so the child can never block on a full pipe. If the
    /// timeout elapses, the child and its tree are killed and
    /// [`ErrorKind::TimedOut`](std::io::ErrorKind::TimedOut) is returned.
    ///
    /// Implementors must drain the not-taken stdout and stderr **concurrently**
    /// (not one then the other) — see the type-level pipe-deadlock contract.
    fn wait(&mut self) -> std::io::Result<i32>;
}

/// Spawn a thread that reads `reader` to EOF and discards it, so a stream the
/// caller did not take can't block the child on a full pipe. Returns `None`
/// when there is nothing to drain.
pub fn spawn_discard<R: Read + Send + 'static>(
    reader: Option<R>,
) -> Option<std::thread::JoinHandle<()>> {
    reader.map(|mut r| {
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut r, &mut std::io::sink());
        })
    })
}

/// Join a [`spawn_discard`] thread (no-op when absent).
pub fn join_discard(handle: Option<std::thread::JoinHandle<()>>) {
    if let Some(t) = handle {
        let _ = t.join();
    }
}

/// Take a readable stream out of an `Option` and box it as a trait object, for
/// the [`SandboxProcess::take_stdout`] / [`SandboxProcess::take_stderr`]
/// accessors. Returns `None` if already taken.
pub fn take_boxed_read<R: Read + Send + 'static>(
    slot: &mut Option<R>,
) -> Option<Box<dyn Read + Send>> {
    slot.take().map(|r| Box::new(r) as Box<dyn Read + Send>)
}

/// Take a writable stream out of an `Option` and box it as a trait object, for
/// the [`SandboxProcess::take_stdin`] accessor. Returns `None` if already taken.
pub fn take_boxed_write<W: Write + Send + 'static>(
    slot: &mut Option<W>,
) -> Option<Box<dyn Write + Send>> {
    slot.take().map(|w| Box::new(w) as Box<dyn Write + Send>)
}

/// Process-tree kill for a Unix child that leads its own process group — the
/// in-tree backends arrange this via `setsid()` (Seatbelt) or
/// `process_group(0)` (Bubblewrap), so the child's pgid equals its pid: a
/// graceful `SIGTERM` to the whole group, then a `SIGKILL` sweep after `grace`.
/// Signalling the negative pgid targets only that group — never the host's —
/// and is a no-op once the child has exited.
///
/// The final `SIGKILL` is sent unconditionally so a descendant forked around
/// the `SIGTERM` (and thus never signalled) can't survive and leave a later
/// `wait()` blocking for its full runtime; while such a descendant exists it
/// keeps the group alive (pgid still valid), and if none remains the sweep is a
/// harmless `ESRCH`. Shared by the Unix backends' streaming `kill()` and their
/// run-to-completion timeout branches.
#[cfg(unix)]
pub fn group_kill(
    child: &mut std::process::Child,
    grace: std::time::Duration,
) -> std::io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    let pgid = child.id() as i32;
    // SAFETY: `kill(2)` with a negative pgid signals the child's own process
    // group; the arguments are plain integers with no memory safety concerns.
    unsafe {
        libc::kill(-pgid, libc::SIGTERM);
    }
    let deadline = std::time::Instant::now() + grace;
    loop {
        if child.try_wait()?.is_some() || std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // SAFETY: as above.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    Ok(())
}

/// How a [`SandboxBackend`] wires the sandboxed child's standard streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioMode {
    /// stdin/stdout/stderr are fresh pipes the caller drives via the handle's
    /// `take_*` accessors (the `mxc` library / streaming path). The child sees
    /// no TTY and leads its own process group so it can be tree-terminated.
    Pipes,
    /// The child inherits the current process's stdin/stdout/stderr (the CLI
    /// executor path): its output goes straight to the binary's own stdio, so
    /// the child sees a TTY exactly when the binary does. The returned handle's
    /// `take_*` all return `None`; [`wait`](SandboxProcess::wait) just waits.
    Inherit,
}

/// A containment backend that spawns a sandboxed process and hands back a
/// [`SandboxProcess`] handle — the single entry point for starting a sandbox.
///
/// The caller picks how the child's stdio is wired ([`StdioMode`]) and then
/// drives the handle: stream it ([`StdioMode::Pipes`]) or just
/// [`wait`](SandboxProcess::wait) ([`StdioMode::Inherit`]). The `mxc` library
/// calls this directly with [`StdioMode::Pipes`]; the CLI executor binaries
/// reach it through the [`RtcRunner`] bridge.
pub trait SandboxBackend {
    /// Backend-specific validation, run before [`spawn`](SandboxBackend::spawn)
    /// and on dry-run. Override to reject unsupported policies; default accepts.
    fn validate(&self, _request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        Ok(())
    }

    /// Apply this backend's containment and spawn the sandboxed process with
    /// stdio wired per `stdio`, returning a handle. On a validation or spawn
    /// failure returns a [`ScriptResponse`] carrying the error.
    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse>;

    /// Optional post-exit diagnostics for the run-to-completion (binary) path:
    /// when the child exits non-zero, return a more actionable error message
    /// (e.g. a known AppContainer filesystem-permission failure). Default: none.
    /// The streaming/library path does not call this.
    fn diagnose_exit(&self, _request: &ExecutionRequest, _exit_code: i32) -> Option<String> {
        None
    }
}

/// The single run-to-completion bridge: adapts any [`SandboxBackend`] to the
/// [`ScriptRunner`] contract the executor binaries (`wxc-exec` / `lxc-exec` /
/// `mxc-exec-mac`) dispatch over.
///
/// It spawns the child with [`StdioMode::Inherit`] — so the sandboxed process
/// reads/writes the binary's own stdio directly (a TTY when the binary has
/// one) — and [`wait`](SandboxProcess::wait)s for exit, mapping the outcome to
/// a [`ScriptResponse`]. Because the child streams straight to the binary's
/// stdio, `standard_out`/`standard_err` stay empty (the binaries already print
/// those, which is then a no-op).
///
/// This is the *only* run-to-completion logic for these backends; the backends
/// themselves expose just [`SandboxBackend::spawn`].
pub struct RtcRunner<B>(pub B);

impl<B> RtcRunner<B> {
    /// Wrap a [`SandboxBackend`] so it can be dispatched as a [`ScriptRunner`].
    pub fn new(backend: B) -> Self {
        Self(backend)
    }
}

impl<B: SandboxBackend> ScriptRunner for RtcRunner<B> {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        self.0.validate(request)
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        let mut child = match self.0.spawn(request, logger, StdioMode::Inherit) {
            Ok(child) => child,
            Err(response) => return response,
        };
        match child.wait() {
            Ok(exit_code) => {
                let mut response = ScriptResponse {
                    exit_code,
                    failure_phase: if exit_code == 0 {
                        FailurePhase::None
                    } else {
                        FailurePhase::ProcessExited
                    },
                    ..Default::default()
                };
                // Let the backend enrich a non-zero exit with an actionable
                // message (the child streamed live, so the response is otherwise
                // empty).
                if exit_code != 0 {
                    if let Some(msg) = self.0.diagnose_exit(request, exit_code) {
                        logger.log_line(&format!("Error: Launch diagnostic: {msg}"));
                        response.error_message = msg.clone();
                        response.standard_err.push_str(&msg);
                    }
                }
                response
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => ScriptResponse {
                exit_code: -1,
                error_message: format!("script timed out after {}ms", request.script_timeout),
                failure_phase: FailurePhase::Timeout,
                ..Default::default()
            },
            Err(e) => ScriptResponse::error(&format!("wait failed: {e}")),
        }
    }
}
