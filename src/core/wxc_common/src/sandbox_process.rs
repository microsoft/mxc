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
use crate::models::{ExecutionRequest, ScriptResponse};

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

/// A backend that can spawn a [`SandboxProcess`] handle.
///
/// The streaming analogue of [`ScriptRunner`](crate::script_runner::ScriptRunner).
/// Implementors apply the same containment setup they would for a
/// run-to-completion execution, but spawn with piped stdio and return the
/// handle instead of waiting.
pub trait StreamingRunner {
    /// Spawn the sandboxed process and return a handle to it. On failure
    /// (validation or spawn error) returns a [`ScriptResponse`] carrying the
    /// error message, mirroring the `ScriptRunner` error convention.
    fn spawn_streaming(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse>;
}
