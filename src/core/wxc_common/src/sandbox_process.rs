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
/// # Abandoning a held-open stream (stdout/stderr closers)
///
/// A read on a taken stdout/stderr only ends at EOF — when **every** write end
/// closes. A backgrounded descendant that inherited the pipe can hold its write
/// end open long after the foreground command exits, so a caller blocked on
/// such a read would hang until that descendant finally exits. A plain
/// [`kill`](SandboxProcess::kill) would unblock it but also tear the descendant
/// down, defeating any grace window for backgrounded work.
///
/// [`stdout_closer`](SandboxProcess::stdout_closer) /
/// [`stderr_closer`](SandboxProcess::stderr_closer) hand back a
/// [`StreamCloser`] for exactly this case: calling
/// [`close`](StreamCloser::close) makes an in-flight or subsequent read on that
/// stream return EOF (`Ok(0)`) promptly **without** terminating the child.
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
    /// and this signals the whole group (an immediate `SIGKILL`, no graceful
    /// `SIGTERM` first); on Windows it terminates the job
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

    /// A closer that EOFs the stdout stream returned by
    /// [`take_stdout`](SandboxProcess::take_stdout), on demand, **without**
    /// killing the child — for abandoning a stream a backgrounded descendant is
    /// holding open past the foreground command's exit (a plain
    /// [`kill`](SandboxProcess::kill) would also take that descendant down).
    ///
    /// Intended for a stream the caller has **taken** and is reading:
    /// [`close`](StreamCloser::close) abandons that read, and may be called
    /// concurrently with it. [`wait`](SandboxProcess::wait) already cancels its
    /// own internal safety-drain of any *not-taken* stream once the child exits,
    /// so a closer is only useful on a taken stream — firing one on a not-taken
    /// stream while the child is still producing output would stall the child on
    /// a full pipe. Returns `None` when the stream is not interruptible — e.g.
    /// inherited stdio ([`StdioMode::Inherit`]), where the caller never reads
    /// from a handle stream. The default returns `None`.
    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        None
    }

    /// A closer for the stderr stream — see
    /// [`stdout_closer`](SandboxProcess::stdout_closer). The default returns
    /// `None`.
    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        None
    }
}

/// Abandons reads on one of a [`SandboxProcess`]'s standard streams: a call to
/// [`close`](StreamCloser::close) makes an in-flight or subsequent read on the
/// corresponding [`take_stdout`](SandboxProcess::take_stdout) /
/// [`take_stderr`](SandboxProcess::take_stderr) stream return EOF (`Ok(0)`)
/// promptly, **without** terminating the child.
///
/// Obtained from [`stdout_closer`](SandboxProcess::stdout_closer) /
/// [`stderr_closer`](SandboxProcess::stderr_closer). `Send + Sync` so a
/// watchdog thread (separate from the one blocked on the read) can hold and
/// fire it.
pub trait StreamCloser: Send + Sync {
    /// Promptly EOF the stream this closer was minted for. Idempotent and safe
    /// to call after the reader has already reached EOF or been dropped.
    fn close(&self);
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

/// Clone a stored stream canceller and box it as a [`StreamCloser`], for the
/// [`SandboxProcess::stdout_closer`] / [`SandboxProcess::stderr_closer`]
/// accessors. Returns `None` when there is no canceller (non-streamed stdio).
pub fn boxed_closer<C: StreamCloser + Clone + 'static>(
    canceller: &Option<C>,
) -> Option<Box<dyn StreamCloser>> {
    canceller
        .clone()
        .map(|c| Box::new(c) as Box<dyn StreamCloser>)
}

/// Join a not-taken stdout/stderr discard thread from
/// [`wait`](SandboxProcess::wait), first cancelling its read so the join can't
/// block. When the stream was drained (a [`spawn_discard`] thread exists), fire
/// `canceller` before joining: a backgrounded descendant holding the pipe's
/// write end open past the foreground child's exit would otherwise keep the
/// discard [`io::copy`](std::io::copy) — and thus `wait()` — from ever returning
/// under a wait-forever (`scriptTimeout == 0`) timeout. The drained output is
/// discarded regardless, so cutting it short is harmless.
///
/// Call *after* the child has exited (so its own output has drained normally).
/// A no-op when the caller took the stream (`drain` is `None`): there is no
/// thread to join, and the canceller must not fire while the caller may still be
/// reading.
pub fn cancel_and_join_discard<C: StreamCloser>(
    drain: Option<std::thread::JoinHandle<()>>,
    canceller: &Option<C>,
) {
    if drain.is_some() {
        if let Some(canceller) = canceller {
            canceller.close();
        }
    }
    join_discard(drain);
}

/// SIGKILL a Unix child's process group. The backends make the child a group
/// leader (`setsid()` / `process_group(0)`), so `-pid` targets that group —
/// never the host's — killing the leader and every descendant.
///
/// No graceful `SIGTERM` first: it's unreliable (a `/bin/sh -c …` wrapper parked
/// in a foreground `wait` defers it and finishes the script) and sandboxed code
/// isn't owed a cleanup window. The **leader is killed before the group**: a
/// `-pid`-only sweep races — the kernel can kill a descendant first, waking the
/// shell to run one more command (seen as post-timeout output on the Inherit
/// path) before its own signal lands — so we make the leader's SIGKILL pending
/// first. The caller reaps the direct child afterwards.
#[cfg(unix)]
pub fn group_kill(child: &mut std::process::Child) -> std::io::Result<()> {
    // The child is unreaped, so its pid (== pgid) can't have been recycled.
    let pid = child.id() as i32;
    // SAFETY: `kill(2)` with a plain pid / negative pgid — just integers.
    unsafe {
        libc::kill(pid, libc::SIGKILL); // leader first
        libc::kill(-pid, libc::SIGKILL); // then its group
    }
    Ok(())
}

/// Outcome of [`wait_with_timeout`]: the child exited, the deadline passed, or
/// the wait itself failed.
#[cfg(unix)]
pub enum WaitError {
    Timeout,
    Io(std::io::Error),
}

/// Wait for `child` to exit. With a timeout we poll (rather than add an async
/// runtime), starting at a short interval and backing off to a cap: a quick
/// child is detected within ~a millisecond instead of always paying a full
/// fixed tick, while a long run settles to an inexpensive cadence. Each sleep is
/// clamped to the time remaining so even sub-interval timeouts fire on time.
/// Shared by the Unix run-to-completion backends.
#[cfg(unix)]
pub fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Option<std::time::Duration>,
) -> Result<std::process::ExitStatus, WaitError> {
    use std::time::{Duration, Instant};
    // Poll interval grows from this floor to the cap (doubling each idle tick),
    // trading low exit-detection latency for short runs against an inexpensive
    // cadence for long ones.
    const MIN_POLL: Duration = Duration::from_millis(1);
    const MAX_POLL: Duration = Duration::from_millis(50);

    let Some(deadline) = timeout.map(|d| Instant::now() + d) else {
        return child.wait().map_err(WaitError::Io);
    };
    let mut interval = MIN_POLL;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(WaitError::Timeout);
                }
                std::thread::sleep((deadline - now).min(interval));
                interval = (interval * 2).min(MAX_POLL);
            }
            Err(error) => return Err(WaitError::Io(error)),
        }
    }
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
/// reach it through the [`Runner`] bridge.
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
pub struct Runner<B>(B);

impl<B> Runner<B> {
    /// Wrap a [`SandboxBackend`] so it can be dispatched as a [`ScriptRunner`].
    pub fn new(backend: B) -> Self {
        Self(backend)
    }
}

impl<B: SandboxBackend> ScriptRunner for Runner<B> {
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
                        response.standard_err.push_str(&msg);
                        response.error_message = msg;
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

#[cfg(all(test, unix))]
mod tests {
    use super::{wait_with_timeout, WaitError};
    use std::process::Command;
    use std::time::{Duration, Instant};

    #[test]
    fn wait_with_timeout_detects_quick_exit_promptly() {
        // A child that exits almost immediately is reaped well before a generous
        // deadline -- the adaptive poll starts in the millisecond range, so the
        // detection latency is small (the old fixed 50ms tick was the worst case).
        let mut child = Command::new("true").spawn().expect("spawn true");
        let start = Instant::now();
        let status = match wait_with_timeout(&mut child, Some(Duration::from_secs(10))) {
            Ok(status) => status,
            Err(_) => panic!("a quick child must exit, not time out"),
        };
        assert!(status.success(), "`true` exits 0");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "quick exit should be detected promptly, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn wait_with_timeout_fires_at_the_deadline() {
        // A long-running child hits the timeout branch at (not before) the
        // deadline, even though the deadline is shorter than the poll cap.
        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let start = Instant::now();
        let result = wait_with_timeout(&mut child, Some(Duration::from_millis(200)));
        let elapsed = start.elapsed();
        let _ = child.kill();
        let _ = child.wait();
        assert!(matches!(result, Err(WaitError::Timeout)), "should time out");
        assert!(
            elapsed >= Duration::from_millis(200),
            "must not fire before the deadline, fired at {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "should fire near the deadline, fired at {elapsed:?}"
        );
    }

    #[test]
    fn wait_with_timeout_without_deadline_waits_for_exit() {
        // A `None` timeout blocks until the child exits.
        let mut child = Command::new("true").spawn().expect("spawn true");
        let status = match wait_with_timeout(&mut child, None) {
            Ok(status) => status,
            Err(_) => panic!("blocking wait must return the exit status"),
        };
        assert!(status.success());
    }
}
