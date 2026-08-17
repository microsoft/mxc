// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Adapter that presents a state-aware [`ExecHandle`] as a streaming
//! [`SandboxProcess`], so the library / FFI streaming path can drive an `exec`
//! phase live (read stdout/stderr, feed stdin, wait, kill) exactly like a
//! spawned one-shot sandbox.
//!
//! [`ExecHandle`] carries the agent's raw stdout / stderr / stdin pipe handles
//! plus a `waiter` closure (blocks until the process exits, yielding its exit
//! code) and a `terminator` closure (kills it). [`ExecSandboxProcess`] wraps the
//! non-null pipe handles as owned readers/writers and runs the `waiter` on a
//! background thread so exit can be observed both blockingly (via
//! [`wait`](SandboxProcess::wait)) and non-blockingly (via
//! [`try_wait`](SandboxProcess::try_wait)).
//!
//! # Pipe-handle ownership
//!
//! [`ExecHandle`]'s contract is that pipe-handle ownership stays with the
//! backend's underlying process object. So this adapter does **not** take the
//! raw handles: it **duplicates** each non-null pipe handle
//! ([`try_clone_to_owned`]) and wraps the *duplicate* as an owned reader/writer.
//! The adapter closes only its duplicates on drop; the backend's originals (and
//! its `waiter`/`terminator`, which may also reference them) are untouched — so
//! there is no double-close even for a backend that keeps and closes its own
//! pipe ends. IsolationSession is exactly that case under
//! [`ExecConsumer::Library`]: it is the only state-aware backend that returns
//! real pipe handles, and it closes its own ends when its process object drops.
//! Under [`ExecConsumer::Executor`] it relays internally and returns null
//! handles, and the other state-aware backends (Windows Sandbox, WSLc) return
//! null handles on every path. A handle with *all three* streams null is
//! refused here rather than wrapped: it means the backend has not implemented
//! the `Library` contract, and a stream-less `SandboxProcess` would hide that.
//!
//! Each readable duplicate is wrapped as a **cancellable** reader, so a read on
//! it can be made to return EOF on demand. That is what lets
//! [`wait`](SandboxProcess::wait) end its own safety-drain of a stream the
//! caller did not take instead of detaching the thread doing it, and what lets a
//! caller abandon a read on a stream it *did* take — see
//! [`stdout_closer`](SandboxProcess::stdout_closer).
//!
//! [`try_clone_to_owned`]: std::os::windows::io::BorrowedHandle::try_clone_to_owned
//! [`ExecConsumer::Library`]: crate::state_aware_backend::ExecConsumer::Library
//! [`ExecConsumer::Executor`]: crate::state_aware_backend::ExecConsumer::Executor

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::mxc_error::MxcError;
use crate::sandbox_process::{boxed_closer, cancel_and_join_discard, SandboxProcess, StreamCloser};
use crate::state_aware_backend::{ExecHandle, ExecOutcome, PipeHandle};

/// The platform's closer for a cancellable read — fired to make an in-flight
/// read on a not-taken stream return EOF, so its discard thread ends and can be
/// joined rather than detached. Same type the process-spawning backends store.
#[cfg(target_os = "windows")]
type StreamCanceller = crate::process_util::PipeReadCanceller;
/// The platform's closer for a cancellable read — see the Windows variant.
#[cfg(not(target_os = "windows"))]
type StreamCanceller = crate::interruptible_reader::ReadCanceller;

/// A wrapped readable stream plus the closer that EOFs it on demand.
type ReadStream = (Box<dyn Read + Send>, StreamCanceller);

/// An [`ExecHandle`]'s streams, once classified.
struct PreparedStreams {
    stdout: Option<ReadStream>,
    stderr: Option<ReadStream>,
    stdin: Option<Box<dyn Write + Send>>,
}

/// A streaming [`SandboxProcess`] backed by a state-aware [`ExecHandle`].
pub struct ExecSandboxProcess {
    stdout: Option<Box<dyn Read + Send>>,
    stderr: Option<Box<dyn Read + Send>>,
    stdin: Option<Box<dyn Write + Send>>,
    /// Closers for the two readable streams, kept whether or not the caller
    /// takes them: [`wait`](SandboxProcess::wait) fires one to end its own
    /// safety-drain, and [`stdout_closer`](SandboxProcess::stdout_closer) hands
    /// a clone to a caller that took the stream and needs to abandon a read.
    stdout_canceller: Option<StreamCanceller>,
    stderr_canceller: Option<StreamCanceller>,
    /// The background thread running the handle's `waiter`. Taken and joined by
    /// the first [`wait`](SandboxProcess::wait) / successful
    /// [`try_wait`](SandboxProcess::try_wait).
    waiter: Option<JoinHandle<Result<ExecOutcome, MxcError>>>,
    /// Kills the process tree. Taken by the first [`kill`](SandboxProcess::kill)
    /// or by `Drop`.
    terminator: Option<Box<dyn FnOnce() -> Result<(), MxcError> + Send>>,
    /// The waiter's outcome once joined, so repeat waits are idempotent. Holds
    /// the outcome rather than a code because a timeout has no code.
    exit: Option<ExecOutcome>,
    /// Whether a termination request was **refused**. Recorded separately
    /// because `terminator` is consumed on both outcomes, so its absence alone
    /// cannot distinguish "killed" from "the kill was rejected" — and those
    /// demand opposite behaviour in [`Drop`].
    kill_refused: bool,
}

impl ExecSandboxProcess {
    /// Wrap an [`ExecHandle`] as a streaming process handle. Spawns a background
    /// thread to run the handle's `waiter` so exit can be polled.
    ///
    /// Fails rather than degrading if a stream the backend *named* cannot be
    /// duplicated, or if the waiter thread cannot start: the caller would
    /// otherwise be handed a process whose live output nobody drains, which
    /// blocks the child once its pipe fills. Either way the exec that was
    /// already started is terminated rather than orphaned.
    pub fn from_exec_handle(handle: ExecHandle) -> Result<Self, MxcError> {
        let ExecHandle {
            stdout,
            stderr,
            stdin,
            waiter,
            terminator,
        } = handle;

        // A handle with nothing on any stream is a backend that has not
        // implemented the `Library` contract — it relayed internally and ran the
        // workload to completion, which is the `Executor` shape. Wrapping it
        // would hand the caller a `SandboxProcess` whose `take_stdout` is `None`
        // and whose `wait` returns an exit code the backend already had, while
        // the sandbox's output went wherever the backend chose — for the
        // internally-relaying backends, the *host application's* own stdout.
        //
        // This is a **backstop, not the guard that matters**. The backends that
        // cannot serve `Library` refuse it up front instead (see
        // `unsupported_library_exec`), so reaching this branch means a backend
        // returned an all-null handle for a `Library` exec anyway — hence the
        // distinct wording, so the two are told apart in a log.
        //
        // **The process is not assumed to have finished.** The comment above
        // describes the shape this usually means, not a guarantee: the
        // IsolationSession `Library` path starts a process and passes through
        // whatever handles the service gave it, so an all-zero set can name a
        // process that is very much alive. Reaping is therefore conditional on
        // the kill being accepted, exactly as on every other teardown path — a
        // refused kill here would otherwise park construction forever, and the
        // caller has no handle yet to interrupt it with.
        if is_null_pipe(stdout) && is_null_pipe(stderr) && is_null_pipe(stdin) {
            terminate_then_reap_if_safe(terminator, || {
                let _ = waiter();
            });
            return Err(MxcError::backend_error(
                "this backend returned no stdout, stderr or stdin for an in-process exec, \
                 which means it relayed the output itself. It should have refused before \
                 running the command; the command may have run",
            ));
        }

        let streams = wrap_cancellable_read_checked(stdout, "stdout").and_then(|out| {
            let err = wrap_cancellable_read_checked(stderr, "stderr")?;
            let input = wrap_write_checked(stdin, "stdin")?;
            Ok(PreparedStreams {
                stdout: out,
                stderr: err,
                stdin: input,
            })
        });

        Self::from_prepared_streams(streams, waiter, terminator)
    }

    /// Build the handle from already-classified streams.
    ///
    /// Split from [`from_exec_handle`](Self::from_exec_handle) so the setup
    /// failure path is reachable in a test without fabricating an invalid OS
    /// handle: a caller can hand this an `Err` directly and observe the exec
    /// being terminated and then reaped.
    fn from_prepared_streams(
        streams: Result<PreparedStreams, MxcError>,
        waiter: Box<dyn FnOnce() -> Result<ExecOutcome, MxcError> + Send>,
        terminator: Box<dyn FnOnce() -> Result<(), MxcError> + Send>,
    ) -> Result<Self, MxcError> {
        let PreparedStreams {
            stdout,
            stderr,
            stdin,
        } = match streams {
            Ok(streams) => streams,
            Err(error) => {
                // Terminating is a request, not a reaping: run the waiter so
                // the backend's completion work happens and no zombie is left
                // behind -- but only once the kill was accepted, since a
                // refused kill can leave a waiter that never returns. Both
                // outcomes are otherwise discarded so the setup error, which is
                // the one the caller asked about, survives to be returned.
                terminate_then_reap_if_safe(terminator, || {
                    let _ = waiter();
                });
                return Err(error);
            }
        };

        // Split each stream from its closer: the stream may be taken by the
        // caller, the closer is kept either way.
        let (stdout, stdout_canceller) = split_stream(stdout);
        let (stderr, stderr_canceller) = split_stream(stderr);

        // The waiter is handed to the thread through a shared slot rather than
        // moved directly, because `Builder::spawn` consumes and drops the
        // closure when the OS refuses a thread -- leaving no way to reap the
        // exec we are about to terminate. On failure the slot still holds it.
        let waiter_slot = Arc::new(Mutex::new(Some(waiter)));
        let thread_slot = Arc::clone(&waiter_slot);
        let spawned = std::thread::Builder::new()
            .name("mxc-exec-waiter".to_string())
            .spawn(
                move || match thread_slot.lock().ok().and_then(|mut w| w.take()) {
                    Some(waiter) => waiter(),
                    None => Err(MxcError::backend_error("exec waiter was already consumed")),
                },
            );

        let waiter_thread = match spawned {
            Ok(thread) => thread,
            Err(error) => {
                // Discarded for the same reason as above: the spawn failure is
                // what the caller needs to see. Reaped only if the kill was
                // accepted -- the waiter is still in the slot precisely because
                // no thread took it, so calling it here would run it inline on
                // this thread and a refused kill would park us indefinitely.
                terminate_then_reap_if_safe(terminator, || {
                    if let Some(waiter) = waiter_slot.lock().ok().and_then(|mut w| w.take()) {
                        let _ = waiter();
                    }
                });
                return Err(MxcError::backend_error(format!(
                    "failed to start the exec waiter thread: {error}"
                )));
            }
        };

        Ok(Self {
            stdout,
            stderr,
            stdin,
            stdout_canceller,
            stderr_canceller,
            waiter: Some(waiter_thread),
            terminator: Some(terminator),
            exit: None,
            kill_refused: false,
        })
    }

    /// Join the waiter thread, caching and returning its outcome.
    ///
    /// The outcome is cached rather than the exit code, because a timeout has
    /// no code to cache and repeat calls must still be idempotent.
    fn join_waiter(&mut self) -> std::io::Result<i32> {
        if let Some(outcome) = self.exit {
            return outcome_to_io(outcome);
        }
        let handle = self
            .waiter
            .take()
            .ok_or_else(|| std::io::Error::other("exec waiter already consumed"))?;
        let outcome = handle
            .join()
            .map_err(|_| std::io::Error::other("exec waiter thread panicked"))?
            .map_err(|e: MxcError| std::io::Error::other(e.message))?;
        self.exit = Some(outcome);
        outcome_to_io(outcome)
    }

    /// Drain whatever output the caller did not take, concurrently with the
    /// wait, then join the waiter.
    ///
    /// The [`SandboxProcess`] contract promises that taking only one stream is
    /// safe, and this is what makes that true: an untaken pipe nobody reads
    /// fills, the child blocks writing to it, and the waiter then waits for an
    /// exit that cannot happen. Both drains start **before** the join for the
    /// same reason the relay starts its pumps before its waiter.
    ///
    /// Afterwards each discard is **cancelled and then joined**, via the same
    /// [`cancel_and_join_discard`] the process-spawning backends use. A plain
    /// join would be wrong twice over — a waiter that returned `Err` means the
    /// exit could not be determined, *not* that the child is gone, and even on
    /// a clean exit a backgrounded descendant that inherited the write end
    /// keeps the pipe open past the foreground child's death — so in both cases
    /// the discard's `io::copy` would never reach EOF and `wait` would never
    /// return. Cancelling first makes the read report EOF, which ends the
    /// thread and bounds the join. Cutting a discard short loses nothing: every
    /// byte was going to `sink()`, and a stream the caller *took* has no
    /// discard and so is never cancelled here.
    ///
    /// This is what satisfies the contract on
    /// [`stdout_closer`](SandboxProcess::stdout_closer) that `wait` "already
    /// cancels its own internal safety-drain".
    ///
    /// # Not covered
    ///
    /// An untaken `stdin` is dropped rather than closed, which does **not**
    /// deliver EOF to the child: the handle here is a duplicate, and the
    /// original belongs to the backend's process object. A workload that reads
    /// stdin to EOF will still block. Closing that cycle needs an owned or
    /// closable `ExecHandle::stdin`, which is tracked separately.
    fn drain_and_join(&mut self) -> std::io::Result<i32> {
        // Deliberately **not** gated on `self.exit`. A cached exit code means a
        // previous `try_wait` observed the child finish; it says nothing about
        // whether anything drained. Returning early here would let
        // `try_wait()` then `wait()` skip the drain the contract promises.
        let drain_stdout = match spawn_discard_checked(self.stdout.take()) {
            Ok(drain) => drain,
            Err(error) => return Err(self.abort_after_drain_failure(None, error)),
        };
        let drain_stderr = match spawn_discard_checked(self.stderr.take()) {
            Ok(drain) => drain,
            Err(error) => return Err(self.abort_after_drain_failure(drain_stdout, error)),
        };

        let result = self.join_waiter();

        cancel_and_join_discard(drain_stdout, &self.stdout_canceller);
        cancel_and_join_discard(drain_stderr, &self.stderr_canceller);
        result
    }

    /// Tear down after a discard thread could not be started.
    ///
    /// Waiting is only safe once every untaken stream has a reader. Without one,
    /// the child can block writing to the stream we failed to cover and the
    /// waiter never returns — so the caller would be stuck inside `wait` with no
    /// way to reach `kill`. Terminate instead, then reap the waiter so the
    /// backend's completion work still runs, then cancel and join whichever
    /// discard did start — only stdout's can have, since stderr's failure is
    /// what brought us here. Returns the original error so the caller reports
    /// the cause rather than the cleanup.
    ///
    /// **The reap is conditional on the kill being accepted.** Joining after a
    /// refused kill would reintroduce exactly the stall this function exists to
    /// avoid — stuck inside `wait`, with the caller unable to reach `kill` —
    /// only on the teardown path instead of the drain path. A refusal is
    /// recorded so a later `Drop` makes the same choice.
    fn abort_after_drain_failure(
        &mut self,
        stdout_drain: Option<JoinHandle<()>>,
        error: std::io::Error,
    ) -> std::io::Error {
        if let Some(terminator) = self.terminator.take() {
            // Discarded: the drain-spawn failure is the error being returned.
            let accepted = terminate_then_reap_if_safe(terminator, || {});
            if accepted {
                let _ = self.join_waiter();
            } else {
                self.kill_refused = true;
            }
        }
        cancel_and_join_discard(stdout_drain, &self.stdout_canceller);
        error
    }
}

/// Terminate an exec that is being abandoned, and reap it **only if that is
/// safe**.
///
/// Every teardown path faces the same choice as [`Drop`](ExecSandboxProcess::drop):
/// the backend's completion work should run, but waiting for it is only bounded
/// once the process is actually dying. A terminator that reported a refusal
/// leaves a process that may still be running, and a waiter with no deadline
/// (`script_timeout` defaults to `0`, meaning INFINITE) then never returns — so
/// reaping would block forever on a path the caller cannot interrupt.
///
/// Returns whether the kill was accepted, so a caller holding
/// [`kill_refused`](ExecSandboxProcess::kill_refused) can record it.
///
/// Shared rather than repeated so the rule has one home. It was previously
/// open-coded at three sites, each of which reaped unconditionally.
fn terminate_then_reap_if_safe(
    terminator: Box<dyn FnOnce() -> Result<(), MxcError> + Send>,
    reap: impl FnOnce(),
) -> bool {
    let accepted = terminator().is_ok();
    if accepted {
        reap();
    }
    accepted
}

/// Split a prepared stream into the stream itself and its closer.
///
/// The stream may later be taken by the caller; the closer is retained either
/// way, so `wait` can still end a discard and a caller that took the stream can
/// still be handed one.
fn split_stream(
    prepared: Option<ReadStream>,
) -> (Option<Box<dyn Read + Send>>, Option<StreamCanceller>) {
    match prepared {
        Some((stream, canceller)) => (Some(stream), Some(canceller)),
        None => (None, None),
    }
}

/// Spawn a thread that reads `reader` to EOF and discards it. `None` in,
/// `Ok(None)` out — there is nothing to drain.
///
/// The fallible counterpart of [`crate::sandbox_process::spawn_discard`], which
/// uses `thread::spawn` and so panics when the OS refuses a thread. This one
/// sits under `wait`, which returns `io::Result` and is reached through the
/// FFI, where an unwind becomes a reported panic instead of an error — the same
/// reason the waiter thread above uses `Builder::spawn`.
fn spawn_discard_checked(
    reader: Option<Box<dyn Read + Send>>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let Some(mut reader) = reader else {
        return Ok(None);
    };
    let thread = std::thread::Builder::new()
        .name("mxc-exec-drain".to_string())
        .spawn(move || {
            let _ = std::io::copy(&mut reader, &mut std::io::sink());
        })?;
    Ok(Some(thread))
}

impl SandboxProcess for ExecSandboxProcess {
    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        self.stdin.take()
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        self.stdout.take()
    }

    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        self.stderr.take()
    }

    /// A closer for a stdout the caller **took** and is reading, so it can
    /// abandon that read without killing the child — the case a backgrounded
    /// descendant holding the write end open past the foreground command's exit
    /// would otherwise leave stuck.
    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stdout_canceller)
    }

    /// A closer for a taken stderr — see [`stdout_closer`](Self::stdout_closer).
    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stderr_canceller)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        if let Some(outcome) = self.exit {
            return outcome_to_io(outcome).map(Some);
        }
        match &self.waiter {
            Some(handle) if handle.is_finished() => self.join_waiter().map(Some),
            Some(_) => Ok(None),
            None => Ok(None),
        }
    }

    fn id(&self) -> u32 {
        // An ExecHandle does not carry the agent process id; the state-aware
        // backend owns the process lifecycle behind its `waiter`/`terminator`.
        0
    }

    fn kill(&mut self) -> std::io::Result<()> {
        // A confirmed exit retires the terminator. The process is gone, so
        // there is nothing to kill, and an earlier refusal no longer describes
        // reality — reporting it would fail a `kill()` for a process that is
        // demonstrably dead. Running the terminator here would be equally
        // wrong: it would surface a failure to terminate something that has
        // already terminated.
        if self.exit.is_some() {
            self.terminator = None;
            self.kill_refused = false;
            return Ok(());
        }
        match self.terminator.take() {
            // A refusal now reaches the caller instead of being swallowed, and
            // is remembered: the terminator is consumed either way, so this flag
            // is the only surviving evidence of which outcome it produced.
            Some(terminator) => terminator().map_err(|e| {
                self.kill_refused = true;
                std::io::Error::other(e.message)
            }),
            // A kill that was refused stays refused, until an exit is
            // confirmed. Reporting `Ok` here would tell a caller retrying after
            // a failure that the process is now dead, when nothing has changed
            // since the refusal.
            None if self.kill_refused => Err(std::io::Error::other(
                "the sandbox refused an earlier request to terminate this exec",
            )),
            // Already killed: killing twice is not an error.
            None => Ok(()),
        }
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        self.drain_and_join()
    }
}

impl Drop for ExecSandboxProcess {
    fn drop(&mut self) {
        // Kill the process (if not already) so the waiter thread can finish,
        // then join it to avoid detaching a thread that borrows the backend's
        // process object.
        //
        // The join is conditional on the kill having been **accepted**. If the
        // platform refused it, the process may still be running and its waiter
        // parked in a wait with no deadline — joining would then block here
        // forever, in a `Drop` a caller cannot opt out of. Abandoning the thread
        // instead is memory-safe (it owns what it borrows through an `Arc`) and
        // costs a leaked thread, its `Arc` share of the process object, and that
        // object's COM reference — in a case that already indicates the sandbox
        // is not responding to termination.
        //
        // This bounds the `Drop` only against a *reported* refusal. A terminate
        // the platform accepted but that never took effect still reports `Ok`,
        // and parks the join exactly as before; bounding that too needs the
        // backend to confirm the process died, which its handle cannot yet do.
        let kill_accepted = match self.terminator.take() {
            // Nothing to terminate once the exit is known; running the
            // terminator over a dead process only invites a spurious failure.
            _ if self.exit.is_some() => true,
            Some(terminator) => terminator().is_ok(),
            // Already killed via `kill()`, whose result the caller has seen —
            // and whose refusal, if it was one, is precisely the case this
            // guard exists for.
            None => !self.kill_refused,
        };
        if let Some(handle) = self.waiter.take() {
            if kill_accepted {
                let _ = handle.join();
            }
        }
    }
}

/// Map an [`ExecOutcome`] onto the [`SandboxProcess`] convention, where a
/// timeout is an `Err` carrying [`io::ErrorKind::TimedOut`](std::io::ErrorKind)
/// rather than an exit code.
///
/// That convention is not invented here: five one-shot backends already report
/// a timeout this way, and `mxc_sdk::Sandbox::wait` maps exactly this kind onto
/// its public `WaitOutcome::TimedOut`. Translating at this boundary is what
/// lets the state-aware path reach that outcome without changing anything above
/// it.
fn outcome_to_io(outcome: ExecOutcome) -> std::io::Result<i32> {
    match outcome {
        ExecOutcome::Exited(code) => Ok(code),
        ExecOutcome::TimedOut => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the exec timed out and the sandbox terminated it",
        )),
    }
}

// ---------------------------------------------------------------------------
// Platform pipe-handle → std stream wrapping
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn wrap_read(handle: PipeHandle) -> Option<Box<dyn Read + Send>> {
    dup_handle_to_file(handle).map(|f| Box::new(f) as Box<dyn Read + Send>)
}

/// Wrap a readable pipe as a **cancellable** reader plus its closer, so a
/// discard of it can be ended on demand rather than abandoned.
///
/// Separate from [`wrap_read`] because the executor's relay does not need a
/// closer — it has its own mute-and-abandon path — and only the streaming
/// adapter stores one.
#[cfg(target_os = "windows")]
fn wrap_cancellable_read(handle: PipeHandle) -> Option<ReadStream> {
    use std::os::windows::io::IntoRawHandle;
    // Hand the duplicate straight to the interruptible reader: `into_raw_handle`
    // releases it from the std wrapper without closing it, and
    // `process_util::OwnedHandle` takes over closing it.
    let raw = dup_handle_to_owned(handle)?.into_raw_handle();
    let owned = crate::process_util::OwnedHandle::new(windows::Win32::Foundation::HANDLE(raw as _));
    let reader = crate::process_util::InterruptiblePipeReader::new(owned);
    let canceller = reader.canceller();
    Some((Box::new(reader) as Box<dyn Read + Send>, canceller))
}

#[cfg(target_os = "windows")]
fn wrap_write(handle: PipeHandle) -> Option<Box<dyn Write + Send>> {
    dup_handle_to_file(handle).map(|f| Box::new(f) as Box<dyn Write + Send>)
}

/// Whether a [`PipeHandle`] is the null sentinel, i.e. a stream the backend
/// does not expose. Distinct from a *valid-looking* handle that cannot be
/// duplicated, which is a failure rather than an absence.
#[cfg(target_os = "windows")]
pub(crate) fn is_null_pipe(handle: PipeHandle) -> bool {
    handle.0.is_null()
}

/// Whether a [`PipeHandle`] is the null sentinel — see the Windows variant.
#[cfg(not(target_os = "windows"))]
pub(crate) fn is_null_pipe(handle: PipeHandle) -> bool {
    handle < 0
}

/// Duplicate a non-null Windows pipe `HANDLE` into an owned [`File`], leaving
/// the caller's original handle untouched. Returns `None` for a null handle or
/// if duplication fails.
#[cfg(target_os = "windows")]
fn dup_handle_to_owned(handle: PipeHandle) -> Option<std::os::windows::io::OwnedHandle> {
    use std::os::windows::io::BorrowedHandle;
    if is_null_pipe(handle) {
        return None;
    }
    // SAFETY: a non-null exec pipe handle is valid for the borrow; we only
    // duplicate it (DuplicateHandle) and never take ownership of the original.
    let borrowed = unsafe { BorrowedHandle::borrow_raw(handle.0 as _) };
    borrowed.try_clone_to_owned().ok()
}

#[cfg(target_os = "windows")]
fn dup_handle_to_file(handle: PipeHandle) -> Option<std::fs::File> {
    dup_handle_to_owned(handle).map(std::fs::File::from)
}

#[cfg(not(target_os = "windows"))]
fn wrap_read(handle: PipeHandle) -> Option<Box<dyn Read + Send>> {
    dup_fd_to_file(handle).map(|f| Box::new(f) as Box<dyn Read + Send>)
}

/// Wrap a readable pipe as a cancellable reader — see the Windows variant.
///
/// Note this does **not** leave the backend's original fd wholly untouched, as
/// [`dup_fd_to_file`] alone would: `InterruptibleReader` sets `O_NONBLOCK`, and
/// that is a property of the open file description, which every `dup` shares.
/// The backend's fd therefore becomes non-blocking too. Harmless while no
/// state-aware backend is non-Windows — all three are Windows — but a Unix one
/// that later reads or re-hands its own fd would see `EAGAIN` where it expected
/// a blocking read.
#[cfg(not(target_os = "windows"))]
fn wrap_cancellable_read(handle: PipeHandle) -> Option<ReadStream> {
    let file = dup_fd_to_file(handle)?;
    let reader = crate::interruptible_reader::InterruptibleReader::new(file.into()).ok()?;
    let canceller = reader.canceller();
    Some((Box::new(reader) as Box<dyn Read + Send>, canceller))
}

#[cfg(not(target_os = "windows"))]
fn wrap_write(handle: PipeHandle) -> Option<Box<dyn Write + Send>> {
    dup_fd_to_file(handle).map(|f| Box::new(f) as Box<dyn Write + Send>)
}

/// Decide what a wrap attempt means, given whether the handle was the null
/// sentinel. Split out from the OS call so the policy can be tested directly,
/// without fabricating an invalid handle to force a duplication failure.
///
/// - null handle -> `Ok(None)`: the backend does not expose this stream.
/// - non-null, wrap succeeded -> `Ok(Some(_))`.
/// - non-null, wrap failed -> `Err`: the backend named a stream that cannot be
///   duplicated (handle exhaustion, or a stale handle). Callers must treat this
///   as fatal, never as absence: nothing would drain that live pipe, so the
///   child blocks once it fills and its waiter never returns.
fn classify_stream<T>(
    is_null: bool,
    wrap: impl FnOnce() -> Option<T>,
    stream: &str,
) -> Result<Option<T>, MxcError> {
    if is_null {
        return Ok(None);
    }
    wrap().map(Some).ok_or_else(|| {
        MxcError::backend_error(format!("failed to duplicate the exec {stream} pipe handle"))
    })
}

/// Wrap a readable exec pipe, distinguishing *absent* from *failed*.
pub(crate) fn wrap_read_checked(
    handle: PipeHandle,
    stream: &str,
) -> Result<Option<Box<dyn Read + Send>>, MxcError> {
    classify_stream(is_null_pipe(handle), || wrap_read(handle), stream)
}

/// Cancellable counterpart of [`wrap_read_checked`], for the streaming adapter.
///
/// Module-private: unlike [`wrap_read_checked`], which the executor's relay also
/// calls, this one has a single caller in this file.
fn wrap_cancellable_read_checked(
    handle: PipeHandle,
    stream: &str,
) -> Result<Option<ReadStream>, MxcError> {
    classify_stream(
        is_null_pipe(handle),
        || wrap_cancellable_read(handle),
        stream,
    )
}

/// Writable counterpart of [`wrap_read_checked`].
pub(crate) fn wrap_write_checked(
    handle: PipeHandle,
    stream: &str,
) -> Result<Option<Box<dyn Write + Send>>, MxcError> {
    classify_stream(is_null_pipe(handle), || wrap_write(handle), stream)
}

/// Duplicate a non-negative pipe fd into an owned [`File`] (via `dup`), leaving
/// the caller's original fd untouched. Returns `None` for an invalid fd or if
/// duplication fails.
#[cfg(not(target_os = "windows"))]
fn dup_fd_to_file(handle: PipeHandle) -> Option<std::fs::File> {
    use std::os::fd::BorrowedFd;
    if is_null_pipe(handle) {
        return None;
    }
    // SAFETY: a non-negative exec pipe fd is valid for the borrow; we only
    // duplicate it (dup) and never take ownership of the original.
    let borrowed = unsafe { BorrowedFd::borrow_raw(handle) };
    borrowed.try_clone_to_owned().ok().map(std::fs::File::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_error::MxcErrorCode;
    use crate::state_aware_backend::null_pipe_handle;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// The null sentinel means "this backend exposes no such stream", and the
    /// wrap is never even attempted.
    #[test]
    fn classify_stream_treats_null_as_absent() {
        let mut attempted = false;
        let got: Option<u8> = classify_stream(
            true,
            || {
                attempted = true;
                None
            },
            "stdout",
        )
        .expect("a null handle is absence, not failure");
        assert!(got.is_none());
        assert!(!attempted, "a null handle must not be duplicated");
    }

    /// A named stream that wraps successfully is passed through.
    #[test]
    fn classify_stream_passes_through_a_successful_wrap() {
        let got = classify_stream(false, || Some(7u8), "stdout").unwrap();
        assert_eq!(got, Some(7));
    }

    /// A stream the backend named but that cannot be duplicated is a setup
    /// failure, and the exec it refers to has *already started*. It must be
    /// terminated and then reaped, in that order.
    ///
    /// The order is asserted, not just the calls: terminating is a request, so
    /// running the waiter first would block on a child nobody has asked to
    /// stop. With no live streams involved, nothing else here would notice the
    /// two being swapped.
    #[test]
    fn from_prepared_streams_terminates_then_reaps_on_setup_failure() {
        let (tx, rx) = std::sync::mpsc::channel();
        let terminator_tx = tx.clone();

        let result = ExecSandboxProcess::from_prepared_streams(
            Err(MxcError::backend_error("stdout could not be duplicated")),
            Box::new(move || {
                let _ = tx.send("waiter");
                Ok(ExecOutcome::Exited(0))
            }),
            Box::new(move || {
                let _ = terminator_tx.send("terminator");
                Ok(())
            }),
        );

        let err = result
            .err()
            .expect("a named-but-undupable stream must fail the constructor");
        assert!(
            err.message.contains("could not be duplicated"),
            "the setup error must survive teardown: {}",
            err.message
        );
        assert_eq!(
            rx.try_recv().ok(),
            Some("terminator"),
            "the exec must be terminated first"
        );
        assert_eq!(
            rx.try_recv().ok(),
            Some("waiter"),
            "and then reaped -- terminating alone leaves it unreaped"
        );
    }

    /// A named stream that will not wrap is a failure, never absence: nothing
    /// would drain that live pipe and the child would block once it filled.
    #[test]
    fn classify_stream_treats_a_failed_wrap_as_an_error() {
        let err = classify_stream(false, || None::<u8>, "stderr")
            .expect_err("a named-but-undupable stream must not be reported as absent");
        assert_eq!(err.code, MxcErrorCode::BackendError);
        assert!(
            err.message.contains("stderr"),
            "the failing stream should be named: {}",
            err.message
        );
    }

    /// A handle with nothing on any stream is refused rather than wrapped.
    ///
    /// This test previously asserted the opposite — that the all-null shape
    /// yielded a stream-less process carrying the waiter's exit code. That was
    /// the contract when no backend surfaced real pipes; it is now the signature
    /// of a backend that has not implemented the `Library` path, and handing the
    /// caller a `SandboxProcess` with no streams hides that behind an object
    /// that looks live. The exec is reaped on the way out, so refusing does not
    /// orphan it.
    #[test]
    fn an_all_null_handle_is_refused_and_reaped() {
        let (waiter_tx, waiter_rx) = mpsc::channel();
        let (term_tx, term_rx) = mpsc::channel();
        let handle = ExecHandle {
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(move || {
                let _ = waiter_tx.send(());
                Ok(ExecOutcome::Exited(7))
            }),
            terminator: Box::new(move || {
                let _ = term_tx.send(());
                Ok(())
            }),
        };

        let err = match ExecSandboxProcess::from_exec_handle(handle) {
            Ok(_) => panic!("a backend exposing no streams cannot serve a library caller"),
            Err(err) => err,
        };
        assert!(
            err.message.contains("relayed the output itself"),
            "the refusal should say why: {}",
            err.message
        );

        // Reaped, not orphaned: both closures ran.
        assert!(
            term_rx.try_recv().is_ok(),
            "the exec must be terminated on refusal"
        );
        assert!(
            waiter_rx.try_recv().is_ok(),
            "the exec must be reaped on refusal"
        );
    }

    /// `kill` invokes the terminator exactly once, and reports what it said.
    #[test]
    fn kill_invokes_terminator_once() {
        // A real stdout, because an all-null handle is now refused outright.
        let (stdout_r, stdout_w) = std::io::pipe().expect("pipe");
        let (tx, rx) = mpsc::channel();
        let handle = ExecHandle {
            stdout: reader_handle(&stdout_r),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::Exited(0))),
            terminator: Box::new(move || {
                let _ = tx.send(());
                Ok(())
            }),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();
        proc.kill().unwrap();
        proc.kill().unwrap(); // second kill is a no-op
                              // Exactly one terminator signal.
        assert!(rx.recv().is_ok());
        assert!(rx.try_recv().is_err());

        drop(stdout_w);
        drop(stdout_r);
    }

    /// A terminator that reports a refusal reaches the caller through `kill`.
    ///
    /// The regression this pins: the terminator used to be infallible, so a
    /// kill the platform rejected surfaced as `Ok(())` and a caller had no way
    /// to learn the workload was still running.
    #[test]
    fn kill_reports_a_refused_termination() {
        let (stdout_r, stdout_w) = std::io::pipe().expect("pipe");
        let handle = ExecHandle {
            stdout: reader_handle(&stdout_r),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::Exited(0))),
            terminator: Box::new(|| Err(MxcError::backend_error("Terminate was refused"))),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();

        let err = proc
            .kill()
            .expect_err("a refused kill must reach the caller");
        assert!(
            err.to_string().contains("Terminate was refused"),
            "the backend's reason should survive: {err}"
        );

        drop(stdout_w);
        drop(stdout_r);
    }

    /// A refused kill stays refused when the caller retries.
    ///
    /// The regression this pins: `kill` consumes the terminator on both
    /// outcomes, so without a separate record of the refusal the second call
    /// reads "already killed" and reports `Ok(())` — telling a caller retrying
    /// after a failure that the process is now dead, when nothing has changed.
    #[test]
    fn a_refused_kill_stays_refused_on_retry() {
        let (stdout_r, stdout_w) = std::io::pipe().expect("pipe");
        let handle = ExecHandle {
            stdout: reader_handle(&stdout_r),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::Exited(0))),
            terminator: Box::new(|| Err(MxcError::backend_error("Terminate was refused"))),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();

        proc.kill().expect_err("first kill is refused");
        proc.kill()
            .expect_err("a retry must not claim the refusal succeeded");

        drop(stdout_w);
        drop(stdout_r);
    }

    /// `Drop` must not join the waiter after a kill the platform refused.
    ///
    /// The regression this pins: a refused `kill()` leaves no terminator, and
    /// `Drop` used to read that absence as "already killed" and join. With the
    /// process still running its waiter is parked in a wait with no deadline, so
    /// the join never returns — a permanent hang inside a `Drop` the caller
    /// cannot opt out of.
    ///
    /// The waiter here blocks until the test releases it, standing in for that
    /// parked wait. `kill_reports_a_refused_termination` cannot catch this: its
    /// waiter has already finished, so joining it costs nothing.
    ///
    /// The stand-in wait is **bounded**. An unbounded `recv()` deadlocks the
    /// whole suite if an assertion above panics: unwinding drops locals in
    /// reverse declaration order, so `proc` is dropped — and its `Drop` joins —
    /// before the sender that would release the waiter. That is not
    /// hypothetical; it hung a full test run.
    #[test]
    fn drop_abandons_the_waiter_after_a_refused_kill() {
        let (stdout_r, stdout_w) = std::io::pipe().expect("pipe");
        // Held by the waiter; never sent to until the assertion is done.
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let handle = ExecHandle {
            stdout: reader_handle(&stdout_r),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(move || {
                let _ = release_rx.recv_timeout(std::time::Duration::from_secs(60));
                Ok(ExecOutcome::Exited(0))
            }),
            terminator: Box::new(|| Err(MxcError::backend_error("Terminate was refused"))),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();
        proc.kill().expect_err("the kill is refused");

        // Drop on a helper thread so a regression fails the test instead of
        // hanging the run.
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            drop(proc);
            let _ = done_tx.send(());
        });

        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .is_ok(),
            "Drop joined a waiter that cannot finish, after a refused kill"
        );

        let _ = release_tx.send(());
        drop(stdout_w);
        drop(stdout_r);
    }

    /// A confirmed exit retires an earlier refusal.
    ///
    /// The regression this pins: `kill_refused` was permanent, so a process
    /// that refused a kill and then exited on its own still reported the old
    /// refusal from every later `kill()` — telling the caller the sandbox would
    /// not terminate a process that is demonstrably gone. `kill()` after a
    /// completed `wait()` is required to be a no-op.
    #[test]
    fn a_confirmed_exit_retires_an_earlier_kill_refusal() {
        let (stdout_r, stdout_w) = std::io::pipe().expect("pipe");
        drop(stdout_w); // EOF so the drain finishes
        let handle = ExecHandle {
            stdout: reader_handle(&stdout_r),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::Exited(0))),
            terminator: Box::new(|| Err(MxcError::backend_error("Terminate was refused"))),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();

        proc.kill().expect_err("the kill is refused while it runs");
        assert_eq!(proc.wait().expect("the process exited on its own"), 0);
        proc.kill()
            .expect("a process known to have exited cannot still be refusing to die");

        drop(stdout_r);
    }

    /// A natural exit must not run the terminator and surface its failure.
    ///
    /// The regression this pins: making the terminator fallible meant a
    /// `kill()` after a completed `wait()` ran it against an already-dead
    /// process and reported whatever that failed with, turning a no-op into an
    /// error.
    #[test]
    fn kill_after_a_completed_wait_does_not_run_the_terminator() {
        let (stdout_r, stdout_w) = std::io::pipe().expect("pipe");
        drop(stdout_w);
        let (tx, rx) = mpsc::channel();
        let handle = ExecHandle {
            stdout: reader_handle(&stdout_r),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::Exited(3))),
            terminator: Box::new(move || {
                let _ = tx.send(());
                Err(MxcError::backend_error("no such process"))
            }),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();

        assert_eq!(proc.wait().expect("exited"), 3);
        proc.kill().expect("kill after wait is a no-op");
        assert!(
            rx.try_recv().is_err(),
            "the terminator must not run against a process already known to be gone"
        );

        drop(stdout_r);
    }

    /// Construction must not block when a refused kill leaves the waiter live.
    ///
    /// The regression this pins: the stream-prep failure path ran the
    /// terminator, discarded its result, and then called the waiter *inline*.
    /// With a refused kill the process may still be running, and with no
    /// deadline (`script_timeout` defaults to 0 = INFINITE) that waiter never
    /// returns — hanging the constructor, which no caller can interrupt because
    /// it has not been handed a handle yet.
    ///
    /// The waiter here blocks until released, standing in for that parked wait.
    #[test]
    fn a_refused_kill_does_not_block_construction_on_a_stream_failure() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = ExecSandboxProcess::from_prepared_streams(
                Err(MxcError::backend_error("stream setup failed")),
                Box::new(move || {
                    let _ = release_rx.recv_timeout(std::time::Duration::from_secs(60));
                    Ok(ExecOutcome::Exited(0))
                }),
                Box::new(|| Err(MxcError::backend_error("Terminate was refused"))),
            );
            let _ = done_tx.send(result.is_err());
        });

        let finished = done_rx.recv_timeout(std::time::Duration::from_secs(10));
        assert!(
            finished.is_ok(),
            "construction reaped a waiter that cannot finish, after a refused kill"
        );
        assert!(finished.unwrap(), "the setup error must still be returned");
        let _ = release_tx.send(());
    }

    /// The same rule on the accepted path: the waiter IS reaped when the kill
    /// was accepted, so the backend's completion work still runs.
    ///
    /// Paired with the test above so "does not block" cannot be satisfied by
    /// never reaping at all.
    #[test]
    fn an_accepted_kill_still_reaps_on_a_stream_failure() {
        let (tx, rx) = mpsc::channel();
        let result = ExecSandboxProcess::from_prepared_streams(
            Err(MxcError::backend_error("stream setup failed")),
            Box::new(move || {
                let _ = tx.send(());
                Ok(ExecOutcome::Exited(0))
            }),
            Box::new(|| Ok(())),
        );
        assert!(result.is_err(), "the setup error must be returned");
        assert!(
            rx.try_recv().is_ok(),
            "an accepted kill must still reap, or the backend leaks its completion work"
        );
    }

    /// `wait()` must not block when a discard thread fails to start and the
    /// kill is then refused.
    ///
    /// The regression this pins: `abort_after_drain_failure` joined the waiter
    /// unconditionally. That reintroduces the exact stall the function exists to
    /// avoid — stuck inside `wait` with the caller unable to reach `kill` — just
    /// on the teardown path rather than the drain path.
    ///
    /// Driven through `abort_after_drain_failure` directly: making a real
    /// thread spawn fail on demand is not something a unit test can arrange.
    #[test]
    fn a_refused_kill_does_not_block_the_drain_failure_teardown() {
        let (stdout_r, stdout_w) = std::io::pipe().expect("pipe");
        drop(stdout_w);
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let handle = ExecHandle {
            stdout: reader_handle(&stdout_r),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(move || {
                let _ = release_rx.recv_timeout(std::time::Duration::from_secs(60));
                Ok(ExecOutcome::Exited(0))
            }),
            terminator: Box::new(|| Err(MxcError::backend_error("Terminate was refused"))),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();

        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let err = proc.abort_after_drain_failure(
                None,
                std::io::Error::other("discard thread could not start"),
            );
            // Report the refusal state alongside completion, so the test can
            // assert both without racing the thread's own teardown.
            let _ = done_tx.send((err.to_string(), proc.kill_refused));
            drop(proc);
        });

        let finished = done_rx.recv_timeout(std::time::Duration::from_secs(10));
        assert!(
            finished.is_ok(),
            "teardown joined a waiter that cannot finish, after a refused kill"
        );
        let (msg, refused) = finished.unwrap();
        assert!(
            msg.contains("discard thread could not start"),
            "the original error must survive the cleanup: {msg}"
        );
        assert!(
            refused,
            "the refusal must be recorded so a later Drop makes the same choice"
        );

        let _ = release_tx.send(());
        drop(stdout_r);
    }

    /// An all-null handle whose kill is refused must not park construction.
    ///
    /// The regression this pins: the backstop reaped unconditionally on the
    /// assumption that an all-null handle always means a finished process. It
    /// does not — the IsolationSession `Library` path starts a process and
    /// passes through whatever handles the service returned, so an all-zero set
    /// can name a live one. With a refused kill and no deadline, reaping it
    /// hangs `from_exec_handle`, which the caller cannot interrupt because it
    /// has not been handed anything yet.
    #[test]
    fn an_all_null_handle_with_a_refused_kill_does_not_block() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let handle = ExecHandle {
                stdout: null_pipe_handle(),
                stderr: null_pipe_handle(),
                stdin: null_pipe_handle(),
                waiter: Box::new(move || {
                    let _ = release_rx.recv_timeout(std::time::Duration::from_secs(60));
                    Ok(ExecOutcome::Exited(0))
                }),
                terminator: Box::new(|| Err(MxcError::backend_error("Terminate was refused"))),
            };
            let _ = done_tx.send(ExecSandboxProcess::from_exec_handle(handle).is_err());
        });

        let finished = done_rx.recv_timeout(std::time::Duration::from_secs(10));
        assert!(
            finished.is_ok(),
            "the all-null backstop reaped a waiter that cannot finish, after a refused kill"
        );
        assert!(finished.unwrap(), "the refusal must still be returned");
        let _ = release_tx.send(());
    }

    /// A waiter reporting a timeout surfaces as `ErrorKind::TimedOut`, which is
    /// what `mxc_sdk::Sandbox::wait` maps onto `WaitOutcome::TimedOut`.
    ///
    /// The regression this pins: the waiter used to return a bare exit code, so
    /// a timed-out exec was indistinguishable from one that exited with the code
    /// its killed process happened to produce.
    #[test]
    fn a_timeout_surfaces_as_the_timed_out_error_kind() {
        let (stdout_r, stdout_w) = std::io::pipe().expect("pipe");
        drop(stdout_w); // EOF, so the drain finishes promptly
        let handle = ExecHandle {
            stdout: reader_handle(&stdout_r),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::TimedOut)),
            terminator: Box::new(|| Ok(())),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();

        let err = proc.wait().expect_err("a timeout is not an exit code");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "the kind is the contract the SDK reads: {err}"
        );

        // Idempotent: the cached outcome maps the same way, rather than the
        // second call reporting a missing waiter.
        let again = proc.wait().expect_err("still a timeout");
        assert_eq!(again.kind(), std::io::ErrorKind::TimedOut);

        drop(stdout_r);
    }

    /// `wait()` drains a stream the caller never took.
    ///
    /// This is the guarantee that makes the `SandboxProcess` contract's "taking
    /// only one stream is always safe" true. Without it the untaken pipe fills,
    /// the child blocks writing to it, and the waiter waits for an exit that
    /// cannot happen — so a regression here **deadlocks** rather than failing an
    /// assertion, which is the honest signature of the defect.
    ///
    /// The payload is far larger than a pipe buffer on purpose: a smaller one
    /// would fit and pass whether or not anything drained.
    #[test]
    fn wait_drains_a_stream_the_caller_never_took() {
        let (stdout_r, mut stdout_w) = std::io::pipe().expect("pipe");

        // The "child": writes more than any pipe buffer holds, then closes.
        // Its completion is what the waiter blocks on, exactly as a real child's
        // exit would be.
        let writer = std::thread::spawn(move || {
            let chunk = vec![b'x'; 8192];
            for _ in 0..64 {
                if stdout_w.write_all(&chunk).is_err() {
                    return false;
                }
            }
            drop(stdout_w);
            true
        });

        let (done_tx, done_rx) = mpsc::channel();
        let handle = ExecHandle {
            stdout: reader_handle(&stdout_r),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            // Stands in for a real wait: it cannot return until the writer has
            // finished, which it cannot do unless someone is draining.
            waiter: Box::new(move || {
                let wrote_everything = done_rx
                    .recv_timeout(std::time::Duration::from_secs(30))
                    .map_err(|_| MxcError::backend_error("the child never finished writing"))?;
                if wrote_everything {
                    Ok(ExecOutcome::Exited(0))
                } else {
                    Err(MxcError::backend_error("the child's writes failed"))
                }
            }),
            terminator: Box::new(|| Ok(())),
        };

        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();
        // Deliberately take nothing.
        let writer_result = std::thread::spawn(move || {
            let ok = writer.join().unwrap_or(false);
            let _ = done_tx.send(ok);
        });

        assert_eq!(
            proc.wait().expect("wait must drain the untaken stdout"),
            0,
            "an untaken stream must be drained, not left to block the child"
        );
        writer_result.join().unwrap();
        drop(stdout_r);
    }

    /// A failing waiter must not leave `wait()` parked on a live pipe.
    ///
    /// The regression this pins: a waiter error means the exit could not be
    /// determined, **not** that the child is gone. Joining the discard
    /// unconditionally then blocks on a pipe that never EOFs, and the caller
    /// cannot even fall back to `kill` because it is stuck inside `wait`.
    ///
    /// The writer is deliberately kept alive for the whole call — that is what
    /// makes this discriminating. An unbounded join hangs here; cancelling the
    /// discard's read first ends it and surfaces the waiter's error.
    #[test]
    fn wait_returns_a_waiter_error_even_with_a_live_writer() {
        let (stdout_r, stdout_w) = std::io::pipe().expect("pipe");

        let handle = ExecHandle {
            stdout: reader_handle(&stdout_r),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Err(MxcError::backend_error("could not determine the exit"))),
            terminator: Box::new(|| Ok(())),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();

        let started = Instant::now();
        let err = proc
            .wait()
            .expect_err("a waiter error must reach the caller");
        let elapsed = started.elapsed();

        assert!(
            err.to_string().contains("could not determine the exit"),
            "the waiter's error must survive the drain: {err}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "wait must not block indefinitely on a writer it does not control; took {elapsed:?}"
        );

        // Held open across the assertions on purpose: dropping it earlier would
        // deliver the EOF whose absence is the point of the test.
        drop(stdout_w);
        drop(stdout_r);
    }

    /// `wait` must **tear its discard down**, not walk away from it.
    ///
    /// This is the regression the cancellable drain exists for, and the other
    /// tests do not pin it: the live-writer test only asserts that `wait`
    /// returns promptly, which the previous design — join with a 5s bound, then
    /// abandon the thread — also satisfied. Abandoning leaks the thread *and*
    /// the duplicated handle it is still reading, once per exec, in exactly the
    /// long-lived host this path serves.
    ///
    /// Made observable by closing the test's own read end first, so the
    /// adapter's duplicate is the only one left. If `wait` joined its discard,
    /// that duplicate is closed by the time it returns and the writer sees a
    /// broken pipe. If it abandoned the thread, the thread is still parked in a
    /// read holding the duplicate open, and the write succeeds.
    #[test]
    fn wait_tears_down_its_discard_rather_than_abandoning_it() {
        let (stdout_r, mut stdout_w) = std::io::pipe().expect("pipe");

        let handle = ExecHandle {
            stdout: reader_handle(&stdout_r),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            // Fails, so the child cannot be assumed gone — the case where the
            // old design gave up on the join and detached the thread.
            waiter: Box::new(|| Err(MxcError::backend_error("could not determine the exit"))),
            terminator: Box::new(|| Ok(())),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();

        // The adapter duplicated it; this end is no longer needed, and dropping
        // it now is what makes the duplicate's fate observable below.
        drop(stdout_r);

        proc.wait()
            .expect_err("the waiter fails, but the drain must still be torn down");

        let wrote = stdout_w.write_all(b"x");
        assert_eq!(
            wrote.map_err(|e| e.kind()),
            Err(std::io::ErrorKind::BrokenPipe),
            "wait() left its discard thread holding the pipe open instead of \
             cancelling and joining it"
        );
    }

    /// A caller that took a stream must be able to abandon a read on it without
    /// killing the child.
    ///
    /// The writer is held open for the whole test, so the read has no reason to
    /// end on its own: reaching EOF is only possible because the closer fired.
    /// This is the capability `stdout_closer` exists for — a backgrounded
    /// descendant holding the write end open past the foreground command's exit
    /// would otherwise strand the caller in a read it cannot cancel.
    #[test]
    fn a_taken_stream_can_be_abandoned_with_its_closer() {
        let (stdout_r, stdout_w) = std::io::pipe().expect("pipe");

        let handle = ExecHandle {
            stdout: reader_handle(&stdout_r),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::Exited(0))),
            terminator: Box::new(|| Ok(())),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();

        let mut taken = proc.take_stdout().expect("stdout must be exposed");
        let closer = proc
            .stdout_closer()
            .expect("a stream this adapter exposes must come with a closer");

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = tx.send(taken.read_to_end(&mut sink).map(|_| ()));
        });

        // Let the reader block on the empty pipe before abandoning it. The
        // canceller also short-circuits a read that has not started yet, so the
        // sleep is a courtesy rather than a correctness requirement.
        std::thread::sleep(Duration::from_millis(50));
        closer.close();

        let outcome = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("closing the stream must end the read");
        assert!(
            outcome.is_ok(),
            "an abandoned read reports EOF, not an error: {outcome:?}"
        );

        // Held open on purpose: an early drop would deliver the EOF whose
        // absence is what makes this test discriminating.
        drop(stdout_w);
        drop(stdout_r);
    }

    /// A prior `try_wait()` must not let `wait()` skip the drain.
    ///
    /// `self.exit` records that the child finished; it says nothing about
    /// whether anything was drained. Returning early on it would silently
    /// break the contract for exactly the caller who polls before waiting.
    ///
    /// The proof is that `wait` **consumed the stream**, not that it copied
    /// every byte. The discard is cancelled as soon as the waiter returns, and
    /// with the exit already cached that is immediate, so how much of a finished
    /// child's buffered output the discard reads first is a race. Bytes were
    /// only ever a proxy; taking the stream is the step an early return skips,
    /// and it is deterministic.
    #[test]
    fn wait_still_drains_after_a_successful_try_wait() {
        let (stdout_r, mut stdout_w) = std::io::pipe().expect("pipe");
        stdout_w.write_all(b"left in the pipe").unwrap();
        drop(stdout_w); // EOF, so the drain can finish

        let handle = ExecHandle {
            stdout: reader_handle(&stdout_r),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::Exited(0))),
            terminator: Box::new(|| Ok(())),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();

        // Guards against the assertion below going vacuous: if the wrap had
        // produced nothing there would be no stream for `wait` to take, and
        // "is_none() afterwards" would hold no matter what `wait` did.
        assert!(
            proc.stdout.is_some(),
            "precondition: the adapter must have wrapped the test's stdout"
        );

        // Poll until the waiter thread has finished, caching the exit code.
        let started = Instant::now();
        while proc.try_wait().unwrap().is_none() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the waiter should have completed"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(proc.wait().unwrap(), 0);

        assert!(
            proc.stdout.is_none(),
            "wait() skipped the drain after try_wait(): the untaken stream was never drained"
        );

        drop(stdout_r);
    }

    // Build a PipeHandle from a live pipe end's raw handle/fd (the adapter
    // duplicates it, so the original stays owned by the test).
    #[cfg(target_os = "windows")]
    fn reader_handle(r: &std::io::PipeReader) -> PipeHandle {
        use std::os::windows::io::AsRawHandle;
        windows::Win32::Foundation::HANDLE(r.as_raw_handle() as _)
    }
    #[cfg(target_os = "windows")]
    fn writer_handle(w: &std::io::PipeWriter) -> PipeHandle {
        use std::os::windows::io::AsRawHandle;
        windows::Win32::Foundation::HANDLE(w.as_raw_handle() as _)
    }
    #[cfg(not(target_os = "windows"))]
    fn reader_handle(r: &std::io::PipeReader) -> PipeHandle {
        use std::os::fd::AsRawFd;
        r.as_raw_fd()
    }
    #[cfg(not(target_os = "windows"))]
    fn writer_handle(w: &std::io::PipeWriter) -> PipeHandle {
        use std::os::fd::AsRawFd;
        w.as_raw_fd()
    }

    /// A real stdout pipe is streamed through the adapter: the adapter reads a
    /// *duplicate*, so the caller's original handle is unaffected and there is
    /// no double-close.
    #[test]
    fn real_stdout_pipe_is_streamed_via_duplicate() {
        use std::io::{Read, Write};

        let (reader, mut writer) = std::io::pipe().expect("pipe");
        writer.write_all(b"exec-stream-ok").unwrap();
        drop(writer); // close the write end so the reader sees EOF

        let handle = ExecHandle {
            stdout: reader_handle(&reader),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::Exited(0))),
            terminator: Box::new(|| Ok(())),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();
        // The adapter duplicated the handle; the test's original can now drop.
        drop(reader);

        let mut out = proc.take_stdout().expect("stdout should be present");
        let mut buf = String::new();
        out.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "exec-stream-ok");
        assert_eq!(proc.wait().unwrap(), 0);
    }

    /// A real stdin pipe is fed through the adapter's writer (a duplicate).
    #[test]
    fn real_stdin_pipe_accepts_writes_via_duplicate() {
        use std::io::{Read, Write};

        let (mut reader, writer) = std::io::pipe().expect("pipe");

        let handle = ExecHandle {
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            stdin: writer_handle(&writer),
            waiter: Box::new(|| Ok(ExecOutcome::Exited(0))),
            terminator: Box::new(|| Ok(())),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle).unwrap();
        drop(writer); // original write end closed; adapter owns a duplicate

        {
            let mut stdin = proc.take_stdin().expect("stdin should be present");
            stdin.write_all(b"fed-via-adapter").unwrap();
            stdin.flush().unwrap();
        } // drop the adapter's writer -> EOF on the read end

        let mut buf = String::new();
        reader.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "fed-via-adapter");
        assert_eq!(proc.wait().unwrap(), 0);
    }
}
