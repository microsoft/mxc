// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Streaming WSLC backend — the handle-based counterpart of
//! [`WSLContainerRunner`]'s run-to-completion `ScriptRunner`.
//!
//! Implementing [`SandboxBackend`] for the same runner lets the Rust SDK
//! (`mxc-sdk`, via `mxc_engine`) spawn a WSL container and drive it live: read
//! its stdout/stderr while it runs, wait for it with the request's timeout, and
//! kill it.
//!
//! Both this and the run-to-completion runner share one lifecycle
//! implementation (`start_container`); they differ only in where the WSLC SDK's
//! output callbacks send their bytes.
//!
//! # What WSLC can and cannot stream
//!
//! - **stdout / stderr** — the SDK pushes them to callbacks, which this module
//!   forwards to an in-memory stream per handle (see [`crate::stream_buffer`]);
//!   the caller reads the other end.
//! - **stdin** — the WSLC SDK exposes no process-input API, so
//!   [`take_stdin`](SandboxProcess::take_stdin) always returns `None`.
//! - **[`id`](SandboxProcess::id)** — the process lives inside the WSL VM and
//!   has no host process id, so this is always `0`.

use std::io::{Read, Write};

use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{ExecutionRequest, ScriptResponse};
use wxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, spawn_discard, take_boxed_read, SandboxBackend,
    SandboxProcess, StdioMode, StreamCloser,
};
use wxc_common::script_runner::ScriptRunner;
use wxc_common::validator::validate_common;

use crate::stream_buffer::{StreamCanceller, StreamReader};
use crate::wsl_container_runner::{OutputMode, StartedContainer, WSLContainerRunner};
use crate::wslc_bindings::WslcSignal;

impl SandboxBackend for WSLContainerRunner {
    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        ScriptRunner::validate_runner(self, request)
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        // The run-to-completion path gets these through `ScriptRunner::run`;
        // the streaming path bypasses that, so — like every other
        // `SandboxBackend` — apply them here. Beyond rejecting an empty
        // command, this is what enforces the central testing-features gate on
        // `network.proxy.builtinTestServer`.
        validate_common(request)?;
        self.validate(request)?;

        // SAFETY: `start_container` drives the WSLC SDK over raw FFI; it owns
        // every buffer it passes in and returns RAII guards for every handle it
        // opens, so the returned value is self-contained.
        let started = unsafe { self.start_container(request, logger, OutputMode::Stream(stdio)) }?;
        Ok(Box::new(WslcSandboxProcess::new(started)))
    }
}

/// The `ErrorKind::TimedOut` error [`SandboxProcess::wait`] reports when the
/// request's `scriptTimeout` elapsed and the container was torn down.
fn timeout_error(timeout_ms: u32) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("Process timed out after {timeout_ms}ms and was terminated"),
    )
}

/// The error reported when the deadline elapsed but the kill could **not** be
/// confirmed.
///
/// Deliberately *not* `ErrorKind::TimedOut`: the public
/// [`mxc_sdk::Sandbox::wait`] maps that kind onto `WaitOutcome::TimedOut`, a
/// success value whose contract is that the process tree *was* killed — which
/// would silently restore the very claim this case exists to avoid, discarding
/// the message with it. Being unable to establish the sandbox's state is a
/// genuine failure, so it surfaces as one and reaches the caller as `Err`.
fn unconfirmed_termination_error(timeout_ms: u32) -> std::io::Error {
    std::io::Error::other(format!(
        "Process timed out after {timeout_ms}ms; the container could not be confirmed terminated \
         and may still be running (call wait() to retry the teardown)"
    ))
}

/// A running WSL container's init process.
struct WslcSandboxProcess {
    started: StartedContainer,
    stdout: Option<StreamReader>,
    stderr: Option<StreamReader>,
    stdout_canceller: Option<StreamCanceller>,
    stderr_canceller: Option<StreamCanceller>,
    /// Exit code cached by the first successful wait, so repeat waits are
    /// idempotent (and don't re-run teardown).
    exit: Option<i32>,
    /// Set once the wait deadline elapsed *and* the kill was confirmed, so
    /// `TimedOut` is reported stickily rather than a later-observed exit code.
    /// Deliberately narrower than [`deadline_elapsed`](Self::deadline_elapsed):
    /// this flag is what promises the process was terminated, so it must never
    /// be set on an unconfirmed kill.
    timed_out: bool,
    /// Set once the wait deadline elapsed, whether or not the kill that follows
    /// could be confirmed. Records only that the deadline is spent, so a repeat
    /// `wait` resumes at confirmation instead of blocking out another full one.
    deadline_elapsed: bool,
    /// Set once the container has been *confirmed* torn down, so `Drop` doesn't
    /// repeat it — and, just as importantly, still retries when teardown failed
    /// or could not be confirmed. Tracked separately from `exit`: a caller that
    /// only ever polls [`try_wait`](SandboxProcess::try_wait) learns the exit
    /// code without any teardown having run.
    torn_down: bool,
    /// Diagnostics from the SDK calls this handle makes after the spawn
    /// returned. The streaming contract has nowhere to flush them — the spawn
    /// itself already logged through the caller's logger — so they are
    /// buffered and dropped with the handle.
    logger: Logger,
}

// SAFETY: the WSLC handles inside `StartedContainer` are opaque SDK pointers,
// not COM interface pointers the caller marshals: `init_and_load_sdk` enters the
// *multithreaded* apartment (`COINIT_MULTITHREADED`), so the SDK's objects live
// in the MTA and the SDK itself invokes our I/O and exit callbacks on its own
// internal threads — it is free-threaded by design.
//
// `CoInitializeEx` is nonetheless per-thread, so moving this handle to a thread
// that never initialized COM would otherwise leave the SDK on the stack of an
// apartment-less thread. Every entry point that calls the SDK joins the MTA for
// the duration via `ComApartment`, mirroring `appcontainer_common`'s guard:
// `StartedContainer`'s `wait_for_exit` / `destroy` / `stop` / `exit_code`, and
// — because a `Send` handle can be *dropped* on such a thread too — the
// `Drop` impls of the `WslcSessionGuard` / `WslcContainerGuard` /
// `WslcProcessGuard` handles it owns. No apartment state or interface pointer
// is cached across calls, so setup and teardown may run on different threads.
//
// The invariant holds with no exception: where an apartment cannot be
// established at all, every one of those paths declines to call the SDK rather
// than proceeding without one — leaking the handle (the guards, which have no
// error channel) or reporting the failure (`destroy`).
//
// The handle is *moved* between threads, never shared (`Sync` is deliberately
// not claimed), so at most one thread calls into the SDK at a time.
unsafe impl Send for WslcSandboxProcess {}

/// What an earlier wait already established about this process's outcome, which
/// every later `wait` / `try_wait` must keep reporting.
///
/// Extracted so the two entry points cannot drift: the trait's promise is that
/// once a run is reported as timed out, no later status query downgrades it to
/// an exit code — and a timeout *kills* the container, so the raw SDK exit code
/// is always available to be mistakenly reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settled {
    /// The deadline elapsed and the kill was confirmed.
    TimedOut,
    /// The deadline elapsed, but the kill could not be confirmed. Still a
    /// timeout — the deadline is spent — with the termination unproven.
    DeadlineUnconfirmed,
    /// The process exited on its own and teardown completed.
    Exited(i32),
    /// Nothing established yet; ask the container.
    Pending,
}

/// Decide the sticky outcome from the flags an earlier wait set.
///
/// `deadline_elapsed` and `exit` are mutually exclusive by construction (the
/// first is only set on the timeout path, the second only on the normal one),
/// so the order these are tested in does not matter.
fn settled_outcome(timed_out: bool, deadline_elapsed: bool, exit: Option<i32>) -> Settled {
    if timed_out {
        Settled::TimedOut
    } else if deadline_elapsed {
        Settled::DeadlineUnconfirmed
    } else if let Some(code) = exit {
        Settled::Exited(code)
    } else {
        Settled::Pending
    }
}

impl WslcSandboxProcess {
    fn new(mut started: StartedContainer) -> Self {
        let pipes = started.pipes.take();
        let (stdout, stderr) = match pipes {
            Some(pipes) => (Some(pipes.stdout), Some(pipes.stderr)),
            None => (None, None),
        };
        Self {
            stdout_canceller: stdout.as_ref().map(|r| r.canceller()),
            stderr_canceller: stderr.as_ref().map(|r| r.canceller()),
            stdout,
            stderr,
            started,
            exit: None,
            timed_out: false,
            deadline_elapsed: false,
            torn_down: false,
            logger: Logger::new(Mode::Buffer),
        }
    }

    /// This handle's [`Settled`] outcome so far.
    fn settled(&self) -> Settled {
        settled_outcome(self.timed_out, self.deadline_elapsed, self.exit)
    }

    /// Complete the timeout path: confirm the sandboxed process is really gone,
    /// tear the container down, and only then make `TimedOut` sticky.
    ///
    /// `wait_for_exit`'s timeout branch only *asks* the container to stop
    /// (`SIGTERM`, short grace, HRESULT ignored), so reaching it proves nothing
    /// about whether the process died — while returning `TimedOut` promises it
    /// was terminated. Every failure here therefore leaves both `timed_out` and
    /// `torn_down` unset, so the promise is never made on an unconfirmed kill
    /// and a later `wait` (or `Drop`) retries instead.
    fn finish_timed_out(&mut self) -> std::io::Result<i32> {
        self.started
            .confirm_terminated(&mut self.logger)
            .map_err(std::io::Error::other)?;
        self.started
            .destroy(&mut self.logger)
            .map_err(std::io::Error::other)?;
        self.torn_down = true;
        self.timed_out = true;
        Err(timeout_error(self.started.timeout_ms))
    }
}

impl SandboxProcess for WslcSandboxProcess {
    /// Always `None`: the WSLC SDK has no API to write to a container process's
    /// stdin.
    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        None
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        take_boxed_read(&mut self.stdout)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        take_boxed_read(&mut self.stderr)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        // The settled outcome is checked exactly as in `wait`. Without this,
        // the timeout path — which kills the container — leaves `has_exited()`
        // true below, so a caller that saw `wait` fail with `TimedOut` would
        // get `Ok(Some(<kill code>))` from a later poll: two contradictory
        // answers, with the timeout silently downgraded to a normal exit.
        match self.settled() {
            Settled::TimedOut => return Err(timeout_error(self.started.timeout_ms)),
            // `try_wait` is non-blocking, so confirmation cannot be retried
            // here the way `wait` retries it — but an exit code would still be
            // the wrong answer for a spent deadline.
            Settled::DeadlineUnconfirmed => {
                return Err(unconfirmed_termination_error(self.started.timeout_ms))
            }
            // A cached code means `wait` already ran the full teardown.
            Settled::Exited(code) => return Ok(Some(code)),
            Settled::Pending => {}
        }
        if !self.started.has_exited() {
            return Ok(None);
        }
        // Deliberately *not* cached into `self.exit`: `wait` treats a cached
        // code as proof that it already drained the streams, destroyed the
        // container, and set `torn_down`, so caching here would make a later
        // `wait` skip teardown entirely — and would mask a prior timeout,
        // turning a `TimedOut` into a normal exit. Re-querying is a cheap
        // SDK call.
        // SAFETY: `started` owns live process and SDK handles.
        unsafe { self.started.exit_code() }
            .map_err(std::io::Error::other)
            .map(Some)
    }

    /// Always `0` — the sandboxed process runs inside the WSL VM and has no
    /// host process id.
    fn id(&self) -> u32 {
        0
    }

    fn kill(&mut self) -> std::io::Result<()> {
        // WSLC has no per-process signal API: stopping the container terminates
        // the init process and everything it spawned — the tree kill the trait
        // asks for. `0` means "don't wait for a graceful stop".
        self.started
            .stop(WslcSignal::WSLC_SIGNAL_SIGKILL, 0)
            .map_err(std::io::Error::other)
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        match self.settled() {
            // Sticky: a confirmed timeout must keep being reported as one,
            // never as a later-observed exit code.
            Settled::TimedOut => return Err(timeout_error(self.started.timeout_ms)),
            Settled::Exited(code) => return Ok(code),
            // An earlier call already burned the deadline but could not confirm
            // the kill. Resume at the confirmation step: re-entering
            // `wait_for_exit` would block for another full deadline, while
            // reporting `TimedOut` outright would promise a kill that never
            // happened.
            Settled::DeadlineUnconfirmed => return self.finish_timed_out(),
            Settled::Pending => {}
        }

        // Drain the streams the caller did not take, concurrently with the
        // wait, so unread output can't accumulate for the life of the process
        // (see the trait's pipe-deadlock contract — here the buffer is
        // in-memory and unbounded, so the cost of not draining is memory rather
        // than a stalled child). A stream the caller *did* take is left alone.
        let stdout_drain = spawn_discard(self.stdout.take());
        let stderr_drain = spawn_discard(self.stderr.take());

        let waited = self.started.wait_for_exit(&mut self.logger);

        // Release the drain readers we own first, whichever way the wait went:
        // firing their canceller can't truncate anything the caller is reading
        // (`cancel_and_join_discard` only fires for a stream we drained), and
        // joining them here keeps a later error return from leaving threads
        // parked on a read.
        cancel_and_join_discard(stdout_drain, &self.stdout_canceller);
        cancel_and_join_discard(stderr_drain, &self.stderr_canceller);

        // Deliberately before `close_streams`: `wait_for_exit` can fail while
        // the process is still running (a failed apartment, or
        // `WslcGetProcessExitEvent`), and closing the SDK-side writers then
        // would EOF a caller-taken reader and discard every later callback for
        // a process that is still producing output.
        let (exit_code, outcome) = waited.map_err(|response| {
            std::io::Error::other(if response.error_message.is_empty() {
                "waiting for the WSL container process failed".to_string()
            } else {
                response.error_message
            })
        })?;

        // The process is gone (or was killed): close the SDK-side write ends so
        // every reader — ours and the caller's — sees EOF once it has consumed
        // what was already buffered.
        self.started.close_streams();

        if outcome.timed_out() {
            // Records only that the deadline elapsed. Even
            // `WaitOutcome::TimedOutTerminated` goes through `finish_timed_out`,
            // whose `confirm_terminated` short-circuits on an already-confirmed
            // exit — so the confirmed case costs nothing and the unconfirmed one
            // gets the retry it needs.
            self.deadline_elapsed = true;
            return self.finish_timed_out();
        }

        // The exit callback fired, so the process is confirmed gone and only the
        // container object can still leak. `torn_down` therefore tracks whether
        // teardown actually succeeded, leaving `Drop` to retry it if not.
        self.torn_down = self.started.destroy(&mut self.logger).is_ok();
        self.exit = Some(exit_code);
        Ok(exit_code)
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stdout_canceller)
    }

    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stderr_canceller)
    }
}

impl Drop for WslcSandboxProcess {
    /// A handle dropped before [`wait`](SandboxProcess::wait) tore the container
    /// down still owns one — possibly still running: stop it (and, when the
    /// request asked for it, delete it) rather than leaking a VM-backed sandbox.
    fn drop(&mut self) {
        if self.torn_down {
            return;
        }
        // Settles the container and blocks on the exit callback before the
        // fields it owns are released — the SDK must have stopped calling back
        // before the `IoContext` is freed and the DLL unloaded.
        let mut logger = Logger::new(Mode::Buffer);
        self.started.quiesce(&mut logger);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact contradiction the streaming contract forbids: a timed-out run
    /// is killed, so the container *has* an exit code to report — and reporting
    /// it would turn `wait`'s `Err(TimedOut)` into a later `Ok(Some(137))`.
    /// Both entry points read this one decision, so they cannot disagree.
    #[test]
    fn a_confirmed_timeout_is_never_downgraded_to_an_exit_code() {
        assert_eq!(
            settled_outcome(true, true, None),
            Settled::TimedOut,
            "a confirmed timeout stays a timeout"
        );
        // Even with an exit code somehow recorded, the timeout still wins.
        assert_eq!(
            settled_outcome(true, true, Some(137)),
            Settled::TimedOut,
            "a recorded exit code must not mask a confirmed timeout"
        );
    }

    /// A deadline that elapsed but whose kill could not be confirmed is still a
    /// timeout — never an exit code — but it is reported apart from the
    /// confirmed case so nothing claims a termination that was not shown.
    #[test]
    fn an_unconfirmed_deadline_is_distinct_from_a_confirmed_timeout() {
        assert_eq!(
            settled_outcome(false, true, None),
            Settled::DeadlineUnconfirmed,
        );
        assert_ne!(
            settled_outcome(false, true, None),
            Settled::TimedOut,
            "an unconfirmed kill must not report as a completed termination"
        );
    }

    #[test]
    fn a_normal_exit_is_reported_once_teardown_cached_it() {
        assert_eq!(settled_outcome(false, false, Some(0)), Settled::Exited(0));
        assert_eq!(settled_outcome(false, false, Some(3)), Settled::Exited(3));
    }

    #[test]
    fn a_fresh_handle_has_nothing_settled_yet() {
        assert_eq!(settled_outcome(false, false, None), Settled::Pending);
    }

    /// The safety property behind both entry points: once the deadline has
    /// elapsed, *no* combination of flags may answer "exited normally". This is
    /// what stops a killed container's exit code from masking the timeout.
    #[test]
    fn a_spent_deadline_never_yields_an_exit_code() {
        for timed_out in [false, true] {
            for exit in [None, Some(0), Some(137)] {
                let outcome = settled_outcome(timed_out, true, exit);
                assert!(
                    !matches!(outcome, Settled::Exited(_)),
                    "a spent deadline (timed_out={timed_out}, exit={exit:?}) must not report an \
                     exit code, got {outcome:?}"
                );
            }
        }
    }

    /// Only a *confirmed* kill may carry `ErrorKind::TimedOut`.
    ///
    /// `mxc_sdk::Sandbox::wait` turns that kind into `WaitOutcome::TimedOut`, a
    /// success value promising the process tree was killed — and drops the
    /// message doing it. An unconfirmed kill must therefore not use that kind,
    /// or the distinction would be erased at the public API boundary.
    #[test]
    fn only_a_confirmed_kill_uses_the_timedout_error_kind() {
        let confirmed = timeout_error(1500);
        let unconfirmed = unconfirmed_termination_error(1500);

        assert_eq!(confirmed.kind(), std::io::ErrorKind::TimedOut);
        assert_ne!(
            unconfirmed.kind(),
            std::io::ErrorKind::TimedOut,
            "an unconfirmed kill must not be convertible into WaitOutcome::TimedOut"
        );

        assert!(confirmed.to_string().contains("1500ms"));
        assert!(unconfirmed.to_string().contains("1500ms"));
        assert!(
            confirmed.to_string().contains("was terminated"),
            "the confirmed message states the termination"
        );
        assert!(
            !unconfirmed.to_string().contains("was terminated"),
            "the unconfirmed message must not claim a termination it did not prove"
        );
        assert!(
            unconfirmed.to_string().contains("may still be running"),
            "the unconfirmed message must say the container may still be running"
        );
    }
}
