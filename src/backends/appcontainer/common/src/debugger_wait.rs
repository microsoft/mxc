// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `--wait-for-debugger` support.
//!
//! The mechanism: the runners create the sandboxed child suspended and
//! assign it to the job object exactly as before, but instead of calling
//! `ResumeThread` immediately, they hand off to
//! [`wait_for_debugger_then_resume`], which:
//!
//!  1. Logs the PID and blocks — with **no timeout** — polling
//!     `CheckRemoteDebuggerPresent` on the child's process handle. The main
//!     thread has not run any code yet — not even its own loader
//!     initialization, so no dependent DLL past the main image is mapped —
//!     so nothing here races an operator who takes an arbitrarily long time
//!     to attach.
//!  2. The instant a debugger attaches, calls `ResumeThread` exactly once.
//!
//! Why step 2 doesn't let the target run away before the operator sets
//! breakpoints: attaching a debugger (`DebugActiveProcess`) synthesizes an
//! initial batch of debug events (process/thread/module state) that stay
//! *outstanding* — and every thread stays frozen — until the debugger
//! itself acknowledges them via `ContinueDebugEvent`/`g`. That freeze is a
//! second, independent contribution to the same suspend-count field
//! `CREATE_SUSPENDED` used, which is why attaching used to leave the count
//! at 2 (our 1 + the debugger's 1) and required an operator-side `~0 m`
//! before `g`. By calling `ResumeThread` ourselves the moment attach is
//! detected, we cancel only *our own* contribution — the debugger's
//! independent freeze is still holding the thread — so all the operator
//! needs is a plain `g`. Every breakpoint set beforehand is still
//! necessarily a deferred/pending one (nothing but the main image has
//! loaded), so it resolves normally once the target actually starts running
//! after `g`.
//!
//! Once resumed this way, `wxc-exec` falls into its normal (already
//! unbounded when `script_timeout` is 0) wait for the child to exit — no
//! special-casing there. Ctrl-C, console close, an unhandled panic, or the
//! parent process killing `wxc-exec` while this loop is still waiting would
//! otherwise orphan the child permanently: it has not run any code at all
//! (not even loader init), so nothing of its own could ever notice
//! `wxc-exec` is gone and resume or reap it. The runner that creates the
//! job object this child is assigned to sets
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` whenever `wait_for_debugger` is
//! requested (see `job_object::UiJobObject::set_kill_on_job_close`), so the
//! OS itself kills the child the instant the last handle to that job
//! closes — which happens on every one of those exit paths, including the
//! ones that bypass every Rust destructor.
//!
//! Failure handling: this loop can end in three ways other than a
//! successful attach, and each is handled distinctly:
//!  - A `CheckRemoteDebuggerPresent` API failure (not "no debugger yet" —
//!    that is a *successful* call reporting `present == false`) is a
//!    permanent condition; retrying it forever would hang `wxc-exec`
//!    indefinitely. Terminates the child and fails closed.
//!  - The suspended child exiting on its own (e.g. killed externally)
//!    before a debugger attaches. A process `HANDLE` stays a valid kernel
//!    object — and `CheckRemoteDebuggerPresent` keeps reporting
//!    `present == false` on it — long after the process it refers to has
//!    terminated, so `present == false` alone can never distinguish "still
//!    waiting" from "can never resolve". Every poll iteration also checks
//!    child liveness via `WaitForSingleObject` (which doubles as the
//!    poll-interval sleep) and fails closed the instant it observes the
//!    child has exited; no `TerminateProcess` is needed since the child is
//!    already dead.
//!  - A failing `ResumeThread` after attach, which must not be reported as
//!    success. Terminates the child and fails closed.
//!
//! All three cases return an error to the caller, which only needs to tear
//! down its own sandbox resources and surface it.

use std::fmt::Write as _;
use std::time::Duration;

use windows::Win32::Foundation::{GetLastError, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent;
use windows::Win32::System::Threading::{ResumeThread, TerminateProcess, WaitForSingleObject};
use windows_core::BOOL;

use wxc_common::error::WxcError;
use wxc_common::logger::Logger;

/// How often to poll `CheckRemoteDebuggerPresent` while waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Outcome of [`wait_loop`]'s pure state machine, distinguishing the two
/// failure modes so the caller can decide whether the child still needs
/// terminating.
#[derive(Debug, PartialEq, Eq)]
enum WaitLoopOutcome {
    /// A debugger attached.
    Attached,
    /// The child exited (observed via the liveness check) before a debugger
    /// attached. The child is already gone; no `TerminateProcess` needed.
    ChildExited,
    /// The attach check itself failed (a permanent condition). Carries the
    /// error message; the caller terminates the child and fails closed.
    ApiFailure(String),
}

/// Pure poll-loop state machine: poll `check_attached` until it reports an
/// attached debugger, checking child liveness via `wait_tick` between polls.
/// Contains no Win32 calls itself -- both are injected as closures so this
/// can be exercised by unit tests with canned sequences and no real process,
/// debugger, or OS wait at all.
///
/// `check_attached` returns `Ok(true)` once attached, `Ok(false)` if not yet
/// attached, or `Err` on a permanent API failure. `wait_tick` is called only
/// when not yet attached; it performs (or simulates) the poll-interval delay
/// and returns `true` if the child died during that wait.
fn wait_loop(
    mut check_attached: impl FnMut() -> Result<bool, String>,
    mut wait_tick: impl FnMut() -> bool,
) -> WaitLoopOutcome {
    loop {
        match check_attached() {
            Ok(true) => return WaitLoopOutcome::Attached,
            Ok(false) => {
                if wait_tick() {
                    return WaitLoopOutcome::ChildExited;
                }
            }
            Err(e) => return WaitLoopOutcome::ApiFailure(e),
        }
    }
}

/// Block (no timeout) until a debugger attaches to `process`, then resume
/// `thread` exactly once — cancelling only the `CREATE_SUSPENDED` increment
/// `wxc-exec` itself added, leaving the debugger's own attach-time freeze in
/// place so the operator's plain `g` is what actually starts it running.
///
/// On failure the child is terminated (fail closed) before returning
/// [`WxcError::Process`]; the caller only needs to tear down its own sandbox
/// resources and surface the error.
///
/// # Safety
/// `process` and `thread` must be valid, still-open handles to the just
/// created, still-suspended child for the duration of this call; the caller
/// retains ownership (this function does not close either handle).
pub fn wait_for_debugger_then_resume(
    process: HANDLE,
    thread: HANDLE,
    pid: u32,
    logger: &mut Logger,
) -> Result<(), WxcError> {
    let banner = format!("Process suspended, PID: {pid}. Attach a debugger to continue.");
    let _ = writeln!(logger, "{banner}");
    eprintln!("{banner}");

    let outcome = wait_loop(
        || {
            let mut present = BOOL(0);
            // SAFETY: `process` is a valid, open handle for the duration of
            // this call (caller contract); `present` is a valid out-param
            // on the stack.
            unsafe { CheckRemoteDebuggerPresent(process, &mut present) }
                .map(|()| present.as_bool())
                .map_err(|e| e.to_string())
        },
        || {
            // `present == false` alone can't distinguish "still waiting"
            // from "the child died and this can never resolve" (see the
            // module doc). `WaitForSingleObject` doubles as the poll
            // interval and a liveness check: it returns early, before the
            // interval elapses, only if `process` has become signaled --
            // i.e. the child exited.
            // SAFETY: `process` is a valid, open handle for the duration of
            // this call (caller contract).
            (unsafe { WaitForSingleObject(process, POLL_INTERVAL.as_millis() as u32) })
                == WAIT_OBJECT_0
        },
    );

    match outcome {
        WaitLoopOutcome::Attached => {}
        WaitLoopOutcome::ChildExited => {
            return Err(WxcError::Process(format!(
                "PID {pid} exited before a debugger attached"
            )));
        }
        WaitLoopOutcome::ApiFailure(e) => {
            // A genuine CheckRemoteDebuggerPresent API failure (distinct
            // from the "no debugger yet" `Ok(false)` case) is a permanent
            // condition -- retrying it forever would hang wxc-exec
            // indefinitely. Fail closed instead.
            // SAFETY: `process` is the caller's still-owned handle;
            // terminating it before returning matches the fail-closed
            // contract every other launch-failure path in the runners
            // follows.
            unsafe {
                let _ = TerminateProcess(process, u32::MAX);
            }
            return Err(WxcError::Process(format!(
                "CheckRemoteDebuggerPresent failed while waiting for a debugger to attach to \
                 PID {pid}: {e}"
            )));
        }
    }

    // SAFETY: `thread` is the caller's still-owned, still-suspended main
    // thread handle; ResumeThread only adjusts its suspend count. This
    // cancels exactly the one increment wxc-exec added via CREATE_SUSPENDED
    // — the debugger's own attach-time freeze (a separate contribution to
    // the same counter) is unaffected and keeps the thread from actually
    // running until the operator issues `g`.
    let resumed = unsafe { ResumeThread(thread) };
    if resumed == u32::MAX {
        let err = unsafe { GetLastError() };
        // SAFETY: same fail-closed contract as above.
        unsafe {
            let _ = TerminateProcess(process, u32::MAX);
        }
        return Err(WxcError::Process(format!(
            "ResumeThread failed after debugger attach for PID {pid}: {err:?}"
        )));
    }
    let _ = writeln!(logger, "Process started, PID: {pid}.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_loop_attaches_immediately() {
        let outcome = wait_loop(|| Ok(true), || panic!("wait_tick must not be called"));
        assert_eq!(outcome, WaitLoopOutcome::Attached);
    }

    #[test]
    fn wait_loop_attaches_after_several_polls() {
        let mut checks = vec![false, false, true].into_iter();
        let mut ticks = 0;
        let outcome = wait_loop(
            || Ok(checks.next().expect("no more canned checks")),
            || {
                ticks += 1;
                false // child stays alive
            },
        );
        assert_eq!(outcome, WaitLoopOutcome::Attached);
        // Two "not yet attached" results precede the final "attached" one.
        assert_eq!(ticks, 2);
    }

    #[test]
    fn wait_loop_reports_child_exited_mid_wait() {
        let outcome = wait_loop(|| Ok(false), || true);
        assert_eq!(outcome, WaitLoopOutcome::ChildExited);
    }

    #[test]
    fn wait_loop_never_attached_keeps_polling_while_alive() {
        // Regression guard: a child that stays alive without ever attaching
        // must not be reported as exited or as a failure -- it should just
        // keep polling (bounded here so the test terminates).
        let mut remaining = 5;
        let outcome = wait_loop(
            || {
                if remaining == 0 {
                    Ok(true)
                } else {
                    remaining -= 1;
                    Ok(false)
                }
            },
            || false, // never dies
        );
        assert_eq!(outcome, WaitLoopOutcome::Attached);
    }

    #[test]
    fn wait_loop_propagates_api_failure() {
        let outcome = wait_loop(
            || Err("access denied".to_string()),
            || panic!("wait_tick must not be called on API failure"),
        );
        assert_eq!(
            outcome,
            WaitLoopOutcome::ApiFailure("access denied".to_string())
        );
    }
}
