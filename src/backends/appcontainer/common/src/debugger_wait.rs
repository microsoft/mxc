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
//! special-casing there. Ctrl-C during the attach-wait is handled by the
//! existing `sandbox_tracking` console-control handler (registered well
//! before this point), which runs on its own OS thread independent of this
//! poll loop.
//!
//! Failure handling: a `CheckRemoteDebuggerPresent` error (e.g. the process
//! handle going bad because the suspended child was killed externally while
//! we were polling) is a permanent condition, not "no debugger yet" — retrying
//! it forever would hang `wxc-exec` indefinitely. Likewise a failing
//! `ResumeThread` after attach must not be reported as success. Both cases
//! terminate the child and return an error, mirroring
//! `SpawnedChild::resume`'s fail-closed behavior; the caller only needs to
//! tear down its own sandbox resources and surface the error.

use std::fmt::Write as _;
use std::time::Duration;

use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent;
use windows::Win32::System::Threading::{ResumeThread, TerminateProcess};
use windows_core::BOOL;

use wxc_common::error::WxcError;
use wxc_common::logger::Logger;

/// How often to poll `CheckRemoteDebuggerPresent` while waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

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

    loop {
        let mut present = BOOL(0);
        // SAFETY: `process` is a valid, open handle for the duration of this
        // call (caller contract); `present` is a valid out-param on the stack.
        let checked = unsafe { CheckRemoteDebuggerPresent(process, &mut present) };
        match checked {
            Ok(()) if present.as_bool() => break,
            Ok(()) => std::thread::sleep(POLL_INTERVAL),
            Err(e) => {
                // The handle went bad (e.g. the still-suspended child was
                // terminated externally) -- this can never resolve on its
                // own, so fail closed instead of polling forever.
                // SAFETY: `process` is the caller's still-owned handle;
                // terminating it before returning matches the fail-closed
                // contract every other launch-failure path in the runners
                // follows.
                unsafe {
                    let _ = TerminateProcess(process, u32::MAX);
                }
                return Err(WxcError::Process(format!(
                    "CheckRemoteDebuggerPresent failed while waiting for a debugger to \
                     attach to PID {pid}: {e}"
                )));
            }
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
