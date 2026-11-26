// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Process handles, waiting, and termination for IsolationSession workloads.

use super::error::{lifecycle_err, op, transport_err, IsolationSessionError};
use super::manager::MtaReference;
use super::owned_thread::{self, Impersonation};
use crate::isolation_session_bindings::bindings::IsoSessionProcess;
use crate::mxc_common::audit::{AuditEvent, AuditEventName, KillMethod};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::state_aware_backend::ExecOutcome;
use std::sync::{Arc, Mutex, PoisonError};

/// A process started inside an isolation session but **not yet awaited**.
///
/// Separating start from wait is what makes streaming possible: the executor
/// path hands these handles to its own relay threads and blocks, while an
/// in-process SDK caller takes them and drives them itself.
///
/// **Handle ownership stays here.** The three pipe handles belong to the
/// `IsoSessionProcess` and are released by its `Close()`; a consumer duplicates
/// them and must never close the originals. A `0` means the stream is genuinely
/// absent, not that a getter failed — `start_process` propagates getter errors
/// rather than coercing them.
pub(super) struct StartedProcess {
    pub(super) process: IsoSessionProcess,
    pub(super) close_lock: Arc<Mutex<()>>,
    pub(super) stdout: u64,
    pub(super) stderr: u64,
    pub(super) stdin: u64,
    identity: &'static str,
    audit_logger: Mutex<Logger>,
}

impl StartedProcess {
    pub(super) fn new(
        process: IsoSessionProcess,
        identity: &'static str,
        logger: Option<&Logger>,
    ) -> Result<Self, IsolationSessionError> {
        // A getter that errors is a backend failure, not an absent stream:
        // propagate it rather than coercing to 0, which downstream treats as
        // "no handle" and silently skips the corresponding stdio relay. A
        // genuinely returned 0 still means absent and is preserved.
        let stdout = process
            .OutputHandle()
            .map_err(|e| transport_err(op::RUN_PROCESS, "get OutputHandle failed", &e))?;
        let stderr = process
            .ErrorHandle()
            .map_err(|e| transport_err(op::RUN_PROCESS, "get ErrorHandle failed", &e))?;
        let stdin = process
            .InputHandle()
            .map_err(|e| transport_err(op::RUN_PROCESS, "get InputHandle failed", &e))?;

        Ok(Self {
            process,
            close_lock: Arc::new(Mutex::new(())),
            stdout,
            stderr,
            stdin,
            identity,
            audit_logger: Mutex::new(
                logger
                    .map(Logger::clone_diagnostic_sink)
                    .unwrap_or_else(Logger::inherit_thread_diagnostic_sink),
            ),
        })
    }

    fn audit(&self, name: AuditEventName) -> AuditEvent {
        AuditEvent::new(name)
            .str("backend", "isolation_session")
            .str("identity", self.identity)
            .u64("pid", 0)
    }

    fn record_exited(&self, exit_code: i32) {
        crate::mxc_common::telemetry::log_process_event(
            self.identity,
            0,
            crate::mxc_common::telemetry::ProcessEvent::Exited(exit_code),
        );
        let mut logger = self.audit_logger.lock().unwrap_or_else(|e| e.into_inner());
        logger.log_audit_event(
            &self
                .audit(AuditEventName::ProcessExited)
                .i64("exit_code", exit_code as i64),
        );
    }

    fn record_timed_out(&self, timeout_ms: u32) {
        crate::mxc_common::telemetry::log_process_event(
            self.identity,
            0,
            crate::mxc_common::telemetry::ProcessEvent::TimedOut(timeout_ms as u64),
        );
        let mut logger = self.audit_logger.lock().unwrap_or_else(|e| e.into_inner());
        logger.log_audit_event(
            &self
                .audit(AuditEventName::ProcessTimedOut)
                .u64("timeout_ms", timeout_ms as u64),
        );
    }

    fn record_kill_failed(&self, error_code: i32) {
        crate::mxc_common::telemetry::log_process_event(
            self.identity,
            0,
            crate::mxc_common::telemetry::ProcessEvent::KillFailed(
                KillMethod::TerminateProcess.as_str(),
                error_code,
            ),
        );
        let mut logger = self.audit_logger.lock().unwrap_or_else(|e| e.into_inner());
        logger.log_audit_event(
            &self
                .audit(AuditEventName::ProcessKillFailed)
                .str("kill_method", KillMethod::TerminateProcess.as_str())
                .i64("error_code", error_code as i64),
        );
    }

    /// Block until the process exits and yield its exit code, escalating
    /// through the graceful-shutdown ladder if it outlives `timeout_ms`.
    ///
    /// The *instruction sequence* is the one the relayed path runs inline, but
    /// the ladder's first two tiers are **inert for a consumer that holds
    /// duplicates of the pipe handles**:
    ///
    /// - Tier 1 closes the backend's stdin write end, but a pipe reaches EOF
    ///   only when *every* write end is closed, so tier 1 alone does not
    ///   produce EOF.
    /// - Tier 2 (`SendCtrlClose`) is ConPTY-only and returns `E_NOTIMPL`
    ///   otherwise, and a piped exec never allocates one.
    ///
    /// The ladder therefore degrades to the full 5s + 3s stall followed by
    /// tier 3's hard terminate.
    ///
    /// # Telling a timeout from an exit
    ///
    /// Reported as [`ExecOutcome::TimedOut`] when the deadline elapsed with the
    /// process still running, and [`ExecOutcome::Exited`] otherwise.
    ///
    /// **Neither available signal is sound alone**, because each is also a legal
    /// exit code: `WaitForExit` answers `-1` on timeout, and a timed-out
    /// process still reads [`STILL_ACTIVE`] (259) from `ExitCode()`. A workload
    /// is untrusted code and can return either value at will.
    ///
    /// Their *conjunction* establishes **whether the process was still running
    /// when it was sampled**, which is what the ladder decision needs. A process
    /// that exited cannot have exited with both values at once, so requiring
    /// both pins the live case:
    ///
    /// | Case | `WaitForExit` | `ExitCode()` | Verdict |
    /// |---|---|---|---|
    /// | still running | `-1` | `259` | `TimedOut` (after the ladder confirms it died) |
    /// | exited after the deadline | `-1` | `7` | `TimedOut` (already gone; no ladder) |
    /// | ambiguous | `-1` | `-1` | `Exited(-1)` |
    /// | exited `259` | `259` | `259` | `Exited(259)` |
    ///
    /// # A spent deadline is sticky
    ///
    /// The two reads are not atomic, so a process can exit in the window between
    /// them. That still reports [`ExecOutcome::TimedOut`]: the sentinel proves
    /// the deadline elapsed while the process was running, and a later-observed
    /// exit code does not un-spend it. Reporting that code instead would hide a
    /// missed deadline from a caller who asked for one.
    ///
    /// `TimedOut` promises the process is **gone**, not that this code killed
    /// it — a process that died on its own satisfies that just as a killed one
    /// does. The sibling WSLc backend draws the same line, tracking
    /// `deadline_elapsed` separately from `timed_out` so a spent deadline is
    /// reported "stickily rather than a later-observed exit code", and treating
    /// an already-confirmed exit as satisfying its termination check.
    ///
    /// The one irreducible case is `-1`/`-1`, where the sentinel and the exit
    /// code collide: nothing distinguishes a timeout from a workload that
    /// exited with `-1`, so it is read as the exit.
    ///
    /// # How far "gone" reaches here
    ///
    /// Both timeout paths confirm **the foreground process only**, because that
    /// is the only thing this API exposes: `IsoSessionProcess` has `Terminate`
    /// and `ExitCode` for the process it represents and no tree primitive. A
    /// descendant the workload backgrounded can therefore outlive a reported
    /// timeout on either path — the live one, which checks `ExitCode()` after
    /// the ladder, and the late-exit one, which has nothing left to terminate.
    ///
    /// That is not a gap this layer can close: descendants live in the isolation
    /// session's own user context and are reclaimed when the session is stopped
    /// and deprovisioned. Stated rather than implied, because
    /// [`ExecOutcome::TimedOut`] leaves the reach to the backend and the SDK's
    /// `WaitOutcome::TimedOut` describes process-tree backends where the kill
    /// does cover the tree.
    ///
    /// A zero `timeout_ms` short-circuits the whole test: it means INFINITE, and
    /// a wait with no deadline cannot have missed one. This is the default, so
    /// without the guard the common configuration would be the one at risk.
    ///
    /// # Why the ladder does not run for an exit
    ///
    /// The ladder exists to kill a **survivor**. Running it for a process that
    /// already exited reintroduces the very ambiguity this function avoids: its
    /// first `ExitCode()` reads 259 for a workload that exited with 259, so it
    /// walks all three tiers and cannot then tell that exit from a live
    /// process. An exited process therefore returns its code directly.
    ///
    /// `before_shutdown` stops caller-owned input copying after a timeout.
    /// Returning false skips the stdin-close grace period.
    pub(super) fn wait(
        &self,
        timeout_ms: u32,
        before_shutdown: impl FnOnce() -> Result<bool, IsolationSessionError>,
    ) -> Result<ExecOutcome, IsolationSessionError> {
        // `WaitForExit` is a Win32 `WaitForSingleObject` on a kernel handle —
        // no COM round-trip. On timeout it returns -1; the ladder below then
        // decides what to do about a process that is still running.
        let waited = self
            .process
            .WaitForExit(timeout_ms)
            .map_err(|e| transport_err(op::RUN_PROCESS, "WaitForExit failed", &e))?;

        // Sampled before the ladder, which kills a survivor and so destroys the
        // evidence. `?`-propagated for the same reason the ladder propagates its
        // first query: a failure here means the kernel handle is broken, and
        // guessing "it exited" would report a fabricated outcome.
        let plan = plan_wait(timeout_ms, waited, || {
            self.process
                .ExitCode()
                .map_err(|e| transport_err(op::RUN_PROCESS, "get ExitCode failed", &e))
        })?;

        match plan {
            // An exited process must skip shutdown: the ladder cannot
            // distinguish a real exit code of 259 from STILL_ACTIVE.
            WaitPlan::Exited(exit_code) => {
                self.record_exited(exit_code);
                return Ok(ExecOutcome::Exited(exit_code));
            }
            // The deadline was spent, but the process is already gone.
            // Nothing needs killing; retain the timeout result.
            WaitPlan::TimedOutAfterDeadline => {
                self.record_timed_out(timeout_ms);
                return Ok(ExecOutcome::TimedOut);
            }
            WaitPlan::KillThenReportTimeout => {}
        }

        self.record_timed_out(timeout_ms);
        let stdin_released = before_shutdown()?;
        let (_, terminate_error) = wait_with_graceful_shutdown(self, stdin_released)?;
        if let Some(error_code) = terminate_error {
            self.record_kill_failed(error_code);
        }
        let after = self
            .process
            .ExitCode()
            .map_err(|e| transport_err(op::RUN_PROCESS, "get ExitCode failed", &e))?;
        if after == STILL_ACTIVE {
            // A 259 exit during shutdown remains ambiguous: conservatively
            // report failure rather than claiming the process was killed.
            return Err(lifecycle_err(
                "the sandboxed process was still running after timeout shutdown; \
                 it timed out but could not be confirmed killed",
            ));
        }
        Ok(ExecOutcome::TimedOut)
    }

    /// Kill the process now, reporting whether the kill request was *accepted*.
    ///
    /// Deliberately **not** the graceful ladder [`Self::wait`] uses. That ladder
    /// gives a well-behaved child up to eight seconds to notice a closed stdin
    /// or a Ctrl-Close, which is right for a shutdown and wrong for a caller who
    /// asked to terminate: `SandboxProcess::kill` promises to kill, and a
    /// cancellation path that takes eight seconds to act reads as a hang.
    ///
    /// The post-kill wait is **bounded**. `WaitForExit(0)` means INFINITE here,
    /// so waiting on the assumption that `Terminate` succeeded would wedge this
    /// call forever if it ever failed against a live process.
    ///
    /// That bound covers *this call only*. A caller that also owns a waiter must
    /// not infer completion from `Ok(())` and unconditionally join it. The PTY
    /// streaming adapter joins only an already-finished waiter during drop and
    /// otherwise detaches it, keeping handle destruction bounded.
    ///
    /// **What this does not tell you.** The bounded wait's result is discarded,
    /// so a `Terminate` the platform accepted but that left the process running
    /// still yields `Ok(())`. What *is* now reported is the distinction between
    /// an accepted request and a refused one: the `Err` this returns reaches the
    /// caller through `ExecHandle::terminator` and `SandboxProcess::kill`.
    /// Confirming the process actually died would need the bounded wait's result
    /// as well, which this type does not carry.
    pub(super) fn terminate(&self) -> Result<(), IsolationSessionError> {
        if let Err(error) = self.process.Terminate() {
            self.record_kill_failed(error.code().0);
            return Err(transport_err(op::RUN_PROCESS, "Terminate failed", &error));
        }
        // Bounded rather than INFINITE so a `Terminate` that was accepted but
        // never took effect cannot park the caller inside this function. The
        // result is discarded because there is nowhere to report it; see the
        // note above, which also covers why this does not bound teardown.
        let _ = self.process.WaitForExit(TERMINATE_WAIT_MS);
        Ok(())
    }

    /// Force-terminate and confirm within a bounded wait that the process is gone.
    ///
    /// Setup-failure paths cannot return a public process handle, so unlike
    /// [`Self::terminate`] they must not report success merely because the
    /// terminate request was accepted.
    fn terminate_and_confirm(&self) -> Result<(), IsolationSessionError> {
        let termination_error = self.process.Terminate().err();
        if let Some(error) = &termination_error {
            self.record_kill_failed(error.code().0);
        }
        let waited = self
            .process
            .WaitForExit(TERMINATE_WAIT_MS)
            .map_err(|error| transport_err(op::RUN_PROCESS, "WaitForExit failed", &error))?;
        let exit_code =
            if waited == WAIT_FOR_EXIT_TIMEOUT {
                Some(self.process.ExitCode().map_err(|error| {
                    transport_err(op::RUN_PROCESS, "get ExitCode failed", &error)
                })?)
            } else {
                None
            };
        if termination_is_confirmed(waited, exit_code) {
            return Ok(());
        }
        if let Some(error) = termination_error {
            return Err(transport_err(op::RUN_PROCESS, "Terminate failed", &error));
        }
        Err(lifecycle_err(
            "the sandboxed process was still running after the bounded terminate wait",
        ))
    }
}

/// A [`StartedProcess`] that releases the session process's pipe handles when
/// it goes out of scope.
///
/// Close-on-drop is **opt-in per consumer** rather than a property of
/// [`StartedProcess`] itself, because the two topologies need opposite things:
///
/// - The streaming consumer has no other teardown point — it hands the handles
///   to an in-process caller and never returns to this crate — so without this
///   a long-lived host would leak three handles per exec, and that host is
///   exactly who the streaming path exists for.
/// - [`IsolationSessionManager::create_process`](super::manager::IsolationSessionManager::create_process) must **not** close on the way
///   out: `RelayScope` owns that teardown and runs it once the relays are done.
pub(super) struct ClosingProcess {
    started: StartedProcess,
    /// The impersonation of the manager that started the process.
    impersonation: Impersonation,
    /// Keeps the apartment alive: the threads that use the object may have none.
    _mta: MtaReference,
}

impl ClosingProcess {
    pub(super) fn new(
        started: StartedProcess,
        impersonation: Impersonation,
        mta: MtaReference,
    ) -> Self {
        Self {
            started,
            impersonation,
            _mta: mta,
        }
    }

    pub(super) fn resize_console(
        &self,
        columns: u16,
        rows: u16,
    ) -> Result<(), IsolationSessionError> {
        owned_thread::call(&self.impersonation, || {
            self.process
                .ResizeConsole(columns, rows)
                .map_err(|error| lifecycle_err(format!("ResizeConsole failed: {error}")))
        })
    }

    pub(super) fn close_standard_input(&self) -> Result<(), IsolationSessionError> {
        owned_thread::call(&self.impersonation, || {
            self.process
                .CloseStandardInput()
                .map_err(|error| lifecycle_err(format!("CloseStandardInput failed: {error}")))
        })
    }

    pub(super) fn wait_for_exit(
        &self,
        timeout_ms: u32,
    ) -> Result<ExecOutcome, IsolationSessionError> {
        owned_thread::call(&self.impersonation, || self.wait(timeout_ms, || Ok(true)))
    }

    pub(super) fn terminate_process(&self) -> Result<(), IsolationSessionError> {
        owned_thread::call(&self.impersonation, || self.terminate())
    }

    pub(super) fn terminate_and_confirm_process(&self) -> Result<(), IsolationSessionError> {
        owned_thread::call(&self.impersonation, || self.terminate_and_confirm())
    }
}

impl std::ops::Deref for ClosingProcess {
    type Target = StartedProcess;

    fn deref(&self) -> &Self::Target {
        &self.started
    }
}

impl Drop for ClosingProcess {
    fn drop(&mut self) {
        let process = &self.started.process;
        let _ = owned_thread::call(&self.impersonation, || {
            let _ = process.Close();
            Ok(())
        });
    }
}

/// `STILL_ACTIVE` (0x103) is exposed by the `windows` crate as
/// `STATUS_PENDING: NTSTATUS` — same numeric value, different name. A process
/// whose `ExitCode()` reads this has not exited.
///
/// **Not sufficient on its own to prove a process is running.** 259 is a legal
/// exit code, so a workload that exits with it is indistinguishable here from
/// one that never exited. Every liveness decision in this file therefore pairs
/// this with a second, independent signal; see [`StartedProcess::wait`].
const STILL_ACTIVE: i32 = windows::Win32::Foundation::STATUS_PENDING.0;

/// What `WaitForExit` returns when the deadline elapses before the process
/// exits. Like [`STILL_ACTIVE`] this is a legal exit code in its own right, so
/// it is never used alone to conclude a timeout.
pub(super) const WAIT_FOR_EXIT_TIMEOUT: i32 = -1;

/// How long [`StartedProcess::terminate`] waits for a kill to land before
/// reporting success anyway. Bounded so a failed `Terminate` cannot wedge that
/// call; generous enough that a normal kill is observed synchronously.
const TERMINATE_WAIT_MS: u32 = 5_000;

fn termination_is_confirmed(waited: i32, exit_code: Option<i32>) -> bool {
    waited != WAIT_FOR_EXIT_TIMEOUT || exit_code.is_some_and(|code| code != STILL_ACTIVE)
}

/// What [`StartedProcess::wait`] should do once its wait has returned.
///
/// A value rather than a branch inside `wait`, because `wait` needs a live COM
/// process object and cannot be exercised on a host without the OS-side
/// service — so the decision it hinges on would otherwise be untestable, and a
/// regression in it silently undetectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WaitPlan {
    /// The process exited within its deadline, or there was no deadline. This
    /// is its exit code. **The shutdown ladder must not run** — it cannot
    /// distinguish a 259 exit from a live process.
    Exited(i32),
    /// The deadline elapsed and the process is **still running**. It must be
    /// killed and confirmed dead before a timeout is reported.
    KillThenReportTimeout,
    /// The deadline elapsed, and the process then exited on its own before it
    /// could be sampled. There is nothing left to kill — the exit-code read is
    /// itself the confirmation the process is gone — but the outcome is still a
    /// timeout, because the caller's deadline was spent while it ran.
    ///
    /// Reporting the later-observed exit code here instead would hide a missed
    /// deadline. The sibling WSLc backend makes the same distinction, tracking
    /// `deadline_elapsed` separately from `timed_out` so a spent deadline is
    /// "reported stickily rather than a later-observed exit code".
    TimedOutAfterDeadline,
}

/// Decides what a completed `WaitForExit` means.
///
/// Split out from [`StartedProcess::wait`] so the rule is exercisable without an
/// OS-side isolation session: every input here is a plain integer, while the
/// call it guards needs a live process object.
///
/// `exit_code` is a closure rather than a value so the ordinary case costs no
/// extra COM round-trip — it is consulted only for the one `waited` value that
/// could mean a timeout. See [`StartedProcess::wait`] for why one signal alone
/// is not enough.
fn plan_wait(
    timeout_ms: u32,
    waited: i32,
    exit_code: impl FnOnce() -> Result<i32, IsolationSessionError>,
) -> Result<WaitPlan, IsolationSessionError> {
    // INFINITE: there was no deadline to miss, so the wait returned because the
    // process exited, and `waited` is its code.
    if timeout_ms == 0 || waited != WAIT_FOR_EXIT_TIMEOUT {
        return Ok(WaitPlan::Exited(waited));
    }
    // The sentinel alone proves nothing — a workload may exit with -1 — so the
    // exit code is the second, independent signal.
    let code = exit_code()?;
    match code {
        // Still running: the deadline is spent and the process must be killed.
        STILL_ACTIVE => Ok(WaitPlan::KillThenReportTimeout),
        // Genuinely ambiguous, and the one case that cannot be resolved: the
        // wait returned -1 and the process's code *is* -1, so the sentinel is
        // indistinguishable from a natural exit. Read as the exit.
        WAIT_FOR_EXIT_TIMEOUT => Ok(WaitPlan::Exited(WAIT_FOR_EXIT_TIMEOUT)),
        // The process is gone, and its code is not -1 — so the -1 the wait
        // returned cannot have been that code, and was therefore the timeout
        // sentinel. The deadline provably elapsed while the process ran, and it
        // exited in the window before this sample.
        _ => Ok(WaitPlan::TimedOutAfterDeadline),
    }
}

/// Three-tier graceful shutdown for an `IsoSessionProcess` that's still
/// running after `WaitForExit(timeout_ms)` returns. Tier 1 asks the platform
/// to close stdin, tier 2 tries `SendCtrlClose` (ConPTY-only; `E_NOTIMPL`
/// outside ConPTY is benign), and tier 3 force-terminates, then waits
/// infinitely (`WaitForExit(0)` = INFINITE) for the kill to land.
/// Tier 1 is skipped if the caller's stdin relay has not exited.
///
/// The first `ExitCode()` query is `?`-propagated: a failure there means
/// the kernel handle is broken, and the cleanup methods on the same
/// handle are unlikely to make progress — better to surface the COM error
/// than to fire blind. Per-tier subsequent queries fall back to
/// `STILL_ACTIVE` so a transient read failure does not short-circuit the
/// escalation.
///
/// # What this does not tell you
///
/// The returned code cannot distinguish a process that exited with 259 from
/// one that is still running, because `ExitCode()` reports 259 for both. A
/// caller that needs that distinction must establish it separately —
/// [`StartedProcess::wait`] does, which is why it only calls this once it has
/// independently determined the process was still running.
fn wait_with_graceful_shutdown(
    started: &StartedProcess,
    stdin_released: bool,
) -> Result<(i32, Option<i32>), IsolationSessionError> {
    let process = &started.process;
    let mut exit_code = process
        .ExitCode()
        .map_err(|e| transport_err(op::RUN_PROCESS, "get ExitCode failed", &e))?;
    if exit_code != STILL_ACTIVE {
        return Ok((exit_code, None));
    }

    // A live relay can still hold a writer, so closing platform stdin alone
    // cannot deliver EOF. Skip that grace period if the relay did not stop.
    if stdin_released {
        {
            let _close = started
                .close_lock
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let _ = process.CloseStandardInput();
        }
        let _ = process.WaitForExit(5000);
        exit_code = process.ExitCode().unwrap_or(STILL_ACTIVE);
        if exit_code != STILL_ACTIVE {
            return Ok((exit_code, None));
        }
    }

    let _ = process.SendCtrlClose();
    let _ = process.WaitForExit(3000);
    exit_code = process.ExitCode().unwrap_or(STILL_ACTIVE);
    if exit_code != STILL_ACTIVE {
        return Ok((exit_code, None));
    }

    let terminate_error = process.Terminate().err().map(|error| error.code().0);
    let _ = process.WaitForExit(0);
    // Unchanged from before the exec-handle reshape: this path serves the
    // executor, which needs an exit code and has no timeout channel. Failing
    // here on a 259 read would turn a workload that legitimately exited with
    // 259 into a backend error on the CLI.
    Ok((process.ExitCode().unwrap_or(-1), terminate_error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_termination_requires_confirmation_after_a_timeout_sentinel() {
        assert!(termination_is_confirmed(0, None));
        assert!(termination_is_confirmed(
            WAIT_FOR_EXIT_TIMEOUT,
            Some(WAIT_FOR_EXIT_TIMEOUT)
        ));
        assert!(!termination_is_confirmed(
            WAIT_FOR_EXIT_TIMEOUT,
            Some(STILL_ACTIVE)
        ));
    }

    /// The exit code a timed-out process reads, paired with the `WaitForExit`
    /// return that accompanies it.
    fn probe(value: i32) -> impl FnOnce() -> Result<i32, IsolationSessionError> {
        move || Ok(value)
    }

    #[test]
    fn timeout_needs_both_signals_not_either() {
        // The real timeout: both signals present, and the ladder must run.
        assert_eq!(
            plan_wait(5_000, WAIT_FOR_EXIT_TIMEOUT, probe(STILL_ACTIVE)).unwrap(),
            WaitPlan::KillThenReportTimeout
        );

        // A workload that exits with the wait sentinel's value. `WaitForExit`
        // reports the code rather than -1, so this is an exit.
        assert_eq!(
            plan_wait(5_000, -1, probe(-1)).unwrap(),
            WaitPlan::Exited(-1)
        );

        // A workload that exits 259 — the value `STILL_ACTIVE` also has. The
        // wait returned the code, not the sentinel, so this is an exit too.
        // Critically it must NOT be planned for the ladder: the ladder reads
        // 259 from `ExitCode()` and cannot tell it from a live process, which
        // is how a clean exit-259 became a backend error.
        assert_eq!(
            plan_wait(5_000, STILL_ACTIVE, probe(STILL_ACTIVE)).unwrap(),
            WaitPlan::Exited(STILL_ACTIVE)
        );

        // An ordinary exit.
        assert_eq!(plan_wait(5_000, 0, probe(0)).unwrap(), WaitPlan::Exited(0));
    }

    /// The sentinel with a non-`STILL_ACTIVE`, non-`-1` code means the deadline
    /// was spent and the process then exited on its own.
    ///
    /// The regression this pins: reporting that later-observed exit code hides
    /// a missed deadline. The `-1` the wait returned cannot have been the
    /// process's code (its code is 7), so it was the timeout sentinel and the
    /// deadline provably elapsed while the process ran.
    #[test]
    fn a_deadline_spent_before_a_late_exit_is_still_a_timeout() {
        assert_eq!(
            plan_wait(5_000, WAIT_FOR_EXIT_TIMEOUT, probe(7)).unwrap(),
            WaitPlan::TimedOutAfterDeadline
        );
        assert_eq!(
            plan_wait(5_000, WAIT_FOR_EXIT_TIMEOUT, probe(0)).unwrap(),
            WaitPlan::TimedOutAfterDeadline,
            "a clean exit past the deadline is still a missed deadline"
        );
    }

    /// The one irreducible collision: sentinel and exit code are both `-1`, so
    /// nothing distinguishes a timeout from a workload that exited with `-1`.
    #[test]
    fn the_sentinel_colliding_with_a_real_minus_one_exit_is_read_as_the_exit() {
        assert_eq!(
            plan_wait(5_000, WAIT_FOR_EXIT_TIMEOUT, probe(-1)).unwrap(),
            WaitPlan::Exited(-1)
        );
    }

    #[test]
    fn infinite_timeout_can_never_be_a_timeout() {
        // 0 means INFINITE. Even with the sentinel apparently present, a wait
        // with no deadline did not miss one. This is the default, so the guard
        // covers the common configuration rather than an exotic one.
        assert_eq!(
            plan_wait(0, WAIT_FOR_EXIT_TIMEOUT, probe(STILL_ACTIVE)).unwrap(),
            WaitPlan::Exited(WAIT_FOR_EXIT_TIMEOUT)
        );
    }

    #[test]
    fn exit_code_is_not_queried_unless_it_could_change_the_answer() {
        let calls = std::cell::Cell::new(0);
        let counting = || {
            calls.set(calls.get() + 1);
            Ok(STILL_ACTIVE)
        };
        assert_eq!(plan_wait(5_000, 0, counting).unwrap(), WaitPlan::Exited(0));
        assert_eq!(calls.get(), 0, "no COM round-trip for a plain exit");
    }

    #[test]
    fn unreadable_exit_code_propagates_rather_than_guessing() {
        let err = plan_wait(5_000, WAIT_FOR_EXIT_TIMEOUT, || {
            Err(lifecycle_err("handle is broken"))
        });
        assert!(
            err.is_err(),
            "a failed probe must not be reported as an exit"
        );
    }
}
