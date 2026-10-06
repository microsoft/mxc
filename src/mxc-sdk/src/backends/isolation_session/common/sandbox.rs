// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Streaming (`SandboxBackend`) surface for one-shot isolation sessions.
//!
//! `one_shot`'s `ScriptRunner` runs the whole lifecycle inline and relays the
//! workload onto this process's stdio. This module serves the *library* shape
//! instead: it runs the same provision → start prologue, hands the caller live
//! pipes, and reclaims the session once the exec reaches a terminal state.
//!
//! A one-shot session exists for exactly one exec, so the returned handle owns
//! it: a completed wait, a kill, or a drop stops the session and removes the
//! agent user, exactly once. That account is a real OS account, so a missed
//! teardown leaves something behind that a later run cannot clean up.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::os::windows::io::{BorrowedHandle, IntoRawHandle, RawHandle};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::process_util::{
    InterruptiblePipeReader, OwnedHandle as ProcessOwnedHandle, PipeReadCanceller,
};
use crate::mxc_common::sandbox_process::{
    NativeStdio, OwnedPipe, PtySize, SandboxBackend, SandboxProcess, StdioMode, StreamCloser,
};
use crate::mxc_common::script_runner::ScriptRunner;
use crate::mxc_common::state_aware_backend::ExecOutcome;
use crate::mxc_common::validator::validate_common;

use super::error::{lifecycle_err, IsolationSessionError};
use super::manager::{
    log_sandbox_torn_down, ClosingProcess, IsolationSessionManager, TeardownOutcome,
};
use super::process_options::{
    build_process_options, build_pty_process_options, with_service_timeout_grace,
};
use super::IsolationSessionRunner;
use windows::Win32::Foundation::HANDLE;

/// Why a one-shot launch failed, with the two classes kept apart so a caller
/// maps each without parsing prose.
pub enum OneShotSpawnFailure {
    /// Refused before any API call, so it carries no API detail.
    Refused(ScriptResponse),
    /// The lifecycle failed, carrying the failing call and its status.
    Launch(MxcError),
}

/// Provision, start and hand back a one-shot exec's live pipes, preserving the
/// backend's typed failure.
///
/// [`SandboxBackend::spawn`] flattens a launch failure into a `ScriptResponse`,
/// which has nowhere to carry the failing API call, its status or its
/// remediation. This is the same sequence with those kept, so an in-process
/// caller is told as much as the state-aware surface tells it.
pub fn spawn_one_shot(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<Box<dyn SandboxProcess>, OneShotSpawnFailure> {
    let runner = IsolationSessionRunner::new();
    validate_common(request).map_err(OneShotSpawnFailure::Refused)?;
    SandboxBackend::validate(&runner, request).map_err(OneShotSpawnFailure::Refused)?;
    spawn_piped(request, logger)
        .map_err(|e| OneShotSpawnFailure::Launch(super::error::map_lifecycle_error(e)))
}

/// The refusal for [`StdioMode::Inherit`].
///
/// Serving it would mean splitting the relay path — which blocks until the
/// workload exits, and whose relay scope borrows the process — into a
/// non-blocking start with detached relays.
fn inherit_not_served() -> ScriptResponse {
    ScriptResponse {
        failure_phase: FailurePhase::Rejected,
        ..ScriptResponse::error(
            "the isolation session backend does not yet support inherited stdio; it serves piped \
             stdio, which is what an in-process caller receives. Run it through wxc-exec to have \
             the workload relayed onto this process's own stdio.",
        )
    }
}

impl SandboxBackend for IsolationSessionRunner {
    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        // One-shot runs the whole lifecycle, so provision-phase rules apply to
        // the whole call — the same check the run-to-completion path makes.
        //
        // Everything it refuses is a caller-fixable request problem, and the
        // phase is what the dispatcher reads back to classify it.
        ScriptRunner::validate_runner(self, request).map_err(|resp| ScriptResponse {
            failure_phase: FailurePhase::Rejected,
            ..resp
        })
    }

    /// Provision, start, and hand back the exec's live pipes.
    ///
    /// Validation runs before anything is provisioned. A failure after
    /// `add_user` would strand an OS account, so the ordering is load-bearing
    /// rather than stylistic.
    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        match stdio {
            StdioMode::Inherit => Err(inherit_not_served()),
            StdioMode::Pty(size) => {
                spawn_one_shot_pty(request, logger, size).map_err(|error| match error {
                    OneShotSpawnFailure::Refused(response) => response,
                    OneShotSpawnFailure::Launch(error) => ScriptResponse {
                        failure_phase: FailurePhase::LaunchFailed,
                        ..ScriptResponse::error(&error.message)
                    },
                })
            }
            // Delegated so both entry points share one validation prologue.
            StdioMode::Pipes => spawn_one_shot(request, logger).map_err(|e| match e {
                OneShotSpawnFailure::Refused(resp) => resp,
                OneShotSpawnFailure::Launch(err) => ScriptResponse {
                    failure_phase: FailurePhase::LaunchFailed,
                    ..ScriptResponse::error(&err.message)
                },
            }),
        }
    }
}

pub fn spawn_one_shot_pty(
    request: &ExecutionRequest,
    logger: &mut Logger,
    size: PtySize,
) -> Result<Box<dyn SandboxProcess>, OneShotSpawnFailure> {
    validate_common(request).map_err(OneShotSpawnFailure::Refused)?;
    ScriptRunner::validate_runner(&IsolationSessionRunner::new(), request)
        .map_err(OneShotSpawnFailure::Refused)?;

    let (_provisioned, manager) = IsolationSessionManager::add_user(None)
        .map_err(super::error::map_lifecycle_error)
        .map_err(OneShotSpawnFailure::Launch)?;
    let _ = writeln!(logger, "Isolation Session: agent user provisioned");
    let mut session = OwnedSession::new(manager);
    if let Err(error) = session.manager.start_session() {
        session.reclaim("start");
        return Err(OneShotSpawnFailure::Launch(
            super::error::map_lifecycle_error(with_cleanup_failures(error, &session.warnings)),
        ));
    }

    let (process, waiter) = match start_pty_process(
        &session.manager,
        request,
        size,
        PtySetupFailureCleanup::ReclaimSession,
    ) {
        Ok(started) => started,
        Err(mut error) => {
            session.reclaim("exec");
            if !session.warnings.is_empty() {
                error
                    .message
                    .push_str(&format!(" (cleanup: {})", session.warnings.join("; ")));
            }
            return Err(OneShotSpawnFailure::Launch(error));
        }
    };

    Ok(Box::new(IsolationPtyProcess {
        session: Some(session),
        process,
        waiter: Some(waiter),
        outcome: None,
        writer_taken: Mutex::new(false),
        size: Mutex::new(size),
        timed_out: false,
    }))
}

pub(super) fn spawn_existing_session_pty(
    manager: IsolationSessionManager,
    request: &ExecutionRequest,
    size: PtySize,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    let (process, waiter) = start_pty_process(
        &manager,
        request,
        size,
        PtySetupFailureCleanup::ConfirmTermination,
    )?;
    Ok(Box::new(IsolationPtyProcess {
        session: None,
        process,
        waiter: Some(waiter),
        outcome: None,
        writer_taken: Mutex::new(false),
        size: Mutex::new(size),
        timed_out: false,
    }))
}

type PtyProcessWaiter = JoinHandle<Result<ExecOutcome, MxcError>>;
type StartedPtyProcess = (Arc<ClosingProcess>, PtyProcessWaiter);

#[derive(Clone, Copy)]
enum PtySetupFailureCleanup {
    ReclaimSession,
    ConfirmTermination,
}

fn start_pty_process(
    manager: &IsolationSessionManager,
    request: &ExecutionRequest,
    size: PtySize,
    cleanup: PtySetupFailureCleanup,
) -> Result<StartedPtyProcess, MxcError> {
    let options = build_pty_process_options(request);
    let timeout_ms = options.timeout_ms;
    let options = with_service_timeout_grace(options);
    let process = manager
        .pty_process(&options, None)
        .map_err(super::error::map_lifecycle_error)?;
    if let Err(error) = process.resize_console(size.cols, size.rows) {
        return Err(with_pty_setup_cleanup(
            super::error::map_lifecycle_error(error),
            &process,
            cleanup,
        ));
    }
    if let Err(error) = release_pty_start_gate(&process) {
        return Err(with_pty_setup_cleanup(error, &process, cleanup));
    }

    let waiter_process = Arc::clone(&process);
    let waiter = std::thread::Builder::new()
        .name("mxc-isolation-pty-waiter".to_string())
        .spawn(move || {
            waiter_process
                .wait_for_exit(timeout_ms)
                .map_err(super::error::map_lifecycle_error)
        })
        .map_err(|error| {
            with_pty_setup_cleanup(
                MxcError::backend_error(format!(
                    "failed to start the IsolationSession PTY waiter: {error}"
                )),
                &process,
                cleanup,
            )
        })?;
    Ok((process, waiter))
}

fn release_pty_start_gate(process: &ClosingProcess) -> Result<(), MxcError> {
    let input = IsolationPtyProcess::duplicate_pipe(process.stdin, "input")
        .map_err(|error| MxcError::backend_error(error.to_string()))?;
    let mut input = std::fs::File::from(input);
    input
        .write_all(b"\r\n")
        .and_then(|()| input.flush())
        .map_err(|error| {
            MxcError::backend_error(format!(
                "failed to release the IsolationSession PTY start gate: {error}"
            ))
        })
}

fn with_pty_setup_cleanup(
    mut error: MxcError,
    process: &ClosingProcess,
    cleanup: PtySetupFailureCleanup,
) -> MxcError {
    if matches!(cleanup, PtySetupFailureCleanup::ConfirmTermination) {
        if let Err(cleanup_error) = process.terminate_and_confirm_process() {
            error.message.push_str(&format!(
                " (cleanup: failed to confirm the started PTY workload stopped: \
                 {cleanup_error})"
            ));
        }
    }
    error
}

fn spawn_piped(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<Box<dyn SandboxProcess>, IsolationSessionError> {
    // Never interactive: a pseudo-console has a single output stream, so
    // allocating one would merge stderr into stdout and destroy the separate
    // streams the caller asked for. The host's own stdio says nothing about a
    // sandbox whose streams the caller drives, so it is not consulted.
    let options = build_process_options(request, false);
    let timeout_ms = options.timeout_ms;
    let options = with_service_timeout_grace(options);

    // The manager comes from `add_user` rather than a separate `new()` — see
    // its doc for why a second activation can strand the account it just minted.
    let (_provisioned, manager) = IsolationSessionManager::add_user(None)?;
    let _ = writeln!(logger, "Isolation Session: agent user provisioned");

    // From here the account exists, so every failure reclaims it rather than
    // abandoning it.
    let mut session = OwnedSession::new(manager);

    if let Err(e) = session.manager.start_session() {
        session.reclaim("start");
        return Err(with_cleanup_failures(e, &session.warnings));
    }

    // `None` is not "no audit logger": it inherits the calling thread's
    // diagnostic sink, which is what the teardown record below also uses.
    let handle = match session
        .manager
        .piped_exec_handle(&options, timeout_ms, None)
    {
        Ok(handle) => handle,
        Err(e) => {
            session.reclaim("exec");
            return Err(with_cleanup_failures(e, &session.warnings));
        }
    };

    let inner = match crate::mxc_common::exec_stream::ExecSandboxProcess::from_exec_handle(handle) {
        Ok(inner) => inner,
        Err(e) => {
            session.reclaim("adapter");
            return Err(with_cleanup_failures(
                lifecycle_err(e.message),
                &session.warnings,
            ));
        }
    };

    Ok(Box::new(OneShotSandboxProcess { session, inner }))
}

/// Folds a failed cleanup into the launch error.
///
/// A launch failure tears the session down on the way out, and that teardown can
/// fail too — leaving a real OS account behind. The session owner is a local on
/// those paths, so its warnings go nowhere; the returned error is the only
/// channel that survives.
///
/// Takes the warnings rather than the session so the fold is a pure function
/// over what it actually reads, and can be exercised without a live host.
fn with_cleanup_failures(err: IsolationSessionError, warnings: &[String]) -> IsolationSessionError {
    if warnings.is_empty() {
        return err;
    }
    err.with_context(&format!(" (cleanup: {})", warnings.join("; ")))
}

/// A provisioned session, and the one place that gives it back.
struct OwnedSession {
    manager: IsolationSessionManager,
    /// `Some` once the account is gone, which is also what disarms the retry.
    outcome: Option<TeardownOutcome>,
    /// Set once the session has been stopped, so the retry that the account
    /// failure arms does not stop it a second time.
    stopped: bool,
    /// The stop's own failure, kept so `kill` can name the cause instead of
    /// reporting that something unspecified went wrong.
    stop_error: Option<String>,
    /// Teardown failures, surfaced through [`SandboxProcess::warnings`]. The
    /// spawn has already returned by the time these happen, so this is the
    /// channel that still reaches the caller.
    warnings: Vec<String>,
}

impl OwnedSession {
    fn new(manager: IsolationSessionManager) -> Self {
        Self {
            manager,
            outcome: None,
            stopped: false,
            stop_error: None,
            warnings: Vec::new(),
        }
    }

    /// Stop the session and remove the agent user, at most once, and report
    /// both steps.
    ///
    /// The result is retained from the deprovision's own outcome, not from
    /// having tried: the OS account is what leaks, so a failure must leave this
    /// armed for the next terminal path — or for `Drop` — to retry.
    fn reclaim(&mut self, phase: &str) -> TeardownOutcome {
        if let Some(outcome) = self.outcome {
            return outcome;
        }
        let stopped = if self.stopped {
            Ok(())
        } else {
            self.manager.stop_session()
        };
        let deprovisioned = self.manager.deprovision_agent_user();
        if let Err(e) = &stopped {
            self.warnings
                .push(format!("the isolation session could not be stopped: {e}"));
            self.stop_error = Some(e.to_string());
        } else {
            self.stopped = true;
        }
        if let Err(e) = &deprovisioned {
            self.warnings.push(format!(
                "the isolation session's agent user could not be removed, so the account \
                 may remain on this host: {e}"
            ));
        }
        let outcome = TeardownOutcome {
            session_stopped: Some(stopped.is_ok()),
            agent_user_deprovisioned: Some(deprovisioned.is_ok()),
        };
        if deprovisioned.is_ok() {
            self.outcome = Some(outcome);
        }
        log_sandbox_torn_down(
            &mut Logger::inherit_thread_diagnostic_sink(),
            phase,
            outcome,
        );
        outcome
    }
}

impl Drop for OwnedSession {
    fn drop(&mut self) {
        self.reclaim("drop");
    }
}

/// A one-shot exec: the session, and the caller's streams onto it.
///
/// `session` is declared first so it is reclaimed before `inner` even if the
/// `Drop` below is ever removed. `inner`'s own teardown can wait on the
/// workload, and stopping the session is what ends it.
struct OneShotSandboxProcess {
    session: OwnedSession,
    inner: crate::mxc_common::exec_stream::ExecSandboxProcess,
}

impl OneShotSandboxProcess {
    fn terminate_and_reclaim(&mut self, timed_out: bool) -> std::io::Result<()> {
        let termination = if timed_out {
            self.inner.kill_for_timeout()
        } else {
            self.inner.kill()
        };
        if let Err(error) = termination {
            self.session
                .warnings
                .push(format!("terminating the workload was refused: {error}"));
        }

        let outcome = self.session.reclaim("kill");
        if outcome.session_stopped == Some(true) {
            return Ok(());
        }
        let mut message = "the isolation session could not be stopped, so the sandboxed process \
                           may still be running"
            .to_string();
        if let Some(cause) = &self.session.stop_error {
            message.push_str(": ");
            message.push_str(cause);
        }
        Err(std::io::Error::other(message))
    }
}

impl SandboxProcess for OneShotSandboxProcess {
    /// Teardown failures, which happen after the spawn returned and so have no
    /// other route to the caller.
    fn warnings(&self) -> Vec<String> {
        self.session.warnings.clone()
    }

    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        self.inner.take_stdin()
    }

    fn stdin_closer(&self) -> Option<Box<dyn StreamCloser>> {
        self.inner.stdin_closer()
    }

    fn take_native_stdio(
        &mut self,
    ) -> std::io::Result<Option<crate::mxc_common::sandbox_process::NativeStdio>> {
        self.inner.take_native_stdio()
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        self.inner.take_stdout()
    }

    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        self.inner.take_stderr()
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        self.inner.stdout_closer()
    }

    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        self.inner.stderr_closer()
    }

    /// Deliberately does **not** reclaim the session: a caller polling for an
    /// exit has not said it is finished with the handle. `Drop` covers the
    /// caller that only ever polls.
    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        self.inner.try_wait()
    }

    fn id(&self) -> u32 {
        self.inner.id()
    }

    /// Terminate the workload, then reclaim the session.
    ///
    /// Terminating reports only that the platform accepted the request, so the
    /// stop is what makes the workload's death observable — and it is what this
    /// reports. A caller that gets `Ok` knows nothing is left running.
    fn kill(&mut self) -> std::io::Result<()> {
        self.terminate_and_reclaim(false)
    }

    fn kill_for_timeout(&mut self) -> std::io::Result<()> {
        self.terminate_and_reclaim(true)
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        let outcome = self.inner.wait();
        self.session.reclaim("wait");
        outcome
    }
}

impl Drop for OneShotSandboxProcess {
    /// Reclaims the session, redundantly with the field order above.
    ///
    /// Fields drop in declaration order, so `session` already reclaims before
    /// `inner`. This states the same intent where a reader of the teardown
    /// sequence will look for it.
    fn drop(&mut self) {
        self.session.reclaim("drop");
    }
}

struct IsolationPtyProcess {
    session: Option<OwnedSession>,
    process: Arc<ClosingProcess>,
    waiter: Option<JoinHandle<Result<ExecOutcome, MxcError>>>,
    outcome: Option<ExecOutcome>,
    writer_taken: Mutex<bool>,
    size: Mutex<PtySize>,
    timed_out: bool,
}

impl IsolationPtyProcess {
    fn duplicate_pipe(raw: u64, name: &str) -> std::io::Result<OwnedPipe> {
        if raw == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("IsolationSession returned no PTY {name} handle"),
            ));
        }
        let borrowed = unsafe { BorrowedHandle::borrow_raw(raw as RawHandle) };
        borrowed.try_clone_to_owned().map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("failed to duplicate the IsolationSession PTY {name} handle: {error}"),
            )
        })
    }

    fn take_input_handle(&self) -> std::io::Result<OwnedPipe> {
        let mut taken = self
            .writer_taken
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *taken {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the PTY writer has already been taken",
            ));
        }
        let input = Self::duplicate_pipe(self.process.stdin, "input")?;
        self.process
            .close_standard_input()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        *taken = true;
        Ok(input)
    }

    fn clone_output_reader(&self) -> std::io::Result<(InterruptiblePipeReader, PipeReadCanceller)> {
        let output = Self::duplicate_pipe(self.process.stdout, "output")?;
        let raw = output.into_raw_handle();
        let reader = InterruptiblePipeReader::new(ProcessOwnedHandle::new(HANDLE(raw)));
        let closer = reader.canceller();
        Ok((reader, closer))
    }

    fn join_waiter(&mut self) -> std::io::Result<ExecOutcome> {
        if let Some(outcome) = self.outcome {
            return Ok(outcome);
        }
        let waiter = self
            .waiter
            .take()
            .ok_or_else(|| std::io::Error::other("PTY waiter was already consumed"))?;
        let mut outcome = waiter
            .join()
            .map_err(|_| std::io::Error::other("IsolationSession PTY waiter panicked"))?
            .map_err(|error| std::io::Error::other(error.message))?;
        if self.timed_out {
            outcome = ExecOutcome::TimedOut;
        }
        self.outcome = Some(outcome);
        Ok(outcome)
    }

    fn outcome_to_io(outcome: ExecOutcome) -> std::io::Result<i32> {
        match outcome {
            ExecOutcome::Exited(code) => Ok(code),
            ExecOutcome::TimedOut => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the IsolationSession PTY process timed out",
            )),
        }
    }

    fn terminate_and_reclaim(&mut self, timed_out: bool) -> std::io::Result<()> {
        if timed_out {
            self.timed_out = true;
        }
        let termination = self
            .process
            .terminate_process()
            .map_err(|error| std::io::Error::other(error.to_string()));
        let Some(session) = self.session.as_mut() else {
            return termination;
        };
        if let Err(error) = &termination {
            session
                .warnings
                .push(format!("terminating the PTY workload was refused: {error}"));
        }
        let outcome = session.reclaim("kill");
        if outcome.session_stopped == Some(true) {
            return Ok(());
        }
        termination?;
        let mut message = "the isolation session could not be stopped, so the PTY process tree \
                           may still be running"
            .to_string();
        if let Some(cause) = &session.stop_error {
            message.push_str(": ");
            message.push_str(cause);
        }
        Err(std::io::Error::other(message))
    }

    fn join_waiter_if_finished(&mut self) {
        if self
            .waiter
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
        {
            let _ = self.join_waiter();
        }
        // An accepted terminate does not prove the process exited. Dropping
        // an unfinished JoinHandle detaches it instead of making handle
        // destruction wait forever on the waiter's infinite platform wait.
    }
}

impl SandboxProcess for IsolationPtyProcess {
    fn warnings(&self) -> Vec<String> {
        self.session
            .as_ref()
            .map(|session| session.warnings.clone())
            .unwrap_or_default()
    }

    fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
        let output = Self::duplicate_pipe(self.process.stdout, "output")?;
        let input = self.take_input_handle()?;
        Ok(Some(NativeStdio {
            stdin: Some(input),
            stdout: Some(output),
            stderr: None,
        }))
    }

    fn is_pty(&self) -> bool {
        true
    }

    fn pty_clone_reader(&self) -> std::io::Result<Box<dyn Read + Send>> {
        let (reader, _) = self.clone_output_reader()?;
        Ok(Box::new(reader))
    }

    fn pty_clone_reader_with_closer(
        &self,
    ) -> std::io::Result<(Box<dyn Read + Send>, Option<Box<dyn StreamCloser>>)> {
        let (reader, closer) = self.clone_output_reader()?;
        Ok((Box::new(reader), Some(Box::new(closer))))
    }

    fn pty_take_writer(&self) -> std::io::Result<Box<dyn Write + Send>> {
        let input = self.take_input_handle()?;
        Ok(Box::new(std::fs::File::from(input)))
    }

    fn pty_resize(&self, size: PtySize) -> std::io::Result<()> {
        self.process
            .resize_console(size.cols, size.rows)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        *self
            .size
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = size;
        Ok(())
    }

    fn pty_size(&self) -> std::io::Result<PtySize> {
        Ok(*self
            .size
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()))
    }

    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        None
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        None
    }

    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        None
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        if self.outcome.is_some()
            || self
                .waiter
                .as_ref()
                .is_some_and(std::thread::JoinHandle::is_finished)
        {
            return Self::outcome_to_io(self.join_waiter()?).map(Some);
        }
        Ok(None)
    }

    fn id(&self) -> u32 {
        0
    }

    fn kill(&mut self) -> std::io::Result<()> {
        self.terminate_and_reclaim(false)
    }

    fn kill_for_timeout(&mut self) -> std::io::Result<()> {
        self.terminate_and_reclaim(true)
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        if !*self
            .writer_taken
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            let _ = self.process.close_standard_input();
        }
        let outcome = self.join_waiter();
        if let Some(session) = self.session.as_mut() {
            session.reclaim("wait");
        }
        Self::outcome_to_io(outcome?)
    }
}

impl Drop for IsolationPtyProcess {
    fn drop(&mut self) {
        if let Some(session) = self.session.as_mut() {
            session.reclaim("drop");
        } else if self.outcome.is_none() && self.process.terminate_process().is_ok() {
            self.join_waiter_if_finished();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::mxc_error::MxcErrorCode;

    /// A launch failure that also failed to clean up keeps its own
    /// classification, so a caller still branches on the real cause.
    ///
    /// The tempting shape — rebuilding the error around a formatted string —
    /// reads the same and silently discards the failing API call, its status
    /// and its remediation.
    #[test]
    fn folding_a_cleanup_failure_keeps_the_launch_errors_classification() {
        let launch = crate::isolation_session_common::error::test_support::stale_failure();
        let folded =
            with_cleanup_failures(launch, &["the agent user could not be removed".to_string()]);
        let mapped = crate::isolation_session_common::error::map_lifecycle_error(folded);

        assert_eq!(mapped.code, MxcErrorCode::StaleId);
        assert!(
            mapped.operation().is_some(),
            "the failing call must survive"
        );
        assert!(mapped.native_code().is_some(), "the status must survive");
        assert!(
            mapped.message.contains("could not be removed"),
            "the cleanup failure must reach the caller: {}",
            mapped.message
        );
    }

    /// With nothing to add, the error is returned untouched.
    #[test]
    fn folding_no_cleanup_failure_leaves_the_error_alone() {
        let launch = crate::isolation_session_common::error::test_support::stale_failure();
        let before = launch.to_string();
        let after = with_cleanup_failures(launch, &[]).to_string();
        assert_eq!(before, after);
    }
}
