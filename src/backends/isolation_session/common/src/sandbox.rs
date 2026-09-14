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

use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use wxc_common::mxc_error::MxcError;
use wxc_common::sandbox_process::{SandboxBackend, SandboxProcess, StdioMode, StreamCloser};
use wxc_common::script_runner::ScriptRunner;
use wxc_common::validator::validate_common;

use super::error::{lifecycle_err, IsolationSessionError};
use super::manager::{log_sandbox_torn_down, IsolationSessionManager, TeardownOutcome};
use super::process_options::{build_process_options, with_service_timeout_grace};
use super::IsolationSessionRunner;

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
    let (provisioned, manager) = IsolationSessionManager::add_user(None)?;
    let _ = writeln!(
        logger,
        "Isolation Session: agent user = {}",
        provisioned.agent_user_name
    );

    // From here the account exists, so every failure reclaims it rather than
    // abandoning it.
    let mut session = OwnedSession::new(manager, provisioned.agent_user_name);

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

    let inner = match wxc_common::exec_stream::ExecSandboxProcess::from_exec_handle(handle) {
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
    agent_user_name: String,
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

/// Runs the two teardown calls on a thread of our own.
///
/// They inherit the apartment of whatever thread finishes the handle, and the
/// handle is `Send`. In a single-threaded apartment they return without doing
/// the work, stranding a real OS account; a thread of our own is never in one.
///
/// `stop` is `false` once the session is already stopped: stopping it again
/// fails, and that failure is indistinguishable from one that never stopped.
fn teardown(
    manager: &mut IsolationSessionManager,
    stop: bool,
) -> (
    Result<(), IsolationSessionError>,
    Result<(), IsolationSessionError>,
) {
    let relayed = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .spawn_scoped(scope, || {
                let stopped = if stop { manager.stop_session() } else { Ok(()) };
                (stopped, manager.deprovision_agent_user())
            })
            .ok()
            .and_then(|worker| worker.join().ok())
    });
    // A worker that could not be created leaves the account behind, which is
    // worse than teardown on the caller's own thread.
    relayed.unwrap_or_else(|| {
        let stopped = if stop { manager.stop_session() } else { Ok(()) };
        (stopped, manager.deprovision_agent_user())
    })
}

impl OwnedSession {
    fn new(manager: IsolationSessionManager, agent_user_name: String) -> Self {
        Self {
            manager,
            agent_user_name,
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
        let (stopped, deprovisioned) = teardown(&mut self.manager, !self.stopped);
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
            &self.agent_user_name,
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
    inner: wxc_common::exec_stream::ExecSandboxProcess,
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
        if let Err(e) = self.inner.kill() {
            self.session
                .warnings
                .push(format!("terminating the workload was refused: {e}"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::mxc_error::MxcErrorCode;

    /// A launch failure that also failed to clean up keeps its own
    /// classification, so a caller still branches on the real cause.
    ///
    /// The tempting shape — rebuilding the error around a formatted string —
    /// reads the same and silently discards the failing API call, its status
    /// and its remediation.
    #[test]
    fn folding_a_cleanup_failure_keeps_the_launch_errors_classification() {
        let launch = crate::error::test_support::stale_failure();
        let folded =
            with_cleanup_failures(launch, &["the agent user could not be removed".to_string()]);
        let mapped = crate::error::map_lifecycle_error(folded);

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
        let launch = crate::error::test_support::stale_failure();
        let before = launch.to_string();
        let after = with_cleanup_failures(launch, &[]).to_string();
        assert_eq!(before, after);
    }
}
