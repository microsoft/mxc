// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! State-aware lifecycle dispatch.
//!
//! The single home for resolving a parsed state-aware request to its backend
//! and driving the per-phase flow. It centralizes the backend-specific
//! construction that would otherwise live inline in `wxc-exec` so the binary
//! can shrink to a thin CLI shell.
//!
//! Backends whose `StatefulSandboxBackend` impl lives in a `backends/*` crate
//! (which depends on `wxc_common`, so the construction can't live inside
//! `wxc_common` without a cycle) are constructed here — the engine already
//! depends on those crates. Anything without a state-aware impl falls back to
//! [`wxc_common::state_aware_dispatch::run_state_aware`], which surfaces the
//! `unsupported_phase` envelope.

use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

use wxc_common::logger::{Logger, Mode};
use wxc_common::mxc_error::MxcError;
use wxc_common::sandbox_process::SandboxProcess;
use wxc_common::state_aware_backend::ExecOutcome;
use wxc_common::state_aware_dispatch::{
    resolve_backend, run_state_aware as run_state_aware_fallback, DispatchOutcome,
};
use wxc_common::state_aware_request::{MxcRequest, ParsedStateAwareRequest, Phase};

use crate::error::Error;

/// The `backend_unavailable` error returned when a state-aware WSLc request
/// reaches a build compiled without the `wslc` feature (or a non-Windows
/// target). Mirrors the documented error mapping so the availability probe can
/// skip a feature-off build instead of misreading `unsupported_phase`.
#[cfg(not(all(target_os = "windows", feature = "wslc")))]
fn wslc_unavailable() -> MxcError {
    MxcError::backend_unavailable(
        "the WSLc backend is not available in this build (compiled without the `wslc` feature)",
    )
}

/// The IsolationSession counterpart to [`wslc_unavailable`].
#[cfg(not(all(target_os = "windows", feature = "isolation_session")))]
fn isolation_session_unavailable() -> MxcError {
    MxcError::backend_unavailable(
        "the IsolationSession backend is not available in this build (requires Windows with the \
         `isolation_session` feature)",
    )
}

/// Reject a state-aware request for an experimental backend when the caller has
/// not enabled experimental features. Applied by both the envelope dispatcher
/// ([`run_state_aware`]) and the streaming exec dispatcher ([`exec_state_aware`])
/// so no entry point can reach an experimental backend without the opt-in.
fn require_experimental_optin(
    backend: &wxc_common::models::ContainmentBackend,
    parsed: &ParsedStateAwareRequest,
) -> Result<(), MxcError> {
    if matches!(
        backend,
        wxc_common::models::ContainmentBackend::WindowsSandbox
            | wxc_common::models::ContainmentBackend::IsolationSession
            | wxc_common::models::ContainmentBackend::Wslc
    ) && !parsed.request.experimental_enabled
    {
        return Err(MxcError::backend_unavailable(format!(
            "{backend:?} is an experimental backend; enable experimental features to use it"
        )));
    }
    Ok(())
}

/// Resolve `parsed`'s backend and run the requested state-aware phase.
///
/// On envelope phases this returns [`DispatchOutcome::Envelope`]; on the exec
/// phase it streams output live and returns
/// [`DispatchOutcome::ExecCompleted`]. Dispatch failures return an
/// [`MxcError`] the caller renders as a JSON error envelope.
pub fn run_state_aware(
    parsed: ParsedStateAwareRequest,
    dry_run: bool,
) -> Result<DispatchOutcome, MxcError> {
    let backend = resolve_backend(&parsed)?;
    require_experimental_optin(&backend, &parsed)?;
    match backend {
        #[cfg(target_os = "windows")]
        wxc_common::models::ContainmentBackend::WindowsSandbox => {
            let mut runner = windows_sandbox_lifecycle::WindowsSandboxRunner::new();
            wxc_common::state_aware_dispatch::dispatch_state_aware(&mut runner, parsed, dry_run)
        }
        #[cfg(all(target_os = "windows", feature = "isolation_session"))]
        wxc_common::models::ContainmentBackend::IsolationSession => {
            let mut runner = isolation_session_common::IsolationSessionRunner::new();
            wxc_common::state_aware_dispatch::dispatch_state_aware(&mut runner, parsed, dry_run)
        }
        #[cfg(target_os = "linux")]
        wxc_common::models::ContainmentBackend::Lxc => {
            let mut runner = lxc_common::state_aware::LxcStateAwareRunner::new();
            wxc_common::state_aware_dispatch::dispatch_state_aware(&mut runner, parsed, dry_run)
        }
        #[cfg(all(target_os = "windows", feature = "wslc"))]
        wxc_common::models::ContainmentBackend::Wslc => {
            let mut runner = wslc_common::WslcStateAwareRunner::new();
            wxc_common::state_aware_dispatch::dispatch_state_aware(&mut runner, parsed, dry_run)
        }
        // Feature-off build: keep the documented `backend_unavailable` contract
        // rather than falling through to the generic `unsupported_phase`.
        #[cfg(not(all(target_os = "windows", feature = "wslc")))]
        wxc_common::models::ContainmentBackend::Wslc => Err(wslc_unavailable()),
        #[cfg(not(all(target_os = "windows", feature = "isolation_session")))]
        wxc_common::models::ContainmentBackend::IsolationSession => {
            Err(isolation_session_unavailable())
        }
        _ => run_state_aware_fallback(parsed, dry_run),
    }
}

/// Resolve `parsed`'s backend and run the `exec` phase as a **streaming**
/// process, returning a [`SandboxProcess`] handle instead of relaying to the
/// caller's stdio. The streaming counterpart of the exec arm of
/// [`run_state_aware`].
///
/// Backends without a state-aware impl return an [`MxcError`] with
/// `unsupported_phase`.
pub fn exec_state_aware(
    parsed: ParsedStateAwareRequest,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    let backend = resolve_backend(&parsed)?;
    require_experimental_optin(&backend, &parsed)?;
    match backend {
        #[cfg(all(target_os = "windows", feature = "isolation_session"))]
        wxc_common::models::ContainmentBackend::IsolationSession => {
            let mut runner = isolation_session_common::IsolationSessionRunner::new();
            let handle =
                wxc_common::state_aware_dispatch::dispatch_state_aware_exec(&mut runner, parsed)?;
            Ok(Box::new(
                wxc_common::exec_stream::ExecSandboxProcess::from_exec_handle(handle)?,
            ))
        }
        #[cfg(all(target_os = "windows", feature = "wslc"))]
        wxc_common::models::ContainmentBackend::Wslc => {
            let mut runner = wslc_common::WslcStateAwareRunner::new();
            let handle =
                wxc_common::state_aware_dispatch::dispatch_state_aware_exec(&mut runner, parsed)?;
            Ok(Box::new(
                wxc_common::exec_stream::ExecSandboxProcess::from_exec_handle(handle)?,
            ))
        }
        // Feature-off build: keep the documented `backend_unavailable` contract
        // rather than falling through to the generic `unsupported_phase`.
        #[cfg(not(all(target_os = "windows", feature = "wslc")))]
        wxc_common::models::ContainmentBackend::Wslc => Err(wslc_unavailable()),
        #[cfg(not(all(target_os = "windows", feature = "isolation_session")))]
        wxc_common::models::ContainmentBackend::IsolationSession => {
            Err(isolation_session_unavailable())
        }
        _ => Err(exec_unsupported_error(&backend)),
    }
}

/// The error returned when a backend cannot serve a **streaming** exec.
///
/// Two distinct situations reach here and the caller needs to tell them apart:
///
/// - The backend has no state-aware lifecycle at all, so nothing about it works
///   through these APIs.
/// - The backend does implement the lifecycle ([`run_state_aware`] dispatches
///   provision/start/exec/stop/deprovision for it) but has no streaming
///   [`SandboxProcess`], so only this one API is unavailable.
///
/// LXC is the second case. Reporting it as "does not implement the state-aware
/// lifecycle" sent callers off to debug a provision path that works fine, so
/// the message names the real gap and points at the API that does work.
fn exec_unsupported_error(backend: &wxc_common::models::ContainmentBackend) -> MxcError {
    if backend_has_state_aware_lifecycle(backend) {
        MxcError::unsupported_phase(format!(
            "backend {backend:?} implements the state-aware lifecycle but not streaming exec; \
             use the non-streaming exec phase instead"
        ))
    } else {
        MxcError::unsupported_phase(format!(
            "backend {backend:?} does not implement the state-aware lifecycle"
        ))
    }
}

/// Whether `backend` has a `StatefulSandboxBackend` impl wired into
/// [`run_state_aware`] on this target. Kept next to that `match` so the two stay
/// in step — a backend added there without being added here would be described
/// by the wrong error.
fn backend_has_state_aware_lifecycle(backend: &wxc_common::models::ContainmentBackend) -> bool {
    match backend {
        #[cfg(target_os = "windows")]
        wxc_common::models::ContainmentBackend::WindowsSandbox => true,
        #[cfg(all(target_os = "windows", feature = "isolation_session"))]
        wxc_common::models::ContainmentBackend::IsolationSession => true,
        #[cfg(all(target_os = "windows", feature = "wslc"))]
        wxc_common::models::ContainmentBackend::Wslc => true,
        #[cfg(target_os = "linux")]
        wxc_common::models::ContainmentBackend::Lxc => true,
        _ => false,
    }
}

/// Parse a state-aware request JSON string into a [`ParsedStateAwareRequest`],
/// rejecting a one-shot config (no `phase`).
///
/// `experimental` is the in-process equivalent of the executor's
/// `--experimental` flag, and is applied **here, after parsing**, because
/// `config_parser` hardcodes `experimental_enabled: false` for every
/// state-aware request.
fn parse_state_aware(
    request_json: &str,
    experimental: bool,
) -> Result<ParsedStateAwareRequest, Error> {
    let mut logger = Logger::new(Mode::Buffer);
    match wxc_common::config_parser::load_mxc_request_from_json(request_json, &mut logger) {
        Ok(MxcRequest::StateAware(mut parsed)) => {
            parsed.request.experimental_enabled = experimental;
            Ok(parsed)
        }
        Ok(MxcRequest::OneShot(_)) => Err(Error::from(MxcError::malformed_request(
            "expected a state-aware lifecycle request (with a 'phase' field), got a one-shot config",
        ))),
        Err(e) => Err(Error::from(parse_error_to_mxc(e))),
    }
}

/// Map a [`config_parser::ParseError`](wxc_common::config_parser::ParseError) to
/// an [`MxcError`]. The state-aware arm already carries one; the decode / one-
/// shot arms carry a `WxcError` that maps to `malformed_request`.
fn parse_error_to_mxc(e: wxc_common::config_parser::ParseError) -> MxcError {
    use wxc_common::config_parser::ParseError;
    match e {
        ParseError::StateAware(err) => err,
        ParseError::Decode(err) | ParseError::OneShot(err) => {
            MxcError::malformed_request(err.to_string())
        }
    }
}

/// Serialises attached execs within this process.
///
/// An attached exec owns process-global console state — raw VT mode, the control
/// handler, the single input buffer. Two at once would race mode restoration and
/// leave the console raw.
static ATTACHED_EXEC_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Releases the attached-exec claim on every exit path, including unwind.
struct AttachedExecClaim;

impl Drop for AttachedExecClaim {
    fn drop(&mut self) {
        ATTACHED_EXEC_ACTIVE.store(false, Ordering::Release);
    }
}

/// Takes the attached-exec claim, or `None` if one is already held.
///
/// Prefer [`with_attached_exec_claim`]; this exists for tests that need to
/// observe the claim directly.
fn claim_attached_exec() -> Option<AttachedExecClaim> {
    if ATTACHED_EXEC_ACTIVE.swap(true, Ordering::AcqRel) {
        None
    } else {
        Some(AttachedExecClaim)
    }
}

/// Runs `work` holding the attached-exec claim, or returns `None` if one is
/// already held.
///
/// Scoped, not a returned guard: binding to `_` would release the claim early.
fn with_attached_exec_claim<T>(work: impl FnOnce() -> T) -> Option<T> {
    let _claim = claim_attached_exec()?;
    Some(work())
}

/// Run a state-aware `exec` **attached to this process's stdio**, returning how
/// the sandboxed process finished.
///
/// The backend relays the workload onto this process's stdout and stderr and
/// blocks until it exits; IsolationSession also forwards stdin. Use
/// [`exec_state_aware_json`] instead to drive the streams yourself.
///
/// Refused with `malformed_request` unless **both** this process's stdout and
/// stdin are terminals, and unless no other attached exec is in flight.
///
/// [`ExecOutcome::TimedOut`] is unreachable: a spent deadline arrives as
/// [`ExecOutcome::Exited`], because the relay rejects anything else.
pub fn exec_state_aware_attached(
    request_json: &str,
    experimental: bool,
) -> Result<ExecOutcome, Error> {
    exec_state_aware_attached_with(request_json, experimental, || {
        host_stdio_is_attachable(
            std::io::stdout().is_terminal(),
            std::io::stdin().is_terminal(),
        )
    })
}

fn host_stdio_is_attachable(stdout_is_terminal: bool, stdin_is_terminal: bool) -> bool {
    stdout_is_terminal && stdin_is_terminal
}

/// Whether an attached exec may proceed, given a host-stdio probe.
///
/// Split from the entry point so the rule is testable: the real probe reads
/// process-global console state, which a test cannot vary. Mirrors the seam
/// `wants_interactive_console` uses in the IsolationSession backend.
///
/// **Both stdout and stdin must be terminals.** Backends select their stdio
/// topology on different streams — IsolationSession on stdout, Windows Sandbox
/// on stdin — and each picks an uncancellable relay for the non-terminal case.
/// Probing only one admits a caller the other would leak a thread for.
fn exec_attached_gate(host_is_interactive: impl FnOnce() -> bool) -> Result<(), Error> {
    if !host_is_interactive() {
        return Err(Error::from(MxcError::malformed_request(
            "an attached exec requires this process's stdout and stdin to both be terminals. \
             The backends relay through the caller's standard handles and cannot shut the \
             relay down when they are not waitable, so it outlives the call and this process \
             does not exit to clean it up. Drive the workload through the streaming exec entry \
             point instead. Nothing has been run.",
        )));
    }
    Ok(())
}

fn exec_state_aware_attached_with(
    request_json: &str,
    experimental: bool,
    host_is_interactive: impl FnOnce() -> bool,
) -> Result<ExecOutcome, Error> {
    let parsed = parse_state_aware(request_json, experimental)?;

    if !matches!(parsed.phase, Phase::Exec) {
        return Err(Error::from(MxcError::malformed_request(format!(
            "an attached exec requires the exec phase, got {}",
            parsed.phase
        ))));
    }

    exec_attached_gate(host_is_interactive)?;
    let dispatched = with_attached_exec_claim(|| run_state_aware(parsed, /* dry_run */ false))
        .ok_or_else(|| {
            Error::from(MxcError::malformed_request(
                "another attached exec is already running in this process. An attached exec \
                 owns this process's console mode and control handler, so only one can run at \
                 a time. Nothing has been run.",
            ))
        })?;

    match dispatched.map_err(Error::from)? {
        DispatchOutcome::ExecCompleted { exit_code } => Ok(ExecOutcome::Exited(exit_code)),
        DispatchOutcome::Envelope(_) => Err(Error::from(MxcError::backend_error(
            "an attached exec returned an envelope instead of an exit code",
        ))),
    }
}

/// Run a state-aware lifecycle request from a JSON string, returning the
/// response-envelope JSON string.
///
/// Handles the envelope phases (provision / start / stop / deprovision) and a
/// dry-run of any phase. A non-dry-run `exec` produces no envelope and is
/// rejected here — run it through an exec entry point instead:
/// [`exec_state_aware_attached`] to attach the workload to this process's stdio,
/// or [`exec_state_aware_json`] to drive the pipes yourself.
///
/// `experimental` opts in to the experimental backends (WindowsSandbox,
/// IsolationSession, WSLc); without it they are refused with
/// `backend_unavailable` before any work is done.
pub fn run_state_aware_json(
    request_json: &str,
    dry_run: bool,
    experimental: bool,
) -> Result<String, Error> {
    let parsed = parse_state_aware(request_json, experimental)?;

    if matches!(parsed.phase, Phase::Exec) && !dry_run {
        return Err(Error::from(MxcError::malformed_request(
            "the exec phase does not return an envelope; run it through one of the exec entry \
             points instead — attached to this process's stdio, or streaming with the caller \
             driving the pipes",
        )));
    }

    match run_state_aware(parsed, dry_run).map_err(Error::from)? {
        DispatchOutcome::Envelope(value) => serde_json::to_string(&value).map_err(|e| {
            Error::from(MxcError::backend_error(format!(
                "serialising the response envelope failed: {e}"
            )))
        }),
        // Only reachable for a non-dry-run exec, which we rejected above.
        DispatchOutcome::ExecCompleted { exit_code } => {
            Ok(format!("{{\"result\":{{\"exitCode\":{exit_code}}}}}"))
        }
    }
}

/// Run the `exec` phase of a state-aware request (from a JSON string) as a live
/// streaming process, returning a [`SandboxProcess`] handle.
///
/// `experimental` opts in to the experimental backends, as for
/// [`run_state_aware_json`].
pub fn exec_state_aware_json(
    request_json: &str,
    experimental: bool,
) -> Result<Box<dyn SandboxProcess>, Error> {
    let parsed = parse_state_aware(request_json, experimental)?;
    if !matches!(parsed.phase, Phase::Exec) {
        return Err(Error::from(MxcError::malformed_request(format!(
            "streaming exec requires the exec phase, got {}",
            parsed.phase
        ))));
    }
    exec_state_aware(parsed).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{ContainmentBackend, ExecutionRequest};
    use wxc_common::mxc_error::MxcErrorCode;
    use wxc_common::state_aware_request::Phase;

    #[test]
    fn experimental_backend_requires_optin() {
        let parsed = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Provision,
            containment: Some(ContainmentBackend::WindowsSandbox),
            sandbox_id: None,
            correlation_vector: None,
            experimental_raw: None,
            source_text: None,
        };

        let error = run_state_aware(parsed, false).unwrap_err();

        assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
        assert!(error.message.contains("experimental"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn exec_error_distinguishes_missing_streaming_from_missing_lifecycle() {
        // LXC dispatches the lifecycle but has no streaming SandboxProcess. The
        // old blanket message sent callers off to debug a provision path that
        // works, so the two cases must read differently.
        let lxc = exec_unsupported_error(&ContainmentBackend::Lxc);
        assert_eq!(lxc.code, MxcErrorCode::UnsupportedPhase);
        assert!(
            lxc.message.contains("not streaming exec"),
            "expected the streaming-specific message, got {:?}",
            lxc.message
        );
        assert!(!lxc.message.contains("does not implement"));

        let bwrap = exec_unsupported_error(&ContainmentBackend::Bubblewrap);
        assert_eq!(bwrap.code, MxcErrorCode::UnsupportedPhase);
        assert!(
            bwrap
                .message
                .contains("does not implement the state-aware lifecycle"),
            "expected the no-lifecycle message, got {:?}",
            bwrap.message
        );
    }

    #[test]
    fn exec_experimental_backend_requires_optin() {
        // The streaming exec entry point applies the same opt-in gate as the
        // envelope dispatcher: a `wslc:` exec without the opt-in must be
        // refused before reaching the backend.
        let parsed = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Exec,
            containment: Some(ContainmentBackend::Wslc),
            sandbox_id: Some("wslc:00000000000000000000000000000000".to_string()),
            correlation_vector: None,
            experimental_raw: None,
            source_text: None,
        };

        let error = match exec_state_aware(parsed) {
            Ok(_) => {
                panic!("expected the experimental gate to reject a wslc exec without the opt-in")
            }
            Err(e) => e,
        };

        assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
        assert!(error.message.contains("experimental"));
    }

    #[test]
    fn attached_exec_gate_admits_only_a_terminal_host() {
        assert!(exec_attached_gate(|| true).is_ok());

        let err = exec_attached_gate(|| false)
            .expect_err("a non-terminal host must be refused before anything runs");
        assert_eq!(err.code, crate::ErrorCode::MalformedRequest);
        assert!(
            err.message.contains("stdout and stdin"),
            "the refusal must name both streams, got: {}",
            err.message
        );
    }

    #[test]
    fn attachable_stdio_requires_both_streams() {
        assert!(host_stdio_is_attachable(true, true));
        assert!(
            !host_stdio_is_attachable(true, false),
            "a redirected stdin must not be attachable: Windows Sandbox selects on stdin"
        );
        assert!(
            !host_stdio_is_attachable(false, true),
            "a redirected stdout must not be attachable: IsolationSession selects on stdout"
        );
        assert!(!host_stdio_is_attachable(false, false));
    }

    /// Serialises the tests that take the process-global attached-exec claim.
    /// They contend by construction — the claim is process-wide because the
    /// console state it guards is — so running them in parallel is a race.
    static CLAIM_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn attached_exec_claim_is_exclusive_and_released() {
        let _serial = CLAIM_TESTS.lock().unwrap_or_else(|e| e.into_inner());

        let first = claim_attached_exec().expect("the claim must be available");
        assert!(
            claim_attached_exec().is_none(),
            "a second claim must be refused while the first is held"
        );

        drop(first);
        let second = claim_attached_exec()
            .expect("the claim must be available again once the first is dropped");

        // Held across the assertion above, so an early release would have let
        // the exclusivity check pass for the wrong reason.
        drop(second);
    }

    #[test]
    fn attached_exec_claim_is_held_for_the_duration_of_the_work() {
        let _serial = CLAIM_TESTS.lock().unwrap_or_else(|e| e.into_inner());

        // Observes the claim from inside the work, which is the only way to
        // tell "held until the work finishes" from "taken and dropped at once".
        let refused_while_working =
            with_attached_exec_claim(|| claim_attached_exec().is_none()).expect("claim available");
        assert!(
            refused_while_working,
            "the claim must still be held while the work runs"
        );

        assert!(
            claim_attached_exec().is_some(),
            "the claim must be released once the work returns"
        );
        ATTACHED_EXEC_ACTIVE.store(false, Ordering::Release);
    }

    #[test]
    fn attached_exec_refuses_a_second_concurrent_call() {
        let _serial = CLAIM_TESTS.lock().unwrap_or_else(|e| e.into_inner());

        // The gate and phase checks pass, so the refusal can only come from the
        // single-flight claim. The exec goes no further: `wsb:` resolves to a
        // backend needing a live host, and the claim is taken before that.
        let json = r#"{"phase":"exec","sandboxId":"wsb:0123abcd",
            "process":{"commandLine":"cmd.exe /c echo hi"}}"#;

        let held = claim_attached_exec().expect("the claim must be available");
        let err = exec_state_aware_attached_with(json, true, || true)
            .expect_err("a second concurrent attached exec must be refused");
        drop(held);

        assert_eq!(err.code, crate::ErrorCode::MalformedRequest);
        assert!(
            err.message.contains("already running"),
            "the refusal must name the conflict, got: {}",
            err.message
        );
    }

    #[test]
    fn attached_exec_requires_a_terminal() {
        let json = r#"{"phase":"exec","sandboxId":"wsb:0123abcd",
            "process":{"commandLine":"cmd.exe /c echo hi"}}"#;

        let err = exec_state_aware_attached_with(json, true, || false)
            .expect_err("an exec phase from a non-terminal host must be refused");
        assert_eq!(err.code, crate::ErrorCode::MalformedRequest);
        assert!(
            err.message.contains("terminals"),
            "the refusal must name the terminal requirement, got: {}",
            err.message
        );
    }

    #[test]
    fn attached_exec_checks_the_phase_before_the_terminal() {
        // A non-exec phase must be reported as such even from a non-terminal
        // host, so the caller learns the actionable problem first.
        let provision = r#"{"phase":"provision","containment":"isolation_session",
            "network":{"defaultPolicy":"allow","allowLocalNetwork":true}}"#;

        let err = exec_state_aware_attached_with(provision, true, || false)
            .expect_err("a non-exec phase must be refused");
        assert!(
            err.message.contains("exec phase"),
            "the phase check must precede the terminal check, got: {}",
            err.message
        );
    }
}
