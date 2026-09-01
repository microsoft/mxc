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

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use wxc_common::logger::{Logger, Mode};
use wxc_common::mxc_error::MxcError;
use wxc_common::sandbox_process::SandboxProcess;
use wxc_common::state_aware_backend::ExecOutcome;
use wxc_common::state_aware_dispatch::{
    resolve_backend, run_state_aware as run_state_aware_fallback, DispatchOutcome,
};
use wxc_common::state_aware_request::{MxcRequest, ParsedStateAwareRequest, Phase};
use wxc_common::telemetry;

use crate::error::Error;
use crate::wrap_state_aware_telemetry_process_with_kind;

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

/// This phase's telemetry correlation vector, purely internal to MXC: no
/// caller ever supplies or relays one. `provision` (whose `sandboxId` doesn't
/// exist yet) mints a fresh vector; every later phase recalls the same
/// lifecycle root persisted by `provision` and spins a distinct child off it —
/// see [`telemetry::correlation_state`].
fn phase_correlation(active: bool, phase: Phase, sandbox_id: Option<&str>) -> String {
    telemetry::correlation_state::pre_dispatch_vector(active, phase == Phase::Provision, sandbox_id)
}

fn surface_attached_warnings(logger: &mut Logger, mut surface: impl FnMut(&str)) {
    for warning in logger.take_warnings() {
        surface(&warning);
    }
}

/// Merge `warnings` from telemetry initialisation into the envelope's
/// `result.warnings` array. Existing entries in the array are preserved and
/// duplicates suppressed so the field remains a stable set-like list.
///
/// This mirrors what the ordinary SDK `spawn` path does for streaming
/// invocations (see `ProcessWithWarnings::wrap` in `lib.rs`): both entry
/// points buffer telemetry-init diagnostics in a `Logger` and must surface
/// them to the caller instead of dropping them on the floor.
fn inject_warnings(outcome: &mut Result<DispatchOutcome, MxcError>, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    if let Ok(DispatchOutcome::Envelope(value)) = outcome {
        if let Some(result) = value
            .get_mut("result")
            .and_then(|result| result.as_object_mut())
        {
            let existing = result
                .entry("warnings")
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            if let Some(array) = existing.as_array_mut() {
                for warning in warnings {
                    let value = serde_json::Value::String(warning.clone());
                    if !array.contains(&value) {
                        array.push(value);
                    }
                }
            }
        }
    }
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
        #[cfg(all(target_os = "windows", feature = "wslc"))]
        wxc_common::models::ContainmentBackend::Wslc => {
            let mut runner = wslc_common::WslcStateAwareRunner::new();
            wxc_common::state_aware_dispatch::dispatch_state_aware(&mut runner, parsed, dry_run)
        }
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
        #[cfg(target_os = "windows")]
        wxc_common::models::ContainmentBackend::WindowsSandbox => {
            let mut runner = windows_sandbox_lifecycle::WindowsSandboxRunner::new();
            let handle =
                wxc_common::state_aware_dispatch::dispatch_state_aware_exec(&mut runner, parsed)?;
            Ok(Box::new(
                wxc_common::exec_stream::ExecSandboxProcess::from_exec_handle(handle)?,
            ))
        }
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
        #[cfg(not(all(target_os = "windows", feature = "wslc")))]
        wxc_common::models::ContainmentBackend::Wslc => Err(wslc_unavailable()),
        #[cfg(not(all(target_os = "windows", feature = "isolation_session")))]
        wxc_common::models::ContainmentBackend::IsolationSession => {
            Err(isolation_session_unavailable())
        }
        _ => Err(MxcError::unsupported_phase(format!(
            "backend {:?} does not implement the state-aware lifecycle",
            backend
        ))),
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
    logger: &mut Logger,
) -> Result<ParsedStateAwareRequest, Error> {
    match wxc_common::config_parser::load_mxc_request_from_json(request_json, logger) {
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
    let mut logger = Logger::new(Mode::Buffer);
    let parsed = parse_state_aware(request_json, experimental, &mut logger)?;

    if !matches!(parsed.phase, Phase::Exec) {
        return Err(Error::from(MxcError::malformed_request(format!(
            "an attached exec requires the exec phase, got {}",
            parsed.phase
        ))));
    }

    exec_attached_gate(host_is_interactive)?;
    let phase = parsed.phase;
    let sandbox_id = parsed.sandbox_id.clone();
    let requested_sandbox_kind = parsed
        .request
        .telemetry
        .as_ref()
        .and_then(|config| config.requested_sandbox_kind);
    let telemetry_active = parsed
        .request
        .telemetry
        .as_ref()
        .map(|config| telemetry::init(config, &mut logger))
        .unwrap_or(false);
    // This API explicitly attaches the workload to the host's stdio and has no
    // warning-bearing return handle. Surface retained parser/init warnings on
    // host stderr rather than silently dropping them as the buffered logger
    // goes out of scope.
    surface_attached_warnings(&mut logger, |warning| {
        let _ = writeln!(std::io::stderr().lock(), "{warning}");
    });
    let backend = resolve_backend(&parsed)
        .map(|backend| backend.wire_name().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let correlation = phase_correlation(telemetry_active, phase, sandbox_id.as_deref());
    let started = std::time::Instant::now();
    let dispatched = with_attached_exec_claim(|| run_state_aware(parsed, /* dry_run */ false))
        .unwrap_or_else(|| {
            Err(MxcError::malformed_request(
                "another attached exec is already running in this process. An attached exec \
                 owns this process's console mode and control handler, so only one can run at \
                 a time. Nothing has been run.",
            ))
        });
    telemetry::emit_sdk_state_aware_with_kind(
        telemetry_active,
        requested_sandbox_kind,
        telemetry::TelemetryContext {
            backend: &backend,
            phase: phase.as_str(),
            correlation_vector: &correlation,
        },
        &dispatched,
        started.elapsed(),
    );

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
    let mut logger = Logger::new(Mode::Buffer);
    let parsed = parse_state_aware(request_json, experimental, &mut logger)?;

    if matches!(parsed.phase, Phase::Exec) && !dry_run {
        return Err(Error::from(MxcError::malformed_request(
            "the exec phase does not return an envelope; run it through one of the exec entry \
             points instead — attached to this process's stdio, or streaming with the caller \
             driving the pipes",
        )));
    }

    let phase = parsed.phase;
    let phase_name = phase.as_str();
    let sandbox_id = parsed.sandbox_id.clone();
    let requested_sandbox_kind = parsed
        .request
        .telemetry
        .as_ref()
        .and_then(|config| config.requested_sandbox_kind);
    let telemetry_active = parsed
        .request
        .telemetry
        .as_ref()
        .map(|config| telemetry::init(config, &mut logger))
        .unwrap_or(false);
    let backend = resolve_backend(&parsed)
        .map(|backend| backend.wire_name().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let correlation = phase_correlation(telemetry_active, phase, sandbox_id.as_deref());
    // Snapshot warnings buffered during telemetry init (e.g., provider
    // registration failures) so we can surface them via the outgoing
    // envelope. The ordinary streaming `spawn` path in lib.rs threads these
    // through `ProcessWithWarnings::wrap`; the envelope-returning state-aware
    // path had been silently dropping them.
    let init_warnings = logger.take_warnings();
    let started = std::time::Instant::now();
    let mut outcome = run_state_aware(parsed, dry_run);
    inject_warnings(&mut outcome, &init_warnings);
    match phase {
        Phase::Provision => {
            telemetry::correlation_state::on_provision_outcome(
                telemetry_active,
                &correlation,
                &outcome,
            );
        }
        Phase::Deprovision => {
            if let Some(id) = sandbox_id.as_deref() {
                telemetry::correlation_state::on_deprovision_outcome(
                    telemetry_active,
                    id,
                    dry_run,
                    &outcome,
                );
            }
        }
        _ => {}
    }
    telemetry::emit_sdk_state_aware_with_kind(
        telemetry_active,
        requested_sandbox_kind,
        telemetry::TelemetryContext {
            backend: &backend,
            phase: phase_name,
            correlation_vector: &correlation,
        },
        &outcome,
        started.elapsed(),
    );

    match outcome.map_err(Error::from)? {
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
    let mut logger = Logger::new(Mode::Buffer);
    let parsed = parse_state_aware(request_json, experimental, &mut logger)?;
    if !matches!(parsed.phase, Phase::Exec) {
        return Err(Error::from(MxcError::malformed_request(format!(
            "streaming exec requires the exec phase, got {}",
            parsed.phase
        ))));
    }
    let phase = parsed.phase;
    let sandbox_id = parsed.sandbox_id.clone();
    let requested_sandbox_kind = parsed
        .request
        .telemetry
        .as_ref()
        .and_then(|config| config.requested_sandbox_kind);
    let telemetry_active = parsed
        .request
        .telemetry
        .as_ref()
        .map(|config| telemetry::init(config, &mut logger))
        .unwrap_or(false);
    let backend = resolve_backend(&parsed)
        .map(|backend| backend.wire_name().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let correlation = phase_correlation(telemetry_active, phase, sandbox_id.as_deref());
    // Same warning-propagation contract as `run_state_aware_json` above:
    // snapshot init-time warnings so the streaming caller sees them via the
    // returned process handle's `warnings()`.
    let init_warnings = logger.take_warnings();
    let started = std::time::Instant::now();
    match exec_state_aware(parsed) {
        Ok(process) => {
            let process = crate::ProcessWithWarnings::wrap(process, init_warnings);
            Ok(wrap_state_aware_telemetry_process_with_kind(
                process,
                telemetry_active,
                backend,
                phase.as_str().to_string(),
                correlation,
                requested_sandbox_kind,
                started,
            ))
        }
        Err(error) => {
            let outcome = Err(error.clone());
            telemetry::emit_sdk_state_aware_with_kind(
                telemetry_active,
                requested_sandbox_kind,
                telemetry::TelemetryContext {
                    backend: &backend,
                    phase: phase.as_str(),
                    correlation_vector: &correlation,
                },
                &outcome,
                started.elapsed(),
            );
            Err(Error::from(error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{ContainmentBackend, ExecutionRequest};
    use wxc_common::mxc_error::MxcErrorCode;
    use wxc_common::state_aware_request::Phase;
    use wxc_common::telemetry::correlation_state::test_support::StoreDirGuard;

    #[test]
    fn inactive_telemetry_does_not_create_a_correlation_vector() {
        assert_eq!(
            phase_correlation(false, Phase::Provision, None),
            String::new()
        );
    }

    #[test]
    fn attached_warning_surface_drains_retained_warnings() {
        let mut logger = Logger::new(Mode::Buffer);
        logger.warning_line("first");
        logger.warning_line("second");
        let mut surfaced = Vec::new();

        surface_attached_warnings(&mut logger, |warning| surfaced.push(warning.to_string()));

        assert_eq!(surfaced, ["first", "second"]);
        assert!(logger.warnings().is_empty());
    }

    #[test]
    fn later_phase_without_a_persisted_record_seeds_a_disconnected_vector() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());

        let a = phase_correlation(true, Phase::Start, Some("wsb:abcdef01"));
        let b = phase_correlation(true, Phase::Start, Some("wsb:abcdef01"));

        assert!(telemetry::correlation_vector::is_relayable(&a));
        assert!(telemetry::correlation_vector::is_relayable(&b));
        // No provision ever persisted a root for this sandbox_id, so each call
        // seeds its own fresh, disconnected vector instead of sharing a base.
        let base_of = |cv: &str| cv.split('.').next().unwrap().to_string();
        assert_ne!(
            base_of(&a),
            base_of(&b),
            "with no persisted record, repeated calls must not coincidentally share a base"
        );
    }

    #[test]
    fn experimental_backend_requires_optin() {
        let parsed = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Provision,
            containment: Some(ContainmentBackend::WindowsSandbox),
            sandbox_id: None,
            experimental_raw: None,
            source_text: None,
        };

        let error = run_state_aware(parsed, false).unwrap_err();

        assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
        assert!(error.message.contains("experimental"));
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

    #[cfg(not(all(target_os = "windows", feature = "wslc")))]
    #[test]
    fn feature_off_wslc_returns_backend_unavailable() {
        let request = ExecutionRequest {
            experimental_enabled: true,
            ..ExecutionRequest::default()
        };
        let parsed = ParsedStateAwareRequest {
            request,
            phase: Phase::Start,
            containment: Some(ContainmentBackend::Wslc),
            sandbox_id: Some("wslc:00000000000000000000000000000000".to_string()),
            experimental_raw: None,
            source_text: None,
        };

        let error = run_state_aware(parsed, false).unwrap_err();

        assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
        assert!(error
            .message
            .contains("compiled without the `wslc` feature"));
    }

    #[test]
    fn parse_state_aware_preserves_parser_warnings_on_caller_logger() {
        let mut logger = Logger::new(Mode::Buffer);
        let parsed = super::parse_state_aware(
            r#"{
                "phase": "provision",
                "containment": "bubblewrap",
                "experimental": {"bubblewrap": {"start": {}}},
                "process": {"commandLine": "echo hi"},
                "network": {
                    "proxy": {"builtinTestServer": true},
                    "defaultPolicy": "block"
                }
            }"#,
            false,
            &mut logger,
        )
        .unwrap();

        assert_eq!(parsed.phase, Phase::Provision);
        assert!(
            logger
                .take_warnings()
                .iter()
                .any(|warning| warning.contains("Bubblewrap network.proxy")),
            "parser warnings should stay on the caller-owned logger"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn exec_state_aware_routes_windows_sandbox_exec_to_backend() {
        let request = ExecutionRequest {
            experimental_enabled: true,
            ..ExecutionRequest::default()
        };
        let parsed = ParsedStateAwareRequest {
            request,
            phase: Phase::Exec,
            containment: Some(ContainmentBackend::WindowsSandbox),
            sandbox_id: Some("wsb:abcd1234".to_string()),
            experimental_raw: None,
            source_text: None,
        };

        let error = match exec_state_aware(parsed) {
            Ok(_) => panic!("expected the backend to reject the synthetic sandbox id"),
            Err(error) => error,
        };
        assert_ne!(
            error.code,
            MxcErrorCode::UnsupportedPhase,
            "Windows Sandbox exec should dispatch to the backend-specific implementation"
        );
    }

    /// `provision` seeds a vector and persists it once dispatch mints a
    /// `sandbox_id`; every non-provision phase of the same lifecycle recalls
    /// that persisted root and *spins* a distinct child off it, so all phases
    /// share a telemetry base without any caller relay or sandbox_id-derived
    /// base.
    #[test]
    fn engine_state_aware_correlation_base_shared_across_phases() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());
        let sandbox_id = "wsb:12345678";

        let provisioned = phase_correlation(true, Phase::Provision, None);
        let provision_outcome: Result<DispatchOutcome, MxcError> = Ok(DispatchOutcome::Envelope(
            serde_json::json!({ "result": { "sandboxId": sandbox_id } }),
        ));
        telemetry::correlation_state::on_provision_outcome(true, &provisioned, &provision_outcome);
        let base_prefix = provisioned
            .split('.')
            .next()
            .expect("provisioned correlation vector has a base")
            .to_string();

        // Every phase in the same lifecycle spins that persisted root.
        for phase in [Phase::Start, Phase::Exec, Phase::Stop, Phase::Deprovision] {
            let spun = phase_correlation(true, phase, Some(sandbox_id));
            assert!(
                spun.starts_with(&base_prefix),
                "phase {phase:?} lost the base prefix: {spun}"
            );
            assert_ne!(spun, provisioned, "phase {phase:?} did not spin");
            assert!(
                telemetry::correlation_vector::is_relayable(&spun),
                "phase {phase:?} produced a non-relayable vector: {spun}"
            );
        }
    }

    #[test]
    fn dry_run_deprovision_keeps_the_shared_correlation_root() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());
        let sandbox_id = "wsb:dryrun02";

        let provisioned = phase_correlation(true, Phase::Provision, None);
        let provision_outcome: Result<DispatchOutcome, MxcError> = Ok(DispatchOutcome::Envelope(
            serde_json::json!({ "result": { "sandboxId": sandbox_id } }),
        ));
        telemetry::correlation_state::on_provision_outcome(true, &provisioned, &provision_outcome);
        telemetry::correlation_state::on_deprovision_outcome(
            true,
            sandbox_id,
            true,
            &Ok(DispatchOutcome::Envelope(serde_json::json!({}))),
        );

        let base_prefix = provisioned.split('.').next().unwrap().to_string();
        let later = phase_correlation(true, Phase::Stop, Some(sandbox_id));
        assert_eq!(later.split('.').next().unwrap(), base_prefix);
    }

    /// `run_state_aware_json` maps engine errors through the shared
    /// `telemetry::classify_mxc_error`. This is the same helper `spawn` in
    /// `lib.rs` now uses, so if the mapping ever regresses in either
    /// direction the two paths would drift; instead they drift together and
    /// this test catches it in a single crate.
    ///
    /// We assert both halves independently:
    ///   * `run_state_aware_json` surfaces the expected `ErrorCode`s (so
    ///     `Error → MxcErrorCode` mapping is preserved).
    ///   * `telemetry::classify_mxc_error` maps those `MxcErrorCode`s to the
    ///     expected `FailureReason` (the actual shared classifier).
    #[test]
    fn engine_state_aware_error_codes_classify_via_shared_helper() {
        use crate::error::ErrorCode;
        use wxc_common::telemetry::FailureReason;

        // Malformed JSON — the JSON decoder rejects it, `parse_state_aware`
        // wraps it as `MalformedRequest`, and the classifier maps that to
        // `ConfigError`. This is the same path a user's typo takes.
        let error = super::run_state_aware_json("{ not json", false, false).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest);
        assert_eq!(
            telemetry::classify_mxc_error(&MxcError::malformed_request(error.message)),
            FailureReason::ConfigError
        );

        // Provision without containment — the dispatcher rejects it as
        // `MalformedRequest` before ever reaching a backend.
        let error =
            super::run_state_aware_json(r#"{"phase":"provision"}"#, false, false).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest);
        assert_eq!(
            telemetry::classify_mxc_error(&MxcError::malformed_request(error.message)),
            FailureReason::ConfigError
        );

        // Provision of an experimental backend without --experimental —
        // `BackendUnavailable` → `InitError`; the shared classifier keeps
        // streaming and state-aware attribution in lockstep.
        let error = super::run_state_aware_json(
            r#"{"phase":"provision","containment":"windows_sandbox"}"#,
            false,
            false,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendUnavailable);
        assert_eq!(
            telemetry::classify_mxc_error(&MxcError::backend_unavailable(error.message)),
            FailureReason::InitError
        );
    }

    /// Telemetry providers are released between successive
    /// `run_state_aware_json` calls, even on the error path. A leaked
    /// provider reference on error would prevent shutdown from ever
    /// happening — a follow-up call would then reuse a partially-torn-down
    /// state. Two chained failing calls exercise this: if the first one
    /// leaked, the second would see stale process context (or, worse, would
    /// double-emit).
    ///
    /// We can't directly observe the ETW provider from user-space test code
    /// on non-Windows platforms, but we can assert the observable contract:
    /// each call finishes cleanly with the expected error, and the process
    /// stays healthy across the two.
    #[test]
    fn engine_state_aware_provider_released_between_calls() {
        use crate::error::ErrorCode;
        for _ in 0..3 {
            let error = super::run_state_aware_json(
                r#"{"phase":"provision","containment":"windows_sandbox"}"#,
                false,
                false,
            )
            .unwrap_err();
            assert_eq!(error.code, ErrorCode::BackendUnavailable);
        }
    }

    /// `inject_warnings` merges telemetry-init warnings into the
    /// envelope's `result.warnings` array, dedupes across calls, and leaves
    /// the outcome untouched when there are no warnings.
    #[test]
    fn engine_state_aware_inject_warnings_merges_into_envelope() {
        // No warnings — outcome untouched (no `warnings` key added).
        let mut outcome = Ok(DispatchOutcome::Envelope(serde_json::json!({
            "result": { "sandboxId": "iso:abc" }
        })));
        super::inject_warnings(&mut outcome, &[]);
        let value = match &outcome {
            Ok(DispatchOutcome::Envelope(v)) => v,
            other => panic!("unexpected: {other:?}"),
        };
        assert!(
            value["result"].get("warnings").is_none(),
            "empty warning list should not add the field"
        );

        // With warnings — merged into `result.warnings`, order preserved.
        let mut outcome = Ok(DispatchOutcome::Envelope(serde_json::json!({
            "result": { "sandboxId": "iso:abc" }
        })));
        super::inject_warnings(
            &mut outcome,
            &["telemetry init failed".to_string(), "second".to_string()],
        );
        let value = match &outcome {
            Ok(DispatchOutcome::Envelope(v)) => v,
            other => panic!("unexpected: {other:?}"),
        };
        let warnings = value["result"]["warnings"]
            .as_array()
            .expect("warnings field should be a JSON array");
        assert_eq!(warnings.len(), 2);
        assert_eq!(warnings[0], "telemetry init failed");
        assert_eq!(warnings[1], "second");

        // Duplicate suppression — merging the same set again is a no-op.
        super::inject_warnings(
            &mut outcome,
            &["telemetry init failed".to_string(), "second".to_string()],
        );
        let value = match &outcome {
            Ok(DispatchOutcome::Envelope(v)) => v,
            other => panic!("unexpected: {other:?}"),
        };
        let warnings = value["result"]["warnings"].as_array().unwrap();
        assert_eq!(warnings.len(), 2, "duplicates must be suppressed");

        // Errors are untouched — `inject_warnings` only mutates envelope
        // results (the error path renders separately).
        let mut outcome: Result<DispatchOutcome, MxcError> =
            Err(MxcError::backend_unavailable("no backend"));
        super::inject_warnings(&mut outcome, &["ignored".to_string()]);
        assert!(outcome.is_err());
    }
}
