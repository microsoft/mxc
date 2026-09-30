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
#[cfg(target_os = "windows")]
use wxc_common::state_aware_dispatch::TypedDispatchOutcome;
use wxc_common::state_aware_dispatch::{
    resolve_backend, run_state_aware as run_state_aware_fallback, DispatchOutcome,
};
use wxc_common::state_aware_request::{MxcRequest, ParsedStateAwareRequest, Phase};
use wxc_common::telemetry;

use crate::error::Error;
#[cfg(all(target_os = "windows", feature = "isolation_session"))]
use crate::state_aware_sdk::IsolationSessionProvisionMetadata;
#[cfg(target_os = "windows")]
use crate::state_aware_sdk::ProvisionMetadata;
use crate::state_aware_sdk::{
    ExecRequest, LifecycleRequest, LifecycleResult, OperationOptions, ProvisionRequest,
    ProvisionResult, SandboxId, StateAwareResult, ValidationResult,
};
use crate::{wrap_state_aware_telemetry_process_with_kind, TelemetryRegistration};

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

/// Reject a Windows Sandbox state-aware request when the caller has not enabled
/// experimental features. Applied by both the envelope dispatcher
/// ([`run_state_aware`]) and the streaming exec dispatcher ([`exec_state_aware`])
/// so no entry point can reach that development backend without the opt-in.
fn require_experimental_optin(
    backend: &wxc_common::models::ContainmentBackend,
    parsed: &ParsedStateAwareRequest,
) -> Result<(), MxcError> {
    if matches!(
        backend,
        wxc_common::models::ContainmentBackend::WindowsSandbox
    ) && !parsed.request().experimental_enabled
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
            let bound = wxc_common::state_aware_binding::bind_windows_sandbox(parsed)?;
            let mut runner = windows_sandbox_lifecycle::WindowsSandboxRunner::new();
            wxc_common::state_aware_dispatch::dispatch_state_aware(&mut runner, bound, dry_run)
        }
        #[cfg(all(target_os = "windows", feature = "isolation_session"))]
        wxc_common::models::ContainmentBackend::IsolationSession => {
            let bound = wxc_common::state_aware_binding::bind_isolation_session(parsed)?;
            let mut runner = isolation_session_common::IsolationSessionRunner::new();
            wxc_common::state_aware_dispatch::dispatch_state_aware(&mut runner, bound, dry_run)
        }
        #[cfg(all(target_os = "windows", feature = "wslc"))]
        wxc_common::models::ContainmentBackend::Wslc => {
            let bound = wxc_common::state_aware_binding::bind_wslc(parsed)?;
            let mut runner = wslc_common::WslcStateAwareRunner::new();
            wxc_common::state_aware_dispatch::dispatch_state_aware(&mut runner, bound, dry_run)
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

#[cfg(target_os = "windows")]
fn typed_dispatch_result<
    BackendProvisionMetadata,
    StartMetadata,
    StopMetadata,
    DeprovisionMetadata,
>(
    outcome: TypedDispatchOutcome<
        BackendProvisionMetadata,
        StartMetadata,
        StopMetadata,
        DeprovisionMetadata,
    >,
    mut map_provision_metadata: impl FnMut(
        BackendProvisionMetadata,
    ) -> Result<ProvisionMetadata, MxcError>,
) -> Result<StateAwareResult, MxcError> {
    match outcome {
        TypedDispatchOutcome::DryRun => Ok(StateAwareResult::empty()),
        TypedDispatchOutcome::Provision(result) => Ok(StateAwareResult::provision(
            result.sandbox_id,
            result
                .metadata
                .map(&mut map_provision_metadata)
                .transpose()?,
        )),
        TypedDispatchOutcome::Start(result) => {
            if result.metadata.is_some() {
                return Err(MxcError::backend_error(
                    "typed start metadata is not represented by the Rust SDK",
                ));
            }
            Ok(StateAwareResult::empty())
        }
        TypedDispatchOutcome::Stop(result) => {
            if result.metadata.is_some() {
                return Err(MxcError::backend_error(
                    "typed stop metadata is not represented by the Rust SDK",
                ));
            }
            Ok(StateAwareResult::empty())
        }
        TypedDispatchOutcome::Deprovision(result) => {
            if result.metadata.is_some() {
                return Err(MxcError::backend_error(
                    "typed deprovision metadata is not represented by the Rust SDK",
                ));
            }
            Ok(StateAwareResult::empty())
        }
        TypedDispatchOutcome::ExecCompleted { .. } => Err(MxcError::backend_error(
            "typed envelope dispatch returned an exec completion",
        )),
    }
}

#[cfg(target_os = "windows")]
fn no_provision_metadata<Metadata>(_: Metadata) -> Result<ProvisionMetadata, MxcError> {
    Err(MxcError::backend_error(
        "typed provision metadata is not represented by the Rust SDK",
    ))
}

fn run_state_aware_typed(
    parsed: ParsedStateAwareRequest,
    dry_run: bool,
) -> Result<StateAwareResult, MxcError> {
    let backend = resolve_backend(&parsed)?;
    require_experimental_optin(&backend, &parsed)?;
    match backend {
        #[cfg(target_os = "windows")]
        wxc_common::models::ContainmentBackend::WindowsSandbox => {
            let bound = wxc_common::state_aware_binding::bind_windows_sandbox(parsed)?;
            let mut runner = windows_sandbox_lifecycle::WindowsSandboxRunner::new();
            let outcome = wxc_common::state_aware_dispatch::dispatch_state_aware_typed(
                &mut runner,
                bound,
                dry_run,
            )?;
            typed_dispatch_result(outcome, no_provision_metadata)
        }
        #[cfg(all(target_os = "windows", feature = "isolation_session"))]
        wxc_common::models::ContainmentBackend::IsolationSession => {
            let bound = wxc_common::state_aware_binding::bind_isolation_session(parsed)?;
            let mut runner = isolation_session_common::IsolationSessionRunner::new();
            let outcome = wxc_common::state_aware_dispatch::dispatch_state_aware_typed(
                &mut runner,
                bound,
                dry_run,
            )?;
            typed_dispatch_result(outcome, |metadata| {
                Ok(ProvisionMetadata::IsolationSessionProvision(
                    IsolationSessionProvisionMetadata {
                        agent_user_name: metadata.agent_user_name,
                        agent_user_sid: metadata.agent_user_sid,
                        ephemeral_workspace_path: metadata.ephemeral_workspace_path,
                    },
                ))
            })
        }
        #[cfg(all(target_os = "windows", feature = "wslc"))]
        wxc_common::models::ContainmentBackend::Wslc => {
            let bound = wxc_common::state_aware_binding::bind_wslc(parsed)?;
            let mut runner = wslc_common::WslcStateAwareRunner::new();
            let outcome = wxc_common::state_aware_dispatch::dispatch_state_aware_typed(
                &mut runner,
                bound,
                dry_run,
            )?;
            typed_dispatch_result(outcome, no_provision_metadata)
        }
        #[cfg(not(all(target_os = "windows", feature = "wslc")))]
        wxc_common::models::ContainmentBackend::Wslc => Err(wslc_unavailable()),
        #[cfg(not(all(target_os = "windows", feature = "isolation_session")))]
        wxc_common::models::ContainmentBackend::IsolationSession => {
            Err(isolation_session_unavailable())
        }
        _ => {
            let _ = dry_run;
            Err(MxcError::unsupported_phase(format!(
                "backend {backend:?} does not implement state-aware lifecycle"
            )))
        }
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
            let bound = wxc_common::state_aware_binding::bind_windows_sandbox(parsed)?;
            let mut runner = windows_sandbox_lifecycle::WindowsSandboxRunner::new();
            let handle =
                wxc_common::state_aware_dispatch::dispatch_state_aware_exec(&mut runner, bound)?;
            Ok(Box::new(
                wxc_common::exec_stream::ExecSandboxProcess::from_exec_handle(handle)?,
            ))
        }
        #[cfg(all(target_os = "windows", feature = "isolation_session"))]
        wxc_common::models::ContainmentBackend::IsolationSession => {
            let bound = wxc_common::state_aware_binding::bind_isolation_session(parsed)?;
            let mut runner = isolation_session_common::IsolationSessionRunner::new();
            let handle =
                wxc_common::state_aware_dispatch::dispatch_state_aware_exec(&mut runner, bound)?;
            Ok(Box::new(
                wxc_common::exec_stream::ExecSandboxProcess::from_exec_handle(handle)?,
            ))
        }
        #[cfg(all(target_os = "windows", feature = "wslc"))]
        wxc_common::models::ContainmentBackend::Wslc => {
            let bound = wxc_common::state_aware_binding::bind_wslc(parsed)?;
            let mut runner = wslc_common::WslcStateAwareRunner::new();
            let handle =
                wxc_common::state_aware_dispatch::dispatch_state_aware_exec(&mut runner, bound)?;
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
            parsed.set_experimental_enabled(experimental);
            Ok(parsed)
        }
        Ok(MxcRequest::OneShot(_)) => Err(Error::from(MxcError::malformed_request(
            "expected a state-aware lifecycle request (with a 'phase' field), got a one-shot config",
        ))),
        Err(e) => Err(Error::from(parse_error_to_mxc(e))),
    }
}

fn normalize_sdk_state_aware(
    input: wxc_common::sdk_input::SdkStateAwareInput,
    experimental: bool,
    logger: &mut Logger,
) -> Result<ParsedStateAwareRequest, Error> {
    let mut parsed = wxc_common::config_parser::normalize_sdk_state_aware_request(input, logger)
        .map_err(|error| Error::from(MxcError::malformed_request(error.to_string())))?;
    parsed.set_experimental_enabled(experimental);
    Ok(parsed)
}

/// Map a [`config_parser::ParseError`](wxc_common::config_parser::ParseError) to
/// an [`MxcError`]. The state-aware arm already carries one; the decode,
/// version, and one-shot arms carry a `WxcError` that maps to `malformed_request`.
fn parse_error_to_mxc(e: wxc_common::config_parser::ParseError) -> MxcError {
    use wxc_common::config_parser::ParseError;
    match e {
        ParseError::StateAware(err) => err,
        ParseError::Decode(err)
        | ParseError::Version(err)
        | ParseError::OneShot(err)
        | ParseError::OneShotMalformed(err) => MxcError::malformed_request(err.to_string()),
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
    exec_state_aware_attached_parsed(parsed, &mut logger, host_is_interactive)
}

fn exec_state_aware_attached_parsed(
    parsed: ParsedStateAwareRequest,
    logger: &mut Logger,
    host_is_interactive: impl FnOnce() -> bool,
) -> Result<ExecOutcome, Error> {
    if !matches!(parsed.phase(), Phase::Exec) {
        return Err(Error::from(MxcError::malformed_request(format!(
            "an attached exec requires the exec phase, got {}",
            parsed.phase()
        ))));
    }

    exec_attached_gate(host_is_interactive)?;
    let phase = parsed.phase();
    let sandbox_id = parsed.sandbox_id().map(str::to_owned);
    let requested_sandbox_kind = parsed
        .request()
        .telemetry
        .as_ref()
        .and_then(|config| config.requested_sandbox_kind);
    let telemetry_active = parsed
        .request()
        .telemetry
        .as_ref()
        .map(|config| telemetry::init(config, logger))
        .unwrap_or(false);
    surface_attached_warnings(logger, |warning| {
        let _ = writeln!(std::io::stderr().lock(), "{warning}");
    });
    let backend = resolve_backend(&parsed)
        .map(|backend| backend.wire_name().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let correlation = phase_correlation(telemetry_active, phase, sandbox_id.as_deref());
    let started = std::time::Instant::now();
    let dispatched =
        with_attached_exec_claim(|| run_state_aware(parsed, false)).unwrap_or_else(|| {
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

fn run_state_aware_envelope(
    parsed: ParsedStateAwareRequest,
    dry_run: bool,
    logger: &mut Logger,
) -> Result<serde_json::Value, Error> {
    if matches!(parsed.phase(), Phase::Exec) && !dry_run {
        return Err(Error::from(MxcError::malformed_request(
            "the exec phase does not return an envelope; run it through one of the exec entry \
             points instead — attached to this process's stdio, or streaming with the caller \
             driving the pipes",
        )));
    }

    let phase = parsed.phase();
    let phase_name = phase.as_str();
    let sandbox_id = parsed.sandbox_id().map(str::to_owned);
    let requested_sandbox_kind = parsed
        .request()
        .telemetry
        .as_ref()
        .and_then(|config| config.requested_sandbox_kind);
    let telemetry_active = parsed
        .request()
        .telemetry
        .as_ref()
        .map(|config| telemetry::init(config, logger))
        .unwrap_or(false);
    let backend = resolve_backend(&parsed)
        .map(|backend| backend.wire_name().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let correlation = phase_correlation(telemetry_active, phase, sandbox_id.as_deref());
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
        DispatchOutcome::Envelope(value) => Ok(value),
        DispatchOutcome::ExecCompleted { exit_code } => {
            Ok(serde_json::json!({"result": {"exitCode": exit_code}}))
        }
    }
}

fn exec_state_aware_parsed(
    parsed: ParsedStateAwareRequest,
    logger: &mut Logger,
) -> Result<Box<dyn SandboxProcess>, Error> {
    if !matches!(parsed.phase(), Phase::Exec) {
        return Err(Error::from(MxcError::malformed_request(format!(
            "streaming exec requires the exec phase, got {}",
            parsed.phase()
        ))));
    }
    let phase = parsed.phase();
    let sandbox_id = parsed.sandbox_id().map(str::to_owned);
    let requested_sandbox_kind = parsed
        .request()
        .telemetry
        .as_ref()
        .and_then(|config| config.requested_sandbox_kind);
    let telemetry_active = parsed
        .request()
        .telemetry
        .as_ref()
        .map(|config| telemetry::init(config, logger))
        .unwrap_or(false);
    let mut telemetry_registration = TelemetryRegistration::new(telemetry_active);
    let backend = resolve_backend(&parsed)
        .map(|backend| backend.wire_name().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let correlation = phase_correlation(telemetry_active, phase, sandbox_id.as_deref());
    let init_warnings = logger.take_warnings();
    let started = std::time::Instant::now();
    match exec_state_aware(parsed) {
        Ok(process) => {
            let process = crate::ProcessWithWarnings::wrap(process, init_warnings);
            Ok(wrap_state_aware_telemetry_process_with_kind(
                process,
                telemetry_registration.transfer(),
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
                telemetry_registration.transfer(),
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

fn run_typed_state_aware(
    input: wxc_common::sdk_input::SdkStateAwareInput,
    options: OperationOptions,
    dry_run: bool,
) -> Result<StateAwareResult, Error> {
    let mut logger = Logger::new(Mode::Buffer);
    let parsed = normalize_sdk_state_aware(input, options.experimental, &mut logger)?;
    let phase = parsed.phase();
    let sandbox_id = parsed.sandbox_id().map(str::to_owned);
    let requested_sandbox_kind = parsed
        .request()
        .telemetry
        .as_ref()
        .and_then(|config| config.requested_sandbox_kind);
    let telemetry_active = parsed
        .request()
        .telemetry
        .as_ref()
        .map(|config| telemetry::init(config, &mut logger))
        .unwrap_or(false);
    let backend = resolve_backend(&parsed)
        .map(|backend| backend.wire_name().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let correlation = phase_correlation(telemetry_active, phase, sandbox_id.as_deref());
    let init_warnings = logger.take_warnings();
    let started = std::time::Instant::now();
    let mut outcome = run_state_aware_typed(parsed, dry_run);
    if let Ok(result) = &mut outcome {
        for warning in init_warnings {
            if !result.warnings.contains(&warning) {
                result.warnings.push(warning);
            }
        }
    }
    let status = outcome
        .as_ref()
        .map(|_| ())
        .map_err(|error| (*error).clone());
    match phase {
        Phase::Provision => {
            telemetry::correlation_state::on_typed_provision_result(
                telemetry_active,
                &correlation,
                outcome
                    .as_ref()
                    .ok()
                    .and_then(|result| result.sandbox_id.as_deref()),
            );
        }
        Phase::Deprovision => {
            if let Some(sandbox_id) = sandbox_id.as_deref() {
                telemetry::correlation_state::on_typed_deprovision_result(
                    sandbox_id, dry_run, &status,
                );
            }
        }
        _ => {}
    }
    telemetry::emit_sdk_state_aware_typed(
        telemetry_active,
        requested_sandbox_kind,
        telemetry::TelemetryContext {
            backend: &backend,
            phase: phase.as_str(),
            correlation_vector: &correlation,
        },
        &status,
        started.elapsed(),
    );
    outcome.map_err(Error::from)
}

/// Provision a state-aware sandbox from typed Rust SDK data.
pub fn provision_sandbox(
    request: ProvisionRequest,
    options: OperationOptions,
) -> Result<ProvisionResult, Error> {
    let input = request
        .into_sdk_input(options.telemetry_opt_in)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options, false)?
        .into_provision()
        .map_err(Error::from)
}

/// Validate a typed provision request without creating a sandbox.
pub fn validate_provision(
    request: ProvisionRequest,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    let input = request
        .into_sdk_input(options.telemetry_opt_in)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options, true)?
        .into_validation()
        .map_err(Error::from)
}

/// Start a provisioned state-aware sandbox from typed Rust SDK data.
pub fn start_sandbox(
    sandbox_id: &SandboxId,
    request: LifecycleRequest,
    options: OperationOptions,
) -> Result<LifecycleResult, Error> {
    let input = request
        .into_start_input(sandbox_id, options.telemetry_opt_in)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options, false)?
        .into_lifecycle()
        .map_err(Error::from)
}

/// Validate a typed start request without starting the sandbox.
pub fn validate_start(
    sandbox_id: &SandboxId,
    request: LifecycleRequest,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    let input = request
        .into_start_input(sandbox_id, options.telemetry_opt_in)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options, true)?
        .into_validation()
        .map_err(Error::from)
}

/// Stop a state-aware sandbox from typed Rust SDK data.
pub fn stop_sandbox(
    sandbox_id: &SandboxId,
    request: LifecycleRequest,
    options: OperationOptions,
) -> Result<LifecycleResult, Error> {
    let input = request
        .into_stop_input(sandbox_id, options.telemetry_opt_in)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options, false)?
        .into_lifecycle()
        .map_err(Error::from)
}

/// Validate a typed stop request without stopping the sandbox.
pub fn validate_stop(
    sandbox_id: &SandboxId,
    request: LifecycleRequest,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    let input = request
        .into_stop_input(sandbox_id, options.telemetry_opt_in)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options, true)?
        .into_validation()
        .map_err(Error::from)
}

/// Deprovision a state-aware sandbox from typed Rust SDK data.
pub fn deprovision_sandbox(
    sandbox_id: &SandboxId,
    request: LifecycleRequest,
    options: OperationOptions,
) -> Result<LifecycleResult, Error> {
    let input = request
        .into_deprovision_input(sandbox_id, options.telemetry_opt_in)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options, false)?
        .into_lifecycle()
        .map_err(Error::from)
}

/// Validate a typed deprovision request without deprovisioning the sandbox.
pub fn validate_deprovision(
    sandbox_id: &SandboxId,
    request: LifecycleRequest,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    let input = request
        .into_deprovision_input(sandbox_id, options.telemetry_opt_in)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options, true)?
        .into_validation()
        .map_err(Error::from)
}

/// Run a typed state-aware exec request as a live streaming process.
pub fn exec_sandbox_request(
    sandbox_id: &SandboxId,
    request: ExecRequest,
    options: OperationOptions,
) -> Result<Box<dyn SandboxProcess>, Error> {
    let input = request
        .into_sdk_input(sandbox_id, options.telemetry_opt_in)
        .map_err(Error::from)?;
    let mut logger = Logger::new(Mode::Buffer);
    let parsed = normalize_sdk_state_aware(input, options.experimental, &mut logger)?;
    exec_state_aware_parsed(parsed, &mut logger)
}

/// Run a typed state-aware exec request attached to this process's stdio.
pub fn exec_attached_request(
    sandbox_id: &SandboxId,
    request: ExecRequest,
    options: OperationOptions,
) -> Result<ExecOutcome, Error> {
    let input = request
        .into_sdk_input(sandbox_id, options.telemetry_opt_in)
        .map_err(Error::from)?;
    let mut logger = Logger::new(Mode::Buffer);
    let parsed = normalize_sdk_state_aware(input, options.experimental, &mut logger)?;
    exec_state_aware_attached_parsed(parsed, &mut logger, || {
        host_stdio_is_attachable(
            std::io::stdout().is_terminal(),
            std::io::stdin().is_terminal(),
        )
    })
}

/// Validate a typed state-aware exec request without running a workload.
pub fn validate_exec(
    sandbox_id: &SandboxId,
    request: ExecRequest,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    let input = request
        .into_sdk_input(sandbox_id, options.telemetry_opt_in)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options, true)?
        .into_validation()
        .map_err(Error::from)
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
/// `experimental` opts in to Windows Sandbox; without it that backend is
/// refused with `backend_unavailable` before any work is done. WSLC and
/// IsolationSession do not require the runtime opt-in.
pub fn run_state_aware_json(
    request_json: &str,
    dry_run: bool,
    experimental: bool,
) -> Result<String, Error> {
    let mut logger = Logger::new(Mode::Buffer);
    let parsed = parse_state_aware(request_json, experimental, &mut logger)?;
    let value = run_state_aware_envelope(parsed, dry_run, &mut logger)?;
    serde_json::to_string(&value).map_err(|error| {
        Error::from(MxcError::backend_error(format!(
            "serialising the response envelope failed: {error}"
        )))
    })
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
    exec_state_aware_parsed(parsed, &mut logger)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        FilesystemSection, NetworkAction, NetworkEgressSection, NetworkPeerSection,
        NetworkPortSection, NetworkProtocol, NetworkRuleSection, NetworkSection,
    };
    use crate::state_aware_sdk::{
        ExecRequest, LifecycleRequest, ProvisionRequest, SandboxId, StateAwareExecBackendOptions,
    };
    use wxc_common::mxc_error::MxcErrorCode;
    use wxc_common::sdk_input::SdkStateAwareInput;
    use wxc_common::state_aware_request::Phase;
    use wxc_common::telemetry::correlation_state::test_support::StoreDirGuard;

    fn request_intent(request: &ParsedStateAwareRequest) -> serde_json::Value {
        let mut value = serde_json::to_value(request.request()).unwrap();
        value.as_object_mut().unwrap().remove("source_contract");
        value
    }

    fn assert_typed_matches_exact(json: &str, input: SdkStateAwareInput) {
        let exact = parse_state_aware(json, false, &mut Logger::new(Mode::Buffer)).unwrap();
        let typed =
            normalize_sdk_state_aware(input, false, &mut Logger::new(Mode::Buffer)).unwrap();

        assert_eq!(typed.operation(), exact.operation());
        assert!(
            exact.request().source_contract.is_some(),
            "raw exact JSON must retain contract attribution"
        );
        assert_eq!(
            typed.request().source_contract,
            None,
            "typed SDK input has no external exact-contract source"
        );
        assert_eq!(request_intent(&typed), request_intent(&exact));
    }

    fn assert_typed_telemetry(input: SdkStateAwareInput, expected: bool) {
        let parsed =
            normalize_sdk_state_aware(input, false, &mut Logger::new(Mode::Buffer)).unwrap();
        assert_eq!(
            parsed
                .request()
                .telemetry
                .as_ref()
                .and_then(|telemetry| telemetry.enabled),
            Some(expected)
        );
    }

    #[test]
    fn typed_operation_options_preserve_telemetry_preference() {
        let sandbox_id = SandboxId::parse("wslc:abc").unwrap();
        for enabled in [true, false] {
            let options = OperationOptions::default().with_telemetry_opt_in(enabled);
            let telemetry_opt_in = options.telemetry_opt_in;
            let inputs = [
                ProvisionRequest::wslc("0.9.0-alpha", None, None)
                    .into_sdk_input(telemetry_opt_in)
                    .unwrap(),
                LifecycleRequest::new("0.9.0-alpha")
                    .into_start_input(&sandbox_id, telemetry_opt_in)
                    .unwrap(),
                LifecycleRequest::new("0.9.0-alpha")
                    .into_stop_input(&sandbox_id, telemetry_opt_in)
                    .unwrap(),
                LifecycleRequest::new("0.9.0-alpha")
                    .into_deprovision_input(&sandbox_id, telemetry_opt_in)
                    .unwrap(),
                ExecRequest::new("0.9.0-alpha", "echo hello")
                    .into_sdk_input(&sandbox_id, telemetry_opt_in)
                    .unwrap(),
            ];
            for input in inputs {
                assert_typed_telemetry(input, enabled);
            }
        }
    }

    #[test]
    fn typed_requests_match_exact_json_without_source_attribution() {
        assert_typed_matches_exact(
            r#"{
                "version":"0.9.0-alpha",
                "phase":"provision",
                "containment":"isolation_session",
                "network":{
                    "egress":{"default":"allow"},
                    "ingress":{"default":"allow","hostLoopback":"allow"}
                },
                "isolationSession":{"provision":{"appId":"example"}}
            }"#,
            ProvisionRequest::isolation_session("0.9.0-alpha", Some("example".to_string()))
                .into_sdk_input(None)
                .unwrap(),
        );

        assert_typed_matches_exact(
            r#"{
                "version":"0.9.0-alpha",
                "phase":"provision",
                "containment":"isolation_session",
                "network":{
                    "egress":{"default":"allow"},
                    "ingress":{"default":"allow","hostLoopback":"allow"}
                }
            }"#,
            ProvisionRequest::isolation_session("0.9.0-alpha", None)
                .into_sdk_input(None)
                .unwrap(),
        );

        assert_typed_matches_exact(
            r#"{
                "version":"0.9.0-alpha",
                "phase":"provision",
                "containment":"isolation_session",
                "network":{
                    "egress":{"default":"allow"},
                    "ingress":{"default":"allow","hostLoopback":"allow"}
                },
                "isolationSession":{"provision":{"appId":""}}
            }"#,
            ProvisionRequest::isolation_session("0.9.0-alpha", Some(String::new()))
                .into_sdk_input(None)
                .unwrap(),
        );

        assert_typed_matches_exact(
            r#"{
                "version":"0.9.0-alpha",
                "phase":"provision",
                "containment":"wslc",
                "wslc":{"provision":{"image":"python:3.12","imageTarPath":"image.tar"}}
            }"#,
            ProvisionRequest::wslc(
                "0.9.0-alpha",
                Some("python:3.12".to_string()),
                Some("image.tar".to_string()),
            )
            .into_sdk_input(None)
            .unwrap(),
        );

        assert_typed_matches_exact(
            r#"{
                "version":"0.9.0-alpha",
                "phase":"provision",
                "containment":"wslc"
            }"#,
            ProvisionRequest::wslc("0.9.0-alpha", None, None)
                .into_sdk_input(None)
                .unwrap(),
        );

        assert_typed_matches_exact(
            r#"{
                "version":"0.9.0-alpha",
                "phase":"provision",
                "containment":"wslc",
                "wslc":{"provision":{"image":"","imageTarPath":""}}
            }"#,
            ProvisionRequest::wslc("0.9.0-alpha", Some(String::new()), Some(String::new()))
                .into_sdk_input(None)
                .unwrap(),
        );

        let mut filesystem_provision =
            ProvisionRequest::wslc("0.9.0-alpha", Some("python:3.12".to_string()), None);
        filesystem_provision.set_filesystem(FilesystemSection {
            readwrite_paths: vec!["/tmp/readwrite".to_string()],
            readonly_paths: vec!["/tmp/readonly".to_string()],
            denied_paths: vec!["/tmp/denied".to_string()],
            clear_policy_on_exit: None,
        });
        assert_typed_matches_exact(
            r#"{
                "version":"0.9.0-alpha",
                "phase":"provision",
                "containment":"wslc",
                "wslc":{"provision":{"image":"python:3.12"}},
                "filesystem":{
                    "readwritePaths":["/tmp/readwrite"],
                    "readonlyPaths":["/tmp/readonly"],
                    "deniedPaths":["/tmp/denied"]
                }
            }"#,
            filesystem_provision.into_sdk_input(None).unwrap(),
        );

        for enabled in [true, false] {
            let telemetry_provision = ProvisionRequest::wslc("0.9.0-alpha", None, None);
            let json = format!(
                r#"{{
                    "version":"0.9.0-alpha",
                    "phase":"provision",
                    "containment":"wslc",
                    "telemetry":{{"enabled":{enabled}}}
                }}"#
            );
            assert_typed_matches_exact(
                &json,
                telemetry_provision.into_sdk_input(Some(enabled)).unwrap(),
            );
        }

        assert_typed_matches_exact(
            r#"{
                "version":"1.1.0-alpha",
                "phase":"provision",
                "containment":"windows_sandbox"
            }"#,
            ProvisionRequest::windows_sandbox("1.1.0-alpha")
                .into_sdk_input(None)
                .unwrap(),
        );

        for (json, input) in [
            (
                r#"{"version":"0.9.0-alpha","phase":"start","sandboxId":"iso:abc"}"#,
                LifecycleRequest::new("0.9.0-alpha")
                    .into_start_input(&SandboxId::parse("iso:abc").unwrap(), None)
                    .unwrap(),
            ),
            (
                r#"{"version":"0.9.0-alpha","phase":"stop","sandboxId":"iso:abc"}"#,
                LifecycleRequest::new("0.9.0-alpha")
                    .into_stop_input(&SandboxId::parse("iso:abc").unwrap(), None)
                    .unwrap(),
            ),
            (
                r#"{"version":"0.9.0-alpha","phase":"deprovision","sandboxId":"iso:abc"}"#,
                LifecycleRequest::new("0.9.0-alpha")
                    .into_deprovision_input(&SandboxId::parse("iso:abc").unwrap(), None)
                    .unwrap(),
            ),
        ] {
            assert_typed_matches_exact(json, input);
        }

        let mut exec = ExecRequest::new("0.9.0-alpha", "echo configured");
        exec.set_working_directory("C:\\work")
            .set_environment([("A", "one"), ("B", "two")])
            .inherit_default_env(false)
            .set_timeout(1234);
        assert_typed_matches_exact(
            r#"{
                "version":"0.9.0-alpha",
                "phase":"exec",
                "sandboxId":"iso:abc",
                "process":{
                    "commandLine":"echo configured",
                    "cwd":"C:\\work",
                    "env":["A=one","B=two"],
                    "inheritDefaultEnv":false,
                    "timeout":1234
                }
            }"#,
            exec.into_sdk_input(&SandboxId::parse("iso:abc").unwrap(), None)
                .unwrap(),
        );

        let mut peer = NetworkPeerSection::new("10.0.0.0/8");
        peer.except = Some(vec!["10.1.0.0/16".to_string()]);
        let network = NetworkSection {
            egress: Some(NetworkEgressSection {
                default: Some(NetworkAction::Deny),
                allow: Some(vec![NetworkRuleSection {
                    to: Some(vec![peer]),
                    ports: Some(vec![NetworkPortSection {
                        protocol: Some(NetworkProtocol::Tcp),
                        port: Some(80),
                        end_port: Some(81),
                    }]),
                }]),
                deny: None,
            }),
            ..Default::default()
        };
        let mut network_provision =
            ProvisionRequest::wslc("0.9.0-alpha", Some("python:3.12".to_string()), None);
        network_provision.set_network(network);
        assert_typed_matches_exact(
            r#"{
                "version":"0.9.0-alpha",
                "phase":"provision",
                "containment":"wslc",
                "wslc":{"provision":{"image":"python:3.12"}},
                "network":{
                    "egress":{
                        "default":"deny",
                        "allow":[{
                            "to":[{
                                "cidr":"10.0.0.0/8",
                                "except":["10.1.0.0/16"]
                            }],
                            "ports":[{
                                "protocol":"tcp",
                                "port":80,
                                "endPort":81
                            }]
                        }]
                    }
                }
            }"#,
            network_provision.into_sdk_input(None).unwrap(),
        );

        let mut empty_network_provision =
            ProvisionRequest::wslc("0.9.0-alpha", Some("python:3.12".to_string()), None);
        empty_network_provision.set_network(NetworkSection::default());
        assert_typed_matches_exact(
            r#"{
                "version":"0.9.0-alpha",
                "phase":"provision",
                "containment":"wslc",
                "wslc":{"provision":{"image":"python:3.12"}},
                "network":{}
            }"#,
            empty_network_provision.into_sdk_input(None).unwrap(),
        );

        let mut proxy_exec = ExecRequest::new("0.9.0-alpha", "echo proxied");
        proxy_exec.set_backend_options(StateAwareExecBackendOptions::Wslc {
            network_proxy: "http://127.0.0.1:8080".to_string(),
        });
        assert_typed_matches_exact(
            r#"{
                "version":"0.9.0-alpha",
                "phase":"exec",
                "sandboxId":"wslc:abc",
                "process":{"commandLine":"echo proxied"},
                "runtimeConfig":{"networkProxy":"http://127.0.0.1:8080"}
            }"#,
            proxy_exec
                .into_sdk_input(&SandboxId::parse("wslc:abc").unwrap(), None)
                .unwrap(),
        );
    }

    #[test]
    fn typed_provision_rejects_clear_policy_on_exit() {
        for enabled in [true, false] {
            let mut request = ProvisionRequest::wslc("0.9.0-alpha", None, None);
            request.set_filesystem(FilesystemSection {
                clear_policy_on_exit: Some(enabled),
                ..Default::default()
            });

            let error = request.into_sdk_input(None).unwrap_err();
            assert_eq!(error.code, MxcErrorCode::MalformedRequest);
            assert!(
                error.message.contains("clearPolicyOnExit"),
                "got: {}",
                error.message
            );
        }
    }

    #[test]
    fn version_failures_keep_the_state_aware_wire_error_code() {
        for json in [
            r#"{"version":"0.6.1-alpha","phase":"start","sandboxId":"wsb:abcd1234"}"#,
            r#"{"phase":"start","sandboxId":"wsb:abcd1234"}"#,
            r#"{"version":null,"phase":"start","sandboxId":"wsb:abcd1234"}"#,
        ] {
            let error = parse_state_aware(json, false, &mut Logger::new(Mode::Buffer)).unwrap_err();
            assert_eq!(error.code, crate::ErrorCode::MalformedRequest);
            assert!(error.message.contains("version"), "{}", error.message);
        }
    }

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
        let parsed = parse_state_aware(
            r#"{"version":"1.1.0-alpha","phase":"provision","containment":"windows_sandbox"}"#,
            false,
            &mut Logger::new(Mode::Buffer),
        )
        .unwrap();

        let error = run_state_aware(parsed, false).unwrap_err();

        assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
        assert!(error.message.contains("experimental"));
    }

    #[test]
    fn isolation_session_does_not_require_optin() {
        let parsed = parse_state_aware(
            r#"{"version":"0.9.0-alpha","phase":"provision","containment":"isolation_session","network":{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}}}"#,
            false,
            &mut Logger::new(Mode::Buffer),
        )
        .unwrap();

        assert!(require_experimental_optin(
            &wxc_common::models::ContainmentBackend::IsolationSession,
            &parsed
        )
        .is_ok());
    }

    #[test]
    fn wslc_does_not_require_optin() {
        let parsed = parse_state_aware(
            r#"{"version":"0.9.0-alpha","phase":"provision","containment":"wslc"}"#,
            false,
            &mut Logger::new(Mode::Buffer),
        )
        .unwrap();

        if let Err(error) = run_state_aware(parsed, true) {
            assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
            assert!(
                error.message.contains("wslc") || error.message.contains("WSLc"),
                "got: {}",
                error.message
            );
            assert!(
                !error.message.contains("experimental"),
                "got: {}",
                error.message
            );
        }
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
        let json = r#"{"version":"1.1.0-alpha","phase":"exec","sandboxId":"wsb:0123abcd",
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
        let json = r#"{"version":"1.1.0-alpha","phase":"exec","sandboxId":"wsb:0123abcd",
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
        let provision = r#"{"version":"0.9.0-alpha","phase":"provision","containment":"isolation_session",
            "network":{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}}}"#;

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
        let parsed = parse_state_aware(
            r#"{"version":"0.9.0-alpha","phase":"start",
                "sandboxId":"wslc:00000000000000000000000000000000"}"#,
            false,
            &mut Logger::new(Mode::Buffer),
        )
        .unwrap();

        let error = run_state_aware(parsed, false).unwrap_err();

        assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
        assert!(error
            .message
            .contains("compiled without the `wslc` feature"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn exec_state_aware_routes_windows_sandbox_exec_to_backend() {
        let parsed = parse_state_aware(
            r#"{"version":"1.1.0-alpha","phase":"exec","sandboxId":"wsb:abcd1234",
                "process":{"commandLine":"echo typed"}}"#,
            true,
            &mut Logger::new(Mode::Buffer),
        )
        .unwrap();

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

    fn backend_cases() -> [(&'static str, &'static str, bool); 3] {
        [
            (
                "windows_sandbox",
                "wsb:abcd1234",
                cfg!(target_os = "windows"),
            ),
            (
                "isolation_session",
                "iso:eyJ2ZXJzaW9uIjoxLCJhZ2VudFVzZXJOYW1lIjoid3hjLWFiY2QxMjM0In0",
                cfg!(all(target_os = "windows", feature = "isolation_session")),
            ),
            (
                "wslc",
                "wslc:00000000000000000000000000000000",
                cfg!(all(target_os = "windows", feature = "wslc")),
            ),
        ]
    }

    fn lifecycle_fixture(backend: &str, id: &str, phase: Phase) -> String {
        let mut value = serde_json::json!({
            "version": if backend == "windows_sandbox" {
                "1.1.0-alpha"
            } else {
                "0.9.0-alpha"
            },
            "phase": phase.as_str(),
        });
        if phase == Phase::Provision {
            value["containment"] = backend.into();
            if backend == "isolation_session" {
                value["network"] = serde_json::json!({
                    "egress": {"default": "allow"},
                    "ingress": {"default": "allow", "hostLoopback": "allow"}
                });
            }
        } else {
            value["sandboxId"] = id.into();
            if phase == Phase::Exec {
                value["process"] = serde_json::json!({"commandLine": "echo typed"});
            }
        }
        value.to_string()
    }

    #[test]
    fn every_backend_and_phase_keeps_required_gates_before_binding() {
        for (backend, id, available) in backend_cases() {
            for phase in [
                Phase::Provision,
                Phase::Start,
                Phase::Exec,
                Phase::Stop,
                Phase::Deprovision,
            ] {
                let json = lifecycle_fixture(backend, id, phase);
                let parsed =
                    parse_state_aware(&json, false, &mut Logger::new(Mode::Buffer)).unwrap();
                if backend == "windows_sandbox" {
                    let error = run_state_aware(parsed.clone(), true).unwrap_err();
                    assert_eq!(
                        error.code,
                        MxcErrorCode::BackendUnavailable,
                        "{backend} {phase}"
                    );
                    assert!(error.message.contains("experimental"));
                    let error = exec_state_aware(parsed)
                        .err()
                        .expect("opt-in must be required");
                    assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
                    assert!(error.message.contains("experimental"));
                }

                if !available {
                    let parsed =
                        parse_state_aware(&json, true, &mut Logger::new(Mode::Buffer)).unwrap();
                    let expected = if backend == "windows_sandbox" {
                        MxcErrorCode::UnsupportedPhase
                    } else {
                        MxcErrorCode::BackendUnavailable
                    };
                    assert_eq!(
                        run_state_aware(parsed.clone(), true).unwrap_err().code,
                        expected,
                        "{backend} {phase}"
                    );
                    assert_eq!(
                        exec_state_aware(parsed)
                            .err()
                            .expect("backend unavailable")
                            .code,
                        expected,
                        "{backend} {phase}"
                    );
                }
            }
        }
    }

    #[test]
    fn compiled_backends_bind_and_validate_every_phase_without_live_execution() {
        for (backend, id, available) in backend_cases() {
            if !available {
                continue;
            }
            for phase in [
                Phase::Provision,
                Phase::Start,
                Phase::Exec,
                Phase::Stop,
                Phase::Deprovision,
            ] {
                let json = lifecycle_fixture(backend, id, phase);
                let parsed =
                    parse_state_aware(&json, true, &mut Logger::new(Mode::Buffer)).unwrap();
                let outcome = run_state_aware(parsed.clone(), true)
                    .unwrap_or_else(|error| panic!("{backend} {phase}: {error}"));
                let DispatchOutcome::Envelope(envelope) = outcome else {
                    panic!("dry run must never execute {backend} {phase}");
                };
                assert_eq!(envelope, serde_json::json!({"result": {}}));
                if phase != Phase::Exec {
                    let error = exec_state_aware(parsed).err().expect("requires exec");
                    assert_eq!(error.code, MxcErrorCode::MalformedRequest);
                    assert_eq!(
                        error.message,
                        format!("streaming exec requires the exec phase, got {phase}")
                    );
                }
            }
        }
    }

    #[test]
    fn compiled_backends_validate_ids_after_binding_even_in_dry_run() {
        for (backend, id, available) in backend_cases() {
            if !available {
                continue;
            }
            let prefix = id.split_once(':').unwrap().0;
            let malformed = format!("{prefix}:invalid-body");
            for phase in [Phase::Start, Phase::Exec, Phase::Stop, Phase::Deprovision] {
                let json = lifecycle_fixture(backend, &malformed, phase);
                let parsed =
                    parse_state_aware(&json, true, &mut Logger::new(Mode::Buffer)).unwrap();
                assert_eq!(
                    run_state_aware(parsed.clone(), true).unwrap_err().code,
                    MxcErrorCode::MalformedId,
                    "{backend} {phase}"
                );
                if phase == Phase::Exec {
                    assert_eq!(
                        exec_state_aware(parsed).err().expect("malformed ID").code,
                        MxcErrorCode::MalformedId,
                        "{backend} {phase}"
                    );
                }
            }
        }
    }

    #[test]
    fn windows_sandbox_refuses_streaming_after_typed_binding_without_running() {
        for (backend, id, available) in backend_cases() {
            if !available || backend != "windows_sandbox" {
                continue;
            }
            let json = lifecycle_fixture(backend, id, Phase::Exec);
            let parsed = parse_state_aware(&json, true, &mut Logger::new(Mode::Buffer)).unwrap();
            let error = exec_state_aware(parsed)
                .err()
                .expect("cannot return streams");
            assert_eq!(error.code, MxcErrorCode::BackendError);
            assert!(error.message.contains("cannot return exec streams"));
            assert!(error.message.contains("Nothing has been run"));
        }
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
        let error = super::run_state_aware_json(
            r#"{"version":"1.1.0-alpha","phase":"provision"}"#,
            false,
            false,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest);
        assert_eq!(
            telemetry::classify_mxc_error(&MxcError::malformed_request(error.message)),
            FailureReason::ConfigError
        );

        // Provision of an experimental backend without --experimental —
        // `BackendUnavailable` → `InitError`; the shared classifier keeps
        // streaming and state-aware attribution in lockstep.
        let error = super::run_state_aware_json(
            r#"{"version":"1.1.0-alpha","phase":"provision","containment":"windows_sandbox"}"#,
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
                r#"{"version":"1.1.0-alpha","phase":"provision","containment":"windows_sandbox"}"#,
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
