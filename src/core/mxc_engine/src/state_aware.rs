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

use wxc_common::logger::{Logger, Mode};
use wxc_common::mxc_error::MxcError;
use wxc_common::sandbox_process::SandboxProcess;
use wxc_common::state_aware_dispatch::{
    resolve_backend, run_state_aware as run_state_aware_fallback, DispatchOutcome,
};
use wxc_common::state_aware_request::{MxcRequest, ParsedStateAwareRequest, Phase};
use wxc_common::telemetry;

use crate::error::Error;
use crate::wrap_state_aware_telemetry_process;

fn phase_correlation(active: bool, phase: Phase, incoming: Option<&str>) -> String {
    if !active {
        return String::new();
    }
    if phase != Phase::Provision {
        if let Some(value) =
            incoming.filter(|value| telemetry::correlation_vector::is_relayable(value))
        {
            return telemetry::correlation_vector::spin(value);
        }
    }
    telemetry::correlation_vector::seed()
}

fn inject_correlation_vector(
    outcome: &mut Result<DispatchOutcome, MxcError>,
    correlation_vector: &str,
) {
    if let Ok(DispatchOutcome::Envelope(value)) = outcome {
        if let Some(result) = value
            .get_mut("result")
            .and_then(|result| result.as_object_mut())
        {
            result.insert(
                "correlationVector".to_string(),
                serde_json::Value::String(correlation_vector.to_string()),
            );
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
    if matches!(
        backend,
        wxc_common::models::ContainmentBackend::WindowsSandbox
            | wxc_common::models::ContainmentBackend::IsolationSession
    ) && !parsed.request.experimental_enabled
    {
        return Err(MxcError::backend_unavailable(format!(
            "{backend:?} is an experimental backend; pass --experimental to enable state-aware \
             dispatch against it"
        )));
    }
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
    match backend {
        #[cfg(all(target_os = "windows", feature = "isolation_session"))]
        wxc_common::models::ContainmentBackend::IsolationSession => {
            let mut runner = isolation_session_common::IsolationSessionRunner::new();
            let handle =
                wxc_common::state_aware_dispatch::dispatch_state_aware_exec(&mut runner, parsed)?;
            Ok(Box::new(
                wxc_common::exec_stream::ExecSandboxProcess::from_exec_handle(handle),
            ))
        }
        _ => Err(MxcError::unsupported_phase(format!(
            "backend {:?} does not implement the state-aware lifecycle",
            backend
        ))),
    }
}

/// Parse a state-aware request JSON string into a [`ParsedStateAwareRequest`],
/// rejecting a one-shot config (no `phase`).
fn parse_state_aware(request_json: &str) -> Result<ParsedStateAwareRequest, Error> {
    let mut logger = Logger::new(Mode::Buffer);
    match wxc_common::config_parser::load_mxc_request_from_json(request_json, &mut logger) {
        Ok(MxcRequest::StateAware(parsed)) => Ok(parsed),
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

/// Run a state-aware lifecycle request from a JSON string, returning the
/// response-envelope JSON string.
///
/// Handles the envelope phases (provision / start / stop / deprovision) and a
/// dry-run of any phase. A non-dry-run `exec` streams its output and is rejected
/// here — drive it through [`exec_state_aware_json`] instead.
pub fn run_state_aware_json(request_json: &str, dry_run: bool) -> Result<String, Error> {
    let parsed = parse_state_aware(request_json)?;

    if matches!(parsed.phase, Phase::Exec) && !dry_run {
        return Err(Error::from(MxcError::malformed_request(
            "the exec phase streams its output; use the streaming exec entry point, not the \
             envelope entry point",
        )));
    }

    let phase = parsed.phase;
    let phase_name = phase.as_str();
    let incoming_correlation = parsed.correlation_vector.clone();
    let mut logger = Logger::new(Mode::Buffer);
    let telemetry_active = parsed
        .request
        .telemetry
        .as_ref()
        .map(|config| telemetry::init(config, &mut logger))
        .unwrap_or(false);
    let backend = resolve_backend(&parsed)
        .map(|backend| backend.wire_name().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let correlation = phase_correlation(telemetry_active, phase, incoming_correlation.as_deref());
    let started = std::time::Instant::now();
    let mut outcome = run_state_aware(parsed, dry_run);
    if phase == Phase::Provision && telemetry_active {
        inject_correlation_vector(&mut outcome, &correlation);
    }
    telemetry::emit_sdk_state_aware(
        telemetry_active,
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
pub fn exec_state_aware_json(request_json: &str) -> Result<Box<dyn SandboxProcess>, Error> {
    let parsed = parse_state_aware(request_json)?;
    if !matches!(parsed.phase, Phase::Exec) {
        return Err(Error::from(MxcError::malformed_request(format!(
            "streaming exec requires the exec phase, got {}",
            parsed.phase
        ))));
    }
    let phase = parsed.phase;
    let incoming_correlation = parsed.correlation_vector.clone();
    let mut logger = Logger::new(Mode::Buffer);
    let telemetry_active = parsed
        .request
        .telemetry
        .as_ref()
        .map(|config| telemetry::init(config, &mut logger))
        .unwrap_or(false);
    let backend = resolve_backend(&parsed)
        .map(|backend| backend.wire_name().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let correlation = phase_correlation(telemetry_active, phase, incoming_correlation.as_deref());
    let started = std::time::Instant::now();
    match exec_state_aware(parsed) {
        Ok(process) => Ok(wrap_state_aware_telemetry_process(
            process,
            telemetry_active,
            backend,
            phase.as_str().to_string(),
            correlation,
            started,
        )),
        Err(error) => {
            let outcome = Err(error.clone());
            telemetry::emit_sdk_state_aware(
                telemetry_active,
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

    #[test]
    fn inactive_telemetry_does_not_create_a_correlation_vector() {
        assert_eq!(
            phase_correlation(false, Phase::Provision, None),
            String::new()
        );
    }

    #[test]
    fn later_phase_spins_a_relayable_correlation_vector() {
        let incoming = telemetry::correlation_vector::seed();
        let correlation = phase_correlation(true, Phase::Start, Some(&incoming));

        assert_ne!(correlation, incoming);
        assert!(correlation.starts_with(incoming.split('.').next().unwrap_or_default()));
        assert!(telemetry::correlation_vector::is_relayable(&correlation));
    }

    #[test]
    fn provision_result_receives_the_correlation_vector() {
        let mut outcome = Ok(DispatchOutcome::Envelope(serde_json::json!({
            "result": { "sandboxId": "iso:abc" }
        })));

        inject_correlation_vector(&mut outcome, "AAAAAAAAAAAAAAAAAAAAAA.0");

        let value = match outcome {
            Ok(DispatchOutcome::Envelope(value)) => value,
            other => panic!("unexpected outcome: {other:?}"),
        };
        assert_eq!(
            value["result"]["correlationVector"],
            "AAAAAAAAAAAAAAAAAAAAAA.0"
        );
    }

    #[test]
    fn experimental_backend_requires_flag() {
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
        assert!(error.message.contains("--experimental"));
    }
}
