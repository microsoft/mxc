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

use crate::error::Error;

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
        #[cfg(target_os = "linux")]
        wxc_common::models::ContainmentBackend::Lxc => {
            let mut runner = lxc_common::state_aware::LxcStateAwareRunner::new();
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
        #[cfg(target_os = "linux")]
        wxc_common::models::ContainmentBackend::Lxc => true,
        _ => false,
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
pub fn exec_state_aware_json(request_json: &str) -> Result<Box<dyn SandboxProcess>, Error> {
    let parsed = parse_state_aware(request_json)?;
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
}
