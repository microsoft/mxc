// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Telemetry and correlation-vector orchestration for the state-aware
//! lifecycle.
//!
//! This wraps [`crate::run_state_aware`] with everything a lifecycle dispatch
//! needs around it: process attribution (backend, sandbox kind, and phase), the
//! Microsoft Correlation Vector (MS-CV) for the phase, the effective policy
//! hash, the crash panic hook, the sandbox identity record, and the terminal
//! `emit_state_aware` event.
//!
//! It lives here — rather than in an executor binary — because every executor
//! that dispatches the state-aware lifecycle needs identical behavior. When
//! this logic lived in `wxc`'s `main.rs`, the `lxc` executor called
//! [`crate::run_state_aware`] directly and so silently produced no lifecycle
//! telemetry and no correlation vector: a Linux lifecycle was invisible to the
//! same dashboards that observed a Windows one. Sharing the orchestration is
//! what keeps the two executors from drifting apart again.

use std::time::Instant;

use wxc_common::audit::{AuditEvent, AuditEventName};
use wxc_common::config_rejection::log_config_rejection_for_outcome;
use wxc_common::logger::Logger;
use wxc_common::mxc_error::MxcError;
use wxc_common::policy_identity;
use wxc_common::state_aware_dispatch::{resolve_backend, DispatchOutcome};
use wxc_common::state_aware_request::ParsedStateAwareRequest;
use wxc_common::telemetry;

/// Marker logged for the `MXC.PolicyHash` identity field when the caller
/// supplied a `sandboxId` for this phase. This call happens before the
/// dispatcher validates the id against real backend state, so a caller-chosen
/// string that merely *looks* like an MXC-minted `iso:`/`wsb:`/`lxc:` id would
/// otherwise pass `redact_identity`'s shape check unverified. Since MXC has not
/// confirmed the id yet, the field records only that a caller-provided id was
/// present, not its value; the later, post-dispatch `SandboxIdentity` record is
/// unaffected and still discloses the real, backend-verified identity on
/// success.
const UNVERIFIED_SANDBOX_ID_MARKER: &str = "unverified";

/// Resolve the identity to report on `MXC.PolicyHash` for this phase.
pub fn state_aware_policy_identity(sandbox_id: Option<&str>) -> String {
    match sandbox_id.filter(|id| !id.is_empty()) {
        None => policy_identity::redact_identity("CLI"),
        Some(_) => UNVERIFIED_SANDBOX_ID_MARKER.to_string(),
    }
}

/// Resolve the sandbox id to report on `mxc.SandboxIdentity` for a completed
/// state-aware dispatch.
///
/// `provision` mints the id, so it is read out of the result envelope; every
/// later phase carries the id inbound. Returns `None` when the phase failed —
/// a failed dispatch produced no sandbox to identify, and emitting an identity
/// record for one would be a lie.
pub fn sandbox_id_for_identity_record(
    outcome: &Result<DispatchOutcome, MxcError>,
    incoming_sandbox_id: Option<&str>,
) -> Option<String> {
    let Ok(outcome) = outcome else {
        return None;
    };
    if let DispatchOutcome::Envelope(value) = outcome {
        if let Some(minted) = value
            .get("result")
            .and_then(|r| r.get("sandboxId"))
            .and_then(|v| v.as_str())
        {
            return Some(minted.to_string());
        }
    }
    incoming_sandbox_id.map(str::to_string)
}

/// Run a state-aware phase with full telemetry and correlation-vector
/// orchestration, returning the dispatch outcome for the caller to render.
///
/// The caller still owns the terminal behavior (flushing `logger`'s buffer,
/// writing the envelope to stdout, choosing an exit code) — only the
/// observability wrapper is shared. Telemetry is stable and independent of the
/// `--experimental` gate used by experimental containment backends, so the
/// caller decides activation and passes it in.
pub fn run_state_aware_with_telemetry(
    parsed: ParsedStateAwareRequest,
    dry_run: bool,
    telemetry_active: bool,
    logger: &mut Logger,
) -> Result<DispatchOutcome, MxcError> {
    // Resolve attribution (phase + backend) BEFORE dispatch consumes `parsed`.
    let phase = parsed.phase.as_str();
    // Whether this invocation is the provision phase: its `sandbox_id` doesn't
    // exist yet, so it always seeds a fresh base rather than deriving one.
    let is_provision = phase == "provision";
    // `sandbox_id` for non-provision phases, from which the lifecycle's shared
    // correlation base is derived internally. Captured before `dispatch`
    // consumes `parsed`. `None` for provision.
    let sandbox_id = if is_provision {
        None
    } else {
        parsed.sandbox_id.clone()
    };
    let resolved_backend = resolve_backend(&parsed).ok();
    let backend = resolved_backend
        .as_ref()
        .map(|b| b.wire_name())
        .unwrap_or("unknown");
    let requested_sandbox_kind = parsed
        .request
        .telemetry
        .as_ref()
        .and_then(|config| config.requested_sandbox_kind);

    // This phase's Microsoft Correlation Vector (MS-CV), purely internal to
    // MXC — no caller supplies or relays one. `provision` seeds a fresh
    // vector (persisted post-dispatch below, once its `sandbox_id` exists);
    // every later phase recalls that persisted lifecycle root and spins a
    // child off it. Empty when telemetry is inactive.
    let correlation = telemetry::correlation_state::pre_dispatch_vector(
        telemetry_active,
        is_provision,
        sandbox_id.as_deref(),
    );

    // Attribute out-of-band emit paths (the console-control handler installed in
    // `main`, and the panic hook installed just below) to the resolved backend
    // and the lifecycle phase, and install a crash-telemetry panic hook for this
    // dispatch — mirroring the one-shot path, which the `-> !` entry points
    // bypass. The shared hook chains the previous hook (default stderr backtrace
    // still prints) and is panic-free.
    if telemetry_active {
        if let Some(containment) = resolved_backend.as_ref() {
            telemetry::set_process_context_with_kind(containment, requested_sandbox_kind);
        }
        telemetry::set_process_phase(phase);
        // Stash this phase's correlation vector so out-of-band events
        // (panic / cancellation) carry the same cV as the terminal emit below.
        telemetry::set_process_correlation_vector(&correlation);
        telemetry::install_panic_hook();
    }

    let started = Instant::now();
    // State-aware dispatch bypasses the one-shot runner funnel, so anchor the
    // effective lifecycle policy here before the request is consumed.
    let phase_config = parsed.experimental_raw.as_ref().and_then(|raw| {
        resolved_backend.as_ref().and_then(|backend| {
            raw.get(backend.wire_name())
                .and_then(|section| section.get(phase))
        })
    });
    let diagnostics_active = logger.has_diagnostic_sink();
    if telemetry_active || diagnostics_active {
        let policy_hash =
            policy_identity::state_aware_policy_hash(&parsed.request, backend, phase, phase_config);
        let identity = state_aware_policy_identity(parsed.sandbox_id.as_deref());
        telemetry::log_policy_hash(&identity, &policy_hash, &parsed.request.schema_version);
        if diagnostics_active {
            let record = AuditEvent::new(AuditEventName::PolicyHash)
                .str("backend", backend)
                .str("policy_hash", &policy_hash)
                .str("config_schema_version", &parsed.request.schema_version);
            logger.log_audit_event(&record);
        }
    }

    // Publish the driver's diagnostic sinks (--log-file, and the diagnostic
    // console pipe on Windows) on this thread so a backend whose
    // `StatefulSandboxBackend::exec` signature has no `Logger` parameter
    // can inherit them via `Logger::inherit_thread_diagnostic_sink` instead
    // of building a throwaway `Logger::new(Mode::Buffer)` and silently
    // dropping every record. The returned guard clears the sink when it
    // drops -- including if `run_state_aware` panics -- so we never leak
    // duplicated handles across independent invocations even on an unwind.
    let diag_sink_guard = logger.install_thread_diagnostic_sink();
    let outcome = crate::run_state_aware(parsed, dry_run);
    drop(diag_sink_guard);
    let elapsed = started.elapsed();

    // Persist (provision) or forget (deprovision) this lifecycle's correlation
    // root now that the outcome — and, for provision, the freshly minted
    // `sandbox_id` — is known.
    if is_provision {
        telemetry::correlation_state::on_provision_outcome(
            telemetry_active,
            &correlation,
            &outcome,
        );
    } else if phase == "deprovision" {
        if let Some(id) = sandbox_id.as_deref() {
            telemetry::correlation_state::on_deprovision_outcome(
                telemetry_active,
                id,
                dry_run,
                &outcome,
            );
        }
    }

    // Record the sandbox identity join key. For `isolation_session` the
    // `sandboxId` tail is the OS-side `provisionId`, which is what joins an MXC
    // record to the `Microsoft.Windows.IsolationSession` OS records. Emitted on
    // success only: a failed phase produced no sandbox to identify.
    if let Some(sandbox_id) = sandbox_id_for_identity_record(&outcome, sandbox_id.as_deref()) {
        let record = AuditEvent::new(AuditEventName::SandboxIdentity)
            .str("backend", backend)
            .str("identity", &policy_identity::redact_identity(&sandbox_id))
            .str_opt("phase", phase);
        logger.log_audit_event(&record);
    }

    log_config_rejection_for_outcome(logger, &outcome, backend, phase);

    // Emit lifecycle telemetry (and shut the provider down) before the caller
    // flushes the diagnostic buffer / envelope. Terminal path — safe to shut
    // down here.
    telemetry::emit_state_aware_with_kind(
        telemetry_active,
        requested_sandbox_kind,
        telemetry::TelemetryContext {
            backend,
            phase,
            correlation_vector: &correlation,
        },
        &outcome,
        elapsed,
    );

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identity_record_reads_the_minted_id_out_of_a_provision_envelope() {
        let outcome = Ok(DispatchOutcome::Envelope(
            json!({"result": {"sandboxId": "iso:wxc-abcd1234"}}),
        ));
        assert_eq!(
            sandbox_id_for_identity_record(&outcome, None).as_deref(),
            Some("iso:wxc-abcd1234")
        );
    }

    #[test]
    fn identity_record_falls_back_to_the_inbound_id_for_later_phases() {
        // Later phases return an envelope with no `sandboxId` (the client
        // already has it), so the inbound id is the one to report.
        let outcome = Ok(DispatchOutcome::Envelope(json!({"result": {}})));
        assert_eq!(
            sandbox_id_for_identity_record(&outcome, Some("iso:wxc-abcd1234")).as_deref(),
            Some("iso:wxc-abcd1234")
        );

        // Exec completes without an envelope at all.
        let exec = Ok(DispatchOutcome::ExecCompleted { exit_code: 0 });
        assert_eq!(
            sandbox_id_for_identity_record(&exec, Some("iso:wxc-abcd1234")).as_deref(),
            Some("iso:wxc-abcd1234")
        );
    }

    #[test]
    fn no_identity_record_for_a_failed_phase() {
        // A failed dispatch produced no sandbox to identify; claiming one would
        // be a lie.
        let outcome = Err(MxcError::backend_unavailable("nope"));
        assert!(sandbox_id_for_identity_record(&outcome, Some("iso:wxc-abcd1234")).is_none());
    }

    #[test]
    fn entra_provision_ids_are_never_logged_verbatim() {
        // `state_aware.rs::provision` sets `provision_id = user.upn` for Entra
        // sandboxes, so the sandboxId tail is a real user identifier. It must not
        // reach a log file in any recoverable form.
        let outcome = Ok(DispatchOutcome::Envelope(
            json!({"result": {"sandboxId": "iso:alice@contoso.com"}}),
        ));
        let id = sandbox_id_for_identity_record(&outcome, None).expect("id");
        let rendered = policy_identity::redact_identity(&id);
        assert!(!rendered.contains("alice"), "got: {rendered}");
        assert!(!rendered.contains('@'), "got: {rendered}");
        assert_eq!(
            rendered,
            policy_identity::ENTRA_UPN_MARKER,
            "got: {rendered}"
        );
    }

    #[test]
    fn state_aware_policy_identity_uses_sandbox_join_key() {
        assert_eq!(state_aware_policy_identity(None), "CLI");
        // An empty id is no id at all.
        assert_eq!(state_aware_policy_identity(Some("")), "CLI");
        // A caller-supplied sandbox id is not yet backend-verified at this
        // logging call site, so it must not be echoed back even when it
        // happens to match the shape of an MXC-minted id.
        assert_eq!(
            state_aware_policy_identity(Some("wsb:0123abcd")),
            UNVERIFIED_SANDBOX_ID_MARKER
        );
        assert_eq!(
            state_aware_policy_identity(Some("some-caller-chosen-string")),
            UNVERIFIED_SANDBOX_ID_MARKER
        );
    }
}
