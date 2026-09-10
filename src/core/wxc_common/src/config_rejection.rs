// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared config-rejection reporting for the executors.
//!
//! Every executor that refuses a configuration reports the refusal the same
//! way: one telemetry event and one audit record, keyed on the same bounded
//! reason code. Keeping the mapping and the emit here is what stops `wxc` and
//! `lxc` from naming the same rejection differently on the same dashboard.

use crate::audit::{process_correlation_id, AuditEvent, AuditEventName, RejectionReason};
use crate::logger::Logger;
use crate::mxc_error::{MxcError, MxcErrorCode};

/// Report a refused configuration to telemetry and to the audit sink, so the
/// same rejection is machine-readable without parsing prose.
///
/// Unlike the ETW path this replaces, there is no initialisation-ordering
/// problem: `Logger` is constructed from CLI flags before any config is read,
/// so *every* rejection site — including "the input was not JSON at all" — can
/// reach it.
pub fn log_config_rejected(
    logger: &mut Logger,
    reason: RejectionReason,
    backend: &str,
    offending_field: &str,
    phase: &str,
) {
    let correlation_id = process_correlation_id();
    crate::telemetry::log_config_rejected(
        correlation_id,
        backend,
        reason.as_str(),
        offending_field,
        phase,
    );
    let record = AuditEvent::new(AuditEventName::ConfigRejected)
        // No sandbox exists yet — the config was refused — so M-ETW-7's
        // "correlation id (or identity if assigned)" resolves to the
        // correlation id here. It groups every rejection from one invocation
        // on a sink that concurrent sandboxes share.
        .str("correlation_id", correlation_id)
        .str("backend", backend)
        .str("reason", reason.as_str())
        .str_opt("offending_field", offending_field)
        .str_opt("phase", phase);
    logger.log_audit_event(&record);
}

/// Extract the bounded field path already rendered by the config parser.
///
/// Parse failures intentionally keep their rich human-readable message for
/// stderr or the state-aware response envelope. The audit event only needs the
/// path between the parser's backticks, never the surrounding error text.
pub fn offending_field_from_message(message: &str) -> &str {
    const PREFIX: &str = "Invalid configuration at `";
    let Some(start) = message.find(PREFIX) else {
        return "";
    };
    let field = &message[start + PREFIX.len()..];
    field.split('`').next().unwrap_or("")
}

/// Map an [`MxcError`] to its bounded [`RejectionReason`].
///
/// Driven by the error's own `code`, which is already an exhaustive closed set —
/// no message-text matching.
pub fn config_rejection_reason_for(error: &MxcError) -> Option<RejectionReason> {
    match error.code {
        MxcErrorCode::MalformedRequest => Some(RejectionReason::SchemaViolation),
        MxcErrorCode::MalformedId => Some(RejectionReason::IdentityShapeInvalid),
        MxcErrorCode::PolicyValidation => Some(RejectionReason::UnsupportedFieldForBackend),
        MxcErrorCode::UnsupportedContainment => Some(RejectionReason::UnsupportedContainment),
        MxcErrorCode::UnsupportedPhase => Some(RejectionReason::UnsupportedPhase),
        MxcErrorCode::BackendUnavailable
        | MxcErrorCode::StaleId
        | MxcErrorCode::NotProvisioned
        | MxcErrorCode::NotStarted
        | MxcErrorCode::AlreadyStarted
        | MxcErrorCode::AlreadyStopped
        | MxcErrorCode::BackendError => None,
    }
}

/// Report a dispatch failure that was a configuration refusal, and do nothing
/// for a failure that was not one.
///
/// Both executors call this on the same terminal path, so a refusal reaches the
/// audit sink whether the lifecycle ran on Windows or Linux.
pub fn log_config_rejection_for_outcome<T>(
    logger: &mut Logger,
    outcome: &Result<T, MxcError>,
    backend: &str,
    phase: &str,
) {
    let Err(error) = outcome else {
        return;
    };
    let Some(reason) = config_rejection_reason_for(error) else {
        return;
    };
    let offending_field = offending_field_from_message(error.message.as_str());
    log_config_rejected(logger, reason, backend, offending_field, phase);
}
