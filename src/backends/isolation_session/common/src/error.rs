// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed error model for the IsolationSession backend and the conversions to
//! `ScriptResponse` (one-shot) and `MxcError` (state-aware dispatch).

use wxc_common::models::ScriptResponse;
use wxc_common::mxc_error::MxcError;

use isolation_session_bindings::bindings::{IsoSessionError, IsoSessionResult};

/// Categorised errors from the IsolationSession backend.
#[derive(Debug)]
pub(super) enum IsolationSessionError {
    /// Caller-supplied container policy carries a field this backend does
    /// not support (filesystem rules, network rules, proxy).
    Policy(String),
    /// The in-proc `Windows.AI.IsolationSession` `IsoSessionOps` API is not
    /// available on this host (DLL not registered or the OS feature gate
    /// is off).
    ServiceUnavailable(String),
    /// A lifecycle step (register / provision / start / exec / stop /
    /// deprovision) returned a failure from the OS API.
    Lifecycle(String),
    /// The OS API could not find the provisionId — the sandbox has been
    /// deprovisioned (or never existed in this user's session). Surfaces
    /// as `MxcError::StaleId` at the dispatch boundary.
    Stale(String),
}

impl std::fmt::Display for IsolationSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(msg) => write!(f, "Isolation Session policy error: {}", msg),
            Self::ServiceUnavailable(msg) => {
                write!(f, "Isolation Session service unavailable: {}", msg)
            }
            Self::Lifecycle(msg) => write!(f, "Isolation Session lifecycle error: {}", msg),
            Self::Stale(msg) => write!(f, "Isolation Session stale id: {}", msg),
        }
    }
}

impl From<IsolationSessionError> for ScriptResponse {
    fn from(err: IsolationSessionError) -> Self {
        ScriptResponse::error(&err.to_string())
    }
}

pub(super) fn lifecycle_err(msg: impl Into<String>) -> IsolationSessionError {
    IsolationSessionError::Lifecycle(msg.into())
}

/// `HRESULT_FROM_WIN32(ERROR_NOT_FOUND)`. Every non-provision lifecycle op
/// (start / exec / stop / deprovision) surfaces this HRESULT when the
/// provisionId is unknown to the OS API; we promote it to `Stale` so a
/// deprovisioned `sandbox_id` reads as `MxcError::StaleId` at the dispatch
/// boundary, not a generic backend error.
const ERROR_NOT_FOUND_HRESULT: u32 = 0x80070490;

/// Formats an `IsoSessionError` into a typed `IsolationSessionError`.
/// Promotes `ERROR_NOT_FOUND` to `Stale`.
pub(super) fn format_iso_error(op: &str, err: &IsoSessionError) -> IsolationSessionError {
    // Read `Code()` first and propagate its failure honestly: it is the
    // classification-critical field (it drives the `Stale` promotion below),
    // so fabricating 0 on a getter failure would silently downgrade a stale
    // sandbox to a generic lifecycle error. `Message`/`Remediation` are
    // cosmetic and stay best-effort.
    let code = match err.Code() {
        Ok(c) => c.0 as u32,
        Err(e) => {
            // Code() is gone, but Message() may still carry signal — fold in
            // the best-effort text so the failure is diagnosable.
            let msg = err.Message().map(|h| h.to_string()).unwrap_or_default();
            return IsolationSessionError::Lifecycle(format!(
                "{} failed: {} (could not read HRESULT code: {})",
                op, msg, e
            ));
        }
    };
    let msg = err.Message().map(|h| h.to_string()).unwrap_or_default();
    let remediation = err.Remediation().map(|h| h.to_string()).unwrap_or_default();
    let suffix = if remediation.is_empty() {
        String::new()
    } else {
        format!(" -- remediation: {}", remediation)
    };
    let formatted = format!("{} failed: {} (HRESULT: {:#010x}){}", op, msg, code, suffix);
    if code == ERROR_NOT_FOUND_HRESULT {
        IsolationSessionError::Stale(formatted)
    } else {
        IsolationSessionError::Lifecycle(formatted)
    }
}

/// Checks the `Error` property of an `IsoSessionResult`. `Ok(())` on no
/// error; lifecycle (or stale) error with formatted details otherwise.
pub(super) fn check_result(
    result: &IsoSessionResult,
    op: &str,
) -> Result<(), IsolationSessionError> {
    let err = result
        .Error()
        .map_err(|e| lifecycle_err(format!("{}: get Error failed: {}", op, e)))?;
    let is_error = err
        .IsError()
        .map_err(|e| lifecycle_err(format!("{}: get IsError failed: {}", op, e)))?;
    if is_error {
        Err(format_iso_error(op, &err))
    } else {
        Ok(())
    }
}

pub(super) fn map_lifecycle_error(err: IsolationSessionError) -> MxcError {
    let message = err.to_string();
    match err {
        IsolationSessionError::Policy(_) => MxcError::policy_validation(message),
        IsolationSessionError::ServiceUnavailable(_) => MxcError::backend_unavailable(message),
        IsolationSessionError::Lifecycle(_) => MxcError::backend_error(message),
        IsolationSessionError::Stale(_) => MxcError::stale_id(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::mxc_error::MxcErrorCode;

    #[test]
    fn map_lifecycle_error_categorises_each_variant() {
        assert_eq!(
            map_lifecycle_error(IsolationSessionError::Policy("x".into())).code,
            MxcErrorCode::PolicyValidation,
        );
        assert_eq!(
            map_lifecycle_error(IsolationSessionError::ServiceUnavailable("x".into())).code,
            MxcErrorCode::BackendUnavailable,
        );
        assert_eq!(
            map_lifecycle_error(IsolationSessionError::Lifecycle("x".into())).code,
            MxcErrorCode::BackendError,
        );
        assert_eq!(
            map_lifecycle_error(IsolationSessionError::Stale("x".into())).code,
            MxcErrorCode::StaleId,
        );
    }

    #[test]
    fn error_not_found_hresult_constant_matches_win32() {
        // HRESULT_FROM_WIN32(ERROR_NOT_FOUND) = 0x80070000 | (1168 & 0xFFFF)
        // = 0x80070490. A regression in this constant would silently downgrade
        // stale-id detection to backend_error.
        use windows::Win32::Foundation::ERROR_NOT_FOUND;
        let expected = 0x8007_0000u32 | (ERROR_NOT_FOUND.0 & 0xFFFF);
        assert_eq!(ERROR_NOT_FOUND_HRESULT, expected);
        assert_eq!(ERROR_NOT_FOUND_HRESULT, 0x80070490);
    }
}
