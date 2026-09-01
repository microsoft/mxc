// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed error model for the IsolationSession backend and the conversions to
//! `ScriptResponse` (one-shot) and `MxcError` (state-aware dispatch).
//!
//! Failures raised by the IsolationSession API are carried **structurally**
//! — operation, HRESULT, message and remediation stay separate fields all the
//! way to the wire, so a caller can react to them without parsing prose. The
//! one-shot path has no structured envelope, so [`IsolationSessionError`]'s
//! `Display` folds the same components back into one human-readable string.

use wxc_common::models::ScriptResponse;
use wxc_common::mxc_error::{ApiFailure, MxcError, MxcErrorCode};

use isolation_session_bindings::bindings::{IsoSessionError, IsoSessionResult};

/// Interface-qualified names of the API operations this backend invokes.
///
/// These are the values that reach the wire as `error.operation`. They are
/// deliberately constants rather than formatted strings: the field must stay
/// low-cardinality and free of call parameters so it can be grouped in
/// telemetry.
pub(super) mod op {
    pub(crate) const CO_INCREMENT_MTA_USAGE: &str = "Com.CoIncrementMTAUsage";
    pub(crate) const CO_GET_APARTMENT_TYPE: &str = "Com.CoGetApartmentType";

    pub(crate) const ACTIVATE: &str = "IsoSessionOps.ActivateInstance";
    /// The app-scoped provisioning overload, preferred when the host advertises
    /// `IsoSessionFeature::AppScopedRegistration`.
    pub(crate) const ADD_USER: &str = "IsoSessionOps.AddUserAsync2";
    /// The legacy provisioning overload, used on hosts that do not support the
    /// app-scoped one. Reported instead of [`ADD_USER`] so telemetry attributes
    /// a failure to the overload actually invoked.
    pub(crate) const ADD_USER_LEGACY: &str = "IsoSessionOps.AddUserAsync";
    pub(crate) const START_SESSION: &str = "IsoSessionOps.StartSessionAsync";
    pub(crate) const RUN_PROCESS: &str = "IsoSessionOps.RunProcessWithOptionsAsync";
    pub(crate) const STOP_SESSION: &str = "IsoSessionOps.StopSessionAsync";
    pub(crate) const REMOVE_USER: &str = "IsoSessionOps.RemoveUserAsync";

    pub(crate) const OPTIONS_NEW: &str = "IsoSessionProcessOptions.new";
    pub(crate) const OPTIONS_TIMEOUT: &str = "IsoSessionProcessOptions.SetTimeoutMilliseconds";
    pub(crate) const OPTIONS_WORKING_DIR: &str = "IsoSessionProcessOptions.SetWorkingDirectory";
    pub(crate) const OPTIONS_INTERACTIVE: &str = "IsoSessionProcessOptions.SetInteractiveConsole";
    pub(crate) const OPTIONS_REDIRECT_STDIN: &str =
        "IsoSessionProcessOptions.SetRedirectStandardInput";
    pub(crate) const OPTIONS_REDIRECT_STDOUT: &str =
        "IsoSessionProcessOptions.SetRedirectStandardOutput";
    pub(crate) const OPTIONS_REDIRECT_STDERR: &str =
        "IsoSessionProcessOptions.SetRedirectStandardError";
    pub(crate) const OPTIONS_ENVIRONMENT: &str = "IsoSessionProcessOptions.Environment";
}

/// `HRESULT_FROM_WIN32(ERROR_NOT_FOUND)`. Every non-provision lifecycle op
/// (start / exec / stop / deprovision) surfaces this HRESULT when the
/// agent user is unknown to the OS API; we promote it to `Stale` so a
/// deprovisioned `sandbox_id` reads as `MxcError::StaleId` at the dispatch
/// boundary, not a generic backend error.
const ERROR_NOT_FOUND_HRESULT: u32 = 0x80070490;

/// `CLASS_E_CLASSNOTAVAILABLE` — the runtime class is known but cannot be
/// activated on this OS build.
const CLASS_E_CLASSNOTAVAILABLE_HRESULT: u32 = 0x80040111;

/// `REGDB_E_CLASSNOTREG` — the runtime class is not registered at all.
const REGDB_E_CLASSNOTREG_HRESULT: u32 = 0x80040154;

/// `E_NOINTERFACE` — the activator produced an object that does not implement
/// the requested interface. In this backend that is the signature of a
/// winmd/MSI version-pin mismatch: `IsoSessionApp.dll` activated, but the
/// interface IID the Preview WinMD was built against does not match the IID
/// the MSI-installed runtime exposes. See [`activation_error`].
const E_NOINTERFACE_HRESULT: u32 = 0x80004002;

/// Renders an HRESULT for the wire `nativeCode` field.
fn format_native_code(code: u32) -> String {
    format!("{code:#010x}")
}

/// Substituted when the API reports a failure but supplies no message text.
///
/// `message` is a required field on the wire envelope. Before the components
/// were split out it was always non-empty because it embedded the operation
/// and HRESULT; now that those have their own fields, nothing backfills it, so
/// a failed or empty `Message()` getter would otherwise surface as
/// `"message": ""`.
const NO_API_MESSAGE: &str = "the IsolationSession API reported a failure without a message";

/// The components of a failure raised by the IsolationSession API, kept
/// separate rather than pre-formatted.
///
/// `operation` is always present — this type only describes failures where an
/// API call was in flight. `code` is absent only when the status could not be
/// read; `remediation` only when the API supplied one. `message` is likewise
/// never empty — see [`IsoApiFailure::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IsoApiFailure {
    /// Interface-qualified operation, e.g. `IsoSessionOps.AddUserAsync`.
    pub operation: String,
    /// The underlying HRESULT, when it could be read.
    pub code: Option<u32>,
    /// The bare human-readable message — no operation prefix, no HRESULT, no
    /// remediation folded in. Never empty.
    pub message: String,
    /// The API-supplied "how to fix it" hint, when it provided one.
    pub remediation: Option<String>,
}

impl IsoApiFailure {
    /// Builds a failure, normalising the two best-effort text fields.
    ///
    /// `Message()` and `Remediation()` are fallible getters that the API may
    /// also answer with an empty string, so both arrive as `Option`. An absent
    /// or empty `message` is replaced with [`NO_API_MESSAGE`] — the wire
    /// requires the field, and no other field backfills it. An absent or empty
    /// `remediation` stays absent, since that field is optional on the wire.
    ///
    /// Normalising here rather than at each call site is what keeps the
    /// guarantee from having to be re-stated (and re-remembered) per branch.
    fn new(
        operation: &str,
        code: Option<u32>,
        message: Option<String>,
        remediation: Option<String>,
    ) -> Self {
        Self {
            operation: operation.to_string(),
            code,
            message: message
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| NO_API_MESSAGE.to_string()),
            remediation: remediation.filter(|r| !r.is_empty()),
        }
    }

    /// Folds the components back into one human-readable string.
    ///
    /// Only the one-shot path consumes this: it has no structured error
    /// envelope, so the string is the sole carrier of the detail. The
    /// state-aware path reads the fields directly and must not use this.
    fn describe(&self) -> String {
        let mut out = format!("{}: {}", self.operation, self.message);
        if let Some(code) = self.code {
            out.push_str(&format!(" (HRESULT: {})", format_native_code(code)));
        }
        if let Some(remediation) = &self.remediation {
            out.push_str(&format!(" -- remediation: {remediation}"));
        }
        out
    }

    /// Builds the wire error, attaching the structured components.
    fn into_mxc_error(self, code: MxcErrorCode) -> MxcError {
        let mut failure = ApiFailure::new(self.operation);
        if let Some(hresult) = self.code {
            failure = failure.with_native_code(format_native_code(hresult));
        }
        let mut error = MxcError::new(code, self.message).with_api_failure(failure);
        if let Some(remediation) = self.remediation {
            error = error.with_remediation(remediation);
        }
        error
    }
}

/// A lifecycle step failed. The arms exist so that a failure MXC raises itself
/// *cannot* carry an API operation: there was no API call in flight, so there
/// is nothing to name.
#[derive(Debug)]
pub(super) enum LifecycleFailure {
    /// An IsolationSession API call failed.
    Api(IsoApiFailure),
    /// MXC's own machinery failed (thread creation, console handles, and
    /// other work that is not an API call). Message-only by construction.
    Internal(String),
    /// MXC declined to proceed and can say what the caller should do instead.
    /// The remediation is required — a refusal with no way forward is
    /// [`LifecycleFailure::Internal`].
    Refused {
        message: String,
        remediation: String,
    },
}

/// Categorised errors from the IsolationSession backend.
#[derive(Debug)]
pub(super) enum IsolationSessionError {
    /// Caller-supplied container policy carries a field this backend does
    /// not support (filesystem rules, network rules, proxy). Raised by MXC
    /// before any API call, so it carries no structured components.
    Policy(String),
    /// The in-proc IsolationSession runtime API is not available on this
    /// host (not registered, or the OS feature gate is off). This is a real
    /// COM activation failure, so it does carry the operation and the
    /// HRESULT.
    ServiceUnavailable(IsoApiFailure),
    /// A lifecycle step (provision / start / exec / stop / deprovision)
    /// failed.
    Lifecycle(LifecycleFailure),
    /// The OS API could not find the agent user — the sandbox has been
    /// deprovisioned (or never existed in this user's session). Surfaces
    /// as `MxcError::StaleId` at the dispatch boundary.
    Stale(IsoApiFailure),
}

impl std::fmt::Display for IsolationSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(msg) => write!(f, "Isolation Session policy error: {}", msg),
            Self::ServiceUnavailable(failure) => {
                write!(
                    f,
                    "Isolation Session service unavailable: {}",
                    failure.describe()
                )
            }
            Self::Lifecycle(LifecycleFailure::Api(failure)) => {
                write!(
                    f,
                    "Isolation Session lifecycle error: {}",
                    failure.describe()
                )
            }
            Self::Lifecycle(LifecycleFailure::Internal(msg)) => {
                write!(f, "Isolation Session lifecycle error: {}", msg)
            }
            Self::Lifecycle(LifecycleFailure::Refused {
                message,
                remediation,
            }) => {
                write!(
                    f,
                    "Isolation Session lifecycle error: {message} -- remediation: {remediation}"
                )
            }
            Self::Stale(failure) => {
                write!(f, "Isolation Session stale id: {}", failure.describe())
            }
        }
    }
}

impl From<IsolationSessionError> for ScriptResponse {
    fn from(err: IsolationSessionError) -> Self {
        ScriptResponse::error(&err.to_string())
    }
}

/// An MXC-side lifecycle failure, with no API operation in flight.
pub(super) fn lifecycle_err(msg: impl Into<String>) -> IsolationSessionError {
    IsolationSessionError::Lifecycle(LifecycleFailure::Internal(msg.into()))
}

/// A transport failure: the API call itself could not be completed (the
/// channel dropped, the object is gone, a property could not be read).
///
/// `step` names the sub-operation within `operation` — the operation stays
/// the lifecycle call in flight so a consumer has a stable value to branch
/// on, while the finer detail rides in the message.
pub(super) fn transport_err(
    operation: &str,
    step: &str,
    err: &windows_core::Error,
) -> IsolationSessionError {
    IsolationSessionError::Lifecycle(LifecycleFailure::Api(IsoApiFailure::new(
        operation,
        Some(err.code().0 as u32),
        Some(compose_transport_message(step, &err.message())),
        None,
    )))
}

/// Joins `step` with the platform's text, tolerating an absent text.
///
/// `windows_core::Error::message()` answers with an empty string for an
/// HRESULT that has no entry in the OS message table (`0xDEADBEEF`, and any
/// custom facility code a service invents). Formatting unconditionally would
/// then yield a dangling `"wait failed: "` — non-empty, so it sails past the
/// empty-message guard in [`IsoApiFailure::new`] and reaches the caller as a
/// trailing colon with no explanation. Fall back to the step alone instead.
fn compose_transport_message(step: &str, platform_message: &str) -> String {
    if platform_message.is_empty() {
        step.to_string()
    } else {
        format!("{step}: {platform_message}")
    }
}

/// Maps an activation failure of the in-proc IsolationSession runtime API to
/// `ServiceUnavailable`.
///
/// Pure over the HRESULT: activation itself depends on whether the host
/// supports isolation sessions, but this mapping does not, so it stays
/// testable on any machine.
pub(super) fn activation_error(code: u32, detail: &str) -> IsolationSessionError {
    let message =
        if code == CLASS_E_CLASSNOTAVAILABLE_HRESULT || code == REGDB_E_CLASSNOTREG_HRESULT {
            "the in-proc IsolationSession runtime API is not available on this OS build. Ensure \
         the OS feature gate is enabled and the platform supports isolation sessions."
                .to_string()
        } else if code == E_NOINTERFACE_HRESULT {
            "the co-located IsoSessionApp.dll activated but returned an object that does not \
         implement the expected IsolationSession interface. This is the classic winmd/MSI \
         version-pin mismatch: the Preview WinMD wxc-exec was built against and the \
         MSI-installed IsolationSession runtime were produced from different OS versions, so \
         their interface IIDs differ. Rebuild the MSI and the \
         Microsoft.Windows.AI.IsolationSession.SDK nuget from the same OS commit."
                .to_string()
        } else {
            format!("IsolationSession runtime API activation failed: {detail}")
        };
    IsolationSessionError::ServiceUnavailable(IsoApiFailure::new(
        op::ACTIVATE,
        Some(code),
        Some(message),
        None,
    ))
}

/// The refusal for a caller already in a single-threaded apartment.
///
/// The apartment query succeeded and no API call was in flight, so the refusal
/// names no operation and carries no status.
pub(super) fn sta_refusal() -> IsolationSessionError {
    IsolationSessionError::Lifecycle(LifecycleFailure::Refused {
        message: "this thread is in a single-threaded apartment, where the lifecycle deadlocks"
            .to_string(),
        remediation: "Call from a multi-threaded apartment; a UI application must marshal this \
                      onto a background thread."
            .to_string(),
    })
}

/// The adjacent lifted activation payload is missing, so the version-pinned
/// MSI-installed IsolationSession runtime cannot be bound.
///
/// Raised for the `None` arm of
/// [`super::regfree::activate_from_adjacent_shim`]. MXC deliberately does
/// **not** fall back to the inbox `System32` runtime here — silently binding a
/// different, unversioned binary set is exactly the failure mode this design
/// exists to prevent — so the missing payload surfaces as a hard,
/// actionable error instead.
#[cfg(feature = "lifted_msi")]
pub(super) fn lifted_payload_missing(operation: &str) -> IsolationSessionError {
    IsolationSessionError::ServiceUnavailable(IsoApiFailure::new(
        operation,
        Some(REGDB_E_CLASSNOTREG_HRESULT),
        Some(
            "IsolationSession lifted activation was not taken: IsoSessionApp.dll and \
             IsoSession.manifest are not co-located with this executable, so the \
             version-pinned MSI-installed IsolationSession runtime could not be bound. MXC will \
             not silently fall back to the inbox System32 runtime."
                .to_string(),
        ),
        Some(
            "Rebuild against the Microsoft.Windows.AI.IsolationSession.SDK NuGet so \
             IsoSessionApp.dll and its stamped IsoSession.manifest are staged beside the host."
                .to_string(),
        ),
    ))
}

/// Whether an `ERROR_NOT_FOUND` from this operation means "the sandbox is
/// gone".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StalePromotion {
    /// Non-provision operations address an existing agent user, so
    /// `ERROR_NOT_FOUND` means that user is gone.
    Eligible,
    /// Provision *mints* the agent user. There is no `sandboxId` yet, so
    /// reporting `stale_id` — whose remediation is "re-provision; treat the
    /// id as dead" — would be incoherent.
    NotEligible,
}

/// Classifies an API failure whose components have already been extracted.
///
/// Pure, and deliberately separate from [`format_iso_error`]: `IsoSessionError`
/// is a WinRT interface obtained by activation and cannot be constructed in a
/// unit test, so the classification rules would otherwise be untestable.
///
/// The `ERROR_NOT_FOUND` promotion is **semantic-path only** by design. The
/// in-proc client maps its internal codes to standard HRESULTs when it builds
/// the `IsoSessionError`, and that mapping is what gives `0x80070490` the
/// meaning "agent user not provisioned". A transport-path HRESULT of the same
/// value has no such provenance — it could be any "not found" from activation
/// or RPC — so promoting it would emit a false `stale_id` and tell the caller
/// to destroy a healthy sandbox. Do not "fix" the asymmetry.
pub(super) fn classify_api_failure(
    failure: IsoApiFailure,
    promotion: StalePromotion,
) -> IsolationSessionError {
    if failure.code == Some(ERROR_NOT_FOUND_HRESULT) && promotion == StalePromotion::Eligible {
        IsolationSessionError::Stale(failure)
    } else {
        IsolationSessionError::Lifecycle(LifecycleFailure::Api(failure))
    }
}

/// Reads an `IsoSessionError`'s components and classifies them.
///
/// Thin by design — the rules live in [`classify_api_failure`] and
/// [`unreadable_code_failure`]; this only crosses the WinRT boundary.
pub(super) fn format_iso_error(
    operation: &str,
    err: &IsoSessionError,
    promotion: StalePromotion,
) -> IsolationSessionError {
    // Both getters are best-effort and may also answer with an empty string,
    // so both collapse to `None` here and `IsoApiFailure::new` decides what an
    // absent value means for each field.
    let message = err
        .Message()
        .map(|h| h.to_string())
        .ok()
        .filter(|m| !m.is_empty());
    let remediation = err.Remediation().map(|h| h.to_string()).ok();

    // `Code()` is the classification-critical field: it drives the `Stale`
    // promotion, so fabricating 0 when the getter fails would silently
    // downgrade a stale sandbox to a generic lifecycle error. Report the
    // read failure instead and leave the code unknown, which also keeps
    // `nativeCode` off the wire rather than carrying the getter's own
    // HRESULT — that would describe reading the field, not the operation.
    match err.Code() {
        Ok(code) => classify_api_failure(
            IsoApiFailure::new(operation, Some(code.0 as u32), message, remediation),
            promotion,
        ),
        Err(read_err) => {
            unreadable_code_failure(operation, message, remediation, &read_err.to_string())
        }
    }
}

/// Builds the failure for the case where the status getter itself failed.
///
/// Pure, and split out of [`format_iso_error`] for the same reason
/// [`classify_api_failure`] is: that function takes an `IsoSessionError`, a
/// WinRT interface obtained by activation, so nothing inside it can be reached
/// from a unit test.
///
/// With no usable status there is nothing to classify on, so this never
/// promotes to `Stale` — the note is the only signal that classification is
/// degraded, which is why it is folded into the message rather than dropped.
fn unreadable_code_failure(
    operation: &str,
    message: Option<String>,
    remediation: Option<String>,
    read_err: &str,
) -> IsolationSessionError {
    let note = format!("could not read HRESULT code: {read_err}");
    let message = Some(match message {
        Some(m) => format!("{m} ({note})"),
        None => note,
    });
    IsolationSessionError::Lifecycle(LifecycleFailure::Api(IsoApiFailure::new(
        operation,
        None,
        message,
        remediation,
    )))
}

/// Checks the `Error` property of an `IsoSessionResult`. `Ok(())` on no
/// error; lifecycle (or stale) error with structured details otherwise.
pub(super) fn check_result(
    result: &IsoSessionResult,
    operation: &str,
    promotion: StalePromotion,
) -> Result<(), IsolationSessionError> {
    let err = result
        .Error()
        .map_err(|e| transport_err(operation, "get Error failed", &e))?;
    let is_error = err
        .IsError()
        .map_err(|e| transport_err(operation, "get IsError failed", &e))?;
    if is_error {
        Err(format_iso_error(operation, &err, promotion))
    } else {
        Ok(())
    }
}

pub(super) fn map_lifecycle_error(err: IsolationSessionError) -> MxcError {
    match err {
        IsolationSessionError::Policy(msg) => MxcError::policy_validation(msg),
        IsolationSessionError::ServiceUnavailable(failure) => {
            failure.into_mxc_error(MxcErrorCode::BackendUnavailable)
        }
        IsolationSessionError::Lifecycle(LifecycleFailure::Internal(msg)) => {
            MxcError::backend_error(msg)
        }
        IsolationSessionError::Lifecycle(LifecycleFailure::Refused {
            message,
            remediation,
        }) => MxcError::backend_error(message).with_remediation(remediation),
        IsolationSessionError::Lifecycle(LifecycleFailure::Api(failure)) => {
            failure.into_mxc_error(MxcErrorCode::BackendError)
        }
        IsolationSessionError::Stale(failure) => failure.into_mxc_error(MxcErrorCode::StaleId),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_failure(code: Option<u32>) -> IsoApiFailure {
        IsoApiFailure::new(
            op::STOP_SESSION,
            code,
            Some("agent user not found".to_string()),
            Some("Re-provision the sandbox.".to_string()),
        )
    }

    // ── Best-effort text fields are normalised at construction ───────────

    /// `message` is required on the wire, and since the operation and status
    /// moved to their own fields nothing else backfills it. A failed or empty
    /// `Message()` getter must not reach a consumer as `"message": ""`.
    #[test]
    fn absent_or_empty_api_message_is_replaced_with_a_stand_in() {
        for supplied in [None, Some(String::new())] {
            let failure = IsoApiFailure::new(op::ADD_USER, Some(0x80004005), supplied, None);
            assert_eq!(failure.message, NO_API_MESSAGE);
            assert!(!failure.message.is_empty());
        }
    }

    #[test]
    fn a_supplied_api_message_is_kept_verbatim() {
        let failure = IsoApiFailure::new(
            op::ADD_USER,
            Some(0x80004005),
            Some("The provision was not found.".to_string()),
            None,
        );
        assert_eq!(failure.message, "The provision was not found.");
    }

    /// `remediation` is optional on the wire, so an empty one stays absent
    /// rather than being stood in for -- the opposite treatment to `message`,
    /// and the reason both go through one constructor.
    #[test]
    fn absent_or_empty_remediation_stays_absent() {
        for supplied in [None, Some(String::new())] {
            let failure = IsoApiFailure::new(op::ADD_USER, None, None, supplied);
            assert_eq!(failure.remediation, None);
        }
    }

    /// The stand-in must survive to the wire, not just to the internal type.
    #[test]
    fn stand_in_message_reaches_the_envelope() {
        let mapped = map_lifecycle_error(classify_api_failure(
            IsoApiFailure::new(op::STOP_SESSION, Some(0x80004005), None, None),
            StalePromotion::Eligible,
        ));
        assert_eq!(mapped.message, NO_API_MESSAGE);
        assert!(!mapped.to_envelope().message.is_empty());
    }

    // ── Constants pinned to the OS values they mirror ────────────────────

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

    #[test]
    fn activation_hresult_constants_match_win32() {
        use windows::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, REGDB_E_CLASSNOTREG};
        assert_eq!(
            CLASS_E_CLASSNOTAVAILABLE_HRESULT,
            CLASS_E_CLASSNOTAVAILABLE.0 as u32
        );
        assert_eq!(REGDB_E_CLASSNOTREG_HRESULT, REGDB_E_CLASSNOTREG.0 as u32);
    }

    // ── nativeCode rendering ─────────────────────────────────────────────

    #[test]
    fn native_code_renders_as_lowercase_hex() {
        assert_eq!(format_native_code(0x80070490), "0x80070490");
        assert_eq!(format_native_code(0x8004005a), "0x8004005a");
    }

    // ── Stale promotion ──────────────────────────────────────────────────

    #[test]
    fn error_not_found_promotes_to_stale_for_non_provision_ops() {
        let err = classify_api_failure(
            api_failure(Some(ERROR_NOT_FOUND_HRESULT)),
            StalePromotion::Eligible,
        );
        assert!(matches!(err, IsolationSessionError::Stale(_)));
        assert_eq!(map_lifecycle_error(err).code, MxcErrorCode::StaleId);
    }

    /// Provision mints the agent user, so it has no sandbox id to be stale.
    #[test]
    fn error_not_found_does_not_promote_for_provision() {
        let mut failure = api_failure(Some(ERROR_NOT_FOUND_HRESULT));
        failure.operation = op::ADD_USER.to_string();
        let err = classify_api_failure(failure, StalePromotion::NotEligible);
        assert!(matches!(
            err,
            IsolationSessionError::Lifecycle(LifecycleFailure::Api(_))
        ));
        assert_eq!(map_lifecycle_error(err).code, MxcErrorCode::BackendError);
    }

    #[test]
    fn other_hresults_do_not_promote_to_stale() {
        let err = classify_api_failure(api_failure(Some(0x80004005)), StalePromotion::Eligible);
        assert_eq!(map_lifecycle_error(err).code, MxcErrorCode::BackendError);
    }

    /// A transport-path `ERROR_NOT_FOUND` has none of the provenance that
    /// gives the semantic one its meaning, so it must stay `backend_error`.
    #[test]
    fn transport_error_not_found_does_not_promote_to_stale() {
        let err = windows_core::Error::from_hresult(windows_core::HRESULT(
            ERROR_NOT_FOUND_HRESULT as i32,
        ));
        let mapped = map_lifecycle_error(transport_err(op::STOP_SESSION, "call failed", &err));
        assert_eq!(mapped.code, MxcErrorCode::BackendError);
        assert_eq!(mapped.native_code(), Some("0x80070490"));
    }

    // ── Transport messages tolerate an absent platform text ──────────────

    /// An HRESULT with no OS message-table entry yields an empty
    /// `message()`. Joining unconditionally produced `"wait failed: "`, which
    /// is non-empty and therefore slipped past the guard in
    /// `IsoApiFailure::new` — the caller got a trailing colon and no
    /// explanation.
    #[test]
    fn transport_message_without_platform_text_is_the_step_alone() {
        assert_eq!(compose_transport_message("wait failed", ""), "wait failed");
    }

    #[test]
    fn transport_message_with_platform_text_keeps_the_step_prefix() {
        assert_eq!(
            compose_transport_message("wait failed", "Unspecified error"),
            "wait failed: Unspecified error"
        );
    }

    /// End-to-end over a real `windows_core::Error`: `0xDEADBEEF` has no
    /// message-table entry on any Windows build, so this pins the whole path
    /// rather than just the helper.
    #[test]
    fn transport_failure_with_unmapped_hresult_has_no_dangling_separator() {
        let err = windows_core::Error::from_hresult(windows_core::HRESULT(0xDEADBEEF_u32 as i32));
        assert!(
            err.message().is_empty(),
            "0xDEADBEEF unexpectedly has a message-table entry: {:?}",
            err.message()
        );
        let mapped = map_lifecycle_error(transport_err(op::ADD_USER, "wait failed", &err));
        assert_eq!(mapped.message, "wait failed");
        assert!(!mapped.message.ends_with(": "));
        assert_eq!(mapped.native_code(), Some("0xdeadbeef"));
    }

    // ── The status getter itself can fail ────────────────────────────────

    /// With no readable status there is nothing to classify on, so the
    /// failure stays a plain lifecycle error and `nativeCode` stays off the
    /// wire — carrying the getter's own HRESULT would describe reading the
    /// field, not the operation.
    #[test]
    fn unreadable_code_keeps_the_message_and_omits_native_code() {
        let err = unreadable_code_failure(
            op::STOP_SESSION,
            Some("agent user not found".to_string()),
            Some("Re-provision the sandbox.".to_string()),
            "RPC_E_DISCONNECTED",
        );
        let mapped = map_lifecycle_error(err);
        assert_eq!(mapped.code, MxcErrorCode::BackendError);
        assert_eq!(
            mapped.message,
            "agent user not found (could not read HRESULT code: RPC_E_DISCONNECTED)"
        );
        assert_eq!(mapped.operation(), Some("IsoSessionOps.StopSessionAsync"));
        assert_eq!(mapped.native_code(), None);
        assert_eq!(
            mapped.remediation.as_deref(),
            Some("Re-provision the sandbox.")
        );
    }

    /// Even an `ERROR_NOT_FOUND`-shaped failure cannot promote here: the code
    /// is precisely what could not be read.
    #[test]
    fn unreadable_code_never_promotes_to_stale() {
        let err = unreadable_code_failure(op::STOP_SESSION, None, None, "RPC_E_DISCONNECTED");
        assert!(matches!(
            err,
            IsolationSessionError::Lifecycle(LifecycleFailure::Api(_))
        ));
        let mapped = map_lifecycle_error(err);
        assert_eq!(mapped.code, MxcErrorCode::BackendError);
        assert_eq!(
            mapped.message,
            "could not read HRESULT code: RPC_E_DISCONNECTED"
        );
    }

    // ── Field population and the MxcError invariant ──────────────────────

    #[test]
    fn semantic_failure_populates_all_structured_fields() {
        let err = classify_api_failure(
            api_failure(Some(ERROR_NOT_FOUND_HRESULT)),
            StalePromotion::Eligible,
        );
        let mapped = map_lifecycle_error(err);
        assert_eq!(mapped.code, MxcErrorCode::StaleId);
        assert_eq!(mapped.message, "agent user not found");
        assert_eq!(mapped.operation(), Some("IsoSessionOps.StopSessionAsync"));
        assert_eq!(mapped.native_code(), Some("0x80070490"));
        assert_eq!(
            mapped.remediation.as_deref(),
            Some("Re-provision the sandbox.")
        );
    }

    #[test]
    fn transport_failure_populates_operation_and_native_code_only() {
        let err = windows_core::Error::from_hresult(windows_core::HRESULT(0x800706ba_u32 as i32));
        let mapped = map_lifecycle_error(transport_err(op::ADD_USER, "call failed", &err));
        assert_eq!(mapped.code, MxcErrorCode::BackendError);
        assert_eq!(mapped.operation(), Some("IsoSessionOps.AddUserAsync2"));
        assert_eq!(mapped.native_code(), Some("0x800706ba"));
        assert_eq!(mapped.remediation.as_deref(), None);
        assert!(mapped.message.starts_with("call failed: "));
    }

    #[test]
    fn activation_failure_populates_operation_and_native_code() {
        let mapped = map_lifecycle_error(activation_error(
            CLASS_E_CLASSNOTAVAILABLE_HRESULT,
            "unused",
        ));
        assert_eq!(mapped.code, MxcErrorCode::BackendUnavailable);
        assert_eq!(mapped.operation(), Some("IsoSessionOps.ActivateInstance"));
        assert_eq!(mapped.native_code(), Some("0x80040111"));
        assert!(mapped.message.contains("not available"));
    }

    #[test]
    fn unknown_activation_hresult_keeps_the_underlying_detail() {
        let mapped = map_lifecycle_error(activation_error(0x80004005, "catastrophic failure"));
        assert_eq!(mapped.code, MxcErrorCode::BackendUnavailable);
        assert_eq!(mapped.native_code(), Some("0x80004005"));
        assert!(mapped.message.contains("catastrophic failure"));
    }

    /// `E_NOINTERFACE` from activation is the winmd/MSI version-pin mismatch
    /// signature: the mapping must name that cause rather than echo the bare
    /// COM detail, so the message points at rebuilding both from one commit.
    #[test]
    fn e_nointerface_activation_names_version_pin_mismatch() {
        let mapped = map_lifecycle_error(activation_error(E_NOINTERFACE_HRESULT, "ignored"));
        assert_eq!(mapped.code, MxcErrorCode::BackendUnavailable);
        assert_eq!(mapped.native_code(), Some("0x80004002"));
        assert!(mapped.message.contains("version-pin mismatch"));
        assert!(mapped.message.contains("same OS commit"));
    }

    /// The hard error raised when the lifted payload is absent must carry the
    /// class-not-registered code, an operation, a message that refuses the
    /// inbox fallback, and an actionable remediation.
    #[cfg(feature = "lifted_msi")]
    #[test]
    fn lifted_payload_missing_is_a_hard_actionable_error() {
        let mapped = map_lifecycle_error(lifted_payload_missing(op::ACTIVATE));
        assert_eq!(mapped.code, MxcErrorCode::BackendUnavailable);
        assert_eq!(mapped.operation(), Some("IsoSessionOps.ActivateInstance"));
        assert_eq!(mapped.native_code(), Some("0x80040154"));
        assert!(mapped.message.contains("not silently fall back"));
        assert!(mapped
            .remediation
            .as_deref()
            .is_some_and(|r| r.contains("IsolationSession.SDK NuGet")));
    }

    #[test]
    fn mxc_internal_failure_carries_no_structured_fields() {
        let mapped = map_lifecycle_error(lifecycle_err("create stdout relay: out of memory"));
        assert_eq!(mapped.code, MxcErrorCode::BackendError);
        assert_eq!(mapped.operation(), None);
        assert_eq!(mapped.native_code(), None);
        assert_eq!(mapped.remediation.as_deref(), None);
    }

    #[test]
    fn policy_failure_carries_no_structured_fields() {
        let mapped = map_lifecycle_error(IsolationSessionError::Policy("no proxy".into()));
        assert_eq!(mapped.code, MxcErrorCode::PolicyValidation);
        assert_eq!(mapped.operation(), None);
        assert_eq!(mapped.native_code(), None);
        assert_eq!(mapped.remediation.as_deref(), None);
    }

    /// A status describes the call that produced it, so it never reaches the
    /// wire without the operation it belongs to.
    #[test]
    fn every_variant_upholds_the_field_invariant() {
        let com = windows_core::Error::from_hresult(windows_core::HRESULT(0x80004005_u32 as i32));
        let cases = vec![
            IsolationSessionError::Policy("x".into()),
            lifecycle_err("internal"),
            transport_err(op::RUN_PROCESS, "call failed", &com),
            activation_error(REGDB_E_CLASSNOTREG_HRESULT, "x"),
            classify_api_failure(api_failure(Some(0x80004005)), StalePromotion::Eligible),
            classify_api_failure(
                api_failure(Some(ERROR_NOT_FOUND_HRESULT)),
                StalePromotion::Eligible,
            ),
            classify_api_failure(api_failure(None), StalePromotion::Eligible),
        ];
        for case in cases {
            let label = case.to_string();
            let mapped = map_lifecycle_error(case);
            if mapped.native_code().is_some() {
                assert!(
                    mapped.operation().is_some(),
                    "nativeCode without operation: {label}"
                );
            }
        }
    }

    #[test]
    fn unreadable_hresult_yields_operation_without_native_code() {
        let mapped = map_lifecycle_error(classify_api_failure(
            api_failure(None),
            StalePromotion::Eligible,
        ));
        assert_eq!(mapped.code, MxcErrorCode::BackendError);
        assert!(mapped.operation().is_some());
        assert_eq!(mapped.native_code(), None);
    }

    /// The apartment query succeeds, so the refusal has no call to name and no
    /// status to report — only a hint the caller can act on.
    #[test]
    fn the_sta_refusal_carries_a_hint_and_no_api_detail() {
        let mapped = map_lifecycle_error(sta_refusal());
        assert_eq!(mapped.code, MxcErrorCode::BackendError);
        assert_eq!(mapped.operation(), None);
        assert_eq!(mapped.native_code(), None);
        assert!(
            mapped
                .remediation
                .as_deref()
                .is_some_and(|hint| hint.contains("multi-threaded apartment")),
            "{:?}",
            mapped.remediation
        );
    }

    /// The one-shot path has no structured envelope, so the hint has to reach
    /// the caller folded into the message.
    #[test]
    fn the_sta_refusal_folds_its_hint_into_the_one_shot_rendering() {
        let rendered = sta_refusal().to_string();
        assert!(rendered.contains("single-threaded apartment"), "{rendered}");
        assert!(
            rendered.contains("remediation: Call from a multi-threaded apartment"),
            "{rendered}"
        );
    }

    // ── One-shot rendering (Display) ─────────────────────────────────────

    /// The one-shot path has no structured envelope, so `Display` must keep
    /// folding every component back into the message — including the
    /// category prefix, which is the only place the category appears there.
    #[test]
    fn display_composes_the_full_human_string() {
        let rendered = classify_api_failure(
            api_failure(Some(ERROR_NOT_FOUND_HRESULT)),
            StalePromotion::Eligible,
        )
        .to_string();
        assert!(
            rendered.starts_with("Isolation Session stale id: "),
            "{rendered}"
        );
        assert!(
            rendered.contains("IsoSessionOps.StopSessionAsync"),
            "{rendered}"
        );
        assert!(rendered.contains("agent user not found"), "{rendered}");
        assert!(rendered.contains("0x80070490"), "{rendered}");
        assert!(
            rendered.contains("remediation: Re-provision the sandbox."),
            "{rendered}"
        );
    }

    #[test]
    fn display_keeps_the_category_prefix_for_every_variant() {
        let com = windows_core::Error::from_hresult(windows_core::HRESULT(0x80004005_u32 as i32));
        assert!(IsolationSessionError::Policy("x".into())
            .to_string()
            .starts_with("Isolation Session policy error: "));
        assert!(activation_error(REGDB_E_CLASSNOTREG_HRESULT, "x")
            .to_string()
            .starts_with("Isolation Session service unavailable: "));
        assert!(lifecycle_err("x")
            .to_string()
            .starts_with("Isolation Session lifecycle error: "));
        assert!(transport_err(op::ADD_USER, "call failed", &com)
            .to_string()
            .starts_with("Isolation Session lifecycle error: "));
    }

    /// The one-shot conversion still carries the full composed detail — it
    /// is the only carrier on that path.
    #[test]
    fn script_response_conversion_keeps_the_rich_message() {
        let response: ScriptResponse =
            classify_api_failure(api_failure(Some(0x80004005)), StalePromotion::Eligible).into();
        assert!(response
            .error_message
            .contains("IsoSessionOps.StopSessionAsync"));
        assert!(response.error_message.contains("0x80004005"));
        assert!(response.error_message.contains("remediation"));
    }

    // ── operation values ─────────────────────────────────────────────────

    /// `operation` must stay interface-qualified and free of call
    /// parameters, so it can be aggregated in telemetry.
    #[test]
    fn operation_constants_are_qualified_and_parameter_free() {
        for value in [
            op::CO_INCREMENT_MTA_USAGE,
            op::CO_GET_APARTMENT_TYPE,
            op::ACTIVATE,
            op::ADD_USER,
            op::START_SESSION,
            op::RUN_PROCESS,
            op::STOP_SESSION,
            op::REMOVE_USER,
            op::OPTIONS_NEW,
            op::OPTIONS_TIMEOUT,
            op::OPTIONS_WORKING_DIR,
            op::OPTIONS_INTERACTIVE,
            op::OPTIONS_REDIRECT_STDIN,
            op::OPTIONS_REDIRECT_STDOUT,
            op::OPTIONS_REDIRECT_STDERR,
            op::OPTIONS_ENVIRONMENT,
        ] {
            assert!(
                value.starts_with("IsoSessionOps.")
                    || value.starts_with("IsoSessionProcessOptions.")
                    || value.starts_with("Com."),
                "unqualified: {value}"
            );
            assert!(!value.contains('('), "carries parameters: {value}");
            assert!(!value.contains(' '), "not a bare member name: {value}");
        }
    }
}
