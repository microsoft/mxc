// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Normalized requests shared by exact parsers and execution entry points.

use crate::models::{ContainmentBackend, ExecutionRequest};
use crate::mxc_error::MxcError;
use crate::state_aware_operation::StateAwareOperation;

/// Lifecycle phase in a state-aware request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    Provision,
    Start,
    Exec,
    Stop,
    Deprovision,
}

impl Phase {
    /// Wire-format string matching the SDK's `Phase` union.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provision => "provision",
            Self::Start => "start",
            Self::Exec => "exec",
            Self::Stop => "stop",
            Self::Deprovision => "deprovision",
        }
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<crate::wire::Phase> for Phase {
    fn from(phase: crate::wire::Phase) -> Self {
        match phase {
            crate::wire::Phase::Provision => Self::Provision,
            crate::wire::Phase::Start => Self::Start,
            crate::wire::Phase::Exec => Self::Exec,
            crate::wire::Phase::Stop => Self::Stop,
            crate::wire::Phase::Deprovision => Self::Deprovision,
        }
    }
}

/// A checked operation and its normalized cross-cutting runtime configuration.
///
/// Routing and configuration presence are derived from the operation. Successful
/// requests retain neither source text nor backend JSON.
///
/// Backend configuration cannot be deserialized from a normalized request:
///
/// ```compile_fail
/// use wxc_common::state_aware_request::ParsedStateAwareRequest;
/// fn reparse(request: &ParsedStateAwareRequest) {
///     let _ = request.deserialize_config::<()>("wslc", "provision");
/// }
/// ```
///
/// Successful requests expose neither raw backend JSON nor retained source:
///
/// ```compile_fail
/// use wxc_common::state_aware_request::ParsedStateAwareRequest;
/// fn raw_payload(request: &ParsedStateAwareRequest) {
///     let _ = &request.experimental_raw;
/// }
/// ```
///
/// ```compile_fail
/// use wxc_common::state_aware_request::ParsedStateAwareRequest;
/// fn source(request: &ParsedStateAwareRequest) {
///     let _ = &request.source_text;
/// }
/// ```
///
/// Construction is reserved for checked normalization, not public callers:
///
/// ```compile_fail
/// use wxc_common::models::ExecutionRequest;
/// use wxc_common::state_aware_operation::StateAwareOperation;
/// use wxc_common::state_aware_request::ParsedStateAwareRequest;
/// let _ = ParsedStateAwareRequest::new(
///     ExecutionRequest::default(),
///     StateAwareOperation::Start { sandbox_id: "iso:example".into() },
/// );
/// ```
///
/// A caller cannot construct independent phase and payload authorities:
///
/// ```compile_fail
/// use wxc_common::models::ExecutionRequest;
/// use wxc_common::state_aware_operation::StateAwareOperation;
/// use wxc_common::state_aware_request::{ParsedStateAwareRequest, Phase};
/// let _ = ParsedStateAwareRequest {
///     request: ExecutionRequest::default(),
///     phase: Phase::Exec,
///     operation: StateAwareOperation::Start { sandbox_id: "iso:example".into() },
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ParsedStateAwareRequest {
    request: ExecutionRequest,
    operation: StateAwareOperation,
}

impl ParsedStateAwareRequest {
    pub(crate) fn new(request: ExecutionRequest, operation: StateAwareOperation) -> Self {
        Self { request, operation }
    }

    /// Normalized process, policy, telemetry, and execution flags.
    pub fn request(&self) -> &ExecutionRequest {
        &self.request
    }

    /// The typed operation, including backend-specific provision configuration.
    pub fn operation(&self) -> &StateAwareOperation {
        &self.operation
    }

    /// Phase derived from the operation.
    pub fn phase(&self) -> Phase {
        self.operation.phase()
    }

    /// Declared backend for provision; later phases route by sandbox ID.
    pub fn containment(&self) -> Option<ContainmentBackend> {
        self.operation.containment()
    }

    /// Sandbox ID carried by a non-provision operation.
    pub fn sandbox_id(&self) -> Option<&str> {
        self.operation.sandbox_id()
    }

    /// Require an ID for a non-provision execution entry point.
    pub fn sandbox_id_required(&self) -> Result<&str, MxcError> {
        self.sandbox_id().ok_or_else(|| {
            MxcError::malformed_request(format!("phase {} requires a sandboxId", self.phase()))
        })
    }

    pub(crate) fn into_parts(self) -> (ExecutionRequest, StateAwareOperation) {
        (self.request, self.operation)
    }

    /// Consume the parsed request, retaining only its cross-cutting configuration.
    pub fn into_request(self) -> ExecutionRequest {
        self.request
    }

    /// Set the caller's experimental execution opt-in.
    pub fn set_experimental_enabled(&mut self, enabled: bool) {
        self.request.experimental_enabled = enabled;
    }

    /// Set validation-only execution.
    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.request.dry_run = dry_run;
    }
}

/// Public bridge between parser and execution entry points.
#[derive(Debug, Clone)]
pub enum MxcRequest {
    OneShot(ExecutionRequest),
    StateAware(ParsedStateAwareRequest),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_aware_operation::StateAwareProvision;

    #[test]
    fn execution_flags_do_not_mutate_the_operation_or_policy() {
        let operation = StateAwareOperation::Exec {
            sandbox_id: "".into(),
        };
        let mut parsed =
            ParsedStateAwareRequest::new(ExecutionRequest::default(), operation.clone());
        let policy = serde_json::to_value(&parsed.request().policy).unwrap();
        assert!(!parsed.request().experimental_enabled);
        assert!(!parsed.request().dry_run);
        parsed.set_experimental_enabled(true);
        parsed.set_dry_run(true);
        assert!(parsed.request().experimental_enabled);
        assert!(parsed.request().dry_run);
        assert_eq!(parsed.operation(), &operation);
        assert_eq!(parsed.phase(), Phase::Exec);
        assert_eq!(parsed.sandbox_id_required().unwrap(), "");
        assert!(parsed.containment().is_none());
        assert_eq!(
            serde_json::to_value(&parsed.request().policy).unwrap(),
            policy
        );
        let request = parsed.into_request();
        assert!(request.experimental_enabled);
        assert!(request.dry_run);
    }

    #[test]
    fn provision_has_no_sandbox_id_even_without_configuration() {
        let operation = StateAwareOperation::Provision(StateAwareProvision::Wslc(None));
        let parsed = ParsedStateAwareRequest::new(ExecutionRequest::default(), operation.clone());
        assert_eq!(parsed.phase(), Phase::Provision);
        assert_eq!(parsed.containment(), Some(ContainmentBackend::Wslc));
        assert!(parsed.sandbox_id().is_none());
        assert!(parsed.sandbox_id_required().is_err());
        let (_, observed) = parsed.into_parts();
        assert_eq!(observed, operation);
    }
}
