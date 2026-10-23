// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Normalized requests shared by exact parsers and execution entry points.

use crate::mxc_common::models::{ContainmentBackend, ExecutionRequest};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_operation::StateAwareOperation;

/// The out-of-band identity a phase is addressed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetIdKind {
    None,
    SandboxId,
    SessionId,
}

impl TargetIdKind {
    /// Wire member that carries this identity on a lifecycle request.
    pub fn wire_member(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::SandboxId => Some("sandboxId"),
            Self::SessionId => Some("sessionId"),
        }
    }
}

/// Lifecycle phase in a state-aware request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    ProvisionSession,
    Provision,
    Start,
    Exec,
    Stop,
    Deprovision,
    DeprovisionSession,
}

impl Phase {
    /// Wire-format string matching the SDK's `Phase` union.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProvisionSession => "provision-session",
            Self::Provision => "provision",
            Self::Start => "start",
            Self::Exec => "exec",
            Self::Stop => "stop",
            Self::Deprovision => "deprovision",
            Self::DeprovisionSession => "deprovision-session",
        }
    }

    /// Whether the backend comes from the declared `containment` rather than
    /// from the prefix of the phase's target ID.
    ///
    /// Only a sandbox ID carries a backend prefix, so a phase addressed by
    /// anything else has to declare its containment.
    pub fn routes_by_containment(self) -> bool {
        !matches!(self.target_id_kind(), TargetIdKind::SandboxId)
    }

    pub fn target_id_kind(self) -> TargetIdKind {
        match self {
            Self::ProvisionSession | Self::Provision => TargetIdKind::None,
            Self::Start | Self::Exec | Self::Stop | Self::Deprovision => TargetIdKind::SandboxId,
            Self::DeprovisionSession => TargetIdKind::SessionId,
        }
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<crate::mxc_common::wire::Phase> for Phase {
    fn from(phase: crate::mxc_common::wire::Phase) -> Self {
        match phase {
            crate::mxc_common::wire::Phase::Provision => Self::Provision,
            crate::mxc_common::wire::Phase::Start => Self::Start,
            crate::mxc_common::wire::Phase::Exec => Self::Exec,
            crate::mxc_common::wire::Phase::Stop => Self::Stop,
            crate::mxc_common::wire::Phase::Deprovision => Self::Deprovision,
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
/// ```compile_fail,E0599
/// use mxc_sdk::mxc_common::state_aware_request::ParsedStateAwareRequest;
/// fn reparse(request: &ParsedStateAwareRequest) {
///     let _ = request.deserialize_config::<()>("wslc", "provision");
/// }
/// ```
///
/// Successful requests expose neither raw backend JSON nor retained source:
///
/// ```compile_fail,E0609
/// use mxc_sdk::mxc_common::state_aware_request::ParsedStateAwareRequest;
/// fn raw_payload(request: &ParsedStateAwareRequest) {
///     let _ = &request.experimental_raw;
/// }
/// ```
///
/// ```compile_fail,E0609
/// use mxc_sdk::mxc_common::state_aware_request::ParsedStateAwareRequest;
/// fn source(request: &ParsedStateAwareRequest) {
///     let _ = &request.source_text;
/// }
/// ```
///
/// Construction is reserved for checked normalization, not public callers:
///
/// ```compile_fail,E0624
/// use mxc_sdk::mxc_common::models::ExecutionRequest;
/// use mxc_sdk::mxc_common::state_aware_operation::StateAwareOperation;
/// use mxc_sdk::mxc_common::state_aware_request::ParsedStateAwareRequest;
/// let _ = ParsedStateAwareRequest::new(
///     ExecutionRequest::default(),
///     StateAwareOperation::Start { sandbox_id: "iso:example".into() },
/// );
/// ```
///
/// A caller cannot construct independent phase and payload authorities:
///
/// ```compile_fail,E0560
/// use mxc_sdk::mxc_common::models::ExecutionRequest;
/// use mxc_sdk::mxc_common::state_aware_operation::StateAwareOperation;
/// use mxc_sdk::mxc_common::state_aware_request::{ParsedStateAwareRequest, Phase};
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

    /// Declared backend for the phases that route by containment; the rest
    /// route by sandbox ID.
    pub fn containment(&self) -> Option<ContainmentBackend> {
        self.operation.containment()
    }

    /// Sandbox ID carried by a sandbox-addressed operation.
    pub fn sandbox_id(&self) -> Option<&str> {
        self.operation.sandbox_id()
    }

    /// Session ID carried by a session-addressed operation.
    pub fn session_id(&self) -> Option<&str> {
        self.operation.session_id()
    }

    /// Require an ID for a sandbox-addressed execution entry point.
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
    use crate::mxc_common::state_aware_operation::StateAwareProvision;

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

    #[test]
    fn every_phase_has_a_distinct_wire_string() {
        let phases = [
            Phase::ProvisionSession,
            Phase::Provision,
            Phase::Start,
            Phase::Exec,
            Phase::Stop,
            Phase::Deprovision,
            Phase::DeprovisionSession,
        ];
        let mut seen: Vec<&str> = phases.iter().map(|phase| phase.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), phases.len());
        assert_eq!(Phase::ProvisionSession.as_str(), "provision-session");
        assert_eq!(Phase::DeprovisionSession.as_str(), "deprovision-session");
        assert_eq!(Phase::ProvisionSession.to_string(), "provision-session");
    }

    #[test]
    fn session_phases_route_by_containment_and_carry_no_sandbox_id() {
        for phase in [Phase::ProvisionSession, Phase::DeprovisionSession] {
            assert!(phase.routes_by_containment(), "{phase}");
            assert_ne!(phase.target_id_kind(), TargetIdKind::SandboxId, "{phase}");
        }
        assert_eq!(Phase::ProvisionSession.target_id_kind(), TargetIdKind::None);
        assert_eq!(
            Phase::DeprovisionSession.target_id_kind(),
            TargetIdKind::SessionId
        );
    }

    #[test]
    fn sandbox_addressed_phases_route_by_their_id() {
        for phase in [Phase::Start, Phase::Exec, Phase::Stop, Phase::Deprovision] {
            assert!(!phase.routes_by_containment(), "{phase}");
            assert_eq!(phase.target_id_kind(), TargetIdKind::SandboxId, "{phase}");
        }
        assert!(Phase::Provision.routes_by_containment());
        assert_eq!(Phase::Provision.target_id_kind(), TargetIdKind::None);
    }

    #[test]
    fn each_identity_has_its_own_wire_member() {
        assert_eq!(TargetIdKind::None.wire_member(), None);
        assert_eq!(TargetIdKind::SandboxId.wire_member(), Some("sandboxId"));
        assert_eq!(TargetIdKind::SessionId.wire_member(), Some("sessionId"));
    }

    #[test]
    fn a_session_operation_exposes_its_id_only_as_a_session_id() {
        let parsed = ParsedStateAwareRequest::new(
            ExecutionRequest::default(),
            StateAwareOperation::DeprovisionSession {
                session_id: "wslcsess:abcd".into(),
            },
        );
        assert_eq!(parsed.phase(), Phase::DeprovisionSession);
        assert_eq!(parsed.containment(), Some(ContainmentBackend::Wslc));
        assert_eq!(parsed.session_id(), Some("wslcsess:abcd"));
        assert!(parsed.sandbox_id().is_none());
        assert!(parsed.sandbox_id_required().is_err());
    }
}
