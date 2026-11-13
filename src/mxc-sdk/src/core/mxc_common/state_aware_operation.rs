// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backend-neutral lifecycle operations produced by exact contract adaptation.
//!
//! The operation determines its phase and routing data. Provision retains its
//! backend even when no configuration was supplied. Sandbox-addressed phases
//! always carry an ID, whose contents are validated at the existing dispatch
//! boundary. A session ID is checked by `validate` instead, because routing
//! never reads it.

use crate::mxc_common::models::{
    ContainmentBackend, IsolationSessionProvisionConfig, MicroVmProvisionConfig,
    WslcProvisionConfig, WslcProvisionSessionConfig,
};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_request::Phase;

/// Backend-specific provision input, before backend-owned validation/defaulting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateAwareProvision {
    /// No configuration differs from a present configuration with no `appId`.
    IsolationSession(Option<IsolationSessionProvisionConfig>),
    /// Windows Sandbox has no backend-specific provision configuration.
    WindowsSandbox,
    /// MicroVM provision configuration.
    MicroVm(Option<MicroVmProvisionConfig>),
    /// An omitted image remains absent until the WSLC backend chooses a default.
    Wslc(Option<WslcProvisionConfig>),
}

impl StateAwareProvision {
    /// The backend selected by this provision operation.
    pub fn containment(&self) -> ContainmentBackend {
        match self {
            Self::IsolationSession(_) => ContainmentBackend::IsolationSession,
            Self::WindowsSandbox => ContainmentBackend::WindowsSandbox,
            Self::MicroVm(_) => ContainmentBackend::MicroVm,
            Self::Wslc(_) => ContainmentBackend::Wslc,
        }
    }
}

/// A lifecycle operation with exactly the routing and configuration it needs.
///
/// Execution process settings, policy, and telemetry belong to the common
/// `ExecutionRequest`, not this payload. Empty backend phase sections do not
/// manufacture backend configurations for non-provision operations.
///
/// The two session operations are WSLc-only: no other backend owns a session
/// a sandbox can be placed into, so no other backend is expressible here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateAwareOperation {
    ProvisionSession(Option<WslcProvisionSessionConfig>),
    Provision(StateAwareProvision),
    Start { sandbox_id: String },
    Exec { sandbox_id: String },
    Stop { sandbox_id: String },
    Deprovision { sandbox_id: String },
    DeprovisionSession { session_id: String },
}

impl StateAwareOperation {
    /// Phase derived from the operation, never an independent discriminator.
    pub fn phase(&self) -> Phase {
        match self {
            Self::ProvisionSession(_) => Phase::ProvisionSession,
            Self::Provision(_) => Phase::Provision,
            Self::Start { .. } => Phase::Start,
            Self::Exec { .. } => Phase::Exec,
            Self::Stop { .. } => Phase::Stop,
            Self::Deprovision { .. } => Phase::Deprovision,
            Self::DeprovisionSession { .. } => Phase::DeprovisionSession,
        }
    }

    /// Declared containment for the phases that route by containment; the rest
    /// route by sandbox ID.
    pub fn containment(&self) -> Option<ContainmentBackend> {
        match self {
            Self::ProvisionSession(_) | Self::DeprovisionSession { .. } => {
                Some(ContainmentBackend::Wslc)
            }
            Self::Provision(provision) => Some(provision.containment()),
            Self::Start { .. }
            | Self::Exec { .. }
            | Self::Stop { .. }
            | Self::Deprovision { .. } => None,
        }
    }

    /// Required ID for sandbox-addressed phases; the rest create their own
    /// identity or address a session.
    pub fn sandbox_id(&self) -> Option<&str> {
        match self {
            Self::ProvisionSession(_) | Self::Provision(_) | Self::DeprovisionSession { .. } => {
                None
            }
            Self::Start { sandbox_id }
            | Self::Exec { sandbox_id }
            | Self::Stop { sandbox_id }
            | Self::Deprovision { sandbox_id } => Some(sandbox_id),
        }
    }

    /// Required ID for session-addressed phases.
    pub fn session_id(&self) -> Option<&str> {
        match self {
            Self::DeprovisionSession { session_id } => Some(session_id),
            Self::ProvisionSession(_)
            | Self::Provision(_)
            | Self::Start { .. }
            | Self::Exec { .. }
            | Self::Stop { .. }
            | Self::Deprovision { .. } => None,
        }
    }

    /// Reject backend configuration the selected backend cannot enforce, and
    /// session ids not in the form the WSLc daemon mints.
    ///
    /// Both the JSON and typed-SDK entry points call this, so neither surface
    /// can accept a payload the other rejects.
    pub(crate) fn validate(&self) -> Result<(), crate::mxc_common::error::WxcError> {
        if let Self::Provision(StateAwareProvision::MicroVm(config)) = self {
            let config = config.as_ref().ok_or_else(|| {
                crate::mxc_common::error::WxcError::Validation(
                    "microvm.image is required".to_owned(),
                )
            })?;
            crate::mxc_contract::dev::ImageReference::validate(&config.image)
                .map_err(crate::mxc_common::error::WxcError::Validation)?;
        }
        match self {
            Self::Provision(StateAwareProvision::Wslc(Some(config))) => {
                match config.port_mappings.as_deref() {
                    Some(mappings) => crate::mxc_common::validator::validate_port_mappings(
                        "wslc.provision.portMappings",
                        mappings,
                    ),
                    None => Ok(()),
                }
            }
            Self::DeprovisionSession { session_id } => {
                validate_wslc_session_id(session_id).map_err(Into::into)
            }
            Self::Provision(StateAwareProvision::MicroVm(Some(config))) => {
                MicroVmProvisionConfig::validate_memory_mib(config.memory_mib)
            }
            // Session sizing carries no cross-backend constraint; the WSLc
            // backend decides what it can honor.
            Self::ProvisionSession(_)
            | Self::Provision(_)
            | Self::Start { .. }
            | Self::Exec { .. }
            | Self::Stop { .. }
            | Self::Deprovision { .. } => Ok(()),
        }
    }
}

const SESSION_ID_TAG: &str = "wslcsess:";
const SESSION_ID_HEX_DIGITS: usize = 32;

pub(crate) fn validate_wslc_session_id(session_id: &str) -> Result<(), MxcError> {
    let well_formed = session_id
        .strip_prefix(SESSION_ID_TAG)
        .is_some_and(|token| {
            token.len() == SESSION_ID_HEX_DIGITS
                && token
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        });
    if well_formed {
        Ok(())
    } else {
        Err(MxcError::malformed_id(format!(
            "a session id must be `{SESSION_ID_TAG}` followed by {SESSION_ID_HEX_DIGITS} \
             lowercase hex digits"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provision_retains_backend_with_no_configuration() {
        for (provision, expected) in [
            (
                StateAwareProvision::IsolationSession(None),
                ContainmentBackend::IsolationSession,
            ),
            (
                StateAwareProvision::WindowsSandbox,
                ContainmentBackend::WindowsSandbox,
            ),
            (
                StateAwareProvision::MicroVm(None),
                ContainmentBackend::MicroVm,
            ),
            (StateAwareProvision::Wslc(None), ContainmentBackend::Wslc),
        ] {
            let operation = StateAwareOperation::Provision(provision);
            assert_eq!(operation.phase(), Phase::Provision);
            assert_eq!(operation.containment(), Some(expected));
            assert_eq!(operation.sandbox_id(), None);
        }
    }

    #[test]
    fn later_operations_derive_phase_and_preserve_unvalidated_id() {
        let id = "not-yet-validated";
        for (operation, phase) in [
            (
                StateAwareOperation::Start {
                    sandbox_id: id.into(),
                },
                Phase::Start,
            ),
            (
                StateAwareOperation::Exec {
                    sandbox_id: id.into(),
                },
                Phase::Exec,
            ),
            (
                StateAwareOperation::Stop {
                    sandbox_id: id.into(),
                },
                Phase::Stop,
            ),
            (
                StateAwareOperation::Deprovision {
                    sandbox_id: id.into(),
                },
                Phase::Deprovision,
            ),
        ] {
            assert_eq!(operation.phase(), phase);
            assert_eq!(operation.containment(), None);
            assert_eq!(operation.sandbox_id(), Some(id));
            assert_eq!(operation.session_id(), None);
        }
    }

    #[test]
    fn session_operations_are_wslc_and_keep_their_id_off_the_sandbox_accessor() {
        let provision = StateAwareOperation::ProvisionSession(Some(WslcProvisionSessionConfig {
            cpu_count: Some(4),
            memory_mb: Some(8192),
            gpu: Some(true),
        }));
        assert_eq!(provision.phase(), Phase::ProvisionSession);
        assert_eq!(provision.containment(), Some(ContainmentBackend::Wslc));
        assert_eq!(provision.sandbox_id(), None);
        assert_eq!(provision.session_id(), None);

        let deprovision = StateAwareOperation::DeprovisionSession {
            session_id: "wslcsess:abcd".into(),
        };
        assert_eq!(deprovision.phase(), Phase::DeprovisionSession);
        assert_eq!(deprovision.containment(), Some(ContainmentBackend::Wslc));
        assert_eq!(deprovision.sandbox_id(), None);
        assert_eq!(deprovision.session_id(), Some("wslcsess:abcd"));
    }

    #[test]
    fn a_session_id_must_have_the_form_the_daemon_mints() {
        let release = |session_id: &str| {
            StateAwareOperation::DeprovisionSession {
                session_id: session_id.into(),
            }
            .validate()
        };
        assert!(release("wslcsess:0123456789abcdef0123456789abcdef").is_ok());

        for malformed in [
            "",
            "wslcsess:",
            "wslcsess:abcd",
            "wslcsess:0123456789abcdef0123456789abcdef0",
            "wslcsess:0123456789ABCDEF0123456789ABCDEF",
            "wslcsess:0123456789abcdef0123456789abcdeg",
            "wslc:0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef",
        ] {
            let error = release(malformed).expect_err(malformed).to_string();
            assert!(
                error.contains("`wslcsess:` followed by 32 lowercase hex digits"),
                "the refusal of {malformed:?} must name the expected form, got: {error}"
            );
        }
    }

    #[test]
    fn session_sizing_presence_and_empty_values_are_distinct() {
        assert_ne!(
            StateAwareOperation::ProvisionSession(None),
            StateAwareOperation::ProvisionSession(Some(WslcProvisionSessionConfig::default()))
        );
        assert_ne!(
            StateAwareOperation::ProvisionSession(Some(WslcProvisionSessionConfig::default())),
            StateAwareOperation::ProvisionSession(Some(WslcProvisionSessionConfig {
                gpu: Some(false),
                ..WslcProvisionSessionConfig::default()
            }))
        );
    }

    #[test]
    fn provision_presence_and_empty_values_are_distinct() {
        let absent = StateAwareProvision::IsolationSession(None);
        let empty = StateAwareProvision::IsolationSession(Some(IsolationSessionProvisionConfig {
            app_id: None,
        }));
        let empty_app_id =
            StateAwareProvision::IsolationSession(Some(IsolationSessionProvisionConfig {
                app_id: Some(String::new()),
            }));
        assert_ne!(absent, empty);
        assert_ne!(empty, empty_app_id);
        assert_ne!(
            StateAwareProvision::Wslc(None),
            StateAwareProvision::Wslc(Some(WslcProvisionConfig::default()))
        );
        assert_ne!(
            StateAwareProvision::MicroVm(None),
            StateAwareProvision::MicroVm(Some(MicroVmProvisionConfig::default()))
        );
    }
}
