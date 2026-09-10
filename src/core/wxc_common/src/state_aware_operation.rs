// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backend-neutral lifecycle operations produced by exact contract adaptation.
//!
//! The operation determines its phase and routing data. Provision retains its
//! backend even when no configuration was supplied. Later phases always carry
//! an ID, whose contents are validated at the existing dispatch boundary.

use crate::models::{ContainmentBackend, IsolationSessionProvisionConfig, WslcProvisionConfig};
use crate::state_aware_request::Phase;

/// Backend-specific provision input, before backend-owned validation/defaulting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateAwareProvision {
    /// No configuration differs from a present configuration with no `appId`.
    IsolationSession(Option<IsolationSessionProvisionConfig>),
    /// Windows Sandbox has no backend-specific provision configuration.
    WindowsSandbox,
    /// An omitted image remains absent until the WSLC backend chooses a default.
    Wslc(Option<WslcProvisionConfig>),
}

impl StateAwareProvision {
    /// The backend selected by this provision operation.
    pub fn containment(&self) -> ContainmentBackend {
        match self {
            Self::IsolationSession(_) => ContainmentBackend::IsolationSession,
            Self::WindowsSandbox => ContainmentBackend::WindowsSandbox,
            Self::Wslc(_) => ContainmentBackend::Wslc,
        }
    }
}

/// A lifecycle operation with exactly the routing and configuration it needs.
///
/// Execution process settings, policy, and telemetry belong to the common
/// `ExecutionRequest`, not this payload. Empty experimental wrappers do not
/// manufacture backend configurations for non-provision operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateAwareOperation {
    Provision(StateAwareProvision),
    Start { sandbox_id: String },
    Exec { sandbox_id: String },
    Stop { sandbox_id: String },
    Deprovision { sandbox_id: String },
}

impl StateAwareOperation {
    /// Phase derived from the operation, never an independent discriminator.
    pub fn phase(&self) -> Phase {
        match self {
            Self::Provision(_) => Phase::Provision,
            Self::Start { .. } => Phase::Start,
            Self::Exec { .. } => Phase::Exec,
            Self::Stop { .. } => Phase::Stop,
            Self::Deprovision { .. } => Phase::Deprovision,
        }
    }

    /// Declared containment for provision; later phases route by sandbox ID.
    pub fn containment(&self) -> Option<ContainmentBackend> {
        match self {
            Self::Provision(provision) => Some(provision.containment()),
            Self::Start { .. }
            | Self::Exec { .. }
            | Self::Stop { .. }
            | Self::Deprovision { .. } => None,
        }
    }

    /// Required ID for later phases; provision has not created an ID yet.
    pub fn sandbox_id(&self) -> Option<&str> {
        match self {
            Self::Provision(_) => None,
            Self::Start { sandbox_id }
            | Self::Exec { sandbox_id }
            | Self::Stop { sandbox_id }
            | Self::Deprovision { sandbox_id } => Some(sandbox_id),
        }
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
        }
    }

    #[test]
    fn provision_presence_and_empty_values_are_distinct() {
        let absent = StateAwareProvision::IsolationSession(None);
        let empty =
            StateAwareProvision::IsolationSession(Some(IsolationSessionProvisionConfig::default()));
        let empty_app_id =
            StateAwareProvision::IsolationSession(Some(IsolationSessionProvisionConfig {
                app_id: Some(String::new()),
                ..Default::default()
            }));
        let acknowledged =
            StateAwareProvision::IsolationSession(Some(IsolationSessionProvisionConfig {
                acknowledge_unrestricted_network: Some(
                    crate::models::UnrestrictedNetworkAcknowledgment,
                ),
                ..Default::default()
            }));
        assert_ne!(absent, empty);
        assert_ne!(empty, empty_app_id);
        assert_ne!(empty, acknowledged);
        assert_ne!(
            StateAwareProvision::Wslc(None),
            StateAwareProvision::Wslc(Some(WslcProvisionConfig::default()))
        );
    }
}
