// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Checked, mechanical binding of neutral lifecycle input to a backend.
//!
//! The engine calls the matching helper after routing and execution gates.
//! Binding neither parses configuration nor supplies backend defaults.

use crate::models::{
    ContainmentBackend, ExecutionRequest, IsolationSessionProvisionConfig, WslcProvisionConfig,
};
use crate::mxc_error::MxcError;
use crate::state_aware_backend::StatefulSandboxBackend;
use crate::state_aware_dispatch::resolve_backend;
use crate::state_aware_operation::{StateAwareOperation, StateAwareProvision};
use crate::state_aware_request::{ParsedStateAwareRequest, Phase};

/// Backend-typed operation. Construction is restricted to checked binding.
pub(crate) enum BoundStateAwareOperation<B: StatefulSandboxBackend> {
    Provision(Option<B::ProvisionConfig>),
    Start {
        sandbox_id: String,
        config: Option<B::StartConfig>,
    },
    Exec {
        sandbox_id: String,
        config: Option<B::ExecConfig>,
    },
    Stop {
        sandbox_id: String,
        config: Option<B::StopConfig>,
    },
    Deprovision {
        sandbox_id: String,
        config: Option<B::DeprovisionConfig>,
    },
}

/// A common runtime request paired with configuration for exactly one backend.
///
/// Both lifecycle and streaming dispatch consume this type. Its configuration
/// remains optional until the backend validates and executes the operation.
pub struct BoundStateAwareRequest<B: StatefulSandboxBackend> {
    request: ExecutionRequest,
    operation: BoundStateAwareOperation<B>,
}

impl<B: StatefulSandboxBackend> std::fmt::Debug for BoundStateAwareRequest<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundStateAwareRequest")
            .field("backend", &B::BACKEND_KEY)
            .field("phase", &self.phase())
            .field("sandbox_id", &self.sandbox_id())
            .finish_non_exhaustive()
    }
}

impl<B: StatefulSandboxBackend> BoundStateAwareRequest<B> {
    /// The operation's phase.
    pub fn phase(&self) -> Phase {
        match self.operation {
            BoundStateAwareOperation::Provision(_) => Phase::Provision,
            BoundStateAwareOperation::Start { .. } => Phase::Start,
            BoundStateAwareOperation::Exec { .. } => Phase::Exec,
            BoundStateAwareOperation::Stop { .. } => Phase::Stop,
            BoundStateAwareOperation::Deprovision { .. } => Phase::Deprovision,
        }
    }

    /// Cross-cutting execution settings, policy, and telemetry.
    pub fn request(&self) -> &ExecutionRequest {
        &self.request
    }

    /// The ID of a non-provision operation.
    pub fn sandbox_id(&self) -> Option<&str> {
        match &self.operation {
            BoundStateAwareOperation::Provision(_) => None,
            BoundStateAwareOperation::Start { sandbox_id, .. }
            | BoundStateAwareOperation::Exec { sandbox_id, .. }
            | BoundStateAwareOperation::Stop { sandbox_id, .. }
            | BoundStateAwareOperation::Deprovision { sandbox_id, .. } => Some(sandbox_id),
        }
    }

    pub(crate) fn into_parts(self) -> (ExecutionRequest, BoundStateAwareOperation<B>) {
        (self.request, self.operation)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        request: ExecutionRequest,
        operation: BoundStateAwareOperation<B>,
    ) -> Self {
        Self { request, operation }
    }
}

impl<B> BoundStateAwareRequest<B>
where
    B: StatefulSandboxBackend<
        StartConfig = (),
        ExecConfig = (),
        StopConfig = (),
        DeprovisionConfig = (),
    >,
{
    fn bind(
        parsed: ParsedStateAwareRequest,
        expected: ContainmentBackend,
        id_prefix: &str,
        provision: impl FnOnce(StateAwareProvision) -> Result<Option<B::ProvisionConfig>, MxcError>,
    ) -> Result<Self, MxcError> {
        let actual = resolve_backend(&parsed)?;
        if actual != expected || B::BACKEND_KEY != expected.wire_name() || B::ID_PREFIX != id_prefix
        {
            return Err(incompatible_payload(&actual, B::BACKEND_KEY));
        }
        let (request, operation) = parsed.into_parts();
        let operation = match operation {
            StateAwareOperation::Provision(config) => {
                BoundStateAwareOperation::Provision(provision(config)?)
            }
            StateAwareOperation::Start { sandbox_id } => BoundStateAwareOperation::Start {
                sandbox_id,
                config: None,
            },
            StateAwareOperation::Exec { sandbox_id } => BoundStateAwareOperation::Exec {
                sandbox_id,
                config: None,
            },
            StateAwareOperation::Stop { sandbox_id } => BoundStateAwareOperation::Stop {
                sandbox_id,
                config: None,
            },
            StateAwareOperation::Deprovision { sandbox_id } => {
                BoundStateAwareOperation::Deprovision {
                    sandbox_id,
                    config: None,
                }
            }
        };
        Ok(Self { request, operation })
    }
}

fn incompatible_payload(actual: &ContainmentBackend, backend: &str) -> MxcError {
    MxcError::malformed_request(format!(
        "state-aware {actual:?} operation is incompatible with backend {backend:?}"
    ))
}

/// Bind an IsolationSession operation without changing configuration presence.
pub fn bind_isolation_session<B>(
    parsed: ParsedStateAwareRequest,
) -> Result<BoundStateAwareRequest<B>, MxcError>
where
    B: StatefulSandboxBackend<
        ProvisionConfig = IsolationSessionProvisionConfig,
        StartConfig = (),
        ExecConfig = (),
        StopConfig = (),
        DeprovisionConfig = (),
    >,
{
    BoundStateAwareRequest::bind(
        parsed,
        ContainmentBackend::IsolationSession,
        "iso",
        |provision| match provision {
            StateAwareProvision::IsolationSession(config) => Ok(config),
            other => Err(incompatible_payload(&other.containment(), B::BACKEND_KEY)),
        },
    )
}

/// Bind a Windows Sandbox operation; no phase has backend configuration today.
pub fn bind_windows_sandbox<B>(
    parsed: ParsedStateAwareRequest,
) -> Result<BoundStateAwareRequest<B>, MxcError>
where
    B: StatefulSandboxBackend<
        ProvisionConfig = (),
        StartConfig = (),
        ExecConfig = (),
        StopConfig = (),
        DeprovisionConfig = (),
    >,
{
    BoundStateAwareRequest::bind(
        parsed,
        ContainmentBackend::WindowsSandbox,
        "wsb",
        |provision| match provision {
            StateAwareProvision::WindowsSandbox => Ok(None),
            other => Err(incompatible_payload(&other.containment(), B::BACKEND_KEY)),
        },
    )
}

/// Bind a WSLC operation, leaving image default resolution in the backend.
pub fn bind_wslc<B>(parsed: ParsedStateAwareRequest) -> Result<BoundStateAwareRequest<B>, MxcError>
where
    B: StatefulSandboxBackend<
        ProvisionConfig = WslcProvisionConfig,
        StartConfig = (),
        ExecConfig = (),
        StopConfig = (),
        DeprovisionConfig = (),
    >,
{
    BoundStateAwareRequest::bind(parsed, ContainmentBackend::Wslc, "wslc", |provision| {
        match provision {
            StateAwareProvision::Wslc(config) => Ok(config),
            other => Err(incompatible_payload(&other.containment(), B::BACKEND_KEY)),
        }
    })
}

#[cfg(test)]
#[path = "state_aware_binding_tests.rs"]
mod tests;
