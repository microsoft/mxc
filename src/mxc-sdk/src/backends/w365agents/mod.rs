// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Internal checkout/release implementation. Readiness and execution are deferred.

mod service;

use crate::mxc_common::models::ExecutionRequest;
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_backend::{
    DeprovisionResult, ExecHandle, ExecStdio, ProvisionResult, StartResult, StatefulSandboxBackend,
    StopResult,
};
use crate::mxc_common::state_aware_operation::W365AgentsProvisionConfig;
use serde::Serialize;

pub(crate) struct Runner;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CheckoutMetadata {
    pool_id: String,
    session_id: String,
    computer_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReleaseMetadata {
    release_requested: bool,
    restartable: bool,
}

fn policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    let p = &request.policy;
    if p.network_specified
        || p.runtime_network_proxy_specified
        || p.ui_specified
        || p.network_proxy.is_enabled()
        || p.least_privilege_mode
        || !p.capabilities.is_empty()
        || !p.readwrite_paths.is_empty()
        || !p.readonly_paths.is_empty()
        || !p.enumerate_paths.is_empty()
        || !p.denied_paths.is_empty()
        || p.capture_denials.is_some()
    {
        return Err(MxcError::policy_validation(
            "w365_agents cannot enforce local filesystem, network, UI or proxy policy",
        ));
    }
    Ok(())
}

pub(crate) fn deferred() -> MxcError {
    MxcError::unsupported_phase(
        "w365_agents Phase 2 supports checkout and terminal release only; start/readiness and exec require Phase 3",
    )
}

impl StatefulSandboxBackend for Runner {
    const ID_PREFIX: &'static str = "w365";
    const BACKEND_KEY: &'static str = "w365_agents";
    type ProvisionConfig = W365AgentsProvisionConfig;
    type StartConfig = ();
    type ExecConfig = ();
    type StopConfig = ();
    type DeprovisionConfig = ();
    type ProvisionMetadata = CheckoutMetadata;
    type StartMetadata = ();
    type StopMetadata = ReleaseMetadata;
    type DeprovisionMetadata = ReleaseMetadata;

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&Self::ProvisionConfig>,
    ) -> Result<(), MxcError> {
        policy(request)?;
        service::validate_provision(config)?;
        service::Client::from_env().map(|_| ())
    }

    fn provision(
        &mut self,
        request: &ExecutionRequest,
        config: Option<Self::ProvisionConfig>,
    ) -> Result<ProvisionResult<Self::ProvisionMetadata>, MxcError> {
        self.validate_provision(request, config.as_ref())?;
        let config = service::validate_provision(config.as_ref())?;
        service::Client::from_env()?.checkout(config)
    }

    fn validate_start(
        &self,
        id: &str,
        request: &ExecutionRequest,
        _: Option<&()>,
    ) -> Result<(), MxcError> {
        policy(request)?;
        service::Identity::parse(id)?;
        Err(deferred())
    }

    fn start(
        &mut self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<()>,
    ) -> Result<StartResult<()>, MxcError> {
        self.validate_start(id, request, config.as_ref())?;
        Err(deferred())
    }

    fn validate_exec(
        &self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<&()>,
    ) -> Result<(), MxcError> {
        self.validate_start(id, request, config)
    }

    fn exec(
        &mut self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<()>,
        _: ExecStdio,
    ) -> Result<ExecHandle, MxcError> {
        self.validate_exec(id, request, config.as_ref())?;
        Err(deferred())
    }

    fn validate_stop(
        &self,
        id: &str,
        request: &ExecutionRequest,
        _: Option<&()>,
    ) -> Result<(), MxcError> {
        policy(request)?;
        service::Identity::parse(id)?;
        service::Client::from_env().map(|_| ())
    }

    fn validate_deprovision(
        &self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<&()>,
    ) -> Result<(), MxcError> {
        self.validate_stop(id, request, config)
    }

    fn stop(
        &mut self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<()>,
    ) -> Result<StopResult<Self::StopMetadata>, MxcError> {
        self.validate_stop(id, request, config.as_ref())?;
        service::Client::from_env()?.release(&service::Identity::parse(id)?)?;
        Ok(StopResult {
            metadata: Some(ReleaseMetadata {
                release_requested: true,
                restartable: false,
            }),
        })
    }

    fn deprovision(
        &mut self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<()>,
    ) -> Result<DeprovisionResult<Self::DeprovisionMetadata>, MxcError> {
        let result = self.stop(id, request, config)?;
        Ok(DeprovisionResult {
            metadata: result.metadata,
        })
    }
}

#[cfg(test)]
mod tests;
