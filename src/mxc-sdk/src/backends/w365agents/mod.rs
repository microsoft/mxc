// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native W365 checkout, readiness, execution and terminal release.

mod data_plane;
mod discovery;
mod exec;
mod routing;
mod service;

use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, ScriptResponse, W365AgentsProvisionConfig};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::sandbox_process::{SandboxBackend, SandboxProcess, StdioMode};
use crate::mxc_common::state_aware_backend::{
    DeprovisionResult, ExecHandle, ExecStdio, ProvisionResult, StartResult, StatefulSandboxBackend,
    StopResult,
};
use crate::mxc_common::validator::validate_network_policy_support;
use serde::Serialize;
use serde_json::{json, Value};

pub(crate) struct Runner;

const CREATE_AND_RUN_UNSUPPORTED: &str =
    "w365_agents supports container lifecycle operations only; create-and-run execution is not supported";

impl SandboxBackend for Runner {
    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_network_policy_support(request, self.network_policy_support())?;
        Err(ScriptResponse::rejected(CREATE_AND_RUN_UNSUPPORTED))
    }

    fn spawn(
        &mut self,
        _: &ExecutionRequest,
        _: &mut Logger,
        _: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        Err(ScriptResponse::rejected(CREATE_AND_RUN_UNSUPPORTED))
    }
}

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

fn with_pool_attempts(mut error: MxcError, attempts: Vec<Value>) -> MxcError {
    if !attempts.is_empty() {
        error
            .message
            .push_str(&format!("; pool checkout attempts={}", attempts.len()));
        error.details.get_or_insert_with(|| json!({}))["poolAttempts"] = json!(attempts);
    }
    error
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
    type StartMetadata = data_plane::ReadyMetadata;
    type StopMetadata = ReleaseMetadata;
    type DeprovisionMetadata = ReleaseMetadata;

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&Self::ProvisionConfig>,
    ) -> Result<(), MxcError> {
        policy(request)?;
        service::validate_provision(config)?;
        discovery::validate()
    }

    fn provision(
        &mut self,
        request: &ExecutionRequest,
        config: Option<Self::ProvisionConfig>,
    ) -> Result<ProvisionResult<Self::ProvisionMetadata>, MxcError> {
        self.validate_provision(request, config.as_ref())?;
        let config = service::validate_provision(config.as_ref())?;
        routing::preflight()?;
        let automatic = config.pool_id.is_none();
        let pools = match config.pool_id.as_ref() {
            Some(pool) => vec![pool.clone()],
            None => discovery::assigned_pools()?,
        };
        if pools.is_empty() {
            return Err(routing::error(
                "no_assigned_pools",
                "Graph returned no assigned pools",
            ));
        }
        let mut attempts = Vec::new();
        let mut last_error = routing::error(
            "no_available_sessions",
            "Graph reported no available sessions in the selected pools",
        );
        for pool in pools {
            let Some((client, source)) = discovery::control_plane(&pool)
                .map_err(|error| with_pool_attempts(error, attempts.clone()))?
            else {
                continue;
            };
            match client.checkout(&pool, config, source) {
                Ok(result) => return Ok(result),
                Err(error) => {
                    if !automatic || !service::can_try_next_pool(&error) {
                        return Err(with_pool_attempts(error, attempts));
                    }
                    if let Some(details) = error.details.as_ref() {
                        attempts.push(details.clone());
                    }
                    last_error = error;
                }
            }
        }
        Err(with_pool_attempts(last_error, attempts))
    }

    fn validate_start(
        &self,
        id: &str,
        request: &ExecutionRequest,
        _: Option<&()>,
    ) -> Result<(), MxcError> {
        policy(request)?;
        data_plane::client(&service::Identity::parse(id)?).map(|_| ())
    }

    fn start(
        &mut self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<()>,
    ) -> Result<StartResult<Self::StartMetadata>, MxcError> {
        self.validate_start(id, request, config.as_ref())?;
        Ok(StartResult {
            metadata: Some(data_plane::ready(&service::Identity::parse(id)?)?),
        })
    }

    fn validate_exec(
        &self,
        id: &str,
        request: &ExecutionRequest,
        _: Option<&()>,
    ) -> Result<(), MxcError> {
        policy(request)?;
        exec::validate(id, request)
    }

    fn exec(
        &mut self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<()>,
        stdio: ExecStdio,
    ) -> Result<ExecHandle, MxcError> {
        self.validate_exec(id, request, config.as_ref())?;
        exec::run(id, request, stdio)
    }

    fn validate_stop(
        &self,
        id: &str,
        request: &ExecutionRequest,
        _: Option<&()>,
    ) -> Result<(), MxcError> {
        policy(request)?;
        routing::client(&service::Identity::parse(id)?, false).map(|_| ())
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
        let identity = service::Identity::parse(id)?;
        routing::client(&identity, false)?.release(&identity)?;
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
