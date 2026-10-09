// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal MXC adapter for one-shot execution through the NVX Rust API.

use std::time::Duration;

use aci_edge_sandboxes::openvmm::OpenVmmConfig;
use aci_edge_sandboxes::{AciEdgeSandbox, ExecOutcome, ExecRequest, ProvisionRequest};
use wxc_common::logger::Logger;
use wxc_common::models::ExecutionRequest;
use wxc_common::mxc_error::{MxcError, MxcErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedOutcome {
    Exited(i32),
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedRun {
    pub outcome: CapturedOutcome,
    pub warnings: Vec<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct NvxRunner;

impl NvxRunner {
    pub fn new() -> Self {
        Self
    }

    pub fn run_captured(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<CapturedRun, MxcError> {
        reject_deferred_policy(request)?;

        let config = OpenVmmConfig::discover().map_err(map_nvx_error)?;
        let client = AciEdgeSandbox::openvmm(config).map_err(map_nvx_error)?;
        client.probe().map_err(map_nvx_error)?;

        let provisioned = client
            .provision(&ProvisionRequest::new())
            .map_err(map_nvx_error)?;
        let sandbox_id = provisioned.sandbox_id;
        let primary = (|| {
            client.start(&sandbox_id).map_err(map_nvx_error)?;
            let execution = client
                .exec(&sandbox_id, &exec_request(request))
                .map_err(map_nvx_error)?;
            execution.wait_with_output().map_err(map_nvx_error)
        })();

        let stop_error = client.stop(&sandbox_id).err().map(map_nvx_error);
        let stop_error = match stop_error {
            Some(error) if primary.is_err() && error.code == MxcErrorCode::AlreadyStopped => None,
            other => other,
        };
        let cleanup_errors: Vec<MxcError> = [
            stop_error,
            client.deprovision(&sandbox_id).err().map(map_nvx_error),
        ]
        .into_iter()
        .flatten()
        .collect();

        let output = match primary {
            Ok(output) if cleanup_errors.is_empty() => output,
            Ok(_) => {
                return Err(MxcError::backend_error(format!(
                    "NVX cleanup failed after workload completion: {}",
                    cleanup_errors
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ")
                )));
            }
            Err(mut error) => {
                for cleanup in cleanup_errors {
                    let warning = format!("NVX cleanup failed: {cleanup}");
                    logger.warning_line(&warning);
                    error.message.push_str("; cleanup failure: ");
                    error.message.push_str(&cleanup.to_string());
                }
                return Err(error);
            }
        };

        let outcome = match output.outcome {
            ExecOutcome::Exited(code) => CapturedOutcome::Exited(code),
            ExecOutcome::TimedOut => CapturedOutcome::TimedOut,
            ExecOutcome::Signaled(signal) => {
                CapturedOutcome::Exited(128_i32.saturating_add(signal))
            }
            other => {
                return Err(MxcError::backend_error(format!(
                    "NVX workload did not complete normally: {other}"
                )));
            }
        };

        Ok(CapturedRun {
            outcome,
            warnings: Vec::new(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

fn reject_deferred_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    let policy = &request.policy;
    let filesystem_supplied = !policy.readonly_paths.is_empty()
        || !policy.readwrite_paths.is_empty()
        || !policy.enumerate_paths.is_empty()
        || !policy.denied_paths.is_empty();
    let network_supplied = policy.network_specified
        || policy.runtime_network_proxy_specified
        || policy.network_proxy.is_enabled();

    if filesystem_supplied || network_supplied || policy.ui_specified {
        return Err(MxcError::policy_validation(
            "the initial NVX integration supports process settings only; filesystem, network, and UI policies are not yet supported",
        ));
    }
    Ok(())
}

fn exec_request(request: &ExecutionRequest) -> ExecRequest {
    let mut exec = ExecRequest::command_line(request.script_code.clone());
    if request.script_timeout != 0 {
        exec = exec.with_timeout(Duration::from_millis(u64::from(request.script_timeout)));
    }
    if !request.working_directory.is_empty() {
        exec = exec.with_cwd(request.working_directory.clone());
    }
    if let Some(environment) = &request.env {
        exec = exec.with_envs(environment.clone());
        exec = exec.with_inherit_default_env(request.inherit_default_env);
    }
    exec
}

fn map_nvx_error(error: aci_edge_sandboxes::Error) -> MxcError {
    let code = match error.code() {
        aci_edge_sandboxes::ErrorCode::MalformedRequest => MxcErrorCode::MalformedRequest,
        aci_edge_sandboxes::ErrorCode::MalformedId => MxcErrorCode::MalformedId,
        aci_edge_sandboxes::ErrorCode::StaleId => MxcErrorCode::StaleId,
        aci_edge_sandboxes::ErrorCode::NotStarted => MxcErrorCode::NotStarted,
        aci_edge_sandboxes::ErrorCode::AlreadyStarted => MxcErrorCode::AlreadyStarted,
        aci_edge_sandboxes::ErrorCode::AlreadyStopped => MxcErrorCode::AlreadyStopped,
        aci_edge_sandboxes::ErrorCode::PolicyValidation => MxcErrorCode::PolicyValidation,
        aci_edge_sandboxes::ErrorCode::BackendUnavailable => MxcErrorCode::BackendUnavailable,
        aci_edge_sandboxes::ErrorCode::Unsupported
        | aci_edge_sandboxes::ErrorCode::BackendError => MxcErrorCode::BackendError,
        _ => MxcErrorCode::BackendError,
    };
    MxcError::new(code, error.message())
}
