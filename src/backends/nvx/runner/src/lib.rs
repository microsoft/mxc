// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MXC adapter for the NVX Rust lifecycle API.

use std::path::PathBuf;
use std::time::Duration;

use aci_edge_sandboxes::openvmm::OpenVmmConfig;
use aci_edge_sandboxes::{
    Access, AciEdgeSandbox, EgressPolicy, ExecOutcome, ExecRequest, FilesystemPolicy,
    IngressPolicy, NetworkPeer, NetworkPolicy, NetworkPort, NetworkRule, Protocol,
    ProvisionRequest,
};
use wxc_common::logger::Logger;
use wxc_common::models::{
    ExecutionRequest, FailurePhase, NetworkAction, NetworkPeer as MxcNetworkPeer,
    NetworkPort as MxcNetworkPort, NetworkProtocol, NetworkRule as MxcNetworkRule, ScriptResponse,
};
use wxc_common::mxc_error::{MxcError, MxcErrorCode};
use wxc_common::script_runner::ScriptRunner;
use wxc_common::validator::{validate_network_policy_support, NetworkPolicySupport};

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
        validate_network_support(request)?;
        validate_request(request)?;

        let config = OpenVmmConfig::discover().map_err(map_nvx_error)?;
        let client = AciEdgeSandbox::openvmm(config).map_err(map_nvx_error)?;
        client.probe().map_err(map_nvx_error)?;

        let mut provision = ProvisionRequest::new();
        if let Some(filesystem) = filesystem_policy(request) {
            provision = provision.with_filesystem(filesystem);
        }
        if let Some(network) = network_policy(request)? {
            provision = provision.with_network(network);
        }
        if let Some(proxy) = network_proxy(request)? {
            provision = provision.with_network_proxy(proxy);
        }

        let provisioned = client.provision(&provision).map_err(map_nvx_error)?;
        let sandbox_id = provisioned.sandbox_id;
        let primary = (|| {
            client.start(&sandbox_id).map_err(map_nvx_error)?;
            let execution = client
                .exec(&sandbox_id, &exec_request(request))
                .map_err(map_nvx_error)?;
            execution.wait_with_output().map_err(map_nvx_error)
        })();

        let cleanup_errors: Vec<MxcError> = [
            client.stop(&sandbox_id).err().map(map_nvx_error),
            client.deprovision(&sandbox_id).err().map(map_nvx_error),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

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
            ExecOutcome::Signaled(signal) => CapturedOutcome::Exited(-signal),
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

impl ScriptRunner for NvxRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_network_support(request)
            .map_err(|error| ScriptResponse::rejected(&error.message))?;
        validate_request(request).map_err(|error| ScriptResponse::rejected(&error.message))
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        match self.run_captured(request, logger) {
            Ok(result) => {
                let standard_out = String::from_utf8_lossy(&result.stdout).into_owned();
                let standard_err = String::from_utf8_lossy(&result.stderr).into_owned();
                match result.outcome {
                    CapturedOutcome::Exited(exit_code) => ScriptResponse {
                        exit_code,
                        standard_out,
                        standard_err,
                        ..Default::default()
                    },
                    CapturedOutcome::TimedOut => ScriptResponse {
                        exit_code: -1,
                        standard_out,
                        standard_err,
                        error_message: "NVX workload timed out".to_string(),
                        failure_phase: FailurePhase::Timeout,
                        ..Default::default()
                    },
                }
            }
            Err(error) if error.code == MxcErrorCode::PolicyValidation => {
                ScriptResponse::rejected(&error.message)
            }
            Err(error) => ScriptResponse {
                exit_code: -1,
                error_message: error.to_string(),
                failure_phase: if error.code == MxcErrorCode::BackendUnavailable {
                    FailurePhase::BackendUnavailable
                } else {
                    FailurePhase::PostLaunchFailed
                },
                ..Default::default()
            },
        }
    }
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

fn validate_request(request: &ExecutionRequest) -> Result<(), MxcError> {
    if request.policy.ui_specified {
        return Err(MxcError::policy_validation(
            "NVX does not support the MXC UI policy",
        ));
    }

    if request.policy.capture_denials.is_some() {
        return Err(MxcError::policy_validation(
            "NVX does not support processContainer.captureDenials",
        ));
    }
    if request.policy.allowed_proxy_peer.is_some() {
        return Err(MxcError::policy_validation(
            "NVX does not support processContainer.network.allowedProxyPeer",
        ));
    }
    Ok(())
}

fn validate_network_support(request: &ExecutionRequest) -> Result<(), MxcError> {
    let support = NetworkPolicySupport::EGRESS_DEFAULT
        | NetworkPolicySupport::EGRESS_RULES
        | NetworkPolicySupport::INGRESS_DEFAULT
        | NetworkPolicySupport::HOST_LOOPBACK
        | NetworkPolicySupport::RUNTIME_PROXY;
    validate_network_policy_support(request, support)
        .map_err(|response| MxcError::policy_validation(response.error_message))
}

fn filesystem_policy(request: &ExecutionRequest) -> Option<FilesystemPolicy> {
    let policy = &request.policy;
    let filesystem = FilesystemPolicy {
        readonly_paths: policy.readonly_paths.iter().map(PathBuf::from).collect(),
        readwrite_paths: policy.readwrite_paths.iter().map(PathBuf::from).collect(),
        denied_paths: policy.denied_paths.iter().map(PathBuf::from).collect(),
    };
    (!filesystem.is_empty()).then_some(filesystem)
}

fn network_proxy(request: &ExecutionRequest) -> Result<Option<String>, MxcError> {
    if request.policy.network_proxy.builtin_test_server {
        return Err(MxcError::policy_validation(
            "NVX does not support network.proxy.builtinTestServer",
        ));
    }
    Ok(request
        .policy
        .network_proxy
        .address
        .as_ref()
        .map(|address| address.to_url()))
}

fn network_policy(request: &ExecutionRequest) -> Result<Option<NetworkPolicy>, MxcError> {
    let policy = &request.policy;
    if !policy.network_specified {
        return Ok(None);
    }
    let egress = policy.network_egress.as_ref().ok_or_else(|| {
        MxcError::policy_validation("NVX requires the directional network policy in 1.1.0-alpha")
    })?;
    let ingress = policy.network_ingress.as_ref().ok_or_else(|| {
        MxcError::policy_validation("NVX requires network.ingress in 1.1.0-alpha")
    })?;

    Ok(Some(NetworkPolicy {
        egress: EgressPolicy {
            default: access(egress.default),
            allow: egress.allow.iter().map(rule).collect(),
            deny: egress.deny.iter().map(rule).collect(),
        },
        ingress: IngressPolicy {
            default: access(ingress.default),
            host_loopback: Some(access(ingress.host_loopback)),
        },
    }))
}

fn access(action: NetworkAction) -> Access {
    match action {
        NetworkAction::Allow => Access::Allow,
        NetworkAction::Deny => Access::Deny,
    }
}

fn protocol(value: NetworkProtocol) -> Protocol {
    match value {
        NetworkProtocol::Tcp => Protocol::Tcp,
        NetworkProtocol::Udp => Protocol::Udp,
        NetworkProtocol::Icmp => Protocol::Icmp,
        NetworkProtocol::Any => Protocol::Any,
    }
}

fn peer(value: &MxcNetworkPeer) -> NetworkPeer {
    NetworkPeer {
        cidr: format!("{}/{}", value.cidr.address, value.cidr.prefix_length),
        except: value
            .except
            .iter()
            .map(|cidr| format!("{}/{}", cidr.address, cidr.prefix_length))
            .collect(),
    }
}

fn port(value: &MxcNetworkPort) -> NetworkPort {
    NetworkPort {
        protocol: protocol(value.protocol),
        port: value.port,
        end_port: value.end_port,
    }
}

fn rule(value: &MxcNetworkRule) -> NetworkRule {
    NetworkRule {
        to: value.to.iter().map(peer).collect(),
        ports: value.ports.iter().map(port).collect(),
    }
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
