// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed Rust SDK models for container lifecycle calls.

use std::fmt;

use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::sdk_input::{
    SdkFilesystemInput, SdkNetworkAction, SdkNetworkEgressInput, SdkNetworkIngressInput,
    SdkNetworkInput, SdkNetworkPeerInput, SdkNetworkPortInput, SdkNetworkProtocol,
    SdkNetworkRuleInput, SdkProcessInput, SdkRuntimeConfigInput, SdkStateAwareInput,
};
use crate::mxc_common::state_aware_operation::{
    StateAwareOperation as RuntimeOperation, StateAwareProvision as RuntimeProvision,
};
use crate::mxc_contract::ContractVersion;

use crate::policy::{
    FilesystemPolicy, NetworkAction, NetworkPeerPolicy, NetworkPolicy, NetworkPortPolicy,
    NetworkProtocol, NetworkRulePolicy, NetworkRuntimeConfig,
};
use crate::Error;

/// Backend selected by a typed lifecycle provision request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
enum ProvisionContainment {
    /// Windows IsolationSession with an optional application identifier.
    IsolationSession { app_id: Option<String> },
    /// WSL Container with optional image selection.
    Wslc {
        image: Option<String>,
        image_tar_path: Option<String>,
    },
}

impl ProvisionContainment {
    fn runtime_operation(&self) -> RuntimeOperation {
        RuntimeOperation::Provision(match self {
            Self::IsolationSession { app_id } => {
                RuntimeProvision::IsolationSession(app_id.clone().map(|app_id| {
                    crate::mxc_common::models::IsolationSessionProvisionConfig {
                        app_id: Some(app_id),
                    }
                }))
            }
            Self::Wslc {
                image,
                image_tar_path,
            } => {
                let config = if image.is_none() && image_tar_path.is_none() {
                    None
                } else {
                    Some(crate::mxc_common::models::WslcProvisionConfig {
                        image: image.clone(),
                        image_tar_path: image_tar_path.clone(),
                    })
                };
                RuntimeProvision::Wslc(config)
            }
        })
    }
}

/// Opaque identity returned for a provisioned container.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContainerId(String);

impl ContainerId {
    /// Parse a container identity previously returned by MXC.
    pub fn parse(value: impl Into<String>) -> Result<Self, Error> {
        Self::try_new(value.into()).map_err(Error::from)
    }

    fn try_new(value: String) -> Result<Self, MxcError> {
        if value.is_empty() {
            return Err(MxcError::malformed_id("container ID must not be empty"));
        }
        if value.contains('\0') {
            return Err(MxcError::malformed_id(
                "container ID must not contain a NUL character",
            ));
        }
        Ok(Self(value))
    }

    pub(crate) fn from_backend(value: String) -> Result<Self, MxcError> {
        Self::try_new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ContainerId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ContainerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Typed lifecycle provision request.
#[derive(Debug, Clone)]
pub struct ProvisionRequest {
    provision: ProvisionContainment,
    filesystem: Option<FilesystemPolicy>,
    network: Option<NetworkPolicy>,
    telemetry: Option<crate::options::TelemetryConfig>,
}

impl ProvisionRequest {
    /// Create an IsolationSession provision request with its required
    /// unrestricted directional network posture.
    ///
    /// `None` omits backend-specific provision configuration.
    pub fn isolation_session(app_id: Option<String>) -> Self {
        let egress = crate::policy::NetworkEgressPolicy {
            default: Some(NetworkAction::Allow),
            ..Default::default()
        };
        let ingress = crate::policy::NetworkIngressPolicy {
            default: Some(NetworkAction::Allow),
            host_loopback: Some(NetworkAction::Allow),
        };
        let network = NetworkPolicy {
            egress: Some(egress),
            ingress: Some(ingress),
            ..Default::default()
        };
        Self {
            provision: ProvisionContainment::IsolationSession { app_id },
            filesystem: None,
            network: Some(network),
            telemetry: None,
        }
    }

    /// Create a WSL Container provision request.
    ///
    /// When both image arguments are `None`, backend-specific provision
    /// configuration is omitted and the backend owns its defaults.
    pub fn wslc(image: Option<String>, image_tar_path: Option<String>) -> Self {
        Self {
            provision: ProvisionContainment::Wslc {
                image,
                image_tar_path,
            },
            filesystem: None,
            network: None,
            telemetry: None,
        }
    }

    /// Set provision-time filesystem policy.
    pub fn set_filesystem(&mut self, filesystem: FilesystemPolicy) -> &mut Self {
        self.filesystem = Some(filesystem);
        self
    }

    /// Set provision-time network policy.
    pub fn set_network(&mut self, network: NetworkPolicy) -> &mut Self {
        self.network = Some(network);
        self
    }

    /// Set the request's telemetry preference, subject to consent and policy.
    pub fn set_telemetry(&mut self, telemetry: crate::options::TelemetryConfig) -> &mut Self {
        self.telemetry = Some(telemetry);
        self
    }

    pub(crate) fn into_sdk_input(
        self,
        telemetry: Option<crate::options::TelemetryConfig>,
    ) -> Result<SdkStateAwareInput, MxcError> {
        let version = ContractVersion::V1_0_0;
        match &self.provision {
            ProvisionContainment::IsolationSession { .. } if self.filesystem.is_some() => {
                return Err(MxcError::malformed_request(
                    "IsolationSession state-aware provision does not accept filesystem policy",
                ));
            }
            _ => {}
        }
        let mut input = SdkStateAwareInput::new(version, self.provision.runtime_operation())
            .map_err(|error| MxcError::malformed_request(error.to_string()))?;
        input.filesystem = self.filesystem.as_ref().map(map_filesystem).transpose()?;
        let (network, runtime_config) = map_network(self.network.as_ref())?;
        input.network = network;
        input.runtime_config = runtime_config;
        input.telemetry_opt_in = telemetry
            .or(self.telemetry)
            .and_then(|config| config.enabled);
        Ok(input)
    }
}

pub(crate) fn lifecycle_sdk_input(
    sandbox_id: &ContainerId,
    telemetry: Option<crate::options::TelemetryConfig>,
    operation: fn(String) -> RuntimeOperation,
) -> Result<SdkStateAwareInput, MxcError> {
    let mut input = SdkStateAwareInput::new(
        ContractVersion::V1_0_0,
        operation(sandbox_id.as_str().to_owned()),
    )
    .map_err(|error| MxcError::malformed_request(error.to_string()))?;
    input.telemetry_opt_in = telemetry.and_then(|config| config.enabled);
    Ok(input)
}

/// Process settings for a workload in an existing container.
#[derive(Debug, Clone)]
pub struct ExecutionRequest {
    /// Command line to execute.
    pub command: String,
    /// Working directory inside the existing container.
    pub working_directory: Option<String>,
    /// Optional environment entries. `None` uses the backend default;
    /// `Some(Vec::new())` requests an explicitly empty environment.
    pub environment: Option<Vec<(String, String)>>,
    /// Whether supplied environment entries layer over the backend default.
    pub inherit_default_environment: Option<bool>,
    /// Execution timeout in milliseconds.
    pub timeout_ms: Option<u32>,
    /// Runtime-only network settings for this execution.
    ///
    /// Provision-time network policy is fixed on the existing container and
    /// cannot be changed by an exec request.
    pub network: Option<ProcessNetworkPolicy>,
    /// Per-invocation telemetry opt-in, subject to consent and policy.
    pub telemetry: Option<crate::options::TelemetryConfig>,
}

/// Runtime network settings available to an existing-container execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessNetworkPolicy {
    /// Runtime values such as the cooperative proxy URL.
    pub runtime_config: Option<NetworkRuntimeConfig>,
}

impl ExecutionRequest {
    /// Create process settings for `command` with backend defaults.
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            working_directory: None,
            environment: None,
            inherit_default_environment: None,
            timeout_ms: None,
            network: None,
            telemetry: None,
        }
    }

    pub(crate) fn into_sdk_input(
        self,
        sandbox_id: &ContainerId,
        telemetry: Option<crate::options::TelemetryConfig>,
    ) -> Result<SdkStateAwareInput, MxcError> {
        let mut input = SdkStateAwareInput::new(
            ContractVersion::V1_0_0,
            RuntimeOperation::Exec {
                sandbox_id: sandbox_id.as_str().to_owned(),
            },
        )
        .map_err(|error| MxcError::malformed_request(error.to_string()))?;
        input.process = Some(SdkProcessInput {
            command_line: self.command,
            cwd: self.working_directory,
            env: self.environment.map(|environment| {
                environment
                    .into_iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect()
            }),
            inherit_default_env: self.inherit_default_environment,
            timeout: self.timeout_ms,
        });
        input.runtime_config =
            self.network
                .and_then(|network| network.runtime_config)
                .map(|runtime_config| SdkRuntimeConfigInput {
                    network_proxy: runtime_config.network_proxy,
                });
        input.telemetry_opt_in = telemetry
            .or(self.telemetry)
            .and_then(|config| config.enabled);
        Ok(input)
    }
}

/// IsolationSession metadata returned by a successful provision.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IsolationSessionProvisionMetadata {
    pub agent_user_name: String,
    pub agent_user_sid: String,
    pub ephemeral_workspace_path: String,
}

/// Backend-specific metadata returned by a typed lifecycle call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvisionMetadata {
    IsolationSessionProvision(IsolationSessionProvisionMetadata),
}

/// Result of successfully provisioning a container.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProvisionResult {
    pub container_id: ContainerId,
    pub metadata: Option<ProvisionMetadata>,
    pub warnings: Vec<String>,
}

/// Result of successfully starting, stopping, or deprovisioning a container.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LifecycleResult {
    pub warnings: Vec<String>,
}

/// Result of validating an operation without executing it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ValidationResult {
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StateAwareResult {
    pub sandbox_id: Option<String>,
    pub metadata: Option<ProvisionMetadata>,
    pub warnings: Vec<String>,
}

impl StateAwareResult {
    pub(crate) fn from_engine(result: crate::mxc_engine::EngineStateAwareResult) -> Self {
        let metadata = result.metadata.map(|metadata| match metadata {
            crate::mxc_engine::EngineProvisionMetadata::IsolationSession {
                agent_user_name,
                agent_user_sid,
                ephemeral_workspace_path,
                ..
            } => ProvisionMetadata::IsolationSessionProvision(IsolationSessionProvisionMetadata {
                agent_user_name,
                agent_user_sid,
                ephemeral_workspace_path,
            }),
        });
        Self {
            sandbox_id: result.sandbox_id,
            metadata,
            warnings: result.warnings,
        }
    }

    pub(crate) fn into_provision(self) -> Result<ProvisionResult, MxcError> {
        let sandbox_id = self.sandbox_id.ok_or_else(|| {
            MxcError::backend_error("typed provision completed without returning a sandbox ID")
        })?;
        Ok(ProvisionResult {
            container_id: ContainerId::from_backend(sandbox_id)?,
            metadata: self.metadata,
            warnings: self.warnings,
        })
    }

    pub(crate) fn into_lifecycle(self) -> Result<LifecycleResult, MxcError> {
        if self.sandbox_id.is_some() || self.metadata.is_some() {
            return Err(MxcError::backend_error(
                "typed lifecycle operation returned provision-only output",
            ));
        }
        Ok(LifecycleResult {
            warnings: self.warnings,
        })
    }

    pub(crate) fn into_validation(self) -> Result<ValidationResult, MxcError> {
        if self.sandbox_id.is_some() || self.metadata.is_some() {
            return Err(MxcError::backend_error(
                "typed dry run returned execution output",
            ));
        }
        Ok(ValidationResult {
            warnings: self.warnings,
        })
    }
}

fn map_filesystem(value: &FilesystemPolicy) -> Result<SdkFilesystemInput, MxcError> {
    if value.clear_policy_on_exit.is_some() {
        return Err(MxcError::malformed_request(
            "state-aware provision filesystem policy does not accept clearPolicyOnExit",
        ));
    }
    Ok(SdkFilesystemInput {
        readwrite_paths: value.readwrite_paths.clone(),
        readonly_paths: value.readonly_paths.clone(),
        denied_paths: value.denied_paths.clone(),
    })
}

fn map_network(
    value: Option<&NetworkPolicy>,
) -> Result<(Option<SdkNetworkInput>, Option<SdkRuntimeConfigInput>), MxcError> {
    let Some(value) = value else {
        return Ok((None, None));
    };
    let network =
        if value.runtime_config.is_none() || value.egress.is_some() || value.ingress.is_some() {
            Some(SdkNetworkInput {
                egress: value.egress.as_ref().map(map_egress).transpose()?,
                ingress: value.ingress.as_ref().map(map_ingress),
            })
        } else {
            None
        };
    let runtime_config = value
        .runtime_config
        .as_ref()
        .map(|runtime| SdkRuntimeConfigInput {
            network_proxy: runtime.network_proxy.clone(),
        });
    Ok((network, runtime_config))
}

fn map_egress(
    value: &crate::policy::NetworkEgressPolicy,
) -> Result<SdkNetworkEgressInput, MxcError> {
    Ok(SdkNetworkEgressInput {
        default: value.default.map(map_action),
        allow: value
            .allow
            .as_ref()
            .map(|rules| rules.iter().map(map_rule).collect())
            .transpose()?,
        deny: value
            .deny
            .as_ref()
            .map(|rules| rules.iter().map(map_rule).collect())
            .transpose()?,
    })
}

fn map_ingress(value: &crate::policy::NetworkIngressPolicy) -> SdkNetworkIngressInput {
    SdkNetworkIngressInput {
        default: value.default.map(map_action),
        host_loopback: value.host_loopback.map(map_action),
    }
}

fn map_rule(value: &NetworkRulePolicy) -> Result<SdkNetworkRuleInput, MxcError> {
    Ok(SdkNetworkRuleInput {
        to: value
            .to
            .as_ref()
            .map(|peers| peers.iter().map(map_peer).collect()),
        ports: value
            .ports
            .as_ref()
            .map(|ports| ports.iter().map(map_port).collect::<Result<Vec<_>, _>>())
            .transpose()?,
    })
}

fn map_peer(value: &NetworkPeerPolicy) -> SdkNetworkPeerInput {
    SdkNetworkPeerInput {
        cidr: value.cidr.clone(),
        except: value.except.clone(),
    }
}

fn map_port(value: &NetworkPortPolicy) -> Result<SdkNetworkPortInput, MxcError> {
    if value.port == Some(0) || value.end_port == Some(0) {
        return Err(MxcError::malformed_request(
            "network ports must be non-zero",
        ));
    }
    Ok(SdkNetworkPortInput {
        protocol: value.protocol.map(map_protocol),
        port: value.port,
        end_port: value.end_port,
    })
}

fn map_action(value: NetworkAction) -> SdkNetworkAction {
    match value {
        NetworkAction::Allow => SdkNetworkAction::Allow,
        NetworkAction::Deny => SdkNetworkAction::Deny,
    }
}

fn map_protocol(value: NetworkProtocol) -> SdkNetworkProtocol {
    match value {
        NetworkProtocol::Tcp => SdkNetworkProtocol::Tcp,
        NetworkProtocol::Udp => SdkNetworkProtocol::Udp,
        NetworkProtocol::Icmp => SdkNetworkProtocol::Icmp,
        NetworkProtocol::Any => SdkNetworkProtocol::Any,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::config_parser::{
        load_mxc_request_from_json, normalize_sdk_state_aware_request,
    };
    use crate::mxc_common::logger::{Logger, Mode};
    use crate::mxc_common::mxc_error::MxcErrorCode;
    use crate::mxc_common::state_aware_request::{MxcRequest, ParsedStateAwareRequest};
    use crate::policy::NetworkEgressPolicy;

    type LifecyclePhase = (&'static str, fn(String) -> RuntimeOperation);

    fn lifecycle_phases() -> [LifecyclePhase; 3] {
        [
            ("start", |sandbox_id| RuntimeOperation::Start { sandbox_id }),
            ("stop", |sandbox_id| RuntimeOperation::Stop { sandbox_id }),
            ("deprovision", |sandbox_id| RuntimeOperation::Deprovision {
                sandbox_id,
            }),
        ]
    }

    fn request_intent(request: &ParsedStateAwareRequest) -> serde_json::Value {
        let mut value = serde_json::to_value(request.request()).unwrap();
        value.as_object_mut().unwrap().remove("source_contract");
        value
    }

    fn assert_matches_exact(json: &str, input: SdkStateAwareInput) {
        let exact = match load_mxc_request_from_json(json, &mut Logger::new(Mode::Buffer)).unwrap()
        {
            MxcRequest::StateAware(request) => request,
            MxcRequest::OneShot(_) => panic!("expected a state-aware exact request"),
        };
        let typed =
            normalize_sdk_state_aware_request(input, &mut Logger::new(Mode::Buffer)).unwrap();

        assert_eq!(typed.operation(), exact.operation());
        assert!(
            exact.request().source_contract.is_some(),
            "exact JSON must retain contract attribution"
        );
        assert_eq!(
            typed.request().source_contract,
            None,
            "typed SDK input has no external contract source"
        );
        assert_eq!(request_intent(&typed), request_intent(&exact));
    }

    fn assert_provision_matches_exact(
        json: &str,
        request: ProvisionRequest,
        telemetry_opt_in: Option<bool>,
    ) {
        assert_matches_exact(
            json,
            request
                .into_sdk_input(
                    telemetry_opt_in.map(|enabled| crate::options::TelemetryConfig {
                        enabled: Some(enabled),
                    }),
                )
                .unwrap(),
        );
    }

    fn assert_lifecycle_matches_exact(
        json: &str,
        sandbox_id: &str,
        operation: fn(String) -> RuntimeOperation,
        telemetry_opt_in: Option<bool>,
    ) {
        let id = ContainerId::parse(sandbox_id).unwrap();
        let input = lifecycle_sdk_input(
            &id,
            telemetry_opt_in.map(|enabled| crate::options::TelemetryConfig {
                enabled: Some(enabled),
            }),
            operation,
        )
        .unwrap();
        assert_matches_exact(json, input);
    }

    fn assert_exec_matches_exact(
        json: &str,
        sandbox_id: &str,
        request: ExecutionRequest,
        telemetry_opt_in: Option<bool>,
    ) {
        let id = ContainerId::parse(sandbox_id).unwrap();
        let input = request
            .into_sdk_input(
                &id,
                telemetry_opt_in.map(|enabled| crate::options::TelemetryConfig {
                    enabled: Some(enabled),
                }),
            )
            .unwrap();
        assert_matches_exact(json, input);
    }

    #[test]
    fn telemetry_options_override_request_even_when_enabled_is_omitted() {
        let id = ContainerId::parse("wslc:test").unwrap();
        for preference in [None, Some(false), Some(true)] {
            let mut request = ExecutionRequest::new("echo hello");
            request.telemetry = Some(crate::options::TelemetryConfig {
                enabled: Some(true),
            });
            let input = request
                .into_sdk_input(
                    &id,
                    Some(crate::options::TelemetryConfig {
                        enabled: preference,
                    }),
                )
                .unwrap();
            assert_eq!(input.telemetry_opt_in, preference);

            let mut provision = ProvisionRequest::wslc(None, None);
            provision.set_telemetry(crate::options::TelemetryConfig {
                enabled: Some(true),
            });
            let input = provision
                .into_sdk_input(Some(crate::options::TelemetryConfig {
                    enabled: preference,
                }))
                .unwrap();
            assert_eq!(input.telemetry_opt_in, preference);
        }
    }

    #[test]
    fn typed_provision_rejects_clear_policy_on_exit() {
        for enabled in [true, false] {
            let mut request = ProvisionRequest::wslc(None, None);
            request.set_filesystem(FilesystemPolicy {
                clear_policy_on_exit: Some(enabled),
                ..Default::default()
            });

            let error = request.into_sdk_input(None).unwrap_err();
            assert_eq!(error.code, MxcErrorCode::MalformedRequest);
            assert!(
                error.message.contains("clearPolicyOnExit"),
                "got: {}",
                error.message
            );
        }
    }

    #[test]
    fn sdk_lifecycle_parity_provision_matches_exact_json() {
        let options = None;
        assert_provision_matches_exact(
            r#"{
                "version":"1.0.0",
                "phase":"provision",
                "containment":"isolation_session",
                "network":{
                    "egress":{"default":"allow"},
                    "ingress":{"default":"allow","hostLoopback":"allow"}
                },
                "isolationSession":{"provision":{"appId":"example"}}
            }"#,
            ProvisionRequest::isolation_session(Some("example".to_string())),
            options,
        );
        assert_provision_matches_exact(
            r#"{
                "version":"1.0.0",
                "phase":"provision",
                "containment":"isolation_session",
                "network":{
                    "egress":{"default":"allow"},
                    "ingress":{"default":"allow","hostLoopback":"allow"}
                }
            }"#,
            ProvisionRequest::isolation_session(None),
            options,
        );
        assert_provision_matches_exact(
            r#"{
                "version":"1.0.0",
                "phase":"provision",
                "containment":"isolation_session",
                "network":{
                    "egress":{"default":"allow"},
                    "ingress":{"default":"allow","hostLoopback":"allow"}
                },
                "isolationSession":{"provision":{"appId":""}}
            }"#,
            ProvisionRequest::isolation_session(Some(String::new())),
            options,
        );
        assert_provision_matches_exact(
            r#"{
                "version":"1.0.0",
                "phase":"provision",
                "containment":"wslc",
                "wslc":{"provision":{"image":"python:3.12","imageTarPath":"image.tar"}}
            }"#,
            ProvisionRequest::wslc(
                Some("python:3.12".to_string()),
                Some("image.tar".to_string()),
            ),
            options,
        );
        assert_provision_matches_exact(
            r#"{"version":"1.0.0","phase":"provision","containment":"wslc"}"#,
            ProvisionRequest::wslc(None, None),
            options,
        );
        assert_provision_matches_exact(
            r#"{
                "version":"1.0.0",
                "phase":"provision",
                "containment":"wslc",
                "wslc":{"provision":{"image":"","imageTarPath":""}}
            }"#,
            ProvisionRequest::wslc(Some(String::new()), Some(String::new())),
            options,
        );

        let mut filesystem = ProvisionRequest::wslc(Some("python:3.12".to_string()), None);
        filesystem.set_filesystem(FilesystemPolicy {
            readwrite_paths: vec!["/tmp/readwrite".to_string()],
            readonly_paths: vec!["/tmp/readonly".to_string()],
            denied_paths: vec!["/tmp/denied".to_string()],
            ..Default::default()
        });
        assert_provision_matches_exact(
            r#"{
                "version":"1.0.0",
                "phase":"provision",
                "containment":"wslc",
                "wslc":{"provision":{"image":"python:3.12"}},
                "filesystem":{
                    "readwritePaths":["/tmp/readwrite"],
                    "readonlyPaths":["/tmp/readonly"],
                    "deniedPaths":["/tmp/denied"]
                }
            }"#,
            filesystem,
            options,
        );

        let mut peer = NetworkPeerPolicy::new("10.0.0.0/8");
        peer.except = Some(vec!["10.1.0.0/16".to_string()]);
        let mut network = ProvisionRequest::wslc(Some("python:3.12".to_string()), None);
        network.set_network(NetworkPolicy {
            egress: Some(NetworkEgressPolicy {
                default: Some(NetworkAction::Deny),
                allow: Some(vec![NetworkRulePolicy {
                    to: Some(vec![peer]),
                    ports: Some(vec![NetworkPortPolicy {
                        protocol: Some(NetworkProtocol::Tcp),
                        port: Some(80),
                        end_port: Some(81),
                    }]),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        });
        assert_provision_matches_exact(
            r#"{
                "version":"1.0.0",
                "phase":"provision",
                "containment":"wslc",
                "wslc":{"provision":{"image":"python:3.12"}},
                "network":{
                    "egress":{
                        "default":"deny",
                        "allow":[{
                            "to":[{
                                "cidr":"10.0.0.0/8",
                                "except":["10.1.0.0/16"]
                            }],
                            "ports":[{
                                "protocol":"tcp",
                                "port":80,
                                "endPort":81
                            }]
                        }]
                    }
                }
            }"#,
            network,
            options,
        );

        let mut empty_network = ProvisionRequest::wslc(Some("python:3.12".to_string()), None);
        empty_network.set_network(NetworkPolicy::default());
        assert_provision_matches_exact(
            r#"{
                "version":"1.0.0",
                "phase":"provision",
                "containment":"wslc",
                "wslc":{"provision":{"image":"python:3.12"}},
                "network":{}
            }"#,
            empty_network,
            options,
        );
    }

    #[test]
    fn sdk_lifecycle_parity_exec_and_lifecycle_match_exact_json() {
        let options = None;
        for (phase, operation) in lifecycle_phases() {
            let json = format!(r#"{{"version":"1.0.0","phase":"{phase}","sandboxId":"iso:abc"}}"#);
            assert_lifecycle_matches_exact(&json, "iso:abc", operation, options);
        }

        let exec = ExecutionRequest {
            working_directory: Some("C:\\work".to_string()),
            environment: Some(vec![
                ("A".to_string(), "one".to_string()),
                ("B".to_string(), "two".to_string()),
            ]),
            inherit_default_environment: Some(false),
            timeout_ms: Some(1234),
            ..ExecutionRequest::new("echo configured")
        };
        assert_exec_matches_exact(
            r#"{
                "version":"1.0.0",
                "phase":"exec",
                "sandboxId":"iso:abc",
                "process":{
                    "commandLine":"echo configured",
                    "cwd":"C:\\work",
                    "env":["A=one","B=two"],
                    "inheritDefaultEnv":false,
                    "timeout":1234
                }
            }"#,
            "iso:abc",
            exec,
            options,
        );

        let empty_environment = ExecutionRequest {
            environment: Some(Vec::new()),
            ..ExecutionRequest::new("echo empty")
        };
        assert_exec_matches_exact(
            r#"{
                "version":"1.0.0",
                "phase":"exec",
                "sandboxId":"iso:abc",
                "process":{"commandLine":"echo empty","env":[]}
            }"#,
            "iso:abc",
            empty_environment,
            options,
        );

        let proxy_exec = ExecutionRequest {
            network: Some(ProcessNetworkPolicy {
                runtime_config: Some(NetworkRuntimeConfig {
                    network_proxy: Some("http://127.0.0.1:8080".to_string()),
                }),
            }),
            ..ExecutionRequest::new("echo proxied")
        };
        assert_exec_matches_exact(
            r#"{
                "version":"1.0.0",
                "phase":"exec",
                "sandboxId":"wslc:abc",
                "process":{"commandLine":"echo proxied"},
                "runtimeConfig":{"networkProxy":"http://127.0.0.1:8080"}
            }"#,
            "wslc:abc",
            proxy_exec,
            options,
        );
    }

    #[test]
    fn sdk_lifecycle_parity_operation_options_preserve_telemetry() {
        for enabled in [false, true] {
            let options = Some(enabled);
            let provision_json = format!(
                r#"{{"version":"1.0.0","phase":"provision","containment":"wslc","telemetry":{{"enabled":{enabled}}}}}"#
            );
            assert_provision_matches_exact(
                &provision_json,
                ProvisionRequest::wslc(None, None),
                options,
            );

            for (phase, operation) in lifecycle_phases() {
                let json = format!(
                    r#"{{"version":"1.0.0","phase":"{phase}","sandboxId":"wslc:abc","telemetry":{{"enabled":{enabled}}}}}"#
                );
                assert_lifecycle_matches_exact(&json, "wslc:abc", operation, options);
            }

            let exec_json = format!(
                r#"{{"version":"1.0.0","phase":"exec","sandboxId":"wslc:abc","process":{{"commandLine":"echo hello"}},"telemetry":{{"enabled":{enabled}}}}}"#
            );
            assert_exec_matches_exact(
                &exec_json,
                "wslc:abc",
                ExecutionRequest::new("echo hello"),
                options,
            );
        }
    }
}
