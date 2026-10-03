// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed Rust SDK models for state-aware lifecycle calls.

use std::fmt;

use mxc_config_contract::ContractVersion;
use wxc_common::mxc_error::MxcError;
use wxc_common::sdk_input::{
    SdkFilesystemInput, SdkNetworkAction, SdkNetworkEgressInput, SdkNetworkIngressInput,
    SdkNetworkInput, SdkNetworkPeerInput, SdkNetworkPortInput, SdkNetworkProtocol,
    SdkNetworkRuleInput, SdkProcessInput, SdkRuntimeConfigInput, SdkStateAwareInput,
};
use wxc_common::state_aware_operation::{
    StateAwareOperation as RuntimeOperation, StateAwareProvision as RuntimeProvision,
};

use crate::policy::{
    FilesystemSection, NetworkAction, NetworkPeerSection, NetworkPortSection, NetworkProtocol,
    NetworkRuleSection, NetworkSection,
};
use crate::Error;

/// Backend selected by a typed state-aware provision request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateAwareProvision {
    /// Windows IsolationSession with an optional application identifier.
    IsolationSession { app_id: Option<String> },
    /// WSL Container with optional image selection.
    Wslc {
        image: Option<String>,
        image_tar_path: Option<String>,
    },
}

impl StateAwareProvision {
    fn runtime_operation(&self) -> RuntimeOperation {
        RuntimeOperation::Provision(match self {
            Self::IsolationSession { app_id } => {
                RuntimeProvision::IsolationSession(app_id.clone().map(|app_id| {
                    wxc_common::models::IsolationSessionProvisionConfig {
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
                    Some(wxc_common::models::WslcProvisionConfig {
                        image: image.clone(),
                        image_tar_path: image_tar_path.clone(),
                    })
                };
                RuntimeProvision::Wslc(config)
            }
        })
    }
}

/// Opaque identity returned for a provisioned state-aware sandbox.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SandboxId(String);

impl SandboxId {
    /// Parse a sandbox identity previously returned by MXC.
    pub fn parse(value: impl Into<String>) -> Result<Self, Error> {
        Self::try_new(value.into()).map_err(Error::from)
    }

    fn try_new(value: String) -> Result<Self, MxcError> {
        if value.is_empty() {
            return Err(MxcError::malformed_id("sandbox ID must not be empty"));
        }
        if value.contains('\0') {
            return Err(MxcError::malformed_id(
                "sandbox ID must not contain a NUL character",
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

impl AsRef<str> for SandboxId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Typed state-aware provision request.
#[derive(Debug, Clone)]
pub struct ProvisionRequest {
    provision: StateAwareProvision,
    filesystem: Option<FilesystemSection>,
    network: Option<NetworkSection>,
}

impl ProvisionRequest {
    /// Create an IsolationSession provision request with its required
    /// unrestricted directional network posture.
    ///
    /// `None` omits backend-specific provision configuration.
    pub fn isolation_session(app_id: Option<String>) -> Self {
        let egress = crate::policy::NetworkEgressSection {
            default: Some(NetworkAction::Allow),
            ..Default::default()
        };
        let ingress = crate::policy::NetworkIngressSection {
            default: Some(NetworkAction::Allow),
            host_loopback: Some(NetworkAction::Allow),
        };
        let network = NetworkSection {
            egress: Some(egress),
            ingress: Some(ingress),
            ..Default::default()
        };
        Self {
            provision: StateAwareProvision::IsolationSession { app_id },
            filesystem: None,
            network: Some(network),
        }
    }

    /// Create a WSL Container provision request.
    ///
    /// When both image arguments are `None`, backend-specific provision
    /// configuration is omitted and the backend owns its defaults.
    pub fn wslc(image: Option<String>, image_tar_path: Option<String>) -> Self {
        Self {
            provision: StateAwareProvision::Wslc {
                image,
                image_tar_path,
            },
            filesystem: None,
            network: None,
        }
    }

    /// Set provision-time filesystem policy.
    pub fn set_filesystem(&mut self, filesystem: FilesystemSection) -> &mut Self {
        self.filesystem = Some(filesystem);
        self
    }

    /// Set provision-time network policy.
    pub fn set_network(&mut self, network: NetworkSection) -> &mut Self {
        self.network = Some(network);
        self
    }

    pub(crate) fn into_sdk_input(
        self,
        telemetry_opt_in: Option<bool>,
    ) -> Result<SdkStateAwareInput, MxcError> {
        let version = ContractVersion::V1_0_0;
        match &self.provision {
            StateAwareProvision::IsolationSession { .. } if self.filesystem.is_some() => {
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
        input.telemetry_opt_in = telemetry_opt_in;
        Ok(input)
    }
}

pub(crate) fn lifecycle_sdk_input(
    sandbox_id: &SandboxId,
    telemetry_opt_in: Option<bool>,
    operation: fn(String) -> RuntimeOperation,
) -> Result<SdkStateAwareInput, MxcError> {
    let mut input = SdkStateAwareInput::new(
        ContractVersion::V1_0_0,
        operation(sandbox_id.as_str().to_owned()),
    )
    .map_err(|error| MxcError::malformed_request(error.to_string()))?;
    input.telemetry_opt_in = telemetry_opt_in;
    Ok(input)
}

/// Typed state-aware exec request.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    command_line: String,
    working_directory: Option<String>,
    environment: Option<Vec<String>>,
    inherit_default_env: Option<bool>,
    timeout_ms: Option<u32>,
    backend_options: Option<StateAwareExecBackendOptions>,
}

/// Backend-specific options for a typed state-aware exec request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateAwareExecBackendOptions {
    /// WSLc cooperative proxy configuration.
    Wslc { network_proxy: String },
}

impl ExecRequest {
    pub fn new(command_line: impl Into<String>) -> Self {
        Self {
            command_line: command_line.into(),
            working_directory: None,
            environment: None,
            inherit_default_env: None,
            timeout_ms: None,
            backend_options: None,
        }
    }

    pub fn set_working_directory(&mut self, directory: impl Into<String>) -> &mut Self {
        self.working_directory = Some(directory.into());
        self
    }

    pub fn set_environment(
        &mut self,
        environment: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> &mut Self {
        self.environment = Some(
            environment
                .into_iter()
                .map(|(key, value)| format!("{}={}", key.into(), value.into()))
                .collect(),
        );
        self
    }

    pub fn inherit_default_env(&mut self, enabled: bool) -> &mut Self {
        self.inherit_default_env = Some(enabled);
        self
    }

    pub fn set_timeout(&mut self, timeout_ms: u32) -> &mut Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }

    /// Set options interpreted by the backend selected from the sandbox ID.
    ///
    /// A backend rejects options it cannot enforce.
    pub fn set_backend_options(&mut self, options: StateAwareExecBackendOptions) -> &mut Self {
        self.backend_options = Some(options);
        self
    }

    pub(crate) fn into_sdk_input(
        self,
        sandbox_id: &SandboxId,
        telemetry_opt_in: Option<bool>,
    ) -> Result<SdkStateAwareInput, MxcError> {
        let mut input = SdkStateAwareInput::new(
            ContractVersion::V1_0_0,
            RuntimeOperation::Exec {
                sandbox_id: sandbox_id.as_str().to_owned(),
            },
        )
        .map_err(|error| MxcError::malformed_request(error.to_string()))?;
        input.process = Some(SdkProcessInput {
            command_line: self.command_line,
            cwd: self.working_directory,
            env: self.environment,
            inherit_default_env: self.inherit_default_env,
            timeout: self.timeout_ms,
        });
        input.runtime_config = self.backend_options.map(|options| match options {
            StateAwareExecBackendOptions::Wslc { network_proxy } => SdkRuntimeConfigInput {
                network_proxy: Some(network_proxy),
            },
        });
        input.telemetry_opt_in = telemetry_opt_in;
        Ok(input)
    }
}

/// Authorization and invocation controls for a lifecycle operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OperationOptions {
    pub experimental: bool,
    pub telemetry_opt_in: Option<bool>,
}

impl OperationOptions {
    pub fn new(experimental: bool) -> Self {
        Self {
            experimental,
            telemetry_opt_in: None,
        }
    }

    /// Set the per-invocation telemetry preference.
    pub fn with_telemetry_opt_in(mut self, enabled: bool) -> Self {
        self.telemetry_opt_in = Some(enabled);
        self
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

/// Result of successfully provisioning a sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProvisionResult {
    pub sandbox_id: SandboxId,
    pub metadata: Option<ProvisionMetadata>,
    pub warnings: Vec<String>,
}

/// Result of successfully starting, stopping, or deprovisioning a sandbox.
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
    pub(crate) fn from_engine(result: mxc_engine::EngineStateAwareResult) -> Self {
        let metadata = result.metadata.map(|metadata| match metadata {
            mxc_engine::EngineProvisionMetadata::IsolationSession {
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
            sandbox_id: SandboxId::from_backend(sandbox_id)?,
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

fn map_filesystem(value: &FilesystemSection) -> Result<SdkFilesystemInput, MxcError> {
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
    value: Option<&NetworkSection>,
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
    value: &crate::policy::NetworkEgressSection,
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

fn map_ingress(value: &crate::policy::NetworkIngressSection) -> SdkNetworkIngressInput {
    SdkNetworkIngressInput {
        default: value.default.map(map_action),
        host_loopback: value.host_loopback.map(map_action),
    }
}

fn map_rule(value: &NetworkRuleSection) -> Result<SdkNetworkRuleInput, MxcError> {
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

fn map_peer(value: &NetworkPeerSection) -> SdkNetworkPeerInput {
    SdkNetworkPeerInput {
        cidr: value.cidr.clone(),
        except: value.except.clone(),
    }
}

fn map_port(value: &NetworkPortSection) -> Result<SdkNetworkPortInput, MxcError> {
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
    use crate::policy::NetworkEgressSection;
    use wxc_common::config_parser::{
        load_mxc_request_from_json, normalize_sdk_state_aware_request,
    };
    use wxc_common::logger::{Logger, Mode};
    use wxc_common::mxc_error::MxcErrorCode;
    use wxc_common::state_aware_request::{MxcRequest, ParsedStateAwareRequest};

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
        options: OperationOptions,
    ) {
        assert_matches_exact(
            json,
            request.into_sdk_input(options.telemetry_opt_in).unwrap(),
        );
    }

    fn assert_lifecycle_matches_exact(
        json: &str,
        sandbox_id: &str,
        operation: fn(String) -> RuntimeOperation,
        options: OperationOptions,
    ) {
        let id = SandboxId::parse(sandbox_id).unwrap();
        let input = lifecycle_sdk_input(&id, options.telemetry_opt_in, operation).unwrap();
        assert_matches_exact(json, input);
    }

    fn assert_exec_matches_exact(
        json: &str,
        sandbox_id: &str,
        request: ExecRequest,
        options: OperationOptions,
    ) {
        let id = SandboxId::parse(sandbox_id).unwrap();
        let input = request
            .into_sdk_input(&id, options.telemetry_opt_in)
            .unwrap();
        assert_matches_exact(json, input);
    }

    #[test]
    fn typed_provision_rejects_clear_policy_on_exit() {
        for enabled in [true, false] {
            let mut request = ProvisionRequest::wslc(None, None);
            request.set_filesystem(FilesystemSection {
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
        let options = OperationOptions::default();
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
        filesystem.set_filesystem(FilesystemSection {
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

        let mut peer = NetworkPeerSection::new("10.0.0.0/8");
        peer.except = Some(vec!["10.1.0.0/16".to_string()]);
        let mut network = ProvisionRequest::wslc(Some("python:3.12".to_string()), None);
        network.set_network(NetworkSection {
            egress: Some(NetworkEgressSection {
                default: Some(NetworkAction::Deny),
                allow: Some(vec![NetworkRuleSection {
                    to: Some(vec![peer]),
                    ports: Some(vec![NetworkPortSection {
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
        empty_network.set_network(NetworkSection::default());
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
        let options = OperationOptions::default();
        for (phase, operation) in lifecycle_phases() {
            let json = format!(r#"{{"version":"1.0.0","phase":"{phase}","sandboxId":"iso:abc"}}"#);
            assert_lifecycle_matches_exact(&json, "iso:abc", operation, options);
        }

        let mut exec = ExecRequest::new("echo configured");
        exec.set_working_directory("C:\\work")
            .set_environment([("A", "one"), ("B", "two")])
            .inherit_default_env(false)
            .set_timeout(1234);
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

        let mut empty_environment = ExecRequest::new("echo empty");
        empty_environment.set_environment(std::iter::empty::<(&str, &str)>());
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

        let mut proxy_exec = ExecRequest::new("echo proxied");
        proxy_exec.set_backend_options(StateAwareExecBackendOptions::Wslc {
            network_proxy: "http://127.0.0.1:8080".to_string(),
        });
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
            let options = OperationOptions::new(false).with_telemetry_opt_in(enabled);
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
                ExecRequest::new("echo hello"),
                options,
            );
        }
    }
}
