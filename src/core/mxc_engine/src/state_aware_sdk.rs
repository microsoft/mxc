// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed Rust SDK models for state-aware lifecycle calls.

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

/// Backend selected by a typed state-aware provision request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateAwareProvision {
    /// Windows IsolationSession with an optional application identifier.
    IsolationSession { app_id: Option<String> },
    /// Windows Sandbox, available only in the development contract.
    WindowsSandbox,
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
            Self::WindowsSandbox => RuntimeProvision::WindowsSandbox,
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

/// Typed state-aware provision request.
#[derive(Debug, Clone)]
pub struct ProvisionRequest {
    version: String,
    provision: StateAwareProvision,
    filesystem: Option<FilesystemSection>,
    network: Option<NetworkSection>,
    telemetry_opt_in: Option<bool>,
}

impl ProvisionRequest {
    /// Create an IsolationSession provision request with its required
    /// unrestricted directional network posture.
    ///
    /// `None` omits backend-specific provision configuration.
    pub fn isolation_session(version: impl Into<String>, app_id: Option<String>) -> Self {
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
            version: version.into(),
            provision: StateAwareProvision::IsolationSession { app_id },
            filesystem: None,
            network: Some(network),
            telemetry_opt_in: None,
        }
    }

    /// Create a Windows Sandbox provision request.
    pub fn windows_sandbox(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            provision: StateAwareProvision::WindowsSandbox,
            filesystem: None,
            network: None,
            telemetry_opt_in: None,
        }
    }

    /// Create a WSL Container provision request.
    ///
    /// When both image arguments are `None`, backend-specific provision
    /// configuration is omitted and the backend owns its defaults.
    pub fn wslc(
        version: impl Into<String>,
        image: Option<String>,
        image_tar_path: Option<String>,
    ) -> Self {
        Self {
            version: version.into(),
            provision: StateAwareProvision::Wslc {
                image,
                image_tar_path,
            },
            filesystem: None,
            network: None,
            telemetry_opt_in: None,
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

    /// Set the per-invocation telemetry preference.
    pub fn set_telemetry_opt_in(&mut self, enabled: bool) -> &mut Self {
        self.telemetry_opt_in = Some(enabled);
        self
    }

    pub(crate) fn into_sdk_input(self) -> Result<SdkStateAwareInput, MxcError> {
        let version = parse_state_aware_version(&self.version)?;
        match &self.provision {
            StateAwareProvision::IsolationSession { .. } if self.filesystem.is_some() => {
                return Err(MxcError::malformed_request(
                    "IsolationSession state-aware provision does not accept filesystem policy",
                ));
            }
            StateAwareProvision::WindowsSandbox if self.network.is_some() => {
                return Err(MxcError::malformed_request(
                    "Windows Sandbox state-aware provision does not accept network policy",
                ));
            }
            _ => {}
        }
        let mut input = SdkStateAwareInput::new(version, self.provision.runtime_operation())
            .map_err(|error| MxcError::malformed_request(error.to_string()))?;
        input.filesystem = self.filesystem.as_ref().map(map_filesystem).transpose()?;
        let (network, runtime_config) = map_network(version, self.network.as_ref())?;
        input.network = network;
        input.runtime_config = runtime_config;
        input.telemetry_opt_in = self.telemetry_opt_in;
        Ok(input)
    }
}

/// Typed start, stop, or deprovision request.
#[derive(Debug, Clone)]
pub struct SandboxLifecycleRequest {
    version: String,
    sandbox_id: String,
    telemetry_opt_in: Option<bool>,
}

impl SandboxLifecycleRequest {
    pub fn new(version: impl Into<String>, sandbox_id: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            sandbox_id: sandbox_id.into(),
            telemetry_opt_in: None,
        }
    }

    /// Set the per-invocation telemetry preference.
    pub fn set_telemetry_opt_in(&mut self, enabled: bool) -> &mut Self {
        self.telemetry_opt_in = Some(enabled);
        self
    }

    fn into_sdk_input(
        self,
        operation: fn(String) -> RuntimeOperation,
    ) -> Result<SdkStateAwareInput, MxcError> {
        let version = parse_state_aware_version(&self.version)?;
        let mut input = SdkStateAwareInput::new(version, operation(self.sandbox_id))
            .map_err(|error| MxcError::malformed_request(error.to_string()))?;
        input.telemetry_opt_in = self.telemetry_opt_in;
        Ok(input)
    }

    pub(crate) fn into_start_input(self) -> Result<SdkStateAwareInput, MxcError> {
        self.into_sdk_input(|sandbox_id| RuntimeOperation::Start { sandbox_id })
    }

    pub(crate) fn into_stop_input(self) -> Result<SdkStateAwareInput, MxcError> {
        self.into_sdk_input(|sandbox_id| RuntimeOperation::Stop { sandbox_id })
    }

    pub(crate) fn into_deprovision_input(self) -> Result<SdkStateAwareInput, MxcError> {
        self.into_sdk_input(|sandbox_id| RuntimeOperation::Deprovision { sandbox_id })
    }
}

/// Typed state-aware exec request.
#[derive(Debug, Clone)]
pub struct StateAwareExecRequest {
    version: String,
    sandbox_id: String,
    command_line: String,
    working_directory: Option<String>,
    environment: Option<Vec<String>>,
    inherit_default_env: Option<bool>,
    timeout_ms: Option<u32>,
    backend_options: Option<StateAwareExecBackendOptions>,
    telemetry_opt_in: Option<bool>,
}

/// Backend-specific options for a typed state-aware exec request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateAwareExecBackendOptions {
    /// WSLc cooperative proxy configuration.
    Wslc { network_proxy: String },
}

impl StateAwareExecRequest {
    pub fn new(
        version: impl Into<String>,
        sandbox_id: impl Into<String>,
        command_line: impl Into<String>,
    ) -> Self {
        Self {
            version: version.into(),
            sandbox_id: sandbox_id.into(),
            command_line: command_line.into(),
            working_directory: None,
            environment: None,
            inherit_default_env: None,
            timeout_ms: None,
            backend_options: None,
            telemetry_opt_in: None,
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

    pub fn set_telemetry_opt_in(&mut self, enabled: bool) -> &mut Self {
        self.telemetry_opt_in = Some(enabled);
        self
    }

    pub(crate) fn into_sdk_input(self) -> Result<SdkStateAwareInput, MxcError> {
        let version = parse_state_aware_version(&self.version)?;
        let mut input = SdkStateAwareInput::new(
            version,
            RuntimeOperation::Exec {
                sandbox_id: self.sandbox_id,
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
        input.telemetry_opt_in = self.telemetry_opt_in;
        Ok(input)
    }
}

/// Execution options that are authorization or invocation behavior rather than
/// sandbox policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StateAwareOptions {
    pub dry_run: bool,
    pub experimental: bool,
}

impl StateAwareOptions {
    pub fn new(dry_run: bool, experimental: bool) -> Self {
        Self {
            dry_run,
            experimental,
        }
    }
}

/// Execution options for live state-aware exec calls.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StateAwareExecOptions {
    pub experimental: bool,
}

impl StateAwareExecOptions {
    pub fn new(experimental: bool) -> Self {
        Self { experimental }
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
pub enum StateAwareMetadata {
    IsolationSessionProvision(IsolationSessionProvisionMetadata),
}

/// Typed result for provision, start, stop, deprovision, or dry-run.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StateAwareResult {
    pub sandbox_id: Option<String>,
    pub metadata: Option<StateAwareMetadata>,
    pub warnings: Vec<String>,
}

impl StateAwareResult {
    #[cfg(target_os = "windows")]
    pub(crate) fn empty() -> Self {
        Self {
            sandbox_id: None,
            metadata: None,
            warnings: Vec::new(),
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn provision(sandbox_id: String, metadata: Option<StateAwareMetadata>) -> Self {
        Self {
            sandbox_id: Some(sandbox_id),
            metadata,
            warnings: Vec::new(),
        }
    }
}

fn parse_state_aware_version(version: &str) -> Result<ContractVersion, MxcError> {
    let version = ContractVersion::parse_exact(version)
        .ok_or_else(|| MxcError::malformed_request(format!("Invalid schema version: {version}")))?;
    if !matches!(
        version,
        ContractVersion::V0_9_0Alpha | ContractVersion::V0_10_0Alpha
    ) {
        return Err(MxcError::malformed_request(format!(
            "typed state-aware Rust SDK requests require schema version \
             0.9.0-alpha or 0.10.0-alpha, got {}",
            version.as_str()
        )));
    }
    Ok(version)
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
    version: ContractVersion,
    value: Option<&NetworkSection>,
) -> Result<(Option<SdkNetworkInput>, Option<SdkRuntimeConfigInput>), MxcError> {
    let Some(value) = value else {
        return Ok((None, None));
    };
    if value.allow_outbound
        || value.allow_local_network
        || !value.allowed_hosts.is_empty()
        || !value.blocked_hosts.is_empty()
        || value.proxy.is_some()
        || value.legacy_fields_specified
    {
        return Err(MxcError::malformed_request(format!(
            "schema {} state-aware typed requests accept directional networking only",
            version.as_str()
        )));
    }
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
