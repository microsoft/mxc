// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed Rust SDK input to shared request normalization.
//!
//! This module is public only because `mxc-sdk` owns the high-level SDK
//! types while `mxc_common` owns the private normalization boundary.

use crate::mxc_contract::ContractVersion;

use crate::mxc_common::common_request_ir::CommonRequestIR;
use crate::mxc_common::error::WxcError;
use crate::mxc_common::state_aware_input::StateAwareInput;
use crate::mxc_common::state_aware_operation::StateAwareOperation;
use crate::mxc_common::wire;

#[derive(Debug, Clone)]
pub struct SdkProcessInput {
    pub command_line: String,
    pub cwd: Option<String>,
    pub env: Option<Vec<String>>,
    pub inherit_default_env: Option<bool>,
    pub timeout: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SdkFilesystemInput {
    pub readwrite_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    pub denied_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum SdkNetworkAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy)]
pub enum SdkNetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

#[derive(Debug, Clone)]
pub struct SdkNetworkPeerInput {
    pub cidr: String,
    pub except: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct SdkNetworkPortInput {
    pub protocol: Option<SdkNetworkProtocol>,
    pub port: Option<u16>,
    pub end_port: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct SdkNetworkRuleInput {
    pub to: Option<Vec<SdkNetworkPeerInput>>,
    pub ports: Option<Vec<SdkNetworkPortInput>>,
}

#[derive(Debug, Clone)]
pub struct SdkNetworkEgressInput {
    pub default: Option<SdkNetworkAction>,
    pub allow: Option<Vec<SdkNetworkRuleInput>>,
    pub deny: Option<Vec<SdkNetworkRuleInput>>,
}

#[derive(Debug, Clone)]
pub struct SdkNetworkIngressInput {
    pub default: Option<SdkNetworkAction>,
    pub host_loopback: Option<SdkNetworkAction>,
}

#[derive(Debug, Clone)]
pub struct SdkNetworkInput {
    pub egress: Option<SdkNetworkEgressInput>,
    pub ingress: Option<SdkNetworkIngressInput>,
}

#[derive(Debug, Clone)]
pub struct SdkRuntimeConfigInput {
    pub network_proxy: Option<String>,
}

/// Common fields supplied by a trusted typed Rust SDK lifecycle request.
///
/// Exact contract metadata and one-shot-only backend sections are deliberately
/// absent. The operation remains the sole phase and routing authority.
#[derive(Debug, Clone)]
pub struct SdkStateAwareInput {
    version: ContractVersion,
    operation: StateAwareOperation,
    pub process: Option<SdkProcessInput>,
    pub filesystem: Option<SdkFilesystemInput>,
    pub network: Option<SdkNetworkInput>,
    pub runtime_config: Option<SdkRuntimeConfigInput>,
    pub telemetry_opt_in: Option<bool>,
}

impl SdkStateAwareInput {
    /// Create typed lifecycle normalization input for the selected exact
    /// compatibility semantics.
    pub fn new(version: ContractVersion, operation: StateAwareOperation) -> Result<Self, WxcError> {
        if !matches!(
            version,
            ContractVersion::V1_0_0 | ContractVersion::V1_1_0Alpha
        ) {
            return Err(WxcError::ConfigParse(format!(
                "typed state-aware Rust SDK requests require schema version \
                 1.0.0 or 1.1.0-alpha, got {}",
                version.as_str()
            )));
        }
        let is_windows_sandbox = matches!(
            operation,
            StateAwareOperation::Provision(
                crate::mxc_common::state_aware_operation::StateAwareProvision::WindowsSandbox
            )
        ) || operation
            .sandbox_id()
            .is_some_and(|sandbox_id| sandbox_id.starts_with("wsb:"));
        if is_windows_sandbox {
            return Err(WxcError::ConfigParse(
                "typed state-aware Rust SDK requests do not support Windows Sandbox; \
                 use raw exact 1.1.0-alpha JSON"
                    .to_string(),
            ));
        }
        Ok(Self {
            version,
            operation,
            process: None,
            filesystem: None,
            network: None,
            runtime_config: None,
            telemetry_opt_in: None,
        })
    }

    pub(crate) fn into_normalization_input(self) -> Result<StateAwareInput, WxcError> {
        let common = CommonRequestIR {
            schema: None,
            comment: None,
            source_contract: self.version,
            phase: None,
            sandbox_id: None,
            container_id: None,
            containment: None,
            process: self.process.map(|process| wire::Process {
                command_line: Some(process.command_line),
                cwd: process.cwd,
                env: process.env,
                inherit_default_env: process.inherit_default_env,
                timeout: process.timeout,
            }),
            lifecycle: None,
            process_container: None,
            lxc: None,
            wslc: None,
            filesystem: self.filesystem.map(|filesystem| wire::Filesystem {
                readwrite_paths: Some(filesystem.readwrite_paths),
                readonly_paths: Some(filesystem.readonly_paths),
                denied_paths: Some(filesystem.denied_paths),
            }),
            fallback: None,
            network: self.network.map(map_network),
            runtime_config: self.runtime_config.map(|runtime| wire::RuntimeConfig {
                network_proxy: runtime.network_proxy,
            }),
            ui: None,
            seatbelt: None,
            telemetry: self.telemetry_opt_in.map(|enabled| wire::Telemetry {
                enabled: Some(enabled),
            }),
            test_feature: None,
            windows_sandbox: None,
            hyperlight: None,
        };
        StateAwareInput::new(common, self.operation)
    }
}

fn map_network(network: SdkNetworkInput) -> wire::Network {
    wire::Network {
        egress: network.egress.map(|egress| wire::NetworkEgress {
            default: egress.default.map(map_action),
            allow: egress.allow.map(map_rules),
            deny: egress.deny.map(map_rules),
        }),
        ingress: network.ingress.map(|ingress| wire::NetworkIngress {
            default: ingress.default.map(map_action),
            host_loopback: ingress.host_loopback.map(map_action),
        }),
    }
}

fn map_rules(rules: Vec<SdkNetworkRuleInput>) -> Vec<wire::NetworkRule> {
    rules
        .into_iter()
        .map(|rule| wire::NetworkRule {
            to: rule.to.map(|peers| {
                peers
                    .into_iter()
                    .map(|peer| wire::NetworkPeer {
                        cidr: peer.cidr,
                        except: peer.except,
                    })
                    .collect()
            }),
            ports: rule.ports.map(|ports| {
                ports
                    .into_iter()
                    .map(|port| wire::NetworkPort {
                        protocol: port.protocol.map(map_protocol),
                        port: port.port,
                        end_port: port.end_port,
                    })
                    .collect()
            }),
        })
        .collect()
}

fn map_action(action: SdkNetworkAction) -> wire::NetworkAction {
    match action {
        SdkNetworkAction::Allow => wire::NetworkAction::Allow,
        SdkNetworkAction::Deny => wire::NetworkAction::Deny,
    }
}

fn map_protocol(protocol: SdkNetworkProtocol) -> wire::NetworkProtocol {
    match protocol {
        SdkNetworkProtocol::Tcp => wire::NetworkProtocol::Tcp,
        SdkNetworkProtocol::Udp => wire::NetworkProtocol::Udp,
        SdkNetworkProtocol::Icmp => wire::NetworkProtocol::Icmp,
        SdkNetworkProtocol::Any => wire::NetworkProtocol::Any,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_v1_rejects_windows_sandbox_ids_for_every_non_provision_phase() {
        for operation in [
            StateAwareOperation::Start {
                sandbox_id: "wsb:abcd1234".to_string(),
            },
            StateAwareOperation::Exec {
                sandbox_id: "wsb:abcd1234".to_string(),
            },
            StateAwareOperation::Stop {
                sandbox_id: "wsb:abcd1234".to_string(),
            },
            StateAwareOperation::Deprovision {
                sandbox_id: "wsb:abcd1234".to_string(),
            },
        ] {
            let error = SdkStateAwareInput::new(ContractVersion::V1_0_0, operation)
                .expect_err("typed v1 must keep Windows Sandbox on the raw exact lane");
            assert!(error.to_string().contains("do not support Windows Sandbox"));
        }
    }
}
