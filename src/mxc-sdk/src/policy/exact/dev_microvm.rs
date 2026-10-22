// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_contract::dev as contract;

use super::super::{
    Containment, NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkProtocol,
    NetworkRulePolicy,
};
use super::{error, non_empty_port, PreparedInput};

fn map_action(value: NetworkAction) -> contract::NetworkAction {
    match value {
        NetworkAction::Allow => contract::NetworkAction::Allow,
        NetworkAction::Deny => contract::NetworkAction::Deny,
    }
}

fn map_protocol(value: NetworkProtocol) -> contract::NetworkProtocol {
    match value {
        NetworkProtocol::Tcp => contract::NetworkProtocol::Tcp,
        NetworkProtocol::Udp => contract::NetworkProtocol::Udp,
        NetworkProtocol::Icmp => contract::NetworkProtocol::Icmp,
        NetworkProtocol::Any => contract::NetworkProtocol::Any,
    }
}

fn map_rule(rule: &NetworkRulePolicy) -> Result<contract::NetworkRule, MxcError> {
    Ok(contract::NetworkRule {
        to: optional!(
            contract,
            rule.to
                .as_ref()
                .map(|peers| {
                    peers
                        .iter()
                        .map(|peer| contract::NetworkPeer {
                            cidr: peer.cidr.clone(),
                            except: optional!(contract, peer.except.clone()),
                        })
                        .collect::<Vec<_>>()
                })
                .map(contract::NonEmptyVec::new)
                .transpose()
                .map_err(error)?
        ),
        ports: optional!(
            contract,
            rule.ports
                .as_ref()
                .map(|ports| {
                    ports
                        .iter()
                        .map(|port| {
                            Ok(contract::NetworkPort {
                                protocol: optional!(contract, port.protocol.map(map_protocol)),
                                port: optional!(
                                    contract,
                                    port.port
                                        .map(|value| non_empty_port(value, "network port"))
                                        .transpose()?
                                ),
                                end_port: optional!(
                                    contract,
                                    port.end_port
                                        .map(|value| non_empty_port(value, "network endPort"))
                                        .transpose()?
                                ),
                            })
                        })
                        .collect::<Result<Vec<_>, MxcError>>()
                })
                .transpose()?
                .map(contract::NonEmptyVec::new)
                .transpose()
                .map_err(error)?
        ),
    })
}

fn map_egress(value: &NetworkEgressPolicy) -> Result<contract::NetworkEgress, MxcError> {
    Ok(contract::NetworkEgress {
        default: optional!(contract, value.default.map(map_action)),
        allow: optional!(
            contract,
            value
                .allow
                .as_ref()
                .map(|rules| rules.iter().map(map_rule).collect())
                .transpose()?
        ),
        deny: optional!(
            contract,
            value
                .deny
                .as_ref()
                .map(|rules| rules.iter().map(map_rule).collect())
                .transpose()?
        ),
    })
}

fn map_ingress(value: &NetworkIngressPolicy) -> contract::NetworkIngress {
    contract::NetworkIngress {
        default: optional!(contract, value.default.map(map_action)),
        host_loopback: optional!(contract, value.host_loopback.map(map_action)),
    }
}

pub(super) fn build(input: &PreparedInput<'_>) -> Result<contract::OneShotRequest, MxcError> {
    let Containment::MicroVm { image } = input.containment else {
        return Err(error(
            "development MicroVM builder requires MicroVm containment",
        ));
    };
    if input.policy.ui.is_some() {
        return Err(error("MicroVM does not support UI policy"));
    }
    let network = match input.policy.network.as_ref() {
        Some(network)
            if network.runtime_config.is_none()
                || network.egress.is_some()
                || network.ingress.is_some() =>
        {
            contract::OptionalField::present(contract::Network {
                egress: optional!(
                    contract,
                    network.egress.as_ref().map(map_egress).transpose()?
                ),
                ingress: optional!(contract, network.ingress.as_ref().map(map_ingress)),
            })
        }
        _ => Default::default(),
    };
    Ok(contract::OneShotRequest {
        schema: Default::default(),
        comment: Default::default(),
        version: contract::Version::V1_1_0Alpha,
        container_id: contract::OptionalField::present(input.container_id.clone()),
        containment: contract::OptionalField::present(contract::OneShotContainment::Microvm),
        lifecycle: contract::OptionalField::present(contract::Lifecycle {
            destroy_on_exit: contract::OptionalField::present(true),
            preserve_policy: contract::OptionalField::present(
                !input
                    .policy
                    .filesystem
                    .as_ref()
                    .and_then(|filesystem| filesystem.clear_policy_on_exit)
                    .unwrap_or(true),
            ),
        }),
        process: contract::Process {
            command_line: contract::NonEmptyString::new(input.script.to_owned()).map_err(error)?,
            cwd: Default::default(),
            env: Default::default(),
            inherit_default_env: Default::default(),
            timeout: contract::OptionalField::present(input.policy.timeout_ms.unwrap_or(0)),
        },
        filesystem: contract::OptionalField::present(contract::Filesystem {
            readwrite_paths: contract::OptionalField::present(
                input
                    .policy
                    .filesystem
                    .as_ref()
                    .map(|filesystem| filesystem.readwrite_paths.clone())
                    .unwrap_or_default(),
            ),
            readonly_paths: contract::OptionalField::present(
                input
                    .policy
                    .filesystem
                    .as_ref()
                    .map(|filesystem| filesystem.readonly_paths.clone())
                    .unwrap_or_default(),
            ),
            denied_paths: contract::OptionalField::present(
                input
                    .policy
                    .filesystem
                    .as_ref()
                    .map(|filesystem| filesystem.denied_paths.clone())
                    .unwrap_or_default(),
            ),
        }),
        fallback: Default::default(),
        network,
        ui: Default::default(),
        process_container: Default::default(),
        lxc: Default::default(),
        seatbelt: Default::default(),
        runtime_config: optional!(
            contract,
            input
                .policy
                .network
                .as_ref()
                .and_then(|network| network.runtime_config.as_ref())
                .map(|runtime| contract::RuntimeConfig {
                    network_proxy: optional!(contract, runtime.network_proxy.clone()),
                })
        ),
        telemetry: Default::default(),
        test: Default::default(),
        windows_sandbox: Default::default(),
        wslc: Default::default(),
        hyperlight: Default::default(),
        microvm: contract::OptionalField::present(contract::OneShotMicroVm {
            image: contract::ImageReference::new(image.clone()).map_err(error)?,
        }),
    })
}
