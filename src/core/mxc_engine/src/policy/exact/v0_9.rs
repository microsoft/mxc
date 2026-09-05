// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::dev as contract;
use wxc_common::mxc_error::MxcError;

use crate::configs::{
    CaptureDenialsMode, ProcessContainerSystemSettings, ProcessContainerUi,
    ProcessContainerUiIsolation,
};

use super::super::{
    ClipboardPolicy, Containment, NetworkAction, NetworkEgressSection, NetworkIngressSection,
    NetworkProtocol, NetworkRuleSection, ProxySpec, UiSection, WslcSection,
};
use super::{
    error, legacy_enforcement, non_empty_port, normalized_capabilities, selected_process_container,
    LegacyEnforcement, NetworkFormat, PreparedInput,
};

fn map_proxy(proxy: &ProxySpec) -> Result<contract::NetworkProxy, MxcError> {
    match proxy {
        ProxySpec::BuiltinTestServer => Err(error(
            "network.proxy.builtinTestServer is not supported by the in-process Rust SDK; use localhost or url",
        )),
        ProxySpec::Localhost(port) => Ok(contract::NetworkProxy::Localhost(non_empty_port(
            *port,
            "network.proxy.localhost",
        )?)),
        ProxySpec::Url(url) => Ok(contract::NetworkProxy::Url(url.clone())),
    }
}

fn map_ui(ui: &UiSection) -> contract::Ui {
    contract::Ui {
        disable: contract::OptionalField::present(!ui.allow_windows),
        clipboard: contract::OptionalField::present(match ui.clipboard {
            ClipboardPolicy::None => contract::UiClipboard::None,
            ClipboardPolicy::Read => contract::UiClipboard::Read,
            ClipboardPolicy::Write => contract::UiClipboard::Write,
            ClipboardPolicy::All => contract::UiClipboard::All,
        }),
        injection: contract::OptionalField::present(ui.allow_input_injection),
    }
}

fn map_process_container_ui(ui: &ProcessContainerUi) -> contract::ProcessContainerUi {
    contract::ProcessContainerUi {
        isolation: contract::OptionalField::present(match ui.isolation {
            ProcessContainerUiIsolation::Container => {
                contract::ProcessContainerUiIsolation::Container
            }
            ProcessContainerUiIsolation::Desktop => contract::ProcessContainerUiIsolation::Desktop,
            ProcessContainerUiIsolation::Handles => contract::ProcessContainerUiIsolation::Handles,
            ProcessContainerUiIsolation::Atoms => contract::ProcessContainerUiIsolation::Atoms,
        }),
        desktop_system_control: contract::OptionalField::present(ui.desktop_system_control),
        system_settings: contract::OptionalField::present(
            match ui.system_settings {
                ProcessContainerSystemSettings::All => "all",
                ProcessContainerSystemSettings::Parameters => "parameters",
                ProcessContainerSystemSettings::Display => "display",
                ProcessContainerSystemSettings::None => "none",
            }
            .to_string(),
        ),
        ime: contract::OptionalField::present(ui.ime),
    }
}

fn map_legacy_enforcement(value: LegacyEnforcement) -> contract::NetworkEnforcementMode {
    match value {
        LegacyEnforcement::Capabilities => contract::NetworkEnforcementMode::Capabilities,
        LegacyEnforcement::Firewall => contract::NetworkEnforcementMode::Firewall,
        LegacyEnforcement::Both => contract::NetworkEnforcementMode::Both,
    }
}

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

fn map_rule(rule: &NetworkRuleSection) -> Result<contract::NetworkRule, MxcError> {
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

fn map_egress(value: &NetworkEgressSection) -> Result<contract::NetworkEgress, MxcError> {
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

fn map_ingress(value: &NetworkIngressSection) -> contract::NetworkIngress {
    contract::NetworkIngress {
        default: optional!(contract, value.default.map(map_action)),
        host_loopback: optional!(contract, value.host_loopback.map(map_action)),
    }
}

fn map_wslc(wslc: &WslcSection) -> Result<contract::OneShotWslc, MxcError> {
    let port_mappings = if wslc.port_mappings.is_empty() {
        Default::default()
    } else {
        contract::OptionalField::present(
            wslc.port_mappings
                .iter()
                .map(|(windows_port, container_port)| {
                    Ok(contract::PortMapping {
                        windows_port: non_empty_port(*windows_port, "windowsPort")?,
                        container_port: non_empty_port(*container_port, "containerPort")?,
                        protocol: contract::OptionalField::present(
                            contract::TransportProtocol::Tcp,
                        ),
                    })
                })
                .collect::<Result<Vec<_>, MxcError>>()?,
        )
    };
    Ok(contract::OneShotWslc {
        target_os: Default::default(),
        image: contract::OptionalField::present(wslc.image.clone()),
        image_tar_path: optional!(contract, wslc.image_tar_path.clone()),
        cpu_count: optional!(contract, wslc.cpu_count),
        memory_mb: optional!(contract, wslc.memory_mb),
        gpu: contract::OptionalField::present(wslc.gpu),
        storage_path: optional!(contract, wslc.storage_path.clone()),
        port_mappings,
    })
}

pub(super) fn build(input: &PreparedInput<'_>) -> Result<contract::OneShotRequest, MxcError> {
    let policy = input.policy;
    let containment = input.containment;
    let network_format = input.network_format;
    let process_container = selected_process_container(containment);
    let enforcement = legacy_enforcement(policy, containment, process_container.is_some());
    let network = match network_format {
        NetworkFormat::Legacy => contract::OptionalField::present(contract::Network {
            default_policy: contract::OptionalField::present(
                if policy
                    .network
                    .as_ref()
                    .is_some_and(|network| network.allow_outbound)
                {
                    contract::DefaultNetworkPolicy::Allow
                } else {
                    contract::DefaultNetworkPolicy::Block
                },
            ),
            enforcement_mode: optional!(contract, enforcement.map(map_legacy_enforcement)),
            allowed_hosts: match policy.network.as_ref() {
                Some(network) => contract::OptionalField::present(network.allowed_hosts.clone()),
                None => Default::default(),
            },
            blocked_hosts: match policy.network.as_ref() {
                Some(network) => contract::OptionalField::present(network.blocked_hosts.clone()),
                None => Default::default(),
            },
            allow_local_network: match policy.network.as_ref() {
                Some(network) => contract::OptionalField::present(network.allow_local_network),
                None => Default::default(),
            },
            proxy: optional!(
                contract,
                policy
                    .network
                    .as_ref()
                    .and_then(|network| network.proxy.as_ref())
                    .map(map_proxy)
                    .transpose()?
            ),
            egress: Default::default(),
            ingress: Default::default(),
        }),
        NetworkFormat::Directional => match policy.network.as_ref() {
            Some(network) if network.egress.is_some() || network.ingress.is_some() => {
                contract::OptionalField::present(contract::Network {
                    default_policy: Default::default(),
                    enforcement_mode: Default::default(),
                    allowed_hosts: Default::default(),
                    blocked_hosts: Default::default(),
                    allow_local_network: Default::default(),
                    proxy: Default::default(),
                    egress: optional!(
                        contract,
                        network.egress.as_ref().map(map_egress).transpose()?
                    ),
                    ingress: optional!(contract, network.ingress.as_ref().map(map_ingress)),
                })
            }
            _ => Default::default(),
        },
    };
    let seatbelt = if cfg!(target_os = "macos") && matches!(containment, Containment::Process) {
        contract::OptionalField::present(contract::Seatbelt {
            profile_override: Default::default(),
            gui_access: Default::default(),
            launch_method: Default::default(),
            nested_pty: Default::default(),
            keychain_access: Default::default(),
            extra_mach_lookups: Default::default(),
        })
    } else {
        Default::default()
    };
    let process_container = process_container
        .as_ref()
        .map(|process_container| {
            let capabilities = normalized_capabilities(policy, process_container, network_format)
                .into_iter()
                .map(contract::ProcessContainerCapability::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(error)?;
            Ok(contract::ProcessContainer {
                least_privilege: contract::OptionalField::present(
                    process_container.least_privilege,
                ),
                learning_mode: optional!(contract, process_container.learning_mode.then_some(true)),
                capabilities: contract::OptionalField::present(capabilities),
                capture_denials: optional!(
                    contract,
                    process_container.capture_denials.as_ref().map(|capture| {
                        contract::CaptureDenials {
                            mode: contract::OptionalField::present(match capture.mode {
                                CaptureDenialsMode::Block => contract::CaptureDenialsMode::Block,
                                CaptureDenialsMode::Allow => contract::CaptureDenialsMode::Allow,
                            }),
                            output_path: optional!(contract, capture.output_path.clone()),
                            retain_etl: contract::OptionalField::present(capture.retain_etl),
                        }
                    })
                ),
                ui: optional!(
                    contract,
                    process_container.ui.as_ref().map(map_process_container_ui)
                ),
                network: optional!(
                    contract,
                    process_container.network.as_ref().and_then(|network| {
                        network.allowed_proxy_peer.as_ref().map(|peer| {
                            contract::ProcessContainerNetwork {
                                allowed_proxy_peer: contract::OptionalField::present(peer.clone()),
                            }
                        })
                    })
                ),
            })
        })
        .transpose()?;
    let experimental = match containment {
        Containment::Wslc(wslc) => {
            contract::OptionalField::present(contract::OneShotExperimental {
                test: Default::default(),
                windows_sandbox: Default::default(),
                wslc: contract::OptionalField::present(map_wslc(wslc)?),
            })
        }
        _ => Default::default(),
    };
    Ok(contract::OneShotRequest {
        schema: Default::default(),
        comment: Default::default(),
        version: contract::Version::V0_9_0Alpha,
        container_id: contract::OptionalField::present(input.container_id.clone()),
        containment: contract::OptionalField::present(
            if cfg!(target_os = "macos") && matches!(containment, Containment::Process) {
                contract::OneShotContainment::Seatbelt
            } else {
                match containment {
                    Containment::Process => contract::OneShotContainment::Process,
                    Containment::ProcessContainer(_) => {
                        contract::OneShotContainment::ProcessContainer
                    }
                    Containment::Wslc(_) => contract::OneShotContainment::Wslc,
                    Containment::IsolationSession => contract::OneShotContainment::IsolationSession,
                }
            },
        ),
        lifecycle: contract::OptionalField::present(contract::Lifecycle {
            destroy_on_exit: contract::OptionalField::present(true),
            preserve_policy: contract::OptionalField::present(
                !policy
                    .filesystem
                    .as_ref()
                    .and_then(|filesystem| filesystem.clear_policy_on_exit)
                    .unwrap_or(true),
            ),
        }),
        process: contract::Process {
            command_line: contract::NonEmptyString::new(input.script.to_string()).map_err(error)?,
            cwd: Default::default(),
            env: Default::default(),
            timeout: contract::OptionalField::present(policy.timeout_ms.unwrap_or(0)),
        },
        filesystem: contract::OptionalField::present(contract::Filesystem {
            readwrite_paths: contract::OptionalField::present(
                policy
                    .filesystem
                    .as_ref()
                    .map(|filesystem| filesystem.readwrite_paths.clone())
                    .unwrap_or_default(),
            ),
            readonly_paths: contract::OptionalField::present(
                policy
                    .filesystem
                    .as_ref()
                    .map(|filesystem| filesystem.readonly_paths.clone())
                    .unwrap_or_default(),
            ),
            denied_paths: contract::OptionalField::present(
                policy
                    .filesystem
                    .as_ref()
                    .map(|filesystem| filesystem.denied_paths.clone())
                    .unwrap_or_default(),
            ),
        }),
        fallback: Default::default(),
        network,
        ui: optional!(contract, policy.ui.as_ref().map(map_ui)),
        process_container: optional!(contract, process_container),
        lxc: Default::default(),
        seatbelt,
        runtime_config: optional!(
            contract,
            policy
                .network
                .as_ref()
                .and_then(|network| network.runtime_config.as_ref())
                .map(|runtime| contract::RuntimeConfig {
                    network_proxy: optional!(contract, runtime.network_proxy.clone()),
                })
        ),
        telemetry: Default::default(),
        experimental,
    })
}
