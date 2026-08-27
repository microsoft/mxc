// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::wire;
use mxc_config_contract::dev as contract;
use mxc_config_contract::ContractVersion;
use std::num::NonZeroU16;

pub(super) fn convert_version(value: contract::Version) -> &'static str {
    match value {
        contract::Version::V0_9_0Alpha => ContractVersion::V0_9_0Alpha.as_str(),
    }
}

pub(super) fn convert_process(value: contract::Process) -> wire::Process {
    let contract::Process {
        command_line,
        cwd,
        env,
        parent_task_id,
        task_display_name,
        timeout,
    } = value;
    wire::Process {
        command_line: Some(command_line.into_inner()),
        cwd: cwd.into_option(),
        env: env.into_option(),
        parent_task_id: parent_task_id.into_option(),
        task_display_name: task_display_name.into_option(),
        timeout: timeout.into_option(),
    }
}

pub(super) fn convert_filesystem(value: contract::Filesystem) -> wire::Filesystem {
    let contract::Filesystem {
        readwrite_paths,
        readonly_paths,
        denied_paths,
    } = value;
    wire::Filesystem {
        readwrite_paths: readwrite_paths.into_option(),
        readonly_paths: readonly_paths.into_option(),
        denied_paths: denied_paths.into_option(),
    }
}

fn convert_default_network_policy(value: contract::DefaultNetworkPolicy) -> wire::NetworkPolicy {
    match value {
        contract::DefaultNetworkPolicy::Allow => wire::NetworkPolicy::Allow,
        contract::DefaultNetworkPolicy::Block => wire::NetworkPolicy::Block,
    }
}

fn convert_network_enforcement_mode(
    value: contract::NetworkEnforcementMode,
) -> wire::NetworkEnforcement {
    match value {
        contract::NetworkEnforcementMode::Capabilities => wire::NetworkEnforcement::Capabilities,
        contract::NetworkEnforcementMode::Firewall => wire::NetworkEnforcement::Firewall,
        contract::NetworkEnforcementMode::Both => wire::NetworkEnforcement::Both,
    }
}

fn convert_network_action(value: contract::NetworkAction) -> wire::NetworkAction {
    match value {
        contract::NetworkAction::Allow => wire::NetworkAction::Allow,
        contract::NetworkAction::Deny => wire::NetworkAction::Deny,
    }
}

fn convert_network_protocol(value: contract::NetworkProtocol) -> wire::NetworkProtocol {
    match value {
        contract::NetworkProtocol::Tcp => wire::NetworkProtocol::Tcp,
        contract::NetworkProtocol::Udp => wire::NetworkProtocol::Udp,
        contract::NetworkProtocol::Icmp => wire::NetworkProtocol::Icmp,
        contract::NetworkProtocol::Any => wire::NetworkProtocol::Any,
    }
}

fn convert_network_peer(value: contract::NetworkPeer) -> wire::NetworkPeer {
    let contract::NetworkPeer { cidr, except } = value;
    wire::NetworkPeer {
        cidr,
        except: except.into_option(),
    }
}

fn convert_network_peers(value: Vec<contract::NetworkPeer>) -> Vec<wire::NetworkPeer> {
    value.into_iter().map(convert_network_peer).collect()
}

fn convert_network_port(value: contract::NetworkPort) -> wire::NetworkPort {
    let contract::NetworkPort {
        port,
        end_port,
        protocol,
    } = value;
    wire::NetworkPort {
        port: port.into_option().map(NonZeroU16::get),
        end_port: end_port.into_option().map(NonZeroU16::get),
        protocol: protocol.into_option().map(convert_network_protocol),
    }
}

fn convert_network_ports(value: Vec<contract::NetworkPort>) -> Vec<wire::NetworkPort> {
    value.into_iter().map(convert_network_port).collect()
}

fn convert_network_rule(value: contract::NetworkRule) -> wire::NetworkRule {
    let contract::NetworkRule { to, ports } = value;
    wire::NetworkRule {
        to: to
            .into_option()
            .map(|to| convert_network_peers(to.into_inner())),
        ports: ports
            .into_option()
            .map(|ports| convert_network_ports(ports.into_inner())),
    }
}

fn convert_network_rules(value: Vec<contract::NetworkRule>) -> Vec<wire::NetworkRule> {
    value.into_iter().map(convert_network_rule).collect()
}

fn convert_network_egress(value: contract::NetworkEgress) -> wire::NetworkEgress {
    let contract::NetworkEgress {
        default,
        allow,
        deny,
    } = value;
    wire::NetworkEgress {
        default: default.into_option().map(convert_network_action),
        allow: allow.into_option().map(convert_network_rules),
        deny: deny.into_option().map(convert_network_rules),
    }
}

fn convert_network_ingress(value: contract::NetworkIngress) -> wire::NetworkIngress {
    let contract::NetworkIngress {
        default,
        host_loopback,
    } = value;
    wire::NetworkIngress {
        default: default.into_option().map(convert_network_action),
        host_loopback: host_loopback.into_option().map(convert_network_action),
    }
}

pub(super) fn convert_network(value: contract::Network) -> wire::Network {
    let contract::Network {
        default_policy,
        enforcement_mode,
        allow_local_network,
        allowed_hosts,
        blocked_hosts,
        proxy,
        egress,
        ingress,
    } = value;
    wire::Network {
        default_policy: default_policy
            .into_option()
            .map(convert_default_network_policy),
        enforcement_mode: enforcement_mode
            .into_option()
            .map(convert_network_enforcement_mode),
        allow_local_network: allow_local_network.into_option(),
        allowed_hosts: allowed_hosts.into_option(),
        blocked_hosts: blocked_hosts.into_option(),
        proxy: proxy.into_option().map(convert_proxy),
        egress: egress.into_option().map(convert_network_egress),
        ingress: ingress.into_option().map(convert_network_ingress),
    }
}

fn convert_proxy(value: contract::NetworkProxy) -> wire::Proxy {
    match value {
        contract::NetworkProxy::Localhost(port) => wire::Proxy {
            localhost: Some(port.get()),
            builtin_test_server: None,
            url: None,
        },
        contract::NetworkProxy::BuiltinTestServer(contract::True) => wire::Proxy {
            localhost: None,
            builtin_test_server: Some(true),
            url: None,
        },
        contract::NetworkProxy::Url(url) => wire::Proxy {
            localhost: None,
            builtin_test_server: None,
            url: Some(url),
        },
    }
}

pub(super) fn convert_telemetry(value: contract::Telemetry) -> wire::Telemetry {
    let contract::Telemetry { enabled } = value;
    wire::Telemetry {
        enabled: enabled.into_option(),
    }
}
