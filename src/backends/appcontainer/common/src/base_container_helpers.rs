// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BaseContainer configuration and policy helpers.

use process_security_environment_spec::process_security_environment_layout::{
    finish_process_security_environment_buffer, DestinationRuleT as PsecDestinationRuleT,
    EndpointPolicyT as PsecEndpointPolicy, EndpointRuleT as PsecEndpointRuleT,
    FilterAction as PsecFilterAction, IpProtocol as PsecIpProtocol, IpSubnetT as PsecIpSubnetT,
    NetworkPolicyT as PsecNetworkPolicy, PortRuleT as PsecPortRuleT,
    ProcessSecurityEnvironmentT as PsecProcessSecurityEnvironment, ProxyInfoT as PsecProxyInfo,
    SchemaVersionT,
};
use sandbox_spec::base_container_layout::{
    endpoint_policyT, finish_sandbox_spec_buffer, proxy_infoT, FilterAction as SboxFilterAction,
    IntegrityLevel, NetworkPolicyT as SboxNetworkPolicy, SandboxSpecT,
};
use wxc_common::models::{
    ContainerPolicy, ExecutionRequest, NetworkAction, NetworkCidr, NetworkPeer, NetworkPolicy,
    NetworkPort, NetworkProtocol, NetworkRule,
};

use crate::network_policy_helpers::{add_default_network_capabilities, ensure_capability};

pub(super) const LOOPBACK_NETWORK_CAPABILITY: &str = "networkLoopback";
pub(super) const LOOPBACK_NETWORK_PEER: &str = "MXC-Loopback";

const SANDBOX_SPEC_VERSION: &str = "0.1.0";

pub(super) fn requires_psec_networking(policy: &ContainerPolicy) -> bool {
    policy
        .network_egress
        .as_ref()
        .is_some_and(|egress| !egress.allow.is_empty() || !egress.deny.is_empty())
        || policy.allowed_proxy_peer.is_some()
        || unrestricted_host_loopback_allowed(policy)
}

pub(super) fn has_conflicting_proxy_identity(policy: &ContainerPolicy) -> bool {
    policy.allowed_proxy_peer.is_some() && unrestricted_host_loopback_allowed(policy)
}

pub(super) fn build_psec_spec(request: &ExecutionRequest) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
    let capabilities = effective_capabilities(&request.policy, true);
    let ui_restrictions = crate::job_object::to_job_object_uilimit_mask(
        &wxc_common::ui_policy::resolve_ui_restrictions(
            &request.policy.ui,
            &request.policy.base_process_ui,
        ),
    ) as u64;

    let mut spec = PsecProcessSecurityEnvironment::default();
    spec.version = SchemaVersionT { major: 1, minor: 0 };
    spec.capabilities = (!capabilities.is_empty()).then(|| capabilities.join(","));
    spec.disallow_win32k_system_calls = request.policy.ui.disable;
    spec.ui_restrictions = ui_restrictions;
    spec.fs_read_write = non_empty_paths(&request.policy.readwrite_paths);
    spec.fs_read_only = non_empty_paths(&request.policy.readonly_paths);
    spec.fs_deny = non_empty_paths(&request.policy.denied_paths);
    spec.network_policy = Some(Box::new(build_psec_network_policy(&request.policy)));
    let spec = spec.pack(&mut builder);
    finish_process_security_environment_buffer(&mut builder, spec);
    builder.finished_data().to_vec()
}

pub(super) fn build_sbox_spec(request: &ExecutionRequest) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
    let capabilities = effective_capabilities(&request.policy, false);
    let ui_restrictions = crate::job_object::to_job_object_uilimit_mask(
        &wxc_common::ui_policy::resolve_ui_restrictions(
            &request.policy.ui,
            &request.policy.base_process_ui,
        ),
    ) as u64;

    let mut spec = SandboxSpecT::default();
    spec.version = SANDBOX_SPEC_VERSION.to_string();
    spec.app_container = true;
    spec.disallow_win32k_system_calls = request.policy.ui.disable;
    spec.ui_restrictions = ui_restrictions;
    spec.least_privilege = request.policy.least_privilege_mode;
    spec.capabilities = (!capabilities.is_empty()).then(|| capabilities.join(","));
    spec.fs_read_write = non_empty_paths(&request.policy.readwrite_paths);
    spec.fs_read_only = non_empty_paths(&request.policy.readonly_paths);
    spec.network_policy = Some(Box::new(build_legacy_sbox_network_policy(&request.policy)));
    spec.integrity = IntegrityLevel::system_default;
    spec.fs_deny = non_empty_paths(&request.policy.denied_paths);
    let spec = spec.pack(&mut builder);
    finish_sandbox_spec_buffer(&mut builder, spec);
    builder.finished_data().to_vec()
}

fn effective_capabilities(policy: &ContainerPolicy, include_host_loopback: bool) -> Vec<String> {
    let mut capabilities: Vec<_> = policy
        .capabilities
        .iter()
        .filter(|capability| !capability.is_empty())
        .cloned()
        .collect();
    add_default_network_capabilities(policy, &mut capabilities);
    if include_host_loopback && unrestricted_host_loopback_allowed(policy) {
        ensure_capability(&mut capabilities, LOOPBACK_NETWORK_CAPABILITY);
    }
    capabilities
}

fn non_empty_paths(paths: &[String]) -> Option<Vec<String>> {
    (!paths.is_empty()).then(|| paths.to_vec())
}

fn build_legacy_sbox_network_policy(policy: &ContainerPolicy) -> SboxNetworkPolicy {
    let mut network = SboxNetworkPolicy::default();
    if policy.network_proxy.is_enabled() && !policy.runtime_network_proxy_specified {
        network.proxy = policy.network_proxy.address.as_ref().map(|address| {
            let mut proxy = proxy_infoT::default();
            proxy.url = Some(address.to_url());
            Box::new(proxy)
        });
    } else {
        let mut egress = endpoint_policyT::default();
        egress.default_action = match effective_egress_default(policy) {
            NetworkAction::Allow => SboxFilterAction::allow,
            NetworkAction::Deny => SboxFilterAction::deny,
        };
        network.egress = Some(Box::new(egress));
    }
    network
}

fn build_psec_network_policy(policy: &ContainerPolicy) -> PsecNetworkPolicy {
    let mut network = PsecNetworkPolicy::default();
    if policy.network_proxy.is_enabled() {
        network.proxy = policy.network_proxy.address.as_ref().map(|address| {
            let mut proxy = PsecProxyInfo::default();
            proxy.url = Some(address.to_url());
            Box::new(proxy)
        });
    } else {
        let mut egress = PsecEndpointPolicy::default();
        egress.default_action = match effective_egress_default(policy) {
            NetworkAction::Allow => PsecFilterAction::allow,
            NetworkAction::Deny => PsecFilterAction::deny,
        };
        if let Some(egress_policy) = policy.network_egress.as_ref() {
            egress.allow = (!egress_policy.allow.is_empty())
                .then(|| psec_endpoint_rules(&egress_policy.allow));
            egress.deny =
                (!egress_policy.deny.is_empty()).then(|| psec_endpoint_rules(&egress_policy.deny));
        }
        network.egress = Some(Box::new(egress));
    }
    network.allowed_appcontainer_peer = allowed_appcontainer_peer(policy);
    network
}

fn effective_egress_default(policy: &ContainerPolicy) -> NetworkAction {
    policy.network_egress.as_ref().map_or(
        match policy.default_network_policy {
            NetworkPolicy::Allow => NetworkAction::Allow,
            NetworkPolicy::Block => NetworkAction::Deny,
        },
        |egress| egress.default,
    )
}

fn unrestricted_host_loopback_allowed(policy: &ContainerPolicy) -> bool {
    policy
        .network_ingress
        .as_ref()
        .is_some_and(|ingress| ingress.host_loopback == NetworkAction::Allow)
}

fn allowed_appcontainer_peer(policy: &ContainerPolicy) -> Option<String> {
    if unrestricted_host_loopback_allowed(policy) {
        Some(LOOPBACK_NETWORK_PEER.to_string())
    } else {
        policy.allowed_proxy_peer.clone()
    }
}

fn psec_subnet(cidr: &NetworkCidr) -> PsecIpSubnetT {
    let mut subnet = PsecIpSubnetT::default();
    subnet.address = Some(cidr.address.to_string());
    subnet.prefix_length = cidr.prefix_length;
    subnet
}

fn psec_destination_rule(peer: &NetworkPeer) -> PsecDestinationRuleT {
    let mut destination = PsecDestinationRuleT::default();
    destination.subnet = Some(Box::new(psec_subnet(&peer.cidr)));
    destination.except =
        (!peer.except.is_empty()).then(|| peer.except.iter().map(psec_subnet).collect());
    destination
}

fn psec_port_rule(port: &NetworkPort, protocol: PsecIpProtocol) -> PsecPortRuleT {
    let mut rule = PsecPortRuleT::default();
    rule.protocol = protocol;
    rule.port = port.port.unwrap_or(0);
    rule.end_port = port.end_port.unwrap_or(0);
    rule
}

fn psec_endpoint_rule<'a>(
    destinations: impl IntoIterator<Item = &'a NetworkPeer>,
    ports: Vec<PsecPortRuleT>,
) -> PsecEndpointRuleT {
    let destinations: Vec<_> = destinations
        .into_iter()
        .map(psec_destination_rule)
        .collect();
    let mut endpoint = PsecEndpointRuleT::default();
    endpoint.destinations = (!destinations.is_empty()).then_some(destinations);
    endpoint.ports = (!ports.is_empty()).then_some(ports);
    endpoint
}

fn psec_non_icmp_port(port: &NetworkPort) -> Option<PsecPortRuleT> {
    let protocol = match port.protocol {
        NetworkProtocol::Any => PsecIpProtocol::any,
        NetworkProtocol::Tcp => PsecIpProtocol::tcp,
        NetworkProtocol::Udp => PsecIpProtocol::udp,
        NetworkProtocol::Icmp => return None,
    };
    Some(psec_port_rule(port, protocol))
}

fn psec_icmp_endpoint(rule: &NetworkRule, ipv4: bool) -> Option<PsecEndpointRuleT> {
    let ports: Vec<_> = rule
        .ports
        .iter()
        .filter(|port| port.protocol == NetworkProtocol::Icmp)
        .map(|port| {
            psec_port_rule(
                port,
                if ipv4 {
                    PsecIpProtocol::icmpv4
                } else {
                    PsecIpProtocol::icmpv6
                },
            )
        })
        .collect();
    if ports.is_empty() {
        return None;
    }

    let destinations: Vec<_> = rule
        .to
        .iter()
        .filter(|peer| peer.cidr.address.is_ipv4() == ipv4)
        .collect();
    if !rule.to.is_empty() && destinations.is_empty() {
        return None;
    }
    Some(psec_endpoint_rule(destinations, ports))
}

fn psec_endpoint_rules(rules: &[NetworkRule]) -> Vec<PsecEndpointRuleT> {
    let mut endpoints = Vec::new();
    for rule in rules {
        let ports: Vec<_> = rule.ports.iter().filter_map(psec_non_icmp_port).collect();
        if rule.ports.is_empty() || !ports.is_empty() {
            endpoints.push(psec_endpoint_rule(&rule.to, ports));
        }
        endpoints.extend(
            [true, false]
                .into_iter()
                .filter_map(|ipv4| psec_icmp_endpoint(rule, ipv4)),
        );
    }
    endpoints
}
