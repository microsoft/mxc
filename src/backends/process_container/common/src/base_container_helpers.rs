// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BaseContainer configuration and policy helpers.

use process_security_environment_spec::process_security_environment_layout::{
    finish_process_security_environment_buffer, DestinationRuleT as PsecDestinationRuleT,
    EndpointPolicyT as PsecEndpointPolicy, EndpointRuleT as PsecEndpointRuleT,
    FilterAction as PsecFilterAction, IngressPolicyT as PsecIngressPolicy,
    IpProtocol as PsecIpProtocol, IpSubnetT as PsecIpSubnetT, NetworkPolicyT as PsecNetworkPolicy,
    PortRuleT as PsecPortRuleT, ProcessSecurityEnvironmentT as PsecProcessSecurityEnvironment,
    ProxyInfoT as PsecProxyInfo, SchemaVersionT,
};
use wxc_common::models::{
    ContainerPolicy, ExecutionRequest, NetworkAction, NetworkCidr, NetworkPeer, NetworkPolicy,
    NetworkPort, NetworkProtocol, NetworkRule,
};

use crate::network_policy_helpers::{add_default_network_capabilities, ensure_capability};

pub(super) const LOOPBACK_NETWORK_PEER: &str = "MXC-Loopback";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PsecContract {
    V1_0,
    V1_1,
}

impl PsecContract {
    pub(super) fn for_request(request: &ExecutionRequest) -> Self {
        if unrestricted_host_loopback_allowed(&request.policy)
            || !request.policy.enumerate_paths.is_empty()
        {
            Self::V1_1
        } else {
            Self::V1_0
        }
    }

    pub(super) fn version(self) -> SchemaVersionT {
        match self {
            Self::V1_0 => SchemaVersionT { major: 1, minor: 0 },
            Self::V1_1 => SchemaVersionT { major: 1, minor: 1 },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ResolvedPsecContract {
    pub(super) contract: PsecContract,
    pub(super) supports_network_ingress: bool,
}

impl ResolvedPsecContract {
    pub(super) fn baseline() -> Self {
        Self {
            contract: PsecContract::V1_0,
            supports_network_ingress: false,
        }
    }

    #[cfg(test)]
    pub(super) fn with_all_contract_capabilities(request: &ExecutionRequest) -> Self {
        Self {
            contract: PsecContract::for_request(request),
            supports_network_ingress: PsecContract::for_request(request) == PsecContract::V1_1,
        }
    }
}

pub(super) fn has_conflicting_proxy_identity(policy: &ContainerPolicy) -> bool {
    policy.allowed_proxy_peer.is_some() && unrestricted_host_loopback_allowed(policy)
}

pub(super) fn build_psec_spec(
    request: &ExecutionRequest,
    resolution: ResolvedPsecContract,
) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
    let mut capabilities = effective_capabilities(&request.policy);
    if request.policy.network_proxy.is_enabled()
        && unrestricted_host_loopback_allowed(&request.policy)
    {
        // Proxy mode cannot carry the native ingress table that grants loopback.
        ensure_capability(&mut capabilities, "networkLoopback");
    }
    let ui_restrictions = crate::job_object::to_job_object_uilimit_mask(
        &wxc_common::ui_policy::resolve_ui_restrictions(
            &request.policy.ui,
            &request.policy.base_process_ui,
        ),
    ) as u64;

    let mut spec = PsecProcessSecurityEnvironment::default();
    spec.version = resolution.contract.version();
    spec.capabilities = (!capabilities.is_empty()).then(|| capabilities.join(","));
    spec.disallow_win32k_system_calls = request.policy.ui.disable;
    spec.ui_restrictions = ui_restrictions;
    spec.fs_read_write = non_empty_paths(&request.policy.readwrite_paths);
    spec.fs_read_only = non_empty_paths(&request.policy.readonly_paths);
    spec.fs_deny = non_empty_paths(&request.policy.denied_paths);
    spec.fs_enumerate = non_empty_paths(&request.policy.enumerate_paths);
    spec.network_policy = Some(Box::new(build_psec_network_policy(
        &request.policy,
        resolution.supports_network_ingress,
    )));
    let spec = spec.pack(&mut builder);
    finish_process_security_environment_buffer(&mut builder, spec);
    builder.finished_data().to_vec()
}

fn effective_capabilities(policy: &ContainerPolicy) -> Vec<String> {
    let mut capabilities: Vec<_> = policy
        .capabilities
        .iter()
        .filter(|capability| !capability.is_empty())
        .cloned()
        .collect();
    add_default_network_capabilities(policy, &mut capabilities);
    capabilities
}

fn non_empty_paths(paths: &[String]) -> Option<Vec<String>> {
    (!paths.is_empty()).then(|| paths.to_vec())
}

fn build_psec_network_policy(
    policy: &ContainerPolicy,
    supports_network_ingress: bool,
) -> PsecNetworkPolicy {
    let mut network = PsecNetworkPolicy::default();
    if policy.network_proxy.is_enabled() {
        // Proxy and direct egress are mutually exclusive PSEC policy forms.
        // The parser requires runtime proxy requests to use deny-by-default
        // egress with no direct allow or deny rules.
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
    // Proxy mode uses the private-network capability and peer for ingress.
    // PSEC rejects a proxy combined with the native ingress table.
    let ingress_policy = if supports_network_ingress && !policy.network_proxy.is_enabled() {
        policy.network_ingress.as_ref()
    } else {
        None
    };
    network.allowed_appcontainer_peer = allowed_appcontainer_peer(policy);
    if let Some(ingress_policy) = ingress_policy {
        let mut ingress = PsecIngressPolicy::default();
        ingress.default_action = psec_filter_action(ingress_policy.default);
        ingress.host_loopback = psec_filter_action(ingress_policy.host_loopback);
        network.ingress = Some(Box::new(ingress));
    }
    network
}

fn psec_filter_action(action: NetworkAction) -> PsecFilterAction {
    match action {
        NetworkAction::Allow => PsecFilterAction::allow,
        NetworkAction::Deny => PsecFilterAction::deny,
    }
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

pub(super) fn unrestricted_host_loopback_allowed(policy: &ContainerPolicy) -> bool {
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

#[cfg(test)]
mod tests;
