// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BaseContainer configuration and policy helpers.

use learning_mode_windows::{SecurityEnvironmentApi, SecurityEnvironmentSupport};
use process_security_environment_spec::process_security_environment_layout::{
    finish_process_security_environment_buffer, DestinationRuleT as PsecDestinationRuleT,
    EndpointPolicyT as PsecEndpointPolicy, EndpointRuleT as PsecEndpointRuleT,
    FilterAction as PsecFilterAction, IngressPolicyT as PsecIngressPolicy,
    IpProtocol as PsecIpProtocol, IpSubnetT as PsecIpSubnetT, NetworkPolicyT as PsecNetworkPolicy,
    PortRuleT as PsecPortRuleT, ProcessSecurityEnvironmentT as PsecProcessSecurityEnvironment,
    ProxyInfoT as PsecProxyInfo, SchemaVersionT,
};
use sandbox_spec::base_container_layout::{
    endpoint_policyT, finish_sandbox_spec_buffer, proxy_infoT, FilterAction as SboxFilterAction,
    IntegrityLevel, NetworkPolicyT as SboxNetworkPolicy, SandboxSpecT,
};
use wxc_common::models::{
    ContainerPolicy, ExecutionRequest, NetworkAction, NetworkCidr, NetworkPeer, NetworkPolicy,
    NetworkPort, NetworkProtocol, NetworkRule,
};

use crate::network_policy_helpers::{add_default_network_capabilities, PRIVATE_NETWORK_CAPABILITY};

const SANDBOX_SPEC_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PsecVersion {
    V1_0,
    V1_1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PsecSupport {
    version: PsecVersion,
    deny_paths: bool,
}

impl PsecSupport {
    pub(super) const V1_0: Self = Self {
        version: PsecVersion::V1_0,
        deny_paths: false,
    };

    #[cfg(test)]
    pub(super) const V1_0_WITH_DENY_PATHS: Self = Self {
        version: PsecVersion::V1_0,
        deny_paths: true,
    };

    #[cfg(test)]
    pub(super) const V1_1: Self = Self {
        version: PsecVersion::V1_1,
        deny_paths: false,
    };

    #[cfg(test)]
    pub(super) const V1_1_WITH_DENY_PATHS: Self = Self {
        version: PsecVersion::V1_1,
        deny_paths: true,
    };

    fn from_os(support: SecurityEnvironmentSupport) -> Self {
        let version = if support.supports_network_ingress() {
            PsecVersion::V1_1
        } else {
            PsecVersion::V1_0
        };
        Self {
            version,
            deny_paths: support.supports_deny_paths(),
        }
    }

    pub(super) fn schema_minor_for(self, policy: &ContainerPolicy) -> u16 {
        match self.version_for(policy) {
            PsecVersion::V1_0 => 0,
            PsecVersion::V1_1 => 1,
        }
    }

    pub(super) fn supports_deny_paths(self) -> bool {
        self.deny_paths
    }

    pub(super) fn host_supports_network_ingress(self) -> bool {
        self.version == PsecVersion::V1_1
    }

    pub(super) fn supports_requested_host_loopback(self, policy: &ContainerPolicy) -> bool {
        if !unrestricted_host_loopback_allowed(policy) {
            return true;
        }
        self.host_supports_network_ingress()
    }

    fn version_for(self, policy: &ContainerPolicy) -> PsecVersion {
        if policy.network_ingress.is_some() {
            self.version
        } else {
            PsecVersion::V1_0
        }
    }
}

pub(super) fn query_psec_support() -> Result<PsecSupport, String> {
    let api = SecurityEnvironmentApi::load()
        .map_err(|error| format!("process security-environment API unavailable: {error}"))?;
    let support = api.support().map_err(|error| {
        format!("could not query process security-environment support: {error}")
    })?;
    Ok(PsecSupport::from_os(support))
}

pub(super) fn resolve_psec_support(
    request: &ExecutionRequest,
    query: impl FnOnce() -> Result<PsecSupport, String>,
) -> Result<PsecSupport, String> {
    if !policy_requires_psec_support_query(&request.policy) {
        return Ok(PsecSupport::V1_0);
    }

    let result = query();
    if unrestricted_host_loopback_allowed(&request.policy) {
        return result;
    }

    match result {
        Ok(support) => Ok(support),
        Err(_) => Ok(PsecSupport::V1_0),
    }
}

fn policy_requires_psec_support_query(policy: &ContainerPolicy) -> bool {
    if !policy.denied_paths.is_empty() {
        return true;
    }
    policy.network_ingress.is_some()
}

pub(super) fn requires_psec_networking(policy: &ContainerPolicy) -> bool {
    let has_endpoint_rules = policy.network_egress.as_ref().is_some_and(|egress| {
        if !egress.allow.is_empty() {
            return true;
        }
        !egress.deny.is_empty()
    });
    if has_endpoint_rules {
        return true;
    }
    if policy.allowed_proxy_peer.is_some() {
        return true;
    }
    unrestricted_host_loopback_allowed(policy)
}

pub(super) fn has_conflicting_proxy_identity(policy: &ContainerPolicy) -> bool {
    policy.allowed_proxy_peer.is_some() && unrestricted_host_loopback_allowed(policy)
}

pub(super) fn psec_policy_compatible(request: &ExecutionRequest, support: PsecSupport) -> bool {
    let policy = &request.policy;
    if policy.least_privilege_mode {
        return false;
    }
    if policy.network_proxy.is_enabled() && !policy.runtime_network_proxy_specified {
        return false;
    }
    if !policy.denied_paths.is_empty() && !support.supports_deny_paths() {
        return false;
    }
    if !support.supports_requested_host_loopback(policy) {
        return false;
    }
    true
}

pub(super) fn build_psec_spec(request: &ExecutionRequest, support: PsecSupport) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
    let capabilities = effective_capabilities(&request.policy, support);
    let ui_restrictions = crate::job_object::to_job_object_uilimit_mask(
        &wxc_common::ui_policy::resolve_ui_restrictions(
            &request.policy.ui,
            &request.policy.base_process_ui,
        ),
    ) as u64;

    let mut spec = PsecProcessSecurityEnvironment::default();
    spec.version = match support.version_for(&request.policy) {
        PsecVersion::V1_0 => SchemaVersionT { major: 1, minor: 0 },
        PsecVersion::V1_1 => SchemaVersionT { major: 1, minor: 1 },
    };
    spec.capabilities = (!capabilities.is_empty()).then(|| capabilities.join(","));
    spec.disallow_win32k_system_calls = request.policy.ui.disable;
    spec.ui_restrictions = ui_restrictions;
    spec.fs_read_write = non_empty_paths(&request.policy.readwrite_paths);
    spec.fs_read_only = non_empty_paths(&request.policy.readonly_paths);
    spec.fs_deny = non_empty_paths(&request.policy.denied_paths);
    spec.network_policy = Some(Box::new(build_psec_network_policy(
        &request.policy,
        support,
    )));
    let spec = spec.pack(&mut builder);
    finish_process_security_environment_buffer(&mut builder, spec);
    builder.finished_data().to_vec()
}

pub(super) fn build_sbox_spec(request: &ExecutionRequest) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
    let capabilities = effective_capabilities(&request.policy, PsecSupport::V1_0);
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

fn effective_capabilities(policy: &ContainerPolicy, support: PsecSupport) -> Vec<String> {
    let mut capabilities: Vec<_> = policy
        .capabilities
        .iter()
        .filter(|capability| !capability.is_empty())
        .cloned()
        .collect();
    add_default_network_capabilities(policy, &mut capabilities);
    if support.host_supports_network_ingress() && policy.network_ingress.is_some() {
        capabilities
            .retain(|capability| !capability.eq_ignore_ascii_case(PRIVATE_NETWORK_CAPABILITY));
    }
    capabilities
}

fn non_empty_paths(paths: &[String]) -> Option<Vec<String>> {
    (!paths.is_empty()).then(|| paths.to_vec())
}

fn build_legacy_sbox_network_policy(policy: &ContainerPolicy) -> SboxNetworkPolicy {
    let mut network = SboxNetworkPolicy::default();
    if policy.network_proxy.is_enabled() {
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

fn build_psec_network_policy(policy: &ContainerPolicy, support: PsecSupport) -> PsecNetworkPolicy {
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
    network.allowed_appcontainer_peer = policy.allowed_proxy_peer.clone();
    if support.host_supports_network_ingress() {
        network.ingress = policy.network_ingress.as_ref().map(|ingress_policy| {
            let mut ingress = PsecIngressPolicy::default();
            ingress.default_action = psec_filter_action(ingress_policy.default);
            ingress.host_loopback = psec_filter_action(ingress_policy.host_loopback);
            Box::new(ingress)
        });
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

fn unrestricted_host_loopback_allowed(policy: &ContainerPolicy) -> bool {
    policy
        .network_ingress
        .as_ref()
        .is_some_and(|ingress| ingress.host_loopback == NetworkAction::Allow)
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
mod tests {
    use super::*;
    use process_security_environment_spec::process_security_environment_layout as psec_layout;
    use wxc_common::models::NetworkIngressPolicy;

    #[test]
    fn psec_1_0_uses_capability_fallback_for_ingress_default() {
        let mut request = ExecutionRequest::default();
        request.policy.network_ingress = Some(NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Deny,
        });

        let bytes = build_psec_spec(&request, PsecSupport::V1_0);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
        let network = spec.network_policy().expect("network policy");
        let version = spec.version();

        assert_eq!((version.major(), version.minor()), (1, 0));
        assert_eq!(spec.capabilities(), Some(PRIVATE_NETWORK_CAPABILITY));
        assert!(network.ingress().is_none());
    }

    #[test]
    fn psec_1_1_encodes_ingress_without_legacy_capabilities_or_peer() {
        let mut request = ExecutionRequest::default();
        request.policy.network_ingress = Some(NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Allow,
        });

        let bytes = build_psec_spec(&request, PsecSupport::V1_1);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
        let network = spec.network_policy().expect("network policy");
        let ingress = network.ingress().expect("ingress policy");
        let version = spec.version();

        assert_eq!((version.major(), version.minor()), (1, 1));
        assert!(spec.capabilities().is_none());
        assert!(network.allowed_appcontainer_peer().is_none());
        assert_eq!(ingress.default_action(), psec_layout::FilterAction::allow);
        assert_eq!(ingress.host_loopback(), psec_layout::FilterAction::allow);
    }

    #[test]
    fn support_query_failure_uses_legacy_ingress_default_lowering() {
        let mut request = ExecutionRequest::default();
        request.policy.network_ingress = Some(NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Deny,
        });

        let support = resolve_psec_support(&request, || Err("query failed".to_string())).unwrap();
        let bytes = build_psec_spec(&request, support);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();

        assert_eq!(spec.version().minor(), 0);
        assert_eq!(spec.capabilities(), Some(PRIVATE_NETWORK_CAPABILITY));
        assert!(spec
            .network_policy()
            .expect("network policy")
            .ingress()
            .is_none());
    }

    #[test]
    fn support_query_failure_rejects_host_loopback_allow() {
        let mut request = ExecutionRequest::default();
        request.policy.network_ingress = Some(NetworkIngressPolicy {
            default: NetworkAction::Deny,
            host_loopback: NetworkAction::Allow,
        });

        let error = resolve_psec_support(&request, || Err("query failed".to_string())).unwrap_err();

        assert_eq!(error, "query failed");
    }
}
