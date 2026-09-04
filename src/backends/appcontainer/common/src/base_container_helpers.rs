// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BaseContainer configuration and policy helpers.

use learning_mode_windows::{
    LearningModeError, SecurityEnvironmentApi, SecurityEnvironmentSupport,
};
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

#[derive(Debug, thiserror::Error)]
pub(super) enum BaseContainerError {
    #[error("Process Security Environment API unavailable: {0}")]
    ProcessSecurityEnvironmentApi(#[source] LearningModeError),
    #[error("Learning Mode API unavailable: {0}")]
    LearningModeApi(#[source] LearningModeError),
    #[error("failed to determine Process Security Environment support: {0}")]
    ProcessSecurityEnvironmentSupport(#[from] LearningModeError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PsecContractVersion {
    V1_0,
    V1_1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivateNetworkAccessEncoding {
    /// Passes `privateNetworkClientServer` to PSEC 1.0 and SBOX on systems without OS ingress
    /// policy support.
    BidirectionalCapability,
    /// Passes the ingress policy to PSEC 1.1 and omits `privateNetworkClientServer` because the OS
    /// applies the required capability from that policy.
    DirectionalIngressPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PsecSupport {
    ingress_policy: bool,
    deny_paths: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProcessSecurityEnvironmentDecision {
    pub(super) use_process_security_environment: bool,
    pub(super) support: PsecSupport,
    pub(super) support_query_attempted: bool,
}

impl ProcessSecurityEnvironmentDecision {
    fn skip_without_support_query() -> Self {
        Self {
            use_process_security_environment: false,
            support: PsecSupport::NO_OPTIONAL_CAPABILITIES,
            support_query_attempted: false,
        }
    }

    pub(super) fn os_query_confirms_host_loopback_is_unsupported(
        self,
        policy: &ContainerPolicy,
    ) -> bool {
        self.support_query_attempted && !self.support.can_enforce_requested_host_loopback(policy)
    }
}

impl PsecSupport {
    /// Conservative PSEC 1.0 support when no optional OS capability is known.
    pub(super) const NO_OPTIONAL_CAPABILITIES: Self = Self {
        ingress_policy: false,
        deny_paths: false,
    };

    fn from_os(support: SecurityEnvironmentSupport) -> Self {
        Self {
            ingress_policy: support.supports_network_ingress(),
            deny_paths: support.supports_deny_paths(),
        }
    }

    pub(super) fn supports_deny_paths(self) -> bool {
        self.deny_paths
    }

    pub(super) fn can_enforce_requested_host_loopback(self, policy: &ContainerPolicy) -> bool {
        if !is_unrestricted_host_loopback_allowed(policy) {
            // Deny is the compatibility default; only an allow requires directional ingress.
            return true;
        }
        self.ingress_policy
    }

    fn contract_version_for(self, policy: &ContainerPolicy) -> PsecContractVersion {
        match (policy.network_ingress.is_some(), self.ingress_policy) {
            (true, true) => PsecContractVersion::V1_1,
            _ => PsecContractVersion::V1_0,
        }
    }

    pub(super) fn schema_version_for(self, policy: &ContainerPolicy) -> SchemaVersionT {
        match self.contract_version_for(policy) {
            PsecContractVersion::V1_0 => SchemaVersionT { major: 1, minor: 0 },
            PsecContractVersion::V1_1 => SchemaVersionT { major: 1, minor: 1 },
        }
    }

    fn private_network_access_encoding(
        self,
        policy: &ContainerPolicy,
    ) -> PrivateNetworkAccessEncoding {
        match (self.ingress_policy, policy.network_ingress.is_some()) {
            (true, true) => PrivateNetworkAccessEncoding::DirectionalIngressPolicy,
            _ => PrivateNetworkAccessEncoding::BidirectionalCapability,
        }
    }
}

pub(super) fn query_psec_support() -> Result<PsecSupport, BaseContainerError> {
    let api = SecurityEnvironmentApi::load()
        .map_err(BaseContainerError::ProcessSecurityEnvironmentApi)?;
    let support = api
        .support()
        .map_err(BaseContainerError::ProcessSecurityEnvironmentSupport)?;
    Ok(PsecSupport::from_os(support))
}

pub(super) fn decide_psec_usage<E>(
    request: &ExecutionRequest,
    process_security_environment_usable: bool,
    process_security_environment_capture_apis_usable: bool,
    query_os_support: impl FnOnce() -> Result<PsecSupport, E>,
) -> Result<ProcessSecurityEnvironmentDecision, E> {
    if !process_security_environment_usable {
        return Ok(ProcessSecurityEnvironmentDecision::skip_without_support_query());
    }

    let capture_requested = request.policy.capture_denials.is_some();
    let required_capture_apis_unavailable =
        capture_requested && !process_security_environment_capture_apis_usable;
    if required_capture_apis_unavailable {
        // PSEC cannot fulfill captureDenials without the Learning Mode APIs. Leave it unselected
        // so the dispatcher can use legacy SBOX with guarded WPR capture instead.
        return Ok(ProcessSecurityEnvironmentDecision::skip_without_support_query());
    }

    let mut support_query_attempted = false;
    let support = resolve_psec_support(request, || {
        support_query_attempted = true;
        query_os_support()
    })?;
    let use_process_security_environment = is_psec_policy_compatible(request, support);
    Ok(ProcessSecurityEnvironmentDecision {
        use_process_security_environment,
        support,
        support_query_attempted,
    })
}

fn resolve_psec_support<E>(
    request: &ExecutionRequest,
    query_os_support: impl FnOnce() -> Result<PsecSupport, E>,
) -> Result<PsecSupport, E> {
    if !policy_requires_psec_support_query(&request.policy) {
        return Ok(PsecSupport::NO_OPTIONAL_CAPABILITIES);
    }

    // Host-loopback deny is the PSEC 1.0 default; allow must be confirmed by OS ingress support.
    let host_loopback_allow_requires_os_ingress =
        is_unrestricted_host_loopback_allowed(&request.policy);
    match query_os_support() {
        Ok(support) => Ok(support),
        Err(error) if host_loopback_allow_requires_os_ingress => Err(error),
        // Without host-loopback allow, PSEC 1.0 is a safe conservative fallback.
        Err(_) => Ok(PsecSupport::NO_OPTIONAL_CAPABILITIES),
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
    is_unrestricted_host_loopback_allowed(policy)
}

pub(super) fn has_conflicting_proxy_identity(policy: &ContainerPolicy) -> bool {
    policy.allowed_proxy_peer.is_some() && is_unrestricted_host_loopback_allowed(policy)
}

pub(super) fn is_psec_policy_compatible(request: &ExecutionRequest, support: PsecSupport) -> bool {
    let policy = &request.policy;
    if policy.least_privilege_mode {
        return false;
    }
    // Legacy proxy requests use the SBOX contract rather than PSEC.
    if policy.network_proxy.is_enabled() && !policy.runtime_network_proxy_specified {
        return false;
    }
    // Denied paths require explicit support from the OS capability query.
    if !policy.denied_paths.is_empty() && !support.supports_deny_paths() {
        return false;
    }
    if !support.can_enforce_requested_host_loopback(policy) {
        return false;
    }
    true
}

pub(super) fn build_psec_spec(request: &ExecutionRequest, support: PsecSupport) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
    let capabilities = effective_capabilities(
        &request.policy,
        support.private_network_access_encoding(&request.policy),
    );
    let ui_restrictions = crate::job_object::to_job_object_uilimit_mask(
        &wxc_common::ui_policy::resolve_ui_restrictions(
            &request.policy.ui,
            &request.policy.base_process_ui,
        ),
    ) as u64;

    let mut spec = PsecProcessSecurityEnvironment::default();
    spec.version = support.schema_version_for(&request.policy);
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
    let capabilities = effective_capabilities(
        &request.policy,
        PrivateNetworkAccessEncoding::BidirectionalCapability,
    );
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

fn effective_capabilities(
    policy: &ContainerPolicy,
    private_network_access_encoding: PrivateNetworkAccessEncoding,
) -> Vec<String> {
    let mut capabilities: Vec<_> = policy
        .capabilities
        .iter()
        .filter(|capability| !capability.is_empty())
        .cloned()
        .collect();
    add_default_network_capabilities(policy, &mut capabilities);
    if private_network_access_encoding == PrivateNetworkAccessEncoding::DirectionalIngressPolicy {
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
    if support.ingress_policy {
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

fn is_unrestricted_host_loopback_allowed(policy: &ContainerPolicy) -> bool {
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
impl PsecSupport {
    pub(super) const DENY_PATHS: Self = Self {
        ingress_policy: false,
        deny_paths: true,
    };

    pub(super) const OS_INGRESS_POLICY: Self = Self {
        ingress_policy: true,
        deny_paths: false,
    };

    pub(super) const OS_INGRESS_POLICY_WITH_DENY_PATHS: Self = Self {
        ingress_policy: true,
        deny_paths: true,
    };
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

        let bytes = build_psec_spec(&request, PsecSupport::NO_OPTIONAL_CAPABILITIES);
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
            default: NetworkAction::Deny,
            host_loopback: NetworkAction::Allow,
        });

        let bytes = build_psec_spec(&request, PsecSupport::OS_INGRESS_POLICY);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
        let network = spec.network_policy().expect("network policy");
        let ingress = network.ingress().expect("ingress policy");
        let version = spec.version();

        assert_eq!((version.major(), version.minor()), (1, 1));
        assert!(spec.capabilities().is_none());
        assert!(network.allowed_appcontainer_peer().is_none());
        assert_eq!(ingress.default_action(), psec_layout::FilterAction::deny);
        assert_eq!(ingress.host_loopback(), psec_layout::FilterAction::allow);
    }

    #[test]
    fn psec_1_1_replaces_private_network_capability_with_ingress_policy() {
        let mut request = ExecutionRequest::default();
        request.policy.network_ingress = Some(NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Deny,
        });

        let bytes = build_psec_spec(&request, PsecSupport::OS_INGRESS_POLICY);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
        let ingress = spec
            .network_policy()
            .expect("network policy")
            .ingress()
            .expect("ingress policy");

        assert!(spec.capabilities().is_none());
        assert_eq!(ingress.default_action(), psec_layout::FilterAction::allow);
        assert_eq!(ingress.host_loopback(), psec_layout::FilterAction::deny);
    }

    #[test]
    fn support_query_failure_falls_back_to_psec_1_0_when_host_loopback_is_denied() {
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
