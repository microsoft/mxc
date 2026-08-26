// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::WxcError;
use crate::models::{
    unbracket_host, ContainerPolicy, ContainmentBackend, NetworkAction, NetworkCidr,
    NetworkEgressPolicy, NetworkIngressPolicy, NetworkPeer, NetworkPort, NetworkProtocol,
    NetworkRule, ProxyAddress, ProxyConfig,
};
use crate::wire;

fn has_legacy_fields(network: &wire::Network) -> bool {
    network.default_policy.is_some()
        || network.enforcement_mode.is_some()
        || network.allow_local_network.is_some()
        || network.allowed_hosts.is_some()
        || network.blocked_hosts.is_some()
        || network.proxy.is_some()
}

fn has_directional_policy_fields(network: &wire::Network) -> bool {
    network.egress.is_some() || network.ingress.is_some()
}

fn has_runtime_fields(runtime: &wire::RuntimeConfig) -> bool {
    runtime.network_proxy.is_some()
}

fn has_process_container_network_fields(network: &wire::ProcessContainerNetwork) -> bool {
    network
        .allowed_proxy_peer
        .as_ref()
        .is_some_and(|peer| !peer.trim().is_empty())
}

/// Returns directional-network support for a valid schema version.
///
/// `None` leaves malformed-version diagnostics to the schema parser.
pub fn directional_network_support(version: &str) -> Option<bool> {
    semver::Version::parse(version)
        .ok()
        .map(|version| version.major > 0 || version.minor >= 8)
}

pub fn supports_directional_network(version: &str) -> bool {
    directional_network_support(version).unwrap_or(false)
}

pub(crate) fn directional_network_version_error() -> WxcError {
    WxcError::ConfigParse(
        "network.egress, network.ingress, runtimeConfig, and processContainer.network \
         require schema version 0.8 or later"
            .to_string(),
    )
}

#[derive(Debug)]
pub(crate) struct NetworkSections {
    pub network: Option<wire::Network>,
    pub runtime: Option<wire::RuntimeConfig>,
    pub process_container: Option<wire::ProcessContainerNetwork>,
}

#[derive(Debug)]
pub(crate) struct NetworkMetadata {
    /// Whether the proxy used the host-loopback shorthand.
    pub proxy_used_localhost: bool,
}

enum NetworkFormat {
    Legacy,
    Directional,
}

/// Any address in `127.0.0.0/8`, plus `::1` and `localhost`.
///
/// Use this to *reject* a host (LXC treats all of `127/8` as the container's
/// own namespace loopback). Breadth is fail-safe here: a wider match rejects
/// more. To *admit* a host, use [`host_is_canonical_loopback`].
pub(crate) fn host_is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    unbracket_host(host)
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Only `127.0.0.1` and `::1`, plus `localhost`; bracketed or not, any case.
///
/// Use this to *admit* a proxy host. The accept-set is exactly what Seatbelt's
/// `(remote ip "localhost:<port>")` enforces — measured, not assumed: under
/// that rule `127.0.0.1` and `::1` connect while `127.0.0.2` gets `EPERM`.
/// Matching `127.0.0.0/8` here would admit a proxy the sandbox then blocks.
pub fn host_is_canonical_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    matches!(
        unbracket_host(host).parse::<IpAddr>(),
        Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)) | Ok(IpAddr::V6(Ipv6Addr::LOCALHOST))
    )
}

fn convert_wire_proxy_at(proxy: wire::Proxy, path: &str) -> Result<ProxyConfig, WxcError> {
    let wire::Proxy {
        builtin_test_server,
        localhost,
        url,
    } = proxy;
    let mut proxy_addr = ProxyAddress::new("127.0.0.1".to_string(), 0);

    if let Some(builtin) = builtin_test_server {
        if !builtin {
            return Err(WxcError::ConfigParse(format!(
                "{path}.builtinTestServer must be true when present"
            )));
        }
        if localhost.is_some() || url.is_some() {
            return Err(WxcError::ConfigParse(format!(
                "When {path}.builtinTestServer is true, no other proxy options may be set"
            )));
        }
        return Ok(ProxyConfig {
            address: Some(proxy_addr),
            builtin_test_server: true,
        });
    }

    if let Some(port) = localhost {
        if port == 0 {
            return Err(WxcError::ConfigParse(format!(
                "{path}.localhost must be a port between 1 and 65535"
            )));
        }
        proxy_addr.port = port;
        return Ok(ProxyConfig {
            address: Some(proxy_addr),
            builtin_test_server: false,
        });
    }

    if let Some(url_str) = url {
        let redacted = crate::proxy_env::redact_proxy_url(&url_str);
        let parsed = url::Url::parse(&url_str)
            .map_err(|e| WxcError::ConfigParse(format!("{path} is invalid: {e}")))?;
        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(WxcError::ConfigParse(format!(
                "{path} must use the 'http' or 'https' scheme (got '{scheme}'): {redacted}"
            )));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| {
                WxcError::ConfigParse(format!(
                    "{path} must include a host (e.g., http://localhost:8080), got: {redacted}"
                ))
            })?
            .to_string();
        let port = parsed.port().ok_or_else(|| {
            WxcError::ConfigParse(format!(
                "{path} must include a port (e.g., http://localhost:8080), got: {redacted}"
            ))
        })?;
        return Ok(ProxyConfig {
            address: Some(ProxyAddress::from_url(&url_str, host, port)),
            builtin_test_server: false,
        });
    }

    Err(WxcError::ConfigParse(format!(
        "{path} must specify builtinTestServer, localhost, or url"
    )))
}

pub(crate) fn convert_wire_proxy(proxy: wire::Proxy) -> Result<ProxyConfig, WxcError> {
    convert_wire_proxy_at(proxy, "network.proxy")
}

fn select_network_format(
    version: &str,
    sections: &NetworkSections,
) -> Result<NetworkFormat, WxcError> {
    let has_legacy = sections.network.as_ref().is_some_and(has_legacy_fields);
    let has_directional_policy = sections
        .network
        .as_ref()
        .is_some_and(has_directional_policy_fields);
    let has_runtime_config = sections.runtime.as_ref().is_some_and(has_runtime_fields);
    let has_process_container_network = sections
        .process_container
        .as_ref()
        .is_some_and(has_process_container_network_fields);
    let has_directional =
        has_directional_policy || has_runtime_config || has_process_container_network;
    let has_directional_section =
        sections.runtime.is_some() || sections.process_container.is_some();
    let supports_directional = supports_directional_network(version);

    if has_legacy && has_directional {
        return Err(WxcError::ConfigParse(
            "network configuration cannot mix defaultPolicy, enforcementMode, \
             allowLocalNetwork, allowedHosts, blockedHosts, or proxy with egress, ingress, \
             runtimeConfig, or processContainer.network"
                .to_string(),
        ));
    }

    if (has_directional_policy || has_directional_section) && !supports_directional {
        return Err(directional_network_version_error());
    }

    // An empty or omitted network block has no fields that identify its format.
    // Use directional deny defaults when the schema supports them.
    if !has_legacy && supports_directional {
        Ok(NetworkFormat::Directional)
    } else {
        Ok(NetworkFormat::Legacy)
    }
}

/// Parses the selected network format into the shared backend-facing policy.
///
/// Returns metadata when backend-specific validation is still required.
pub(crate) fn parse_network_policy(
    policy: &mut ContainerPolicy,
    version: &str,
    sections: NetworkSections,
    containment: &ContainmentBackend,
) -> Result<Option<NetworkMetadata>, WxcError> {
    match select_network_format(version, &sections)? {
        NetworkFormat::Legacy => apply_legacy_network(policy, sections.network),
        NetworkFormat::Directional => {
            apply_directional_network(policy, sections, containment)?;
            Ok(None)
        }
    }
}

fn apply_legacy_network(
    policy: &mut ContainerPolicy,
    network: Option<wire::Network>,
) -> Result<Option<NetworkMetadata>, WxcError> {
    policy.network_specified = network.is_some();
    let Some(network) = network else {
        return Ok(None);
    };

    policy.network_mode_specified = network.default_policy.is_some()
        || network.enforcement_mode.is_some()
        || network.allow_local_network.is_some()
        || network.allowed_hosts.is_some()
        || network.blocked_hosts.is_some();

    let proxy_used_localhost = network
        .proxy
        .as_ref()
        .is_some_and(|proxy| proxy.localhost.is_some());
    if let Some(proxy) = network.proxy {
        policy.network_proxy = convert_wire_proxy(proxy)?;
    }
    if let Some(default) = network.default_policy {
        policy.default_network_policy = default.into();
    }
    if let Some(mode) = network.enforcement_mode {
        policy.network_enforcement_mode = mode.into();
    }
    if let Some(allow) = network.allow_local_network {
        policy.allow_local_network = allow;
    }
    if let Some(hosts) = network.allowed_hosts {
        policy.allowed_hosts = hosts;
    }
    if let Some(hosts) = network.blocked_hosts {
        policy.blocked_hosts = hosts;
    }

    Ok(Some(NetworkMetadata {
        proxy_used_localhost,
    }))
}

fn convert_egress(egress: Option<wire::NetworkEgress>) -> Result<NetworkEgressPolicy, WxcError> {
    let egress = egress.unwrap_or(wire::NetworkEgress {
        default: None,
        allow: None,
        deny: None,
    });
    Ok(NetworkEgressPolicy {
        default: egress.default.map(convert_action).unwrap_or_default(),
        allow: convert_rules(egress.allow.unwrap_or_default(), "network.egress.allow")?,
        deny: convert_rules(egress.deny.unwrap_or_default(), "network.egress.deny")?,
    })
}

fn convert_ingress(ingress: Option<wire::NetworkIngress>) -> NetworkIngressPolicy {
    let ingress = ingress.unwrap_or(wire::NetworkIngress {
        default: None,
        host_loopback: None,
    });
    NetworkIngressPolicy {
        default: ingress.default.map(convert_action).unwrap_or_default(),
        host_loopback: ingress
            .host_loopback
            .map(convert_action)
            .unwrap_or_default(),
    }
}

fn apply_directional_network(
    policy: &mut ContainerPolicy,
    sections: NetworkSections,
    containment: &ContainmentBackend,
) -> Result<(), WxcError> {
    let NetworkSections {
        network,
        runtime,
        process_container,
    } = sections;
    policy.network_specified = network.is_some();
    policy.allowed_proxy_peer = process_container
        .and_then(|network| network.allowed_proxy_peer)
        .filter(|peer| !peer.trim().is_empty());

    match network {
        Some(network) => {
            // Egress and ingress define the sandbox's network posture and are
            // immutable after provision for state-aware backends. Runtime proxy
            // metadata is intentionally excluded because it may be supplied at exec.
            policy.network_mode_specified = has_directional_policy_fields(&network);

            let egress = convert_egress(network.egress)?;
            policy.network_egress = Some(egress);

            let ingress = convert_ingress(network.ingress);
            policy.network_ingress = Some(ingress);
        }
        None => {
            policy.network_egress = Some(NetworkEgressPolicy::default());
            policy.network_ingress = Some(NetworkIngressPolicy::default());
        }
    }

    if let Some(url) = runtime.and_then(|runtime| runtime.network_proxy) {
        policy.runtime_network_proxy_specified = true;
        // Runtime proxy is a 0.8 wire field normalized into the existing
        // backend-facing proxy configuration.
        let proxy = convert_wire_proxy_at(
            wire::Proxy {
                localhost: None,
                builtin_test_server: None,
                url: Some(url),
            },
            "runtimeConfig.networkProxy",
        )?;
        let host = proxy
            .address
            .as_ref()
            .map(ProxyAddress::host)
            .unwrap_or_default();
        if !host_is_canonical_loopback(host) {
            return Err(WxcError::ConfigParse(
                "runtimeConfig.networkProxy must use localhost, 127.0.0.1, or [::1]".to_string(),
            ));
        }
        policy.network_proxy = proxy;
    }

    if policy.network_mode_specified && policy.network_proxy.is_enabled() {
        validate_directional_proxy_policy(policy)?;
    }

    validate_proxy_policy(policy, containment)
}

fn validate_directional_proxy_policy(policy: &ContainerPolicy) -> Result<(), WxcError> {
    let Some(egress) = policy.network_egress.as_ref() else {
        return Err(WxcError::ConfigParse(
            "runtimeConfig.networkProxy requires an egress policy".to_string(),
        ));
    };
    if egress.default != NetworkAction::Deny || !egress.allow.is_empty() || !egress.deny.is_empty()
    {
        return Err(WxcError::ConfigParse(
            "runtimeConfig.networkProxy requires network.egress.default='deny' with no direct \
             allow or deny rules"
                .to_string(),
        ));
    }
    Ok(())
}

fn convert_action(action: wire::NetworkAction) -> NetworkAction {
    match action {
        wire::NetworkAction::Allow => NetworkAction::Allow,
        wire::NetworkAction::Deny => NetworkAction::Deny,
    }
}

fn parse_cidr(value: &str, path: &str) -> Result<NetworkCidr, WxcError> {
    value.parse::<NetworkCidr>().map_err(|error| {
        WxcError::ConfigParse(format!("{path} must be a valid network CIDR: {error}"))
    })
}

fn convert_rules(rules: Vec<wire::NetworkRule>, path: &str) -> Result<Vec<NetworkRule>, WxcError> {
    rules
        .into_iter()
        .enumerate()
        .map(|(index, rule)| convert_rule(rule, path, index))
        .collect()
}

fn convert_rule(
    rule: wire::NetworkRule,
    path: &str,
    rule_index: usize,
) -> Result<NetworkRule, WxcError> {
    let rule_path = format!("{path}[{rule_index}]");
    if rule.to.as_ref().is_some_and(Vec::is_empty) {
        return Err(WxcError::ConfigParse(format!(
            "{rule_path}.to must contain at least one destination when specified"
        )));
    }
    if rule.ports.as_ref().is_some_and(Vec::is_empty) {
        return Err(WxcError::ConfigParse(format!(
            "{rule_path}.ports must contain at least one selector when specified"
        )));
    }

    let to = rule
        .to
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(index, peer)| convert_peer(peer, &rule_path, index))
        .collect::<Result<Vec<_>, _>>()?;
    let ports = rule
        .ports
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(index, port)| convert_port(port, &rule_path, index))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(NetworkRule { to, ports })
}

fn convert_peer(
    peer: wire::NetworkPeer,
    rule_path: &str,
    peer_index: usize,
) -> Result<NetworkPeer, WxcError> {
    let peer_path = format!("{rule_path}.to[{peer_index}]");
    let cidr = parse_cidr(&peer.cidr, &format!("{peer_path}.cidr"))?;
    let except = peer
        .except
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(index, value)| parse_cidr(&value, &format!("{peer_path}.except[{index}]")))
        .collect::<Result<Vec<_>, _>>()?;

    validate_exclusions(&cidr, &except, &peer_path)?;
    Ok(NetworkPeer { cidr, except })
}

fn validate_exclusions(
    cidr: &NetworkCidr,
    exclusions: &[NetworkCidr],
    peer_path: &str,
) -> Result<(), WxcError> {
    for (index, exclusion) in exclusions.iter().enumerate() {
        if !cidr.contains_cidr(exclusion) {
            return Err(WxcError::ConfigParse(format!(
                "{peer_path}.except[{index}] must be contained within {peer_path}.cidr"
            )));
        }
    }
    Ok(())
}

fn convert_port(
    port: wire::NetworkPort,
    rule_path: &str,
    port_index: usize,
) -> Result<NetworkPort, WxcError> {
    let port_path = format!("{rule_path}.ports[{port_index}]");
    validate_port_range(&port, &port_path)?;

    let protocol = match port.protocol.unwrap_or(wire::NetworkProtocol::Any) {
        wire::NetworkProtocol::Tcp => NetworkProtocol::Tcp,
        wire::NetworkProtocol::Udp => NetworkProtocol::Udp,
        wire::NetworkProtocol::Icmp => NetworkProtocol::Icmp,
        wire::NetworkProtocol::Any => NetworkProtocol::Any,
    };
    if protocol == NetworkProtocol::Icmp && (port.port.is_some() || port.end_port.is_some()) {
        return Err(WxcError::ConfigParse(format!(
            "{port_path} cannot specify port or endPort for protocol='icmp'"
        )));
    }
    Ok(NetworkPort {
        protocol,
        port: port.port,
        end_port: port.end_port,
    })
}

fn validate_port_range(port: &wire::NetworkPort, path: &str) -> Result<(), WxcError> {
    if port.port == Some(0) {
        return Err(WxcError::ConfigParse(format!(
            "{path}.port must be between 1 and 65535"
        )));
    }
    if port.end_port == Some(0) {
        return Err(WxcError::ConfigParse(format!(
            "{path}.endPort must be between 1 and 65535"
        )));
    }
    if port.end_port.is_some() && port.port.is_none() {
        return Err(WxcError::ConfigParse(format!(
            "{path}.endPort requires port"
        )));
    }
    if let (Some(start), Some(end)) = (port.port, port.end_port) {
        if end < start {
            return Err(WxcError::ConfigParse(format!(
                "{path}.endPort must be greater than or equal to port"
            )));
        }
    }
    Ok(())
}

fn validate_proxy_policy(
    policy: &ContainerPolicy,
    containment: &ContainmentBackend,
) -> Result<(), WxcError> {
    let proxy_enabled = policy.network_proxy.is_enabled();
    if !proxy_enabled {
        return match containment {
            ContainmentBackend::ProcessContainer => {
                validate_process_container_proxy_policy(policy, false)
            }
            _ => Ok(()),
        };
    }

    match containment {
        ContainmentBackend::ProcessContainer => {
            validate_process_container_proxy_policy(policy, true)
        }
        _ => Ok(()),
    }
}

fn validate_process_container_proxy_policy(
    policy: &ContainerPolicy,
    proxy_enabled: bool,
) -> Result<(), WxcError> {
    if policy
        .allowed_proxy_peer
        .as_deref()
        .is_some_and(|peer| peer.eq_ignore_ascii_case("MXC-Loopback"))
    {
        return Err(WxcError::ConfigParse(
            "processContainer.network.allowedProxyPeer must not use the reserved \
             'MXC-Loopback' identity"
                .to_string(),
        ));
    }
    if policy.allowed_proxy_peer.is_some() && !proxy_enabled {
        return Err(WxcError::ConfigParse(
            "processContainer.network.allowedProxyPeer requires runtimeConfig.networkProxy"
                .to_string(),
        ));
    }
    if !proxy_enabled {
        return Ok(());
    }

    let Some(ingress) = policy.network_ingress.as_ref() else {
        return Err(WxcError::ConfigParse(
            "ProcessContainer runtimeConfig.networkProxy requires an ingress policy".to_string(),
        ));
    };
    if ingress.default != NetworkAction::Allow {
        return Err(WxcError::ConfigParse(
            "ProcessContainer runtimeConfig.networkProxy requires \
             network.ingress.default='allow'"
                .to_string(),
        ));
    }

    match (policy.allowed_proxy_peer.is_some(), ingress.host_loopback) {
        (true, NetworkAction::Allow) => Err(WxcError::ConfigParse(
            "an identity-scoped ProcessContainer proxy requires \
             network.ingress.hostLoopback='deny'"
                .to_string(),
        )),
        (false, NetworkAction::Deny) => Err(WxcError::ConfigParse(
            "a ProcessContainer proxy without allowedProxyPeer requires \
             network.ingress.hostLoopback='allow'"
                .to_string(),
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod proxy_policy_tests {
    use super::*;

    #[test]
    fn reserved_loopback_peer_identity_is_rejected_case_insensitively() {
        let policy = ContainerPolicy {
            allowed_proxy_peer: Some("mxc-loopback".to_string()),
            ..Default::default()
        };

        let error = validate_process_container_proxy_policy(&policy, true).unwrap_err();
        match error {
            WxcError::ConfigParse(message) => assert_eq!(
                message,
                "processContainer.network.allowedProxyPeer must not use the reserved \
                 'MXC-Loopback' identity"
            ),
            other => panic!("expected config error, got {other:?}"),
        }
    }
}

#[cfg(test)]
#[path = "network_parser_loopback_spec_tests.rs"]
mod loopback_spec_tests;
