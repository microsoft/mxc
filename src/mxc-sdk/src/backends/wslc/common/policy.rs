// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Policy validation for the WSLc backend.
//!
//! WSLc honours a richer policy surface than IsolationSession, and each field
//! is bound to the phase where the daemon can actually apply it. Anything the
//! daemon cannot honour at a given phase is rejected (a `policy_validation`
//! envelope) rather than silently ignored:
//!
//! | Field                       | provision                    | start / stop / deprovision | exec                       |
//! |-----------------------------|------------------------------|----------------------------|----------------------------|
//! | `readwrite` / `readonly`    | honoured (volume mounts)     | rejected (immutable)       | rejected (immutable)       |
//! | `denied_paths`              | rejected if overlapping [^1] | rejected                   | rejected                   |
//! | `ui`                        | rejected (no UI primitive)   | rejected                   | rejected                   |
//! | `network.egress.default`    | honoured (None / Bridged)    | rejected (immutable)       | rejected (immutable)       |
//! | `network.ingress.*`         | must match egress (deny all / allow all) | rejected         | rejected                   |
//! | `runtimeConfig.networkProxy` | rejected (applies at exec) | rejected                   | honoured (cooperative env) |
//!
//! [^1]: a standalone `denied_path` is honoured by container isolation (unlisted
//! host paths are simply never mounted); only a denied path nested under a
//! mounted `rw`/`ro` parent is rejected, because WSLc has no overlay primitive
//! to mask a subtree of a mounted volume.
//!
//! Create-and-run also accepts egress rules and mixed postures, which
//! [`create_and_run_network_mode`] routes through the built-in proxy.
//!
//! Checks run filesystem → ui → network, so a request that trips several gets a
//! stable message rather than one that depends on field order (asserted by
//! tests). [`reject_ui_policy`] applies to both one-shot and state-aware validation.

use std::net::IpAddr;

use crate::mxc_common::models::{
    ExecutionRequest, NetworkAction, NetworkCidr, NetworkEgressPolicy, NetworkPeer, NetworkPort,
    NetworkProtocol,
};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::validator::NetworkPolicySupport;

use crate::wslc_common::policy_mapping::validate_denied_path_overlap;
use crate::wslc_common::process_env::EnvScope;
use crate::wslc_gateway_policy as gateway;

const ERR_FILESYSTEM_IMMUTABLE: &str =
    "filesystem policy (readwritePaths / readonlyPaths / deniedPaths and processContainer.filesystem.enumeratePaths) is bound to the provision \
     phase and cannot be changed by the WSLc backend after provisioning";
const ERR_ENUMERATE_PATHS: &str =
    "processContainer.filesystem.enumeratePaths is not supported by the WSLc backend";
const ERR_NETWORK_IMMUTABLE: &str =
    "network mode is bound to the provision phase and cannot be changed by the WSLc backend after \
     provisioning";
const ERR_PROXY_AT_PROVISION: &str =
    "runtimeConfig.networkProxy is applied per-exec by the WSLc backend; set it on the exec phase, not provision";
const ERR_PROXY_AT_PHASE: &str =
    "runtimeConfig.networkProxy is only honoured on the exec phase by the WSLc backend";
const ERR_PROXY_URL_TOO_LONG: &str = "WSLc: runtimeConfig.networkProxy must not exceed 8192 bytes";
const ERR_PROXY_MISMATCH: &str =
    "WSLc: runtimeConfig.networkProxy on exec must match the proxy set at provision; omit it to \
     use the provisioned proxy";
const ERR_PROXY_URL_FORM: &str =
    "WSLc: runtimeConfig.networkProxy requires a proxy url reachable from inside the container; \
     a host-loopback proxy is not reachable from the container's own network namespace";
const ERR_PROXY_WITHOUT_ROUTE: &str =
    "WSLc runtimeConfig.networkProxy requires bridged networking; a proxy cannot create a route \
     in an isolated container";
const ERR_UI_POLICY: &str =
    "WSLc: the ui section is not supported. The backend has no mechanism to enforce UI \
     restrictions on a container, so no ui posture is truthful here. Omitting the ui section is \
     accepted but applies no restriction — it is not the lockdown the schema's default implies. \
     Use a backend that enforces UI policy if you need one";
const ERR_PROXY_CREDENTIALS_IN_ARGV: &str =
    "WSLc: runtimeConfig.networkProxy must not carry credentials when \
     process.env is supplied without process.inheritDefaultEnv. That combination replaces the \
     container image's environment, which WSLc performs by prefixing the command line with \
     'env -i NAME=VALUE', so the proxy URL becomes a process argument readable through \
     /proc/<pid>/cmdline for the lifetime of the command. Set process.inheritDefaultEnv to keep \
     the URL out of the command line, use a proxy that needs no inline credentials, or supply \
     them to the proxy itself";

/// WSLc enforces these axes only as a single all-or-nothing networking mode.
/// `validate_directional_network` rejects every independently filtered posture.
pub(crate) fn network_policy_support() -> NetworkPolicySupport {
    NetworkPolicySupport::EGRESS_DEFAULT
        | NetworkPolicySupport::INGRESS_DEFAULT
        | NetworkPolicySupport::HOST_LOOPBACK
        | NetworkPolicySupport::RUNTIME_PROXY
}

/// Create-and-run also filters egress rules through the built-in proxy.
pub(crate) fn create_and_run_network_policy_support() -> NetworkPolicySupport {
    network_policy_support() | NetworkPolicySupport::EGRESS_RULES
}

/// How a create-and-run container is networked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NetworkMode {
    /// No network at all.
    None,
    /// The session's NAT network, unfiltered.
    Bridged,
    /// An internal network whose only way out is the built-in proxy.
    Proxied(ProxiedEgress),
}

/// Egress filtering for [`NetworkMode::Proxied`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxiedEgress {
    pub(crate) egress: gateway::Egress,
    /// Deny entries the proxy has nothing to apply to.
    pub(crate) warnings: Vec<String>,
}

/// Choose how a create-and-run container is networked, rejecting what the
/// chosen mode cannot enforce. `field_path` names the port mappings list.
pub(crate) fn create_and_run_network_mode(
    request: &ExecutionRequest,
    field_path: &str,
    has_port_mappings: bool,
) -> Result<NetworkMode, MxcError> {
    let egress = request.policy.network_egress.clone().unwrap_or_default();
    let ingress = request.policy.network_ingress.clone().unwrap_or_default();
    let proxy = request.policy.network_proxy.is_enabled();

    // Nothing reaches a container with no network, so ingress and deny
    // rules are already enforced.
    if egress.default == NetworkAction::Deny
        && egress.allow.is_empty()
        && ingress.host_loopback == NetworkAction::Deny
    {
        if proxy {
            return Err(MxcError::policy_validation(ERR_PROXY_WITHOUT_ROUTE));
        }
        reject_port_mappings_without_bridged_network(request, field_path, has_port_mappings)?;
        return Ok(NetworkMode::None);
    }
    if egress.default == NetworkAction::Allow
        && egress.allow.is_empty()
        && egress.deny.is_empty()
        && ingress.default == NetworkAction::Allow
        && ingress.host_loopback == NetworkAction::Allow
    {
        return Ok(NetworkMode::Bridged);
    }

    if has_port_mappings {
        return Err(MxcError::policy_validation(format!(
            "WSLc: {field_path} cannot be combined with egress filtering by the built-in proxy. \
             Remove the port mappings, or use bridged networking: network.egress.default, \
             network.ingress.default and network.ingress.hostLoopback all 'allow', with no \
             egress rules"
        )));
    }
    if ingress.host_loopback == NetworkAction::Allow {
        return Err(MxcError::policy_validation(
            "WSLc: network.ingress.hostLoopback 'allow' cannot be combined with egress filtering \
             by the built-in proxy. Set it to 'deny', or use bridged networking",
        ));
    }
    if proxy {
        return Err(MxcError::policy_validation(
            "WSLc: runtimeConfig.networkProxy cannot be combined with egress filtering by the \
             built-in proxy. Remove the proxy, or use bridged networking",
        ));
    }
    proxied_egress(&egress).map(NetworkMode::Proxied)
}

/// Lower egress rules to the proxy's TCP-only rules.
fn proxied_egress(egress: &NetworkEgressPolicy) -> Result<ProxiedEgress, MxcError> {
    let mut allow = Vec::with_capacity(egress.allow.len());
    for rule in &egress.allow {
        if rule.ports.is_empty() {
            return Err(MxcError::policy_validation(
                "WSLc: network.egress.allow supports only protocol 'tcp', and an entry without \
                 ports allows every protocol; the built-in proxy carries TCP only. Use \"ports\": \
                 [{\"protocol\": \"tcp\"}] to allow every TCP port",
            ));
        }
        if let Some(port) = rule
            .ports
            .iter()
            .find(|p| p.protocol != NetworkProtocol::Tcp)
        {
            return Err(MxcError::policy_validation(format!(
                "WSLc: network.egress.allow supports only protocol 'tcp' (got '{}'); the \
                 built-in proxy carries TCP only",
                protocol_name(port.protocol)
            )));
        }
        let to = targets(&rule.to)?;
        if let Some(target) = to
            .iter()
            .find(|t| gateway::GATEWAY_SUBNETS.contains_network(&t.cidr))
        {
            return Err(MxcError::policy_validation(format!(
                "WSLc: network.egress.allow target {} is inside {}, which the built-in proxy \
                 reserves for its own networks",
                target.cidr,
                gateway::GATEWAY_SUBNETS
            )));
        }
        allow.push(gateway::Rule {
            to,
            ports: port_ranges(&rule.ports)?,
        });
    }

    let mut deny = Vec::with_capacity(egress.deny.len());
    let mut warnings = Vec::new();
    for rule in &egress.deny {
        let to = targets(&rule.to)?;
        let (tcp, other): (Vec<NetworkPort>, Vec<NetworkPort>) = rule
            .ports
            .iter()
            .cloned()
            .partition(|p| matches!(p.protocol, NetworkProtocol::Tcp | NetworkProtocol::Any));
        for port in &other {
            warnings.push(format!(
                "network.egress.deny entry for '{}' has no effect: the built-in proxy carries \
                 TCP only",
                protocol_name(port.protocol)
            ));
        }
        if !rule.ports.is_empty() && tcp.is_empty() {
            continue;
        }
        deny.push(gateway::Rule {
            to,
            ports: port_ranges(&tcp)?,
        });
    }

    Ok(ProxiedEgress {
        egress: gateway::Egress {
            default: match egress.default {
                NetworkAction::Allow => gateway::Action::Allow,
                NetworkAction::Deny => gateway::Action::Deny,
            },
            allow,
            deny,
        },
        warnings,
    })
}

fn protocol_name(protocol: NetworkProtocol) -> &'static str {
    match protocol {
        NetworkProtocol::Tcp => "tcp",
        NetworkProtocol::Udp => "udp",
        NetworkProtocol::Icmp => "icmp",
        NetworkProtocol::Any => "any",
    }
}

/// An empty `to` matches every IPv4 destination.
fn targets(to: &[NetworkPeer]) -> Result<Vec<gateway::Target>, MxcError> {
    if to.is_empty() {
        return Ok(vec![gateway::Target {
            cidr: gateway::Cidr::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
            except: Vec::new(),
        }]);
    }
    to.iter()
        .map(|peer| {
            Ok(gateway::Target {
                cidr: ipv4_cidr(&peer.cidr)?,
                except: peer
                    .except
                    .iter()
                    .map(ipv4_cidr)
                    .collect::<Result<_, _>>()?,
            })
        })
        .collect()
}

fn ipv4_cidr(cidr: &NetworkCidr) -> Result<gateway::Cidr, MxcError> {
    match cidr.address {
        IpAddr::V4(address) if cidr.prefix_length <= 32 => {
            Ok(gateway::Cidr::new(address, cidr.prefix_length))
        }
        IpAddr::V4(address) => Err(MxcError::policy_validation(format!(
            "WSLc: network.egress CIDR {address}/{} has an invalid prefix length",
            cidr.prefix_length
        ))),
        IpAddr::V6(address) => Err(MxcError::policy_validation(format!(
            "WSLc: network.egress CIDR {address}/{} is IPv6; the built-in proxy supports IPv4 \
             only",
            cidr.prefix_length
        ))),
    }
}

/// TCP port ranges; `None` matches every port.
fn port_ranges(ports: &[NetworkPort]) -> Result<Option<Vec<gateway::PortRange>>, MxcError> {
    let mut ranges = Vec::with_capacity(ports.len());
    let mut every_port = ports.is_empty();
    for port in ports {
        match (port.port, port.end_port) {
            (Some(0), _) | (_, Some(0)) => {
                return Err(MxcError::policy_validation(
                    "WSLc: network.egress port values must be between 1 and 65535",
                ));
            }
            (None, Some(end)) => {
                return Err(MxcError::policy_validation(format!(
                    "WSLc: network.egress endPort {end} needs a matching port"
                )));
            }
            (Some(start), Some(end)) if end < start => {
                return Err(MxcError::policy_validation(format!(
                    "WSLc: network.egress port range {start}-{end} ends before it starts"
                )));
            }
            (Some(start), end) => ranges.push(gateway::PortRange {
                start,
                end: end.unwrap_or(start),
            }),
            (None, None) => every_port = true,
        }
    }
    Ok((!every_port).then_some(ranges))
}

/// Read the directional posture; absent egress defaults to deny.
pub(crate) fn network_is_isolated(request: &ExecutionRequest) -> bool {
    request
        .policy
        .network_egress
        .as_ref()
        .is_none_or(|egress| egress.default == NetworkAction::Deny)
}

/// Reject port mappings that isolated networking cannot carry. `field_path`
/// names the list in the caller's own request shape.
///
/// WslcCreateContainer fails with E_INVALIDARG when port mappings accompany
/// isolated networking.
pub(crate) fn reject_port_mappings_without_bridged_network(
    request: &ExecutionRequest,
    field_path: &str,
    has_port_mappings: bool,
) -> Result<(), MxcError> {
    if has_port_mappings && network_is_isolated(request) {
        return Err(MxcError::policy_validation(format!(
            "WSLc: {field_path} requires bridged networking. Set network.egress.default, \
             network.ingress.default and network.ingress.hostLoopback all to 'allow', or remove \
             the port mappings"
        )));
    }
    Ok(())
}

/// No firewall is installed inside or outside a WSLc container. NONE denies all
/// connectivity; BRIDGED cannot promise either inbound or host-loopback filtering.
pub(crate) fn validate_directional_network(request: &ExecutionRequest) -> Result<(), MxcError> {
    let policy = &request.policy;
    if policy
        .network_egress
        .as_ref()
        .is_some_and(|egress| !egress.allow.is_empty() || !egress.deny.is_empty())
    {
        return Err(MxcError::policy_validation(
            "WSLc does not support network.egress allow/deny rules; networking is all-or-nothing",
        ));
    }
    let isolated = network_is_isolated(request);
    let action = if isolated {
        NetworkAction::Deny
    } else {
        NetworkAction::Allow
    };
    let ingress = policy.network_ingress.clone().unwrap_or_default();
    if ingress.default != action || ingress.host_loopback != action {
        return Err(MxcError::policy_validation(
            "WSLc cannot filter ingress or host-loopback independently: isolated networking \
             requires network.egress.default, network.ingress.default and \
             network.ingress.hostLoopback all 'deny'; bridged networking requires all 'allow'",
        ));
    }
    if isolated && policy.network_proxy.is_enabled() {
        return Err(MxcError::policy_validation(ERR_PROXY_WITHOUT_ROUTE));
    }
    Ok(())
}

/// The daemon's provision proxy check; requests that skip
/// [`validate_provision_policy`] reach the daemon directly.
pub fn check_provision_proxy(network_proxy: Option<&str>) -> Result<(), &'static str> {
    match network_proxy {
        Some(_) => Err(ERR_PROXY_AT_PROVISION),
        None => Ok(()),
    }
}

/// Validate the request for the provision phase. `rw` / `ro` paths become
/// volume mounts and `network.egress.default` selects the container network
/// mode; both are honoured here. Everything else in the module table is
/// rejected.
pub(crate) fn validate_provision_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    if !request.policy.enumerate_paths.is_empty() {
        return Err(MxcError::policy_validation(ERR_ENUMERATE_PATHS));
    }
    validate_denied_path_overlap(
        &request.policy.readwrite_paths,
        &request.policy.readonly_paths,
        &request.policy.denied_paths,
    )
    .map_err(MxcError::policy_validation)?;
    reject_ui_policy(request)?;
    // Only proxied containers hold a provision proxy; bridged ones set it per exec.
    if request.policy.network_proxy.is_enabled() {
        return Err(MxcError::policy_validation(ERR_PROXY_AT_PROVISION));
    }
    validate_directional_network(request)?;
    Ok(())
}

/// Validate the request for start / stop / deprovision. These phases carry no
/// applicable policy: filesystem and network mode are fixed at provision and
/// the proxy is an exec-time concern. A UI policy is never supported.
pub(crate) fn validate_post_provision_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    reject_filesystem_policy(request)?;
    reject_ui_policy(request)?;
    reject_post_provision_network_mode(request)?;
    if request.policy.network_proxy.is_enabled() {
        return Err(MxcError::policy_validation(ERR_PROXY_AT_PHASE));
    }
    Ok(())
}

/// Validate the request for the exec phase. Filesystem, network mode and `ui`
/// are rejected; the cooperative proxy is honoured and must be in `url` form so
/// a routable value reaches the container.
pub(crate) fn validate_exec_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    reject_filesystem_policy(request)?;
    reject_ui_policy(request)?;
    reject_post_provision_network_mode(request)?;
    reject_non_url_proxy(request)?;
    reject_proxy_credentials_in_argv(request)?;
    Ok(())
}

/// The proxy must be a URL so a routable value reaches the container.
fn reject_non_url_proxy(request: &ExecutionRequest) -> Result<(), MxcError> {
    if !request.policy.network_proxy.is_enabled() {
        return Ok(());
    }
    let url =
        exec_proxy_url(request).ok_or_else(|| MxcError::policy_validation(ERR_PROXY_URL_FORM))?;
    check_proxy_url_len(url).map_err(MxcError::policy_validation)
}

/// Upper bound on a proxy URL. The daemon copies it into several environment
/// variables after the IPC frame-size check, so this bounds that expansion.
const MAX_PROXY_URL_BYTES: usize = 8192;

fn check_proxy_url_len(url: &str) -> Result<(), &'static str> {
    if url.len() > MAX_PROXY_URL_BYTES {
        return Err(ERR_PROXY_URL_TOO_LONG);
    }
    Ok(())
}

/// Refuse a credential-bearing proxy URL for a request that replaces the image
/// environment.
///
/// [`EnvScope::Replace`] carries every entry as a command-line argument, and
/// `apply_cooperative_proxy_env` puts the configured URL among them, so the
/// credential would be readable through `/proc/<pid>/cmdline` while the command
/// runs. The other scopes leave the entries with the SDK's environment setter,
/// which argv never sees.
pub(crate) fn reject_proxy_credentials_in_argv(request: &ExecutionRequest) -> Result<(), MxcError> {
    match exec_proxy_url(request) {
        Some(url) if exposes_proxy_credentials(EnvScope::of(request), url) => {
            Err(MxcError::policy_validation(ERR_PROXY_CREDENTIALS_IN_ARGV))
        }
        _ => Ok(()),
    }
}

fn exposes_proxy_credentials(scope: EnvScope, url: &str) -> bool {
    scope == EnvScope::Replace && crate::mxc_common::proxy_env::proxy_url_has_credentials(url)
}

/// The proxy URL an exec runs under: its own, or the one a proxied container
/// was provisioned with when it names none. The daemon calls this because only
/// it holds the provisioned URL; the error is a rejection message that never
/// repeats either URL.
pub fn resolve_exec_proxy<'a>(
    provisioned: Option<&'a str>,
    requested: Option<&'a str>,
    scope: EnvScope,
) -> Result<Option<&'a str>, &'static str> {
    if provisioned.is_some() && requested.is_some() && provisioned != requested {
        return Err(ERR_PROXY_MISMATCH);
    }
    let url = requested.or(provisioned);
    if let Some(url) = url {
        check_proxy_url_len(url)?;
        if exposes_proxy_credentials(scope, url) {
            return Err(ERR_PROXY_CREDENTIALS_IN_ARGV);
        }
    }
    Ok(url)
}

/// The routable proxy URL to inject at exec, or `None` when the proxy is
/// disabled or specified without an original URL.
/// Borrows from the request so presence validation does not allocate.
pub(crate) fn exec_proxy_url(request: &ExecutionRequest) -> Option<&str> {
    if !request.policy.network_proxy.is_enabled() {
        return None;
    }
    request
        .policy
        .network_proxy
        .address
        .as_ref()
        .and_then(|addr| addr.original_url.as_deref())
}

fn reject_filesystem_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    if !request.policy.readwrite_paths.is_empty()
        || !request.policy.readonly_paths.is_empty()
        || !request.policy.enumerate_paths.is_empty()
        || !request.policy.denied_paths.is_empty()
    {
        return Err(MxcError::policy_validation(ERR_FILESYSTEM_IMMUTABLE));
    }
    Ok(())
}

/// Reject any supplied UI policy: WSLc cannot enforce UI restrictions.
pub(crate) fn reject_ui_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    if request.policy.ui_specified {
        return Err(MxcError::policy_validation(ERR_UI_POLICY));
    }
    Ok(())
}

/// Reject any network *mode* field supplied after provision: the posture is
/// bound to the provision phase. Presence, not value — an explicit
/// `egress.default: "deny"` must still be rejected.
/// The cooperative proxy is a separate exec-time concern handled by the callers.
fn reject_post_provision_network_mode(request: &ExecutionRequest) -> Result<(), MxcError> {
    if request.policy.network_mode_specified
        || request.policy.network_egress.is_some()
        || request.policy.network_ingress.is_some()
    {
        return Err(MxcError::policy_validation(ERR_NETWORK_IMMUTABLE));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{
        ContainerPolicy, NetworkEgressPolicy, NetworkIngressPolicy, ProxyAddress, ProxyConfig,
        UiPolicy,
    };
    use crate::mxc_common::mxc_error::MxcErrorCode;

    fn request_with_policy(policy: ContainerPolicy) -> ExecutionRequest {
        ExecutionRequest {
            policy,
            ..Default::default()
        }
    }

    fn url_proxy() -> ProxyConfig {
        ProxyConfig {
            address: Some(ProxyAddress::from_url(
                "http://127.0.0.1:8888",
                "127.0.0.1".to_string(),
                8888,
            )),
        }
    }

    fn non_url_proxy() -> ProxyConfig {
        ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8888)),
        }
    }

    fn credential_proxy() -> ProxyConfig {
        ProxyConfig {
            address: Some(ProxyAddress::from_url(
                "http://alice:hunter2@proxy.example:8080",
                "proxy.example".to_string(),
                8080,
            )),
        }
    }

    fn credential_proxy_request(
        env: Option<Vec<&str>>,
        inherit_default_env: bool,
    ) -> ExecutionRequest {
        ExecutionRequest {
            policy: ContainerPolicy {
                network_proxy: credential_proxy(),
                ..Default::default()
            },
            env: env.map(|e| e.into_iter().map(String::from).collect()),
            inherit_default_env,
            ..Default::default()
        }
    }

    fn assert_policy_validation(err: MxcError, needle: &str) {
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
        assert!(
            err.message.contains(needle),
            "expected {:?} in {:?}",
            needle,
            err.message
        );
    }

    fn parsed(source: &str) -> ExecutionRequest {
        let request = crate::mxc_common::config_parser::load_mxc_request_from_json(
            source,
            &mut crate::mxc_common::logger::Logger::new(crate::mxc_common::logger::Mode::Buffer),
        )
        .unwrap();
        match request {
            crate::mxc_common::state_aware_request::MxcRequest::OneShot(request) => request,
            crate::mxc_common::state_aware_request::MxcRequest::StateAware(request) => {
                request.into_request()
            }
        }
    }

    #[test]
    fn directional_networking_accepts_only_truthful_all_or_nothing_postures() {
        for egress in ["allow", "deny"] {
            for ingress in ["allow", "deny"] {
                for loopback in ["allow", "deny"] {
                    let source = format!(
                        r#"{{"version":"0.9.0-alpha","phase":"provision","containment":"wslc","network":{{"egress":{{"default":"{egress}"}},"ingress":{{"default":"{ingress}","hostLoopback":"{loopback}"}}}}}}"#
                    );
                    let request = parsed(&source);
                    assert_eq!(network_is_isolated(&request), egress == "deny");
                    assert_eq!(
                        validate_provision_policy(&request).is_ok(),
                        egress == ingress && ingress == loopback,
                        "{source}"
                    );
                }
            }
        }
        let defaults =
            parsed(r#"{"version":"0.9.0-alpha","phase":"provision","containment":"wslc"}"#);
        assert!(network_is_isolated(&defaults));
        validate_provision_policy(&defaults).unwrap();
    }

    #[test]
    fn provision_rejects_enumerate_paths() {
        let request = request_with_policy(ContainerPolicy {
            enumerate_paths: vec!["C:\\tools".to_string()],
            ..Default::default()
        });

        assert_policy_validation(
            validate_provision_policy(&request).unwrap_err(),
            ERR_ENUMERATE_PATHS,
        );
    }

    #[test]
    fn runtime_proxy_only_exec_inherits_mode_and_retains_guest_routable_url() {
        let request = parsed(
            r#"{"version":"0.9.0-alpha","phase":"exec","sandboxId":"wslc:0123456789abcdef0123456789abcdef","process":{"commandLine":"echo"},"runtimeConfig":{"networkProxy":"http://proxy.example:8080"}}"#,
        );
        assert!(!request.policy.network_specified);
        assert!(!request.policy.network_mode_specified);
        assert!(request.policy.runtime_network_proxy_specified);
        assert!(request.policy.network_egress.is_none());
        assert!(request.policy.network_ingress.is_none());
        crate::mxc_common::validator::validate_state_aware_network_policy_support(
            &request,
            network_policy_support(),
        )
        .unwrap();
        validate_exec_policy(&request).unwrap();
        assert_eq!(exec_proxy_url(&request), Some("http://proxy.example:8080"));

        for network in [r#"{}"#, r#"{"egress":{"default":"deny"}}"#] {
            let source = format!(
                r#"{{"version":"0.9.0-alpha","phase":"exec","sandboxId":"wslc:0123456789abcdef0123456789abcdef","process":{{"commandLine":"echo"}},"network":{network},"runtimeConfig":{{"networkProxy":"http://proxy.example:8080"}}}}"#
            );
            assert_policy_validation(
                validate_exec_policy(&parsed(&source)).unwrap_err(),
                "network mode",
            );
        }
    }

    #[test]
    fn one_shot_runtime_proxy_requires_a_real_route_not_a_proxy_only_firewall_promise() {
        let bridged = parsed(
            r#"{"version":"0.9.0-alpha","containment":"wslc","process":{"commandLine":"echo"},"network":{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}},"runtimeConfig":{"networkProxy":"http://proxy.example:8080"}}"#,
        );
        validate_directional_network(&bridged).unwrap();
        assert_eq!(exec_proxy_url(&bridged), Some("http://proxy.example:8080"));
        let isolated = parsed(
            r#"{"version":"0.9.0-alpha","containment":"wslc","process":{"commandLine":"echo"},"runtimeConfig":{"networkProxy":"http://proxy.example:8080"}}"#,
        );
        assert_policy_validation(
            validate_directional_network(&isolated).unwrap_err(),
            "requires bridged networking",
        );
    }

    #[test]
    fn directional_rules_and_proxy_peer_identity_are_not_advertised_or_ignored() {
        assert!(!network_policy_support().contains(NetworkPolicySupport::EGRESS_RULES));
        assert!(!network_policy_support().contains(NetworkPolicySupport::PROXY_PEER_IDENTITY));
        for action in ["allow", "deny"] {
            let source = format!(
                r#"{{"version":"0.9.0-alpha","phase":"provision","containment":"wslc","network":{{"egress":{{"{action}":[{{"to":[{{"cidr":"192.0.2.0/24"}}]}}]}}}}}}"#
            );
            assert_policy_validation(
                validate_provision_policy(&parsed(&source)).unwrap_err(),
                "allow/deny rules",
            );
        }
    }

    // ---- provision ----

    #[test]
    fn provision_accepts_rw_ro_and_network_mode() {
        let req = request_with_policy(ContainerPolicy {
            readwrite_paths: vec!["C:\\src".to_string()],
            readonly_paths: vec!["C:\\data".to_string()],
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            }),
            network_ingress: Some(NetworkIngressPolicy {
                default: NetworkAction::Allow,
                host_loopback: NetworkAction::Allow,
            }),
            ..Default::default()
        });
        validate_provision_policy(&req).unwrap();
    }

    #[test]
    fn provision_accepts_standalone_denied_path() {
        let req = request_with_policy(ContainerPolicy {
            readwrite_paths: vec!["C:\\src".to_string()],
            denied_paths: vec!["D:\\secrets".to_string()],
            ..Default::default()
        });
        validate_provision_policy(&req).unwrap();
    }

    #[test]
    fn provision_rejects_denied_nested_under_mount() {
        let req = request_with_policy(ContainerPolicy {
            readwrite_paths: vec!["C:\\src".to_string()],
            denied_paths: vec!["C:\\src\\secret".to_string()],
            ..Default::default()
        });
        assert_policy_validation(validate_provision_policy(&req).unwrap_err(), "deniedPaths");
    }

    #[test]
    fn provision_rejects_proxy_in_bridged_and_isolated_containers() {
        for network in [
            r#""network":{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}},"#,
            "",
        ] {
            let req = parsed(&format!(
                r#"{{"version":"1.1.0-alpha","phase":"provision","containment":"wslc",{network}"runtimeConfig":{{"networkProxy":"http://proxy.example:8080"}}}}"#
            ));
            assert_policy_validation(validate_provision_policy(&req).unwrap_err(), "exec phase");
        }
    }

    #[test]
    fn a_proxy_url_longer_than_the_limit_is_rejected() {
        let at_limit = format!(
            "http://p.example:8080/{}",
            "a".repeat(MAX_PROXY_URL_BYTES - 22)
        );
        assert_eq!(at_limit.len(), MAX_PROXY_URL_BYTES);
        let over_limit = format!("{at_limit}a");
        assert_eq!(
            resolve_exec_proxy(None, Some(&at_limit), EnvScope::Merge),
            Ok(Some(at_limit.as_str()))
        );
        assert_eq!(
            resolve_exec_proxy(None, Some(&over_limit), EnvScope::Merge),
            Err(ERR_PROXY_URL_TOO_LONG)
        );
        assert_eq!(
            resolve_exec_proxy(Some(&over_limit), None, EnvScope::Merge),
            Err(ERR_PROXY_URL_TOO_LONG)
        );

        let exec = |url: &str| {
            parsed(&format!(
                r#"{{"version":"0.9.0-alpha","phase":"exec","sandboxId":"wslc:0123456789abcdef0123456789abcdef","process":{{"commandLine":"echo"}},"runtimeConfig":{{"networkProxy":"{url}"}}}}"#
            ))
        };
        validate_exec_policy(&exec(&at_limit)).unwrap();
        assert_policy_validation(
            validate_exec_policy(&exec(&over_limit)).unwrap_err(),
            "8192 bytes",
        );
    }

    #[test]
    fn an_exec_runs_under_its_own_or_the_provisioned_proxy_but_not_a_different_one() {
        let provisioned = Some("http://proxy.example:8080");
        for requested in [None, provisioned] {
            assert_eq!(
                resolve_exec_proxy(provisioned, requested, EnvScope::Merge),
                Ok(provisioned)
            );
        }
        assert_eq!(
            resolve_exec_proxy(None, provisioned, EnvScope::Merge),
            Ok(provisioned)
        );
        assert_eq!(
            resolve_exec_proxy(
                provisioned,
                Some("http://other.example:8080"),
                EnvScope::Merge
            ),
            Err(ERR_PROXY_MISMATCH)
        );
    }

    #[test]
    fn a_replaced_environment_refuses_a_credential_bearing_provisioned_proxy() {
        let url = credential_proxy().address.unwrap().original_url.unwrap();
        assert_eq!(
            resolve_exec_proxy(Some(&url), None, EnvScope::Replace),
            Err(ERR_PROXY_CREDENTIALS_IN_ARGV)
        );
        assert_eq!(
            resolve_exec_proxy(Some(&url), None, EnvScope::Merge),
            Ok(Some(url.as_str()))
        );
    }

    // ---- post-provision (start / stop / deprovision) ----

    #[test]
    fn post_provision_accepts_empty_policy() {
        validate_post_provision_policy(&ExecutionRequest::default()).unwrap();
    }

    #[test]
    fn post_provision_rejects_filesystem() {
        let req = request_with_policy(ContainerPolicy {
            readwrite_paths: vec!["C:\\src".to_string()],
            ..Default::default()
        });
        assert_policy_validation(
            validate_post_provision_policy(&req).unwrap_err(),
            "provision phase",
        );
    }

    #[test]
    fn post_provision_rejects_network_mode_by_presence() {
        // Even an explicit directional deny (equal to the default) must be
        // rejected post-provision: presence, not value, is what matters.
        let req = request_with_policy(ContainerPolicy {
            network_mode_specified: true,
            ..Default::default()
        });
        assert_policy_validation(
            validate_post_provision_policy(&req).unwrap_err(),
            "network mode",
        );
    }

    #[test]
    fn post_provision_rejects_proxy() {
        let req = request_with_policy(ContainerPolicy {
            network_proxy: url_proxy(),
            ..Default::default()
        });
        assert_policy_validation(
            validate_post_provision_policy(&req).unwrap_err(),
            "exec phase",
        );
    }

    // ---- exec ----

    #[test]
    fn exec_accepts_url_proxy() {
        let req = request_with_policy(ContainerPolicy {
            network_proxy: url_proxy(),
            ..Default::default()
        });
        validate_exec_policy(&req).unwrap();
        assert_eq!(exec_proxy_url(&req), Some("http://127.0.0.1:8888"));
    }

    #[test]
    fn exec_rejects_non_url_proxy() {
        let req = request_with_policy(ContainerPolicy {
            network_proxy: non_url_proxy(),
            ..Default::default()
        });
        assert_policy_validation(validate_exec_policy(&req).unwrap_err(), "url");
        assert!(exec_proxy_url(&req).is_none());
    }

    #[test]
    fn exec_rejects_filesystem() {
        let req = request_with_policy(ContainerPolicy {
            readonly_paths: vec!["C:\\data".to_string()],
            ..Default::default()
        });
        assert_policy_validation(validate_exec_policy(&req).unwrap_err(), "provision phase");
    }

    #[test]
    fn exec_rejects_network_mode_by_presence() {
        let req = request_with_policy(ContainerPolicy {
            network_mode_specified: true,
            ..Default::default()
        });
        assert_policy_validation(validate_exec_policy(&req).unwrap_err(), "network mode");
    }

    #[test]
    fn exec_accepts_proxy_only_network_block() {
        // A proxy-only network block sets `network_specified` but not
        // `network_mode_specified`, so exec still honours the cooperative proxy.
        let req = request_with_policy(ContainerPolicy {
            network_specified: true,
            network_proxy: url_proxy(),
            ..Default::default()
        });
        validate_exec_policy(&req).unwrap();
        assert_eq!(exec_proxy_url(&req), Some("http://127.0.0.1:8888"));
    }

    #[test]
    fn exec_accepts_empty_policy() {
        validate_exec_policy(&ExecutionRequest::default()).unwrap();
        assert!(exec_proxy_url(&ExecutionRequest::default()).is_none());
    }

    // ---- ui (rejected on every phase) ----

    #[test]
    fn every_phase_rejects_supplied_ui() {
        let req = request_with_policy(ContainerPolicy {
            ui_specified: true,
            ..Default::default()
        });
        for (phase, result) in [
            ("provision", validate_provision_policy(&req)),
            ("post_provision", validate_post_provision_policy(&req)),
            ("exec", validate_exec_policy(&req)),
        ] {
            let err = result.expect_err(&format!("{phase} must reject a supplied ui"));
            assert_policy_validation(err, "ui section is not supported");
        }
    }

    /// A value-based check would let the most restrictive request a caller can
    /// write through unenforced, since that is also the default.
    #[test]
    fn provision_rejects_lockdown_equivalent_ui() {
        let req = request_with_policy(ContainerPolicy {
            ui: UiPolicy::default(),
            ui_specified: true,
            ..Default::default()
        });
        assert_policy_validation(
            validate_provision_policy(&req).unwrap_err(),
            "ui section is not supported",
        );
    }

    #[test]
    fn absent_ui_is_accepted_on_every_phase() {
        let req = ExecutionRequest::default();
        assert!(!req.policy.ui_specified);
        validate_provision_policy(&req).unwrap();
        validate_post_provision_policy(&req).unwrap();
        validate_exec_policy(&req).unwrap();
    }

    // ---- rejection ordering ----
    //
    // filesystem -> ui -> network. Pinned so reordering the validator bodies is
    // caught.

    #[test]
    fn filesystem_error_takes_precedence_over_ui() {
        let req = request_with_policy(ContainerPolicy {
            readwrite_paths: vec!["C:\\src".to_string()],
            ui_specified: true,
            ..Default::default()
        });
        assert_policy_validation(
            validate_post_provision_policy(&req).unwrap_err(),
            "provision phase",
        );
        assert_policy_validation(validate_exec_policy(&req).unwrap_err(), "provision phase");
    }

    #[test]
    fn ui_error_takes_precedence_over_network() {
        let req = request_with_policy(ContainerPolicy {
            ui_specified: true,
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                allow: vec![Default::default()],
                ..Default::default()
            }),
            network_proxy: url_proxy(),
            ..Default::default()
        });
        for (phase, result) in [
            ("provision", validate_provision_policy(&req)),
            ("post_provision", validate_post_provision_policy(&req)),
            ("exec", validate_exec_policy(&req)),
        ] {
            let err = result.expect_err(&format!("{phase} must reject"));
            assert_policy_validation(err, "ui section is not supported");
        }
    }

    #[test]
    fn every_new_rejection_maps_to_policy_validation() {
        let cases = [
            ContainerPolicy {
                ui_specified: true,
                ..Default::default()
            },
            ContainerPolicy {
                network_egress: Some(NetworkEgressPolicy {
                    default: NetworkAction::Allow,
                    allow: vec![Default::default()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];
        for policy in cases {
            let err = validate_provision_policy(&request_with_policy(policy)).unwrap_err();
            assert_eq!(err.code, MxcErrorCode::PolicyValidation);
        }
    }

    #[test]
    fn a_replaced_environment_refuses_a_credential_bearing_proxy_url() {
        let request = credential_proxy_request(Some(vec!["FOO=bar"]), false);

        let err = reject_proxy_credentials_in_argv(&request).unwrap_err();
        assert_policy_validation(err.clone(), "must not carry credentials");
        assert!(
            !err.message.contains("hunter2"),
            "the rejection must not repeat the password: {:?}",
            err.message
        );
    }

    #[test]
    fn an_environment_the_sdk_applies_accepts_a_credential_bearing_proxy_url() {
        // These reach the container through the SDK's environment setter, which
        // never puts a value on the command line.
        for (env, inherit_default_env) in [
            (None, false),
            (None, true),
            (Some(vec!["FOO=bar"]), true),
            (Some(vec![]), true),
        ] {
            let request = credential_proxy_request(env, inherit_default_env);
            assert!(reject_proxy_credentials_in_argv(&request).is_ok());
        }
    }

    #[test]
    fn a_replaced_environment_accepts_a_proxy_url_without_credentials() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                network_proxy: url_proxy(),
                ..Default::default()
            },
            env: Some(vec!["FOO=bar".to_string()]),
            ..Default::default()
        };

        assert!(reject_proxy_credentials_in_argv(&request).is_ok());
    }

    #[test]
    fn the_exec_phase_refuses_a_credential_bearing_proxy_url_in_a_replaced_environment() {
        let request = credential_proxy_request(Some(vec!["FOO=bar"]), false);

        assert_policy_validation(
            validate_exec_policy(&request).unwrap_err(),
            "must not carry credentials",
        );
    }

    // ---- create-and-run network modes ----

    fn one_shot(network: &str) -> ExecutionRequest {
        parsed(&format!(
            r#"{{"version":"0.9.0-alpha","containment":"wslc","process":{{"commandLine":"echo"}},"network":{network}}}"#
        ))
    }

    fn mode(network: &str) -> Result<NetworkMode, MxcError> {
        create_and_run_network_mode(&one_shot(network), "wslc.portMappings", false)
    }

    fn proxied(network: &str) -> ProxiedEgress {
        match mode(network).unwrap() {
            NetworkMode::Proxied(proxied) => proxied,
            other => panic!("{network} gave {other:?}"),
        }
    }

    #[test]
    fn create_and_run_uses_the_proxy_only_for_postures_the_sdk_cannot_express() {
        assert_eq!(mode("{}").unwrap(), NetworkMode::None);
        assert_eq!(
            mode(
                r#"{"egress":{"deny":[{"to":[{"cidr":"10.0.0.0/8"}]}]},"ingress":{"default":"allow"}}"#
            )
            .unwrap(),
            NetworkMode::None
        );
        assert_eq!(
            mode(r#"{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}}"#)
                .unwrap(),
            NetworkMode::Bridged
        );

        let open = proxied(r#"{"egress":{"default":"allow"},"ingress":{"default":"allow"}}"#);
        assert_eq!(open.egress.default, gateway::Action::Allow);
        assert!(open.egress.allow.is_empty() && open.egress.deny.is_empty());

        let filtered = proxied(
            r#"{"egress":{"allow":[{"to":[{"cidr":"192.0.2.0/24","except":["192.0.2.8/29"]}],"ports":[{"protocol":"tcp","port":8000,"endPort":8010},{"protocol":"tcp","port":443}]}]}}"#,
        );
        assert_eq!(filtered.egress.default, gateway::Action::Deny);
        assert_eq!(
            filtered.egress.allow,
            vec![gateway::Rule {
                to: vec![gateway::Target {
                    cidr: "192.0.2.0/24".parse().unwrap(),
                    except: vec!["192.0.2.8/29".parse().unwrap()],
                }],
                ports: Some(vec![
                    gateway::PortRange {
                        start: 8000,
                        end: 8010
                    },
                    gateway::PortRange {
                        start: 443,
                        end: 443
                    },
                ]),
            }]
        );
        assert!(
            create_and_run_network_policy_support().contains(NetworkPolicySupport::EGRESS_RULES)
        );
    }

    #[test]
    fn the_proxy_rejects_what_it_cannot_enforce() {
        let rule = r#"{"egress":{"allow":[{"to":[{"cidr":"192.0.2.0/24"}]}]}}"#;
        assert_policy_validation(
            create_and_run_network_mode(&one_shot(rule), "wslc.portMappings", true).unwrap_err(),
            "wslc.portMappings cannot be combined",
        );
        let mut with_proxy = one_shot(rule);
        with_proxy.policy.network_proxy = url_proxy();
        assert_policy_validation(
            create_and_run_network_mode(&with_proxy, "wslc.portMappings", false).unwrap_err(),
            "runtimeConfig.networkProxy cannot be combined",
        );
        for (network, needle) in [
            (
                r#"{"egress":{"default":"allow"},"ingress":{"hostLoopback":"allow"}}"#,
                "hostLoopback 'allow' cannot be combined",
            ),
            (
                r#"{"egress":{"allow":[{"ports":[{"protocol":"udp","port":53}]}]}}"#,
                "only protocol 'tcp' (got 'udp')",
            ),
            (
                r#"{"egress":{"allow":[{"ports":[{"protocol":"any"}]}]}}"#,
                "(got 'any')",
            ),
            (
                r#"{"egress":{"allow":[{"to":[{"cidr":"192.0.2.0/24"}]}]}}"#,
                "an entry without ports allows every protocol",
            ),
            (
                r#"{"egress":{"allow":[{"to":[{"cidr":"2001:db8::/32"}],"ports":[{"protocol":"tcp"}]}]}}"#,
                "is IPv6",
            ),
            (
                r#"{"egress":{"default":"allow","deny":[{"to":[{"cidr":"::/0"}]}]}}"#,
                "is IPv6",
            ),
            (
                r#"{"egress":{"allow":[{"to":[{"cidr":"10.231.1.0/24"}],"ports":[{"protocol":"tcp"}]}]}}"#,
                "reserves for its own networks",
            ),
        ] {
            assert_policy_validation(mode(network).unwrap_err(), needle);
        }
    }

    #[test]
    fn deny_rules_keep_only_their_tcp_entries() {
        let p = proxied(
            r#"{"egress":{"default":"allow","deny":[{"ports":[{"protocol":"udp","port":53}]},{"to":[{"cidr":"10.0.0.0/8"}],"ports":[{"protocol":"icmp"},{"protocol":"any","port":22}]},{"to":[{"cidr":"10.231.0.0/16"}]}]}}"#,
        );
        assert_eq!(p.warnings.len(), 2, "{:?}", p.warnings);
        assert_eq!(
            p.egress.deny,
            vec![
                gateway::Rule {
                    to: vec![gateway::Target {
                        cidr: "10.0.0.0/8".parse().unwrap(),
                        except: vec![],
                    }],
                    ports: Some(vec![gateway::PortRange { start: 22, end: 22 }]),
                },
                gateway::Rule {
                    to: vec![gateway::Target {
                        cidr: "10.231.0.0/16".parse().unwrap(),
                        except: vec![],
                    }],
                    ports: None,
                },
            ]
        );

        let everywhere = proxied(r#"{"egress":{"allow":[{"ports":[{"protocol":"tcp"}]}]}}"#);
        assert_eq!(
            everywhere.egress.allow[0],
            gateway::Rule {
                to: vec![gateway::Target {
                    cidr: "0.0.0.0/0".parse().unwrap(),
                    except: vec![],
                }],
                ports: None,
            }
        );
    }
}
