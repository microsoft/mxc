// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Seatbelt invariants enforced by the backend's own `validate`.
//!
//! `validate` runs on every execution path -- the JSON parser and a Rust caller
//! that hands `mxc_engine::run` an `ExecutionRequest` it built itself both
//! reach it -- so one home here covers both.
//!
//! Each check returns the caller-facing message; the backend wraps it as a
//! `ScriptResponse`.

use crate::host_is_canonical_loopback;
use crate::models::{
    ContainerPolicy, ExecutionRequest, NetworkAction, NetworkEnforcementMode, NetworkPolicy,
};

pub(crate) const SYSTEM_POWER_ACCESS_VERSION_ERROR: &str =
    "seatbelt.systemPowerAccess requires schema version 0.9 or later";

/// Returns system-power capability support for a valid schema version.
///
/// `None` leaves malformed-version diagnostics to the config parser.
pub(crate) fn system_power_access_support(version: &str) -> Option<bool> {
    semver::Version::parse(version)
        .ok()
        .map(|version| version.major > 0 || version.minor >= 9)
}

/// Reject system power access when the request predates its 0.9 contract.
///
/// This validation runs at execution time so requests changed after parsing,
/// including through the Rust SDK setters, cannot bypass the version boundary.
pub fn validate_system_power_access(request: &ExecutionRequest) -> Result<(), String> {
    let enabled = request
        .seatbelt
        .as_ref()
        .is_some_and(|seatbelt| seatbelt.system_power_access);

    if enabled && !system_power_access_support(&request.schema_version).unwrap_or(false) {
        return Err(SYSTEM_POWER_ACCESS_VERSION_ERROR.to_string());
    }

    Ok(())
}

/// Effective outbound posture, preferring the directional `network.egress`
/// over the legacy `defaultPolicy` when both are present.
pub fn egress_allowed(policy: &ContainerPolicy) -> bool {
    match policy.network_egress.as_ref() {
        Some(egress) => egress.default == NetworkAction::Allow,
        None => matches!(policy.default_network_policy, NetworkPolicy::Allow),
    }
}

/// Effective inbound posture. Seatbelt maps `network.ingress.default` onto its
/// `(allow network-inbound (local ip))` rule; `hostLoopback` must match
/// `default` (checked by the backend), so it plays no part here.
pub fn local_network_allowed(policy: &ContainerPolicy) -> bool {
    match policy.network_ingress.as_ref() {
        Some(ingress) => ingress.default == NetworkAction::Allow,
        None => policy.allow_local_network,
    }
}

/// Check every Seatbelt network invariant. Covers both the legacy and the
/// directional shape via [`egress_allowed`].
pub fn validate_seatbelt_network_policy(policy: &ContainerPolicy) -> Result<(), String> {
    let proxy_enabled = policy.network_proxy.is_enabled();
    let outbound_allowed = egress_allowed(policy);

    // No packet-filter layer on macOS, so a firewall mode can't be honored.
    if proxy_enabled
        && matches!(
            policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        )
    {
        return Err("Seatbelt: network.proxy cannot be combined with \
                    network.enforcementMode='firewall' or 'both'. macOS Seatbelt \
                    enforces network policy through the sandbox profile and has no \
                    packet-filter layer, so a firewall mode cannot be honored."
            .to_string());
    }

    // A remote proxy can't be expressed as a reachability rule, so it would
    // simply be unreachable. Loopback proxies (including builtinTestServer,
    // whose address is resolved at runtime and absent here) stay port-scoped.
    if !outbound_allowed
        && policy
            .network_proxy
            .address
            .as_ref()
            .is_some_and(|addr| !host_is_canonical_loopback(addr.host()))
    {
        return Err(
            "Seatbelt: a remote network.proxy (non-loopback host) cannot be \
                    combined with defaultPolicy='block'. Seatbelt cannot express \
                    reachability to a specific remote host, so the proxy would be \
                    unreachable and no outbound connection could succeed. Note that \
                    allowedHosts/blockedHosts are never forwarded to an external \
                    proxy, so it cannot enforce them on MXC's behalf. Use a loopback \
                    proxy (127.0.0.1, [::1], or localhost) or \
                    'network.proxy.builtinTestServer: true' (testing only, and the \
                    only form where MXC enforces the host lists) for port-scoped \
                    reachability under deny."
                .to_string(),
        );
    }

    // Outbound is already unrestricted, so the proxy adds no enforcement and
    // any intent to route through it is silently ignored.
    if proxy_enabled && outbound_allowed {
        return Err("Seatbelt: network.proxy cannot be combined with \
                    defaultPolicy='allow'. Outbound network is already unrestricted \
                    under 'allow', so the proxy would have no enforcement effect and \
                    any intent to route traffic through it would be silently ignored. \
                    Use defaultPolicy='block' with a loopback proxy (or \
                    'network.proxy.builtinTestServer: true') to actually enforce \
                    proxy-only egress."
            .to_string());
    }

    // Seatbelt's `(remote ...)` filter accepts only `*` / `localhost`, so a
    // hostname allowlist can't be expressed. Under deny the only approximations
    // are allow-all (the inverse of the request) or deny-all (silently dropping
    // it). The MXC-run builtin test proxy is the exception: it does filter hosts.
    if !policy.allowed_hosts.is_empty()
        && !outbound_allowed
        && !policy.network_proxy.builtin_test_server
    {
        return Err("Seatbelt: allowedHosts cannot be combined with \
                    defaultPolicy='block'. macOS Seatbelt has no per-host network \
                    filtering primitive, so the allowlist cannot be enforced and \
                    would degrade to allow-all outbound -- the inverse of the \
                    requested policy. Use 'network.proxy.builtinTestServer: true' \
                    (testing only) for MXC-enforced host filtering, remove \
                    allowedHosts to keep the deny, or use defaultPolicy='allow' if \
                    unrestricted egress is intended."
            .to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ProxyAddress, ProxyConfig, SeatbeltConfig};

    fn policy() -> ContainerPolicy {
        ContainerPolicy::default()
    }

    fn proxy(host: &str) -> ProxyConfig {
        ProxyConfig {
            address: Some(ProxyAddress::from_url(
                &format!("http://{host}:8080"),
                host.to_string(),
                8080,
            )),
            builtin_test_server: false,
        }
    }

    #[test]
    fn system_power_access_support_starts_at_v09() {
        assert_eq!(system_power_access_support("0.8.0-alpha"), Some(false));
        assert_eq!(system_power_access_support("0.9.0-alpha"), Some(true));
        assert_eq!(system_power_access_support("invalid"), None);
    }

    #[test]
    fn system_power_access_validation_rejects_pre_v09_requests() {
        let request = ExecutionRequest {
            schema_version: "0.8.0-alpha".to_string(),
            seatbelt: Some(SeatbeltConfig {
                system_power_access: true,
                ..Default::default()
            }),
            ..Default::default()
        };

        let error = validate_system_power_access(&request).unwrap_err();
        assert!(error.contains("schema version 0.9"), "got: {error}");
    }

    #[test]
    fn rejects_proxy_with_default_allow() {
        // Outbound is already unrestricted under 'allow' — a proxy adds no
        // enforcement, so the combination is a config-authoring mistake.
        let mut p = policy();
        p.default_network_policy = NetworkPolicy::Allow;
        p.network_proxy = ProxyConfig {
            address: None,
            builtin_test_server: true,
        };

        let msg = validate_seatbelt_network_policy(&p).unwrap_err();
        assert!(msg.contains("defaultPolicy='allow'"), "got: {msg}");
    }

    #[test]
    fn rejects_proxy_with_firewall_enforcement_mode() {
        let mut p = policy();
        p.network_proxy = proxy("127.0.0.1");
        p.network_enforcement_mode = NetworkEnforcementMode::Firewall;

        let msg = validate_seatbelt_network_policy(&p).unwrap_err();
        assert!(msg.contains("enforcementMode"), "got: {msg}");
    }

    /// The guard compared unbracketed literals only, so `http://[::1]` — the
    /// documented IPv6 form — was misread as remote and rejected.
    #[test]
    fn accepts_loopback_proxy_under_block_in_every_spelling() {
        for host in ["127.0.0.1", "[::1]", "localhost", "[0:0:0:0:0:0:0:1]"] {
            let mut p = policy();
            p.default_network_policy = NetworkPolicy::Block;
            p.network_proxy = proxy(host);

            assert!(
                validate_seatbelt_network_policy(&p).is_ok(),
                "loopback proxy host {host:?} should be accepted under a deny default"
            );
        }
    }

    #[test]
    fn rejects_remote_proxy_under_block() {
        for host in ["proxy.corp.example", "10.0.0.5", "[2001:db8::1]"] {
            let mut p = policy();
            p.default_network_policy = NetworkPolicy::Block;
            p.network_proxy = proxy(host);

            let msg = validate_seatbelt_network_policy(&p).unwrap_err();
            assert!(msg.contains("non-loopback host"), "{host:?} got: {msg}");
        }
    }

    #[test]
    fn rejects_allowed_hosts_with_default_block() {
        // Seatbelt has no per-host filtering primitive, so an allowlist under a
        // deny default cannot be enforced and used to degrade to allow-all.
        let mut p = policy();
        p.default_network_policy = NetworkPolicy::Block;
        p.allowed_hosts = vec!["api.github.com".to_string()];

        let msg = validate_seatbelt_network_policy(&p).unwrap_err();
        assert!(
            msg.contains("allowedHosts cannot be combined with defaultPolicy='block'"),
            "got: {msg}"
        );
    }

    #[test]
    fn accepts_allowed_hosts_with_builtin_test_proxy() {
        // The builtin test proxy is the cooperative-enforcement escape hatch.
        let mut p = policy();
        p.default_network_policy = NetworkPolicy::Block;
        p.allowed_hosts = vec!["api.github.com".to_string()];
        p.network_proxy = ProxyConfig {
            address: None,
            builtin_test_server: true,
        };

        assert!(validate_seatbelt_network_policy(&p).is_ok());
    }

    #[test]
    fn rejects_allowed_hosts_with_external_proxy() {
        let mut p = policy();
        p.default_network_policy = NetworkPolicy::Block;
        p.allowed_hosts = vec!["api.github.com".to_string()];
        p.network_proxy = proxy("127.0.0.1");

        let msg = validate_seatbelt_network_policy(&p).unwrap_err();
        assert!(msg.contains("allowedHosts"), "got: {msg}");
    }

    #[test]
    fn accepts_allowed_hosts_with_default_allow() {
        let mut p = policy();
        p.default_network_policy = NetworkPolicy::Allow;
        p.allowed_hosts = vec!["api.github.com".to_string()];

        assert!(validate_seatbelt_network_policy(&p).is_ok());
    }
}
