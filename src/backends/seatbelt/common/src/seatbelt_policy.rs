// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Seatbelt network invariants, enforced by the backend's own `validate`.
//!
//! `validate` runs on every execution path -- the JSON parser feeds one here,
//! and a Rust caller that hands `mxc_engine` an `ExecutionRequest` it built
//! itself reaches the same check -- so this is the only home the rules need.
//!
//! Each check returns the caller-facing message; the backend wraps it as a
//! `ScriptResponse`.

use wxc_common::host_is_canonical_loopback;
use wxc_common::models::{ContainerPolicy, NetworkAction, NetworkEnforcementMode, NetworkPolicy};

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

/// Effective host-loopback posture, or `None` for the legacy shape, which has
/// no `hostLoopback` concept and keeps its 0.6/0.7 behavior untouched.
pub fn host_loopback_allowed(policy: &ContainerPolicy) -> Option<bool> {
    policy
        .network_ingress
        .as_ref()
        .map(|ingress| ingress.host_loopback == NetworkAction::Allow)
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
    use wxc_common::models::{ProxyAddress, ProxyConfig};

    #[test]
    fn host_loopback_allowed_is_none_for_the_legacy_shape() {
        // 0.6/0.7 has no hostLoopback concept; the caller must not synthesize
        // one, or legacy configs would change behavior.
        let mut p = policy();
        p.allow_local_network = true;
        assert_eq!(host_loopback_allowed(&p), None);
        p.allow_local_network = false;
        assert_eq!(host_loopback_allowed(&p), None);
    }

    #[test]
    fn host_loopback_allowed_reads_the_directional_field() {
        let mut p = policy();
        for (action, expected) in [
            (NetworkAction::Allow, Some(true)),
            (NetworkAction::Deny, Some(false)),
        ] {
            p.network_ingress = Some(wxc_common::models::NetworkIngressPolicy {
                default: action,
                host_loopback: action,
            });
            assert_eq!(host_loopback_allowed(&p), expected);
        }
    }

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
        for mode in [
            NetworkEnforcementMode::Firewall,
            NetworkEnforcementMode::Both,
        ] {
            let mut p = policy();
            p.network_proxy = proxy("127.0.0.1");
            p.network_enforcement_mode = mode.clone();

            let msg = validate_seatbelt_network_policy(&p).unwrap_err();
            assert!(msg.contains("enforcementMode"), "{mode:?} got: {msg}");
        }
    }

    #[test]
    fn accepts_builtin_test_proxy_under_block() {
        // builtinTestServer binds a loopback port at runtime, so it has no
        // address here — port-scoped and therefore safe under a deny default.
        let mut p = policy();
        p.default_network_policy = NetworkPolicy::Block;
        p.network_proxy = ProxyConfig {
            address: None,
            builtin_test_server: true,
        };

        assert!(validate_seatbelt_network_policy(&p).is_ok());
    }

    /// The guard compared unbracketed literals only, so `http://[::1]` — the
    /// documented IPv6 form — was misread as remote and rejected.
    #[test]
    fn accepts_loopback_proxy_under_block_in_every_spelling() {
        for host in [
            "127.0.0.1",
            "[::1]",
            "localhost",
            "[0:0:0:0:0:0:0:1]",
            "[0000:0000:0000:0000:0000:0000:0000:0001]",
        ] {
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
        // The last three are the other half of the widening above: accepting
        // every ::1 spelling must not spill into the rest of 127.0.0.0/8, since
        // the profile's `(remote ip "localhost:<port>")` covers only the
        // canonical addresses.
        for host in [
            "proxy.corp.example",
            "10.0.0.5",
            "[2001:db8::1]",
            "127.0.0.2",
            "127.0.0.53",
            "0.0.0.0",
        ] {
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
