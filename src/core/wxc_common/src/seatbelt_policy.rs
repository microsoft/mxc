// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Seatbelt network invariants, shared by the config parser and the Seatbelt
//! backend's own `validate`.
//!
//! The parser only sees requests built from JSON. A Rust caller can hand
//! `mxc_engine::run` an `ExecutionRequest` it built itself, skipping the parser
//! entirely, so these checks live here and are called from both places.
//!
//! Each returns the caller-facing message; the parser wraps it as a config
//! error and the backend as a `ScriptResponse`.

use crate::host_is_canonical_loopback;
use crate::models::{ContainerPolicy, NetworkAction, NetworkEnforcementMode, NetworkPolicy};

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
