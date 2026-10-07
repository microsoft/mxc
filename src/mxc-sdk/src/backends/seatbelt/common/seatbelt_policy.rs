// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Seatbelt policy invariants, enforced by the backend's own `validate`.
//!
//! `validate` runs on every execution path -- the JSON parser feeds one here,
//! and a Rust caller that hands `mxc_engine` an `ExecutionRequest` it built
//! itself reaches the same check -- so this is the only home the rules need.
//!
//! Each check returns the caller-facing message; the backend wraps it as a
//! `ScriptResponse`.

use crate::mxc_common::host_is_canonical_loopback;
use crate::mxc_common::models::{ContainerPolicy, ExecutionRequest, NetworkAction};

/// Effective GUI posture: `seatbelt.guiAccess` only means anything when the UI
/// policy leaves UI enabled, since every GUI grant is emitted alongside the
/// WindowServer allows. Single source of truth so the profile builder and the
/// runner cannot drift apart on what "GUI access" means.
///
/// [`validate_seatbelt_ui_policy`] rejects the contradictory combination, so on
/// an executed request this equals the raw `guiAccess` flag; the helper keeps
/// the direct `build_profile` callers (unit tests, embedders) consistent too.
pub fn gui_access_effective(request: &ExecutionRequest) -> bool {
    request.seatbelt.as_ref().is_some_and(|c| c.gui_access) && !request.policy.ui.disable
}

/// Reject a `guiAccess` request that the UI policy contradicts.
/// Fail loudly rather than hand back a sandbox that ignored the request.
pub fn validate_seatbelt_ui_policy(request: &ExecutionRequest) -> Result<(), String> {
    let gui_requested = request.seatbelt.as_ref().is_some_and(|c| c.gui_access);
    if gui_requested && request.policy.ui.disable {
        return Err("Seatbelt: seatbelt.guiAccess=true cannot be combined with \
                    ui.disable=true. The GUI grants (Mach IPC, mach-register, IOKit, \
                    pseudo-tty, per-user temp/cache writes) are only emitted when UI \
                    is enabled, so this combination would drop every GUI capability \
                    and deny WindowServer instead. Set 'ui.disable' to false to grant \
                    GUI access, or remove 'seatbelt.guiAccess'. Note that 'ui.disable' \
                    defaults to true, so an omitted 'ui' section conflicts too."
            .to_string());
    }
    Ok(())
}

/// Effective outbound posture; omission defaults to deny.
pub fn egress_allowed(policy: &ContainerPolicy) -> bool {
    policy
        .network_egress
        .as_ref()
        .is_some_and(|egress| egress.default == NetworkAction::Allow)
}

/// Effective inbound posture. Seatbelt maps `network.ingress.default` onto its
/// `(allow network-inbound (local ip))` rule; `hostLoopback` is enforced
/// separately on the container-to-host direction, so it plays no part here.
pub fn local_network_allowed(policy: &ContainerPolicy) -> bool {
    policy
        .network_ingress
        .as_ref()
        .is_some_and(|ingress| ingress.default == NetworkAction::Allow)
}

/// Effective host-loopback posture; omission defaults to deny.
pub fn host_loopback_allowed(policy: &ContainerPolicy) -> bool {
    policy
        .network_ingress
        .as_ref()
        .is_some_and(|ingress| ingress.host_loopback == NetworkAction::Allow)
}

/// Check every Seatbelt network invariant before profile construction.
pub fn validate_seatbelt_network_policy(policy: &ContainerPolicy) -> Result<(), String> {
    let proxy_enabled = policy.network_proxy.is_enabled();
    let outbound_allowed = egress_allowed(policy);

    // A remote proxy can't be expressed as a reachability rule.
    if !outbound_allowed
        && policy
            .network_proxy
            .address
            .as_ref()
            .is_some_and(|addr| !host_is_canonical_loopback(addr.host()))
    {
        return Err(
            "Seatbelt: runtimeConfig.networkProxy must name a loopback endpoint \
                    (127.0.0.1, [::1], or localhost); a remote proxy cannot be reached \
                    under network.egress.default='deny'"
                .to_string(),
        );
    }

    // Outbound is already unrestricted, so the proxy adds no enforcement and
    // any intent to route through it is silently ignored.
    if proxy_enabled && outbound_allowed {
        return Err("Seatbelt: runtimeConfig.networkProxy requires \
                    network.egress.default='deny'; an allow default would bypass \
                    the proxy and leave direct outbound traffic unrestricted"
            .to_string());
    }

    // `hostLoopback` is bidirectional and Seatbelt can only enforce its
    // container-to-host half (see `write_host_loopback_rules`): an inbound
    // filter cannot be scoped by peer, so there is no rule that admits a
    // loopback peer while refusing a LAN one. Only `hostLoopback: "allow"`
    // under `default: "deny"` is inexpressible -- the blanket
    // `network-inbound` grant that would carry it is exactly what
    // `default: "deny"` withholds -- so only that pair is refused.
    if let Some(ingress) = policy.network_ingress.as_ref() {
        if ingress.host_loopback == NetworkAction::Allow && ingress.default == NetworkAction::Deny {
            return Err(
                "macOS Seatbelt cannot enforce network.ingress.hostLoopback='allow' \
                 alongside network.ingress.default='deny': the inbound half of \
                 host loopback rides the same Seatbelt rule as the inbound \
                 default, so it cannot be granted while that default denies it. \
                 Set network.ingress.default='allow' as well, or set \
                 hostLoopback='deny'. Note that an omitted 'hostLoopback' is \
                 'deny', not an inherit of 'default'."
                    .to_string(),
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{ProxyAddress, ProxyConfig, SeatbeltConfig};

    #[test]
    fn omitted_host_loopback_defaults_to_deny() {
        assert!(!host_loopback_allowed(&policy()));
    }

    #[test]
    fn host_loopback_allowed_reads_the_directional_field() {
        let mut p = policy();
        for (action, expected) in [(NetworkAction::Allow, true), (NetworkAction::Deny, false)] {
            p.network_ingress = Some(crate::mxc_common::models::NetworkIngressPolicy {
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
        }
    }

    #[test]
    fn rejects_proxy_with_default_allow() {
        let mut p = policy();
        p.network_egress = Some(crate::mxc_common::models::NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        p.network_proxy = proxy("127.0.0.1");

        let msg = validate_seatbelt_network_policy(&p).unwrap_err();
        assert!(msg.contains("network.egress.default='deny'"), "got: {msg}");
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
            p.network_proxy = proxy(host);

            let msg = validate_seatbelt_network_policy(&p).unwrap_err();
            assert!(msg.contains("loopback endpoint"), "{host:?} got: {msg}");
        }
    }

    /// `guiAccess` with a `SeatbeltConfig` and the given `ui.disable`.
    fn gui_request(gui_access: bool, ui_disabled: bool) -> ExecutionRequest {
        let mut r = ExecutionRequest::default();
        r.policy.ui.disable = ui_disabled;
        r.seatbelt = Some(SeatbeltConfig {
            gui_access,
            ..Default::default()
        });
        r
    }

    #[test]
    fn rejects_gui_access_when_ui_is_disabled() {
        // ui.disable defaults to true, so this is what an omitted `ui`
        // section produces — the case that used to be silently ignored.
        let msg = validate_seatbelt_ui_policy(&gui_request(true, true)).unwrap_err();
        assert!(msg.contains("guiAccess"), "got: {msg}");
        assert!(msg.contains("ui.disable"), "got: {msg}");
    }

    #[test]
    fn accepts_gui_access_when_ui_is_enabled() {
        assert!(validate_seatbelt_ui_policy(&gui_request(true, false)).is_ok());
    }

    #[test]
    fn accepts_ui_disabled_without_gui_access() {
        assert!(validate_seatbelt_ui_policy(&gui_request(false, true)).is_ok());
        // An absent seatbelt section must not trip the rule either.
        assert!(validate_seatbelt_ui_policy(&ExecutionRequest::default()).is_ok());
    }

    #[test]
    fn gui_access_effective_requires_both_flags() {
        assert!(gui_access_effective(&gui_request(true, false)));
        assert!(!gui_access_effective(&gui_request(true, true)));
        assert!(!gui_access_effective(&gui_request(false, false)));
        assert!(!gui_access_effective(&ExecutionRequest::default()));
    }
}
