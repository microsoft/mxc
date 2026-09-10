// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Policy validation for the IsolationSession backend.
//!
//! Filesystem policy (`rw`, `ro`, `denied`) is rejected at every phase — the
//! backend has no host-folder-sharing primitive.
//!
//! UI policy is rejected at every phase — the backend has no UI-restriction
//! primitive. The isolation session is a *separate OS session*, which isolates
//! the host's UI from the contained code but does not deny the contained code
//! the capability: window creation, GDI, and the session's own clipboard all
//! work inside it. A `ui` policy therefore cannot be honored, and accepting it
//! would assert a guarantee the backend does not provide.
//!
//! Network policy is honesty-gated. The container runs on an unrestricted
//! network that MXC cannot filter or deny, so at provision (and one-shot, which
//! runs the full lifecycle in one call) the caller must supply an explicit
//! [`UnrestrictedNetworkAcknowledgment`] through the backend's own runtime
//! config, over a request that authored no network policy at all. The former
//! legacy allow-policy marker pair is not an acknowledgment.
//!
//! Anything else is refused: an absent acknowledgment (the domain default is
//! the unenforceable `Block`), an explicitly authored but empty network
//! section, host rules, non-default enforcement, or a proxy. An acknowledgment
//! never overrides an authored restriction and never synthesizes a legacy
//! `allow` grant. On post-provision phases the network posture is fixed at
//! provision: any supplied network policy is refused, an absent one is
//! inherited.

use wxc_common::models::{
    ExecutionRequest, NetworkEgressPolicy, NetworkEnforcementMode, NetworkIngressPolicy,
    NetworkPolicy, UnrestrictedNetworkAcknowledgment,
};

use super::error::IsolationSessionError;

const ERR_FILESYSTEM_POLICY: &str =
    "filesystem policy is not supported by the isolation session backend";
const ERR_UI_POLICY: &str = "UI policy is not supported by the isolation session backend; the \
    session isolates the host's UI from the contained code but does not deny it UI \
    capabilities (window creation, GDI, and the session's own clipboard all work inside \
    it), so no ui posture is truthful here. Omitting the ui section is accepted but \
    applies no restriction — it is not the lockdown the schema's default implies. Use a \
    backend that enforces UI policy if you need one";
const ERR_NETWORK_POLICY: &str = "the network is unrestricted and cannot be filtered or denied; \
    acknowledge that the container is fully network-accessible with no network policy at all — \
    experimental.isolation_session.acknowledgeUnrestrictedNetwork=true on a one-shot request, or \
    experimental.isolation_session.provision.acknowledgeUnrestrictedNetwork=true on a state-aware \
    provision request — or use a backend that enforces network policy";
const ERR_PROXY_POLICY: &str =
    "the network cannot be routed through a proxy; remove network.proxy \
    (the container's network is unrestricted and unproxied)";
const ERR_NETWORK_IMMUTABLE: &str =
    "network policy is fixed at provision and cannot be changed on \
    this phase; omit the network policy on post-provision phases";

/// Validates the request for the provision phase (also used by the one-shot
/// runner, which runs the whole lifecycle in one call so provision-phase
/// semantics apply). Filesystem policy is rejected first, then UI policy, then
/// the backend configuration must carry the explicit acknowledgment.
///
/// `acknowledgment` is the caller's explicit acknowledgment as it arrived in
/// the backend's own runtime config — the one-shot `experimental.isolation_session`
/// section or the state-aware provision config. It is passed in rather than read
/// from the request because the two surfaces carry it in different places, and
/// because `wxc_common` must not learn backend-specific semantics.
pub(super) fn validate_provision_policy(
    request: &ExecutionRequest,
    acknowledgment: Option<UnrestrictedNetworkAcknowledgment>,
) -> Result<(), IsolationSessionError> {
    reject_filesystem_policy(request)?;
    reject_ui_policy(request)?;
    validate_provision_network_policy(request, acknowledgment)
}

/// Validates the request for any non-provision phase (start / exec / stop /
/// deprovision). Filesystem policy is rejected (bound to provision and
/// immutable). UI policy is rejected (never supported). The network posture is
/// likewise fixed at provision, so a network policy supplied here is refused;
/// an absent one is inherited.
pub(super) fn validate_post_provision_policy(
    request: &ExecutionRequest,
) -> Result<(), IsolationSessionError> {
    reject_filesystem_policy(request)?;
    reject_ui_policy(request)?;
    if request.policy.network_proxy.is_enabled() {
        return Err(IsolationSessionError::Policy(ERR_PROXY_POLICY.to_string()));
    }
    if request.policy.network_specified
        || request.policy.network_mode_specified
        || request.policy.network_egress.is_some()
        || request.policy.network_ingress.is_some()
    {
        return Err(IsolationSessionError::Policy(
            ERR_NETWORK_IMMUTABLE.to_string(),
        ));
    }
    Ok(())
}

/// Rejects any filesystem policy field. Shared by the provision and
/// post-provision validators — the backend has no host-folder-sharing
/// primitive, so `rw` / `ro` / `denied` are rejected at every phase. Runs
/// before the network check so a filesystem rejection takes precedence.
fn reject_filesystem_policy(request: &ExecutionRequest) -> Result<(), IsolationSessionError> {
    if !request.policy.readwrite_paths.is_empty()
        || !request.policy.readonly_paths.is_empty()
        || !request.policy.denied_paths.is_empty()
    {
        return Err(IsolationSessionError::Policy(
            ERR_FILESYSTEM_POLICY.to_string(),
        ));
    }
    Ok(())
}

/// Rejects any supplied UI policy. Presence-based, not value-based: the domain
/// `UiPolicy::default()` is full lockdown, so an explicitly-supplied lockdown
/// `ui` is indistinguishable from an absent one by value — the same blind spot
/// `network_specified` closes for the network policy. Runs after the filesystem
/// check so a filesystem rejection keeps precedence.
fn reject_ui_policy(request: &ExecutionRequest) -> Result<(), IsolationSessionError> {
    if request.policy.ui_specified {
        return Err(IsolationSessionError::Policy(ERR_UI_POLICY.to_string()));
    }
    Ok(())
}

/// Accepts only an acknowledged unrestricted network and refuses everything
/// else. The container's network is open on both axes — outbound is
/// unrestricted and a process inside can listen on a localhost-reachable port —
/// and MXC has no primitive to change that.
///
/// The explicit acknowledgment applies only over an unauthored network. Parser
/// defaults are not authored restrictions; an empty section, any directional
/// posture, a proxy, or legacy policy values remain refused.
fn validate_provision_network_policy(
    request: &ExecutionRequest,
    acknowledgment: Option<UnrestrictedNetworkAcknowledgment>,
) -> Result<(), IsolationSessionError> {
    if acknowledgment.is_some() && network_policy_unauthored(request) {
        return Ok(());
    }
    if request.policy.network_proxy.is_enabled() {
        return Err(IsolationSessionError::Policy(ERR_PROXY_POLICY.to_string()));
    }
    Err(IsolationSessionError::Policy(
        ERR_NETWORK_POLICY.to_string(),
    ))
}

/// True when nothing in the request authored any network policy.
///
/// Presence flags separate a caller-authored section from the parser's implicit
/// defaults, which is the only thing that distinguishes an omitted `network`
/// from `network: {}` or an authored directional deny — all three normalize to
/// the same values. The flags alone are not enough, though: a direct typed
/// caller can populate the policy without setting them, so every field that
/// could carry a restriction or a grant is also checked against its unauthored
/// value. Runtime proxy, proxy-peer identity, and host lists are included, so
/// an absent `network` section cannot hide network settings supplied elsewhere.
fn network_policy_unauthored(request: &ExecutionRequest) -> bool {
    let policy = &request.policy;
    !policy.network_specified
        && !policy.network_mode_specified
        && !policy.runtime_network_proxy_specified
        && !policy.network_proxy.is_enabled()
        && policy.allowed_proxy_peer.is_none()
        && policy.allowed_hosts.is_empty()
        && policy.blocked_hosts.is_empty()
        && policy.default_network_policy == NetworkPolicy::Block
        && !policy.allow_local_network
        && policy.network_enforcement_mode == NetworkEnforcementMode::Capabilities
        && policy
            .network_egress
            .as_ref()
            .is_none_or(|egress| *egress == NetworkEgressPolicy::default())
        && policy
            .network_ingress
            .as_ref()
            .is_none_or(|ingress| *ingress == NetworkIngressPolicy::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{
        ContainerPolicy, NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, ProxyAddress,
        ProxyConfig, UiPolicy,
    };
    use wxc_common::mxc_error::MxcErrorCode;

    fn assert_policy_err_contains(err: IsolationSessionError, expected: &str) {
        match err {
            IsolationSessionError::Policy(msg) => {
                assert!(msg.contains(expected), "expected '{}' in {}", expected, msg)
            }
            other => panic!("expected Policy variant, got {:?}", other),
        }
    }

    /// A `ContainerPolicy` in the one canonical unrestricted-network form the
    /// provision validator accepts: `allow` outbound + `allowLocalNetwork` +
    /// no host rules + default enforcement + no proxy.
    fn canonical_allow_policy() -> ContainerPolicy {
        ContainerPolicy {
            default_network_policy: NetworkPolicy::Allow,
            allow_local_network: true,
            ..Default::default()
        }
    }

    // ====== Phase-specific policy validation ======
    //
    // Filesystem policy is rejected at every phase (shared
    // `reject_filesystem_policy`, checked before the network policy).
    // Provision (and one-shot) additionally require the canonical
    // unrestricted-network acknowledgment; post-provision phases reject any
    // supplied network policy (`network_specified`) and inherit an absent one.

    #[test]
    fn provision_policy_rejects_readwrite_paths() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_readonly_paths() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_readwrite_and_readonly_together() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                readonly_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_denied_paths() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                denied_paths: vec!["C:\\secret".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_denied_even_with_rw() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                denied_paths: vec!["C:\\secret".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_legacy_allow_without_acknowledgment() {
        let request = ExecutionRequest {
            policy: canonical_allow_policy(),
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_default_request() {
        // Absent network policy → domain default `Block`, which the backend
        // cannot enforce, so provision refuses it.
        let request = ExecutionRequest::default();
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_block_even_with_local_network() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Block,
                allow_local_network: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_allow_without_local_network() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Allow,
                allow_local_network: false,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_allowed_hosts() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                allowed_hosts: vec!["example.com".to_string()],
                ..canonical_allow_policy()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_blocked_hosts() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                blocked_hosts: vec!["evil.com".to_string()],
                ..canonical_allow_policy()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_firewall_enforcement() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                network_enforcement_mode: NetworkEnforcementMode::Firewall,
                ..canonical_allow_policy()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_both_enforcement() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                network_enforcement_mode: NetworkEnforcementMode::Both,
                ..canonical_allow_policy()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_proxy() {
        // Canonical on the network axis, but a proxy the backend cannot route.
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                network_proxy: ProxyConfig {
                    address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
                    builtin_test_server: false,
                },
                ..canonical_allow_policy()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_PROXY_POLICY,
        );
    }

    #[test]
    fn provision_policy_filesystem_error_takes_precedence_over_network() {
        // Both a filesystem field and a non-canonical (absent/Block) network:
        // the filesystem rejection fires first.
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    // ====== UI policy (rejected at every phase) ======

    #[test]
    fn provision_policy_rejects_supplied_ui() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                ui_specified: true,
                ..canonical_allow_policy()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            "UI policy is not supported",
        );
    }

    #[test]
    fn provision_policy_accepts_absent_ui() {
        // Guard against over-rejection: the canonical request carries no `ui`.
        let request = ExecutionRequest {
            policy: unauthored_directional_policy(),
            ..Default::default()
        };
        validate_provision_policy(&request, ACK).unwrap();
    }

    #[test]
    fn provision_policy_rejects_lockdown_equivalent_ui() {
        // Presence, not value, drives the refusal. `UiPolicy::default()` is
        // full lockdown, so a caller sending an explicit lockdown `ui` is
        // indistinguishable by value from one sending none — but the backend
        // still cannot deliver the Win32k/clipboard denial the policy asserts.
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                ui_specified: true,
                ui: UiPolicy::default(),
                ..canonical_allow_policy()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request, None).unwrap_err(),
            "UI policy is not supported",
        );
    }

    #[test]
    fn post_provision_policy_rejects_supplied_ui() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                ui_specified: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            "UI policy is not supported",
        );
    }

    #[test]
    fn post_provision_policy_accepts_absent_ui() {
        let request = ExecutionRequest::default();
        assert!(validate_post_provision_policy(&request).is_ok());
    }

    #[test]
    fn ui_error_takes_precedence_over_network_but_not_filesystem() {
        // Ordering is filesystem -> ui -> network, so each existing
        // precedence test stays valid and the new check slots in between.
        let fs_and_ui = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                ui_specified: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&fs_and_ui, None).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );

        // `ui` supplied with a non-canonical (absent -> Block) network: the ui
        // rejection fires first.
        let ui_and_network = ExecutionRequest {
            policy: ContainerPolicy {
                ui_specified: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&ui_and_network, None).unwrap_err(),
            "UI policy is not supported",
        );
    }

    // ====== Explicit unrestricted-network acknowledgment ======
    //
    // The explicit acknowledgment accepts a request that authored no network
    // policy at all. It never rescues authored content or the removed marker pair.

    const ACK: Option<UnrestrictedNetworkAcknowledgment> = Some(UnrestrictedNetworkAcknowledgment);

    /// The policy a v0.9 request with no `network` section normalizes to: the
    /// parser installs implicit directional deny defaults and leaves every
    /// presence flag false.
    fn unauthored_directional_policy() -> ContainerPolicy {
        ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy::default()),
            network_ingress: Some(NetworkIngressPolicy::default()),
            ..Default::default()
        }
    }

    fn request_with_policy(policy: ContainerPolicy) -> ExecutionRequest {
        ExecutionRequest {
            policy,
            ..Default::default()
        }
    }

    #[test]
    fn acknowledgment_accepts_an_unauthored_network() {
        // Implicit directional deny defaults are the *absence* of a policy, not
        // a restriction, so the acknowledgment covers them without any legacy
        // `allow` being synthesized.
        validate_provision_policy(&request_with_policy(unauthored_directional_policy()), ACK)
            .unwrap();
        // A default-constructed policy (a direct typed caller that never went
        // through the parser) is equally unauthored.
        validate_provision_policy(&request_with_policy(ContainerPolicy::default()), ACK).unwrap();
    }

    #[test]
    fn acknowledgment_rejects_the_legacy_form_even_for_direct_typed_callers() {
        assert_policy_err_contains(
            validate_provision_policy(&request_with_policy(canonical_allow_policy()), ACK)
                .unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn absent_acknowledgment_is_rejected() {
        assert_policy_err_contains(
            validate_provision_policy(&request_with_policy(unauthored_directional_policy()), None)
                .unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn acknowledgment_rejects_an_authored_empty_network_section() {
        // `network: {}` normalizes to exactly the same values as an omitted
        // section; only `network_specified` tells them apart, and an explicitly
        // authored section is not an omission.
        let policy = ContainerPolicy {
            network_specified: true,
            ..unauthored_directional_policy()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request_with_policy(policy), ACK).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn acknowledgment_rejects_an_authored_directional_deny() {
        let policy = ContainerPolicy {
            network_specified: true,
            network_mode_specified: true,
            ..unauthored_directional_policy()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request_with_policy(policy), ACK).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn acknowledgment_rejects_an_authored_directional_allow() {
        // Value-level authorship, reachable by a direct typed caller whose
        // presence flags were never set.
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            }),
            ..unauthored_directional_policy()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request_with_policy(policy), ACK).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn acknowledgment_rejects_network_settings_supplied_outside_the_network_section() {
        // An absent `network` section must not hide a runtime proxy, a proxy
        // peer identity, or host lists supplied elsewhere.
        let runtime_proxy = ContainerPolicy {
            runtime_network_proxy_specified: true,
            network_proxy: ProxyConfig {
                address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
                builtin_test_server: false,
            },
            ..unauthored_directional_policy()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request_with_policy(runtime_proxy), ACK).unwrap_err(),
            ERR_PROXY_POLICY,
        );

        let proxy_peer = ContainerPolicy {
            allowed_proxy_peer: Some("C:\\proxy.exe".to_string()),
            ..unauthored_directional_policy()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request_with_policy(proxy_peer), ACK).unwrap_err(),
            ERR_NETWORK_POLICY,
        );

        let allowed_hosts = ContainerPolicy {
            allowed_hosts: vec!["example.test".to_string()],
            ..unauthored_directional_policy()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request_with_policy(allowed_hosts), ACK).unwrap_err(),
            ERR_NETWORK_POLICY,
        );

        let enforcement = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
            ..unauthored_directional_policy()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request_with_policy(enforcement), ACK).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn acknowledgment_preserves_the_established_diagnostic_order() {
        // Filesystem and UI rejections keep precedence over the network check,
        // acknowledged or not.
        let filesystem = ContainerPolicy {
            readwrite_paths: vec!["C:\\src".to_string()],
            ..unauthored_directional_policy()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request_with_policy(filesystem), ACK).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );

        let ui = ContainerPolicy {
            ui_specified: true,
            ..unauthored_directional_policy()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request_with_policy(ui), ACK).unwrap_err(),
            ERR_UI_POLICY,
        );

        // Canonical legacy network plus a proxy still reports the proxy error,
        // not the network error, exactly as it does without the acknowledgment.
        let canonical_with_proxy = ContainerPolicy {
            network_proxy: ProxyConfig {
                address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
                builtin_test_server: false,
            },
            ..canonical_allow_policy()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request_with_policy(canonical_with_proxy.clone()), ACK)
                .unwrap_err(),
            ERR_PROXY_POLICY,
        );
        assert_policy_err_contains(
            validate_provision_policy(&request_with_policy(canonical_with_proxy), None)
                .unwrap_err(),
            ERR_PROXY_POLICY,
        );
    }

    #[test]
    fn acknowledgment_does_not_reach_post_provision_phases() {
        // The posture is fixed at provision. Post-provision validation takes no
        // acknowledgment at all, so an authored network stays refused and an
        // absent one stays inherited.
        validate_post_provision_policy(&request_with_policy(ContainerPolicy::default())).unwrap();
        let authored = ContainerPolicy {
            network_specified: true,
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request_with_policy(authored)).unwrap_err(),
            ERR_NETWORK_IMMUTABLE,
        );
    }

    #[test]
    fn acknowledgment_rejection_maps_to_policy_validation() {
        let policy = ContainerPolicy {
            network_specified: true,
            ..unauthored_directional_policy()
        };
        let err = super::super::error::map_lifecycle_error(
            validate_provision_policy(&request_with_policy(policy), ACK).unwrap_err(),
        );
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn ui_rejection_maps_to_policy_validation() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                ui_specified: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let err = super::super::error::map_lifecycle_error(
            validate_provision_policy(&request, None).unwrap_err(),
        );
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn post_provision_policy_rejects_readwrite_paths() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    #[test]
    fn post_provision_policy_rejects_readonly_paths() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    #[test]
    fn post_provision_policy_rejects_denied_paths() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                denied_paths: vec!["C:\\secret".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    #[test]
    fn post_provision_policy_rejects_specified_network() {
        // Any supplied network policy is refused post-provision (fixed at
        // provision), regardless of value — here a canonical allow.
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                network_specified: true,
                ..canonical_allow_policy()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            ERR_NETWORK_IMMUTABLE,
        );
    }

    #[test]
    fn post_provision_policy_rejects_specified_network_even_when_block() {
        // Closes the presence-signal blind spot: an explicit default-valued
        // (Block) network is indistinguishable from absent in the domain model,
        // so the `network_specified` flag — not the value — drives the refusal.
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                network_specified: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            ERR_NETWORK_IMMUTABLE,
        );
    }

    #[test]
    fn post_provision_policy_accepts_absent_network() {
        // No network supplied → inherit what provision established.
        let request = ExecutionRequest::default();
        assert!(validate_post_provision_policy(&request).is_ok());
    }

    #[test]
    fn post_provision_policy_rejects_raw_directional_policy() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                network_egress: Some(NetworkEgressPolicy::default()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            ERR_NETWORK_IMMUTABLE,
        );
    }

    #[test]
    fn post_provision_policy_filesystem_error_takes_precedence() {
        // Filesystem rejection fires before the network-immutability check.
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                network_specified: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }
}
