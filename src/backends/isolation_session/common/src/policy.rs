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
//! runs the full lifecycle in one call) the ONLY accepted network policy is the
//! canonical acknowledgment — `defaultPolicy=allow` + `allowLocalNetwork=true`
//! with no host rules, no proxy, and default enforcement. Anything else,
//! including an absent policy (which defaults to the unenforceable `Block`), is
//! refused. On post-provision phases the network posture is fixed at provision:
//! any supplied network policy is refused, an absent one is inherited.

use wxc_common::models::{ExecutionRequest, NetworkEnforcementMode, NetworkPolicy};

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
    set network.defaultPolicy=allow and network.allowLocalNetwork=true with no allowed/blocked \
    hosts, no proxy, and default enforcement to acknowledge the container is fully \
    network-accessible, or use a backend that enforces network policy";
const ERR_PROXY_POLICY: &str =
    "the network cannot be routed through a proxy; remove network.proxy \
    (the container's network is unrestricted and unproxied)";
const ERR_NETWORK_IMMUTABLE: &str =
    "network policy is fixed at provision and cannot be changed on \
    this phase; omit the network policy on post-provision phases";

/// Validates the request for the provision phase (also used by the one-shot
/// runner, which runs the whole lifecycle in one call so provision-phase
/// semantics apply). Filesystem policy is rejected first, then the network
/// policy must be the canonical unrestricted-network acknowledgment.
pub(super) fn validate_provision_policy(
    request: &ExecutionRequest,
) -> Result<(), IsolationSessionError> {
    reject_filesystem_policy(request)?;
    reject_ui_policy(request)?;
    validate_provision_network_policy(request)
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

/// Accepts only the canonical unrestricted-network acknowledgment and refuses
/// everything else. The container's network is open on both axes — outbound is
/// unrestricted and a process inside can listen on a localhost-reachable port —
/// and MXC has no primitive to change that, so the one honest request is
/// `defaultPolicy=allow` + `allowLocalNetwork=true` with no host rules, no
/// proxy, and default enforcement. An absent policy (domain default `Block`),
/// an explicit `Block`, host rules, non-default enforcement, or a proxy all
/// imply a restriction the backend cannot honor and are refused.
fn validate_provision_network_policy(
    request: &ExecutionRequest,
) -> Result<(), IsolationSessionError> {
    let policy = &request.policy;
    let is_canonical_allow = policy.default_network_policy == NetworkPolicy::Allow
        && policy.allow_local_network
        && policy.allowed_hosts.is_empty()
        && policy.blocked_hosts.is_empty()
        && policy.network_enforcement_mode == NetworkEnforcementMode::Capabilities;
    if !is_canonical_allow {
        return Err(IsolationSessionError::Policy(
            ERR_NETWORK_POLICY.to_string(),
        ));
    }
    if policy.network_proxy.is_enabled() {
        return Err(IsolationSessionError::Policy(ERR_PROXY_POLICY.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{
        ContainerPolicy, NetworkEgressPolicy, ProxyAddress, ProxyConfig, UiPolicy,
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
            validate_provision_policy(&request).unwrap_err(),
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
            validate_provision_policy(&request).unwrap_err(),
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
            validate_provision_policy(&request).unwrap_err(),
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
            validate_provision_policy(&request).unwrap_err(),
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
            validate_provision_policy(&request).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    #[test]
    fn provision_policy_accepts_canonical_allow() {
        let request = ExecutionRequest {
            policy: canonical_allow_policy(),
            ..Default::default()
        };
        validate_provision_policy(&request).unwrap();
    }

    #[test]
    fn provision_policy_rejects_default_request() {
        // Absent network policy → domain default `Block`, which the backend
        // cannot enforce, so provision refuses it.
        let request = ExecutionRequest::default();
        assert_policy_err_contains(
            validate_provision_policy(&request).unwrap_err(),
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
            validate_provision_policy(&request).unwrap_err(),
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
            validate_provision_policy(&request).unwrap_err(),
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
            validate_provision_policy(&request).unwrap_err(),
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
            validate_provision_policy(&request).unwrap_err(),
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
            validate_provision_policy(&request).unwrap_err(),
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
            validate_provision_policy(&request).unwrap_err(),
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
            validate_provision_policy(&request).unwrap_err(),
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
            validate_provision_policy(&request).unwrap_err(),
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
            validate_provision_policy(&request).unwrap_err(),
            "UI policy is not supported",
        );
    }

    #[test]
    fn provision_policy_accepts_absent_ui() {
        // Guard against over-rejection: the canonical request carries no `ui`.
        let request = ExecutionRequest {
            policy: canonical_allow_policy(),
            ..Default::default()
        };
        validate_provision_policy(&request).unwrap();
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
            validate_provision_policy(&request).unwrap_err(),
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
            validate_provision_policy(&fs_and_ui).unwrap_err(),
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
            validate_provision_policy(&ui_and_network).unwrap_err(),
            "UI policy is not supported",
        );
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
            validate_provision_policy(&request).unwrap_err(),
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
