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
//! runs the full lifecycle in one call) the caller must describe that actual
//! unrestricted posture through the standard directional all-allow spelling.
//! Anything else, including an absent policy (which defaults to deny), is
//! refused. On post-provision phases the network posture is fixed at provision:
//! any supplied network policy is refused, an absent one is inherited.
//!
//! Every process starts from the agent user's default environment, which
//! `process.env` can be layered over (`process.inheritDefaultEnv`) but cannot
//! replace or empty. A `process.env` without `process.inheritDefaultEnv` is
//! therefore refused wherever a process is launched: one-shot and exec.

use crate::mxc_common::default_env::EnvResolution;
use crate::mxc_common::models::{ExecutionRequest, IsolationSessionUser, NetworkAction};

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
    describe that posture with network.egress.default=allow, \
    network.ingress.default=allow, and network.ingress.hostLoopback=allow; do not supply rules \
    or proxy settings, or use a backend that enforces network policy";
const ERR_PROXY_POLICY: &str =
    "the network cannot be routed through a proxy; remove network.proxy \
    (the container's network is unrestricted and unproxied)";
const ERR_NETWORK_IMMUTABLE: &str =
    "network policy is fixed at provision and cannot be changed on \
    this phase; omit the network policy on post-provision phases";
const ERR_ENVIRONMENT_POLICY: &str = "process.env without process.inheritDefaultEnv=true is not \
    supported by the isolation session backend: every process starts from the agent user's \
    default environment, which cannot be replaced or emptied; set process.inheritDefaultEnv to \
    true to layer process.env over it, or omit process.env";

/// Validates the request for the provision phase (also used by the one-shot
/// runner, which runs the whole lifecycle in one call so provision-phase
/// semantics apply). Filesystem policy is rejected first, then the network
/// policy must be one of the canonical unrestricted-network postures.
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

/// Rejects a `process.env` that asks to replace the default environment
/// rather than be layered over it.
pub(super) fn reject_unhonorable_environment(
    request: &ExecutionRequest,
) -> Result<(), IsolationSessionError> {
    match EnvResolution::of(request) {
        EnvResolution::Replace => Err(IsolationSessionError::Policy(
            ERR_ENVIRONMENT_POLICY.to_string(),
        )),
        EnvResolution::Default | EnvResolution::Overlay => Ok(()),
    }
}

/// The request field carrying Entra credentials for a phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UserField {
    Provision,
    Start,
}

impl UserField {
    fn path(self) -> &'static str {
        match self {
            Self::Provision => "isolationSession.provision.user",
            Self::Start => "isolationSession.start.user",
        }
    }
}

/// Validates an Entra credential bundle before any OS call.
pub(super) fn validate_isolation_session_user(
    request: &ExecutionRequest,
    field: UserField,
    user: &IsolationSessionUser,
) -> Result<(), IsolationSessionError> {
    let path = field.path();
    if !request.experimental_enabled {
        return Err(IsolationSessionError::Policy(format!(
            "{path} is an experimental feature; enable experimental features to use it"
        )));
    }
    let upn = user.upn.trim();
    if !upn.contains('@') || upn.starts_with('@') || upn.ends_with('@') {
        return Err(IsolationSessionError::Policy(format!(
            "{path}.upn must be a user principal name containing '@'"
        )));
    }
    if user.wam_token.is_empty() {
        return Err(IsolationSessionError::Policy(format!(
            "{path}.wamToken must not be empty"
        )));
    }
    Ok(())
}

/// Refuses Entra credentials on a host that deduces the enterprise agent user.
pub(super) fn user_superseded_by_deduction(field: UserField) -> IsolationSessionError {
    IsolationSessionError::Policy(format!(
        "{} is not accepted on a host that deduces the enterprise agent user; omit user",
        field.path()
    ))
}

/// Rejects any filesystem policy field. Shared by the provision and
/// post-provision validators — the backend has no host-folder-sharing
/// primitive, so `rw` / `ro` / `denied` are rejected at every phase. Runs
/// before the network check so a filesystem rejection takes precedence.
fn reject_filesystem_policy(request: &ExecutionRequest) -> Result<(), IsolationSessionError> {
    if !request.policy.readwrite_paths.is_empty()
        || !request.policy.readonly_paths.is_empty()
        || !request.policy.enumerate_paths.is_empty()
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

/// Accepts only the canonical directional unrestricted-network spelling.
fn validate_provision_network_policy(
    request: &ExecutionRequest,
) -> Result<(), IsolationSessionError> {
    let policy = &request.policy;
    let is_directional_allow = policy.network_egress.as_ref().is_some_and(|egress| {
        egress.default == NetworkAction::Allow && egress.allow.is_empty() && egress.deny.is_empty()
    }) && policy.network_ingress.as_ref().is_some_and(|ingress| {
        ingress.default == NetworkAction::Allow && ingress.host_loopback == NetworkAction::Allow
    });
    if !is_directional_allow {
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
    use crate::mxc_common::models::{
        ContainerPolicy, NetworkEgressPolicy, NetworkIngressPolicy, ProxyAddress, ProxyConfig,
        UiPolicy,
    };
    use crate::mxc_common::mxc_error::MxcErrorCode;

    fn assert_policy_err_contains(err: IsolationSessionError, expected: &str) {
        match err {
            IsolationSessionError::Policy(msg) => {
                assert!(msg.contains(expected), "expected '{}' in {}", expected, msg)
            }
            other => panic!("expected Policy variant, got {:?}", other),
        }
    }

    fn directional_allow_policy() -> ContainerPolicy {
        ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            }),
            network_ingress: Some(NetworkIngressPolicy {
                default: NetworkAction::Allow,
                host_loopback: NetworkAction::Allow,
            }),
            network_specified: true,
            network_mode_specified: true,
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
    fn provision_policy_rejects_enumerate_paths() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                enumerate_paths: vec!["C:\\data".to_string()],
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
    fn provision_policy_accepts_directional_allow() {
        let request = ExecutionRequest {
            policy: directional_allow_policy(),
            ..Default::default()
        };
        validate_provision_policy(&request).unwrap();
    }

    #[test]
    fn provision_policy_rejects_mixed_or_partial_directional_postures() {
        for policy in [
            ContainerPolicy {
                network_ingress: None,
                ..directional_allow_policy()
            },
            ContainerPolicy {
                network_egress: None,
                ..directional_allow_policy()
            },
            ContainerPolicy {
                network_ingress: Some(NetworkIngressPolicy {
                    default: NetworkAction::Allow,
                    host_loopback: NetworkAction::Deny,
                }),
                ..directional_allow_policy()
            },
            ContainerPolicy {
                network_egress: Some(NetworkEgressPolicy {
                    default: NetworkAction::Allow,
                    allow: vec![Default::default()],
                    deny: Vec::new(),
                }),
                ..directional_allow_policy()
            },
        ] {
            assert_policy_err_contains(
                validate_provision_policy(&ExecutionRequest {
                    policy,
                    ..Default::default()
                })
                .unwrap_err(),
                ERR_NETWORK_POLICY,
            );
        }
    }

    #[test]
    fn provision_policy_rejects_default_request() {
        // Absent network policy defaults to deny, which the backend cannot
        // enforce, so provision refuses it.
        let request = ExecutionRequest::default();
        assert_policy_err_contains(
            validate_provision_policy(&request).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_proxy() {
        // Unrestricted on the network axis, but a proxy the backend cannot route.
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                network_proxy: ProxyConfig {
                    address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
                },
                ..directional_allow_policy()
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
                ..directional_allow_policy()
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
            policy: directional_allow_policy(),
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
                ..directional_allow_policy()
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
        // provision), regardless of value — here a directional allow.
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                network_specified: true,
                ..directional_allow_policy()
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
        // Even an explicit default-valued (deny) network is rejected on
        // presence, not just on its values.
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

    // ====== process.env (refused when it would replace the default) ======

    fn request_with_env(env: Option<Vec<&str>>, inherit_default_env: bool) -> ExecutionRequest {
        ExecutionRequest {
            env: env.map(|e| e.into_iter().map(String::from).collect()),
            inherit_default_env,
            ..Default::default()
        }
    }

    #[test]
    fn only_an_environment_that_would_replace_the_default_is_refused() {
        let cases = [
            (None, false, true),
            (None, true, true),
            (Some(vec![]), false, false),
            (Some(vec![]), true, true),
            (Some(vec!["FOO=bar"]), false, false),
            (Some(vec!["FOO=bar"]), true, true),
        ];

        for (env, inherit_default_env, accepted) in cases {
            let state = format!("{env:?}, inherit_default_env={inherit_default_env}");
            let request = request_with_env(env, inherit_default_env);
            match (reject_unhonorable_environment(&request), accepted) {
                (Ok(()), true) => {}
                (Err(err), false) => assert_policy_err_contains(err, ERR_ENVIRONMENT_POLICY),
                (result, _) => panic!("{state}: expected accepted={accepted}, got {result:?}"),
            }
        }
    }

    // ====== Entra credential bundle ======

    fn user(upn: &str, wam_token: &str) -> IsolationSessionUser {
        IsolationSessionUser {
            upn: upn.to_string(),
            wam_token: wam_token.to_string(),
        }
    }

    fn experimental_request() -> ExecutionRequest {
        ExecutionRequest {
            experimental_enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn user_accepts_a_well_formed_bundle_for_each_phase() {
        for field in [UserField::Provision, UserField::Start] {
            for upn in ["alice@contoso.com", "  alice@contoso.com\t"] {
                validate_isolation_session_user(&experimental_request(), field, &user(upn, "tok"))
                    .unwrap();
            }
        }
    }

    #[test]
    fn user_requires_the_experimental_opt_in_before_any_shape_check() {
        for field in [UserField::Provision, UserField::Start] {
            for user in [user("alice@contoso.com", "tok"), user("alice", "")] {
                assert_policy_err_contains(
                    validate_isolation_session_user(&ExecutionRequest::default(), field, &user)
                        .unwrap_err(),
                    &format!(
                        "{} is an experimental feature; enable experimental features",
                        field.path()
                    ),
                );
            }
        }
    }

    #[test]
    fn user_rejects_a_upn_without_an_interior_at_sign_without_echoing_it() {
        for upn in ["", "   ", "alice", "@contoso.com", "alice@", " alice@ "] {
            let err = validate_isolation_session_user(
                &experimental_request(),
                UserField::Provision,
                &user(upn, "tok"),
            )
            .unwrap_err();
            let IsolationSessionError::Policy(message) = err else {
                panic!("expected Policy variant for {upn:?}");
            };
            assert!(
                message.contains("isolationSession.provision.user.upn must be"),
                "{upn:?}: {message}"
            );
            if !upn.trim().is_empty() {
                assert!(!message.contains(upn.trim()), "{upn:?}: {message}");
            }
        }
    }

    #[test]
    fn user_rejects_an_empty_wam_token() {
        assert_policy_err_contains(
            validate_isolation_session_user(
                &experimental_request(),
                UserField::Start,
                &user("alice@contoso.com", ""),
            )
            .unwrap_err(),
            "isolationSession.start.user.wamToken must not be empty",
        );
    }

    #[test]
    fn deduction_refusal_names_the_phase_field() {
        for (field, path) in [
            (UserField::Provision, "isolationSession.provision.user"),
            (UserField::Start, "isolationSession.start.user"),
        ] {
            assert_policy_err_contains(
                user_superseded_by_deduction(field),
                &format!("{path} is not accepted on a host that deduces the enterprise agent user"),
            );
        }
    }
}
