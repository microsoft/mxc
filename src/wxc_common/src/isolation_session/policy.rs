// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Policy validation for the IsolationSession backend. Filesystem `rw` and
//! `ro` paths are honored at provision (applied via `share_folders`); every
//! other filesystem field is rejected, and network / proxy policy is
//! rejected at every phase — the backend has no equivalent primitive.

use crate::models::{CodexRequest, IsolationSessionUser, NetworkPolicy};
use crate::mxc_error::MxcError;

use super::error::IsolationSessionError;

const ERR_FILESYSTEM_POLICY: &str =
    "filesystem policy is not supported by the isolation session backend";
const ERR_NETWORK_POLICY: &str = "network policy is not supported by the isolation session backend";
const ERR_PROXY_POLICY: &str = "network proxy is not supported by the isolation session backend";

/// Validates the request for the provision phase. `rw` and `ro` paths are
/// honored (applied later via `share_folders`); `denied_paths` is rejected
/// because the underlying API has no equivalent primitive.
pub(super) fn validate_provision_policy(
    request: &CodexRequest,
) -> Result<(), IsolationSessionError> {
    if !request.policy.denied_paths.is_empty() {
        return Err(IsolationSessionError::Policy(
            ERR_FILESYSTEM_POLICY.to_string(),
        ));
    }
    validate_network_and_proxy_policy(request)
}

/// Validates the request for any non-provision phase. All filesystem fields
/// are rejected because filesystem policy is bound to provision and
/// immutable thereafter.
pub(super) fn validate_post_provision_policy(
    request: &CodexRequest,
) -> Result<(), IsolationSessionError> {
    if !request.policy.readwrite_paths.is_empty()
        || !request.policy.readonly_paths.is_empty()
        || !request.policy.denied_paths.is_empty()
    {
        return Err(IsolationSessionError::Policy(
            ERR_FILESYSTEM_POLICY.to_string(),
        ));
    }
    validate_network_and_proxy_policy(request)
}

/// Shape check for an `IsolationSessionUser` bundle: `upn` must contain
/// `@` not at either boundary; `wam_token` must be non-empty. Surfaces
/// shape errors as `policy_validation` so they appear as structured
/// wire-format errors at the dispatch boundary.
pub(super) fn validate_isolation_session_user(user: &IsolationSessionUser) -> Result<(), MxcError> {
    let upn = user.upn.trim();
    if upn.is_empty() || !upn.contains('@') || upn.starts_with('@') || upn.ends_with('@') {
        return Err(MxcError::policy_validation(format!(
            "user.upn must be a UPN containing '@' (got {:?})",
            user.upn
        )));
    }
    if user.wam_token.is_empty() {
        return Err(MxcError::policy_validation(
            "user.wamToken must not be empty",
        ));
    }
    Ok(())
}

fn validate_network_and_proxy_policy(request: &CodexRequest) -> Result<(), IsolationSessionError> {
    if !request.policy.allowed_hosts.is_empty()
        || !request.policy.blocked_hosts.is_empty()
        || request.policy.default_network_policy != NetworkPolicy::Allow
    {
        return Err(IsolationSessionError::Policy(
            ERR_NETWORK_POLICY.to_string(),
        ));
    }
    if request.policy.network_proxy.is_enabled() {
        return Err(IsolationSessionError::Policy(ERR_PROXY_POLICY.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ContainerPolicy, ProxyAddress, ProxyConfig};
    use crate::mxc_error::MxcErrorCode;

    fn assert_policy_err_contains(err: IsolationSessionError, expected: &str) {
        match err {
            IsolationSessionError::Policy(msg) => {
                assert!(msg.contains(expected), "expected '{}' in {}", expected, msg)
            }
            other => panic!("expected Policy variant, got {:?}", other),
        }
    }

    // ====== Phase-specific policy validation ======
    //
    // Filesystem fields behave differently per phase; network and proxy
    // policy share `validate_network_and_proxy_policy` and behave the
    // same at every phase. Coverage strategy: filesystem tests on both
    // phase-specific helpers; network/proxy tests split across them so
    // every branch of the shared helper runs at least once.

    #[test]
    fn provision_policy_accepts_readwrite_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_provision_policy(&request).is_ok());
    }

    #[test]
    fn provision_policy_accepts_readonly_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_provision_policy(&request).is_ok());
    }

    #[test]
    fn provision_policy_accepts_readwrite_and_readonly_together() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                readonly_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_provision_policy(&request).is_ok());
    }

    #[test]
    fn provision_policy_rejects_denied_paths() {
        let request = CodexRequest {
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
        let request = CodexRequest {
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
    fn provision_policy_rejects_network_policy() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                allowed_hosts: vec!["example.com".to_string()],
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
    fn provision_policy_rejects_proxy() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                network_proxy: ProxyConfig {
                    address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
                    builtin_test_server: false,
                },
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request).unwrap_err(),
            ERR_PROXY_POLICY,
        );
    }

    #[test]
    fn post_provision_policy_rejects_readwrite_paths() {
        let request = CodexRequest {
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
        let request = CodexRequest {
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
        let request = CodexRequest {
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
    fn post_provision_policy_rejects_blocked_hosts() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                blocked_hosts: vec!["evil.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn post_provision_policy_rejects_network_block_policy() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Block,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn post_provision_policy_allows_defaults() {
        let request = CodexRequest::default();
        assert!(validate_post_provision_policy(&request).is_ok());
    }

    // ====== IsolationSessionUser shape validation ======

    fn well_formed_user() -> IsolationSessionUser {
        IsolationSessionUser {
            upn: "alice@contoso.com".to_string(),
            wam_token: "tok".to_string(),
        }
    }

    #[test]
    fn validate_isolation_session_user_accepts_well_formed_bundle() {
        validate_isolation_session_user(&well_formed_user()).unwrap();
    }

    #[test]
    fn validate_isolation_session_user_rejects_upn_without_at() {
        let user = IsolationSessionUser {
            upn: "alice".to_string(),
            wam_token: "tok".to_string(),
        };
        let err = validate_isolation_session_user(&user).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
        assert!(err.message.contains("upn"), "got {}", err.message);
    }

    #[test]
    fn validate_isolation_session_user_rejects_upn_at_at_start() {
        let user = IsolationSessionUser {
            upn: "@contoso.com".to_string(),
            wam_token: "tok".to_string(),
        };
        let err = validate_isolation_session_user(&user).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_isolation_session_user_rejects_upn_at_at_end() {
        let user = IsolationSessionUser {
            upn: "alice@".to_string(),
            wam_token: "tok".to_string(),
        };
        let err = validate_isolation_session_user(&user).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_isolation_session_user_rejects_empty_upn() {
        let user = IsolationSessionUser {
            upn: String::new(),
            wam_token: "tok".to_string(),
        };
        let err = validate_isolation_session_user(&user).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_isolation_session_user_rejects_empty_wam_token() {
        let user = IsolationSessionUser {
            upn: "alice@contoso.com".to_string(),
            wam_token: String::new(),
        };
        let err = validate_isolation_session_user(&user).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
        assert!(err.message.contains("wamToken"), "got {}", err.message);
    }
}
