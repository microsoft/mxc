// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Policy validation for the state-aware WSLc backend.
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
//! | `allowed` / `blocked` hosts | rejected (no host filtering) | rejected                   | rejected                   |
//! | `default_network_policy`    | honoured (None / Bridged)    | rejected if non-default    | rejected if non-default    |
//! | `network.proxy`             | rejected (applies at exec)   | rejected                   | honoured (cooperative env) |
//!
//! [^1]: a standalone `denied_path` is honoured by container isolation (unlisted
//! host paths are simply never mounted); only a denied path nested under a
//! mounted `rw`/`ro` parent is rejected, because WSLc has no overlay primitive
//! to mask a subtree of a mounted volume.

use wxc_common::models::ExecutionRequest;
use wxc_common::mxc_error::MxcError;

use crate::policy_mapping::validate_denied_path_overlap;

const ERR_FILESYSTEM_IMMUTABLE: &str =
    "filesystem policy (readwritePaths / readonlyPaths / deniedPaths) is bound to the provision \
     phase and cannot be changed by the WSLc backend after provisioning";
const ERR_HOST_FILTERING: &str =
    "per-host network filtering (allowedHosts / blockedHosts) is not supported by the WSLc backend";
const ERR_NETWORK_IMMUTABLE: &str =
    "network mode is bound to the provision phase and cannot be changed by the WSLc backend after \
     provisioning";
const ERR_PROXY_AT_PROVISION: &str =
    "network.proxy is applied per-exec by the WSLc backend; set it on the exec phase, not provision";
const ERR_PROXY_AT_PHASE: &str =
    "network.proxy is only honoured on the exec phase by the WSLc backend";
const ERR_PROXY_URL_FORM: &str =
    "WSLc: network.proxy requires the 'url' form (a routable proxy URL); the localhost and \
     builtinTestServer forms are not supported because a WSLc container runs in its own network \
     namespace";

/// Validate the request for the provision phase. `rw` / `ro` paths become
/// volume mounts and `default_network_policy` selects the container network
/// mode; both are honoured here. Overlapping denied paths, host filtering, and
/// a provision-phase proxy are rejected.
pub(crate) fn validate_provision_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    validate_denied_path_overlap(
        &request.policy.readwrite_paths,
        &request.policy.readonly_paths,
        &request.policy.denied_paths,
    )
    .map_err(MxcError::policy_validation)?;
    reject_host_filtering(request)?;
    if request.policy.network_proxy.is_enabled() {
        return Err(MxcError::policy_validation(ERR_PROXY_AT_PROVISION));
    }
    Ok(())
}

/// Validate the request for start / stop / deprovision. These phases carry no
/// applicable policy: filesystem and network mode are fixed at provision and
/// the proxy is an exec-time concern.
pub(crate) fn validate_post_provision_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    reject_filesystem_policy(request)?;
    reject_host_filtering(request)?;
    reject_post_provision_network_mode(request)?;
    if request.policy.network_proxy.is_enabled() {
        return Err(MxcError::policy_validation(ERR_PROXY_AT_PHASE));
    }
    Ok(())
}

/// Validate the request for the exec phase. Filesystem and network mode are
/// fixed at provision (rejected here); the cooperative proxy is honoured and
/// must be in `url` form so a routable value reaches the container.
pub(crate) fn validate_exec_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    reject_filesystem_policy(request)?;
    reject_host_filtering(request)?;
    reject_post_provision_network_mode(request)?;
    if request.policy.network_proxy.is_enabled() && exec_proxy_url(request).is_none() {
        return Err(MxcError::policy_validation(ERR_PROXY_URL_FORM));
    }
    Ok(())
}

/// The routable proxy URL to inject at exec, or `None` when the proxy is
/// disabled or specified in a non-`url` form (localhost / builtinTestServer).
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
        || !request.policy.denied_paths.is_empty()
    {
        return Err(MxcError::policy_validation(ERR_FILESYSTEM_IMMUTABLE));
    }
    Ok(())
}

fn reject_host_filtering(request: &ExecutionRequest) -> Result<(), MxcError> {
    if !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty() {
        return Err(MxcError::policy_validation(ERR_HOST_FILTERING));
    }
    Ok(())
}

/// Reject any network *mode* field supplied after provision. The network
/// posture (`defaultPolicy` / `enforcementMode` / `allowLocalNetwork` / host
/// lists) is bound to the provision phase; presence — not value — is checked so
/// an explicit `defaultPolicy: "block"` (indistinguishable from an omitted
/// block by value) is rejected too. The cooperative proxy is a separate
/// exec-time concern handled by the callers.
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
    use wxc_common::models::{ContainerPolicy, NetworkPolicy, ProxyAddress, ProxyConfig};
    use wxc_common::mxc_error::MxcErrorCode;

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
            builtin_test_server: false,
        }
    }

    fn non_url_proxy() -> ProxyConfig {
        ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8888)),
            builtin_test_server: false,
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

    // ---- provision ----

    #[test]
    fn provision_accepts_rw_ro_and_network_mode() {
        let req = request_with_policy(ContainerPolicy {
            readwrite_paths: vec!["C:\\src".to_string()],
            readonly_paths: vec!["C:\\data".to_string()],
            default_network_policy: NetworkPolicy::Allow,
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
    fn provision_rejects_host_filtering() {
        let req = request_with_policy(ContainerPolicy {
            allowed_hosts: vec!["example.com".to_string()],
            ..Default::default()
        });
        assert_policy_validation(validate_provision_policy(&req).unwrap_err(), "allowedHosts");
    }

    #[test]
    fn provision_rejects_proxy() {
        let req = request_with_policy(ContainerPolicy {
            network_proxy: url_proxy(),
            ..Default::default()
        });
        assert_policy_validation(validate_provision_policy(&req).unwrap_err(), "exec phase");
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
        // Explicit `defaultPolicy: "block"` (value equals the default) must still
        // be rejected post-provision: presence, not value, is what matters.
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
}
