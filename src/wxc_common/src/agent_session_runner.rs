// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `AgentSessionRunner` — executes scripts in an IsoEnvBroker Agent Session.
//!
//! Uses the `Windows.AI.IsolationEnvironment.Session` WinRT API to create an
//! isolated Windows session with a dedicated agent user account and run
//! processes within it.
//!
//! This module has two layers:
//! - `AgentSessionManager`: reusable core, methods map 1:1 to the Session API lifecycle.
//! - `AgentSessionRunner`: thin `ScriptRunner` impl for v0.1 that calls all lifecycle
//!   steps per invocation.

// TODO: remove once AgentSessionRunner::run() is implemented (CP6).
#![allow(dead_code)]

use crate::models::{CodexRequest, NetworkPolicy};

// -- Error messages for unsupported policy fields ----------------------------

pub(crate) const ERR_FILESYSTEM_POLICY: &str =
    "filesystem policy is not supported by the agent session backend";
pub(crate) const ERR_NETWORK_POLICY: &str =
    "network policy is not supported by the agent session backend";
pub(crate) const ERR_PROXY_POLICY: &str =
    "network proxy is not supported by the agent session backend";

/// Validates that the request does not contain policy fields unsupported by
/// the agent session backend. Returns `Ok(())` if valid, or `Err(message)`.
pub(crate) fn validate_policy(request: &CodexRequest) -> Result<(), String> {
    if !request.policy.readwrite_paths.is_empty()
        || !request.policy.readonly_paths.is_empty()
        || !request.policy.denied_paths.is_empty()
    {
        return Err(ERR_FILESYSTEM_POLICY.to_string());
    }
    if !request.policy.allowed_hosts.is_empty()
        || !request.policy.blocked_hosts.is_empty()
        || request.policy.default_network_policy != NetworkPolicy::Allow
    {
        return Err(ERR_NETWORK_POLICY.to_string());
    }
    if request.policy.network_proxy.is_enabled() {
        return Err(ERR_PROXY_POLICY.to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CodexRequest, ContainerPolicy, NetworkPolicy, ProxyAddress, ProxyConfig};

    #[test]
    fn policy_rejects_readwrite_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_FILESYSTEM_POLICY));
    }

    #[test]
    fn policy_rejects_readonly_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_FILESYSTEM_POLICY));
    }

    #[test]
    fn policy_rejects_denied_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                denied_paths: vec!["C:\\secret".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_FILESYSTEM_POLICY));
    }

    #[test]
    fn policy_rejects_allowed_hosts() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                allowed_hosts: vec!["example.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_NETWORK_POLICY));
    }

    #[test]
    fn policy_rejects_blocked_hosts() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                blocked_hosts: vec!["evil.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_NETWORK_POLICY));
    }

    #[test]
    fn policy_rejects_network_block_policy() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Block,
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_NETWORK_POLICY));
    }

    #[test]
    fn policy_rejects_proxy() {
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
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_PROXY_POLICY));
    }

    #[test]
    fn policy_allows_defaults() {
        let request = CodexRequest::default();
        assert!(validate_policy(&request).is_ok());
    }
}
