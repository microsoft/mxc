// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_common::models::{ExecutionRequest, NetworkAction, ScriptResponse};
use crate::mxc_common::mxc_error::MxcError;

/// Declares which optional network policy features a backend enforces.
///
/// Backends compose the named feature constants with `|`. Shared validation
/// rejects unsupported requests before backend-specific validation or process
/// creation runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetworkPolicySupport(u8);

impl NetworkPolicySupport {
    /// Support for the outbound network default policy.
    pub const EGRESS_DEFAULT: Self = Self(1 << 4);

    /// Support for CIDR, protocol, and port allow/deny rules.
    pub const EGRESS_RULES: Self = Self(1 << 0);

    /// Support for the inbound network default policy.
    pub const INGRESS_DEFAULT: Self = Self(1 << 1);

    /// Support for bidirectional host-loopback access.
    pub const HOST_LOOPBACK: Self = Self(1 << 2);

    /// Support for the runtime proxy endpoint, with backend-specific reachability constraints.
    pub const RUNTIME_PROXY: Self = Self(1 << 3);

    /// Support for restricting a ProcessContainer proxy to a named peer.
    pub const PROXY_PEER_IDENTITY: Self = Self(1 << 5);

    /// A backend that fully supports every optional network policy feature.
    pub const ALL: Self = Self(
        Self::EGRESS_DEFAULT.0
            | Self::EGRESS_RULES.0
            | Self::INGRESS_DEFAULT.0
            | Self::HOST_LOOPBACK.0
            | Self::RUNTIME_PROXY.0
            | Self::PROXY_PEER_IDENTITY.0,
    );

    /// Returns whether all features in `required` are supported.
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

impl std::ops::BitOr for NetworkPolicySupport {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Reject network policy features that the selected backend cannot enforce.
pub fn validate_network_policy_support(
    request: &ExecutionRequest,
    support: NetworkPolicySupport,
) -> Result<(), ScriptResponse> {
    let directional_posture_supplied = request.policy.network_mode_specified
        || (request.policy.network_egress.is_some() && request.policy.network_proxy.is_enabled());

    if !support.contains(NetworkPolicySupport::EGRESS_DEFAULT)
        && request
            .policy
            .network_egress
            .as_ref()
            .is_some_and(|egress| {
                directional_posture_supplied || egress.default == NetworkAction::Allow
            })
    {
        return Err(ScriptResponse::rejected(
            "network.egress.default is not supported by the selected backend",
        ));
    }
    if !support.contains(NetworkPolicySupport::EGRESS_RULES)
        && request
            .policy
            .network_egress
            .as_ref()
            .is_some_and(|egress| !egress.allow.is_empty() || !egress.deny.is_empty())
    {
        return Err(ScriptResponse::rejected(
            "network.egress allow/deny rules are not supported by the selected backend",
        ));
    }

    if !support.contains(NetworkPolicySupport::INGRESS_DEFAULT)
        && request
            .policy
            .network_ingress
            .as_ref()
            .is_some_and(|ingress| {
                directional_posture_supplied || ingress.default == NetworkAction::Allow
            })
    {
        return Err(ScriptResponse::rejected(
            "network.ingress.default is not supported by the selected backend",
        ));
    }
    if !support.contains(NetworkPolicySupport::HOST_LOOPBACK)
        && request
            .policy
            .network_ingress
            .as_ref()
            .is_some_and(|ingress| {
                directional_posture_supplied || ingress.host_loopback == NetworkAction::Allow
            })
    {
        return Err(ScriptResponse::rejected(
            "network.ingress.hostLoopback is not supported by the selected backend",
        ));
    }
    if !support.contains(NetworkPolicySupport::PROXY_PEER_IDENTITY)
        && request.policy.allowed_proxy_peer.is_some()
    {
        return Err(ScriptResponse::rejected(
            "processContainer.network.allowedProxyPeer is not supported by the selected backend",
        ));
    }

    if !support.contains(NetworkPolicySupport::RUNTIME_PROXY)
        && request.policy.runtime_network_proxy_specified
    {
        return Err(ScriptResponse::rejected(
            "runtimeConfig.networkProxy is not supported by the selected backend",
        ));
    }

    Ok(())
}

/// Reject network policy features unsupported by a state-aware backend.
pub fn validate_state_aware_network_policy_support(
    request: &ExecutionRequest,
    support: NetworkPolicySupport,
) -> Result<(), MxcError> {
    validate_network_policy_support(request, support)
        .map_err(|response| MxcError::policy_validation(response.error_message))
}

/// Validates non-backend-specific parts of the request (e.g. non-empty script).
pub fn validate_common(request: &ExecutionRequest) -> Result<(), ScriptResponse> {
    if request.script_code.is_empty() {
        return Err(ScriptResponse::error("Script content must not be empty."));
    }

    if !request.policy.enumerate_paths.is_empty()
        && request.containment != crate::mxc_common::models::ContainmentBackend::ProcessContainer
    {
        return Err(ScriptResponse::error(
            "processContainer.filesystem.enumeratePaths is supported only by the Windows \
             ProcessContainer backend",
        ));
    }

    Ok(())
}

/// Cross-backend invariants for state-aware `exec`. The dispatcher calls this
/// before the backend's own `validate_exec` hook. Only the exec phase has a
/// common-check today (a non-empty `process.commandLine`).
pub fn validate_exec_common(request: &ExecutionRequest) -> Result<(), MxcError> {
    if request.script_code.is_empty() {
        return Err(MxcError::malformed_request(
            "exec phase requires a non-empty process.commandLine",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{
        ExecutionRequest, NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkRule,
        ProxyAddress, ProxyConfig,
    };
    use crate::mxc_common::mxc_error::MxcErrorCode;

    #[test]
    fn rejects_empty_script() {
        let req = ExecutionRequest {
            script_code: String::new(),
            ..Default::default()
        };
        assert!(validate_common(&req).is_err());
    }

    #[test]
    fn accepts_valid_script() {
        let req = ExecutionRequest {
            script_code: "echo hello".to_string(),
            ..Default::default()
        };
        assert!(validate_common(&req).is_ok());
    }

    #[test]
    fn enumerate_paths_reject_non_process_container_one_shot_backends() {
        for containment in [
            crate::mxc_common::models::ContainmentBackend::Bubblewrap,
            crate::mxc_common::models::ContainmentBackend::Lxc,
            crate::mxc_common::models::ContainmentBackend::Wslc,
        ] {
            let req = ExecutionRequest {
                script_code: "echo hello".to_string(),
                containment: containment.clone(),
                policy: crate::mxc_common::models::ContainerPolicy {
                    enumerate_paths: vec!["C:\\tools".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            };

            let error = validate_common(&req).expect_err("backend must not ignore enumeratePaths");

            assert!(
                error.error_message.contains("Windows ProcessContainer"),
                "{containment:?}: {}",
                error.error_message
            );
        }
    }

    #[test]
    fn accepts_full_config() {
        let req = ExecutionRequest {
            script_code: "print('test')".to_string(),
            working_directory: "C:\\temp".to_string(),
            script_timeout: 5000,
            container_id: "Test".to_string(),
            ..Default::default()
        };
        assert!(validate_common(&req).is_ok());
    }

    #[test]
    fn error_mentions_empty() {
        let req = ExecutionRequest::default();
        let err = validate_common(&req).unwrap_err();
        assert!(
            err.error_message.contains("empty"),
            "Error should mention empty: {}",
            err.error_message
        );
    }

    #[test]
    fn validate_exec_common_rejects_empty_command_line() {
        let req = ExecutionRequest::default();
        let err = validate_exec_common(&req).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }

    #[test]
    fn validate_exec_common_accepts_non_empty_command_line() {
        let req = ExecutionRequest {
            script_code: "echo hello".to_string(),
            ..Default::default()
        };
        assert!(validate_exec_common(&req).is_ok());
    }

    #[test]
    fn network_support_reports_egress_error_before_ingress_error() {
        let mut request = ExecutionRequest::default();
        request.policy.network_mode_specified = true;
        request.policy.network_egress = Some(NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(NetworkIngressPolicy::default());

        let error =
            validate_network_policy_support(&request, NetworkPolicySupport::default()).unwrap_err();
        assert_eq!(
            error.error_message,
            "network.egress.default is not supported by the selected backend"
        );
    }

    #[test]
    fn network_support_rejects_unimplemented_features() {
        let mut request = ExecutionRequest::default();
        request.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        let error =
            validate_network_policy_support(&request, NetworkPolicySupport::default()).unwrap_err();
        assert!(error.error_message.contains("network.egress.default"));

        let mut request = ExecutionRequest::default();
        request.policy.network_egress = Some(NetworkEgressPolicy {
            allow: vec![NetworkRule::default()],
            ..Default::default()
        });
        let error = validate_network_policy_support(&request, NetworkPolicySupport::EGRESS_DEFAULT)
            .unwrap_err();
        assert!(error.error_message.contains("allow/deny rules"));

        let mut request = ExecutionRequest::default();
        request.policy.network_ingress = Some(NetworkIngressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        let error = validate_network_policy_support(
            &request,
            NetworkPolicySupport::EGRESS_DEFAULT | NetworkPolicySupport::EGRESS_RULES,
        )
        .unwrap_err();
        assert!(error.error_message.contains("network.ingress.default"));

        let mut request = ExecutionRequest::default();
        request.policy.network_ingress = Some(NetworkIngressPolicy {
            host_loopback: NetworkAction::Allow,
            ..Default::default()
        });
        let error = validate_network_policy_support(
            &request,
            NetworkPolicySupport::EGRESS_DEFAULT
                | NetworkPolicySupport::EGRESS_RULES
                | NetworkPolicySupport::INGRESS_DEFAULT,
        )
        .unwrap_err();
        assert!(error.error_message.contains("network.ingress.hostLoopback"));

        let mut request = ExecutionRequest::default();
        request.policy.runtime_network_proxy_specified = true;
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
        };
        let error = validate_network_policy_support(
            &request,
            NetworkPolicySupport::EGRESS_DEFAULT
                | NetworkPolicySupport::EGRESS_RULES
                | NetworkPolicySupport::INGRESS_DEFAULT
                | NetworkPolicySupport::HOST_LOOPBACK,
        )
        .unwrap_err();
        assert!(error.error_message.contains("runtimeConfig.networkProxy"));

        let mut request = ExecutionRequest::default();
        request.policy.allowed_proxy_peer = Some("Contoso.Proxy_123".to_string());
        let error = validate_network_policy_support(
            &request,
            NetworkPolicySupport::EGRESS_DEFAULT
                | NetworkPolicySupport::EGRESS_RULES
                | NetworkPolicySupport::INGRESS_DEFAULT
                | NetworkPolicySupport::HOST_LOOPBACK
                | NetworkPolicySupport::RUNTIME_PROXY,
        )
        .unwrap_err();
        assert!(error.error_message.contains("allowedProxyPeer"));
    }

    #[test]
    fn network_support_accepts_declared_features() {
        let mut request = ExecutionRequest::default();
        request.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            allow: vec![NetworkRule::default()],
            ..Default::default()
        });
        request.policy.network_ingress = Some(NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Allow,
        });
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
        };
        request.policy.runtime_network_proxy_specified = true;
        request.policy.allowed_proxy_peer = Some("Contoso.Proxy_123".to_string());
        assert!(validate_network_policy_support(&request, NetworkPolicySupport::ALL,).is_ok());
    }

    #[test]
    fn partial_network_support_rejects_undeclared_directional_defaults() {
        let mut request = ExecutionRequest::default();
        request.policy.network_egress = Some(NetworkEgressPolicy::default());
        request.policy.network_mode_specified = true;
        let error = validate_network_policy_support(&request, NetworkPolicySupport::RUNTIME_PROXY)
            .unwrap_err();
        assert!(error.error_message.contains("network.egress.default"));

        request.policy.network_egress = None;
        request.policy.network_ingress = Some(NetworkIngressPolicy::default());
        request.policy.network_mode_specified = true;
        let error = validate_network_policy_support(&request, NetworkPolicySupport::EGRESS_DEFAULT)
            .unwrap_err();
        assert!(error.error_message.contains("network.ingress.default"));
    }

    #[test]
    fn network_support_accepts_implicit_directional_defaults_without_declared_features() {
        let mut request = ExecutionRequest::default();
        request.policy.network_egress = Some(NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(NetworkIngressPolicy::default());

        assert!(validate_network_policy_support(&request, NetworkPolicySupport::default()).is_ok());
    }

    #[test]
    fn network_support_features_compose() {
        let support = NetworkPolicySupport::EGRESS_DEFAULT
            | NetworkPolicySupport::EGRESS_RULES
            | NetworkPolicySupport::INGRESS_DEFAULT
            | NetworkPolicySupport::HOST_LOOPBACK
            | NetworkPolicySupport::RUNTIME_PROXY
            | NetworkPolicySupport::PROXY_PEER_IDENTITY;

        assert_eq!(support, NetworkPolicySupport::ALL);
    }

    #[test]
    fn state_aware_network_support_uses_policy_validation_errors() {
        let mut request = ExecutionRequest::default();
        request.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });

        let error =
            validate_state_aware_network_policy_support(&request, NetworkPolicySupport::default())
                .unwrap_err();

        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert!(error.message.contains("network.egress.default"));
    }
}
