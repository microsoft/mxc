// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::models::{
    ExecutionRequest, FailurePhase, NetworkAction, NetworkPolicy, ScriptResponse,
    WorkingDirectoryScope,
};
use crate::mxc_error::MxcError;

/// Declares which optional network policy features a backend enforces.
///
/// Backends compose the named feature constants with `|`. Shared validation
/// rejects unsupported requests before backend-specific validation or process
/// creation runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetworkPolicySupport(u8);

impl NetworkPolicySupport {
    /// Support for the legacy network policy without additive 0.8 features.
    pub const LEGACY: Self = Self(0);

    /// Support for the outbound network default policy.
    pub const EGRESS_DEFAULT: Self = Self(1 << 4);

    /// Support for CIDR, protocol, and port allow/deny rules.
    pub const EGRESS_RULES: Self = Self(1 << 0);

    /// Support for the inbound network default policy.
    pub const INGRESS_DEFAULT: Self = Self(1 << 1);

    /// Support for bidirectional host-loopback access.
    pub const HOST_LOOPBACK: Self = Self(1 << 2);

    /// Support for the runtime loopback proxy endpoint.
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
        return Err(ScriptResponse::error(
            "network.egress.default is not supported by the selected backend",
        ));
    }
    if !support.contains(NetworkPolicySupport::EGRESS_DEFAULT)
        && request
            .policy
            .network_egress
            .as_ref()
            .is_some_and(|egress| egress.default == NetworkAction::Deny)
        && request.policy.default_network_policy == NetworkPolicy::Allow
    {
        return Err(ScriptResponse::error(
            "network.egress.default='deny' conflicts with the legacy outbound policy",
        ));
    }

    if !support.contains(NetworkPolicySupport::EGRESS_RULES)
        && request
            .policy
            .network_egress
            .as_ref()
            .is_some_and(|egress| !egress.allow.is_empty() || !egress.deny.is_empty())
    {
        return Err(ScriptResponse::error(
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
        return Err(ScriptResponse::error(
            "network.ingress.default is not supported by the selected backend",
        ));
    }
    if !support.contains(NetworkPolicySupport::INGRESS_DEFAULT)
        && request
            .policy
            .network_ingress
            .as_ref()
            .is_some_and(|ingress| ingress.default == NetworkAction::Deny)
        && request.policy.allow_local_network
    {
        return Err(ScriptResponse::error(
            "network.ingress.default='deny' conflicts with the legacy inbound policy",
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
        return Err(ScriptResponse::error(
            "network.ingress.hostLoopback is not supported by the selected backend",
        ));
    }
    if !support.contains(NetworkPolicySupport::HOST_LOOPBACK)
        && request
            .policy
            .network_ingress
            .as_ref()
            .is_some_and(|ingress| ingress.host_loopback == NetworkAction::Deny)
        && request.policy.allow_local_network
    {
        return Err(ScriptResponse::error(
            "network.ingress.hostLoopback='deny' conflicts with the legacy inbound policy",
        ));
    }

    if !support.contains(NetworkPolicySupport::PROXY_PEER_IDENTITY)
        && request.policy.allowed_proxy_peer.is_some()
    {
        return Err(ScriptResponse::error(
            "processContainer.network.allowedProxyPeer is not supported by the selected backend",
        ));
    }

    if !support.contains(NetworkPolicySupport::RUNTIME_PROXY)
        && request.policy.runtime_network_proxy_specified
    {
        return Err(ScriptResponse::error(
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

/// First schema version (major, minor) that requires an absolute `process.cwd`.
const ABSOLUTE_CWD_MIN_SCHEMA: (u64, u64) = (0, 9);

/// Reject a relative `process.cwd` from schema 0.9.0-alpha on, where relative
/// means "resolves against the launching process's working directory".
///
/// Absoluteness belongs to the target the path reaches, not the host, so the
/// shape comes from [`ContainmentBackend::working_directory_style`] for
/// `scope`. Earlier schema versions keep the previous behavior.
pub fn validate_working_directory(
    request: &ExecutionRequest,
    scope: WorkingDirectoryScope,
) -> Result<(), String> {
    // Validate the exact string the backends receive: only a genuinely empty
    // value means "omitted", and " /tmp" is relative everywhere.
    let cwd = request.working_directory.as_str();
    if cwd.is_empty() || !schema_requires_absolute_cwd(&request.schema_version) {
        return Ok(());
    }

    let style = request.containment.working_directory_style(scope);
    if style.is_absolute(cwd) {
        return Ok(());
    }

    Err(format!(
        "process.cwd must be an absolute path (e.g. {}), got '{}'. Schema 0.9.0-alpha and \
         later reject a relative working directory because it resolves against the host \
         process's working directory.",
        style.example(),
        crate::config_deserialize::escape_diagnostic_text(cwd)
    ))
}

/// A malformed version is left to the schema-version validator, which owns that
/// diagnostic.
fn schema_requires_absolute_cwd(version: &str) -> bool {
    semver::Version::parse(version)
        .is_ok_and(|parsed| (parsed.major, parsed.minor) >= ABSOLUTE_CWD_MIN_SCHEMA)
}

/// Validates non-backend-specific parts of the request (e.g. non-empty script).
pub fn validate_common(request: &ExecutionRequest) -> Result<(), ScriptResponse> {
    if request.script_code.is_empty() {
        return Err(ScriptResponse::error("Script content must not be empty."));
    }

    // `Rejected` so the SDK surfaces this as `policy_validation`, matching what
    // state-aware `exec` returns for the same cwd.
    validate_working_directory(request, WorkingDirectoryScope::OneShot).map_err(|message| {
        ScriptResponse {
            failure_phase: FailurePhase::Rejected,
            ..ScriptResponse::error(&message)
        }
    })?;

    // Enforce the testing-only-features gate centrally so it applies uniformly
    // to all backends — every backend runs `validate_common` before executing.
    // Currently this gates `network.proxy.builtinTestServer` (a deliberately-
    // permissive test proxy); see `ExecutionRequest::testing_features_enabled`
    // for the rationale behind the dedicated `--allow-testing-features` axis.
    if request.policy.network_proxy.builtin_test_server && !request.testing_features_enabled {
        return Err(ScriptResponse::error(
            "network.proxy.builtinTestServer is a testing-only feature and requires the \
             --allow-testing-features flag. For production, point network.proxy at a real \
             HTTP proxy via 'localhost' or 'url'.",
        ));
    }

    Ok(())
}

/// Cross-backend invariants for state-aware `exec`. The dispatcher calls this
/// before the backend's own `validate_exec` hook.
pub fn validate_exec_common(request: &ExecutionRequest) -> Result<(), MxcError> {
    if request.script_code.is_empty() {
        return Err(MxcError::malformed_request(
            "exec phase requires a non-empty process.commandLine",
        ));
    }
    validate_working_directory(request, WorkingDirectoryScope::Exec)
        .map_err(MxcError::policy_validation)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        ContainmentBackend, ExecutionRequest, NetworkAction, NetworkEgressPolicy,
        NetworkIngressPolicy, NetworkRule, ProxyAddress, ProxyConfig,
    };
    use crate::mxc_error::MxcErrorCode;

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
    fn rejects_builtin_test_server_without_testing_features() {
        let mut req = ExecutionRequest {
            script_code: "echo hi".to_string(),
            ..Default::default()
        };
        req.policy.network_proxy.builtin_test_server = true;
        req.testing_features_enabled = false;

        let err = validate_common(&req).unwrap_err();
        assert!(
            err.error_message.contains("builtinTestServer")
                && err.error_message.contains("--allow-testing-features"),
            "expected testing-gate error, got: {}",
            err.error_message
        );
    }

    #[test]
    fn accepts_builtin_test_server_with_testing_features() {
        let mut req = ExecutionRequest {
            script_code: "echo hi".to_string(),
            ..Default::default()
        };
        req.policy.network_proxy.builtin_test_server = true;
        req.testing_features_enabled = true;

        assert!(validate_common(&req).is_ok());
    }

    fn request_with_cwd(
        version: &str,
        containment: ContainmentBackend,
        cwd: &str,
    ) -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo hi".to_string(),
            schema_version: version.to_string(),
            containment,
            working_directory: cwd.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn rejects_relative_cwd_on_schema_0_9_for_every_backend() {
        let backends = [
            ContainmentBackend::ProcessContainer,
            ContainmentBackend::WindowsSandbox,
            ContainmentBackend::IsolationSession,
            ContainmentBackend::Lxc,
            ContainmentBackend::Bubblewrap,
            ContainmentBackend::Seatbelt,
            ContainmentBackend::Wslc,
            ContainmentBackend::MicroVm,
            ContainmentBackend::Hyperlight,
            ContainmentBackend::Vm,
        ];
        for backend in backends {
            for cwd in ["sub", ".", "..\\sibling", "./sub", "C:relative"] {
                let req = request_with_cwd("0.9.0-alpha", backend.clone(), cwd);
                let resp = validate_common(&req)
                    .expect_err(&format!("{} accepted '{cwd}'", backend.wire_name()));
                assert!(
                    resp.error_message
                        .contains("process.cwd must be an absolute path"),
                    "unexpected message: {}",
                    resp.error_message
                );
                // Caller-fixable, so the SDK reports `policy_validation`.
                assert_eq!(resp.failure_phase, FailurePhase::Rejected);
            }
        }
    }

    #[test]
    fn a_rejected_cwd_is_escaped_before_it_reaches_the_diagnostic() {
        let req = request_with_cwd(
            "0.9.0-alpha",
            ContainmentBackend::Bubblewrap,
            "sub\nerror: forged\u{202e}",
        );
        let message = validate_common(&req).unwrap_err().error_message;
        assert!(!message.contains('\n'), "raw newline in: {message}");
        assert!(message.contains("\\n") && message.contains("\\u{202e}"));
    }

    #[test]
    fn only_seatbelt_accepts_a_tilde_cwd() {
        // Everything else hands the path to `cd -- "$1"` or `--chdir`, which
        // treat `~` as an ordinary relative name.
        for backend in [ContainmentBackend::Lxc, ContainmentBackend::Bubblewrap] {
            for cwd in ["~", "~/workspace"] {
                let req = request_with_cwd("0.9.0-alpha", backend.clone(), cwd);
                assert!(
                    validate_common(&req).is_err(),
                    "{} accepted '{cwd}'",
                    backend.wire_name()
                );
            }
        }

        let exec = request_with_cwd("0.9.0-alpha", ContainmentBackend::Wslc, "~/workspace");
        assert!(validate_exec_common(&exec).is_err());

        let seatbelt = request_with_cwd("0.9.0-alpha", ContainmentBackend::Seatbelt, "~/workspace");
        assert!(validate_common(&seatbelt).is_ok());
    }

    #[test]
    fn accepts_absolute_cwd_in_the_backend_path_style() {
        let cases = [
            (ContainmentBackend::ProcessContainer, "C:\\workspace"),
            (ContainmentBackend::ProcessContainer, "C:/workspace"),
            (ContainmentBackend::ProcessContainer, "\\\\server\\share"),
            (ContainmentBackend::Seatbelt, "/workspace"),
            (ContainmentBackend::Seatbelt, "~/workspace"),
            (ContainmentBackend::Bubblewrap, "/workspace"),
            (ContainmentBackend::Wslc, "C:\\workspace"),
        ];
        for (backend, cwd) in cases {
            let req = request_with_cwd("0.9.0-alpha", backend.clone(), cwd);
            assert!(
                validate_common(&req).is_ok(),
                "{} rejected '{cwd}'",
                backend.wire_name()
            );
        }
    }

    #[test]
    fn rejects_a_unix_cwd_on_a_windows_backend_and_the_reverse() {
        // `/tmp` on Windows is relative to the launching process's drive.
        let windows = request_with_cwd("0.9.0-alpha", ContainmentBackend::ProcessContainer, "/tmp");
        assert!(validate_common(&windows).is_err());

        let unix = request_with_cwd("0.9.0-alpha", ContainmentBackend::Seatbelt, "C:\\tmp");
        assert!(validate_common(&unix).is_err());
    }

    #[test]
    fn wslc_reads_cwd_against_a_different_target_per_phase() {
        // One-shot takes a Windows host path; exec takes the in-container path.
        let host_path = request_with_cwd("0.9.0-alpha", ContainmentBackend::Wslc, "C:\\workspace");
        assert!(validate_common(&host_path).is_ok());
        assert!(validate_exec_common(&host_path).is_err());

        let container_path =
            request_with_cwd("0.9.0-alpha", ContainmentBackend::Wslc, "/workspace");
        assert!(validate_common(&container_path).is_err());
        assert!(validate_exec_common(&container_path).is_ok());
    }

    #[test]
    fn relative_cwd_is_accepted_below_schema_0_9() {
        for version in ["", "0.6.0-alpha", "0.8.0-alpha"] {
            let req = request_with_cwd(version, ContainmentBackend::ProcessContainer, "sub");
            assert!(
                validate_common(&req).is_ok(),
                "version '{version}' rejected"
            );
        }
    }

    #[test]
    fn relative_cwd_is_rejected_above_schema_0_9() {
        for version in ["0.9.0-dev", "0.10.0", "1.0.0"] {
            let req = request_with_cwd(version, ContainmentBackend::ProcessContainer, "sub");
            assert!(
                validate_common(&req).is_err(),
                "version '{version}' accepted"
            );
        }
    }

    #[test]
    fn an_omitted_cwd_is_still_accepted_on_schema_0_9() {
        let req = request_with_cwd("0.9.0-alpha", ContainmentBackend::ProcessContainer, "");
        assert!(validate_common(&req).is_ok());
    }

    #[test]
    fn state_aware_exec_rejects_a_relative_cwd_as_policy_validation() {
        let req = request_with_cwd("0.9.0-alpha", ContainmentBackend::IsolationSession, "sub");
        let error = validate_exec_common(&req).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert!(error.message.contains("process.cwd"), "got {error:?}");
    }

    #[test]
    fn network_support_rejects_unimplemented_features() {
        let mut request = ExecutionRequest::default();
        request.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        let error =
            validate_network_policy_support(&request, NetworkPolicySupport::LEGACY).unwrap_err();
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
            builtin_test_server: false,
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
            builtin_test_server: false,
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
    fn network_support_rejects_inconsistent_dual_model_defaults() {
        let mut request = ExecutionRequest::default();
        request.policy.network_egress = Some(NetworkEgressPolicy::default());
        request.policy.default_network_policy = NetworkPolicy::Allow;
        let error =
            validate_network_policy_support(&request, NetworkPolicySupport::LEGACY).unwrap_err();
        assert!(error.error_message.contains("legacy outbound policy"));

        let mut request = ExecutionRequest::default();
        request.policy.network_ingress = Some(NetworkIngressPolicy::default());
        request.policy.allow_local_network = true;
        let error = validate_network_policy_support(&request, NetworkPolicySupport::HOST_LOOPBACK)
            .unwrap_err();
        assert!(error.error_message.contains("network.ingress.default"));
        assert!(error.error_message.contains("legacy inbound policy"));

        let mut request = ExecutionRequest::default();
        request.policy.network_ingress = Some(NetworkIngressPolicy::default());
        request.policy.allow_local_network = true;
        let error =
            validate_network_policy_support(&request, NetworkPolicySupport::INGRESS_DEFAULT)
                .unwrap_err();
        assert!(error.error_message.contains("network.ingress.hostLoopback"));
        assert!(error.error_message.contains("legacy inbound policy"));
    }

    #[test]
    fn network_support_accepts_implicit_directional_defaults_for_legacy_backends() {
        let mut request = ExecutionRequest::default();
        request.policy.network_egress = Some(NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(NetworkIngressPolicy::default());

        assert!(validate_network_policy_support(&request, NetworkPolicySupport::LEGACY).is_ok());
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
            validate_state_aware_network_policy_support(&request, NetworkPolicySupport::LEGACY)
                .unwrap_err();

        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert!(error.message.contains("network.egress.default"));
    }
}
