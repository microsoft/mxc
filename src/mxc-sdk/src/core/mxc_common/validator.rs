// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_common::error::WxcError;
use crate::mxc_common::models::{
    ContainmentBackend, ExecutionRequest, NetworkAction, PortMapping, ResourcePriority,
    ScriptResponse,
};
use crate::mxc_common::mxc_error::MxcError;
use std::collections::HashSet;

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

/// Declares which resource limits a backend enforces.
///
/// Every backend reports resource usage when it declares any support, so a
/// request with an empty `resources` object is accepted exactly where some
/// limit could be.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourcePolicySupport(u8);

impl ResourcePolicySupport {
    /// Support for `resources.cpuTimeMs`.
    pub const CPU_TIME: Self = Self(1 << 0);

    /// Support for `resources.memoryMb`.
    pub const MEMORY: Self = Self(1 << 1);

    /// Support for `resources.maxProcesses`.
    pub const MAX_PROCESSES: Self = Self(1 << 2);

    /// Support for a non-normal `resources.priority`.
    pub const PRIORITY: Self = Self(1 << 3);

    /// A backend that enforces every resource limit.
    pub const ALL: Self =
        Self(Self::CPU_TIME.0 | Self::MEMORY.0 | Self::MAX_PROCESSES.0 | Self::PRIORITY.0);

    /// The resource limits `backend` enforces. A backend that enforces any
    /// limit also reports resource usage.
    ///
    /// Bubblewrap sets rlimits and a nice value on `bwrap`, which every
    /// process in the sandbox inherits. It has no per-workload process
    /// counter: `RLIMIT_NPROC` counts every process of the user. Seatbelt
    /// does the same on the process it launches, but macOS rejects memory
    /// rlimits (`RLIMIT_DATA`, `RLIMIT_AS`, `RLIMIT_RSS`) with `EINVAL`.
    /// ProcessContainer enforces every limit through the job object its
    /// workload is assigned to before it is resumed.
    pub const fn for_backend(backend: &ContainmentBackend) -> Self {
        match backend {
            ContainmentBackend::Bubblewrap => {
                Self(Self::CPU_TIME.0 | Self::MEMORY.0 | Self::PRIORITY.0)
            }
            ContainmentBackend::Seatbelt => Self(Self::CPU_TIME.0 | Self::PRIORITY.0),
            ContainmentBackend::ProcessContainer => Self::ALL,
            ContainmentBackend::Wslc
            | ContainmentBackend::Lxc
            | ContainmentBackend::Vm
            | ContainmentBackend::MicroVm
            | ContainmentBackend::Hyperlight
            | ContainmentBackend::WindowsSandbox
            | ContainmentBackend::IsolationSession => Self(0),
        }
    }

    /// Returns whether all features in `required` are supported.
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for ResourcePolicySupport {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Reject resource limits that the selected backend cannot enforce.
pub fn validate_resource_policy_support(
    request: &ExecutionRequest,
    support: ResourcePolicySupport,
) -> Result<(), ScriptResponse> {
    let Some(resources) = request.policy.resources.as_ref() else {
        return Ok(());
    };
    let backend = request.containment.wire_name();
    if support.is_empty() {
        return Err(ScriptResponse::rejected(&format!(
            "resources is not supported by the '{backend}' backend"
        )));
    }
    let requested = [
        (
            resources.cpu_time_ms.is_some(),
            ResourcePolicySupport::CPU_TIME,
            "resources.cpuTimeMs",
        ),
        (
            resources.memory_mb.is_some(),
            ResourcePolicySupport::MEMORY,
            "resources.memoryMb",
        ),
        (
            resources.max_processes.is_some(),
            ResourcePolicySupport::MAX_PROCESSES,
            "resources.maxProcesses",
        ),
        (
            resources.priority != ResourcePriority::Normal,
            ResourcePolicySupport::PRIORITY,
            "resources.priority",
        ),
    ];
    for (present, feature, field) in requested {
        if present && !support.contains(feature) {
            return Err(ScriptResponse::rejected(&format!(
                "{field} is not supported by the '{backend}' backend"
            )));
        }
    }
    Ok(())
}

/// Validates non-backend-specific parts of the request (e.g. non-empty script).
pub fn validate_common(request: &ExecutionRequest) -> Result<(), ScriptResponse> {
    if request.script_code.is_empty() {
        return Err(ScriptResponse::error("Script content must not be empty."));
    }

    validate_resource_policy_support(
        request,
        ResourcePolicySupport::for_backend(&request.containment),
    )?;

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

/// Reject WSLC port mappings the WSLC runtime cannot apply.
///
/// The exact JSON contract rejects a zero port and a non-TCP protocol
/// structurally, but a caller building the runtime config directly hands over
/// a plain `u16` and `String`, so the checks have to live here too. The daemon
/// wire format carries no protocol and the worker rebuilds every mapping as
/// TCP, so accepting anything else here would silently apply a different
/// mapping than the caller asked for.
pub fn validate_port_mappings(field_path: &str, mappings: &[PortMapping]) -> Result<(), WxcError> {
    for (index, mapping) in mappings.iter().enumerate() {
        for (name, port) in [
            ("windowsPort", mapping.windows_port),
            ("containerPort", mapping.container_port),
        ] {
            if port == 0 {
                return Err(WxcError::ConfigParse(format!(
                    "{field_path}[{index}]: '{name}' must be > 0"
                )));
            }
        }
        if mapping.protocol != "tcp" {
            return Err(WxcError::ConfigParse(format!(
                "{field_path}[{index}]: 'protocol' must be 'tcp', got '{}'",
                mapping.protocol
            )));
        }
    }

    let mut seen: HashSet<(u16, &str)> = HashSet::with_capacity(mappings.len());
    for mapping in mappings {
        if !seen.insert((mapping.windows_port, mapping.protocol.as_str())) {
            return Err(WxcError::ConfigParse(format!(
                "{field_path}: duplicate windowsPort {} for protocol '{}'",
                mapping.windows_port, mapping.protocol
            )));
        }
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

    fn port_mapping(windows_port: u16, container_port: u16) -> PortMapping {
        PortMapping {
            windows_port,
            container_port,
            protocol: "tcp".to_string(),
        }
    }

    #[test]
    fn port_mapping_messages_name_the_caller_supplied_field_path() {
        for field_path in ["wslc.portMappings", "wslc.provision.portMappings"] {
            let zero = validate_port_mappings(field_path, &[port_mapping(0, 80)]).unwrap_err();
            assert!(
                zero.to_string()
                    .ends_with(&format!("{field_path}[0]: 'windowsPort' must be > 0")),
                "{zero}"
            );

            let duplicate =
                validate_port_mappings(field_path, &[port_mapping(80, 8080), port_mapping(80, 81)])
                    .unwrap_err();
            assert!(
                duplicate.to_string().ends_with(&format!(
                    "{field_path}: duplicate windowsPort 80 for protocol 'tcp'"
                )),
                "{duplicate}"
            );
        }
    }

    #[test]
    fn a_zero_port_outranks_an_earlier_duplicate() {
        // Both surfaces share this helper, so changing the order would reword a
        // user-facing rejection on each of them.
        let mappings = [
            port_mapping(8080, 80),
            port_mapping(8080, 81),
            port_mapping(0, 82),
        ];
        let error = validate_port_mappings("wslc.portMappings", &mappings).unwrap_err();
        assert!(
            error
                .to_string()
                .ends_with("wslc.portMappings[2]: 'windowsPort' must be > 0"),
            "{error}"
        );
    }

    #[test]
    fn distinct_host_ports_and_an_empty_list_are_accepted() {
        assert!(validate_port_mappings("wslc.portMappings", &[]).is_ok());
        assert!(validate_port_mappings(
            "wslc.portMappings",
            &[port_mapping(8080, 80), port_mapping(8081, 80)]
        )
        .is_ok());
    }

    #[test]
    fn a_protocol_the_daemon_cannot_carry_is_rejected() {
        // The daemon wire format drops the protocol and the worker rebuilds
        // every mapping as TCP, so anything else would be applied as something
        // the caller did not ask for.
        for protocol in ["udp", "UDP", "Tcp", "sctp", ""] {
            let mapping = PortMapping {
                windows_port: 8080,
                container_port: 80,
                protocol: protocol.to_string(),
            };
            let error = validate_port_mappings("wslc.portMappings", &[mapping])
                .expect_err("only 'tcp' is applicable");
            assert!(
                error.to_string().contains("'protocol' must be 'tcp'"),
                "{error}"
            );
        }
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

    fn request_with_resources(
        containment: ContainmentBackend,
        resources: crate::mxc_common::models::ResourcePolicy,
    ) -> ExecutionRequest {
        let mut request = ExecutionRequest {
            script_code: "echo".to_string(),
            containment,
            ..Default::default()
        };
        request.policy.resources = Some(resources);
        request
    }

    fn every_resource_limit() -> crate::mxc_common::models::ResourcePolicy {
        crate::mxc_common::models::ResourcePolicy {
            cpu_time_ms: Some(1000),
            memory_mb: Some(512),
            max_processes: Some(8),
            priority: ResourcePriority::Idle,
        }
    }

    #[test]
    fn omitted_resources_are_accepted_by_every_backend() {
        for containment in [
            ContainmentBackend::Wslc,
            ContainmentBackend::Lxc,
            ContainmentBackend::IsolationSession,
            ContainmentBackend::Bubblewrap,
        ] {
            let request = ExecutionRequest {
                script_code: "echo".to_string(),
                containment,
                ..Default::default()
            };
            assert!(validate_common(&request).is_ok());
        }
    }

    #[test]
    fn backends_without_resource_support_reject_even_empty_resources() {
        for containment in [
            ContainmentBackend::Wslc,
            ContainmentBackend::Lxc,
            ContainmentBackend::Vm,
            ContainmentBackend::MicroVm,
            ContainmentBackend::Hyperlight,
            ContainmentBackend::WindowsSandbox,
            ContainmentBackend::IsolationSession,
        ] {
            let request = request_with_resources(containment, Default::default());
            let error = validate_common(&request).unwrap_err();
            assert_eq!(
                error.failure_phase,
                crate::mxc_common::models::FailurePhase::Rejected
            );
            assert!(error.error_message.contains("resources is not supported"));
        }
    }

    #[test]
    fn bubblewrap_enforces_every_limit_but_max_processes() {
        let mut resources = every_resource_limit();
        let request = request_with_resources(ContainmentBackend::Bubblewrap, resources);
        let error = validate_common(&request).unwrap_err();
        assert!(error.error_message.contains("resources.maxProcesses"));

        resources.max_processes = None;
        let request = request_with_resources(ContainmentBackend::Bubblewrap, resources);
        assert!(validate_common(&request).is_ok());
    }

    #[test]
    fn seatbelt_enforces_cpu_time_and_priority_only() {
        let mut resources = every_resource_limit();
        resources.max_processes = None;
        let request = request_with_resources(ContainmentBackend::Seatbelt, resources);
        let error = validate_common(&request).unwrap_err();
        assert!(error.error_message.contains("resources.memoryMb"));

        resources.memory_mb = None;
        let request = request_with_resources(ContainmentBackend::Seatbelt, resources);
        assert!(validate_common(&request).is_ok());
    }

    #[test]
    fn process_container_enforces_every_resource_limit() {
        let request =
            request_with_resources(ContainmentBackend::ProcessContainer, every_resource_limit());
        assert!(validate_common(&request).is_ok());
    }

    #[test]
    fn each_unsupported_limit_is_rejected_by_name() {
        for (missing, field) in [
            (ResourcePolicySupport::CPU_TIME, "resources.cpuTimeMs"),
            (ResourcePolicySupport::MEMORY, "resources.memoryMb"),
            (
                ResourcePolicySupport::MAX_PROCESSES,
                "resources.maxProcesses",
            ),
            (ResourcePolicySupport::PRIORITY, "resources.priority"),
        ] {
            let support = ResourcePolicySupport(ResourcePolicySupport::ALL.0 & !missing.0);
            let request =
                request_with_resources(ContainmentBackend::Bubblewrap, every_resource_limit());
            let error = validate_resource_policy_support(&request, support).unwrap_err();
            assert!(error.error_message.contains(field), "{field}");
            assert!(error.error_message.contains("'bubblewrap' backend"));
        }
    }

    #[test]
    fn normal_priority_needs_no_priority_support() {
        let support = ResourcePolicySupport::CPU_TIME;
        let request = request_with_resources(
            ContainmentBackend::Bubblewrap,
            crate::mxc_common::models::ResourcePolicy {
                priority: ResourcePriority::Normal,
                ..Default::default()
            },
        );
        assert!(validate_resource_policy_support(&request, support).is_ok());
    }
}
