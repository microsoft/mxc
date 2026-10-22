// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::PathBuf;

use super::abi::{
    Access, Capabilities, EgressPolicy, ExecRequest, FilesystemPolicy, IngressPolicy, NetworkPeer,
    NetworkPolicy, NetworkPort, NetworkRule, Protocol, ProvisionRequest, RuntimeConfig,
    SandboxSpec,
};

use crate::mxc_common::models::{
    ExecutionRequest, NetworkAction, NetworkCidr, NetworkPeer as MxcNetworkPeer,
    NetworkPort as MxcNetworkPort, NetworkProtocol, NetworkRule as MxcNetworkRule,
};
use crate::mxc_common::mxc_error::MxcError;

const MAX_ENVIRONMENT_BYTES: usize = 32 * 1024;
const MAX_TIMEOUT_MS: u32 = 3_600_000;
const MAX_ENVIRONMENT_ENTRIES: usize = 256;
const MAX_CWD_BYTES: usize = 4095;
const PROXY_ENVIRONMENT_KEYS: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

pub(super) fn provision_request(
    request: &ExecutionRequest,
    capabilities: &Capabilities,
) -> Result<(ProvisionRequest, SandboxSpec), MxcError> {
    validate_request(request)?;
    let image = request
        .microvm_image
        .as_deref()
        .ok_or_else(|| MxcError::malformed_request("microvm.image is required"))?;
    let spec = super::runtime::sandbox_spec(image)?;
    if !capabilities.spec.image_reference {
        return Err(unsupported("microvm.image"));
    }
    validate_provision_capabilities(request, capabilities)?;

    let provision =
        ProvisionRequest {
            filesystem: filesystem_policy(request),
            network: network_policy(request)?,
            runtime_config: request.policy.network_proxy.address.as_ref().map(|proxy| {
                RuntimeConfig {
                    network_proxy: Some(proxy.to_url()),
                }
            }),
        };
    Ok((provision, spec))
}

pub(super) fn exec_request(
    request: &ExecutionRequest,
    capabilities: &Capabilities,
) -> Result<ExecRequest, MxcError> {
    validate_request(request)?;
    if !capabilities.exec.command_line {
        return Err(unsupported("process.commandLine"));
    }
    if !request.working_directory.is_empty() && !capabilities.exec.cwd {
        return Err(unsupported("process.cwd"));
    }
    if request.env.is_some() && !capabilities.exec.env {
        return Err(unsupported("process.env"));
    }
    if let Some(max) = capabilities.exec.max_timeout_ms {
        if u64::from(request.script_timeout) > max {
            return Err(MxcError::policy_validation(format!(
                "NVX process.timeout must not exceed {max} ms"
            )));
        }
    }

    let mut exec = ExecRequest::command_line(request.script_code.clone())
        .with_inherit_default_env(request.inherit_default_env);
    if request.script_timeout != 0 {
        exec = exec.with_timeout_ms(u64::from(request.script_timeout));
    }
    if !request.working_directory.is_empty() {
        exec = exec.with_cwd(request.working_directory.clone());
    }
    if let Some(environment) = &request.env {
        exec = exec.with_envs(environment.clone());
    }
    Ok(exec)
}

pub(super) fn validate_request(request: &ExecutionRequest) -> Result<(), MxcError> {
    if !request.lifecycle.destroy_on_exit {
        return Err(MxcError::policy_validation(
            "NVX requires lifecycle.destroyOnExit=true",
        ));
    }
    if request.lifecycle.preserve_policy {
        return Err(MxcError::policy_validation(
            "NVX requires lifecycle.preservePolicy=false",
        ));
    }
    let image = request
        .microvm_image
        .as_deref()
        .ok_or_else(|| MxcError::malformed_request("microvm.image is required"))?;
    crate::mxc_contract::dev::ImageReference::validate(image)
        .map_err(MxcError::malformed_request)?;
    if !request.policy.enumerate_paths.is_empty() {
        return Err(MxcError::policy_validation(
            "NVX does not support filesystem.enumeratePaths",
        ));
    }
    if request.policy.ui_specified {
        return Err(MxcError::policy_validation(
            "NVX does not support UI policy",
        ));
    }
    if request.policy.capture_denials.is_some() {
        return Err(MxcError::policy_validation(
            "NVX does not support processContainer.captureDenials",
        ));
    }
    if request.policy.least_privilege_specified {
        return Err(MxcError::policy_validation(
            "NVX does not support processContainer.leastPrivilege",
        ));
    }
    if request.policy.learning_mode_specified {
        return Err(MxcError::policy_validation(
            "NVX does not support processContainer.learningMode",
        ));
    }
    if request.policy.capabilities_specified {
        return Err(MxcError::policy_validation(
            "NVX does not support processContainer.capabilities",
        ));
    }
    if request.policy.base_process_ui_specified {
        return Err(MxcError::policy_validation(
            "NVX does not support processContainer.ui",
        ));
    }
    if request.policy.fallback_specified {
        return Err(MxcError::policy_validation(
            "NVX does not support fallback policy",
        ));
    }
    if request.script_code.contains('\0') || request.working_directory.contains('\0') {
        return Err(MxcError::malformed_request(
            "NVX process.commandLine and process.cwd must not contain null bytes",
        ));
    }
    if request.script_timeout > MAX_TIMEOUT_MS {
        return Err(MxcError::policy_validation(
            "NVX process.timeout must not exceed 3600000 ms (one hour)",
        ));
    }
    if request
        .working_directory
        .split('/')
        .any(|component| component == "..")
    {
        return Err(MxcError::policy_validation(
            "NVX process.cwd must not contain '..' path components",
        ));
    }
    if !request.working_directory.is_empty() && !request.working_directory.starts_with('/') {
        return Err(MxcError::policy_validation(
            "NVX process.cwd must be an absolute POSIX guest path",
        ));
    }
    if request.working_directory.len() > MAX_CWD_BYTES {
        return Err(MxcError::policy_validation(
            "NVX process.cwd must not exceed 4095 UTF-8 bytes",
        ));
    }
    if let Some(environment) = &request.env {
        if !request.inherit_default_env {
            return Err(MxcError::policy_validation(
                "NVX process.env requires inheritDefaultEnv=true",
            ));
        }
        if environment.len() > MAX_ENVIRONMENT_ENTRIES {
            return Err(MxcError::policy_validation(
                "NVX process.env must not exceed 256 entries",
            ));
        }
        let bytes = environment
            .iter()
            .map(|entry| entry.len().saturating_add(1))
            .sum::<usize>();
        if bytes > MAX_ENVIRONMENT_BYTES {
            return Err(MxcError::policy_validation(
                "NVX process.env must not exceed 32 KiB",
            ));
        }
        for entry in environment {
            if entry.contains('\0') || entry.split_once('=').is_none_or(|(key, _)| key.is_empty()) {
                return Err(MxcError::malformed_request(
                    "NVX process.env entries must be KEY=VALUE without null bytes",
                ));
            }
            let key = entry.split_once('=').map_or(entry.as_str(), |(key, _)| key);
            if PROXY_ENVIRONMENT_KEYS
                .iter()
                .any(|candidate| key.eq_ignore_ascii_case(candidate))
            {
                return Err(MxcError::policy_validation(
                    "NVX rejects proxy environment variables; use runtimeConfig.networkProxy",
                ));
            }
        }
    }
    Ok(())
}

fn validate_provision_capabilities(
    request: &ExecutionRequest,
    capabilities: &Capabilities,
) -> Result<(), MxcError> {
    let filesystem = &capabilities.filesystem;
    if !request.policy.readonly_paths.is_empty() && !filesystem.readonly_paths {
        return Err(unsupported("filesystem.readonlyPaths"));
    }
    if !request.policy.readwrite_paths.is_empty() && !filesystem.readwrite_paths {
        return Err(unsupported("filesystem.readwritePaths"));
    }
    if !request.policy.denied_paths.is_empty() && !filesystem.denied_paths {
        return Err(unsupported("filesystem.deniedPaths"));
    }

    if request.policy.runtime_network_proxy_specified
        && request.policy.network_proxy.is_enabled()
        && !capabilities.network.network_proxy
    {
        return Err(unsupported("runtimeConfig.networkProxy"));
    }
    if request.policy.network_specified {
        let egress = request.policy.network_egress.clone().unwrap_or_default();
        let ingress = request.policy.network_ingress.clone().unwrap_or_default();
        match egress.default {
            NetworkAction::Allow if !capabilities.network.egress_allow => {
                return Err(unsupported("network.egress.default=allow"));
            }
            NetworkAction::Deny if !capabilities.network.egress_deny => {
                return Err(unsupported("network.egress.default=deny"));
            }
            _ => {}
        }
        if (!egress.allow.is_empty() || !egress.deny.is_empty())
            && !capabilities.network.egress_rules
        {
            return Err(unsupported("network egress rules"));
        }
        match ingress.default {
            NetworkAction::Allow if !capabilities.network.ingress_allow => {
                return Err(unsupported("network.ingress.default=allow"));
            }
            NetworkAction::Deny if !capabilities.network.ingress_deny => {
                return Err(unsupported("network.ingress.default=deny"));
            }
            _ => {}
        }
        match ingress.host_loopback {
            NetworkAction::Allow if !capabilities.network.host_loopback_allow => {
                return Err(unsupported("network.ingress.hostLoopback=allow"));
            }
            NetworkAction::Deny if !capabilities.network.host_loopback_deny => {
                return Err(unsupported("network.ingress.hostLoopback=deny"));
            }
            _ => {}
        }
    }
    Ok(())
}

fn filesystem_policy(request: &ExecutionRequest) -> Option<FilesystemPolicy> {
    let filesystem = FilesystemPolicy {
        readonly_paths: request
            .policy
            .readonly_paths
            .iter()
            .map(PathBuf::from)
            .collect(),
        readwrite_paths: request
            .policy
            .readwrite_paths
            .iter()
            .map(PathBuf::from)
            .collect(),
        denied_paths: request
            .policy
            .denied_paths
            .iter()
            .map(PathBuf::from)
            .collect(),
    };
    (!filesystem.is_empty()).then_some(filesystem)
}

fn network_policy(request: &ExecutionRequest) -> Result<Option<NetworkPolicy>, MxcError> {
    if !request.policy.network_specified {
        return Ok(None);
    }
    let egress = request.policy.network_egress.clone().unwrap_or_default();
    let ingress = request.policy.network_ingress.clone().unwrap_or_default();
    Ok(Some(NetworkPolicy {
        egress: EgressPolicy {
            default: access(egress.default),
            allow: egress.allow.iter().map(network_rule).collect(),
            deny: egress.deny.iter().map(network_rule).collect(),
        },
        ingress: IngressPolicy {
            default: access(ingress.default),
            host_loopback: Some(access(ingress.host_loopback)),
        },
    }))
}

fn access(action: NetworkAction) -> Access {
    match action {
        NetworkAction::Allow => Access::Allow,
        NetworkAction::Deny => Access::Deny,
    }
}

fn protocol(value: NetworkProtocol) -> Protocol {
    match value {
        NetworkProtocol::Tcp => Protocol::Tcp,
        NetworkProtocol::Udp => Protocol::Udp,
        NetworkProtocol::Icmp => Protocol::Icmp,
        NetworkProtocol::Any => Protocol::Any,
    }
}

fn cidr(value: &NetworkCidr) -> String {
    format!("{}/{}", value.address, value.prefix_length)
}

fn network_peer(peer: &MxcNetworkPeer) -> NetworkPeer {
    NetworkPeer {
        cidr: cidr(&peer.cidr),
        except: peer.except.iter().map(cidr).collect(),
    }
}

fn network_port(port: &MxcNetworkPort) -> NetworkPort {
    NetworkPort {
        protocol: protocol(port.protocol),
        port: port.port,
        end_port: port.end_port,
    }
}

fn network_rule(rule: &MxcNetworkRule) -> NetworkRule {
    NetworkRule {
        to: rule.to.iter().map(network_peer).collect(),
        ports: rule.ports.iter().map(network_port).collect(),
    }
}

fn unsupported(feature: &str) -> MxcError {
    MxcError::policy_validation(format!(
        "the configured NVX runtime does not support {feature}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{NetworkEgressPolicy, NetworkIngressPolicy};
    use crate::mxc_common::mxc_error::MxcErrorCode;

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo ok".to_owned(),
            microvm_image: Some("python:3.12-alpine".to_owned()),
            ..ExecutionRequest::default()
        }
    }

    fn assert_policy_error(request: &ExecutionRequest, text: &str) {
        let error = validate_request(request).unwrap_err();
        assert_eq!(
            error.code,
            crate::mxc_common::mxc_error::MxcErrorCode::PolicyValidation
        );
        assert!(error.message.contains(text), "{error}");
    }

    fn capabilities() -> Capabilities {
        let mut capabilities = Capabilities::default();
        capabilities.exec.command_line = true;
        capabilities.exec.cwd = true;
        capabilities.exec.env = true;
        capabilities.exec.max_timeout_ms = Some(3_600_000);
        capabilities.filesystem.readonly_paths = true;
        capabilities.filesystem.readwrite_paths = true;
        capabilities.filesystem.denied_paths = true;
        capabilities.network.egress_allow = true;
        capabilities.network.egress_deny = true;
        capabilities.network.ingress_deny = true;
        capabilities.network.host_loopback_deny = true;
        capabilities.network.egress_rules = true;
        capabilities.network.network_proxy = true;
        capabilities.spec.image_reference = true;
        capabilities
    }

    fn typed_network_rules_request() -> ExecutionRequest {
        use crate::v1::{
            ContainerRequest, Containment, NetworkEgressPolicy, NetworkPeerPolicy, NetworkPolicy,
            NetworkPortPolicy, NetworkProtocol, NetworkRulePolicy,
        };

        let request = ContainerRequest {
            containment: Containment::MicroVm {
                image: "python:3.12-alpine".to_owned(),
            },
            network: Some(NetworkPolicy {
                egress: Some(NetworkEgressPolicy {
                    allow: Some(vec![
                        NetworkRulePolicy {
                            to: Some(vec![NetworkPeerPolicy {
                                cidr: "10.0.0.0/8".to_owned(),
                                except: Some(vec!["10.1.0.0/16".to_owned()]),
                            }]),
                            ports: Some(vec![
                                NetworkPortPolicy {
                                    protocol: Some(NetworkProtocol::Tcp),
                                    port: Some(8000),
                                    end_port: Some(8080),
                                },
                                NetworkPortPolicy {
                                    protocol: Some(NetworkProtocol::Udp),
                                    port: Some(53),
                                    end_port: None,
                                },
                                NetworkPortPolicy {
                                    protocol: Some(NetworkProtocol::Any),
                                    ..Default::default()
                                },
                            ]),
                        },
                        NetworkRulePolicy {
                            to: Some(vec![NetworkPeerPolicy::new("2001:db8::/32")]),
                            ports: None,
                        },
                    ]),
                    deny: Some(vec![NetworkRulePolicy {
                        to: Some(vec![NetworkPeerPolicy::new("192.0.2.0/24")]),
                        ports: Some(vec![NetworkPortPolicy {
                            protocol: Some(NetworkProtocol::Icmp),
                            ..Default::default()
                        }]),
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..ContainerRequest::new("printf captured")
        };
        crate::policy::prepare_creation_request(&request, None)
            .expect("typed nonempty rules pass development contract and shared parser")
            .inner
    }

    #[test]
    fn typed_network_rules_reach_provision_with_exact_selectors() {
        let request = typed_network_rules_request();
        let (provision, _) = provision_request(&request, &capabilities()).unwrap();
        let network = provision.network.expect("network policy");
        assert_eq!(network.egress.default, Access::Deny);
        assert_eq!(network.egress.allow.len(), 2);
        assert_eq!(network.egress.deny.len(), 1);
        let allow = &network.egress.allow[0];
        assert_eq!(allow.to.len(), 1);
        assert_eq!(allow.to[0].cidr, "10.0.0.0/8");
        assert_eq!(allow.to[0].except, vec!["10.1.0.0/16"]);
        assert_eq!(allow.ports.len(), 3);
        for (actual, (protocol, port, end_port)) in allow.ports.iter().zip([
            (Protocol::Tcp, Some(8000), Some(8080)),
            (Protocol::Udp, Some(53), None),
            (Protocol::Any, None, None),
        ]) {
            assert_eq!(actual.protocol, protocol);
            assert_eq!(actual.port, port);
            assert_eq!(actual.end_port, end_port);
        }
        let omitted_ports = &network.egress.allow[1];
        assert_eq!(omitted_ports.to.len(), 1);
        assert_eq!(omitted_ports.to[0].cidr, "2001:db8::/32");
        assert!(omitted_ports.to[0].except.is_empty());
        assert!(omitted_ports.ports.is_empty());
        let deny = &network.egress.deny[0];
        assert_eq!(deny.to.len(), 1);
        assert_eq!(deny.to[0].cidr, "192.0.2.0/24");
        assert!(deny.to[0].except.is_empty());
        assert_eq!(deny.ports.len(), 1);
        assert_eq!(deny.ports[0].protocol, Protocol::Icmp);
        assert_eq!(deny.ports[0].port, None);
        assert_eq!(deny.ports[0].end_port, None);
    }

    #[test]
    fn typed_network_rules_require_the_advertised_egress_rules_capability() {
        for (keep_allow, keep_deny) in [(true, true), (true, false), (false, true)] {
            let mut request = typed_network_rules_request();
            let egress = request.policy.network_egress.as_mut().unwrap();
            if !keep_allow {
                egress.allow.clear();
            }
            if !keep_deny {
                egress.deny.clear();
            }
            let mut capabilities = capabilities();
            // Reach the mapper before removing only the rules capability.
            assert!(provision_request(&request, &capabilities).is_ok());
            capabilities.network.egress_rules = false;
            let error = provision_request(&request, &capabilities).unwrap_err();
            assert_eq!(error.code, MxcErrorCode::PolicyValidation);
            assert_eq!(
                error.message,
                "the configured NVX runtime does not support network egress rules"
            );
        }
    }

    #[test]
    fn creation_rejects_missing_invalid_or_unsupported_image() {
        let mut request = request();
        for image in [None, Some(""), Some(" "), Some("python:\n3.12")] {
            request.microvm_image = image.map(str::to_owned);
            let error = provision_request(&request, &capabilities()).unwrap_err();
            assert_eq!(error.code, MxcErrorCode::MalformedRequest, "{error}");
            assert!(error.message.contains("microvm.image"), "{error}");
        }
        request.microvm_image = Some("python:3.12-alpine".to_owned());
        let mut unsupported = capabilities();
        unsupported.spec.image_reference = false;
        let error = provision_request(&request, &unsupported).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation, "{error}");
        assert!(error.message.contains("microvm.image"));
    }

    #[test]
    fn creation_propagates_the_selected_reference() {
        let request = request();
        let (_, spec) = provision_request(&request, &capabilities()).unwrap();
        assert_eq!(
            spec.image,
            Some(super::super::abi::ImageSource::Reference(
                "python:3.12-alpine".to_owned()
            ))
        );
    }

    #[test]
    fn typed_creation_reaches_runtime_spec_through_the_development_contract() {
        use crate::v1::{ContainerRequest, Containment, FilesystemPolicy, NetworkPolicy};

        for image in [
            "python:3.12-alpine",
            "mcr.microsoft.com/azurelinux/base/core:3.0",
        ] {
            let request = ContainerRequest {
                containment: Containment::MicroVm {
                    image: image.to_owned(),
                },
                filesystem: Some(FilesystemPolicy {
                    readonly_paths: vec![r"C:\ro".to_owned()],
                    readwrite_paths: vec![r"C:\rw".to_owned()],
                    denied_paths: vec![r"C:\rw\secret".to_owned()],
                    ..Default::default()
                }),
                network: Some(NetworkPolicy::default()),
                ..ContainerRequest::new("printf captured")
            };
            let prepared = crate::policy::prepare_creation_request(&request, None).unwrap();
            assert_eq!(
                prepared.inner.containment,
                crate::mxc_common::models::ContainmentBackend::MicroVm
            );
            assert!(!prepared.inner.experimental_enabled);
            let (provision, spec) = provision_request(&prepared.inner, &capabilities()).unwrap();
            assert_eq!(
                spec.image,
                Some(super::super::abi::ImageSource::Reference(image.to_owned()))
            );
            let filesystem = provision.filesystem.unwrap();
            assert_eq!(filesystem.readonly_paths, vec![PathBuf::from(r"C:\ro")]);
            assert_eq!(filesystem.readwrite_paths, vec![PathBuf::from(r"C:\rw")]);
            assert_eq!(
                filesystem.denied_paths,
                vec![PathBuf::from(r"C:\rw\secret")]
            );
            let network = provision.network.unwrap();
            assert_eq!(network.egress.default, Access::Deny);
            assert_eq!(network.ingress.default, Access::Deny);
            assert_eq!(network.ingress.host_loopback, Some(Access::Deny));
        }
    }

    #[test]
    fn maps_filesystem_network_and_proxy() {
        let mut request = request();
        request.policy.readonly_paths = vec![r"C:\ro".to_owned()];
        request.policy.readwrite_paths = vec![r"C:\rw".to_owned()];
        request.policy.denied_paths = vec![r"C:\rw\secret".to_owned()];
        request.policy.network_specified = true;
        request.policy.network_egress = Some(NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(NetworkIngressPolicy::default());
        request.policy.runtime_network_proxy_specified = true;
        request.policy.network_proxy.address = Some(crate::mxc_common::models::ProxyAddress::new(
            "127.0.0.1".to_owned(),
            3128,
        ));
        let (provision, _) = provision_request(&request, &capabilities()).unwrap();
        assert_eq!(
            provision.filesystem.unwrap().readwrite_paths,
            vec![PathBuf::from(r"C:\rw")]
        );
        assert_eq!(
            provision
                .runtime_config
                .as_ref()
                .and_then(|runtime| runtime.network_proxy.as_deref()),
            Some("http://127.0.0.1:3128")
        );
    }

    #[test]
    fn rejects_unadvertised_ingress_allow() {
        let mut request = request();
        request.policy.network_specified = true;
        request.policy.network_egress = Some(NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Deny,
        });
        let error = provision_request(&request, &capabilities()).unwrap_err();
        assert!(error.message.contains("ingress.default=allow"));
    }

    #[test]
    fn signed_profile_process_restrictions_fail_closed() {
        let mut cwd = request();
        cwd.working_directory = "/work/../escape".to_owned();
        assert!(exec_request(&cwd, &capabilities())
            .unwrap_err()
            .message
            .contains("must not contain '..'"));

        let mut replacement = request();
        replacement.env = Some(vec!["KEY=value".to_owned()]);
        assert!(exec_request(&replacement, &capabilities())
            .unwrap_err()
            .message
            .contains("inheritDefaultEnv=true"));

        let mut proxy = request();
        proxy.env = Some(vec!["Http_Proxy=http://proxy".to_owned()]);
        proxy.inherit_default_env = true;
        assert!(exec_request(&proxy, &capabilities())
            .unwrap_err()
            .message
            .contains("proxy environment"));

        let mut timeout = request();
        timeout.script_timeout = MAX_TIMEOUT_MS + 1;
        assert_policy_error(&timeout, "one hour");
    }

    #[test]
    fn environment_entry_limit_counts_duplicates_and_preserves_absent_and_empty() {
        let mut request = request();
        assert!(validate_request(&request).is_ok());
        request.env = Some(Vec::new());
        assert_policy_error(&request, "inheritDefaultEnv=true");
        request.inherit_default_env = true;
        assert!(validate_request(&request).is_ok());
        request.env = Some(vec!["KEY=value".to_owned(); MAX_ENVIRONMENT_ENTRIES]);
        assert!(validate_request(&request).is_ok());
        request.env.as_mut().unwrap().push("KEY=later".to_owned());
        assert_policy_error(&request, "must not exceed 256 entries");
    }

    #[test]
    fn cwd_limit_counts_utf8_bytes_instead_of_characters() {
        let mut request = request();
        for directory in [
            format!("/{}", "x".repeat(MAX_CWD_BYTES - 1)),
            format!("/{}", "\u{00e9}".repeat((MAX_CWD_BYTES - 1) / 2)),
        ] {
            assert_eq!(directory.len(), MAX_CWD_BYTES);
            request.working_directory = directory;
            assert!(validate_request(&request).is_ok());
            request.working_directory.push('x');
            assert_policy_error(&request, "must not exceed 4095 UTF-8 bytes");
        }
    }

    #[test]
    fn validates_posix_cwd_and_exact_process_boundaries() {
        let mut request = request();
        request.script_timeout = MAX_TIMEOUT_MS;
        request.working_directory = "/tmp/./workspace".to_owned();
        request.env = Some(vec![format!(
            "KEY={}",
            "x".repeat(MAX_ENVIRONMENT_BYTES - 5)
        )]);
        request.inherit_default_env = true;
        assert!(validate_request(&request).is_ok());

        request.working_directory = "C:\\host".to_owned();
        assert_policy_error(&request, "absolute POSIX guest path");
        request.working_directory = "/tmp".to_owned();
        for key in PROXY_ENVIRONMENT_KEYS {
            request.env = Some(vec![format!("{}=value", key.to_ascii_lowercase())]);
            assert_policy_error(&request, "proxy environment");
        }
        request.env = Some(vec!["=missing-key".to_owned()]);
        assert_eq!(
            validate_request(&request).unwrap_err().code,
            crate::mxc_common::mxc_error::MxcErrorCode::MalformedRequest
        );
        request.env = None;
        request.script_code.push('\0');
        assert_eq!(
            validate_request(&request).unwrap_err().code,
            crate::mxc_common::mxc_error::MxcErrorCode::MalformedRequest
        );
    }
}
