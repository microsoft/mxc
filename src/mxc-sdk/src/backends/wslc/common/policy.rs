// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Policy validation for the WSLc backend.
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
//! | `ui`                        | rejected (no UI primitive)   | rejected                   | rejected                   |
//! | `network.egress.default`    | honoured (None / Bridged)    | rejected (immutable)       | rejected (immutable)       |
//! | `network.ingress.*`         | must match egress (deny all / allow all) | rejected         | rejected                   |
//! | `runtimeConfig.networkProxy` | rejected (applies at exec) | rejected                   | honoured (cooperative env) |
//!
//! [^1]: a standalone `denied_path` is honoured by container isolation (unlisted
//! host paths are simply never mounted); only a denied path nested under a
//! mounted `rw`/`ro` parent is rejected, because WSLc has no overlay primitive
//! to mask a subtree of a mounted volume.
//!
//! Checks run filesystem → ui → network, so a request that trips several gets a
//! stable message rather than one that depends on field order (asserted by
//! tests). [`reject_ui_policy`] applies to both one-shot and state-aware validation.

use crate::mxc_common::models::{ExecutionRequest, NetworkAction};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::validator::NetworkPolicySupport;

use crate::wslc_common::policy_mapping::validate_denied_path_overlap;
use crate::wslc_common::process_env::EnvScope;

const ERR_FILESYSTEM_IMMUTABLE: &str =
    "filesystem policy (readwritePaths / readonlyPaths / deniedPaths and processContainer.filesystem.enumeratePaths) is bound to the provision \
     phase and cannot be changed by the WSLc backend after provisioning";
const ERR_ENUMERATE_PATHS: &str =
    "processContainer.filesystem.enumeratePaths is not supported by the WSLc backend";
const ERR_NETWORK_IMMUTABLE: &str =
    "network mode is bound to the provision phase and cannot be changed by the WSLc backend after \
     provisioning";
const ERR_PROXY_AT_PROVISION: &str =
    "runtimeConfig.networkProxy is applied per-exec by the WSLc backend; set it on the exec phase, not provision";
const ERR_PROXY_AT_PHASE: &str =
    "runtimeConfig.networkProxy is only honoured on the exec phase by the WSLc backend";
const ERR_PROXY_URL_FORM: &str =
    "WSLc: runtimeConfig.networkProxy requires a proxy url reachable from inside the container; \
     a host-loopback proxy is not reachable from the container's own network namespace";
const ERR_UI_POLICY: &str =
    "WSLc: the ui section is not supported. The backend has no mechanism to enforce UI \
     restrictions on a container, so no ui posture is truthful here. Omitting the ui section is \
     accepted but applies no restriction — it is not the lockdown the schema's default implies. \
     Use a backend that enforces UI policy if you need one";
const ERR_PROXY_CREDENTIALS_IN_ARGV: &str =
    "WSLc: runtimeConfig.networkProxy must not carry credentials when \
     process.env is supplied without process.inheritDefaultEnv. That combination replaces the \
     container image's environment, which WSLc performs by prefixing the command line with \
     'env -i NAME=VALUE', so the proxy URL becomes a process argument readable through \
     /proc/<pid>/cmdline for the lifetime of the command. Set process.inheritDefaultEnv to keep \
     the URL out of the command line, use a proxy that needs no inline credentials, or supply \
     them to the proxy itself";

/// WSLc enforces these axes only as a single all-or-nothing networking mode.
/// `validate_directional_network` rejects every independently filtered posture.
pub(crate) fn network_policy_support() -> NetworkPolicySupport {
    NetworkPolicySupport::EGRESS_DEFAULT
        | NetworkPolicySupport::INGRESS_DEFAULT
        | NetworkPolicySupport::HOST_LOOPBACK
        | NetworkPolicySupport::RUNTIME_PROXY
}

/// Read the directional posture; absent egress defaults to deny.
pub(crate) fn network_is_isolated(request: &ExecutionRequest) -> bool {
    request
        .policy
        .network_egress
        .as_ref()
        .is_none_or(|egress| egress.default == NetworkAction::Deny)
}

/// No firewall is installed inside or outside a WSLc container. NONE denies all
/// connectivity; BRIDGED cannot promise either inbound or host-loopback filtering.
pub(crate) fn validate_directional_network(request: &ExecutionRequest) -> Result<(), MxcError> {
    let policy = &request.policy;
    if policy
        .network_egress
        .as_ref()
        .is_some_and(|egress| !egress.allow.is_empty() || !egress.deny.is_empty())
    {
        return Err(MxcError::policy_validation(
            "WSLc does not support network.egress allow/deny rules; networking is all-or-nothing",
        ));
    }
    let isolated = network_is_isolated(request);
    let action = if isolated {
        NetworkAction::Deny
    } else {
        NetworkAction::Allow
    };
    let ingress = policy.network_ingress.clone().unwrap_or_default();
    if ingress.default != action || ingress.host_loopback != action {
        return Err(MxcError::policy_validation(
            "WSLc cannot filter ingress or host-loopback independently: isolated networking \
             requires network.egress.default, network.ingress.default and \
             network.ingress.hostLoopback all 'deny'; bridged networking requires all 'allow'",
        ));
    }
    if isolated && policy.network_proxy.is_enabled() {
        return Err(MxcError::policy_validation(
            "WSLc runtimeConfig.networkProxy requires bridged networking; a proxy cannot \
             create a route in an isolated container",
        ));
    }
    Ok(())
}

/// Validate the request for the provision phase. `rw` / `ro` paths become
/// volume mounts and `network.egress.default` selects the container network
/// mode; both are honoured here. Everything else in the module table is
/// rejected.
pub(crate) fn validate_provision_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    if !request.policy.enumerate_paths.is_empty() {
        return Err(MxcError::policy_validation(ERR_ENUMERATE_PATHS));
    }
    validate_denied_path_overlap(
        &request.policy.readwrite_paths,
        &request.policy.readonly_paths,
        &request.policy.denied_paths,
    )
    .map_err(MxcError::policy_validation)?;
    reject_ui_policy(request)?;
    if request.policy.network_proxy.is_enabled() {
        return Err(MxcError::policy_validation(ERR_PROXY_AT_PROVISION));
    }
    validate_directional_network(request)?;
    Ok(())
}

/// Validate the request for start / stop / deprovision. These phases carry no
/// applicable policy: filesystem and network mode are fixed at provision and
/// the proxy is an exec-time concern. A UI policy is never supported.
pub(crate) fn validate_post_provision_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    reject_filesystem_policy(request)?;
    reject_ui_policy(request)?;
    reject_post_provision_network_mode(request)?;
    if request.policy.network_proxy.is_enabled() {
        return Err(MxcError::policy_validation(ERR_PROXY_AT_PHASE));
    }
    Ok(())
}

/// Validate the request for the exec phase. Filesystem, network mode and `ui`
/// are rejected; the cooperative proxy is honoured and must be in `url` form so
/// a routable value reaches the container.
pub(crate) fn validate_exec_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    reject_filesystem_policy(request)?;
    reject_ui_policy(request)?;
    reject_post_provision_network_mode(request)?;
    if request.policy.network_proxy.is_enabled() && exec_proxy_url(request).is_none() {
        return Err(MxcError::policy_validation(ERR_PROXY_URL_FORM));
    }
    reject_proxy_credentials_in_argv(request)?;
    Ok(())
}

/// Refuse a credential-bearing proxy URL for a request that replaces the image
/// environment.
///
/// [`EnvScope::Replace`] carries every entry as a command-line argument, and
/// `apply_cooperative_proxy_env` puts the configured URL among them, so the
/// credential would be readable through `/proc/<pid>/cmdline` while the command
/// runs. The other scopes leave the entries with the SDK's environment setter,
/// which argv never sees.
pub(crate) fn reject_proxy_credentials_in_argv(request: &ExecutionRequest) -> Result<(), MxcError> {
    if EnvScope::of(request) != EnvScope::Replace {
        return Ok(());
    }

    match exec_proxy_url(request) {
        Some(url) if crate::mxc_common::proxy_env::proxy_url_has_credentials(url) => {
            Err(MxcError::policy_validation(ERR_PROXY_CREDENTIALS_IN_ARGV))
        }
        _ => Ok(()),
    }
}

/// The routable proxy URL to inject at exec, or `None` when the proxy is
/// disabled or specified without an original URL.
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
        || !request.policy.enumerate_paths.is_empty()
        || !request.policy.denied_paths.is_empty()
    {
        return Err(MxcError::policy_validation(ERR_FILESYSTEM_IMMUTABLE));
    }
    Ok(())
}

/// Reject any supplied UI policy: WSLc cannot enforce UI restrictions.
pub(crate) fn reject_ui_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    if request.policy.ui_specified {
        return Err(MxcError::policy_validation(ERR_UI_POLICY));
    }
    Ok(())
}

/// Reject any network *mode* field supplied after provision: the posture is
/// bound to the provision phase. Presence, not value — an explicit
/// `egress.default: "deny"` must still be rejected.
/// The cooperative proxy is a separate exec-time concern handled by the callers.
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
    use crate::mxc_common::models::{
        ContainerPolicy, NetworkEgressPolicy, NetworkIngressPolicy, ProxyAddress, ProxyConfig,
        UiPolicy,
    };
    use crate::mxc_common::mxc_error::MxcErrorCode;

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
        }
    }

    fn non_url_proxy() -> ProxyConfig {
        ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8888)),
        }
    }

    fn credential_proxy() -> ProxyConfig {
        ProxyConfig {
            address: Some(ProxyAddress::from_url(
                "http://alice:hunter2@proxy.example:8080",
                "proxy.example".to_string(),
                8080,
            )),
        }
    }

    fn credential_proxy_request(
        env: Option<Vec<&str>>,
        inherit_default_env: bool,
    ) -> ExecutionRequest {
        ExecutionRequest {
            policy: ContainerPolicy {
                network_proxy: credential_proxy(),
                ..Default::default()
            },
            env: env.map(|e| e.into_iter().map(String::from).collect()),
            inherit_default_env,
            ..Default::default()
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

    fn parsed(source: &str) -> ExecutionRequest {
        let request = crate::mxc_common::config_parser::load_mxc_request_from_json(
            source,
            &mut crate::mxc_common::logger::Logger::new(crate::mxc_common::logger::Mode::Buffer),
        )
        .unwrap();
        match request {
            crate::mxc_common::state_aware_request::MxcRequest::OneShot(request) => request,
            crate::mxc_common::state_aware_request::MxcRequest::StateAware(request) => {
                request.into_request()
            }
        }
    }

    #[test]
    fn directional_networking_accepts_only_truthful_all_or_nothing_postures() {
        for egress in ["allow", "deny"] {
            for ingress in ["allow", "deny"] {
                for loopback in ["allow", "deny"] {
                    let source = format!(
                        r#"{{"version":"0.9.0-alpha","phase":"provision","containment":"wslc","network":{{"egress":{{"default":"{egress}"}},"ingress":{{"default":"{ingress}","hostLoopback":"{loopback}"}}}}}}"#
                    );
                    let request = parsed(&source);
                    assert_eq!(network_is_isolated(&request), egress == "deny");
                    assert_eq!(
                        validate_provision_policy(&request).is_ok(),
                        egress == ingress && ingress == loopback,
                        "{source}"
                    );
                }
            }
        }
        let defaults =
            parsed(r#"{"version":"0.9.0-alpha","phase":"provision","containment":"wslc"}"#);
        assert!(network_is_isolated(&defaults));
        validate_provision_policy(&defaults).unwrap();
    }

    #[test]
    fn provision_rejects_enumerate_paths() {
        let request = request_with_policy(ContainerPolicy {
            enumerate_paths: vec!["C:\\tools".to_string()],
            ..Default::default()
        });

        assert_policy_validation(
            validate_provision_policy(&request).unwrap_err(),
            ERR_ENUMERATE_PATHS,
        );
    }

    #[test]
    fn runtime_proxy_only_exec_inherits_mode_and_retains_guest_routable_url() {
        let request = parsed(
            r#"{"version":"0.9.0-alpha","phase":"exec","sandboxId":"wslc:0123456789abcdef0123456789abcdef","process":{"commandLine":"echo"},"runtimeConfig":{"networkProxy":"http://proxy.example:8080"}}"#,
        );
        assert!(!request.policy.network_specified);
        assert!(!request.policy.network_mode_specified);
        assert!(request.policy.runtime_network_proxy_specified);
        assert!(request.policy.network_egress.is_none());
        assert!(request.policy.network_ingress.is_none());
        crate::mxc_common::validator::validate_state_aware_network_policy_support(
            &request,
            network_policy_support(),
        )
        .unwrap();
        validate_exec_policy(&request).unwrap();
        assert_eq!(exec_proxy_url(&request), Some("http://proxy.example:8080"));

        for network in [r#"{}"#, r#"{"egress":{"default":"deny"}}"#] {
            let source = format!(
                r#"{{"version":"0.9.0-alpha","phase":"exec","sandboxId":"wslc:0123456789abcdef0123456789abcdef","process":{{"commandLine":"echo"}},"network":{network},"runtimeConfig":{{"networkProxy":"http://proxy.example:8080"}}}}"#
            );
            assert_policy_validation(
                validate_exec_policy(&parsed(&source)).unwrap_err(),
                "network mode",
            );
        }
    }

    #[test]
    fn one_shot_runtime_proxy_requires_a_real_route_not_a_proxy_only_firewall_promise() {
        let bridged = parsed(
            r#"{"version":"0.9.0-alpha","containment":"wslc","process":{"commandLine":"echo"},"network":{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}},"runtimeConfig":{"networkProxy":"http://proxy.example:8080"}}"#,
        );
        validate_directional_network(&bridged).unwrap();
        assert_eq!(exec_proxy_url(&bridged), Some("http://proxy.example:8080"));
        let isolated = parsed(
            r#"{"version":"0.9.0-alpha","containment":"wslc","process":{"commandLine":"echo"},"runtimeConfig":{"networkProxy":"http://proxy.example:8080"}}"#,
        );
        assert_policy_validation(
            validate_directional_network(&isolated).unwrap_err(),
            "requires bridged networking",
        );
    }

    #[test]
    fn directional_rules_and_proxy_peer_identity_are_not_advertised_or_ignored() {
        assert!(!network_policy_support().contains(NetworkPolicySupport::EGRESS_RULES));
        assert!(!network_policy_support().contains(NetworkPolicySupport::PROXY_PEER_IDENTITY));
        for action in ["allow", "deny"] {
            let source = format!(
                r#"{{"version":"0.9.0-alpha","phase":"provision","containment":"wslc","network":{{"egress":{{"{action}":[{{"to":[{{"cidr":"192.0.2.0/24"}}]}}]}}}}}}"#
            );
            assert_policy_validation(
                validate_provision_policy(&parsed(&source)).unwrap_err(),
                "allow/deny rules",
            );
        }
    }

    // ---- provision ----

    #[test]
    fn provision_accepts_rw_ro_and_network_mode() {
        let req = request_with_policy(ContainerPolicy {
            readwrite_paths: vec!["C:\\src".to_string()],
            readonly_paths: vec!["C:\\data".to_string()],
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            }),
            network_ingress: Some(NetworkIngressPolicy {
                default: NetworkAction::Allow,
                host_loopback: NetworkAction::Allow,
            }),
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
        // Even an explicit directional deny (equal to the default) must be
        // rejected post-provision: presence, not value, is what matters.
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

    // ---- ui (rejected on every phase) ----

    #[test]
    fn every_phase_rejects_supplied_ui() {
        let req = request_with_policy(ContainerPolicy {
            ui_specified: true,
            ..Default::default()
        });
        for (phase, result) in [
            ("provision", validate_provision_policy(&req)),
            ("post_provision", validate_post_provision_policy(&req)),
            ("exec", validate_exec_policy(&req)),
        ] {
            let err = result.expect_err(&format!("{phase} must reject a supplied ui"));
            assert_policy_validation(err, "ui section is not supported");
        }
    }

    /// A value-based check would let the most restrictive request a caller can
    /// write through unenforced, since that is also the default.
    #[test]
    fn provision_rejects_lockdown_equivalent_ui() {
        let req = request_with_policy(ContainerPolicy {
            ui: UiPolicy::default(),
            ui_specified: true,
            ..Default::default()
        });
        assert_policy_validation(
            validate_provision_policy(&req).unwrap_err(),
            "ui section is not supported",
        );
    }

    #[test]
    fn absent_ui_is_accepted_on_every_phase() {
        let req = ExecutionRequest::default();
        assert!(!req.policy.ui_specified);
        validate_provision_policy(&req).unwrap();
        validate_post_provision_policy(&req).unwrap();
        validate_exec_policy(&req).unwrap();
    }

    // ---- rejection ordering ----
    //
    // filesystem -> ui -> network. Pinned so reordering the validator bodies is
    // caught.

    #[test]
    fn filesystem_error_takes_precedence_over_ui() {
        let req = request_with_policy(ContainerPolicy {
            readwrite_paths: vec!["C:\\src".to_string()],
            ui_specified: true,
            ..Default::default()
        });
        assert_policy_validation(
            validate_post_provision_policy(&req).unwrap_err(),
            "provision phase",
        );
        assert_policy_validation(validate_exec_policy(&req).unwrap_err(), "provision phase");
    }

    #[test]
    fn ui_error_takes_precedence_over_network() {
        let req = request_with_policy(ContainerPolicy {
            ui_specified: true,
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                allow: vec![Default::default()],
                ..Default::default()
            }),
            network_proxy: url_proxy(),
            ..Default::default()
        });
        for (phase, result) in [
            ("provision", validate_provision_policy(&req)),
            ("post_provision", validate_post_provision_policy(&req)),
            ("exec", validate_exec_policy(&req)),
        ] {
            let err = result.expect_err(&format!("{phase} must reject"));
            assert_policy_validation(err, "ui section is not supported");
        }
    }

    #[test]
    fn every_new_rejection_maps_to_policy_validation() {
        let cases = [
            ContainerPolicy {
                ui_specified: true,
                ..Default::default()
            },
            ContainerPolicy {
                network_egress: Some(NetworkEgressPolicy {
                    default: NetworkAction::Allow,
                    allow: vec![Default::default()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];
        for policy in cases {
            let err = validate_provision_policy(&request_with_policy(policy)).unwrap_err();
            assert_eq!(err.code, MxcErrorCode::PolicyValidation);
        }
    }

    #[test]
    fn a_replaced_environment_refuses_a_credential_bearing_proxy_url() {
        let request = credential_proxy_request(Some(vec!["FOO=bar"]), false);

        let err = reject_proxy_credentials_in_argv(&request).unwrap_err();
        assert_policy_validation(err.clone(), "must not carry credentials");
        assert!(
            !err.message.contains("hunter2"),
            "the rejection must not repeat the password: {:?}",
            err.message
        );
    }

    #[test]
    fn an_environment_the_sdk_applies_accepts_a_credential_bearing_proxy_url() {
        // These reach the container through the SDK's environment setter, which
        // never puts a value on the command line.
        for (env, inherit_default_env) in [
            (None, false),
            (None, true),
            (Some(vec!["FOO=bar"]), true),
            (Some(vec![]), true),
        ] {
            let request = credential_proxy_request(env, inherit_default_env);
            assert!(reject_proxy_credentials_in_argv(&request).is_ok());
        }
    }

    #[test]
    fn a_replaced_environment_accepts_a_proxy_url_without_credentials() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                network_proxy: url_proxy(),
                ..Default::default()
            },
            env: Some(vec!["FOO=bar".to_string()]),
            ..Default::default()
        };

        assert!(reject_proxy_credentials_in_argv(&request).is_ok());
    }

    #[test]
    fn the_exec_phase_refuses_a_credential_bearing_proxy_url_in_a_replaced_environment() {
        let request = credential_proxy_request(Some(vec!["FOO=bar"]), false);

        assert_policy_validation(
            validate_exec_policy(&request).unwrap_err(),
            "must not carry credentials",
        );
    }
}
