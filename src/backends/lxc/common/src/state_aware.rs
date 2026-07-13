// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! State-aware lifecycle implementation for the LXC backend.
//!
//! LXC keeps the durable sandbox state in the named container. Provision creates
//! the container, start applies mount/network policy and starts it, exec reuses
//! the one-shot `lxc-attach` PTY path, stop stops the container, and
//! deprovision destroys it plus any remaining iptables state.

use std::time::{Duration, Instant};

use serde::Serialize;

use wxc_common::id::mint_random_token;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{ContainerPolicy, ExecutionRequest, LxcConfig, NetworkEnforcementMode};
use wxc_common::mxc_error::MxcError;
use wxc_common::state_aware_backend::{
    DeprovisionResult, ExecHandle, ProvisionResult, StartResult, StatefulSandboxBackend,
    StopResult, INVALID_PIPE_HANDLE,
};

use crate::filesystem_mounts;
use crate::lxc_bindings::LxcContainer;
use crate::network_iptables::NetworkIptablesManager;

/// Stateless state-aware LXC runner.
pub struct LxcStateAwareRunner;

impl LxcStateAwareRunner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LxcStateAwareRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Provision-phase metadata for diagnostics and caller cleanup visibility.
#[derive(Debug, Clone, Serialize)]
pub struct LxcProvisionMetadata {
    #[serde(rename = "containerName")]
    pub container_name: String,
    pub created: bool,
}

/// Parses the `lxc:<containerName>` sandbox_id form and returns the container
/// name segment.
fn extract_container_name(sandbox_id: &str) -> Result<&str, MxcError> {
    let prefix = <LxcStateAwareRunner as StatefulSandboxBackend>::ID_PREFIX;
    match sandbox_id.split_once(':') {
        Some((p, rest)) if p == prefix && is_valid_container_name(rest) => Ok(rest),
        _ => Err(MxcError::malformed_id(format!(
            "expected {}:<containerName>, got {:?}",
            prefix, sandbox_id
        ))),
    }
}

/// Maximum LXC sandbox container-name length.
///
/// `NetworkIptablesManager::new` derives a per-container iptables chain name
/// (`MXC-<sanitized>`) by keeping only alphanumeric/`-`/`_` characters and
/// truncating to 20 characters. Bounding valid container names to that same
/// length and character set (see [`is_valid_container_name`]) makes the
/// derivation an identity map on valid names — nothing is filtered out and no
/// truncation occurs — so two distinct container names can never collide onto
/// the same firewall chain (e.g. `"a.b"` vs `"ab"`, or long names that differ
/// only after the 20th character). Such a collision would let one container's
/// stop/deprovision tear down another container's firewall rules.
const MAX_CONTAINER_NAME_LEN: usize = 20;

/// Returns whether `name` is a valid LXC sandbox container name: non-empty, at
/// most [`MAX_CONTAINER_NAME_LEN`] characters, and restricted to ASCII
/// alphanumerics, `-`, and `_`.
///
/// The character set and length deliberately match the iptables chain-name
/// derivation in `NetworkIptablesManager::new` so the container-name →
/// chain-name mapping stays collision-free. `'.'` is intentionally excluded
/// because it is stripped by that derivation.
fn is_valid_container_name(name: &str) -> bool {
    // Valid characters are ASCII (one byte each), so the byte length reported
    // by `str::len` equals the character count for any otherwise-valid name.
    !name.is_empty()
        && name.len() <= MAX_CONTAINER_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

fn resolve_container_name(request: &ExecutionRequest) -> Result<String, MxcError> {
    if request.container_id.is_empty() {
        return Ok(format!("mxc-{}", mint_random_token()));
    }
    if is_valid_container_name(&request.container_id) {
        Ok(request.container_id.clone())
    } else {
        Err(MxcError::malformed_request(format!(
            "containerId contains characters that are not valid for an LXC sandbox id: {:?}",
            request.container_id
        )))
    }
}

fn validate_lxc_config(config: Option<&LxcConfig>) -> Result<(), MxcError> {
    let Some(config) = config else {
        return Err(MxcError::malformed_request(
            "experimental.lxc.provision with distribution and release is required",
        ));
    };
    if config.distribution.is_empty() || config.release.is_empty() {
        return Err(MxcError::malformed_request(
            "LXC distribution and release are required",
        ));
    }
    Ok(())
}

fn has_filesystem_policy(policy: &ContainerPolicy) -> bool {
    !policy.readwrite_paths.is_empty()
        || !policy.readonly_paths.is_empty()
        || !policy.denied_paths.is_empty()
}

fn has_network_policy(policy: &ContainerPolicy) -> bool {
    matches!(
        policy.network_enforcement_mode,
        NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
    ) || !policy.allowed_hosts.is_empty()
        || !policy.blocked_hosts.is_empty()
        || policy.allow_local_network
        || policy.network_proxy.is_enabled()
}

fn reject_start_policy_on_other_phase(
    phase: &str,
    policy: &ContainerPolicy,
) -> Result<(), MxcError> {
    if has_filesystem_policy(policy) || has_network_policy(policy) {
        return Err(MxcError::policy_validation(format!(
            "LXC state-aware {phase} does not accept filesystem or network policy; pass it to start"
        )));
    }
    Ok(())
}

fn normalized_policy(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<ContainerPolicy, MxcError> {
    let policy =
        match wxc_common::filesystem_object::normalize_object_conflicts(&request.policy, logger) {
            Ok(Some(policy)) => policy,
            Ok(None) => request.policy.clone(),
            Err(msg) => return Err(MxcError::policy_validation(msg)),
        };

    wxc_common::filesystem_access::check_delegation(&policy)
        .map_err(MxcError::policy_validation)?;
    Ok(policy)
}

fn wait_for_network(container: &LxcContainer, timeout: Duration) -> bool {
    let start = Instant::now();
    let poll_interval = Duration::from_millis(500);

    while start.elapsed() < timeout {
        let output = std::process::Command::new("lxc-info")
            .arg("-P")
            .arg(container.lxc_path())
            .arg("-n")
            .arg(container.name())
            .arg("-iH")
            .output();

        if let Ok(out) = output {
            if !String::from_utf8_lossy(&out.stdout).trim().is_empty() {
                return true;
            }
        }

        std::thread::sleep(poll_interval);
    }

    false
}

fn apply_filesystem_policy(
    container: &LxcContainer,
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<(), MxcError> {
    let policy = normalized_policy(request, logger)?;
    filesystem_mounts::configure_filesystem_mounts(container, &policy, logger)
        .map_err(|e| MxcError::policy_validation(format!("Failed to configure filesystem: {e}")))
}

fn apply_network_policy(
    container: &LxcContainer,
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<(), MxcError> {
    if request.policy.network_proxy.is_enabled() {
        return Err(MxcError::policy_validation(
            "LXC state-aware start does not support network.proxy",
        ));
    }

    let policy = normalized_policy(request, logger)?;
    if has_network_policy(&policy) {
        let _ = wait_for_network(container, Duration::from_secs(10));
    }

    let mut fw_manager = NetworkIptablesManager::new(container.name());
    if let Some(veth) = NetworkIptablesManager::discover_veth_interface(container.name()) {
        fw_manager.set_veth_interface(&veth);
    }

    match fw_manager.apply_firewall_rules(&policy, logger) {
        Ok(true) => {
            if fw_manager.rules_applied() {
                // Rules must survive after the start phase returns. stop and
                // deprovision call force_cleanup to remove this persistent state.
                std::mem::forget(fw_manager);
            }
            Ok(())
        }
        Ok(false) => Err(MxcError::policy_validation(
            "Failed to apply network firewall rules",
        )),
        Err(e) => Err(MxcError::policy_validation(format!(
            "Network policy error: {e}"
        ))),
    }
}

fn cleanup_network(container_name: &str, logger: &mut Logger) {
    let veth = NetworkIptablesManager::discover_veth_interface(container_name);
    NetworkIptablesManager::force_cleanup(container_name, veth.as_deref(), logger);
}

impl StatefulSandboxBackend for LxcStateAwareRunner {
    const ID_PREFIX: &'static str = "lxc";
    const BACKEND_KEY: &'static str = "lxc";

    type ProvisionConfig = LxcConfig;
    type StartConfig = ();
    type ExecConfig = ();
    type StopConfig = ();
    type DeprovisionConfig = ();
    type ProvisionMetadata = LxcProvisionMetadata;
    type StartMetadata = ();
    type StopMetadata = ();
    type DeprovisionMetadata = ();

    fn provision(
        &mut self,
        request: &ExecutionRequest,
        config: Option<LxcConfig>,
    ) -> Result<ProvisionResult<LxcProvisionMetadata>, MxcError> {
        validate_lxc_config(config.as_ref())?;
        reject_start_policy_on_other_phase("provision", &request.policy)?;

        let config = config.expect("validated above");
        let container_name = resolve_container_name(request)?;
        let container = LxcContainer::new(&container_name, None);
        let created = !container.is_defined();
        if created {
            container
                .create(&config.distribution, &config.release)
                .map_err(|e| MxcError::backend_error(format!("Failed to create container: {e}")))?;
        }

        Ok(ProvisionResult {
            sandbox_id: format!("{}:{}", Self::ID_PREFIX, container_name),
            metadata: Some(LxcProvisionMetadata {
                container_name,
                created,
            }),
        })
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StartResult<()>, MxcError> {
        let container_name = extract_container_name(sandbox_id)?;
        let container = LxcContainer::new(container_name, None);
        if !container.is_defined() {
            return Err(MxcError::not_provisioned(format!(
                "LXC container {:?} is not provisioned",
                container_name
            )));
        }
        let mut logger = Logger::new(Mode::Buffer);
        if container.is_running() {
            if has_filesystem_policy(&request.policy) || has_network_policy(&request.policy) {
                return Err(MxcError::already_started(
                    "LXC container is already running; start policy cannot be reapplied",
                ));
            }
        } else {
            apply_filesystem_policy(&container, request, &mut logger)?;
            container
                .start()
                .map_err(|e| MxcError::backend_error(format!("Failed to start container: {e}")))?;
            if let Err(e) = apply_network_policy(&container, request, &mut logger) {
                cleanup_network(container_name, &mut logger);
                let _ = container.stop();
                return Err(e);
            }
        }
        Ok(StartResult { metadata: None })
    }

    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<ExecHandle, MxcError> {
        let container_name = extract_container_name(sandbox_id)?;
        reject_start_policy_on_other_phase("exec", &request.policy)?;

        let container = LxcContainer::new(container_name, None);
        if !container.is_defined() {
            return Err(MxcError::not_provisioned(format!(
                "LXC container {:?} is not provisioned",
                container_name
            )));
        }
        if !container.is_running() {
            return Err(MxcError::not_started(format!(
                "LXC container {:?} is not started",
                container_name
            )));
        }

        let timeout = if request.script_timeout == 0 {
            None
        } else {
            Some(Duration::from_millis(u64::from(request.script_timeout)))
        };
        let exit_code = container
            .attach_run(
                &request.script_code,
                &request.working_directory,
                &request.env,
                timeout,
            )
            .map(|(exit_code, _, _)| exit_code)
            .map_err(|e| MxcError::backend_error(format!("Execution failed: {e}")))?;

        Ok(ExecHandle {
            stdout: INVALID_PIPE_HANDLE,
            stderr: INVALID_PIPE_HANDLE,
            stdin: INVALID_PIPE_HANDLE,
            waiter: Box::new(move || Ok(exit_code)),
            terminator: Box::new(|| {}),
        })
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StopResult<()>, MxcError> {
        let container_name = extract_container_name(sandbox_id)?;
        reject_start_policy_on_other_phase("stop", &request.policy)?;

        let container = LxcContainer::new(container_name, None);
        if !container.is_defined() {
            return Err(MxcError::not_provisioned(format!(
                "LXC container {:?} is not provisioned",
                container_name
            )));
        }

        let mut logger = Logger::new(Mode::Buffer);
        cleanup_network(container_name, &mut logger);
        if container.is_running() {
            container
                .stop()
                .map_err(|e| MxcError::backend_error(format!("Failed to stop container: {e}")))?;
        }
        Ok(StopResult { metadata: None })
    }

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<DeprovisionResult<()>, MxcError> {
        let container_name = extract_container_name(sandbox_id)?;
        reject_start_policy_on_other_phase("deprovision", &request.policy)?;

        let mut logger = Logger::new(Mode::Buffer);
        cleanup_network(container_name, &mut logger);
        let container = LxcContainer::new(container_name, None);
        if container.is_defined() {
            container.destroy().map_err(|e| {
                MxcError::backend_error(format!("Failed to destroy container: {e}"))
            })?;
        }
        Ok(DeprovisionResult { metadata: None })
    }

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&LxcConfig>,
    ) -> Result<(), MxcError> {
        validate_lxc_config(config)?;
        resolve_container_name(request)?;
        reject_start_policy_on_other_phase("provision", &request.policy)
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_container_name(sandbox_id)?;
        Ok(())
    }

    fn validate_exec(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_container_name(sandbox_id)?;
        reject_start_policy_on_other_phase("exec", &request.policy)
    }

    fn validate_stop(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_container_name(sandbox_id)?;
        reject_start_policy_on_other_phase("stop", &request.policy)
    }

    fn validate_deprovision(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_container_name(sandbox_id)?;
        reject_start_policy_on_other_phase("deprovision", &request.policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::LifecycleConfig;
    use wxc_common::mxc_error::MxcErrorCode;

    fn provision_config() -> LxcConfig {
        LxcConfig {
            distribution: "alpine".to_string(),
            release: "3.20".to_string(),
        }
    }

    #[test]
    fn backend_key_matches_wire_format() {
        assert_eq!(
            <LxcStateAwareRunner as StatefulSandboxBackend>::BACKEND_KEY,
            "lxc"
        );
    }

    #[test]
    fn id_prefix_matches_wire_format() {
        assert_eq!(
            <LxcStateAwareRunner as StatefulSandboxBackend>::ID_PREFIX,
            "lxc"
        );
    }

    #[test]
    fn extract_container_name_unwraps_lxc_prefix() {
        assert_eq!(
            extract_container_name("lxc:mxc-abcd1234").unwrap(),
            "mxc-abcd1234"
        );
    }

    #[test]
    fn extract_container_name_rejects_other_prefix() {
        let err = extract_container_name("iso:abc").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_container_name_rejects_missing_colon() {
        let err = extract_container_name("no-colon").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_container_name_rejects_empty_payload() {
        let err = extract_container_name("lxc:").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_container_name_rejects_invalid_name_chars() {
        let err = extract_container_name("lxc:name/with/slash").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn is_valid_container_name_rejects_dot() {
        // '.' is stripped by the iptables chain-name derivation, so "a.b" and
        // "ab" would collide onto the same chain; reject dotted names.
        assert!(!is_valid_container_name("a.b"));
    }

    #[test]
    fn is_valid_container_name_rejects_overlong_name() {
        // One character over the bound: the chain derivation would truncate it,
        // letting names that differ only past the bound collide.
        assert!(!is_valid_container_name(
            &"a".repeat(MAX_CONTAINER_NAME_LEN + 1)
        ));
    }

    #[test]
    fn is_valid_container_name_accepts_max_length_name() {
        assert!(is_valid_container_name(&"a".repeat(MAX_CONTAINER_NAME_LEN)));
    }

    #[test]
    fn extract_container_name_rejects_dotted_name() {
        let err = extract_container_name("lxc:a.b").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn generated_container_name_fits_iptables_chain_bound() {
        // The auto-generated name must itself satisfy the tightened rules so the
        // firewall chain derived from it is collision-free.
        let name = resolve_container_name(&ExecutionRequest::default()).unwrap();
        assert!(
            is_valid_container_name(&name),
            "generated name {name:?} is invalid"
        );
        assert!(name.len() <= MAX_CONTAINER_NAME_LEN);
    }

    #[test]
    fn validate_provision_requires_distribution_and_release() {
        let runner = LxcStateAwareRunner::new();
        let err = runner
            .validate_provision(&ExecutionRequest::default(), Some(&LxcConfig::default()))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }

    #[test]
    fn validate_provision_accepts_config_and_generated_id() {
        let runner = LxcStateAwareRunner::new();
        runner
            .validate_provision(&ExecutionRequest::default(), Some(&provision_config()))
            .unwrap();
    }

    #[test]
    fn validate_provision_rejects_invalid_container_id() {
        let runner = LxcStateAwareRunner::new();
        let req = ExecutionRequest {
            container_id: "bad/name".to_string(),
            ..Default::default()
        };
        let err = runner
            .validate_provision(&req, Some(&provision_config()))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }

    #[test]
    fn validate_provision_rejects_dotted_container_id() {
        // A dotted containerId would collide with its dot-stripped sibling on
        // the derived iptables chain, so provisioning must reject it up front.
        let runner = LxcStateAwareRunner::new();
        let req = ExecutionRequest {
            container_id: "has.dot".to_string(),
            ..Default::default()
        };
        let err = runner
            .validate_provision(&req, Some(&provision_config()))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }

    #[test]
    fn validate_provision_rejects_start_phase_policy() {
        let runner = LxcStateAwareRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["/workspace".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = runner
            .validate_provision(&req, Some(&provision_config()))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_start_accepts_policy_and_lxc_id() {
        let runner = LxcStateAwareRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["/workspace".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        runner
            .validate_start("lxc:mxc-abcd1234", &req, None)
            .unwrap();
    }

    #[test]
    fn validate_exec_rejects_policy() {
        let runner = LxcStateAwareRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                blocked_hosts: vec!["example.com".to_string()],
                network_enforcement_mode: NetworkEnforcementMode::Firewall,
                ..Default::default()
            },
            ..Default::default()
        };
        let err = runner
            .validate_exec("lxc:mxc-abcd1234", &req, None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn state_aware_runner_is_constructible_next_to_one_shot_lifecycle() {
        let _runner = LxcStateAwareRunner::new();
        let lifecycle = LifecycleConfig::default();
        assert!(lifecycle.destroy_on_exit);
    }
}
