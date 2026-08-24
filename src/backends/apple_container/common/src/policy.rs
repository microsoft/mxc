// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;
use wxc_common::models::{
    ClipboardPolicy, ExecutionRequest, NetworkEnforcementMode, NetworkPolicy,
};

use crate::plan::{EnvironmentFile, MountAccess, MountPlan, PlanError, ResourceLimits, RunPlan};
use crate::resource::{OwnershipToken, ResourceError};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("{0}")]
    Rejected(String),
    #[error("{0}")]
    Plan(#[from] PlanError),
    #[error("{0}")]
    Resource(#[from] ResourceError),
    #[error("failed to canonicalize Apple Container policy path {path:?}: {source}")]
    Canonicalize {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Validate the Apple Container policy and create an immutable launch plan.
pub fn build_run_plan(
    request: &ExecutionRequest,
    environment_file: Option<EnvironmentFile>,
) -> Result<RunPlan, PolicyError> {
    validate_policy(request)?;
    let config = request
        .experimental
        .apple_container
        .as_ref()
        .ok_or_else(|| {
            PolicyError::Rejected(
                "Apple Container requires experimental.apple_container configuration".to_string(),
            )
        })?;
    let mounts = build_mounts(request)?;
    let token = OwnershipToken::generate()?;
    let resources = ResourceLimits::new(config.cpu_count, config.memory_mb)?;
    RunPlan::new(
        &config.image,
        &request.container_id,
        &token,
        request.policy.default_network_policy == NetworkPolicy::Block,
        mounts,
        environment_file,
        resources,
    )
    .map_err(Into::into)
}

/// Validate the complete one-shot policy before any Apple resource is created.
pub fn validate_policy(request: &ExecutionRequest) -> Result<(), PolicyError> {
    if !request.experimental_enabled {
        return Err(rejected(
            "Apple Container is experimental; use the --experimental flag",
        ));
    }
    if request.experimental.apple_container.is_none() {
        return Err(rejected(
            "Apple Container requires experimental.apple_container configuration",
        ));
    }
    if !request.policy.capabilities.is_empty() {
        return Err(rejected(
            "Apple Container does not support requested process capabilities",
        ));
    }
    if request.policy.least_privilege_mode {
        return Err(rejected(
            "Apple Container does not support process leastPrivilegeMode",
        ));
    }
    if request.policy.fallback_specified {
        return Err(rejected(
            "Apple Container does not support the Windows-only fallback policy",
        ));
    }
    if request.policy.allow_local_network {
        return Err(rejected(
            "Apple Container does not support network.allowLocalNetwork=true",
        ));
    }
    if !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty() {
        return Err(rejected(
            "Apple Container does not support network.allowedHosts or network.blockedHosts",
        ));
    }
    if request.policy.network_proxy.is_enabled() {
        return Err(rejected("Apple Container does not support network.proxy"));
    }
    if request.policy.network_enforcement_mode_specified
        || request.policy.network_enforcement_mode != NetworkEnforcementMode::Capabilities
    {
        return Err(rejected(
            "Apple Container does not support network.enforcementMode",
        ));
    }
    if !request.policy.ui.disable
        || request.policy.ui.clipboard != ClipboardPolicy::None
        || request.policy.ui.injection
    {
        return Err(rejected(
            "Apple Container supports only the default-deny UI policy",
        ));
    }
    if !request.lifecycle.destroy_on_exit {
        return Err(rejected(
            "Apple Container one-shot execution requires lifecycle.destroyOnExit=true",
        ));
    }
    if request.lifecycle.preserve_policy {
        return Err(rejected(
            "Apple Container one-shot execution does not support lifecycle.preservePolicy=true",
        ));
    }
    if request.policy.capture_denials.is_some() {
        return Err(rejected(
            "Apple Container does not support processContainer.captureDenials",
        ));
    }
    let process_container_ui = &request.policy.base_process_ui;
    if process_container_ui.isolation != "container"
        || process_container_ui.desktop_system_control
        || process_container_ui.system_settings != "none"
        || process_container_ui.ime
    {
        return Err(rejected(
            "Apple Container does not support processContainer.ui",
        ));
    }
    if !request.working_directory.is_empty() && !Path::new(&request.working_directory).is_absolute()
    {
        return Err(rejected(
            "Apple Container process.cwd must be an absolute guest path",
        ));
    }
    validate_environment(&request.env)?;
    Ok(())
}

fn validate_environment(environment: &[String]) -> Result<(), PolicyError> {
    for entry in environment {
        let Some((key, _)) = entry.split_once('=') else {
            return Err(rejected(
                "Apple Container process.env entries must use KEY=VALUE form",
            ));
        };
        if key.is_empty()
            || !key
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || key.contains('\0')
            || key.contains('\n')
            || key.contains('\r')
            || key.contains('=')
        {
            return Err(rejected(
                "Apple Container process.env contains an invalid variable name",
            ));
        }
        if entry.contains('\0') || entry.contains('\n') || entry.contains('\r') {
            return Err(rejected(
                "Apple Container process.env values must not contain NUL or newline characters",
            ));
        }
    }
    Ok(())
}

fn build_mounts(request: &ExecutionRequest) -> Result<Vec<MountPlan>, PolicyError> {
    let mut destinations = BTreeMap::<PathBuf, MountAccess>::new();
    let mut mounts = Vec::new();
    for (paths, access) in [
        (&request.policy.readwrite_paths, MountAccess::ReadWrite),
        (&request.policy.readonly_paths, MountAccess::ReadOnly),
    ] {
        for requested in paths {
            let requested_path = Path::new(requested);
            let guest_path = normalize_absolute(requested_path).ok_or_else(|| {
                rejected(format!(
                    "Apple Container mount path {requested:?} must be absolute and normalized"
                ))
            })?;
            let guest_text = guest_path.to_str().ok_or_else(|| {
                rejected(format!(
                    "Apple Container mount path {requested:?} is not valid UTF-8"
                ))
            })?;
            if guest_text.contains(',') {
                return Err(rejected(format!(
                    "Apple Container mount path {guest_text:?} contains ',' and cannot be represented safely"
                )));
            }
            let canonical =
                std::fs::canonicalize(&guest_path).map_err(|source| PolicyError::Canonicalize {
                    path: requested.clone(),
                    source,
                })?;
            let canonical_text = canonical.to_str().ok_or_else(|| {
                rejected(format!(
                    "Apple Container mount path {requested:?} resolves to a non-UTF-8 path"
                ))
            })?;
            if canonical_text.contains(',') {
                return Err(rejected(format!(
                    "Apple Container mount path {canonical_text:?} contains ',' and cannot be represented safely"
                )));
            }
            if let Some(existing) = destinations.insert(canonical.clone(), access) {
                let conflict = if existing == access {
                    "duplicate"
                } else {
                    "conflicting read-only/read-write"
                };
                return Err(rejected(format!(
                    "Apple Container has {conflict} mount destination {canonical:?}"
                )));
            }
            mounts.push(MountPlan::new(&canonical, guest_path, access)?);
        }
    }

    for denied in &request.policy.denied_paths {
        let denied = normalize_absolute(Path::new(denied)).ok_or_else(|| {
            rejected(format!(
                "Apple Container denied path {denied:?} must be an absolute normalized path"
            ))
        })?;
        let denied =
            resolve_existing_prefix(&denied).map_err(|source| PolicyError::Canonicalize {
                path: denied.to_string_lossy().into_owned(),
                source,
            })?;
        if destinations
            .keys()
            .any(|mapped| denied.starts_with(mapped) || mapped.starts_with(&denied))
        {
            return Err(rejected(format!(
                "Apple Container cannot combine denied path {denied:?} with an overlapping mapped path"
            )));
        }
    }
    Ok(mounts)
}

fn resolve_existing_prefix(path: &Path) -> std::io::Result<PathBuf> {
    let mut prefix = path;
    let mut absent_tail = Vec::new();
    loop {
        match std::fs::canonicalize(prefix) {
            Ok(mut canonical) => {
                for component in absent_tail.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::symlink_metadata(prefix) {
                    Ok(_) => return Err(error),
                    Err(metadata_error)
                        if metadata_error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(metadata_error) => return Err(metadata_error),
                }
                let Some(name) = prefix.file_name() else {
                    return Err(error);
                };
                absent_tail.push(name.to_os_string());
                let Some(parent) = prefix.parent() else {
                    return Err(error);
                };
                prefix = parent;
            }
            Err(error) => return Err(error),
        }
    }
}

fn normalize_absolute(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => normalized.push(component),
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

fn rejected(message: impl Into<String>) -> PolicyError {
    PolicyError::Rejected(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{AppleContainerConfig, ExperimentalConfig};

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            container_id: "test".to_string(),
            script_code: "echo ok".to_string(),
            containment: wxc_common::models::ContainmentBackend::AppleContainer,
            experimental_enabled: true,
            experimental: ExperimentalConfig {
                apple_container: Some(AppleContainerConfig {
                    image: "alpine:3.22".to_string(),
                    cpu_count: None,
                    memory_mb: None,
                }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn rejects_every_unsupported_network_and_lifecycle_grant() {
        let mut cases = Vec::new();
        let mut local = request();
        local.policy.allow_local_network = true;
        cases.push(local);
        let mut hosts = request();
        hosts.policy.allowed_hosts.push("example.com".to_string());
        cases.push(hosts);
        let mut enforcement = request();
        enforcement.policy.network_enforcement_mode = NetworkEnforcementMode::Firewall;
        cases.push(enforcement);
        let mut retain = request();
        retain.lifecycle.destroy_on_exit = false;
        cases.push(retain);
        let mut preserve = request();
        preserve.lifecycle.preserve_policy = true;
        cases.push(preserve);
        let mut process_container_ui = request();
        process_container_ui.policy.base_process_ui.ime = true;
        cases.push(process_container_ui);

        for case in cases {
            assert!(validate_policy(&case).is_err());
        }
    }

    #[test]
    fn rejects_unsafe_environment_file_entries() {
        for entry in ["PATH", "=value", "KEY=line\nnext", "BAD\rKEY=value"] {
            let mut request = request();
            request.env = vec![entry.to_string()];
            assert!(validate_policy(&request).is_err(), "accepted {entry:?}");
        }
    }

    #[test]
    fn accepts_default_deny_policy() {
        assert!(validate_policy(&request()).is_ok());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn rejects_denied_and_mapped_path_overlap_in_either_direction() {
        let root =
            std::env::temp_dir().join(format!("mxc-apple-policy-overlap-{}", std::process::id()));
        let child = root.join("child");
        std::fs::create_dir_all(&child).unwrap();

        for (mapped, denied) in [(&root, &child), (&child, &root)] {
            let mut request = request();
            request.policy.readwrite_paths = vec![mapped.to_string_lossy().into_owned()];
            request.policy.denied_paths = vec![denied.to_string_lossy().into_owned()];

            let error = build_run_plan(&request, None).unwrap_err();

            assert!(
                error.to_string().contains("overlapping mapped path"),
                "{error}"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn mount_preserves_requested_guest_path_after_host_canonicalization() {
        let root = std::env::temp_dir().join(format!(
            "mxc-apple-policy-destination-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut request = request();
        request.policy.readwrite_paths = vec![root.to_string_lossy().into_owned()];

        let plan = build_run_plan(&request, None).unwrap();

        assert_eq!(plan.mounts[0].guest_path, root);
        assert_eq!(
            plan.mounts[0].host_path,
            std::fs::canonicalize(&root).unwrap()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
