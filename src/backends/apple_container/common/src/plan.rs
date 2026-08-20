// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::resource::{OwnedResource, OwnershipToken, ResourceNames};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PlanError {
    #[error("{field} must be an absolute path")]
    RelativePath { field: &'static str },
    #[error("Apple Container image must not be empty")]
    EmptyImage,
    #[error("Apple Container image must not begin with '-'")]
    InvalidImage,
    #[error("Apple Container CPU count must be greater than zero")]
    InvalidCpuCount,
    #[error("Apple Container memory limit must be greater than zero")]
    InvalidMemory,
}

/// Access granted to one host bind mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountAccess {
    ReadOnly,
    ReadWrite,
}

/// Canonical host-to-guest bind-mount plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountPlan {
    pub host_path: PathBuf,
    pub guest_path: PathBuf,
    pub access: MountAccess,
}

impl MountPlan {
    pub fn new(
        host_path: impl Into<PathBuf>,
        guest_path: impl Into<PathBuf>,
        access: MountAccess,
    ) -> Result<Self, PlanError> {
        let host_path = host_path.into();
        let guest_path = guest_path.into();
        require_absolute(&host_path, "mount host path")?;
        require_absolute(&guest_path, "mount guest path")?;
        Ok(Self {
            host_path,
            guest_path,
            access,
        })
    }
}

/// Secure environment file prepared outside process argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentFile {
    pub path: PathBuf,
}

impl EnvironmentFile {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, PlanError> {
        let path = path.into();
        require_absolute(&path, "environment file path")?;
        Ok(Self { path })
    }
}

/// Apple Container networking selected for one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPlan {
    /// Apple's normal NAT-backed default network.
    DefaultNat,
    /// Per-run host-only network with ownership verification.
    Isolated { resource: OwnedResource },
}

/// Optional VM resource limits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceLimits {
    pub cpu_count: Option<u32>,
    pub memory_mb: Option<u64>,
}

impl ResourceLimits {
    pub fn new(cpu_count: Option<u32>, memory_mb: Option<u64>) -> Result<Self, PlanError> {
        if cpu_count == Some(0) {
            return Err(PlanError::InvalidCpuCount);
        }
        if memory_mb == Some(0) {
            return Err(PlanError::InvalidMemory);
        }
        Ok(Self {
            cpu_count,
            memory_mb,
        })
    }
}

/// Fully typed inputs for a future one-shot Apple Container launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunPlan {
    pub image: String,
    pub ownership_token: OwnershipToken,
    pub container: OwnedResource,
    pub network: NetworkPlan,
    pub mounts: Vec<MountPlan>,
    pub environment_file: Option<EnvironmentFile>,
    pub resources: ResourceLimits,
}

impl RunPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        image: impl Into<String>,
        container_hint: &str,
        token: &OwnershipToken,
        isolated_network: bool,
        mounts: Vec<MountPlan>,
        environment_file: Option<EnvironmentFile>,
        resources: ResourceLimits,
    ) -> Result<Self, PlanError> {
        let image = image.into();
        let image = image.trim();
        if image.is_empty() {
            return Err(PlanError::EmptyImage);
        }
        if image.starts_with('-') {
            return Err(PlanError::InvalidImage);
        }
        let image = image.to_string();
        let names = ResourceNames::new(container_hint, token);
        let container = OwnedResource::container(names.container, token);
        let network = if isolated_network {
            NetworkPlan::Isolated {
                resource: OwnedResource::network(names.network, token),
            }
        } else {
            NetworkPlan::DefaultNat
        };
        Ok(Self {
            image,
            ownership_token: token.clone(),
            container,
            network,
            mounts,
            environment_file,
            resources,
        })
    }

    /// Cleanup targets in safe order: container first, then its network.
    pub fn cleanup_plan(&self) -> CleanupPlan {
        CleanupPlan {
            container: self.container.clone(),
            network: match &self.network {
                NetworkPlan::DefaultNat => None,
                NetworkPlan::Isolated { resource } => Some(resource.clone()),
            },
        }
    }
}

/// Owned resources to inspect, verify, and delete after a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupPlan {
    pub container: OwnedResource,
    pub network: Option<OwnedResource>,
}

fn require_absolute(path: &Path, field: &'static str) -> Result<(), PlanError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(PlanError::RelativePath { field })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use crate::resource::ResourceKind;

    fn token() -> OwnershipToken {
        OwnershipToken::parse("0123456789abcdef0123456789abcdef").unwrap()
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn isolated_run_produces_owned_cleanup_targets() {
        let plan = RunPlan::new(
            "docker.io/library/alpine:3.23",
            "test",
            &token(),
            true,
            vec![MountPlan::new("/tmp/input", "/workspace/input", MountAccess::ReadOnly).unwrap()],
            Some(EnvironmentFile::new("/tmp/mxc.env").unwrap()),
            ResourceLimits::new(Some(2), Some(1024)).unwrap(),
        )
        .unwrap();

        let cleanup = plan.cleanup_plan();
        assert_eq!(cleanup.container.name.kind(), ResourceKind::Container);
        assert_eq!(
            cleanup
                .network
                .as_ref()
                .map(|resource| resource.name.kind()),
            Some(ResourceKind::Network)
        );
    }

    #[test]
    fn plans_reject_relative_paths_and_zero_resources() {
        assert!(MountPlan::new("relative", "/guest", MountAccess::ReadOnly).is_err());
        assert!(EnvironmentFile::new("relative.env").is_err());
        assert!(ResourceLimits::new(Some(0), None).is_err());
        assert!(ResourceLimits::new(None, Some(0)).is_err());
    }

    #[test]
    fn plans_reject_image_values_that_look_like_cli_options() {
        assert!(matches!(
            RunPlan::new(
                "--rm",
                "test",
                &token(),
                false,
                Vec::new(),
                None,
                ResourceLimits::default(),
            ),
            Err(PlanError::InvalidImage)
        ));
    }
}
