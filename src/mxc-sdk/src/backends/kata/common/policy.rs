// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Which requests the Kata backend accepts, and how it maps filesystem policy
//! to OCI mounts.
//!
//! Anything the backend cannot enforce is rejected here, before a VM exists.

use std::path::{Component, Path, PathBuf};

use serde_json::{json, Value};

use crate::kata_common::error::KataError;
use crate::kata_common::host::{self, EnvLookup};
use crate::kata_common::loopdev;
use crate::mxc_common::filesystem_resolve::{resolve_mount_order, FsIntent};
use crate::mxc_common::filesystem_symlink::resolve_through_symlinks;
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{
    ContainerPolicy, ExecutionRequest, KataConfig, KataHypervisor, NetworkAction,
};
use crate::mxc_common::validator::NetworkPolicySupport;

/// What the guest root filesystem is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RootfsKind {
    /// A directory. Served over the shared filesystem with a writable layer.
    Directory,
    /// An ext4 image. Presented to the guest as a block device.
    Image,
}

/// Filesystem policy as OCI configuration.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct FilesystemMapping {
    /// OCI `mounts` entries, shallow to deep.
    pub(crate) mounts: Vec<Value>,
    /// OCI `linux.maskedPaths` entries: denied files, which the guest agent
    /// hides by binding `/dev/null` over them.
    pub(crate) masked_paths: Vec<String>,
}

/// A request the backend has accepted, with everything resolved.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub(crate) hypervisor: KataHypervisor,
    /// The canonical host path of the guest root filesystem.
    pub(crate) rootfs: PathBuf,
    pub(crate) rootfs_kind: RootfsKind,
    pub(crate) filesystem: FilesystemMapping,
}

/// Network policy the shared validator may accept for this backend.
///
/// The sandbox has no network interface, which enforces default deny in both
/// directions. Declaring these lets an explicit deny-all policy through;
/// [`reject_unsupported_network`] refuses every `allow`.
pub(crate) fn network_support() -> NetworkPolicySupport {
    NetworkPolicySupport::EGRESS_DEFAULT
        | NetworkPolicySupport::INGRESS_DEFAULT
        | NetworkPolicySupport::HOST_LOOPBACK
}

/// Whether the hypervisor can share host directories into the guest.
/// Firecracker has no shared filesystem.
pub(crate) fn shares_host_directories(hypervisor: KataHypervisor) -> bool {
    !matches!(hypervisor, KataHypervisor::Firecracker)
}

/// Refuses any network policy that would need an interface in the VM.
///
/// The shared validator has already refused rules and the runtime proxy
/// (the backend declares no support for them). This refuses `allow` defaults.
fn reject_unsupported_network(policy: &ContainerPolicy) -> Result<(), KataError> {
    const ADVICE: &str = "the Kata sandbox has no network interface, so only a deny-all network \
         policy can be enforced; omit network or set every default to deny";
    if policy
        .network_egress
        .as_ref()
        .is_some_and(|egress| egress.default == NetworkAction::Allow)
    {
        return Err(KataError::rejected(format!(
            "network.egress.default is allow, which the kata backend cannot enforce: {ADVICE}"
        )));
    }
    if let Some(ingress) = policy.network_ingress.as_ref() {
        if ingress.default == NetworkAction::Allow {
            return Err(KataError::rejected(format!(
                "network.ingress.default is allow, which the kata backend cannot enforce: \
                 {ADVICE}"
            )));
        }
        if ingress.host_loopback == NetworkAction::Allow {
            return Err(KataError::rejected(format!(
                "network.ingress.hostLoopback is allow, which the kata backend cannot enforce: \
                 {ADVICE}"
            )));
        }
    }
    Ok(())
}

/// The checks that need neither the host nor the filesystem. Dry runs and
/// lifecycle validation hooks use this alone.
pub(crate) fn validate_request(request: &ExecutionRequest) -> Result<(), KataError> {
    crate::mxc_common::validator::validate_network_policy_support(request, network_support())
        .map_err(|response| KataError::rejected(response.error_message))?;
    reject_unsupported_network(&request.policy)?;
    if request.policy.ui_specified {
        return Err(KataError::rejected(
            "the kata backend cannot enforce a ui policy: the sandbox is a headless VM. \
             Remove the ui section",
        ));
    }
    if !request.lifecycle.destroy_on_exit {
        return Err(KataError::rejected(
            "lifecycle.destroyOnExit=false is not supported by the kata backend: a run always \
             ends with its VM. Use the container lifecycle operations to keep a sandbox",
        ));
    }
    if request.lifecycle.preserve_policy {
        return Err(KataError::rejected(
            "lifecycle.preservePolicy is not supported by the kata backend: it installs no \
             host firewall rules to preserve",
        ));
    }
    Ok(())
}

/// The hypervisor a request selects: its own, else the host default.
pub(crate) fn resolve_hypervisor(
    config: &KataConfig,
    env: EnvLookup<'_>,
) -> Result<KataHypervisor, KataError> {
    match config.hypervisor {
        Some(hypervisor) => Ok(hypervisor),
        None => host::default_hypervisor(env).map_err(KataError::rejected),
    }
}

/// The `kata` section, which must be present.
pub(crate) fn kata_config(request: &ExecutionRequest) -> Result<&KataConfig, KataError> {
    request.kata.as_ref().ok_or_else(|| {
        KataError::rejected(
            "the kata backend requires a kata section with rootfs, the host path of the guest \
             root filesystem",
        )
    })
}

/// Checks the rootfs path and returns its canonical form and kind.
pub(crate) fn resolve_rootfs(
    rootfs: &str,
    hypervisor: KataHypervisor,
) -> Result<(PathBuf, RootfsKind), KataError> {
    let path = Path::new(rootfs);
    if !path.is_absolute() {
        return Err(KataError::rejected(format!(
            "kata.rootfs must be an absolute path, got {rootfs:?}"
        )));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| KataError::rejected(format!("kata.rootfs {rootfs:?} cannot be used: {e}")))?;
    let metadata = std::fs::metadata(&canonical)
        .map_err(|e| KataError::rejected(format!("kata.rootfs {rootfs:?} cannot be read: {e}")))?;
    let kind = if metadata.is_dir() {
        RootfsKind::Directory
    } else if metadata.is_file() {
        RootfsKind::Image
    } else {
        return Err(KataError::rejected(format!(
            "kata.rootfs {rootfs:?} must be a directory or an ext4 image file"
        )));
    };

    match kind {
        RootfsKind::Directory => {
            if !shares_host_directories(hypervisor) {
                return Err(KataError::rejected(format!(
                    "the {} hypervisor has no shared filesystem, so kata.rootfs must be an ext4 \
                     image file, not the directory {rootfs:?}. Build one with \
                     `mke2fs -t ext4 -d <rootfs-dir> <image> <size>`",
                    hypervisor.wire_name()
                )));
            }
            // The directory becomes the overlay's lowerdir, where a comma
            // starts a new option and a colon a new layer.
            if let Some(bad) = canonical
                .to_string_lossy()
                .chars()
                .find(|c| matches!(c, ',' | ':' | '\n' | '\0'))
            {
                return Err(KataError::rejected(format!(
                    "kata.rootfs {rootfs:?} contains {bad:?}, which cannot appear in an overlay \
                     mount option. Use a path without it, or a symlink to the directory"
                )));
            }
        }
        RootfsKind::Image => {
            let is_ext4 = loopdev::is_ext4_image(&canonical).map_err(|e| {
                KataError::rejected(format!("kata.rootfs {rootfs:?} cannot be read: {e}"))
            })?;
            if !is_ext4 {
                return Err(KataError::rejected(format!(
                    "kata.rootfs {rootfs:?} is a file but not an ext4 image; only ext4 images \
                     are supported"
                )));
            }
        }
    }
    Ok((canonical, kind))
}

/// Resolves a denied path through symlinks and decides how to mask it.
///
/// Returns the real host path and whether it is a file. Refuses what it cannot
/// resolve: a mask on the wrong path would leave the real target exposed.
fn resolve_denied(path: &str) -> Result<(String, bool), KataError> {
    let resolved = resolve_through_symlinks(Path::new(path)).ok_or_else(|| {
        KataError::rejected(format!("filesystem.deniedPaths entry {path:?} is empty"))
    })?;
    if let Some(error) = resolved.error {
        return Err(KataError::rejected(format!(
            "filesystem.deniedPaths entry {path:?} could not be resolved ({error}); refusing to \
             start"
        )));
    }
    let real = resolved.path.to_str().ok_or_else(|| {
        KataError::rejected(format!(
            "filesystem.deniedPaths entry {path:?} resolves to a non-UTF-8 host path that cannot \
             be masked safely; refusing to start"
        ))
    })?;
    let is_file = std::fs::symlink_metadata(real)
        .map(|m| !m.file_type().is_dir())
        .unwrap_or(false);
    Ok((real.to_string(), is_file))
}

fn check_policy_path(list: &str, path: &str) -> Result<(), KataError> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(KataError::rejected(format!(
            "filesystem.{list} entry {path:?} must be an absolute path"
        )));
    }
    if path.contains(['\0', '\n']) {
        return Err(KataError::rejected(format!(
            "filesystem.{list} entry {path:?} contains a control character"
        )));
    }
    if p.components().any(|c| c == Component::ParentDir) {
        return Err(KataError::rejected(format!(
            "filesystem.{list} entry {path:?} must not contain '..'"
        )));
    }
    Ok(())
}

/// Whether a re-bound grant sits strictly below the denied directory, which
/// needs the mask to accept a mount point.
fn has_rebound_descendant(denied: &Path, rebound: &[PathBuf]) -> bool {
    rebound
        .iter()
        .any(|path| path != denied && path.starts_with(denied))
}

/// Maps the filesystem policy to OCI mounts.
///
/// Read-write and read-only paths become bind mounts of the same path from the
/// host. A denied file is hidden with `maskedPaths`. A denied directory gets an
/// empty tmpfs over it, which is the guest agent's only way to hide one: it
/// ignores directories in `maskedPaths`.
pub(crate) fn map_filesystem(
    policy: &ContainerPolicy,
    hypervisor: KataHypervisor,
) -> Result<FilesystemMapping, KataError> {
    for (list, paths) in [
        ("readwritePaths", &policy.readwrite_paths),
        ("readonlyPaths", &policy.readonly_paths),
        ("deniedPaths", &policy.denied_paths),
    ] {
        for path in paths {
            check_policy_path(list, path)?;
        }
    }

    let plan = resolve_mount_order(policy);
    let grants: Vec<&str> = plan
        .iter()
        .filter(|m| m.intent != FsIntent::Denied)
        .map(|m| m.path.as_str())
        .collect();
    if !grants.is_empty() && !shares_host_directories(hypervisor) {
        return Err(KataError::rejected(format!(
            "the {} hypervisor has no shared filesystem, so host paths cannot be granted: \
             remove {} from filesystem.readwritePaths and filesystem.readonlyPaths, or use a \
             hypervisor that shares directories (qemu, clh, dragonball)",
            hypervisor.wire_name(),
            grants.join(", ")
        )));
    }

    let rebound: Vec<PathBuf> = grants
        .iter()
        .map(|path| {
            resolve_through_symlinks(Path::new(path))
                .map(|r| r.path)
                .unwrap_or_else(|| PathBuf::from(path))
        })
        .collect();

    let mut mapping = FilesystemMapping::default();
    for mount in &plan {
        match mount.intent {
            FsIntent::ReadWrite | FsIntent::ReadOnly => {
                let (list, access) = match mount.intent {
                    FsIntent::ReadWrite => ("readwritePaths", "rw"),
                    _ => ("readonlyPaths", "ro"),
                };
                if !Path::new(&mount.path).exists() {
                    return Err(KataError::rejected(format!(
                        "filesystem.{list} entry {:?} does not exist on the host",
                        mount.path
                    )));
                }
                mapping.mounts.push(json!({
                    "destination": mount.path,
                    "type": "bind",
                    "source": mount.path,
                    "options": ["rbind", access],
                }));
            }
            FsIntent::Denied => {
                let (real, is_file) = resolve_denied(&mount.path)?;
                if is_file {
                    mapping.masked_paths.push(real);
                } else {
                    // Writable, but only 1 MiB and discarded with the VM, when
                    // a grant below it needs a mount point inside the mask.
                    let options: &[&str] = if has_rebound_descendant(Path::new(&real), &rebound) {
                        &["nosuid", "nodev", "noexec", "mode=0555", "size=1m"]
                    } else {
                        &["ro", "nosuid", "nodev", "noexec", "mode=0000", "size=4k"]
                    };
                    mapping.mounts.push(json!({
                        "destination": real,
                        "type": "tmpfs",
                        "source": "tmpfs",
                        "options": options,
                    }));
                }
            }
        }
    }
    Ok(mapping)
}

/// Accepts a request and resolves everything the backend needs from the
/// filesystem: the hypervisor, the root filesystem, and the policy mounts.
pub(crate) fn plan(
    request: &ExecutionRequest,
    config: &KataConfig,
    env: EnvLookup<'_>,
    logger: &mut Logger,
) -> Result<Plan, KataError> {
    validate_request(request)?;
    if config.rootfs.trim().is_empty() {
        return Err(KataError::rejected("kata.rootfs must not be empty"));
    }
    let hypervisor = resolve_hypervisor(config, env)?;
    let (rootfs, rootfs_kind) = resolve_rootfs(&config.rootfs, hypervisor)?;

    // Tighten aliases of one host object to the strictest intent and refuse
    // paths the caller cannot reach, as the other Linux backends do.
    let normalized;
    let policy = match crate::mxc_common::filesystem_object::normalize_object_conflicts(
        &request.policy,
        logger,
    ) {
        Ok(Some(policy)) => {
            normalized = policy;
            &normalized
        }
        Ok(None) => &request.policy,
        Err(error) => return Err(error.into()),
    };
    crate::mxc_common::filesystem_access::check_delegation(policy)?;
    let filesystem = map_filesystem(policy, hypervisor)?;

    Ok(Plan {
        hypervisor,
        rootfs,
        rootfs_kind,
        filesystem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{
        NetworkEgressPolicy, NetworkIngressPolicy, NetworkRule, ProxyConfig,
    };

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "uname -r".into(),
            kata: Some(KataConfig {
                rootfs: "/srv/rootfs".into(),
                hypervisor: None,
            }),
            ..Default::default()
        }
    }

    fn rejected(error: KataError) -> String {
        match error {
            KataError::Rejected(message) => message,
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_plain_request_is_accepted_and_deny_all_may_be_spelled_out() {
        validate_request(&request()).unwrap();

        let mut explicit = request();
        explicit.policy.network_mode_specified = true;
        explicit.policy.network_egress = Some(NetworkEgressPolicy::default());
        explicit.policy.network_ingress = Some(NetworkIngressPolicy::default());
        validate_request(&explicit).unwrap();
    }

    #[test]
    fn network_allow_is_rejected_in_every_form() {
        let mut egress = request();
        egress.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        let message = rejected(validate_request(&egress).unwrap_err());
        assert!(message.contains("network.egress.default"), "{message}");
        assert!(message.contains("no network interface"), "{message}");

        let mut ingress = request();
        ingress.policy.network_ingress = Some(NetworkIngressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        assert!(
            rejected(validate_request(&ingress).unwrap_err()).contains("network.ingress.default")
        );

        let mut loopback = request();
        loopback.policy.network_ingress = Some(NetworkIngressPolicy {
            host_loopback: NetworkAction::Allow,
            ..Default::default()
        });
        assert!(rejected(validate_request(&loopback).unwrap_err()).contains("hostLoopback"));
    }

    #[test]
    fn egress_rules_and_the_runtime_proxy_are_rejected_by_the_shared_check() {
        let mut rules = request();
        rules.policy.network_egress = Some(NetworkEgressPolicy {
            allow: vec![NetworkRule::default()],
            ..Default::default()
        });
        assert!(rejected(validate_request(&rules).unwrap_err()).contains("allow/deny rules"));

        let mut proxy = request();
        proxy.policy.runtime_network_proxy_specified = true;
        proxy.policy.network_proxy = ProxyConfig::default();
        assert!(rejected(validate_request(&proxy).unwrap_err()).contains("networkProxy"));
    }

    #[test]
    fn a_ui_policy_a_kept_vm_and_preserved_policy_are_rejected() {
        let mut ui = request();
        ui.policy.ui_specified = true;
        assert!(rejected(validate_request(&ui).unwrap_err()).contains("ui policy"));

        let mut keep = request();
        keep.lifecycle.destroy_on_exit = false;
        assert!(rejected(validate_request(&keep).unwrap_err()).contains("destroyOnExit"));

        let mut preserve = request();
        preserve.lifecycle.preserve_policy = true;
        assert!(rejected(validate_request(&preserve).unwrap_err()).contains("preservePolicy"));
    }

    #[test]
    fn the_kata_section_and_its_rootfs_are_required() {
        let mut none = request();
        none.kata = None;
        assert!(rejected(kata_config(&none).unwrap_err()).contains("kata section"));

        let empty = KataConfig {
            rootfs: "  ".into(),
            hypervisor: None,
        };
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let error = plan(&request(), &empty, &|_| None, &mut logger).unwrap_err();
        assert!(rejected(error).contains("must not be empty"));
    }

    #[test]
    fn the_request_hypervisor_wins_over_the_host_default() {
        let env = |key: &str| (key == host::ENV_HYPERVISOR).then(|| "dragonball".to_string());
        let mut config = KataConfig {
            rootfs: "/r".into(),
            hypervisor: Some(KataHypervisor::Clh),
        };
        assert_eq!(resolve_hypervisor(&config, &env), Ok(KataHypervisor::Clh));
        config.hypervisor = None;
        assert_eq!(
            resolve_hypervisor(&config, &env),
            Ok(KataHypervisor::Dragonball)
        );
        let none = |_: &str| None;
        assert_eq!(resolve_hypervisor(&config, &none), Ok(KataHypervisor::Qemu));
    }

    #[test]
    fn a_rootfs_directory_is_refused_for_firecracker_with_the_remedy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let message = rejected(resolve_rootfs(path, KataHypervisor::Firecracker).unwrap_err());
        assert!(message.contains("firecracker"), "{message}");
        assert!(message.contains("ext4 image"), "{message}");
        assert!(message.contains("mke2fs"), "{message}");

        let (canonical, kind) = resolve_rootfs(path, KataHypervisor::Qemu).unwrap();
        assert_eq!(kind, RootfsKind::Directory);
        assert_eq!(canonical, std::fs::canonicalize(dir.path()).unwrap());
    }

    #[test]
    fn a_rootfs_file_must_be_an_ext4_image() {
        let dir = tempfile::tempdir().unwrap();
        let junk = dir.path().join("junk.img");
        std::fs::write(&junk, vec![0u8; 4096]).unwrap();
        let message = rejected(
            resolve_rootfs(junk.to_str().unwrap(), KataHypervisor::Firecracker).unwrap_err(),
        );
        assert!(message.contains("not an ext4 image"), "{message}");

        let image = dir.path().join("ok.img");
        let mut bytes = vec![0u8; 4096];
        bytes[1080] = 0x53;
        bytes[1081] = 0xEF;
        std::fs::write(&image, bytes).unwrap();
        for hypervisor in KataHypervisor::ALL {
            let (_, kind) = resolve_rootfs(image.to_str().unwrap(), hypervisor).unwrap();
            assert_eq!(kind, RootfsKind::Image);
        }
    }

    #[test]
    fn a_bad_rootfs_path_is_rejected_with_its_reason() {
        let message = rejected(resolve_rootfs("relative/path", KataHypervisor::Qemu).unwrap_err());
        assert!(message.contains("absolute"), "{message}");
        let message =
            rejected(resolve_rootfs("/nonexistent/mxc/rootfs", KataHypervisor::Qemu).unwrap_err());
        assert!(message.contains("cannot be used"), "{message}");
    }

    #[test]
    fn a_rootfs_directory_with_an_overlay_option_separator_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let odd = dir.path().join("a,b");
        std::fs::create_dir(&odd).unwrap();
        let message =
            rejected(resolve_rootfs(odd.to_str().unwrap(), KataHypervisor::Qemu).unwrap_err());
        assert!(message.contains("overlay"), "{message}");
    }

    fn policy_with(rw: &[&str], ro: &[&str], denied: &[&str]) -> ContainerPolicy {
        ContainerPolicy {
            readwrite_paths: rw.iter().map(|s| s.to_string()).collect(),
            readonly_paths: ro.iter().map(|s| s.to_string()).collect(),
            denied_paths: denied.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn grants_become_binds_of_the_same_path_shallow_to_deep() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let work = root.join("work");
        let docs = work.join("docs");
        std::fs::create_dir_all(&docs).unwrap();
        let (work_s, docs_s) = (work.to_str().unwrap(), docs.to_str().unwrap());

        let mapping = map_filesystem(
            &policy_with(&[work_s], &[docs_s], &[]),
            KataHypervisor::Qemu,
        )
        .unwrap();
        assert_eq!(
            mapping.mounts,
            vec![
                json!({"destination": work_s, "type": "bind", "source": work_s,
                       "options": ["rbind", "rw"]}),
                json!({"destination": docs_s, "type": "bind", "source": docs_s,
                       "options": ["rbind", "ro"]}),
            ]
        );
        assert!(mapping.masked_paths.is_empty());
    }

    #[test]
    fn a_denied_file_is_masked_and_a_denied_directory_gets_an_empty_read_only_tmpfs() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let secret_file = root.join("secret.txt");
        std::fs::write(&secret_file, "x").unwrap();
        let secret_dir = root.join("private");
        std::fs::create_dir(&secret_dir).unwrap();

        let mapping = map_filesystem(
            &policy_with(
                &[],
                &[],
                &[secret_file.to_str().unwrap(), secret_dir.to_str().unwrap()],
            ),
            KataHypervisor::Dragonball,
        )
        .unwrap();
        assert_eq!(mapping.masked_paths, [secret_file.to_str().unwrap()]);
        assert_eq!(mapping.mounts.len(), 1);
        assert_eq!(mapping.mounts[0]["type"], "tmpfs");
        assert_eq!(
            mapping.mounts[0]["destination"],
            secret_dir.to_str().unwrap()
        );
        let options = mapping.mounts[0]["options"].as_array().unwrap();
        assert!(options.iter().any(|o| o == "ro"), "{options:?}");
    }

    #[test]
    fn a_denied_directory_with_a_grant_below_it_gets_a_mask_that_accepts_a_mount_point() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let outer = root.join("outer");
        let inner = outer.join("inner");
        std::fs::create_dir_all(&inner).unwrap();

        let mapping = map_filesystem(
            &policy_with(&[inner.to_str().unwrap()], &[], &[outer.to_str().unwrap()]),
            KataHypervisor::Clh,
        )
        .unwrap();
        // The mask comes first (shallower), then the grant is bound inside it.
        assert_eq!(mapping.mounts[0]["type"], "tmpfs");
        let options = mapping.mounts[0]["options"].as_array().unwrap();
        assert!(!options.iter().any(|o| o == "ro"), "{options:?}");
        assert_eq!(mapping.mounts[1]["type"], "bind");
    }

    #[test]
    fn a_denied_symlink_masks_its_real_target() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let real = root.join("real.txt");
        std::fs::write(&real, "x").unwrap();
        let link = root.join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let mapping = map_filesystem(
            &policy_with(&[], &[], &[link.to_str().unwrap()]),
            KataHypervisor::Qemu,
        )
        .unwrap();
        assert_eq!(mapping.masked_paths, [real.to_str().unwrap()]);
    }

    #[test]
    fn a_dangling_denied_symlink_is_refused_rather_than_masked_wrongly() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let link = root.join("dangling");
        std::os::unix::fs::symlink(root.join("gone"), &link).unwrap();
        let message = rejected(
            map_filesystem(
                &policy_with(&[], &[], &[link.to_str().unwrap()]),
                KataHypervisor::Qemu,
            )
            .unwrap_err(),
        );
        assert!(
            message.contains("could not be resolved") || message.contains("refusing"),
            "{message}"
        );
    }

    #[test]
    fn firecracker_refuses_grants_but_still_hides_denied_paths() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let message = rejected(
            map_filesystem(
                &policy_with(&[root.to_str().unwrap()], &[], &[]),
                KataHypervisor::Firecracker,
            )
            .unwrap_err(),
        );
        assert!(message.contains("no shared filesystem"), "{message}");
        assert!(message.contains(root.to_str().unwrap()), "{message}");

        let secret = root.join("secret");
        std::fs::write(&secret, "x").unwrap();
        let mapping = map_filesystem(
            &policy_with(&[], &[], &[secret.to_str().unwrap()]),
            KataHypervisor::Firecracker,
        )
        .unwrap();
        assert_eq!(mapping.masked_paths, [secret.to_str().unwrap()]);
    }

    #[test]
    fn a_grant_that_does_not_exist_is_rejected_by_name() {
        let message = rejected(
            map_filesystem(
                &policy_with(&["/nonexistent/mxc/grant"], &[], &[]),
                KataHypervisor::Qemu,
            )
            .unwrap_err(),
        );
        assert!(message.contains("readwritePaths"), "{message}");
        assert!(message.contains("/nonexistent/mxc/grant"), "{message}");
    }

    #[test]
    fn relative_and_parent_traversing_policy_paths_are_rejected() {
        for (rw, expected) in [("relative", "absolute"), ("/a/../b", "..")] {
            let message = rejected(
                map_filesystem(&policy_with(&[rw], &[], &[]), KataHypervisor::Qemu).unwrap_err(),
            );
            assert!(message.contains(expected), "{message}");
        }
    }
}
