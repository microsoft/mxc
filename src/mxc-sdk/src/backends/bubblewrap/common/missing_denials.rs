// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::bwrap_command::{BaselineLink, PolicyMount, BASELINE_RO_BIND_PATHS};
use super::bwrap_version::BwrapVersion;
use crate::mxc_common::filesystem_object::FilesystemPolicyError;
use crate::mxc_common::filesystem_resolve::FsIntent;

/// Keep missing deny mountpoints off the host and out of read-only binds.
/// The returned directory must outlive the sandbox's overlay mounts.
pub(crate) fn prepare(
    mounts: &mut Vec<PolicyMount>,
    baseline_links: &[BaselineLink],
    version: BwrapVersion,
) -> Result<Option<TempDir>, FilesystemPolicyError> {
    let baseline: Vec<_> = BASELINE_RO_BIND_PATHS
        .iter()
        .filter(|path| !baseline_links.iter().any(|link| link.path == **path))
        .map(|path| PolicyMount {
            source: (*path).to_owned(),
            destination: (*path).to_owned(),
            intent: FsIntent::ReadOnly,
            readonly_overlay: None,
        })
        .collect();
    let mut overlays = BTreeMap::<(String, String), Vec<PathBuf>>::new();
    for (index, denied) in mounts.iter().enumerate() {
        if denied.intent != FsIntent::Denied {
            continue;
        }
        let target = Path::new(&denied.destination);
        let parent = baseline.iter().chain(&mounts[..index]).rfind(|mount| {
            target != Path::new(&mount.destination) && target.starts_with(&mount.destination)
        });
        let Some(parent) = parent.filter(|parent| parent.intent == FsIntent::ReadOnly) else {
            continue;
        };
        let relative = target.strip_prefix(&parent.destination).map_err(|error| {
            FilesystemPolicyError::Policy(format!(
                "Bubblewrap: could not place deniedPaths entry '{}': {error}",
                denied.source
            ))
        })?;
        let host_target = Path::new(&parent.source).join(relative);
        match std::fs::symlink_metadata(&host_target) {
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(FilesystemPolicyError::Host(format!(
                    "Bubblewrap: could not inspect deniedPaths entry '{}': {error}",
                    denied.source
                )))
            }
        }
        if version < BwrapVersion::new(0, 11, 0) {
            return Err(FilesystemPolicyError::Host(format!(
                "Bubblewrap: missing deniedPaths entry '{}' beneath read-only '{}' \
                 requires bwrap 0.11.0 or newer for private read-only overlays; found {version}.",
                denied.source, parent.destination
            )));
        }
        overlays
            .entry((parent.source.clone(), parent.destination.clone()))
            .or_default()
            .push(relative.to_path_buf());
    }
    if overlays.is_empty() {
        return Ok(None);
    }

    let directory = tempfile::tempdir().map_err(|error| {
        FilesystemPolicyError::Host(format!(
            "Bubblewrap: could not create private deny mountpoint storage: {error}"
        ))
    })?;
    let storage = std::fs::canonicalize(directory.path()).map_err(|error| {
        FilesystemPolicyError::Host(format!(
            "Bubblewrap: could not resolve private deny mountpoint storage: {error}"
        ))
    })?;
    for (index, ((source, destination), paths)) in overlays.into_iter().enumerate() {
        // Overlayfs rejects lower layers that contain one another.
        if storage.starts_with(&source) || Path::new(&source).starts_with(&storage) {
            return Err(FilesystemPolicyError::Host(format!(
                "Bubblewrap: cannot prepare missing deniedPaths entry '{}' beneath \
                 read-only '{destination}': private temporary storage overlaps its host \
                 source '{source}'. Set TMPDIR outside that source.",
                Path::new(&destination).join(&paths[0]).display()
            )));
        }
        let layer = storage.join(index.to_string());
        for path in paths {
            std::fs::create_dir_all(layer.join(&path)).map_err(|error| {
                FilesystemPolicyError::Host(format!(
                    "Bubblewrap: could not prepare private mountpoint for deniedPaths \
                     entry '{}': {error}",
                    Path::new(&destination).join(path).display()
                ))
            })?;
        }
        let layer = layer.into_os_string().into_string().map_err(|_| {
            FilesystemPolicyError::Host(
                "Bubblewrap: private deny mountpoint storage is not valid UTF-8".to_owned(),
            )
        })?;
        match mounts.iter_mut().find(|mount| {
            mount.intent == FsIntent::ReadOnly
                && mount.source == source
                && mount.destination == destination
        }) {
            Some(mount) => mount.readonly_overlay = Some(layer),
            None => mounts.push(PolicyMount {
                source,
                destination,
                intent: FsIntent::ReadOnly,
                readonly_overlay: Some(layer),
            }),
        }
    }
    mounts.sort_by_key(|mount| Path::new(&mount.destination).components().count());
    Ok(Some(directory))
}

#[cfg(test)]
mod tests;
