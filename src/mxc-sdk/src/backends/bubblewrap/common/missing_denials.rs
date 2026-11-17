// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::BTreeMap;
#[cfg(any(target_os = "linux", test))]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::bwrap_command::{BaselineLink, PolicyMount, BASELINE_RO_BIND_PATHS};
use super::bwrap_version::BwrapVersion;
use crate::mxc_common::filesystem_object::FilesystemPolicyError;
use crate::mxc_common::filesystem_probe::FilesystemProbe;
use crate::mxc_common::filesystem_resolve::FsIntent;

#[cfg(target_os = "linux")]
const MAX_MOUNTINFO_BYTES: usize = 1_048_576;
#[cfg(any(target_os = "linux", test))]
const MAX_MOUNTINFO_ENTRIES: usize = 4096;

#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
struct MountInfoEntry {
    device: (u32, u32),
    root: PathBuf,
    mountpoint: PathBuf,
}

fn inspect_path(
    probe: &mut FilesystemProbe,
    path: PathBuf,
) -> Result<Result<(), std::io::Error>, String> {
    let display = path.display().to_string();
    probe.run(&display, move |_| {
        #[cfg(test)]
        crate::mxc_common::filesystem_probe::launch_tests::stall("bwrap-missing-denials", &path);
        std::fs::symlink_metadata(path).map(|_| ())
    })
}

fn baseline_mounts(
    paths: &[&str],
    baseline_links: &[BaselineLink],
    probe: &mut FilesystemProbe,
) -> Result<Vec<PolicyMount>, FilesystemPolicyError> {
    let mut mounts = Vec::new();
    for &path in paths {
        if baseline_links.iter().any(|link| link.path == path) {
            continue;
        }
        match inspect_path(probe, PathBuf::from(path)).map_err(FilesystemPolicyError::Host)? {
            Ok(()) => mounts.push(PolicyMount {
                source: path.to_owned(),
                destination: path.to_owned(),
                intent: FsIntent::ReadOnly,
                readonly_overlay: None,
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(FilesystemPolicyError::Host(format!(
                    "Bubblewrap: could not inspect baseline source '{path}': {error}"
                )))
            }
        }
    }
    Ok(mounts)
}

/// What a policy needs before Bubblewrap can enforce its deny masks.
#[derive(Debug)]
pub(crate) struct DenyPreparation {
    /// Private storage backing the read-only overlays, held so the overlays
    /// stay mounted for as long as the sandbox runs.
    pub(crate) _storage: Option<TempDir>,

    /// Mount points Bubblewrap will make on the host for denied entries that do
    /// not exist yet beneath a read-write grant.
    mount_points: Vec<HostMountPoint>,

    /// Cleared once the sandbox owns the cleanup. Until then, dropping this
    /// removes the mount points, so a startup path that gives up after bwrap
    /// already created its masks does not leave them behind.
    armed: bool,
}

impl DenyPreparation {
    /// Hand the cleanup to whoever now owns the sandbox. That owner calls
    /// [`Self::remove_placeholders`] once the sandbox has stopped; until it
    /// does, dropping this no longer removes anything.
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    /// Remove the mount points now. Safe to call more than once, and callable
    /// after [`Self::disarm`]: handing the cleanup over changes who calls this,
    /// not whether it may run.
    pub(crate) fn remove_placeholders(&mut self) {
        if self.mount_points.is_empty() {
            return;
        }
        remove_mount_points(&self.mount_points);
        self.mount_points.clear();
    }
}

impl Drop for DenyPreparation {
    fn drop(&mut self) {
        if self.armed {
            self.remove_placeholders();
        }
    }
}

/// A mount point Bubblewrap creates on the host for a missing denied entry
/// beneath a read-write grant.
#[derive(Debug)]
pub(crate) struct HostMountPoint {
    /// The deepest path Bubblewrap creates. Its parents below
    /// `existing_ancestor` are new too when the entry names more than one
    /// missing level.
    pub(crate) path: PathBuf,

    /// The deepest directory that already existed when the policy was
    /// prepared, spelled the way this run spells it. Removal stops here:
    /// everything below it is this run's placeholder, everything at or above it
    /// is the caller's, whether or not it happens to be empty.
    pub(crate) spelled_ancestor: PathBuf,

    /// The same directory, resolved to the entity it was at preparation.
    /// Removal compares against this, so an ancestor the caller replaced with a
    /// symlink in the meantime does not redirect it.
    pub(crate) existing_ancestor: PathBuf,
}

/// The deepest directory at or above `path` that exists right now.
///
/// `path` itself is known to be missing, so this starts at its parent and walks
/// up to `stop_at`. Returns `stop_at` when nothing below it exists: the grant is
/// the caller's own directory, and Bubblewrap fails on a grant it cannot bind.
fn deepest_existing_ancestor(
    probe: &mut FilesystemProbe,
    path: &Path,
    stop_at: &Path,
) -> Result<PathBuf, FilesystemPolicyError> {
    let mut current = path.parent();
    while let Some(candidate) = current.filter(|candidate| *candidate != stop_at) {
        match inspect_path(probe, candidate.to_path_buf()).map_err(FilesystemPolicyError::Host)? {
            Ok(()) => return Ok(candidate.to_path_buf()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(FilesystemPolicyError::Host(format!(
                    "Bubblewrap: could not inspect '{}' above a missing deniedPaths entry: {error}",
                    candidate.display()
                )))
            }
        }
        current = candidate.parent();
    }
    Ok(stop_at.to_path_buf())
}

/// Remove the mount points Bubblewrap created for missing denied entries.
///
/// Only placeholders this run left behind are removed, walking up from each one
/// to the ancestor that already existed when the policy was prepared. A
/// directory the workload wrote into, or a file with content, is left alone
/// together with everything above it, so this never deletes anything the caller
/// or the workload owns.
///
/// The path is re-resolved for every removal and must still be the same entity
/// the preparation recorded. `symlink_metadata` only refuses to follow the last
/// component: an ancestor replaced by a symlink while the sandbox ran would
/// otherwise redirect the removal to wherever that link points.
///
/// Runs on the same bounded worker startup uses. Teardown walks filesystems the
/// caller granted, and one that stops answering would otherwise hold the handle
/// and a timed-out sandbox's return open indefinitely; a probe that does not
/// answer within its deadline leaves the objects in place instead.
pub(crate) fn remove_mount_points(mount_points: &[HostMountPoint]) {
    let mut probe = FilesystemProbe::default();
    for mount_point in mount_points {
        let relative = match mount_point.path.strip_prefix(&mount_point.spelled_ancestor) {
            Ok(relative) => relative.to_path_buf(),
            Err(_) => continue,
        };
        let spelled = mount_point.path.clone();
        let ancestor = mount_point.existing_ancestor.clone();
        let display = spelled.display().to_string();
        // One probe per placeholder, so a stalled filesystem costs a deadline
        // once instead of once per level. A probe that does not answer leaves
        // the objects in place, which is the safe outcome.
        let _ = probe.run(&display, move |_| {
            remove_below(&spelled, &ancestor, &relative)
        });
    }
}

/// Walk up from `spelled`, removing empty placeholders until the spelled
/// ancestor or the first path that is no longer ours.
fn remove_below(spelled: &Path, resolved_ancestor: &Path, relative: &Path) {
    let mut spelled = spelled.to_path_buf();
    let mut relative = relative.to_path_buf();
    while !relative.as_os_str().is_empty() {
        if !remove_placeholder(&spelled, resolved_ancestor, &relative) {
            return;
        }
        let (Some(parent), Some(up)) = (
            spelled.parent().map(Path::to_path_buf),
            relative.parent().map(Path::to_path_buf),
        ) else {
            return;
        };
        spelled = parent;
        relative = up;
    }
}

/// Remove an empty placeholder: a directory Bubblewrap made for a `--tmpfs`
/// mask, or the empty file it made for a `--ro-bind /dev/null` mask.
///
/// `spelled` is removed only when resolving it lands exactly on `relative`
/// below `resolved_ancestor`, the entity recorded at preparation. A path that
/// now resolves elsewhere — an ancestor replaced by a symlink, or a component
/// that became a link — is left alone: this run did not make what is there now.
fn remove_placeholder(spelled: &Path, resolved_ancestor: &Path, relative: &Path) -> bool {
    let Ok(resolved) = std::fs::canonicalize(spelled) else {
        return false;
    };
    if resolved != resolved_ancestor.join(relative) {
        return false;
    }
    match std::fs::symlink_metadata(spelled) {
        Ok(metadata) if metadata.is_dir() => std::fs::remove_dir(spelled).is_ok(),
        Ok(metadata) if metadata.is_file() && metadata.len() == 0 => {
            std::fs::remove_file(spelled).is_ok()
        }
        _ => false,
    }
}

/// Keep missing deny mountpoints off the host and out of read-only binds.
///
/// A read-only parent can be overlaid privately, so nothing is created on the
/// host. A read-write parent is bound from the host as it is, which leaves the
/// mount point Bubblewrap needs in that same directory; those entries are
/// reported in [`DenyPreparation::mount_points`] for the sandbox to remove.
pub(crate) fn prepare(
    mounts: &mut Vec<PolicyMount>,
    baseline_links: &[BaselineLink],
    version: BwrapVersion,
    bwrap_is_setuid: bool,
) -> Result<DenyPreparation, FilesystemPolicyError> {
    let mut probe = FilesystemProbe::default();
    let baseline = baseline_mounts(BASELINE_RO_BIND_PATHS, baseline_links, &mut probe)?;
    let mut overlays = BTreeMap::<(String, String), Vec<PathBuf>>::new();
    let mut mount_points = Vec::new();
    for (index, denied) in mounts.iter().enumerate() {
        if denied.intent != FsIntent::Denied {
            continue;
        }
        let target = Path::new(&denied.destination);
        let parent = baseline.iter().chain(&mounts[..index]).rfind(|mount| {
            target != Path::new(&mount.destination) && target.starts_with(&mount.destination)
        });
        // A denied parent is masked with its own tmpfs, so a denied entry below
        // it is created inside that tmpfs and never reaches the host. A denied
        // parent has no host directory to prepare against either.
        let Some(parent) = parent.filter(|parent| parent.intent != FsIntent::Denied) else {
            continue;
        };
        let relative = target.strip_prefix(&parent.destination).map_err(|error| {
            FilesystemPolicyError::Policy(format!(
                "Bubblewrap: could not place deniedPaths entry '{}': {error}",
                denied.source
            ))
        })?;
        let host_target = Path::new(&parent.source).join(relative);
        match inspect_path(&mut probe, host_target.clone()).map_err(FilesystemPolicyError::Host)? {
            Ok(()) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(FilesystemPolicyError::Host(format!(
                    "Bubblewrap: could not inspect deniedPaths entry '{}': {error}",
                    denied.source
                )))
            }
        }
        if parent.intent == FsIntent::ReadOnly {
            overlays
                .entry((parent.source.clone(), parent.destination.clone()))
                .or_default()
                .push(relative.to_path_buf());
        } else {
            let grant = Path::new(&parent.source);
            let spelled_ancestor = deepest_existing_ancestor(&mut probe, &host_target, grant)?;
            mount_points.push(HostMountPoint {
                existing_ancestor: std::fs::canonicalize(&spelled_ancestor).map_err(|error| {
                    FilesystemPolicyError::Host(format!(
                        "Bubblewrap: could not resolve '{}' above a missing deniedPaths entry: \
                         {error}",
                        spelled_ancestor.display()
                    ))
                })?,
                spelled_ancestor,
                path: host_target,
            });
        }
    }
    let first_overlay = overlays
        .iter()
        .next()
        .and_then(|((_, destination), paths)| {
            paths
                .first()
                .map(|path| (destination.clone(), path.clone()))
        });
    let Some((first_destination, first_path)) = first_overlay else {
        return Ok(DenyPreparation {
            _storage: None,
            mount_points,
            armed: true,
        });
    };

    #[cfg(target_os = "linux")]
    let mountinfo = read_mountinfo(&mut probe)?;

    #[cfg(target_os = "linux")]
    for ((source, destination), paths) in &overlays {
        if let Some(nested) = nested_mountpoint(Path::new(source), &mountinfo) {
            let Some(path) = paths.first() else {
                continue;
            };
            return Err(FilesystemPolicyError::Host(format!(
                "Bubblewrap: missing deniedPaths entry '{}' beneath read-only '{destination}' \
                 cannot be enforced because nested host mount '{}' would be hidden by its \
                 private overlay. Use a read-only grant without nested mounts or avoid a \
                 missing denied path beneath that grant.",
                Path::new(destination).join(path).display(),
                nested.display()
            )));
        }
    }
    if version < BwrapVersion::new(0, 11, 0) {
        return Err(FilesystemPolicyError::Host(format!(
            "Bubblewrap: missing deniedPaths entry '{}' beneath read-only '{}' \
             requires bwrap 0.11.0 or newer for private read-only overlays; found {version}.",
            Path::new(&first_destination).join(first_path).display(),
            first_destination
        )));
    }
    if bwrap_is_setuid {
        return Err(FilesystemPolicyError::Host(format!(
            "Bubblewrap: missing deniedPaths entry '{}' beneath read-only '{}' requires a \
             non-setuid bwrap installation; the selected bwrap has the setuid bit set.",
            Path::new(&first_destination).join(first_path).display(),
            first_destination
        )));
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
    #[cfg(target_os = "linux")]
    add_alias_masks(&storage, &mountinfo, mounts).map_err(FilesystemPolicyError::Host)?;
    // A caller may grant its whole temporary directory read-write. The workload
    // must not reach the overlay's private lower layer through any bind alias.
    let hidden = storage.into_os_string().into_string().map_err(|_| {
        FilesystemPolicyError::Host(
            "Bubblewrap: private deny mountpoint storage is not valid UTF-8".to_owned(),
        )
    })?;
    mounts.push(PolicyMount {
        source: hidden.clone(),
        destination: hidden,
        intent: FsIntent::Denied,
        readonly_overlay: None,
    });
    mounts.sort_by_key(|mount| Path::new(&mount.destination).components().count());
    Ok(DenyPreparation {
        _storage: Some(directory),
        mount_points,
        armed: true,
    })
}

#[cfg(target_os = "linux")]
fn read_mountinfo(
    probe: &mut FilesystemProbe,
) -> Result<Vec<MountInfoEntry>, FilesystemPolicyError> {
    let contents = probe
        .run("/proc/self/mountinfo", read_mountinfo_file)
        .map_err(FilesystemPolicyError::Host)?
        .map_err(|error| {
            FilesystemPolicyError::Host(format!(
                "Bubblewrap: could not read /proc/self/mountinfo: {error}"
            ))
        })?;
    parse_mountinfo(&contents).map_err(FilesystemPolicyError::Host)
}

#[cfg(target_os = "linux")]
fn read_mountinfo_file(path: &str) -> io::Result<String> {
    let file = std::fs::File::open(path)?;
    let mut contents = String::new();
    file.take((MAX_MOUNTINFO_BYTES + 1) as u64)
        .read_to_string(&mut contents)?;
    if contents.len() > MAX_MOUNTINFO_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mount information exceeds the 1 MiB limit",
        ));
    }
    Ok(contents)
}

#[cfg(any(target_os = "linux", test))]
fn parse_mountinfo(contents: &str) -> Result<Vec<MountInfoEntry>, String> {
    let mut entries = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        if index >= MAX_MOUNTINFO_ENTRIES {
            return Err(format!(
                "mount information exceeds the {MAX_MOUNTINFO_ENTRIES} entry limit"
            ));
        }
        let Some((fields, filesystem_fields)) = line.split_once(" - ") else {
            return Err(format!(
                "mount information entry {} has no filesystem separator",
                index + 1
            ));
        };
        let fields = fields.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 6
            || filesystem_fields.split_whitespace().count() < 3
            || fields[0].parse::<u64>().is_err()
            || fields[1].parse::<u64>().is_err()
        {
            return Err(format!(
                "mount information entry {} is incomplete or has invalid identifiers",
                index + 1
            ));
        }
        let device = fields[2]
            .split_once(':')
            .and_then(|(major, minor)| {
                Some((major.parse::<u32>().ok()?, minor.parse::<u32>().ok()?))
            })
            .ok_or_else(|| {
                format!(
                    "mount information entry {} has an invalid device number",
                    index + 1
                )
            })?;
        let root = PathBuf::from(unescape_mountinfo_path(fields[3]).ok_or_else(|| {
            format!(
                "mount information entry {} has an invalid root path",
                index + 1
            )
        })?);
        let mountpoint = PathBuf::from(unescape_mountinfo_path(fields[4]).ok_or_else(|| {
            format!(
                "mount information entry {} has an invalid mountpoint",
                index + 1
            )
        })?);
        if !root.is_absolute() || !mountpoint.is_absolute() {
            return Err(format!(
                "mount information entry {} contains a non-absolute path",
                index + 1
            ));
        }
        entries.push(MountInfoEntry {
            device,
            root,
            mountpoint,
        });
    }
    if entries.is_empty() {
        return Err("mount information contains no entries".to_owned());
    }
    Ok(entries)
}

#[cfg(any(target_os = "linux", test))]
fn unescape_mountinfo_path(path: &str) -> Option<String> {
    let mut unescaped = String::new();
    let mut characters = path.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            unescaped.push(character);
            continue;
        }
        let escape: String = characters.by_ref().take(3).collect();
        unescaped.push(match escape.as_str() {
            "040" => ' ',
            "011" => '\t',
            "012" => '\n',
            "134" => '\\',
            _ => return None,
        });
        if escape.len() != 3 {
            return None;
        }
    }
    Some(unescaped)
}

#[cfg(any(target_os = "linux", test))]
fn nested_mountpoint<'a>(source: &Path, entries: &'a [MountInfoEntry]) -> Option<&'a Path> {
    entries
        .iter()
        .find(|entry| entry.mountpoint != source && entry.mountpoint.starts_with(source))
        .map(|entry| entry.mountpoint.as_path())
}

#[cfg(any(target_os = "linux", test))]
fn mount_aliases(path: &Path, entries: &[MountInfoEntry]) -> Result<BTreeSet<PathBuf>, String> {
    let containing = entries
        .iter()
        .filter(|entry| path.starts_with(&entry.mountpoint))
        .max_by_key(|entry| entry.mountpoint.components().count())
        .ok_or_else(|| {
            format!(
                "private temporary storage '{}' is not listed in mount information",
                path.display()
            )
        })?;
    let root = containing
        .root
        .join(path.strip_prefix(&containing.mountpoint).map_err(|error| {
            format!(
                "could not locate private temporary storage '{}' in mount information: {error}",
                path.display()
            )
        })?);
    let mut aliases = entries
        .iter()
        .filter(|entry| entry.device == containing.device && root.starts_with(&entry.root))
        .filter_map(|entry| {
            root.strip_prefix(&entry.root)
                .ok()
                .map(|relative| entry.mountpoint.join(relative))
        })
        .collect::<BTreeSet<_>>();
    aliases.remove(path);
    Ok(aliases)
}

#[cfg(any(target_os = "linux", test))]
fn add_alias_masks(
    storage: &Path,
    entries: &[MountInfoEntry],
    mounts: &mut Vec<PolicyMount>,
) -> Result<(), String> {
    for alias in mount_aliases(storage, entries)? {
        if !is_writable_at(&alias, mounts) {
            continue;
        }
        let alias = alias
            .into_os_string()
            .into_string()
            .map_err(|_| "private deny mountpoint alias is not valid UTF-8".to_owned())?;
        mounts.push(PolicyMount {
            source: alias.clone(),
            destination: alias,
            intent: FsIntent::Denied,
            readonly_overlay: None,
        });
    }
    Ok(())
}

fn is_writable_at(path: &Path, mounts: &[PolicyMount]) -> bool {
    mounts
        .iter()
        .filter(|mount| path.starts_with(&mount.destination))
        .max_by_key(|mount| Path::new(&mount.destination).components().count())
        .is_some_and(|mount| mount.intent == FsIntent::ReadWrite)
}

#[cfg(test)]
mod tests;
