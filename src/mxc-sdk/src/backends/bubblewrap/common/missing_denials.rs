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

    /// Remove the mount points on a thread of their own, leaving the caller
    /// free. Teardown walks filesystems the caller granted, and exit polling
    /// promises not to block, so the work is handed off rather than done here.
    pub(crate) fn remove_placeholders_in_background(mut self) {
        if self.mount_points.is_empty() {
            return;
        }
        self.armed = false;
        let mount_points = std::mem::take(&mut self.mount_points);
        let spawned = std::thread::Builder::new()
            .name("bwrap-deny-cleanup".to_string())
            .spawn(move || remove_mount_points(&mount_points));
        if spawned.is_err() {
            // No thread to hand it to: do it here, since leaving the mount
            // points on the host is the outcome this exists to prevent.
            remove_mount_points(&self.mount_points);
        }
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

/// A mount point this run creates on the host for a missing denied entry
/// beneath a read-write grant.
///
/// Bubblewrap reuses an existing mount point instead of making one, so creating
/// it here is what makes it unambiguously ours: the recorded device and inode
/// name the exact object this run made, and cleanup removes nothing else. A
/// caller that replaces it, or creates its own object at the same path while the
/// sandbox runs, is left alone however empty that object is.
#[derive(Debug)]
pub(crate) struct HostMountPoint {
    /// Every level this run created beneath the grant, deepest first, each with
    /// the device and inode it had at creation. A level is removed only while it
    /// is still that same object and still empty.
    pub(crate) created_levels: Vec<(PathBuf, (u64, u64))>,
}

/// Identity of a host object: its device and inode.
type ObjectId = (u64, u64);

/// Create the mount point for a missing denied entry and record what it made.
///
/// Bubblewrap reuses an existing mount point rather than making one, so creating
/// it here is what establishes ownership. Every level this run adds is recorded
/// with its identity; cleanup removes only those exact objects.
fn create_mount_point(target: &Path, is_file: bool) -> Vec<(PathBuf, ObjectId)> {
    let mut created = Vec::new();
    let mut current = target;
    // Collect the missing levels first so they can be created top-down.
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(current) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => missing.push(current),
            Err(_) => break,
        }
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent;
    }
    let deepest = missing.first().copied();
    for directory in missing.into_iter().rev() {
        // The leaf is a file when the deny mask binds /dev/null over it; every
        // level above it is always a directory.
        let make = || {
            if is_file && Some(directory) == deepest {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(directory)
                    .map(|_| ())
            } else {
                std::fs::create_dir(directory)
            }
        };
        if let Err(error) = make() {
            // Another process made it first, or the tree is not ours to extend.
            // Stop: whatever is there now is not this run's to remove.
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                break;
            }
        }
        let Ok(metadata) = std::fs::symlink_metadata(directory) else {
            break;
        };
        use std::os::unix::fs::MetadataExt;
        created.push((directory.to_path_buf(), (metadata.dev(), metadata.ino())));
    }
    // Deepest first, which is the order cleanup needs.
    created.reverse();
    created
}

/// Remove the mount points this run created for missing denied entries.
///
/// Each recorded level is removed only while it is still the same device and
/// inode this run created and still empty. A caller that replaced it, or created
/// its own object there while the sandbox ran, is left alone: the identity no
/// longer matches, whatever the path looks like.
///
/// Runs on the same bounded worker startup uses. Teardown walks filesystems the
/// caller granted, and one that stops answering would otherwise hold the handle
/// and a timed-out sandbox's return open indefinitely; a probe that does not
/// answer within its deadline leaves the objects in place instead.
pub(crate) fn remove_mount_points(mount_points: &[HostMountPoint]) {
    let mut probe = FilesystemProbe::default();
    for mount_point in mount_points {
        for (path, created) in &mount_point.created_levels {
            let path = path.clone();
            let created = *created;
            let display = path.display().to_string();
            let removed = probe.run(&display, move |_| remove_level(&path, created));
            // A level that is no longer ours means everything above it may not be
            // either, so stop this mount point here.
            if !matches!(removed, Ok(true)) {
                break;
            }
        }
    }
}

/// Remove one level if it is still the object this run created and still empty.
fn remove_level(path: &Path, created: ObjectId) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    use std::os::unix::fs::MetadataExt;
    if (metadata.dev(), metadata.ino()) != created {
        return false;
    }
    if metadata.is_dir() {
        std::fs::remove_dir(path).is_ok()
    } else if metadata.is_file() && metadata.len() == 0 {
        std::fs::remove_file(path).is_ok()
    } else {
        false
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
    denied_files: &std::collections::HashSet<String>,
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
            // Bubblewrap reuses a mount point that already exists, so creating it
            // here is what makes it this run's to remove. Without it, nothing
            // distinguishes its placeholder from an object the caller creates at
            // the same path while the sandbox runs.
            let is_file = denied_files.contains(&denied.source);
            let display = host_target.display().to_string();
            let created_levels = probe
                .run(&display, move |_| create_mount_point(&host_target, is_file))
                .map_err(|error| FilesystemPolicyError::Host(format!("Bubblewrap: {error}")))?;
            // Nothing to create means bwrap will make the mount point itself,
            // and this run has no way to tell it from an object the caller puts
            // there later. Leaving it is worse than trying to remove it, so the
            // entry is not recorded and nothing is removed afterwards.
            if !created_levels.is_empty() {
                mount_points.push(HostMountPoint { created_levels });
            }
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
