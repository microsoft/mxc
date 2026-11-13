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

/// Keep missing deny mountpoints off the host and out of read-only binds.
/// The returned directory must outlive the sandbox's overlay mounts.
pub(crate) fn prepare(
    mounts: &mut Vec<PolicyMount>,
    baseline_links: &[BaselineLink],
    version: BwrapVersion,
    bwrap_is_setuid: bool,
) -> Result<Option<TempDir>, FilesystemPolicyError> {
    let mut probe = FilesystemProbe::default();
    let baseline = baseline_mounts(BASELINE_RO_BIND_PATHS, baseline_links, &mut probe)?;
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
        match inspect_path(&mut probe, host_target).map_err(FilesystemPolicyError::Host)? {
            Ok(()) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(FilesystemPolicyError::Host(format!(
                    "Bubblewrap: could not inspect deniedPaths entry '{}': {error}",
                    denied.source
                )))
            }
        }
        overlays
            .entry((parent.source.clone(), parent.destination.clone()))
            .or_default()
            .push(relative.to_path_buf());
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
        return Ok(None);
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
    Ok(Some(directory))
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
