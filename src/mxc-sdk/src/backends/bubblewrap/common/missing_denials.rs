// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::BTreeMap;
#[cfg(any(target_os = "linux", test))]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::bwrap_command::{BaselineLink, PolicyMount, WritableOverlay, BASELINE_RO_BIND_PATHS};
use super::bwrap_version::BwrapVersion;
use crate::mxc_common::filesystem_object::FilesystemPolicyError;
use crate::mxc_common::filesystem_probe::FilesystemProbe;
use crate::mxc_common::filesystem_resolve::FsIntent;

#[cfg(target_os = "linux")]
const MAX_MOUNTINFO_BYTES: usize = 1_048_576;
#[cfg(any(target_os = "linux", test))]
const MAX_MOUNTINFO_ENTRIES: usize = 4096;

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug)]
struct MountInfoEntry {
    id: u64,
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
                writable_overlay: None,
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

struct OverlayPlan {
    intent: FsIntent,
    paths: Vec<PathBuf>,
}

#[derive(Debug)]
pub(crate) struct OverlayStorage {
    _directory: TempDir,
    workdir: Option<PathBuf>,
}

impl OverlayStorage {
    fn read_only(directory: TempDir) -> Self {
        Self {
            _directory: directory,
            workdir: None,
        }
    }

    fn writable(directory: TempDir, workdir: PathBuf) -> Self {
        Self {
            _directory: directory,
            workdir: Some(workdir),
        }
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        self._directory.path()
    }
}

impl Drop for OverlayStorage {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;

        // Overlayfs creates its internal work/work directory with mode 000.
        // Make only that private directory traversable so TempDir can remove it.
        let Some(workdir) = &self.workdir else {
            return;
        };
        let internal = workdir.join("work");
        if std::fs::symlink_metadata(&internal).is_ok_and(|metadata| metadata.file_type().is_dir())
        {
            let _ = std::fs::set_permissions(&internal, std::fs::Permissions::from_mode(0o700));
        }
    }
}

fn same_mount(source: &Path, storage: &Path, entries: &[MountInfoEntry]) -> bool {
    if entries.is_empty() {
        return cfg!(not(target_os = "linux"));
    }
    let Some(source_mount) = containing_mount(source, entries) else {
        return false;
    };
    let Some(storage_mount) = containing_mount(storage, entries) else {
        return false;
    };
    source_mount.id == storage_mount.id
}

fn storage_is_compatible(
    source: &Path,
    storage: &Path,
    source_device: u64,
    mountinfo: &[MountInfoEntry],
) -> Result<bool, FilesystemPolicyError> {
    use std::os::unix::fs::MetadataExt;

    if storage.starts_with(source) || source.starts_with(storage) {
        return Ok(false);
    }
    let device = std::fs::metadata(storage)
        .map_err(|error| {
            FilesystemPolicyError::Host(format!(
                "Bubblewrap: could not inspect private overlay storage '{}': {error}",
                storage.display()
            ))
        })?
        .dev();
    Ok(device == source_device && same_mount(source, storage, mountinfo))
}

fn writable_storage(
    source: &Path,
    denied_paths: &[PathBuf],
    mountinfo: &[MountInfoEntry],
) -> Result<(TempDir, PathBuf), FilesystemPolicyError> {
    use std::os::unix::fs::MetadataExt;

    let source_device = std::fs::metadata(source)
        .map_err(|error| {
            FilesystemPolicyError::Host(format!(
                "Bubblewrap: could not inspect read-write grant '{}': {error}",
                source.display()
            ))
        })?
        .dev();
    if let Some(parent) = source.parent() {
        if let Ok(directory) = tempfile::Builder::new()
            .prefix(".mxc-bwrap-overlay-")
            .tempdir_in(parent)
        {
            let storage = std::fs::canonicalize(directory.path()).map_err(|error| {
                FilesystemPolicyError::Host(format!(
                    "Bubblewrap: could not resolve private overlay storage for '{}': {error}",
                    source.display()
                ))
            })?;
            if storage_is_compatible(source, &storage, source_device, mountinfo)? {
                return initialize_writable_storage(directory, storage, source, denied_paths);
            }
        }
    }

    // A writable grant does not imply a writable parent. Both upperdir and
    // workdir must be on the same mount, not merely the same device.
    let directory = tempfile::tempdir().map_err(|error| {
        FilesystemPolicyError::Host(format!(
            "Bubblewrap: could not create private overlay storage in TMPDIR for '{}': {error}",
            source.display()
        ))
    })?;
    let storage = std::fs::canonicalize(directory.path()).map_err(|error| {
        FilesystemPolicyError::Host(format!(
            "Bubblewrap: could not resolve private overlay storage for '{}': {error}",
            source.display()
        ))
    })?;
    if !storage_is_compatible(source, &storage, source_device, mountinfo)? {
        return Err(FilesystemPolicyError::Host(format!(
            "Bubblewrap: cannot prepare writable overlay storage for '{}': neither its parent \
             nor TMPDIR provides a writable directory outside the grant on the same mount and \
             filesystem. Bind-mounted grants at a mount root cannot use their parent or TMPDIR; \
             grant a subdirectory inside that mount instead.",
            source.display()
        )));
    }
    initialize_writable_storage(directory, storage, source, denied_paths)
}

fn initialize_writable_storage(
    directory: TempDir,
    storage: PathBuf,
    source: &Path,
    denied_paths: &[PathBuf],
) -> Result<(TempDir, PathBuf), FilesystemPolicyError> {
    let layer = storage.join("lower");
    let workdir = storage.join("work");
    #[cfg(test)]
    crate::mxc_common::filesystem_probe::launch_tests::stall("bwrap-writable-storage", source);
    std::fs::create_dir(&workdir).map_err(|error| {
        FilesystemPolicyError::Host(format!(
            "Bubblewrap: could not create private overlay workdir '{}': {error}",
            workdir.display()
        ))
    })?;
    for path in denied_paths {
        std::fs::create_dir_all(layer.join(path)).map_err(|error| {
            FilesystemPolicyError::Host(format!(
                "Bubblewrap: could not prepare private mountpoint for deniedPaths entry '{}': \
                 {error}",
                source.join(path).display()
            ))
        })?;
    }
    Ok((directory, storage))
}

fn intent_name(intent: FsIntent) -> &'static str {
    match intent {
        FsIntent::ReadOnly => "read-only",
        FsIntent::ReadWrite => "read-write",
        FsIntent::Denied => "denied",
    }
}

/// Keep missing deny mountpoints off the host with private overlay layers.
/// The returned directories must outlive the sandbox's overlay mounts.
pub(crate) fn prepare(
    mounts: &mut Vec<PolicyMount>,
    baseline_links: &[BaselineLink],
    version: BwrapVersion,
    bwrap_is_setuid: bool,
) -> Result<Option<Vec<OverlayStorage>>, FilesystemPolicyError> {
    let mut probe = FilesystemProbe::default();
    let baseline = baseline_mounts(BASELINE_RO_BIND_PATHS, baseline_links, &mut probe)?;
    let mut overlays = BTreeMap::<(String, String), OverlayPlan>::new();
    for (index, denied) in mounts.iter().enumerate() {
        if denied.intent != FsIntent::Denied {
            continue;
        }
        let target = Path::new(&denied.destination);
        let parent = baseline.iter().chain(&mounts[..index]).rfind(|mount| {
            target != Path::new(&mount.destination) && target.starts_with(&mount.destination)
        });
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
            .or_insert_with(|| OverlayPlan {
                intent: parent.intent,
                paths: Vec::new(),
            })
            .paths
            .push(relative.to_path_buf());
    }
    let first_overlay = overlays
        .iter()
        .next()
        .and_then(|((_, destination), overlay)| {
            overlay.paths.first().map(|path| {
                (
                    destination.clone(),
                    path.clone(),
                    intent_name(overlay.intent),
                )
            })
        });
    let Some((first_destination, first_path, first_intent)) = first_overlay else {
        return Ok(None);
    };

    #[cfg(target_os = "linux")]
    let mountinfo = read_mountinfo(&mut probe)?;

    #[cfg(target_os = "linux")]
    for ((source, destination), overlay) in &overlays {
        if let Some(nested) = nested_mountpoint(Path::new(source), &mountinfo) {
            let Some(path) = overlay.paths.first() else {
                continue;
            };
            return Err(FilesystemPolicyError::Host(format!(
                "Bubblewrap: missing deniedPaths entry '{}' beneath {} '{destination}' \
                 cannot be enforced because nested host mount '{}' would be hidden by its \
                 private overlay. Use a grant without nested mounts or avoid a missing denied \
                 path beneath that grant.",
                Path::new(destination).join(path).display(),
                intent_name(overlay.intent),
                nested.display()
            )));
        }
    }
    let (minimum_version, overlay_kind) = if overlays
        .values()
        .any(|overlay| overlay.intent == FsIntent::ReadWrite)
    {
        (BwrapVersion::new(0, 12, 0), "writable")
    } else {
        (BwrapVersion::new(0, 11, 0), "read-only")
    };
    if version < minimum_version {
        return Err(FilesystemPolicyError::Host(format!(
            "Bubblewrap: missing deniedPaths entry '{}' beneath {first_intent} '{}' \
             requires bwrap {minimum_version} or newer for private {overlay_kind} overlays; \
             found {version}.",
            Path::new(&first_destination).join(first_path).display(),
            first_destination
        )));
    }
    if bwrap_is_setuid {
        return Err(FilesystemPolicyError::Host(format!(
            "Bubblewrap: missing deniedPaths entry '{}' beneath {first_intent} '{}' requires a \
             non-setuid bwrap installation; the selected bwrap has the setuid bit set.",
            Path::new(&first_destination).join(first_path).display(),
            first_destination
        )));
    }

    let mut directories = Vec::new();
    let mut storage_roots = Vec::new();
    let readonly_storage = if overlays
        .values()
        .any(|overlay| overlay.intent == FsIntent::ReadOnly)
    {
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
        directories.push(OverlayStorage::read_only(directory));
        storage_roots.push(storage.clone());
        Some(storage)
    } else {
        None
    };

    for (index, ((source, destination), overlay)) in overlays.into_iter().enumerate() {
        let (layer, workdir) = match overlay.intent {
            FsIntent::ReadOnly => {
                // Overlayfs rejects lower layers that contain one another.
                let storage = readonly_storage.as_ref().expect("read-only storage");
                if storage.starts_with(&source) || Path::new(&source).starts_with(storage) {
                    return Err(FilesystemPolicyError::Host(format!(
                        "Bubblewrap: cannot prepare missing deniedPaths entry '{}' beneath \
                         read-only '{destination}': private temporary storage overlaps its host \
                         source '{source}'. Set TMPDIR outside that source.",
                        Path::new(&destination).join(&overlay.paths[0]).display()
                    )));
                }
                (storage.join(index.to_string()), None)
            }
            FsIntent::ReadWrite => {
                #[cfg(target_os = "linux")]
                let (directory, storage) = {
                    let display = source.clone();
                    let worker_source = display.clone();
                    let worker_mountinfo = mountinfo.clone();
                    let worker_paths = overlay.paths.clone();
                    probe
                        .run(&display, move |_| {
                            writable_storage(
                                Path::new(&worker_source),
                                &worker_paths,
                                &worker_mountinfo,
                            )
                        })
                        .map_err(FilesystemPolicyError::Host)??
                };
                #[cfg(not(target_os = "linux"))]
                let (directory, storage) =
                    writable_storage(Path::new(&source), &overlay.paths, &[])?;
                let layer = storage.join("lower");
                let workdir = storage.join("work");
                directories.push(OverlayStorage::writable(directory, workdir.clone()));
                storage_roots.push(storage);
                (layer, Some(workdir))
            }
            FsIntent::Denied => unreachable!("denied parents are not overlay grants"),
        };
        if overlay.intent == FsIntent::ReadOnly {
            for path in &overlay.paths {
                std::fs::create_dir_all(layer.join(path)).map_err(|error| {
                    FilesystemPolicyError::Host(format!(
                        "Bubblewrap: could not prepare private mountpoint for deniedPaths \
                         entry '{}': {error}",
                        Path::new(&destination).join(path).display()
                    ))
                })?;
            }
        }
        let layer = layer.into_os_string().into_string().map_err(|_| {
            FilesystemPolicyError::Host(
                "Bubblewrap: private deny mountpoint storage is not valid UTF-8".to_owned(),
            )
        })?;
        match overlay.intent {
            FsIntent::ReadOnly => match mounts.iter_mut().find(|mount| {
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
                    writable_overlay: None,
                }),
            },
            FsIntent::ReadWrite => {
                let workdir = workdir
                    .expect("writable overlay workdir")
                    .into_os_string()
                    .into_string()
                    .map_err(|_| {
                        FilesystemPolicyError::Host(
                            "Bubblewrap: private overlay workdir is not valid UTF-8".to_owned(),
                        )
                    })?;
                let mount = mounts
                    .iter_mut()
                    .find(|mount| {
                        mount.intent == FsIntent::ReadWrite
                            && mount.source == source
                            && mount.destination == destination
                    })
                    .ok_or_else(|| {
                        FilesystemPolicyError::Host(format!(
                            "Bubblewrap: read-write overlay parent '{destination}' disappeared \
                             during preparation."
                        ))
                    })?;
                mount.writable_overlay = Some(WritableOverlay {
                    lower: layer,
                    workdir,
                });
            }
            FsIntent::Denied => unreachable!("denied parents are not overlay grants"),
        }
    }
    #[cfg(target_os = "linux")]
    for storage in &storage_roots {
        add_alias_masks(storage, &mountinfo, mounts).map_err(FilesystemPolicyError::Host)?;
    }
    // A caller may grant a directory containing private overlay storage. The
    // workload must not reach lower layers or workdirs through any bind alias.
    for storage in storage_roots {
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
            writable_overlay: None,
        });
    }
    mounts.sort_by_key(|mount| Path::new(&mount.destination).components().count());
    Ok(Some(directories))
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
            id: fields[0].parse::<u64>().map_err(|_| {
                format!(
                    "mount information entry {} has an invalid mount identifier",
                    index + 1
                )
            })?,
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
fn containing_mount<'a>(path: &Path, entries: &'a [MountInfoEntry]) -> Option<&'a MountInfoEntry> {
    entries
        .iter()
        .filter(|entry| path.starts_with(&entry.mountpoint))
        .max_by_key(|entry| entry.mountpoint.components().count())
}

#[cfg(any(target_os = "linux", test))]
fn mount_aliases(path: &Path, entries: &[MountInfoEntry]) -> Result<BTreeSet<PathBuf>, String> {
    let containing = containing_mount(path, entries).ok_or_else(|| {
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
            writable_overlay: None,
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
