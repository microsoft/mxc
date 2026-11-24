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

pub(crate) type CleanupWarnings = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

fn warn_cleanup(warnings: &CleanupWarnings, warning: String) {
    warnings
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(warning);
}

fn spawn_cleanup(
    levels: &[(PathBuf, ObjectId)],
    warnings: CleanupWarnings,
    storage: Option<std::sync::Arc<TempDir>>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    #[cfg(test)]
    if test_control::take_spawn_failure(levels) {
        return Err(std::io::Error::other("injected cleanup spawn failure"));
    }
    let owned_levels = levels.to_vec();
    std::thread::Builder::new()
        .name("bwrap-deny-cleanup".to_string())
        .spawn(move || {
            #[cfg(test)]
            test_control::wait_for_storage_job(&owned_levels);
            // Keep overlay storage alive until the detached cleanup has
            // finished. Its destructor therefore runs off the polling thread.
            let _storage = storage;
            remove_levels_with_warnings(&owned_levels, &warnings);
        })
}

fn remove_levels_with_warnings(created_levels: &[(PathBuf, ObjectId)], warnings: &CleanupWarnings) {
    #[cfg(test)]
    {
        test_control::wait(created_levels);
        test_control::wait_for_completion_cleanup(created_levels);
        test_control::wait_for_storage_cleanup(created_levels);
    }

    if let Err(error) = remove_levels_with_probe(created_levels, FilesystemProbe::default()) {
        warn_cleanup(
            warnings,
            format!("Bubblewrap: denied-path cleanup did not finish: {error}"),
        );
    }
}

/// Completion state for a detached cleanup. Polling drops nothing that a later
/// blocking teardown needs in order to wait for the worker and read its warnings.
#[derive(Debug)]
pub(crate) struct CleanupCompletion {
    worker: Option<std::thread::JoinHandle<()>>,
    warnings: CleanupWarnings,
}

impl CleanupCompletion {
    pub(crate) fn wait(mut self) {
        const WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        let deadline = std::time::Instant::now() + WAIT_TIMEOUT;
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            if std::time::Instant::now() >= deadline {
                warn_cleanup(
                    &self.warnings,
                    "Bubblewrap: denied-path cleanup did not finish within 5 seconds".to_string(),
                );
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// What a policy needs before Bubblewrap can enforce its deny masks.
#[derive(Debug)]
pub(crate) struct DenyPreparation {
    /// Private storage backing the read-only overlays, held so the overlays
    /// stay mounted for as long as the sandbox runs.
    pub(crate) _storage: Option<std::sync::Arc<TempDir>>,

    /// Every level this run created on the host for a denied entry that did not
    /// exist yet beneath a read-write grant.
    created_levels: Vec<(PathBuf, ObjectId)>,

    /// Cleared once the sandbox owns the cleanup. Until then, dropping this
    /// removes the mount points, so a startup path that gives up after bwrap
    /// already created its masks does not leave them behind.
    armed: bool,

    /// Shared with the process so a detached cleanup can report failure after
    /// the handoff has already returned.
    cleanup_warnings: CleanupWarnings,
}

impl DenyPreparation {
    #[cfg(test)]
    pub(crate) fn for_test(created_levels: Vec<(PathBuf, ObjectId)>) -> Self {
        Self {
            _storage: None,
            created_levels,
            armed: true,
            cleanup_warnings: CleanupWarnings::default(),
        }
    }

    pub(crate) fn warnings(&self) -> CleanupWarnings {
        std::sync::Arc::clone(&self.cleanup_warnings)
    }

    /// Hand the cleanup to whoever now owns the sandbox. That owner calls
    /// [`Self::remove_placeholders`] once the sandbox has stopped; until it
    /// does, dropping this no longer removes anything.
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    /// Remove the mount points on a thread of their own, leaving the caller
    /// free. Teardown walks filesystems the caller granted, and exit polling
    /// promises not to block, so the work is handed off rather than done here.
    pub(crate) fn remove_placeholders_in_background(
        mut self,
    ) -> Result<CleanupCompletion, (std::io::Error, Self)> {
        if self.created_levels.is_empty() && self._storage.is_none() {
            return Ok(CleanupCompletion {
                worker: None,
                warnings: self.warnings(),
            });
        }
        self.armed = false;
        let levels = std::mem::take(&mut self.created_levels);
        let warnings = self.warnings();
        match spawn_cleanup(
            &levels,
            std::sync::Arc::clone(&warnings),
            self._storage.clone(),
        ) {
            Ok(worker) => Ok(CleanupCompletion {
                worker: Some(worker),
                warnings,
            }),
            Err(error) => {
                // Polling must remain non-blocking. Return the complete owner so
                // the runner can keep it for the blocking wait/drop teardown;
                // neither registry ownership nor overlay storage is abandoned.
                warn_cleanup(
                    &warnings,
                    format!("Bubblewrap: could not start denied-path cleanup: {error}"),
                );
                self.created_levels = levels;
                self.armed = true;
                Err((error, self))
            }
        }
    }

    /// Remove the mount points now. Safe to call more than once, and callable
    /// after [`Self::disarm`]: handing the cleanup over changes who calls this,
    /// not whether it may run.
    pub(crate) fn remove_placeholders(&mut self) {
        if self.created_levels.is_empty() {
            return;
        }
        remove_levels_with_warnings(&self.created_levels, &self.cleanup_warnings);
        self.created_levels.clear();
    }
}

impl Drop for DenyPreparation {
    fn drop(&mut self) {
        if self.armed {
            self.remove_placeholders();
        }
    }
}

/// Identity of a host object: its device and inode.
///
/// A caller that replaces this run's placeholder is normally caught here,
/// because a different object carries a different inode. The exception is a
/// filesystem that hands the freed inode straight back to the replacement. The
/// change time cannot close that gap: a directory's change time moves whenever
/// an entry is added to it, so this run's own multi-level placeholder would
/// stop matching itself.
type ObjectId = (u64, u64);

#[derive(Default)]
struct CleanupRegistry {
    users: BTreeMap<ObjectId, usize>,
    handles: BTreeMap<ObjectId, std::fs::File>,
    parents: BTreeMap<ObjectId, std::fs::File>,
    paths: BTreeMap<ObjectId, PathBuf>,
    removing: BTreeSet<ObjectId>,
}

impl CleanupRegistry {
    fn global() -> &'static std::sync::Mutex<Self> {
        static REGISTRY: std::sync::OnceLock<std::sync::Mutex<CleanupRegistry>> =
            std::sync::OnceLock::new();
        REGISTRY.get_or_init(|| std::sync::Mutex::new(Self::default()))
    }

    fn record(
        &mut self,
        path: &Path,
        created: ObjectId,
        handle: std::fs::File,
        parent: std::fs::File,
    ) {
        let key = created;
        *self.users.entry(key).or_insert(0) += 1;
        // Holding one descriptor pins the inode until every user has released
        // it, so a replacement cannot recycle the recorded identity.
        self.handles.entry(key).or_insert(handle);
        self.parents.entry(key).or_insert(parent);
        self.paths.entry(key).or_insert_with(|| path.to_path_buf());
    }

    fn borrow(&mut self, _path: &Path, created: ObjectId) -> bool {
        let key = created;
        if self.removing.contains(&key) {
            return false;
        }
        let Some(users) = self.users.get_mut(&key) else {
            return false;
        };
        *users += 1;
        true
    }

    fn begin_remove(&mut self, _path: &Path, created: ObjectId) -> bool {
        let key = created;
        self.users.get(&key) == Some(&1) && self.removing.insert(key)
    }

    fn removal_handles(
        &self,
        _path: &Path,
        created: ObjectId,
    ) -> std::io::Result<(
        Option<std::fs::File>,
        Option<std::fs::File>,
        Option<PathBuf>,
    )> {
        let key = created;
        Ok((
            self.handles
                .get(&key)
                .map(std::fs::File::try_clone)
                .transpose()?,
            self.parents
                .get(&key)
                .map(std::fs::File::try_clone)
                .transpose()?,
            self.paths.get(&key).cloned(),
        ))
    }

    fn finish_remove(&mut self, _path: &Path, created: ObjectId, removed: bool) {
        let key = created;
        self.removing.remove(&key);
        if removed {
            self.users.remove(&key);
            self.handles.remove(&key);
            self.parents.remove(&key);
            self.paths.remove(&key);
        }
    }

    fn release_if_shared(&mut self, _path: &Path, created: ObjectId) -> bool {
        let key = created;
        let Some(users) = self.users.get_mut(&key) else {
            return true;
        };
        if *users > 1 {
            *users -= 1;
            return true;
        }
        false
    }

    fn release_unstarted(&mut self, created: ObjectId) {
        self.removing.remove(&created);
        let Some(users) = self.users.get_mut(&created) else {
            return;
        };
        if *users > 1 {
            *users -= 1;
            return;
        }
        self.users.remove(&created);
        self.handles.remove(&created);
        self.parents.remove(&created);
        self.paths.remove(&created);
    }
}

fn metadata_id(metadata: &std::fs::Metadata) -> ObjectId {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

const PLACEHOLDER_MARKER: &[u8] = b"mxc-deny-placeholder-v1";

fn marker_name() -> std::ffi::CString {
    std::ffi::CString::new("user.mxc.deny-placeholder").unwrap()
}

#[cfg(target_os = "linux")]
fn set_placeholder_marker(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let name = marker_name();
    // SAFETY: the name and value stay alive for the call, and file is an open
    // descriptor for the staging object that has not been published yet.
    let result = unsafe {
        nix::libc::fsetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            PLACEHOLDER_MARKER.as_ptr().cast(),
            PLACEHOLDER_MARKER.len(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn set_placeholder_marker(_file: &std::fs::File) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "host deny placeholders are only supported on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn path_has_placeholder_marker(path: &Path) -> std::io::Result<bool> {
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("denied mount point contains a NUL byte"))?;
    let name = marker_name();
    let mut value = [0_u8; 64];
    // SAFETY: path/name are NUL-terminated and value is writable for its given
    // length. lgetxattr does not follow a final symlink.
    let result = unsafe {
        nix::libc::lgetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if result >= 0 {
        return Ok(&value[..result as usize] == PLACEHOLDER_MARKER);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(nix::libc::ENODATA) | Some(nix::libc::ENOTSUP) => Ok(false),
        _ => Err(error),
    }
}

#[cfg(not(target_os = "linux"))]
fn path_has_placeholder_marker(_path: &Path) -> std::io::Result<bool> {
    Ok(false)
}

#[cfg(target_os = "linux")]
fn file_has_placeholder_marker(file: &std::fs::File) -> std::io::Result<bool> {
    use std::os::unix::io::AsRawFd;

    let name = marker_name();
    let mut value = [0_u8; 64];
    // SAFETY: file is open, name is NUL-terminated, and value is writable for
    // its given length.
    let result = unsafe {
        nix::libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if result >= 0 {
        return Ok(&value[..result as usize] == PLACEHOLDER_MARKER);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(nix::libc::ENODATA) | Some(nix::libc::ENOTSUP) => Ok(false),
        _ => Err(error),
    }
}

#[cfg(not(target_os = "linux"))]
fn file_has_placeholder_marker(_file: &std::fs::File) -> std::io::Result<bool> {
    Ok(false)
}

fn lock_shared(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: flock only borrows the open descriptor for this call.
    if unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_SH) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn try_lock_exclusive(file: &std::fs::File) -> std::io::Result<bool> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: flock only borrows the open descriptor for this call. A failed
    // non-blocking upgrade is how another live process reports shared use.
    if unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error)
    }
}

fn path_lock(path: &Path) -> std::sync::Arc<std::sync::Mutex<()>> {
    static LOCKS: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, std::sync::Weak<std::sync::Mutex<()>>>>,
    > = std::sync::OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Keep a live path on the same mutex while any caller can still use it.
    // Once its last Arc is gone, the next acquisition reclaims the path key too.
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(path).and_then(std::sync::Weak::upgrade) {
        return lock;
    }
    let lock = std::sync::Arc::new(std::sync::Mutex::new(()));
    locks.insert(path.to_path_buf(), std::sync::Arc::downgrade(&lock));
    lock
}

fn open_at(
    directory: Option<&std::fs::File>,
    path: &Path,
    flags: i32,
    mode: u32,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("denied mount point contains a NUL byte"))?;
    let directory = directory.map_or(nix::libc::AT_FDCWD, AsRawFd::as_raw_fd);
    // SAFETY: path is NUL-terminated and directory is open. A successful call
    // returns a newly owned descriptor; mode is used only when flags create.
    // Ownership and locking stay in this host process. Inheriting one of these
    // descriptors into bwrap or its workload would keep the shared lock alive
    // after the sandbox owner had already exited.
    let descriptor =
        unsafe { nix::libc::openat(directory, path.as_ptr(), flags | nix::libc::O_CLOEXEC, mode) };
    if descriptor < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: ownership of the new descriptor was transferred by openat.
        Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
    }
}

fn descriptor_path(file: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;

    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn verify_beneath(root: &Path, file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let resolved = descriptor_path(file)?;
    if resolved.as_os_str().as_bytes().ends_with(b" (deleted)") || !resolved.starts_with(root) {
        return Err(std::io::Error::other(format!(
            "denied mount point '{}' resolved outside its original grant",
            resolved.display()
        )));
    }
    Ok(())
}

fn open_grant_root(root: &Path) -> std::io::Result<(std::fs::File, PathBuf)> {
    let canonical = std::fs::canonicalize(root)?;
    let handle = open_at(
        None,
        &canonical,
        nix::libc::O_RDONLY | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW,
        0,
    )?;
    if descriptor_path(&handle)? != canonical {
        return Err(std::io::Error::other(format!(
            "writable grant '{}' changed while it was opened",
            root.display()
        )));
    }
    Ok((handle, canonical))
}

fn open_relative(
    root: &std::fs::File,
    relative: &Path,
    flags: i32,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt;

    let current_root = descriptor_path(root)?;
    if current_root.as_os_str().as_bytes().ends_with(b" (deleted)") {
        return Err(std::io::Error::other(
            "the original writable grant was deleted",
        ));
    }
    let handle = if relative.as_os_str().is_empty() {
        root.try_clone()?
    } else {
        open_at(Some(root), relative, flags, 0)?
    };
    verify_beneath(&current_root, &handle)?;
    Ok(handle)
}

fn open_parent(root: &std::fs::File, relative: &Path) -> std::io::Result<std::fs::File> {
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    open_relative(root, parent, nix::libc::O_RDONLY | nix::libc::O_DIRECTORY)
}

fn open_object(root: &std::fs::File, relative: &Path) -> std::io::Result<std::fs::File> {
    // A caller can replace a checked regular file with a FIFO before this open.
    // Nonblocking mode keeps that race from stalling the bounded probe worker.
    open_relative(
        root,
        relative,
        nix::libc::O_RDONLY | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK,
    )
}

fn metadata_at(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<std::fs::Metadata> {
    use std::os::unix::io::AsRawFd;

    std::fs::symlink_metadata(
        Path::new("/proc/self/fd")
            .join(directory.as_raw_fd().to_string())
            .join(name),
    )
}

fn unlink_at(directory: &std::fs::File, name: &std::ffi::OsStr) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::AsRawFd;

    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::other("denied mount point contains a NUL byte"))?;
    // SAFETY: directory is open and name is NUL-terminated. AT_REMOVEDIR makes
    // this helper incapable of unlinking a caller-written regular file.
    let result = unsafe {
        nix::libc::unlinkat(
            directory.as_raw_fd(),
            name.as_ptr(),
            nix::libc::AT_REMOVEDIR,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn rename_noreplace_at(
    parent: &std::fs::File,
    from_name: &std::ffi::OsStr,
    to_name: &std::ffi::OsStr,
    _from_path: &Path,
    _to_path: &Path,
) -> Result<(), nix::Error> {
    use std::os::unix::io::AsRawFd;

    #[cfg(test)]
    if test_control::rename_fails(_from_path, _to_path) {
        return Err(nix::errno::Errno::EOPNOTSUPP);
    }
    nix::fcntl::renameat2(
        Some(parent.as_raw_fd()),
        Path::new(from_name),
        Some(parent.as_raw_fd()),
        Path::new(to_name),
        nix::fcntl::RenameFlags::RENAME_NOREPLACE,
    )
}

#[cfg(not(target_os = "linux"))]
fn rename_noreplace_at(
    _parent: &std::fs::File,
    _from_name: &std::ffi::OsStr,
    _to_name: &std::ffi::OsStr,
    _from_path: &Path,
    _to_path: &Path,
) -> Result<(), nix::Error> {
    Err(nix::errno::Errno::EOPNOTSUPP)
}

fn create_object_at(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    path: &Path,
) -> std::io::Result<(std::fs::File, ObjectId)> {
    use std::os::unix::io::AsRawFd;

    let temporary = std::ffi::OsString::from(format!(".mxc-create-{}", uuid::Uuid::new_v4()));
    let temporary_path = path
        .parent()
        .ok_or_else(|| std::io::Error::other("denied mount point has no parent"))?
        .join(&temporary);
    let mut created = None;
    let mut staging_created = false;
    let mut staging_handle = None;
    let result = (|| {
        let temporary_c = std::ffi::CString::new(temporary.as_encoded_bytes())
            .map_err(|_| std::io::Error::other("staging name contains a NUL byte"))?;
        // SAFETY: parent is open and temporary_c is NUL-terminated.
        if unsafe { nix::libc::mkdirat(parent.as_raw_fd(), temporary_c.as_ptr(), 0o777) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        staging_created = true;
        #[cfg(test)]
        test_control::fail_initial_staging_metadata(path)?;
        created = Some(metadata_id(&metadata_at(parent, &temporary)?));
        #[cfg(test)]
        test_control::fail_staging_open(path)?;
        let handle = open_at(
            Some(parent),
            Path::new(&temporary),
            nix::libc::O_RDONLY | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW,
            0,
        )?;
        staging_handle = Some(handle);
        let handle = staging_handle.as_ref().unwrap();
        let id = metadata_id(&handle.metadata()?);
        if Some(id) != created {
            return Err(std::io::Error::other(
                "staging object changed while it was opened",
            ));
        }
        // Publish only after the marker and shared lock are attached to the
        // staging inode. A concurrent process can therefore never observe a
        // marked placeholder whose creator has not joined its lifetime yet.
        set_placeholder_marker(handle)?;
        lock_shared(handle)?;
        rename_noreplace_at(parent, &temporary, name, &temporary_path, path)
            .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
        Ok((staging_handle.take().unwrap(), id))
    })();
    if let Err(error) = result {
        // Track creation separately from identity capture: the first metadata
        // call itself can fail after mkdir/open has already created the object.
        // Prefer the retained handle when available; otherwise re-read the
        // random staging entry and compare it again immediately before unlink.
        let rollback_id = if staging_created {
            created
                .or_else(|| {
                    staging_handle.as_ref().and_then(|handle| {
                        handle
                            .metadata()
                            .ok()
                            .map(|metadata| metadata_id(&metadata))
                    })
                })
                .or_else(|| {
                    metadata_at(parent, &temporary)
                        .ok()
                        .map(|metadata| metadata_id(&metadata))
                })
        } else {
            None
        };
        if rollback_id.is_some_and(|id| {
            metadata_at(parent, &temporary).is_ok_and(|metadata| metadata_id(&metadata) == id)
        }) {
            let _ = unlink_at(parent, &temporary);
        }
        return Err(error);
    }
    result
}

enum BorrowOutcome {
    Borrowed,
    Unmarked,
    Retry,
}

fn borrow_existing(
    path: &Path,
    created: ObjectId,
    handle: std::fs::File,
    parent: std::fs::File,
) -> std::io::Result<BorrowOutcome> {
    if CleanupRegistry::global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .borrow(path, created)
    {
        return Ok(BorrowOutcome::Borrowed);
    }
    if metadata_id(&handle.metadata()?) != created || !file_has_placeholder_marker(&handle)? {
        return Ok(BorrowOutcome::Unmarked);
    }
    lock_shared(&handle)?;
    // The previous last user may finish between the open and the lock. Accept
    // the lifetime only if the name in the pinned parent still has this identity.
    let Some(name) = path.file_name() else {
        return Ok(BorrowOutcome::Unmarked);
    };
    if !metadata_at(&parent, name).is_ok_and(|metadata| metadata_id(&metadata) == created) {
        return Ok(BorrowOutcome::Retry);
    }
    let mut registry = CleanupRegistry::global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if registry.removing.contains(&created) {
        return Ok(BorrowOutcome::Retry);
    }
    registry.record(path, created, handle, parent);
    Ok(BorrowOutcome::Borrowed)
}

#[derive(Debug)]
struct CreationFailure {
    error: std::io::Error,
    created: Vec<(PathBuf, ObjectId)>,
}

/// Create the mount point for a missing denied entry and record what it made.
///
/// Bubblewrap reuses an existing mount point rather than making one, so creating
/// it here is what establishes ownership. Every level this run adds is recorded
/// with its identity; cleanup removes only those exact objects.
fn create_mount_point(
    root: &Path,
    target: &Path,
    is_file: bool,
) -> Result<Vec<(PathBuf, ObjectId)>, CreationFailure> {
    let mut reached_existing = false;
    let mut paths: Vec<PathBuf> = target
        .ancestors()
        .take_while(|path| {
            if reached_existing {
                return false;
            }
            if std::fs::symlink_metadata(path).is_ok() {
                reached_existing = true;
            }
            // Include the target and the first existing ancestor. Both can be
            // shared placeholders whose cleanup must serialize with this run.
            true
        })
        .map(Path::to_path_buf)
        .collect();
    paths.sort_by_key(|path| path.components().count());
    let locks: Vec<_> = paths.iter().map(|path| path_lock(path)).collect();
    let _guards: Vec<_> = locks
        .iter()
        .map(|lock| {
            lock.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        })
        .collect();
    create_mount_point_locked(root, target, is_file)
}

fn create_mount_point_locked(
    root_path: &Path,
    target: &Path,
    is_file: bool,
) -> Result<Vec<(PathBuf, ObjectId)>, CreationFailure> {
    let (root, _) = open_grant_root(root_path).map_err(|error| CreationFailure {
        error,
        created: Vec::new(),
    })?;
    let relative = target
        .strip_prefix(root_path)
        .map_err(|error| CreationFailure {
            error: std::io::Error::other(error),
            created: Vec::new(),
        })?;
    let mut created = Vec::new();
    let mut current = target.to_path_buf();
    let mut current_relative = relative.to_path_buf();
    // Collect the missing levels first so they can be created top-down. Existing
    // levels are borrowed only when their marker and shared lifetime are valid.
    let mut missing = Vec::new();
    loop {
        if current_relative.as_os_str().is_empty() {
            break;
        }
        // Existing caller objects, including FIFOs, sockets, and symlinks, are
        // valid deny targets and need no readable handle. Only our marked file
        // or directory placeholders enter the shared-lifetime protocol.
        if std::fs::symlink_metadata(&current).is_ok_and(|metadata| {
            if !metadata.is_dir() {
                return true;
            }
            path_has_placeholder_marker(&current).is_ok_and(|marked| !marked)
        }) {
            break;
        }
        match open_object(&root, &current_relative) {
            Ok(handle) => {
                let metadata = match handle.metadata() {
                    Ok(metadata) => metadata,
                    Err(error) => return Err(CreationFailure { error, created }),
                };
                if !metadata.is_dir() {
                    break;
                }
                let created_id = metadata_id(&metadata);
                let parent = match open_parent(&root, &current_relative) {
                    Ok(parent) => parent,
                    Err(error) => return Err(CreationFailure { error, created }),
                };
                match borrow_existing(&current, created_id, handle, parent) {
                    Ok(BorrowOutcome::Borrowed) => {
                        created.push((current.clone(), created_id));
                    }
                    Ok(BorrowOutcome::Unmarked) => break,
                    Ok(BorrowOutcome::Retry) => missing.push(current.clone()),
                    Err(error) => return Err(CreationFailure { error, created }),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(current.clone());
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    || error.raw_os_error() == Some(nix::libc::ELOOP) =>
            {
                // An unreadable or symbolic-link caller object is still a valid
                // preexisting deny target. Only a marked placeholder must be
                // opened and shared; failing to do so rejects startup.
                match path_has_placeholder_marker(&current) {
                    Ok(false) => break,
                    Ok(true) => return Err(CreationFailure { error, created }),
                    Err(marker_error) if marker_error.kind() == std::io::ErrorKind::NotFound => {
                        missing.push(current.clone());
                    }
                    Err(marker_error) => {
                        return Err(CreationFailure {
                            error: marker_error,
                            created,
                        });
                    }
                }
            }
            Err(error) => return Err(CreationFailure { error, created }),
        }
        let Some(parent) = current.parent() else {
            break;
        };
        let Some(relative_parent) = current_relative.parent() else {
            break;
        };
        current = parent.to_path_buf();
        current_relative = relative_parent.to_path_buf();
    }
    let deepest = missing.first().cloned();
    if is_file && deepest.is_some() {
        // POSIX provides no atomic "unlink only if still empty" operation that
        // excludes writes through an already-open descriptor. Fail closed rather
        // than creating a host-visible file we might later delete after a write.
        return Err(CreationFailure {
            error: std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "missing file deny target requires an unsafe host file placeholder",
            ),
            created,
        });
    }
    for directory in missing.into_iter().rev() {
        // The leaf is a file when the deny mask binds /dev/null over it; every
        // level above it is always a directory.
        #[cfg(test)]
        {
            test_control::wait_before_create(&directory);
            test_control::wait_for_root_swap_create(&directory);
        }
        let directory_relative = match directory.strip_prefix(root_path) {
            Ok(relative) => relative,
            Err(error) => {
                return Err(CreationFailure {
                    error: std::io::Error::other(error),
                    created,
                });
            }
        };
        let parent = match open_parent(&root, directory_relative) {
            Ok(parent) => parent,
            Err(error) => return Err(CreationFailure { error, created }),
        };
        let Some(name) = directory.file_name() else {
            return Err(CreationFailure {
                error: std::io::Error::other("denied mount point has no final name"),
                created,
            });
        };
        // Stage and lock the file or directory before publishing it with a
        // no-replace rename in the pinned parent. The handle, not a later path
        // lookup, is the identity of the object this call created.
        match create_object_at(&parent, name, &directory) {
            Ok((handle, created_id)) => {
                #[cfg(test)]
                test_control::wait_for_identity(&directory);
                CleanupRegistry::global()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .record(&directory, created_id, handle, parent);
                created.push((directory, created_id));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                // Another run made this level. Borrow only a marked placeholder;
                // an unrelated object is never claimed, but descendants may
                // still be ours to create.
                let handle = match open_object(&root, directory_relative) {
                    Ok(handle) => handle,
                    Err(error) => return Err(CreationFailure { error, created }),
                };
                let metadata = match handle.metadata() {
                    Ok(metadata) => metadata,
                    Err(error) => return Err(CreationFailure { error, created }),
                };
                if !metadata.is_dir() {
                    continue;
                }
                let created_id = metadata_id(&metadata);
                match borrow_existing(&directory, created_id, handle, parent) {
                    Ok(BorrowOutcome::Borrowed) => {
                        created.push((directory, created_id));
                    }
                    Ok(BorrowOutcome::Unmarked) => {}
                    Ok(BorrowOutcome::Retry) => {
                        return Err(CreationFailure {
                            error: std::io::Error::new(
                                std::io::ErrorKind::AlreadyExists,
                                "placeholder changed repeatedly while joining its lifetime",
                            ),
                            created,
                        });
                    }
                    Err(error) => return Err(CreationFailure { error, created }),
                }
            }
            Err(error) => return Err(CreationFailure { error, created }),
        }
    }
    created.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    #[cfg(test)]
    {
        test_control::wait_for_creation(target);
        test_control::wait_for_stalled_creation(target);
    }
    Ok(created)
}

#[cfg(test)]
pub(crate) mod test_control {
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{Receiver, SyncSender};
    use std::sync::{Mutex, OnceLock};

    type PathGate = OnceLock<(PathBuf, SyncSender<()>, Mutex<Receiver<()>>)>;

    static STARTED: OnceLock<SyncSender<()>> = OnceLock::new();
    static RELEASE: OnceLock<Mutex<Receiver<()>>> = OnceLock::new();
    static TARGET: OnceLock<PathBuf> = OnceLock::new();
    static CLEANUP_ENABLED: AtomicBool = AtomicBool::new(false);
    static COMPLETION_STARTED: OnceLock<SyncSender<()>> = OnceLock::new();
    static COMPLETION_RELEASE: OnceLock<Mutex<Receiver<()>>> = OnceLock::new();
    static COMPLETION_TARGET: OnceLock<PathBuf> = OnceLock::new();
    static COMPLETION_CLEANUP_ENABLED: AtomicBool = AtomicBool::new(false);
    static PATH: PathGate = OnceLock::new();
    static PATH_ENTERED: AtomicBool = AtomicBool::new(false);
    static CREATION: PathGate = OnceLock::new();
    static STALLED_CREATION: PathGate = OnceLock::new();
    static STORAGE_CLEANUP: PathGate = OnceLock::new();
    static STORAGE_JOB: OnceLock<(SyncSender<()>, Mutex<Receiver<()>>)> = OnceLock::new();
    static STORAGE_JOB_ENTERED: AtomicBool = AtomicBool::new(false);
    static BEFORE_CREATE: PathGate = OnceLock::new();
    static ROOT_SWAP_CREATE: PathGate = OnceLock::new();
    static ROOT_SWAP_REMOVE: PathGate = OnceLock::new();
    static IDENTITY: PathGate = OnceLock::new();
    static REMOVAL: PathGate = OnceLock::new();
    static REMOVAL_ENTERED: AtomicBool = AtomicBool::new(false);
    static FAIL_SPAWN_TARGETS: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());
    static FAIL_RENAME_TARGETS: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());
    static FAIL_STAGING_OPEN_TARGETS: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());
    static FAIL_INITIAL_STAGING_METADATA_TARGETS: Mutex<BTreeSet<PathBuf>> =
        Mutex::new(BTreeSet::new());

    pub(crate) fn hold_cleanup(path: PathBuf) -> (Receiver<()>, SyncSender<()>) {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        TARGET.set(path).expect("cleanup barrier installed twice");
        STARTED
            .set(started_tx)
            .expect("cleanup barrier installed twice");
        RELEASE
            .set(Mutex::new(release_rx))
            .expect("cleanup barrier installed twice");
        CLEANUP_ENABLED.store(true, Ordering::Release);
        (started_rx, release_tx)
    }

    pub(crate) fn hold_completion_cleanup(path: PathBuf) -> (Receiver<()>, SyncSender<()>) {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        COMPLETION_TARGET
            .set(path)
            .expect("completion cleanup barrier installed twice");
        COMPLETION_STARTED
            .set(started_tx)
            .expect("completion cleanup barrier installed twice");
        COMPLETION_RELEASE
            .set(Mutex::new(release_rx))
            .expect("completion cleanup barrier installed twice");
        COMPLETION_CLEANUP_ENABLED.store(true, Ordering::Release);
        (started_rx, release_tx)
    }

    pub(crate) fn fail_cleanup_spawn_for(path: PathBuf) {
        FAIL_SPAWN_TARGETS.lock().unwrap().insert(path);
    }

    pub(super) fn take_spawn_failure(levels: &[(PathBuf, (u64, u64))]) -> bool {
        let mut targets = FAIL_SPAWN_TARGETS.lock().unwrap();
        let matched = targets
            .iter()
            .find(|target| levels.iter().any(|(path, _)| path == *target))
            .cloned();
        if let Some(matched) = matched {
            targets.remove(&matched);
            return true;
        }
        false
    }

    pub(crate) fn fail_rename_for(path: PathBuf) {
        FAIL_RENAME_TARGETS.lock().unwrap().insert(path);
    }

    pub(crate) fn clear_rename_failure_for(path: &std::path::Path) {
        FAIL_RENAME_TARGETS.lock().unwrap().remove(path);
    }

    pub(crate) fn fail_staging_open_for(path: PathBuf) {
        FAIL_STAGING_OPEN_TARGETS.lock().unwrap().insert(path);
    }

    pub(crate) fn fail_initial_staging_metadata_for(path: PathBuf) {
        FAIL_INITIAL_STAGING_METADATA_TARGETS
            .lock()
            .unwrap()
            .insert(path);
    }

    pub(super) fn fail_initial_staging_metadata(path: &std::path::Path) -> std::io::Result<()> {
        if FAIL_INITIAL_STAGING_METADATA_TARGETS
            .lock()
            .unwrap()
            .contains(path)
        {
            Err(std::io::Error::other(
                "injected initial staging metadata failure",
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn fail_staging_open(path: &std::path::Path) -> std::io::Result<()> {
        if FAIL_STAGING_OPEN_TARGETS.lock().unwrap().contains(path) {
            Err(std::io::Error::other("injected staging open failure"))
        } else {
            Ok(())
        }
    }

    pub(super) fn rename_fails(from: &std::path::Path, to: &std::path::Path) -> bool {
        FAIL_RENAME_TARGETS
            .lock()
            .unwrap()
            .iter()
            .any(|target| target == from || target == to)
    }

    pub(crate) fn hold_path(path: PathBuf) -> (Receiver<()>, SyncSender<()>) {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        PATH.set((path, started_tx, Mutex::new(release_rx)))
            .expect("path barrier installed twice");
        (started_rx, release_tx)
    }

    pub(crate) fn hold_creation(path: PathBuf) -> (Receiver<()>, SyncSender<()>) {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        CREATION
            .set((path, started_tx, Mutex::new(release_rx)))
            .expect("creation barrier installed twice");
        (started_rx, release_tx)
    }

    pub(crate) fn hold_before_create(path: PathBuf) -> (Receiver<()>, SyncSender<()>) {
        hold_gate(&BEFORE_CREATE, path)
    }

    pub(crate) fn hold_stalled_creation(path: PathBuf) -> (Receiver<()>, SyncSender<()>) {
        hold_gate(&STALLED_CREATION, path)
    }

    pub(crate) fn hold_storage_cleanup(path: PathBuf) -> (Receiver<()>, SyncSender<()>) {
        hold_gate(&STORAGE_CLEANUP, path)
    }

    pub(crate) fn hold_storage_job() -> (Receiver<()>, SyncSender<()>) {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        STORAGE_JOB
            .set((started_tx, Mutex::new(release_rx)))
            .expect("storage job barrier installed twice");
        STORAGE_JOB_ENTERED.store(false, Ordering::Release);
        (started_rx, release_tx)
    }

    pub(super) fn wait_for_storage_job(levels: &[(PathBuf, (u64, u64))]) {
        if !levels.is_empty() || STORAGE_JOB_ENTERED.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some((started, release)) = STORAGE_JOB.get() else {
            return;
        };
        started.send(()).expect("report storage job start");
        release
            .lock()
            .unwrap()
            .recv()
            .expect("wait for storage job release");
    }

    pub(crate) fn hold_root_swap_create(path: PathBuf) -> (Receiver<()>, SyncSender<()>) {
        hold_gate(&ROOT_SWAP_CREATE, path)
    }

    pub(crate) fn hold_root_swap_remove(path: PathBuf) -> (Receiver<()>, SyncSender<()>) {
        hold_gate(&ROOT_SWAP_REMOVE, path)
    }

    pub(crate) fn hold_identity(path: PathBuf) -> (Receiver<()>, SyncSender<()>) {
        hold_gate(&IDENTITY, path)
    }

    pub(crate) fn hold_removal(path: PathBuf) -> (Receiver<()>, SyncSender<()>) {
        hold_gate(&REMOVAL, path)
    }

    fn hold_gate(gate: &'static PathGate, path: PathBuf) -> (Receiver<()>, SyncSender<()>) {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        gate.set((path, started_tx, Mutex::new(release_rx)))
            .expect("path barrier installed twice");
        (started_rx, release_tx)
    }

    fn wait_at(gate: &PathGate, path: &std::path::Path) {
        let Some((selected, started, release)) = gate.get() else {
            return;
        };
        if selected != path {
            return;
        }
        started.send(()).expect("report path start");
        release
            .lock()
            .unwrap()
            .recv()
            .expect("wait for path release");
    }

    pub(super) fn wait_for_path(path: &std::path::Path) {
        if PATH.get().is_none_or(|(selected, _, _)| selected != path)
            || PATH_ENTERED.swap(true, Ordering::AcqRel)
        {
            return;
        }
        wait_at(&PATH, path);
    }

    pub(super) fn wait_for_creation(path: &std::path::Path) {
        wait_at(&CREATION, path);
    }

    pub(super) fn wait_for_stalled_creation(path: &std::path::Path) {
        wait_at(&STALLED_CREATION, path);
    }

    pub(super) fn wait_for_storage_cleanup(levels: &[(PathBuf, (u64, u64))]) {
        if STORAGE_CLEANUP
            .get()
            .is_some_and(|(selected, _, _)| levels.iter().any(|(path, _)| path == selected))
        {
            wait_at(&STORAGE_CLEANUP, &levels[0].0);
        }
    }

    pub(super) fn wait_before_create(path: &std::path::Path) {
        wait_at(&BEFORE_CREATE, path);
    }

    pub(super) fn wait_for_root_swap_create(path: &std::path::Path) {
        wait_at(&ROOT_SWAP_CREATE, path);
    }

    pub(super) fn wait_for_root_swap_remove(path: &std::path::Path) {
        wait_at(&ROOT_SWAP_REMOVE, path);
    }

    pub(super) fn wait_for_identity(path: &std::path::Path) {
        wait_at(&IDENTITY, path);
    }

    pub(super) fn wait_for_removal(path: &std::path::Path) {
        if REMOVAL
            .get()
            .is_some_and(|(selected, _, _)| selected == path)
            && !REMOVAL_ENTERED.swap(true, Ordering::AcqRel)
        {
            wait_at(&REMOVAL, path);
        }
    }

    pub(super) fn wait_for_completion_cleanup(created_levels: &[(PathBuf, (u64, u64))]) {
        if !COMPLETION_CLEANUP_ENABLED.load(Ordering::Acquire)
            || !created_levels
                .iter()
                .any(|(path, _)| Some(path) == COMPLETION_TARGET.get())
        {
            return;
        }
        let (Some(started), Some(release)) = (COMPLETION_STARTED.get(), COMPLETION_RELEASE.get())
        else {
            return;
        };
        started.send(()).expect("report completion cleanup start");
        release
            .lock()
            .unwrap()
            .recv()
            .expect("wait for completion cleanup release");
        COMPLETION_CLEANUP_ENABLED.store(false, Ordering::Release);
    }

    pub(super) fn wait(created_levels: &[(PathBuf, (u64, u64))]) {
        if !CLEANUP_ENABLED.load(Ordering::Acquire)
            || !created_levels
                .iter()
                .any(|(path, _)| Some(path) == TARGET.get())
        {
            return;
        }
        let (Some(started), Some(release)) = (STARTED.get(), RELEASE.get()) else {
            return;
        };
        started.send(()).expect("report cleanup start");
        release
            .lock()
            .unwrap()
            .recv()
            .expect("wait for cleanup release");
        CLEANUP_ENABLED.store(false, Ordering::Release);
    }
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
pub(crate) fn remove_levels(created_levels: &[(PathBuf, ObjectId)]) {
    if let Err(error) = remove_levels_with_probe(created_levels, FilesystemProbe::default()) {
        eprintln!("Bubblewrap: denied-path cleanup did not finish: {error}");
    }
}

fn remove_levels_with_probe(
    created_levels: &[(PathBuf, ObjectId)],
    mut probe: FilesystemProbe,
) -> Result<(), String> {
    if created_levels.is_empty() {
        return Ok(());
    }
    // Siblings share ancestors: `grant/missing/a` and `grant/missing/b` both
    // create `grant/missing`. Removing one entry at a time would leave the
    // shared ancestor behind, because it is not empty until the last sibling is
    // gone. Deepest first, so a level is reached again after the siblings that
    // kept it non-empty have already been removed.
    let mut levels: Vec<(PathBuf, ObjectId)> = created_levels.to_vec();
    levels.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));

    let display = created_levels
        .first()
        .map(|(path, _)| path.display().to_string())
        .unwrap_or_else(|| "denied paths".to_string());
    let (submitted, result) = probe.run_with_submission(&display, move |_| {
        let mut failures = Vec::new();
        let mut registry = CleanupRegistry::global()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (_path, created) in &levels {
            registry.users.entry(*created).or_insert(1);
        }
        // One deadline covers the whole dependent walk. If the caller stops
        // waiting, this worker still finishes the same ordered passes, so a late
        // child removal is always followed by another ancestor attempt.
        loop {
            let mut removed = false;
            for (path, created) in levels.iter().cloned() {
                if !registry.begin_remove(&path, created) {
                    continue;
                }
                let handles = registry.removal_handles(&path, created);
                // Do not hold the registry across filesystem IO. The removing
                // mark stops another run from borrowing the object meanwhile.
                drop(registry);
                let outcome = match handles {
                    Ok((handle, parent, registered_path)) => {
                        let operation_path = registered_path.as_deref().unwrap_or(&path);
                        remove_level(operation_path, created, handle, parent)
                    }
                    Err(error) => Err(error),
                };
                registry = CleanupRegistry::global()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match outcome {
                    Ok(removed_now) => {
                        registry.finish_remove(&path, created, removed_now);
                        if removed_now {
                            removed = true;
                        }
                    }
                    Err(error) => {
                        registry.finish_remove(&path, created, false);
                        failures.push(error.to_string());
                    }
                }
            }
            if !removed {
                break;
            }
        }
        for (path, created) in &levels {
            if registry.release_if_shared(path, *created) {
                continue;
            }
            if !registry.begin_remove(path, *created) {
                continue;
            }
            let handles = registry.removal_handles(path, *created);
            drop(registry);
            let outcome = match handles {
                Ok((handle, parent, registered_path)) => {
                    let operation_path = registered_path.as_deref().unwrap_or(path);
                    remove_level(operation_path, *created, handle, parent)
                }
                Err(error) => Err(error),
            };
            registry = CleanupRegistry::global()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match outcome {
                Ok(_) => registry.finish_remove(path, *created, true),
                Err(error) => {
                    // This exited sandbox has no later cleanup attempt. End
                    // its ownership even on failure so the retained handle
                    // cannot strand a shared or exclusive flock.
                    registry.finish_remove(path, *created, true);
                    failures.push(error.to_string());
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    });
    let result = result.and_then(std::convert::identity);
    if !submitted {
        // No worker owns the clone. Release this run's registry references
        // without filesystem IO so a later borrower can become the last user.
        let mut registry = CleanupRegistry::global()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (_path, created) in created_levels {
            registry.release_unstarted(*created);
        }
    }
    result
}

/// Shared ownership of every level created during one preparation.
///
/// Creation jobs keep a reference in their probe result. If a preparation
/// times out, its cleanup therefore waits for the outstanding job's ownership
/// to settle; the last reference removes all levels, including ancestors that
/// were nonempty when the preparation first unwound.
#[derive(Debug, Default)]
struct CreationGroup {
    levels: std::sync::Mutex<Vec<(PathBuf, ObjectId)>>,
}

impl CreationGroup {
    fn record(&self, created: Vec<(PathBuf, ObjectId)>) {
        self.levels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(created);
    }

    fn take(mut self) -> Vec<(PathBuf, ObjectId)> {
        std::mem::take(
            self.levels
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

impl Drop for CreationGroup {
    fn drop(&mut self) {
        let levels = std::mem::take(
            self.levels
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if !levels.is_empty() {
            remove_levels(&levels);
        }
    }
}

fn finish_creations(group: std::sync::Arc<CreationGroup>) -> Vec<(PathBuf, ObjectId)> {
    std::sync::Arc::try_unwrap(group)
        .expect("all creation results settled before a successful preparation")
        .take()
}

/// Move one level aside before deciding whether it is ours to remove. The
/// no-replace rename closes the check/remove pathname race; anything that does
/// not match after the move is put back without deleting its contents.
fn remove_level(
    path: &Path,
    created: ObjectId,
    handle: Option<std::fs::File>,
    parent: Option<std::fs::File>,
) -> std::io::Result<bool> {
    let lock = path_lock(path);
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    #[cfg(test)]
    test_control::wait_for_path(path);

    let handle = match handle {
        Some(handle) => handle,
        None => {
            #[cfg(test)]
            {
                use std::os::unix::fs::OpenOptionsExt;

                match std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(nix::libc::O_NOFOLLOW)
                    .open(path)
                {
                    Ok(handle) => handle,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                    Err(error) => return Err(error),
                }
            }
            #[cfg(not(test))]
            {
                return Err(std::io::Error::other(format!(
                    "denied mount point '{}' has no retained ownership handle",
                    path.display()
                )));
            }
        }
    };
    let parent = match parent {
        Some(parent) => parent,
        None => {
            #[cfg(test)]
            {
                use std::os::unix::fs::OpenOptionsExt;

                let parent_path = path
                    .parent()
                    .ok_or_else(|| std::io::Error::other("denied mount point has no parent"))?;
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
                    .open(parent_path)?
            }
            #[cfg(not(test))]
            {
                return Err(std::io::Error::other(format!(
                    "denied mount point '{}' has no retained parent handle",
                    path.display()
                )));
            }
        }
    };
    if !try_lock_exclusive(&handle)? {
        // A non-blocking flock upgrade is not atomic and may have dropped this
        // handle's old shared lock. Restore it while the record remains visible;
        // another process still holding shared use does not prevent that.
        lock_shared(&handle)?;
        // Another process still holds a shared lifetime. It has its own
        // registered cleanup record and will retry when it becomes the last user.
        return Ok(false);
    }

    let Some(name) = path.file_name() else {
        return Ok(false);
    };
    let metadata = match metadata_at(&parent, name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if metadata_id(&metadata) != created {
        return Ok(false);
    }
    #[cfg(test)]
    {
        test_control::wait_for_removal(path);
        test_control::wait_for_root_swap_remove(path);
    }

    let quarantine_name =
        std::ffi::OsString::from(format!(".mxc-cleanup-{}", uuid::Uuid::new_v4()));
    let quarantine = path
        .parent()
        .ok_or_else(|| std::io::Error::other("denied mount point has no parent"))?
        .join(&quarantine_name);
    if let Err(error) = rename_noreplace_at(&parent, name, &quarantine_name, path, &quarantine) {
        return Err(std::io::Error::other(format!(
            "could not quarantine denied mount point '{}': {error}",
            path.display()
        )));
    }

    let removed = metadata_at(&parent, &quarantine_name).is_ok_and(|metadata| {
        if metadata_id(&metadata) != created {
            return false;
        }
        if metadata.is_dir() {
            unlink_at(&parent, &quarantine_name).is_ok()
        } else {
            // There is no atomic unlink that excludes a concurrent write through
            // an existing file descriptor. Files are therefore never deleted.
            false
        }
    });
    if removed {
        return Ok(true);
    }

    // A replacement, newly populated object, or a directory that gained an
    // entry is not this run's to delete. Restore it if the original name is
    // still free; never overwrite a newer object at that name.
    rename_noreplace_at(&parent, &quarantine_name, name, &quarantine, path).map_err(|error| {
        std::io::Error::other(format!(
            "could not restore denied mount point '{}' from '{}': {error}",
            path.display(),
            quarantine.display()
        ))
    })?;
    Ok(false)
}

/// Keep missing deny mountpoints off the host and out of read-only binds.
///
/// A read-only parent can be overlaid privately, so nothing is created on the
/// host. A read-write parent is bound from the host as it is, which leaves the
/// mount point Bubblewrap needs in that same directory; those entries are
/// reported in [`DenyPreparation::created_levels`] for the sandbox to remove.
pub(crate) fn prepare(
    mounts: &mut Vec<PolicyMount>,
    baseline_links: &[BaselineLink],
    denied_files: &std::collections::HashSet<String>,
    version: BwrapVersion,
    bwrap_is_setuid: bool,
) -> Result<DenyPreparation, FilesystemPolicyError> {
    prepare_inner(
        mounts,
        baseline_links,
        denied_files,
        version,
        bwrap_is_setuid,
        FilesystemProbe::default(),
    )
}

fn prepare_inner(
    mounts: &mut Vec<PolicyMount>,
    baseline_links: &[BaselineLink],
    denied_files: &std::collections::HashSet<String>,
    version: BwrapVersion,
    bwrap_is_setuid: bool,
    mut probe: FilesystemProbe,
) -> Result<DenyPreparation, FilesystemPolicyError> {
    let baseline = baseline_mounts(BASELINE_RO_BIND_PATHS, baseline_links, &mut probe)?;
    let mut overlays = BTreeMap::<(String, String), Vec<PathBuf>>::new();
    // Shared with every creation job so a failed preparation cannot release an
    // ancestor before a late sibling result has settled.
    let group = std::sync::Arc::new(CreationGroup::default());
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
            Ok(()) if parent.intent == FsIntent::ReadOnly => continue,
            Ok(()) => {}
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
            let host_root = Path::new(&parent.source).to_path_buf();
            let display = host_target.display().to_string();
            // The job returns its shared reference with the result. On timeout,
            // dropping that result releases the last owner only after the job
            // has finished, so the complete ancestor walk includes its levels.
            let creations = std::sync::Arc::clone(&group);
            let creation_result = probe
                .run(&display, move |_| {
                    match create_mount_point(&host_root, &host_target, is_file) {
                        Ok(created) => {
                            creations.record(created);
                            Ok(creations)
                        }
                        Err(failure) => {
                            // Even a failed creation can own ancestors it made
                            // first. Return them through the shared group so the
                            // failed preparation releases the complete walk.
                            creations.record(failure.created);
                            Err(failure.error)
                        }
                    }
                })
                .map_err(|error| FilesystemPolicyError::Host(format!("Bubblewrap: {error}")))?
                .map_err(|error| {
                    FilesystemPolicyError::Host(format!(
                        "Bubblewrap: could not create deniedPaths entry '{}': {error}",
                        denied.source
                    ))
                })?;
            drop(creation_result);
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
            created_levels: finish_creations(group),
            armed: true,
            cleanup_warnings: CleanupWarnings::default(),
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
        _storage: Some(std::sync::Arc::new(directory)),
        created_levels: finish_creations(group),
        armed: true,
        cleanup_warnings: CleanupWarnings::default(),
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
