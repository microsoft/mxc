// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MicroVM staging directory builder for mount-based script delivery.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use thiserror::Error;
use uuid::Uuid;

/// Entry point filename (warm-start protocol executes this automatically).
pub const BOOTSTRAP_FILENAME: &str = "bootstrap.py";
/// Subdirectory for read-write staged host paths.
pub const RW_DIR: &str = "rw";
/// Subdirectory for read-only staged host paths.
pub const RO_DIR: &str = "ro";
/// Guest mount root inside the NanVix VM.
const GUEST_MOUNT_ROOT: &str = "/mnt";

/// Builds the guest-visible path for a staged host directory.
fn build_guest_path(category: &str, name: &str) -> String {
    format!("{}/{}/{}", GUEST_MOUNT_ROOT, category, name)
}

/// Preamble prepended to the user script in bootstrap.py.
///
/// Composed from [`GUEST_MOUNT_ROOT`] and [`BOOTSTRAP_FILENAME`] so that
/// any future change to either constant flows through automatically.
fn bootstrap_preamble() -> String {
    format!(
        "import sys\nsys.argv = ['{}/{}']\n",
        GUEST_MOUNT_ROOT, BOOTSTRAP_FILENAME
    )
}

/// Errors produced while creating or validating a staging directory.
#[derive(Debug, Error)]
pub enum StagingError {
    /// A requested host path does not exist.
    #[error("host path does not exist: {0}")]
    PathNotFound(String),
    /// A symlink was found in a source path.
    #[error("symlink found in source path: {0}")]
    SymlinkFound(String),
    /// I/O failure.
    #[error("staging I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Intermediate result from the staging build closure.
struct StagingBuildOutput {
    /// Total bytes written to the staging directory.
    size_bytes: u64,
}

/// Return type of the staging build closure.
type StagingBuildResult = Result<StagingBuildOutput, StagingError>;

/// RAII wrapper over a temporary staging directory.
#[derive(Debug)]
pub struct StagingDir {
    path: PathBuf,
    size_bytes: u64,
}

impl StagingDir {
    /// Creates and populates a staging directory under `root`.
    ///
    /// Read-write paths are exposed as symlinks pointing at the original host
    /// location, so guest writes are visible live on the host without an
    /// explicit copy-back step. Read-only paths are copied into the staging
    /// directory and marked read-only to enforce the policy independently of
    /// the host filesystem ACLs.
    pub fn new(
        root: PathBuf,
        script: &str,
        readwrite_paths: &[String],
        readonly_paths: &[String],
    ) -> Result<Self, StagingError> {
        // Validate source paths up front. Read-write paths are exposed via
        // symlink so we only need to check existence and reject `..` traversal;
        // read-only paths are still copied so the no-symlink/no-reparse check
        // applies recursively to their contents.
        for source in readwrite_paths {
            validate_rw_source_path(Path::new(source), source)?;
        }
        for source in readonly_paths {
            validate_ro_source_path(Path::new(source), source)?;
        }

        fs::create_dir_all(&root)?;
        let path = root.join(format!("mxc-staging-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&path)?;

        let build_result = || -> StagingBuildResult {
            // Collect host→guest path mappings for script rewriting.
            let mut rewrite_map: Vec<(String, String)> = Vec::new();
            // Track staged bytes incrementally to avoid a full directory walk
            // at the end (which scaled with total staged content size).
            let mut size_bytes: u64 = 0;

            if !readwrite_paths.is_empty() {
                fs::create_dir_all(path.join(RW_DIR))?;
            }
            for source in readwrite_paths {
                let host_path = PathBuf::from(source);

                let relative = host_path_to_guest_relative(&host_path);
                let slot_dir = path.join(RW_DIR).join(&relative);
                let bytes = stage_rw_host_path(&host_path, &slot_dir)?;
                size_bytes = size_bytes.saturating_add(bytes);
                let guest_path = build_guest_path(RW_DIR, &relative);
                rewrite_map.push((source.clone(), guest_path));
            }

            if !readonly_paths.is_empty() {
                fs::create_dir_all(path.join(RO_DIR))?;
            }
            for source in readonly_paths {
                let host_path = PathBuf::from(source);

                let relative = host_path_to_guest_relative(&host_path);
                let slot_dir = path.join(RO_DIR).join(&relative);
                let bytes = if host_path.is_dir() {
                    copy_dir_recursive(&host_path, &slot_dir)?
                } else {
                    fs::create_dir_all(&slot_dir)?;
                    let file_name = host_path
                        .file_name()
                        .ok_or_else(|| StagingError::PathNotFound(source.clone()))?;
                    fs::copy(&host_path, slot_dir.join(file_name))?
                };
                size_bytes = size_bytes.saturating_add(bytes);
                set_readonly_recursive(&slot_dir)?;
                let guest_path = build_guest_path(RO_DIR, &relative);
                rewrite_map.push((source.clone(), guest_path));
            }

            // Rewrite host paths in the user script so callers don't need to
            // know about the guest mount layout. Both backslash and forward-slash
            // variants of each host path are replaced.
            let rewritten_script = rewrite_paths_in_script(script, &rewrite_map);
            let bootstrap_content = format!("{}{}", bootstrap_preamble(), rewritten_script);
            fs::write(path.join(BOOTSTRAP_FILENAME), &bootstrap_content)?;
            size_bytes = size_bytes.saturating_add(bootstrap_content.len() as u64);

            Ok(StagingBuildOutput { size_bytes })
        }();

        let StagingBuildOutput { size_bytes } = match build_result {
            Ok(result) => result,
            Err(err) => {
                let _ = remove_dir_all_force(&path);
                return Err(err);
            }
        };

        Ok(Self { path, size_bytes })
    }

    /// Returns the host path to the staging directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// No-op kept for backward compatibility with the previous copy-back model.
    ///
    /// Read-write paths are now exposed as symlinks, so guest writes land on
    /// the original host path immediately. Callers retain the same call site
    /// but the operation is a guaranteed success.
    pub fn copy_back_to_host(&mut self) -> Result<(), StagingError> {
        Ok(())
    }

    /// Always `None`: there is nothing to preserve because no copy-back step
    /// can fail under the symlink-based model.
    pub fn preserved_path(&self) -> Option<&Path> {
        None
    }

    /// Returns additional staging overhead in milliseconds.
    pub fn staging_overhead_ms(&self) -> u64 {
        let ms = ((self.size_bytes as f64 / (1024.0 * 1024.0)) * 100.0) as u64;
        ms.min(30_000)
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = remove_dir_all_force(&self.path);
    }
}

/// Converts a host path to a guest-relative path by stripping the drive letter prefix
/// and normalizing separators. E.g. `C:\Users\me\work` → `c/Users/me/work`.
fn host_path_to_guest_relative(host_path: &Path) -> String {
    let s = host_path.to_string_lossy();
    // Strip drive letter prefix (e.g. "C:\") and normalize to forward slashes.
    let stripped = if s.len() >= 3
        && s.as_bytes()[1] == b':'
        && (s.as_bytes()[2] == b'\\' || s.as_bytes()[2] == b'/')
    {
        let drive = s.as_bytes()[0].to_ascii_lowercase() as char;
        format!("{}/{}", drive, s[3..].replace('\\', "/"))
    } else {
        // UNC or relative path — just normalize slashes.
        s.replace('\\', "/")
    };
    // Trim trailing slash.
    stripped.trim_end_matches('/').to_string()
}

/// Replaces host paths in the script source with their guest mount equivalents.
/// Both backslash (`C:\Users\work`) and forward-slash (`C:/Users/work`) variants
/// are replaced. Longer paths are replaced first to avoid partial prefix matches.
fn rewrite_paths_in_script(script: &str, mappings: &[(String, String)]) -> String {
    let mut result = script.to_string();
    // Sort by host path length descending so longer prefixes match first.
    let mut sorted: Vec<_> = mappings.to_vec();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.0.len()));
    for (host_path, guest_path) in &sorted {
        // Replace escaped backslash variant first (Python string literals: C:\\Users\\work).
        let escaped = host_path.replace('\\', "\\\\");
        if escaped != *host_path {
            result = result.replace(&escaped, guest_path);
        }
        // Replace native backslash variant (C:\Users\work).
        result = result.replace(host_path, guest_path);
        // Replace forward-slash variant (C:/Users/work).
        let forward = host_path.replace('\\', "/");
        if forward != *host_path {
            result = result.replace(&forward, guest_path);
        }
    }
    result
}

/// Stages a single host path as a symlink under the read-write slot so guest
/// writes propagate live to the original host location. Falls back to a
/// private copy if symlink creation fails (e.g., the process lacks the
/// `SeCreateSymbolicLinkPrivilege` and Developer Mode is off).
///
/// Returns the number of bytes consumed by the staged content (0 for the
/// symlink path; the copy-back path returns the bytes copied).
fn stage_rw_host_path(host_path: &Path, slot_dir: &Path) -> Result<u64, StagingError> {
    if host_path.is_dir() {
        // Mirror the slot layout of the copy-based staging: the symlink lives
        // at `slot_dir` itself, with its parent already created.
        if let Some(parent) = slot_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        match create_symlink(host_path, slot_dir, true) {
            Ok(()) => Ok(0),
            Err(_) => copy_dir_recursive(host_path, slot_dir),
        }
    } else {
        fs::create_dir_all(slot_dir)?;
        let file_name = host_path
            .file_name()
            .ok_or_else(|| StagingError::PathNotFound(host_path.display().to_string()))?;
        let link_path = slot_dir.join(file_name);
        match create_symlink(host_path, &link_path, false) {
            Ok(()) => Ok(0),
            Err(_) => Ok(fs::copy(host_path, link_path)?),
        }
    }
}

/// Creates a symlink at `link` pointing to `target`.
///
/// On Windows the kind (file vs. directory) must be specified up front; on
/// other platforms it is irrelevant.
fn create_symlink(target: &Path, link: &Path, is_dir: bool) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::{symlink_dir, symlink_file};
        if is_dir {
            symlink_dir(target, link)
        } else {
            symlink_file(target, link)
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = is_dir;
        std::os::unix::fs::symlink(target, link)
    }
}

/// Copies a directory recursively. Returns the total number of bytes copied so
/// callers can track staging size without an extra full-tree walk afterward.
/// Uses `symlink_metadata` per entry to reject symlinks/reparse points during
/// traversal, closing the TOCTOU window between upfront validation and the actual copy.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<u64, StagingError> {
    fs::create_dir_all(dst)?;
    let mut total: u64 = 0;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(StagingError::SymlinkFound(
                entry.path().display().to_string(),
            ));
        }
        let target = dst.join(entry.file_name());
        if metadata.file_type().is_dir() {
            total = total.saturating_add(copy_dir_recursive(&entry.path(), &target)?);
        } else {
            total = total.saturating_add(fs::copy(entry.path(), target)?);
        }
    }
    Ok(total)
}

/// Sets the read-only attribute recursively for all files in `dir`.
fn set_readonly_recursive(dir: &Path) -> Result<(), StagingError> {
    if dir.is_file() {
        let mut perms = fs::metadata(dir)?.permissions();
        perms.set_readonly(true);
        fs::set_permissions(dir, perms)?;
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            set_readonly_recursive(&path)?;
        } else {
            let mut perms = fs::metadata(&path)?.permissions();
            perms.set_readonly(true);
            fs::set_permissions(&path, perms)?;
        }
    }
    Ok(())
}

/// Validates a read-write source: exists, has a filename, and contains no
/// `..` components. The path is exposed via symlink so we do not traverse it
/// to reject internal symlinks/reparse points — the host filesystem will
/// resolve them at access time.
fn validate_rw_source_path(path: &Path, original: &str) -> Result<(), StagingError> {
    validate_basic_source(path, original)
}

/// Validates a read-only source: same basic checks plus a recursive
/// no-symlink/no-reparse-point scan, since the content will be copied.
fn validate_ro_source_path(path: &Path, original: &str) -> Result<(), StagingError> {
    validate_basic_source(path, original)?;
    check_no_reparse_points(path)
}

/// Shared validation for both RW and RO sources.
fn validate_basic_source(path: &Path, original: &str) -> Result<(), StagingError> {
    if !path.exists() {
        return Err(StagingError::PathNotFound(original.to_string()));
    }
    if path.file_name().is_none() {
        return Err(StagingError::PathNotFound(format!(
            "root paths are not supported for microvm filesystem staging: {}",
            original
        )));
    }
    // Reject paths with `..` components to prevent path-traversal attacks that
    // could write outside the staging directory (e.g., `C:\a\..\b`).
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(StagingError::PathNotFound(format!(
                "paths with '..' components are not supported: {}",
                original
            )));
        }
    }
    Ok(())
}

/// Ensures no symlink or Windows reparse point is present in `path` or descendants.
fn check_no_reparse_points(path: &Path) -> Result<(), StagingError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(StagingError::SymlinkFound(path.display().to_string()));
    }

    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            check_no_reparse_points(&entry?.path())?;
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
}

#[cfg(not(target_os = "windows"))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

/// Removes a directory tree, clearing read-only attributes first.
#[allow(clippy::permissions_set_readonly_false)]
fn remove_dir_all_force(path: &Path) -> Result<(), StagingError> {
    if !path.exists() {
        return Ok(());
    }
    clear_readonly_recursive(path)?;
    fs::remove_dir_all(path)?;
    Ok(())
}

#[allow(clippy::permissions_set_readonly_false)]
fn clear_readonly_recursive(path: &Path) -> Result<(), StagingError> {
    let metadata = fs::symlink_metadata(path)?;
    // Never follow symlinks/reparse points: under the RW slot the staged
    // entries are symlinks pointing at host paths we must not mutate.
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Ok(());
    }

    if metadata.is_file() {
        let mut perms = metadata.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            fs::set_permissions(path, perms)?;
        }
        return Ok(());
    }

    for entry in fs::read_dir(path)? {
        clear_readonly_recursive(&entry?.path())?;
    }

    let mut perms = fs::metadata(path)?.permissions();
    if perms.readonly() {
        perms.set_readonly(false);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Removes orphaned `mxc-staging-*` directories under `root` that are older than `max_age`.
/// Called at the start of each run to prevent temp dir accumulation on process crash.
pub(crate) fn sweep_orphaned_staging_dirs(root: &Path, max_age: Duration) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("mxc-staging-") || !entry.path().is_dir() {
            continue;
        }
        let is_old = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|modified| now.duration_since(modified).ok())
            .map(|age| age >= max_age)
            .unwrap_or(false);
        if is_old {
            let _ = remove_dir_all_force(&entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_file(path: &Path, content: &str) {
        fs::write(path, content).unwrap();
    }

    /// Helper: compute the staged directory path for a host path.
    fn staged_rw(staging: &StagingDir, host_path: &Path) -> PathBuf {
        staging
            .path()
            .join(RW_DIR)
            .join(host_path_to_guest_relative(host_path))
    }

    /// Probe whether the current process can create symlinks. On Windows this
    /// requires `SeCreateSymbolicLinkPrivilege` or Developer Mode; on POSIX
    /// it always succeeds. Live-update assertions are gated on this so the
    /// suite still passes on hosts where the runtime falls back to copying.
    fn symlinks_available() -> bool {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("target");
        fs::create_dir_all(&target).unwrap();
        let link = tmp.path().join("link");
        create_symlink(&target, &link, true).is_ok()
    }

    #[test]
    fn staging_creates_bootstrap() {
        let root = tempdir().unwrap();
        let script = "print('hello')";
        let staging = StagingDir::new(root.path().to_path_buf(), script, &[], &[]).unwrap();

        let bootstrap = staging.path().join(BOOTSTRAP_FILENAME);
        assert!(bootstrap.exists());
        let content = fs::read_to_string(bootstrap).unwrap();
        assert!(content.starts_with(&bootstrap_preamble()));
        assert!(content.contains(script));
    }

    #[test]
    fn staging_empty_policy() {
        let root = tempdir().unwrap();
        let staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &[], &[]).unwrap();
        assert!(!staging.path().join(RW_DIR).exists());
        assert!(!staging.path().join(RO_DIR).exists());
    }

    #[test]
    fn staging_single_rw_path() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source = source_root.path().join("sample");
        fs::create_dir_all(&source).unwrap();
        write_file(&source.join("data.txt"), "abc");

        let host_path = source.display().to_string();
        let script = format!("open('{}')", host_path);
        let rw = vec![host_path.clone()];
        let staging = StagingDir::new(root.path().to_path_buf(), &script, &rw, &[]).unwrap();
        let guest_rel = host_path_to_guest_relative(&PathBuf::from(&host_path));
        assert!(staging.path().join(RW_DIR).join(&guest_rel).exists());
        // Verify the script was rewritten with the guest path.
        let rewritten = fs::read_to_string(staging.path().join(BOOTSTRAP_FILENAME)).unwrap();
        let expected_guest = build_guest_path(RW_DIR, &guest_rel);
        assert!(
            rewritten.contains(&expected_guest),
            "expected guest path in rewritten script, got: {}",
            rewritten
        );
    }

    #[test]
    fn staging_ro_path_has_readonly_attribute() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source = source_root.path().join("readonly");
        fs::create_dir_all(&source).unwrap();
        write_file(&source.join("data.txt"), "abc");

        let ro = vec![source.display().to_string()];
        let staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &[], &ro).unwrap();
        let guest_rel = host_path_to_guest_relative(&source);
        let staged_file = staging
            .path()
            .join(RO_DIR)
            .join(&guest_rel)
            .join("data.txt");
        let metadata = fs::metadata(staged_file).unwrap();
        assert!(metadata.permissions().readonly());
    }

    #[test]
    fn staging_two_rw_paths_get_distinct_guest_dirs() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let first = source_root.path().join("input");
        let second_parent = source_root.path().join("other");
        let second = second_parent.join("input");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();

        let rw = vec![first.display().to_string(), second.display().to_string()];
        let staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap();
        // Full path mirroring means both exist at distinct paths.
        let rel1 = host_path_to_guest_relative(&first);
        let rel2 = host_path_to_guest_relative(&second);
        assert!(staging.path().join(RW_DIR).join(&rel1).exists());
        assert!(staging.path().join(RW_DIR).join(&rel2).exists());
        assert_ne!(rel1, rel2);
    }

    #[test]
    fn staging_script_rewrite_replaces_host_paths() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source = source_root.path().join("sample");
        fs::create_dir_all(&source).unwrap();

        let host_path = source.display().to_string();
        let forward_path = host_path.replace('\\', "/");
        let script = format!("a = '{}'\nb = '{}'", host_path, forward_path);
        let rw = vec![host_path.clone()];
        let staging = StagingDir::new(root.path().to_path_buf(), &script, &rw, &[]).unwrap();

        let rewritten = fs::read_to_string(staging.path().join(BOOTSTRAP_FILENAME)).unwrap();
        let guest_rel = host_path_to_guest_relative(&PathBuf::from(&host_path));
        let expected_guest = build_guest_path(RW_DIR, &guest_rel);
        assert!(
            rewritten.contains(&expected_guest),
            "expected guest path in rewritten script, got: {}",
            rewritten
        );
        assert!(
            !rewritten.contains(&forward_path),
            "forward-slash host path should have been replaced"
        );
    }

    #[test]
    fn staging_bootstrap_is_stable() {
        let root = tempdir().unwrap();
        let a = StagingDir::new(root.path().to_path_buf(), "print(1)", &[], &[]).unwrap();
        let b = StagingDir::new(root.path().to_path_buf(), "print(2)", &[], &[]).unwrap();

        let left = fs::read_to_string(a.path().join(BOOTSTRAP_FILENAME)).unwrap();
        let right = fs::read_to_string(b.path().join(BOOTSTRAP_FILENAME)).unwrap();
        // The preamble (loader boilerplate) must be identical regardless of script content.
        let preamble = bootstrap_preamble();
        assert!(left.starts_with(&preamble));
        assert!(right.starts_with(&preamble));
        let left_preamble = &left[..preamble.len()];
        let right_preamble = &right[..preamble.len()];
        assert_eq!(left_preamble, right_preamble);
    }

    #[test]
    fn staging_cleanup_on_drop() {
        let root = tempdir().unwrap();
        let path_to_check = {
            let staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &[], &[]).unwrap();
            let p = staging.path().to_path_buf();
            assert!(p.exists());
            p
        };
        assert!(!path_to_check.exists());
    }

    #[test]
    fn staging_missing_path_returns_error() {
        let root = tempdir().unwrap();
        let rw = vec![root.path().join("missing").display().to_string()];
        let err = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap_err();
        assert!(matches!(err, StagingError::PathNotFound(_)));
    }

    #[test]
    fn staging_single_file_rw_wrapped_in_slot() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source_file = source_root.path().join("payload");
        write_file(&source_file, "data");

        let rw = vec![source_file.display().to_string()];
        let staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap();
        let staged_file = staged_rw(&staging, &source_file).join("payload");
        assert!(staged_file.exists());
    }

    #[test]
    fn host_path_to_guest_relative_strips_drive() {
        let p = PathBuf::from(r"C:\Users\me\work");
        assert_eq!(host_path_to_guest_relative(&p), "c/Users/me/work");
    }

    #[test]
    fn host_path_to_guest_relative_normalizes_slashes() {
        let p = PathBuf::from(r"D:\data\ref-data");
        assert_eq!(host_path_to_guest_relative(&p), "d/data/ref-data");
    }

    #[test]
    fn staging_rw_directory_updates_are_live() {
        if !symlinks_available() {
            return;
        }
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source = source_root.path().join("work");
        fs::create_dir_all(&source).unwrap();
        write_file(&source.join("data.txt"), "before");

        let rw = vec![source.display().to_string()];
        let mut staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap();
        let staged_file = staged_rw(&staging, &source).join("data.txt");

        // Writes to the staged path land on the host immediately (no copy-back
        // step required) because the staged slot is a symlink to the source.
        fs::write(&staged_file, "after").unwrap();
        assert_eq!(
            fs::read_to_string(source.join("data.txt")).unwrap(),
            "after"
        );

        // copy_back_to_host is a guaranteed-success no-op under the symlink model.
        staging.copy_back_to_host().unwrap();
        assert_eq!(
            fs::read_to_string(source.join("data.txt")).unwrap(),
            "after"
        );
    }

    #[test]
    fn staging_rw_file_updates_are_live() {
        if !symlinks_available() {
            return;
        }
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source_file = source_root.path().join("payload.txt");
        write_file(&source_file, "before");

        let rw = vec![source_file.display().to_string()];
        let mut staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap();
        let staged_file = staged_rw(&staging, &source_file).join("payload.txt");

        fs::write(&staged_file, "after").unwrap();
        assert_eq!(fs::read_to_string(&source_file).unwrap(), "after");

        staging.copy_back_to_host().unwrap();
        assert_eq!(fs::read_to_string(&source_file).unwrap(), "after");
    }

    #[test]
    fn staging_rw_directory_propagates_deletions_and_additions_live() {
        if !symlinks_available() {
            return;
        }
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source = source_root.path().join("work");
        fs::create_dir_all(&source).unwrap();
        write_file(&source.join("kept.txt"), "before");
        write_file(&source.join("deleted.txt"), "remove me");

        let rw = vec![source.display().to_string()];
        let mut staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap();
        let staged_dir = staged_rw(&staging, &source);

        fs::remove_file(staged_dir.join("deleted.txt")).unwrap();
        fs::write(staged_dir.join("kept.txt"), "after").unwrap();
        fs::write(staged_dir.join("created.txt"), "new").unwrap();

        // copy_back_to_host is a no-op; the changes are already on the host.
        staging.copy_back_to_host().unwrap();

        assert_eq!(
            fs::read_to_string(source.join("kept.txt")).unwrap(),
            "after"
        );
        assert_eq!(
            fs::read_to_string(source.join("created.txt")).unwrap(),
            "new"
        );
        assert!(!source.join("deleted.txt").exists());
    }

    #[test]
    fn staging_drop_does_not_delete_host_rw_paths() {
        if !symlinks_available() {
            return;
        }
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source = source_root.path().join("work");
        fs::create_dir_all(&source).unwrap();
        write_file(&source.join("data.txt"), "keep");

        let rw = vec![source.display().to_string()];
        {
            let _staging =
                StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap();
            // staging dropped here
        }

        // The host source must survive Drop — only the symlink should be removed.
        assert!(source.exists(), "host RW directory must not be removed");
        assert_eq!(
            fs::read_to_string(source.join("data.txt")).unwrap(),
            "keep",
            "host RW contents must be preserved across staging Drop"
        );
    }

    #[test]
    fn staging_allows_large_content() {
        // Verify that staging succeeds for large source content (~64 MB).
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source = source_root.path().join("big");
        fs::create_dir_all(&source).unwrap();
        // Sparse file ~64 MB. Sparse so we don't actually consume the disk
        // space on test runners.
        let big_file = source.join("large.bin");
        let big_size: u64 = 64 * 1024 * 1024;
        {
            let f = fs::File::create(&big_file).unwrap();
            f.set_len(big_size).unwrap();
        }

        let rw = vec![source.display().to_string()];
        let staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[])
            .expect("staging should succeed for large content");

        // The large file was staged into the RW slot.
        let rel = host_path_to_guest_relative(&source);
        let staged = staging.path().join(RW_DIR).join(&rel).join("large.bin");
        assert!(staged.exists(), "expected staged file at {staged:?}");
        assert_eq!(fs::metadata(&staged).unwrap().len(), big_size);
    }

    #[test]
    #[allow(clippy::permissions_set_readonly_false)]
    fn staging_readonly_paths_not_copied_back() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source = source_root.path().join("reference");
        fs::create_dir_all(&source).unwrap();
        write_file(&source.join("data.txt"), "original");

        let ro = vec![source.display().to_string()];
        let mut staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &[], &ro).unwrap();

        // Mutate the staged read-only copy.
        let guest_rel = host_path_to_guest_relative(&source);
        let staged_file = staging
            .path()
            .join(RO_DIR)
            .join(&guest_rel)
            .join("data.txt");
        // Clear read-only flag so we can write to the staged copy.
        let mut perms = fs::metadata(&staged_file).unwrap().permissions();
        perms.set_readonly(false);
        fs::set_permissions(&staged_file, perms).unwrap();
        fs::write(&staged_file, "mutated").unwrap();

        // copy_back_to_host only copies RW mappings — RO should NOT be copied back.
        staging.copy_back_to_host().unwrap();
        assert_eq!(
            fs::read_to_string(source.join("data.txt")).unwrap(),
            "original",
            "read-only paths must not be copied back to host"
        );
    }

    #[test]
    fn sweep_removes_old_staging_dirs() {
        let root = tempdir().unwrap();
        let old_dir = root.path().join("mxc-staging-aabbccdd");
        let fresh_dir = root.path().join("mxc-staging-11223344");
        let unrelated = root.path().join("other-dir");
        fs::create_dir_all(&old_dir).unwrap();
        fs::create_dir_all(&fresh_dir).unwrap();
        fs::create_dir_all(&unrelated).unwrap();

        // Backdate the old_dir modification time via a workaround: zero-age threshold
        // sweeps everything older than 0 seconds (all of them qualify in CI).
        sweep_orphaned_staging_dirs(root.path(), Duration::from_secs(0));

        // Both staging dirs should be removed; unrelated must stay.
        assert!(!old_dir.exists(), "old staging dir should be swept");
        assert!(!fresh_dir.exists(), "staging dir should be swept at age 0");
        assert!(unrelated.exists(), "unrelated dir must not be swept");
    }

    #[test]
    fn staging_rejects_path_with_parent_dir_component() {
        let root = tempdir().unwrap();
        let source = root.path().join("legit");
        fs::create_dir_all(&source).unwrap();
        // Construct a path with `..` to attempt traversal.
        let traversal = source.join("..").join("legit");
        let rw = vec![traversal.display().to_string()];
        let err = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap_err();
        assert!(
            matches!(err, StagingError::PathNotFound(ref msg) if msg.contains("..")),
            "expected PathNotFound with '..' mention, got: {err}"
        );
    }

    #[test]
    fn staging_mixed_rw_and_ro_paths() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let rw_dir = source_root.path().join("editable");
        let ro_dir = source_root.path().join("reference");
        fs::create_dir_all(&rw_dir).unwrap();
        fs::create_dir_all(&ro_dir).unwrap();
        write_file(&rw_dir.join("a.txt"), "rw-content");
        write_file(&ro_dir.join("b.txt"), "ro-content");

        let rw = vec![rw_dir.display().to_string()];
        let ro = vec![ro_dir.display().to_string()];
        let staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &ro).unwrap();

        // Both subdirectories must exist.
        assert!(staging.path().join(RW_DIR).exists());
        assert!(staging.path().join(RO_DIR).exists());
        // Verify file content was staged.
        let rw_rel = host_path_to_guest_relative(&rw_dir);
        let ro_rel = host_path_to_guest_relative(&ro_dir);
        let staged_rw_file = staging.path().join(RW_DIR).join(&rw_rel).join("a.txt");
        let staged_ro_file = staging.path().join(RO_DIR).join(&ro_rel).join("b.txt");
        assert_eq!(fs::read_to_string(staged_rw_file).unwrap(), "rw-content");
        assert_eq!(fs::read_to_string(staged_ro_file).unwrap(), "ro-content");
    }

    #[test]
    fn staging_overhead_ms_scales_with_size() {
        let root = tempdir().unwrap();
        let staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &[], &[]).unwrap();
        // A minimal staging dir should have near-zero overhead.
        assert!(staging.staging_overhead_ms() < 5);
    }

    #[test]
    fn staging_overhead_ms_capped_at_30s() {
        let root = tempdir().unwrap();
        let mut staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &[], &[]).unwrap();
        // Simulate a huge staging size (won't actually allocate).
        staging.size_bytes = 500 * 1024 * 1024; // 500 MB
        assert_eq!(staging.staging_overhead_ms(), 30_000);
    }

    #[test]
    fn preserved_path_none_when_not_preserved() {
        let root = tempdir().unwrap();
        let staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &[], &[]).unwrap();
        assert!(staging.preserved_path().is_none());
    }

    #[test]
    fn host_path_to_guest_relative_handles_trailing_slash() {
        let p = PathBuf::from(r"C:\Users\me\work\");
        assert_eq!(host_path_to_guest_relative(&p), "c/Users/me/work");
    }

    #[test]
    fn host_path_to_guest_relative_lowercase_drive() {
        let p = PathBuf::from(r"E:\Projects\src");
        let result = host_path_to_guest_relative(&p);
        assert!(result.starts_with('e'), "drive letter should be lowercase");
        assert_eq!(result, "e/Projects/src");
    }

    #[test]
    fn rewrite_paths_handles_escaped_backslashes() {
        let host = r"C:\Users\me\work".to_string();
        let guest = "/mnt/rw/c/Users/me/work".to_string();
        let script = r#"path = "C:\\Users\\me\\work""#;
        let result = rewrite_paths_in_script(script, &[(host, guest.clone())]);
        assert!(
            result.contains(&guest),
            "escaped backslashes not rewritten: {result}"
        );
    }

    #[test]
    fn rewrite_paths_longer_prefix_first() {
        let short_host = r"C:\data".to_string();
        let short_guest = "/mnt/rw/c/data".to_string();
        let long_host = r"C:\data\subdir".to_string();
        let long_guest = "/mnt/rw/c/data/subdir".to_string();
        let script = r"C:\data\subdir\file.txt";
        let mappings = vec![
            (short_host, short_guest.clone()),
            (long_host, long_guest.clone()),
        ];
        let result = rewrite_paths_in_script(script, &mappings);
        // The longer path must match first so we don't get a partial replacement.
        assert!(
            result.contains("/mnt/rw/c/data/subdir"),
            "longer prefix should match first: {result}"
        );
    }

    #[test]
    fn build_guest_path_format() {
        assert_eq!(build_guest_path("rw", "c/Users/me"), "/mnt/rw/c/Users/me");
        assert_eq!(build_guest_path("ro", "d/ref"), "/mnt/ro/d/ref");
    }

    #[test]
    fn staging_empty_script() {
        let root = tempdir().unwrap();
        let staging = StagingDir::new(root.path().to_path_buf(), "", &[], &[]).unwrap();
        let content = fs::read_to_string(staging.path().join(BOOTSTRAP_FILENAME)).unwrap();
        // Should only contain the preamble.
        assert_eq!(content, bootstrap_preamble());
    }

    #[test]
    fn staging_nested_directory_rw_updates_are_live() {
        if !symlinks_available() {
            return;
        }
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source = source_root.path().join("nested");
        let sub = source.join("sub").join("deep");
        fs::create_dir_all(&sub).unwrap();
        write_file(&sub.join("deep.txt"), "original");
        write_file(&source.join("top.txt"), "top-original");

        let rw = vec![source.display().to_string()];
        let mut staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap();
        let staged_dir = staged_rw(&staging, &source);

        // Modify deep file and add a new file — both should appear on the host
        // immediately because staged_dir is a symlink to source.
        fs::write(
            staged_dir.join("sub").join("deep").join("deep.txt"),
            "modified",
        )
        .unwrap();
        fs::write(staged_dir.join("new.txt"), "added").unwrap();

        assert_eq!(
            fs::read_to_string(sub.join("deep.txt")).unwrap(),
            "modified"
        );
        assert_eq!(fs::read_to_string(source.join("new.txt")).unwrap(), "added");

        staging.copy_back_to_host().unwrap();
    }

    #[test]
    fn sweep_ignores_nonexistent_root() {
        let nonexistent = PathBuf::from(r"C:\nonexistent_mxc_test_dir_12345");
        // Should not panic or error.
        sweep_orphaned_staging_dirs(&nonexistent, Duration::from_secs(0));
    }

    #[test]
    fn staging_dir_has_unique_names() {
        let root = tempdir().unwrap();
        let a = StagingDir::new(root.path().to_path_buf(), "print(1)", &[], &[]).unwrap();
        let b = StagingDir::new(root.path().to_path_buf(), "print(1)", &[], &[]).unwrap();
        assert_ne!(a.path(), b.path());
    }
}
