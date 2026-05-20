// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MicroVM staging directory builder for mount-based script delivery.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use thiserror::Error;
use uuid::Uuid;

/// Maximum allowed total staging directory size (16 MB).
pub const MAX_STAGING_BYTES: u64 = 16 * 1024 * 1024;
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
const BOOTSTRAP_PREAMBLE: &str = "import sys\nsys.argv = ['/mnt/bootstrap.py']\n";

/// Errors produced while creating or validating a staging directory.
#[derive(Debug, Error)]
pub enum StagingError {
    /// A requested host path does not exist.
    #[error("host path does not exist: {0}")]
    PathNotFound(String),
    /// Total staged content exceeded the configured cap.
    #[error("staging size cap exceeded: {actual_mb:.2} MB > {limit_mb:.2} MB")]
    SizeCapExceeded { actual_mb: f64, limit_mb: f64 },
    /// A symlink was found in a source path.
    #[error("symlink found in source path: {0}")]
    SymlinkFound(String),
    /// I/O failure.
    #[error("staging I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Intermediate result from the staging build closure.
struct StagingBuildOutput {
    /// Read-write directory mappings for copyback.
    rw_mappings: Vec<RwMapping>,
    /// Total bytes written to the staging directory.
    size_bytes: u64,
}

/// Return type of the staging build closure.
type StagingBuildResult = Result<StagingBuildOutput, StagingError>;

/// Whether the original host path was a file or directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostPathKind {
    File,
    Directory,
}

/// Tracks the relationship between a host path, its staged copy, and its type.
#[derive(Debug)]
struct RwMapping {
    host_path: PathBuf,
    staged_path: PathBuf,
    kind: HostPathKind,
}

/// RAII wrapper over a temporary staging directory.
#[derive(Debug)]
pub struct StagingDir {
    path: PathBuf,
    rw_mappings: Vec<RwMapping>,
    size_bytes: u64,
    /// When true, `Drop` skips cleanup so the staging dir can be recovered.
    preserve: bool,
}

impl StagingDir {
    /// Creates and populates a staging directory under `root`.
    pub fn new(
        root: PathBuf,
        script: &str,
        readwrite_paths: &[String],
        readonly_paths: &[String],
    ) -> Result<Self, StagingError> {
        // Pre-flight size estimate — fail fast before writing anything.
        let estimated = estimate_source_size(readwrite_paths)?
            .saturating_add(estimate_source_size(readonly_paths)?);
        if estimated > MAX_STAGING_BYTES {
            return Err(StagingError::SizeCapExceeded {
                actual_mb: estimated as f64 / (1024.0 * 1024.0),
                limit_mb: MAX_STAGING_BYTES as f64 / (1024.0 * 1024.0),
            });
        }

        fs::create_dir_all(&root)?;
        let path = root.join(format!("mxc-staging-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&path)?;

        let build_result = || -> StagingBuildResult {
            // Collect host→guest path mappings for script rewriting.
            let mut rewrite_map: Vec<(String, String)> = Vec::new();
            let mut rw_mappings: Vec<RwMapping> = Vec::new();

            if !readwrite_paths.is_empty() {
                fs::create_dir_all(path.join(RW_DIR))?;
            }
            for source in readwrite_paths {
                let host_path = PathBuf::from(source);
                validate_source_path(&host_path, source)?;

                let relative = host_path_to_guest_relative(&host_path);
                let slot_dir = path.join(RW_DIR).join(&relative);
                let kind = stage_host_path(&host_path, &slot_dir)?;
                let guest_path = build_guest_path(RW_DIR, &relative);
                rewrite_map.push((source.clone(), guest_path));
                rw_mappings.push(RwMapping {
                    host_path,
                    staged_path: slot_dir,
                    kind,
                });
            }

            if !readonly_paths.is_empty() {
                fs::create_dir_all(path.join(RO_DIR))?;
            }
            for source in readonly_paths {
                let host_path = PathBuf::from(source);
                validate_source_path(&host_path, source)?;

                let relative = host_path_to_guest_relative(&host_path);
                let slot_dir = path.join(RO_DIR).join(&relative);
                if host_path.is_dir() {
                    copy_dir_recursive(&host_path, &slot_dir)?;
                } else {
                    fs::create_dir_all(&slot_dir)?;
                    let file_name = host_path
                        .file_name()
                        .ok_or_else(|| StagingError::PathNotFound(source.clone()))?;
                    fs::copy(&host_path, slot_dir.join(file_name))?;
                }
                set_readonly_recursive(&slot_dir)?;
                let guest_path = build_guest_path(RO_DIR, &relative);
                rewrite_map.push((source.clone(), guest_path));
            }

            // Rewrite host paths in the user script so callers don't need to
            // know about the guest mount layout. Both backslash and forward-slash
            // variants of each host path are replaced.
            let rewritten_script = rewrite_paths_in_script(script, &rewrite_map);
            let bootstrap_content = format!("{}{}", BOOTSTRAP_PREAMBLE, rewritten_script);
            fs::write(path.join(BOOTSTRAP_FILENAME), &bootstrap_content)?;

            let size_bytes = dir_size(&path)?;
            if size_bytes > MAX_STAGING_BYTES {
                return Err(StagingError::SizeCapExceeded {
                    actual_mb: size_bytes as f64 / (1024.0 * 1024.0),
                    limit_mb: MAX_STAGING_BYTES as f64 / (1024.0 * 1024.0),
                });
            }

            Ok(StagingBuildOutput {
                rw_mappings,
                size_bytes,
            })
        }();

        let StagingBuildOutput {
            rw_mappings,
            size_bytes,
        } = match build_result {
            Ok(result) => result,
            Err(err) => {
                let _ = remove_dir_all_force(&path);
                return Err(err);
            }
        };

        Ok(Self {
            path,
            rw_mappings,
            size_bytes,
            preserve: false,
        })
    }

    /// Returns the host path to the staging directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Copies all read-write staged paths back to their original host locations.
    /// Attempts all mappings even if one fails; returns the first error encountered.
    /// On any failure, marks the staging dir as preserved so `Drop` won't delete it.
    pub fn copy_back_to_host(&mut self) -> Result<(), StagingError> {
        let mut first_err: Option<StagingError> = None;
        // Preserve before starting — if any copy fails, staging must survive Drop.
        self.preserve = true;
        for mapping in &self.rw_mappings {
            if let Err(e) = copy_back_mapping(mapping) {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        if first_err.is_none() {
            // All copies succeeded — allow normal cleanup on Drop.
            self.preserve = false;
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Returns the staging directory path (useful for recovery messages).
    pub fn preserved_path(&self) -> Option<&Path> {
        if self.preserve {
            Some(&self.path)
        } else {
            None
        }
    }

    /// Returns additional staging overhead in milliseconds.
    pub fn staging_overhead_ms(&self) -> u64 {
        let ms = ((self.size_bytes as f64 / (1024.0 * 1024.0)) * 100.0) as u64;
        ms.min(30_000)
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        if self.preserve {
            return;
        }
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

/// Stages a single host path in a target slot directory using a private copy.
fn stage_host_path(host_path: &Path, slot_dir: &Path) -> Result<HostPathKind, StagingError> {
    if host_path.is_dir() {
        copy_dir_recursive(host_path, slot_dir)?;
        return Ok(HostPathKind::Directory);
    }

    fs::create_dir_all(slot_dir)?;
    let file_name = host_path
        .file_name()
        .ok_or_else(|| StagingError::PathNotFound(host_path.display().to_string()))?;
    fs::copy(host_path, slot_dir.join(file_name))?;
    Ok(HostPathKind::File)
}

/// Copies staged RW content back to the original host path.
fn copy_back_mapping(mapping: &RwMapping) -> Result<(), StagingError> {
    match mapping.kind {
        HostPathKind::Directory => mirror_directory(&mapping.staged_path, &mapping.host_path),
        HostPathKind::File => {
            let file_name = mapping.host_path.file_name().ok_or_else(|| {
                StagingError::PathNotFound(mapping.host_path.display().to_string())
            })?;
            let staged_file = mapping.staged_path.join(file_name);
            fs::copy(staged_file, &mapping.host_path)?;
            Ok(())
        }
    }
}

/// Replaces the destination directory with the source directory contents.
/// Uses a rename-based backup to avoid permanent data loss if the copy fails mid-way.
fn mirror_directory(src: &Path, dst: &Path) -> Result<(), StagingError> {
    // Build a sibling backup path on the same volume as dst — rename is atomic.
    // Include the PID to avoid collision with stale backups from prior interrupted runs.
    let backup = dst.with_extension(format!("__mxc_bak_{}", std::process::id()));
    // Clean up any pre-existing backup with the same name (e.g. from a previous run
    // of this process that was interrupted between the rename and cleanup).
    if backup.exists() {
        let _ = remove_dir_all_force(&backup);
    }
    if dst.exists() {
        fs::rename(dst, &backup)?;
    }
    match copy_dir_recursive(src, dst) {
        Ok(()) => {
            // Copy succeeded — best-effort removal of the backup.
            if backup.exists() {
                let _ = remove_dir_all_force(&backup);
            }
            Ok(())
        }
        Err(e) => {
            // Copy failed — attempt to restore the backup to the original path.
            if backup.exists() {
                if dst.exists() {
                    let _ = remove_dir_all_force(dst);
                }
                let _ = fs::rename(&backup, dst);
            }
            Err(e)
        }
    }
}

/// Copies a directory recursively.
/// Uses `symlink_metadata` per entry to reject symlinks/reparse points during
/// traversal, closing the TOCTOU window between upfront validation and the actual copy.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), StagingError> {
    fs::create_dir_all(dst)?;
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
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
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

/// Validates that a source host path exists, has a filename, and contains no reparse points.
fn validate_source_path(path: &Path, original: &str) -> Result<(), StagingError> {
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
    check_no_reparse_points(path)
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
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
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
    if path.is_file() {
        let mut perms = fs::metadata(path)?.permissions();
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

/// Computes the recursive total size in bytes for all files in `path`.
fn dir_size(path: &Path) -> Result<u64, StagingError> {
    if path.is_file() {
        return Ok(fs::metadata(path)?.len());
    }

    let mut total = 0_u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            total = total.saturating_add(dir_size(&entry_path)?);
        } else {
            total = total.saturating_add(fs::metadata(entry_path)?.len());
        }
    }
    Ok(total)
}

/// Estimates the total on-disk size of a list of host paths without copying them.
/// Returns an error on the first path that cannot be sized, ensuring the preflight
/// check is deterministic and does not silently under-estimate.
fn estimate_source_size(paths: &[String]) -> Result<u64, StagingError> {
    let mut total = 0_u64;
    for s in paths {
        let p = Path::new(s);
        // Validate before sizing to avoid following symlinks/reparse points during traversal.
        validate_source_path(p, s)?;
        total = total.saturating_add(dir_size(p)?);
    }
    Ok(total)
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

    #[test]
    fn staging_creates_bootstrap() {
        let root = tempdir().unwrap();
        let script = "print('hello')";
        let staging = StagingDir::new(root.path().to_path_buf(), script, &[], &[]).unwrap();

        let bootstrap = staging.path().join(BOOTSTRAP_FILENAME);
        assert!(bootstrap.exists());
        let content = fs::read_to_string(bootstrap).unwrap();
        assert!(content.starts_with(BOOTSTRAP_PREAMBLE));
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
        assert!(left.starts_with(BOOTSTRAP_PREAMBLE));
        assert!(right.starts_with(BOOTSTRAP_PREAMBLE));
        let left_preamble = &left[..BOOTSTRAP_PREAMBLE.len()];
        let right_preamble = &right[..BOOTSTRAP_PREAMBLE.len()];
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
    fn staging_rw_directory_is_private_until_copyback() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source = source_root.path().join("work");
        fs::create_dir_all(&source).unwrap();
        write_file(&source.join("data.txt"), "before");

        let rw = vec![source.display().to_string()];
        let mut staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap();
        let staged_file = staged_rw(&staging, &source).join("data.txt");

        // Mutate the staged copy — original must remain unchanged.
        fs::write(&staged_file, "after").unwrap();
        assert_eq!(
            fs::read_to_string(source.join("data.txt")).unwrap(),
            "before"
        );

        // After explicit copyback, original should reflect the staged changes.
        staging.copy_back_to_host().unwrap();
        assert_eq!(
            fs::read_to_string(source.join("data.txt")).unwrap(),
            "after"
        );
    }

    #[test]
    fn staging_rw_file_copyback_updates_original_file() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source_file = source_root.path().join("payload.txt");
        write_file(&source_file, "before");

        let rw = vec![source_file.display().to_string()];
        let mut staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap();
        let staged_file = staged_rw(&staging, &source_file).join("payload.txt");

        fs::write(&staged_file, "after").unwrap();
        assert_eq!(fs::read_to_string(&source_file).unwrap(), "before");

        staging.copy_back_to_host().unwrap();
        assert_eq!(fs::read_to_string(&source_file).unwrap(), "after");
    }

    #[test]
    fn staging_rw_directory_copyback_mirrors_deletions() {
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
    fn staging_preserve_on_copyback_failure() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source = source_root.path().join("work");
        fs::create_dir_all(&source).unwrap();
        write_file(&source.join("data.txt"), "original");

        let rw = vec![source.display().to_string()];
        let mut staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap();
        let staging_path = staging.path().to_path_buf();

        // Delete the staged directory to make copyback fail.
        fs::remove_dir_all(staging.path().join(RW_DIR)).unwrap();

        let result = staging.copy_back_to_host();
        assert!(result.is_err(), "expected copyback error");

        // The staging dir must still exist (preserve=true) so the user can inspect it.
        assert!(
            staging_path.exists(),
            "staging dir must be preserved on copyback failure"
        );

        // The original host directory is unchanged.
        assert_eq!(
            fs::read_to_string(source.join("data.txt")).unwrap(),
            "original"
        );
    }

    #[test]
    fn staging_rejects_oversized_content() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source = source_root.path().join("big");
        fs::create_dir_all(&source).unwrap();
        // Sparse file exceeding MAX_STAGING_BYTES.
        let big_file = source.join("large.bin");
        {
            let f = fs::File::create(&big_file).unwrap();
            f.set_len(MAX_STAGING_BYTES + 1).unwrap();
        }

        let rw = vec![source.display().to_string()];
        let err = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap_err();
        assert!(
            matches!(err, StagingError::SizeCapExceeded { .. }),
            "expected SizeCapExceeded, got: {err}"
        );
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
}
