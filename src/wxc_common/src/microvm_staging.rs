// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MicroVM staging directory builder for mount-based script delivery.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use thiserror::Error;
use uuid::Uuid;

/// Maximum allowed total staging directory size (16 MB).
pub const MAX_STAGING_BYTES: u64 = 16 * 1024 * 1024;
/// Bootstrap Python loader filename.
pub const BOOTSTRAP_FILENAME: &str = ".mxc-bootstrap.py";
/// User script filename in staging.
pub const SCRIPT_FILENAME: &str = ".mxc-script.py";
/// Path map JSON filename in staging.
pub const PATHMAP_FILENAME: &str = ".mxc-pathmap.json";
/// Subdirectory for read-write staged host paths.
pub const RW_DIR: &str = "rw";
/// Subdirectory for read-only staged host paths.
pub const RO_DIR: &str = "ro";
/// Maximum slug length in characters to avoid exceeding MAX_PATH in the staging hierarchy.
const MAX_SLUG_CHARS: usize = 80;
/// Bootstrap Python source used by the guest runtime.
pub(crate) const BOOTSTRAP_SOURCE: &str = "import json, os, sys
with open('/mnt/.mxc-pathmap.json') as f:
    for slug, guest_path in json.load(f).items():
        os.environ[f'MXC_PATH_{slug}'] = guest_path
sys.argv = ['/mnt/.mxc-script.py']
with open(sys.argv[0]) as _f:
    exec(compile(_f.read(), sys.argv[0], 'exec'), {'__name__': '__main__', '__file__': sys.argv[0]})
";

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

/// Return type of the staging build closure.
type StagingBuildResult = Result<(BTreeMap<String, String>, Vec<RwMapping>, u64), StagingError>;

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
    path_map: BTreeMap<String, String>,
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
            fs::write(path.join(BOOTSTRAP_FILENAME), BOOTSTRAP_SOURCE)?;
            fs::write(path.join(SCRIPT_FILENAME), script)?;

            let mut used_env_keys: Vec<String> = Vec::new();
            let mut path_map: BTreeMap<String, String> = BTreeMap::new();
            let mut rw_mappings: Vec<RwMapping> = Vec::new();

            if !readwrite_paths.is_empty() {
                fs::create_dir_all(path.join(RW_DIR))?;
            }
            for source in readwrite_paths {
                let host_path = PathBuf::from(source);
                validate_source_path(&host_path, source)?;

                let slug = allocate_slug(&host_path, &mut used_env_keys);
                let slot_dir = path.join(RW_DIR).join(&slug);
                let kind = stage_host_path(&host_path, &slot_dir)?;
                path_map.insert(slug_to_env_key(&slug), format!("/mnt/{}/{}", RW_DIR, slug));
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

                let slug = allocate_slug(&host_path, &mut used_env_keys);
                let slot_dir = path.join(RO_DIR).join(&slug);
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
                path_map.insert(slug_to_env_key(&slug), format!("/mnt/{}/{}", RO_DIR, slug));
            }

            let serialized = serde_json::to_string(&path_map).map_err(|e| {
                StagingError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;
            fs::write(path.join(PATHMAP_FILENAME), serialized)?;

            let size_bytes = dir_size(&path)?;
            if size_bytes > MAX_STAGING_BYTES {
                return Err(StagingError::SizeCapExceeded {
                    actual_mb: size_bytes as f64 / (1024.0 * 1024.0),
                    limit_mb: MAX_STAGING_BYTES as f64 / (1024.0 * 1024.0),
                });
            }

            Ok((path_map, rw_mappings, size_bytes))
        }();

        let (path_map, rw_mappings, size_bytes) = match build_result {
            Ok(result) => result,
            Err(err) => {
                let _ = remove_dir_all_force(&path);
                return Err(err);
            }
        };

        Ok(Self {
            path,
            path_map,
            rw_mappings,
            size_bytes,
            preserve: false,
        })
    }

    /// Returns the host path to the staging directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the host-path slug to guest-path map.
    pub fn path_map(&self) -> &BTreeMap<String, String> {
        &self.path_map
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

/// Allocates a unique guest path slug whose derived env key is also unique.
fn allocate_slug(host_path: &Path, used_env_keys: &mut Vec<String>) -> String {
    let raw_base = host_path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("path")
        .to_ascii_lowercase()
        .replace('-', "_");

    let base = sanitize_slug(&raw_base);
    let mut counter = 1_u64;

    loop {
        let candidate = if counter == 1 {
            base.clone()
        } else {
            format!("{}_{}", base, counter)
        };
        let env_key = slug_to_env_key(&candidate);
        if !used_env_keys.iter().any(|key| key == &env_key) {
            used_env_keys.push(env_key);
            return candidate;
        }
        counter += 1;
    }
}

fn sanitize_slug(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => ch.to_ascii_lowercase(),
            _ => '_',
        })
        .collect();

    let trimmed = sanitized.trim_matches('_');
    let capped = if trimmed.len() > MAX_SLUG_CHARS {
        &trimmed[..MAX_SLUG_CHARS]
    } else {
        trimmed
    };
    // Re-trim in case the cap landed on a trailing underscore.
    let final_slug = capped.trim_end_matches('_');
    if final_slug.is_empty() {
        "path".to_string()
    } else {
        final_slug.to_string()
    }
}

/// Converts a slug to an upper snake case environment key suffix.
pub(crate) fn slug_to_env_key(slug: &str) -> String {
    slug.chars()
        .map(|ch| match ch {
            'a'..='z' => ch.to_ascii_uppercase(),
            'A'..='Z' | '0'..='9' => ch,
            _ => '_',
        })
        .collect()
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
        let ft = entry.metadata()?.file_type();
        if ft.is_symlink() {
            return Err(StagingError::SymlinkFound(
                entry.path().display().to_string(),
            ));
        }
        let target = dst.join(entry.file_name());
        if ft.is_dir() {
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
        if !p.exists() {
            return Err(StagingError::PathNotFound(s.clone()));
        }
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

    #[test]
    fn staging_creates_bootstrap_and_script() {
        let root = tempdir().unwrap();
        let script = "print('hello')";
        let staging = StagingDir::new(root.path().to_path_buf(), script, &[], &[]).unwrap();

        let bootstrap = staging.path().join(BOOTSTRAP_FILENAME);
        let script_path = staging.path().join(SCRIPT_FILENAME);
        assert!(bootstrap.exists());
        assert!(script_path.exists());
        assert_eq!(fs::read_to_string(script_path).unwrap(), script);
    }

    #[test]
    fn staging_empty_policy() {
        let root = tempdir().unwrap();
        let staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &[], &[]).unwrap();
        assert!(!staging.path().join(RW_DIR).exists());
        assert!(!staging.path().join(RO_DIR).exists());
        assert!(staging.path_map().is_empty());
    }

    #[test]
    fn staging_single_rw_path() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source = source_root.path().join("sample");
        fs::create_dir_all(&source).unwrap();
        write_file(&source.join("data.txt"), "abc");

        let rw = vec![source.display().to_string()];
        let staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap();
        assert!(staging.path().join(RW_DIR).join("sample").exists());
        assert_eq!(
            staging.path_map().get("SAMPLE").map(String::as_str),
            Some("/mnt/rw/sample")
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
        let staged_file = staging
            .path()
            .join(RO_DIR)
            .join("readonly")
            .join("data.txt");
        let metadata = fs::metadata(staged_file).unwrap();
        assert!(metadata.permissions().readonly());
    }

    #[test]
    fn staging_slug_collision() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let first = source_root.path().join("input");
        let second_parent = source_root.path().join("other");
        let second = second_parent.join("input");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();

        let rw = vec![first.display().to_string(), second.display().to_string()];
        let staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap();
        assert!(staging.path_map().contains_key("INPUT"));
        assert!(staging.path_map().contains_key("INPUT_2"));
    }

    #[test]
    fn staging_pathmap_json_shape() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let source = source_root.path().join("sample");
        fs::create_dir_all(&source).unwrap();

        let rw = vec![source.display().to_string()];
        let staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap();

        let json = fs::read_to_string(staging.path().join(PATHMAP_FILENAME)).unwrap();
        let parsed: BTreeMap<String, String> = serde_json::from_str(&json).unwrap();
        assert!(parsed.contains_key("SAMPLE"));
        assert_eq!(parsed, *staging.path_map());
    }

    #[test]
    fn staging_bootstrap_is_stable() {
        let root = tempdir().unwrap();
        let a = StagingDir::new(root.path().to_path_buf(), "print(1)", &[], &[]).unwrap();
        let b = StagingDir::new(root.path().to_path_buf(), "print(2)", &[], &[]).unwrap();

        let left = fs::read_to_string(a.path().join(BOOTSTRAP_FILENAME)).unwrap();
        let right = fs::read_to_string(b.path().join(BOOTSTRAP_FILENAME)).unwrap();
        assert_eq!(left, right);
        assert_eq!(left, BOOTSTRAP_SOURCE);
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
        // File "payload" has no extension, slug stays "payload"
        let staged_file = staging.path().join(RW_DIR).join("payload").join("payload");
        assert!(staged_file.exists());
    }

    #[test]
    fn slug_generation_dash_to_underscore() {
        let root = tempdir().unwrap();
        let source = root.path().join("ref-data");
        fs::create_dir_all(&source).unwrap();

        let mut used_keys = Vec::new();
        let slug = allocate_slug(&source, &mut used_keys);
        assert_eq!(slug, "ref_data");
        assert_eq!(slug_to_env_key(&slug), "REF_DATA");
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
        let staged_file = staging.path().join(RW_DIR).join("work").join("data.txt");

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
        // slug for "payload.txt" is "payload_txt" (dot sanitized to underscore)
        let staged_file = staging
            .path()
            .join(RW_DIR)
            .join("payload_txt")
            .join("payload.txt");

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
        let staged_dir = staging.path().join(RW_DIR).join("work");

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
    fn staging_env_key_collision_is_disambiguated() {
        let root = tempdir().unwrap();
        let source_root = tempdir().unwrap();
        let first = source_root.path().join("foo-bar");
        let second = source_root.path().join("foo bar");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();

        let rw = vec![first.display().to_string(), second.display().to_string()];
        let staging = StagingDir::new(root.path().to_path_buf(), "print(1)", &rw, &[]).unwrap();

        assert!(staging.path_map().contains_key("FOO_BAR"));
        assert!(staging.path_map().contains_key("FOO_BAR_2"));
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
        let staged_file = staging
            .path()
            .join(RO_DIR)
            .join("reference")
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
    fn sanitize_slug_caps_at_max_slug_chars() {
        let long_name = "a".repeat(MAX_SLUG_CHARS + 20);
        let slug = sanitize_slug(&long_name);
        assert!(
            slug.len() <= MAX_SLUG_CHARS,
            "slug length {} exceeds MAX_SLUG_CHARS {}",
            slug.len(),
            MAX_SLUG_CHARS
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
