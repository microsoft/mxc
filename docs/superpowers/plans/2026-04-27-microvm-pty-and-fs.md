# MicroVM PTY Parity & Filesystem Policy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable microvm backend to support PTY input and filesystem policy (`readwrite_paths`/`readonly_paths`) by delivering scripts via nanvixd `-mount` instead of hijacking stdin.

**Architecture:** Build a per-request staging directory containing the user script, a bootstrap loader, and filesystem policy paths. Pass the staging directory to nanvixd via `-mount`. Switch stdin from `Stdio::piped()` to `Stdio::inherit()` so the ConPTY relay works end-to-end. The staging directory is managed by a RAII `StagingDir` type that auto-cleans on drop.

**Tech Stack:** Rust (wxc_common crate), serde_json, uuid, tempfile (dev-deps), Windows filesystem APIs for junction creation and FAT32 RO attribute.

**Spec:** `docs/superpowers/specs/2026-04-27-microvm-pty-and-fs-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `src/wxc_common/src/microvm_staging.rs` (NEW) | `StagingDir` RAII struct, staging tree builder, slug generation, RO attribute, path map JSON, size validation, bootstrap writer |
| `src/wxc_common/src/nanvix_runner.rs` (MODIFY) | Update `validate_policies` to accept RW/RO paths, reject `denied_paths`; update `spawn_nanvixd` to use `-mount` + `Stdio::inherit()`; update `build_guest_args`; update `total_timeout_ms`; update `run()` to create staging dir |
| `src/wxc_common/src/lib.rs` (MODIFY) | Add `pub mod microvm_staging;` |
| `src/wxc_common/Cargo.toml` (MODIFY) | Add `uuid` to runtime deps (already in workspace) |
| `test_configs/microvm_pty_input.json` (NEW) | Integration test: stdin/input() via PTY |
| `test_configs/microvm_rw_path.json` (NEW) | Integration test: readwrite_paths with copyback |
| `test_configs/microvm_ro_path.json` (NEW) | Integration test: readonly_paths with EACCES on write |
| `test_configs/microvm_denied_paths.json` (NEW) | Integration test: denied_paths rejection |
| `test_configs/microvm_no_fs_mount.json` (NEW) | Regression: empty FS policy still works with mount-based script delivery |
| `docs/microvm.md` (NEW) | User-facing documentation |
| `docs/nanvix-integration-plan.md` (MODIFY) | Update supported/unsupported tables |

---

### Task 1: Create `microvm_staging.rs` — StagingDir RAII and Bootstrap Writer

**Files:**
- Create: `src/wxc_common/src/microvm_staging.rs`

This task builds the foundational type — the `StagingDir` struct with `Drop` cleanup, and the bootstrap/script file writer. No slug or FS policy logic yet.

- [ ] **Step 1: Write the failing test — staging dir creates bootstrap + script files**

Add to the bottom of `src/wxc_common/src/microvm_staging.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_creates_bootstrap_and_script() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = StagingDir::new(
            tmp.path().to_path_buf(),
            "print('hello')",
            &[],
            &[],
        )
        .unwrap();

        assert!(staging.path().join(BOOTSTRAP_FILENAME).exists());
        assert!(staging.path().join(SCRIPT_FILENAME).exists());
        assert!(staging.path().join(PATHMAP_FILENAME).exists());

        let script_content = std::fs::read_to_string(staging.path().join(SCRIPT_FILENAME)).unwrap();
        assert_eq!(script_content, "print('hello')");
    }
}
```

- [ ] **Step 2: Write the minimal implementation**

Create `src/wxc_common/src/microvm_staging.rs`:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Staging directory builder for the NanVix microvm backend.
//!
//! Builds a temporary directory containing the user script, a bootstrap loader,
//! and filesystem policy paths (readwrite/readonly). The staging directory is
//! passed to `nanvixd -mount` as a single mount target.
//!
//! The `StagingDir` type implements `Drop` for guaranteed cleanup.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Maximum total staging content in bytes (nanvixd mount image limit).
const MAX_STAGING_BYTES: u64 = 16 * 1024 * 1024;

/// Bootstrap script filename (dot-prefixed to avoid collisions with user files).
const BOOTSTRAP_FILENAME: &str = ".mxc-bootstrap.py";

/// User script filename.
const SCRIPT_FILENAME: &str = ".mxc-script.py";

/// Path map JSON filename.
const PATHMAP_FILENAME: &str = ".mxc-pathmap.json";

/// Subdirectory for readwrite paths.
const RW_DIR: &str = "rw";

/// Subdirectory for readonly paths.
const RO_DIR: &str = "ro";

/// Bootstrap Python source. Reads the path map, exports MXC_PATH_* env vars,
/// then runs the user script via `runpy.run_path`. stdin is untouched so
/// `input()` and REPLs work.
const BOOTSTRAP_SOURCE: &str = r#"import json, os, runpy, sys
with open('/mnt/.mxc-pathmap.json') as f:
    for slug, guest_path in json.load(f).items():
        os.environ[f'MXC_PATH_{slug}'] = guest_path
sys.argv = ['/mnt/.mxc-script.py']
runpy.run_path(sys.argv[0], run_name='__main__')
"#;

/// Error type for staging directory operations.
#[derive(Debug)]
pub enum StagingError {
    /// A filesystem policy path does not exist on the host.
    PathNotFound(String),
    /// Total staging content exceeds the mount image limit.
    SizeCapExceeded { actual_mb: f64, limit_mb: f64 },
    /// `denied_paths` is not supported by the microvm backend.
    DeniedPathsNotSupported,
    /// A source path contains a symbolic link (FAT32 cannot represent symlinks).
    SymlinkFound(String),
    /// I/O error during staging.
    Io(std::io::Error),
}

impl std::fmt::Display for StagingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StagingError::PathNotFound(p) => {
                write!(f, "filesystem policy path does not exist: {}", p)
            }
            StagingError::SizeCapExceeded { actual_mb, limit_mb } => {
                write!(
                    f,
                    "total filesystem policy content is {:.1} MB, exceeding the {:.0} MB mount image limit",
                    actual_mb, limit_mb
                )
            }
            StagingError::DeniedPathsNotSupported => {
                write!(
                    f,
                    "denied_paths is not meaningful for the microvm backend \
                     -- the guest has no host filesystem visibility. \
                     Only readwrite_paths and readonly_paths are supported"
                )
            }
            StagingError::SymlinkFound(p) => {
                write!(
                    f,
                    "symbolic links in readwrite_paths/readonly_paths are not supported \
                     -- FAT32 has no symlink representation. Path: {}",
                    p
                )
            }
            StagingError::Io(e) => write!(f, "staging I/O error: {}", e),
        }
    }
}

impl From<std::io::Error> for StagingError {
    fn from(e: std::io::Error) -> Self {
        StagingError::Io(e)
    }
}

/// A staging directory for a single NanVix microvm invocation.
///
/// Created before spawning nanvixd and cleaned up via `Drop` after exit.
/// Contains the bootstrap script, user script, path map, and optional
/// `rw/` and `ro/` subdirectories with filesystem policy content.
pub struct StagingDir {
    path: PathBuf,
    path_map: BTreeMap<String, String>,
}

impl StagingDir {
    /// Build a new staging directory at `root` with the given script and
    /// filesystem policy paths.
    ///
    /// # Arguments
    /// - `root` — directory path to create (must not exist)
    /// - `script` — user Python source code
    /// - `readwrite_paths` — host paths to stage read-write under `/mnt/rw/`
    /// - `readonly_paths` — host paths to stage read-only under `/mnt/ro/`
    pub fn new(
        root: PathBuf,
        script: &str,
        readwrite_paths: &[String],
        readonly_paths: &[String],
    ) -> Result<Self, StagingError> {
        std::fs::create_dir_all(&root)?;

        // Write bootstrap, script, and an initial empty path map.
        std::fs::write(root.join(BOOTSTRAP_FILENAME), BOOTSTRAP_SOURCE)?;
        std::fs::write(root.join(SCRIPT_FILENAME), script)?;

        let path_map = BTreeMap::new();
        // Path map will be populated by stage_paths and written at the end.

        let mut staging = Self { path: root, path_map };

        staging.stage_paths(readwrite_paths, readonly_paths)?;
        staging.write_pathmap()?;

        Ok(staging)
    }

    /// Returns the staging directory path (the value to pass to `nanvixd -mount`).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the path map (slug → guest path).
    pub fn path_map(&self) -> &BTreeMap<String, String> {
        &self.path_map
    }

    /// Compute the estimated staging overhead in milliseconds for timeout adjustment.
    /// Returns `staging_size_mb × 100`, capped at 30_000 ms.
    pub fn staging_overhead_ms(&self) -> u64 {
        let size_bytes = dir_size(&self.path).unwrap_or(0);
        let size_mb = size_bytes as f64 / (1024.0 * 1024.0);
        let overhead = (size_mb * 100.0) as u64;
        overhead.min(30_000)
    }

    fn stage_paths(
        &mut self,
        readwrite_paths: &[String],
        readonly_paths: &[String],
    ) -> Result<(), StagingError> {
        if !readwrite_paths.is_empty() {
            std::fs::create_dir_all(self.path.join(RW_DIR))?;
        }
        if !readonly_paths.is_empty() {
            std::fs::create_dir_all(self.path.join(RO_DIR))?;
        }

        let mut used_slugs: Vec<String> = Vec::new();

        for host_path_str in readwrite_paths {
            let host_path = Path::new(host_path_str);
            if !host_path.exists() {
                return Err(StagingError::PathNotFound(host_path_str.clone()));
            }
            check_no_symlinks(host_path)?;

            let slug = allocate_slug(host_path, &mut used_slugs);
            let slot_dir = self.path.join(RW_DIR).join(&slug);
            stage_host_path(host_path, &slot_dir)?;
            self.path_map
                .insert(slug_to_env_key(&slug), format!("/mnt/{}/{}", RW_DIR, slug));
        }

        for host_path_str in readonly_paths {
            let host_path = Path::new(host_path_str);
            if !host_path.exists() {
                return Err(StagingError::PathNotFound(host_path_str.clone()));
            }
            check_no_symlinks(host_path)?;

            let slug = allocate_slug(host_path, &mut used_slugs);
            let slot_dir = self.path.join(RO_DIR).join(&slug);
            copy_dir_recursive(host_path, &slot_dir)?;
            set_readonly_recursive(&slot_dir)?;
            self.path_map
                .insert(slug_to_env_key(&slug), format!("/mnt/{}/{}", RO_DIR, slug));
        }

        // Size cap check after staging.
        let total = dir_size(&self.path)?;
        if total > MAX_STAGING_BYTES {
            let actual_mb = total as f64 / (1024.0 * 1024.0);
            let limit_mb = MAX_STAGING_BYTES as f64 / (1024.0 * 1024.0);
            return Err(StagingError::SizeCapExceeded { actual_mb, limit_mb });
        }

        Ok(())
    }

    fn write_pathmap(&self) -> Result<(), StagingError> {
        let json = serde_json::to_string_pretty(&self.path_map)
            .map_err(|e| StagingError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        std::fs::write(self.path.join(PATHMAP_FILENAME), json)?;
        Ok(())
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// -- Helper functions --------------------------------------------------------

/// Generate a slug from a host path's basename.
/// Uses UPPER_SNAKE_CASE. On collision, appends `_2`, `_3`, etc.
fn allocate_slug(host_path: &Path, used: &mut Vec<String>) -> String {
    let base = host_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed");
    let normalized = base
        .replace('-', "_")
        .replace(' ', "_")
        .to_ascii_lowercase();

    let mut candidate = normalized.clone();
    let mut counter = 2u32;
    while used.contains(&candidate) {
        candidate = format!("{}_{}", normalized, counter);
        counter += 1;
    }
    used.push(candidate.clone());
    candidate
}

/// Convert a slug (lowercase) to an env var key (UPPER_SNAKE).
fn slug_to_env_key(slug: &str) -> String {
    slug.to_ascii_uppercase()
}

/// Stage a host path into a slot directory.
/// For directories: creates a junction (Windows) or falls back to copy.
/// For files: wraps in a slot directory and copies.
fn stage_host_path(host_path: &Path, slot_dir: &Path) -> Result<(), StagingError> {
    if host_path.is_dir() {
        // Try junction first (Windows only), fall back to recursive copy.
        #[cfg(target_os = "windows")]
        {
            if try_create_junction(host_path, slot_dir) {
                return Ok(());
            }
        }
        copy_dir_recursive(host_path, slot_dir)?;
    } else {
        // Single file: wrap in a slot directory.
        std::fs::create_dir_all(slot_dir)?;
        let dest = slot_dir.join(
            host_path
                .file_name()
                .unwrap_or(std::ffi::OsStr::new("file")),
        );
        std::fs::copy(host_path, dest)?;
    }
    Ok(())
}

/// Attempt to create a directory junction (Windows).
/// Returns true on success, false on failure (caller should fall back to copy).
#[cfg(target_os = "windows")]
fn try_create_junction(source: &Path, target: &Path) -> bool {
    use std::process::Command;
    // Use mklink /J via cmd.exe for junction creation.
    let status = Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &target.to_string_lossy(),
            &source.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    matches!(status, Ok(s) if s.success())
}

/// Recursively copy a directory tree.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), StagingError> {
    std::fs::create_dir_all(dst)?;
    if src.is_dir() {
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let src_child = entry.path();
            let dst_child = dst.join(entry.file_name());
            if src_child.is_dir() {
                copy_dir_recursive(&src_child, &dst_child)?;
            } else {
                std::fs::copy(&src_child, &dst_child)?;
            }
        }
    } else {
        // src is a file — copy into dst directory.
        std::fs::create_dir_all(dst)?;
        let filename = src
            .file_name()
            .unwrap_or(std::ffi::OsStr::new("file"));
        std::fs::copy(src, dst.join(filename))?;
    }
    Ok(())
}

/// Set the read-only attribute on all files in a directory tree.
fn set_readonly_recursive(dir: &Path) -> Result<(), StagingError> {
    if dir.is_file() {
        let mut perms = std::fs::metadata(dir)?.permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(dir, perms)?;
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            set_readonly_recursive(&path)?;
        } else {
            let mut perms = std::fs::metadata(&path)?.permissions();
            perms.set_readonly(true);
            std::fs::set_permissions(&path, perms)?;
        }
    }
    Ok(())
}

/// Check that a path and its children contain no symbolic links.
fn check_no_symlinks(path: &Path) -> Result<(), StagingError> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_symlink() {
        return Err(StagingError::SymlinkFound(path.display().to_string()));
    }
    if meta.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            check_no_symlinks(&entry.path())?;
        }
    }
    Ok(())
}

/// Recursively compute the total size of all files in a directory.
fn dir_size(path: &Path) -> Result<u64, StagingError> {
    let mut total = 0u64;
    if path.is_file() {
        return Ok(std::fs::metadata(path)?.len());
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            total += dir_size(&entry_path)?;
        } else {
            total += std::fs::metadata(&entry_path)?.len();
        }
    }
    Ok(total)
}
```

- [ ] **Step 3: Run test to verify it passes**

Run: `cd src && cargo test -p wxc_common staging_creates_bootstrap_and_script -- --nocapture`
Expected: PASS

- [ ] **Step 4: Write more unit tests**

Add these tests to the `#[cfg(test)] mod tests` block in `microvm_staging.rs`:

```rust
    #[test]
    fn staging_empty_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = StagingDir::new(
            tmp.path().join("stage"),
            "pass",
            &[],
            &[],
        )
        .unwrap();

        // Only bootstrap files exist, no rw/ or ro/ subdirs.
        assert!(!staging.path().join("rw").exists());
        assert!(!staging.path().join("ro").exists());
        assert!(staging.path_map().is_empty());
    }

    #[test]
    fn staging_single_rw_path() {
        let tmp = tempfile::tempdir().unwrap();
        let src_dir = tmp.path().join("mydata");
        std::fs::create_dir(&src_dir).unwrap();
        std::fs::write(src_dir.join("file.txt"), "content").unwrap();

        let staging = StagingDir::new(
            tmp.path().join("stage"),
            "pass",
            &[src_dir.to_string_lossy().into_owned()],
            &[],
        )
        .unwrap();

        assert!(staging.path().join("rw").join("mydata").exists());
        assert_eq!(
            staging.path_map().get("MYDATA"),
            Some(&"/mnt/rw/mydata".to_string())
        );
    }

    #[test]
    fn staging_ro_path_has_readonly_attribute() {
        let tmp = tempfile::tempdir().unwrap();
        let src_dir = tmp.path().join("ref");
        std::fs::create_dir(&src_dir).unwrap();
        std::fs::write(src_dir.join("data.txt"), "readonly").unwrap();

        let staging = StagingDir::new(
            tmp.path().join("stage"),
            "pass",
            &[],
            &[src_dir.to_string_lossy().into_owned()],
        )
        .unwrap();

        let staged_file = staging.path().join("ro").join("ref").join("data.txt");
        assert!(staged_file.exists());
        let perms = std::fs::metadata(&staged_file).unwrap().permissions();
        assert!(perms.readonly(), "staged RO file should be read-only");
    }

    #[test]
    fn staging_slug_collision() {
        let tmp = tempfile::tempdir().unwrap();
        let dir_a = tmp.path().join("a").join("input");
        let dir_b = tmp.path().join("b").join("input");
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();
        std::fs::write(dir_a.join("x.txt"), "a").unwrap();
        std::fs::write(dir_b.join("y.txt"), "b").unwrap();

        let staging = StagingDir::new(
            tmp.path().join("stage"),
            "pass",
            &[
                dir_a.to_string_lossy().into_owned(),
                dir_b.to_string_lossy().into_owned(),
            ],
            &[],
        )
        .unwrap();

        assert_eq!(staging.path_map().len(), 2);
        assert!(staging.path_map().contains_key("INPUT"));
        assert!(staging.path_map().contains_key("INPUT_2"));
    }

    #[test]
    fn staging_pathmap_json_shape() {
        let tmp = tempfile::tempdir().unwrap();
        let src_dir = tmp.path().join("data");
        std::fs::create_dir(&src_dir).unwrap();
        std::fs::write(src_dir.join("x.txt"), "hi").unwrap();

        let staging = StagingDir::new(
            tmp.path().join("stage"),
            "pass",
            &[src_dir.to_string_lossy().into_owned()],
            &[],
        )
        .unwrap();

        let json_str =
            std::fs::read_to_string(staging.path().join(PATHMAP_FILENAME)).unwrap();
        let map: BTreeMap<String, String> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(map.get("DATA"), Some(&"/mnt/rw/data".to_string()));
    }

    #[test]
    fn staging_bootstrap_is_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let s1 = StagingDir::new(tmp.path().join("s1"), "pass", &[], &[]).unwrap();
        let s2 = StagingDir::new(tmp.path().join("s2"), "pass", &[], &[]).unwrap();

        let b1 = std::fs::read_to_string(s1.path().join(BOOTSTRAP_FILENAME)).unwrap();
        let b2 = std::fs::read_to_string(s2.path().join(BOOTSTRAP_FILENAME)).unwrap();
        assert_eq!(b1, b2, "bootstrap content must be identical across invocations");
    }

    #[test]
    fn staging_cleanup_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let stage_path = tmp.path().join("stage");
        {
            let _staging =
                StagingDir::new(stage_path.clone(), "pass", &[], &[]).unwrap();
            assert!(stage_path.exists());
        }
        // After drop, the directory should be gone.
        assert!(!stage_path.exists());
    }

    #[test]
    fn staging_missing_path_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let result = StagingDir::new(
            tmp.path().join("stage"),
            "pass",
            &["/nonexistent/path/abc123".to_string()],
            &[],
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, StagingError::PathNotFound(_)),
            "expected PathNotFound, got: {}",
            err
        );
    }

    #[test]
    fn staging_single_file_rw_wrapped_in_slot() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("single.txt");
        std::fs::write(&file_path, "content").unwrap();

        let staging = StagingDir::new(
            tmp.path().join("stage"),
            "pass",
            &[file_path.to_string_lossy().into_owned()],
            &[],
        )
        .unwrap();

        // Single file should be in rw/single.txt/single.txt
        let slot = staging.path().join("rw").join("single.txt");
        assert!(slot.is_dir(), "single file should be wrapped in a slot dir");
        assert!(slot.join("single.txt").exists());
    }

    #[test]
    fn slug_generation_dash_to_underscore() {
        let mut used = Vec::new();
        let path = Path::new("/some/ref-data");
        let slug = allocate_slug(path, &mut used);
        assert_eq!(slug, "ref_data");
        assert_eq!(slug_to_env_key(&slug), "REF_DATA");
    }
```

- [ ] **Step 5: Run all staging tests**

Run: `cd src && cargo test -p wxc_common staging_ -- --nocapture`
Expected: All PASS

- [ ] **Step 6: Add module to lib.rs**

In `src/wxc_common/src/lib.rs`, add after the `nanvix_runner` line:

```rust
#[cfg(target_os = "windows")]
pub mod microvm_staging;
```

- [ ] **Step 7: Add uuid to runtime dependencies**

In `src/wxc_common/Cargo.toml`, add to the `[target.'cfg(target_os = "windows")'.dependencies]` section:

```toml
uuid = { workspace = true }
```

- [ ] **Step 8: Run full crate build + tests**

Run: `cd src && cargo build -p wxc_common && cargo test -p wxc_common`
Expected: Build succeeds, all tests pass

- [ ] **Step 9: Commit**

```bash
git add src/wxc_common/src/microvm_staging.rs src/wxc_common/src/lib.rs src/wxc_common/Cargo.toml
git commit -m "feat(microvm): add StagingDir RAII type for mount-based script delivery

Introduces microvm_staging.rs with staging directory builder, bootstrap
script writer, slug generation, read-only attribute handling, path map
JSON, size validation, and RAII cleanup via Drop.

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 2: Update `nanvix_runner.rs` — Policy Validation

**Files:**
- Modify: `src/wxc_common/src/nanvix_runner.rs:56-64` (error constants)
- Modify: `src/wxc_common/src/nanvix_runner.rs:247-268` (`validate_policies`)

Update policy validation to accept `readwrite_paths`/`readonly_paths` and explicitly reject `denied_paths`.

- [ ] **Step 1: Write a failing test — denied_paths rejection**

Add to the `#[cfg(test)] mod tests` block in `nanvix_runner.rs`:

```rust
    #[test]
    fn policy_rejects_denied_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                denied_paths: vec!["/secret".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let result = NanVixScriptRunner::validate_policies(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("denied_paths"),
            "expected denied_paths error, got: {}",
            err
        );
    }
```

- [ ] **Step 2: Run test — verify it fails**

Run: `cd src && cargo test -p wxc_common policy_rejects_denied_paths -- --nocapture`
Expected: FAIL — currently denied_paths triggers the generic filesystem policy error, not a denied_paths-specific error.

- [ ] **Step 3: Update error constants**

In `src/wxc_common/src/nanvix_runner.rs`, replace the filesystem policy error constant:

Replace:
```rust
const ERR_FILESYSTEM_POLICY: &str =
    "filesystem policy is not supported by the NanVix backend -- guest has a read-only ramfs";
```

With:
```rust
const ERR_DENIED_PATHS: &str =
    "denied_paths is not meaningful for the microvm backend \
     -- the guest has no host filesystem visibility. \
     Only readwrite_paths and readonly_paths are supported";
```

- [ ] **Step 4: Update `validate_policies`**

Replace the entire `validate_policies` method:

```rust
    fn validate_policies(request: &CodexRequest) -> Result<(), NanVixError> {
        // denied_paths is explicitly rejected — microvm has no host visibility.
        if !request.policy.denied_paths.is_empty() {
            return Err(NanVixError::Preflight(ERR_DENIED_PATHS.to_string()));
        }
        // readwrite_paths and readonly_paths are now accepted (handled via staging dir).
        // Network policy is still rejected — NanVix has no network stack.
        if !request.policy.allowed_hosts.is_empty()
            || !request.policy.blocked_hosts.is_empty()
            || request.policy.default_network_policy != NetworkPolicy::Allow
        {
            return Err(NanVixError::Preflight(ERR_NETWORK_POLICY.to_string()));
        }
        if request.policy.network_proxy.is_enabled() {
            return Err(NanVixError::Preflight(ERR_PROXY_POLICY.to_string()));
        }
        if !request.working_directory.is_empty() {
            return Err(NanVixError::Preflight(ERR_WORKDIR.to_string()));
        }

        Ok(())
    }
```

- [ ] **Step 5: Update existing tests that reference ERR_FILESYSTEM_POLICY**

The tests `policy_rejects_filesystem_paths`, `policy_rejects_readonly_paths` now test paths that are **accepted**. Update them:

Replace `policy_rejects_filesystem_paths` with:
```rust
    #[test]
    fn policy_accepts_readwrite_paths() {
        // readwrite_paths are now accepted (staging dir handles them).
        // Validation passes; the runner fails later on path resolution.
        let request = CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["/tmp".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let result = NanVixScriptRunner::validate_policies(&request);
        assert!(result.is_ok(), "readwrite_paths should be accepted");
    }
```

Replace `policy_rejects_readonly_paths` with:
```rust
    #[test]
    fn policy_accepts_readonly_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["/data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let result = NanVixScriptRunner::validate_policies(&request);
        assert!(result.is_ok(), "readonly_paths should be accepted");
    }
```

- [ ] **Step 6: Run all NanVix tests**

Run: `cd src && cargo test -p wxc_common -- nanvix --nocapture`
Expected: All PASS (including the new `policy_rejects_denied_paths` and updated acceptance tests)

- [ ] **Step 7: Commit**

```bash
git add src/wxc_common/src/nanvix_runner.rs
git commit -m "feat(microvm): accept readwrite/readonly paths, reject denied_paths

Update validate_policies to allow readwrite_paths and readonly_paths
(handled via staging directory). Explicitly reject denied_paths with
a clear error message. Network and workdir rejections unchanged.

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 3: Update `nanvix_runner.rs` — Spawn with Mount + Inherit stdin

**Files:**
- Modify: `src/wxc_common/src/nanvix_runner.rs:270-324` (`build_guest_args`, `spawn_nanvixd`)
- Modify: `src/wxc_common/src/nanvix_runner.rs:238-245` (`total_timeout_ms`)
- Modify: `src/wxc_common/src/nanvix_runner.rs:479-522` (`run`)

This is the core change: script goes to staging dir, stdin becomes inherit, nanvixd gets `-mount`.

- [ ] **Step 1: Write the failing test — guest args use bootstrap path**

Add to the test module in `nanvix_runner.rs`:

```rust
    #[test]
    fn guest_args_use_bootstrap_path() {
        let args = NanVixScriptRunner::build_guest_args();
        assert!(
            args.contains(".mxc-bootstrap.py"),
            "guest args should reference bootstrap script, got: {}",
            args
        );
        assert!(
            !args.contains("exec(__import__"),
            "guest args should NOT use stdin exec trick, got: {}",
            args
        );
    }
```

- [ ] **Step 2: Run test — verify it fails**

Run: `cd src && cargo test -p wxc_common guest_args_use_bootstrap -- --nocapture`
Expected: FAIL — current args still use `exec(__import__('sys').stdin.read())`

- [ ] **Step 3: Update `build_guest_args`**

Replace the `build_guest_args` method:

```rust
    fn build_guest_args() -> String {
        // Build the NanVix guest argument string for mount-based script delivery.
        // Format: "/mnt/.mxc-bootstrap.py;PYTHONHOME=/sysroot"
        //
        // The bootstrap script lives in the staging directory mounted at /mnt.
        // It reads /mnt/.mxc-pathmap.json, exports MXC_PATH_* env vars,
        // then runs /mnt/.mxc-script.py via runpy.run_path().
        //
        // No spaces in the path → survives NanVix's space-splitting.
        // ';' separates argv from env vars (kernel splits on ';').
        format!("/mnt/.mxc-bootstrap.py;PYTHONHOME={}", PYTHON_HOME)
    }
```

- [ ] **Step 4: Update `spawn_nanvixd` — add `-mount`, switch to `Stdio::inherit()` for stdin**

Replace the `spawn_nanvixd` method signature and body. The method no longer takes `script` (script is in the staging dir):

```rust
    fn spawn_nanvixd(
        paths: (&Path, &Path, &Path, &Path),
        guest_args: &str,
        staging_dir: &Path,
    ) -> Result<std::process::Child, NanVixError> {
        let (nanvixd_path, bin_dir, ramfs_path, python_path) = paths;
        Command::new(nanvixd_path)
            .arg("-bin-dir")
            .arg(bin_dir)
            .arg("-ramfs")
            .arg(ramfs_path)
            .arg("-mount")
            .arg(staging_dir)
            .arg("--")
            .arg(python_path)
            .arg(guest_args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                NanVixError::Platform(format!("failed to spawn {}: {}", NANVIXD_BINARY, e))
            })
    }
```

- [ ] **Step 5: Update `total_timeout_ms` to accept staging overhead**

Replace the `total_timeout_ms` method:

```rust
    /// Compute total timeout: boot grace + staging overhead + script timeout.
    fn total_timeout_ms(script_timeout: u32, staging_overhead_ms: u64) -> u64 {
        if script_timeout == 0 {
            u64::MAX
        } else {
            BOOT_TIMEOUT_MS
                .saturating_add(staging_overhead_ms)
                .saturating_add(script_timeout as u64)
        }
    }
```

- [ ] **Step 6: Update the `run` method to use staging dir**

Replace the entire `run` method implementation in the `impl ScriptRunner for NanVixScriptRunner` block:

```rust
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        if let Err(e) = Self::validate_policies(request) {
            return e.to_response();
        }

        let (nanvixd_path, bin_dir, ramfs_path, python_path) = match self.resolve_paths() {
            Ok(paths) => paths,
            Err(e) => return e.to_response(),
        };

        // Build staging directory with script and filesystem policy paths.
        let staging_root = std::env::temp_dir()
            .join("mxc-microvm")
            .join(uuid::Uuid::new_v4().to_string());
        let staging = match crate::microvm_staging::StagingDir::new(
            staging_root,
            &request.script_code,
            &request.policy.readwrite_paths,
            &request.policy.readonly_paths,
        ) {
            Ok(s) => s,
            Err(e) => {
                let err = NanVixError::Preflight(e.to_string());
                let _ = writeln!(logger, "{}", err);
                return err.to_response();
            }
        };

        Self::log_resolved_paths(logger, &nanvixd_path, &bin_dir, &ramfs_path, &python_path);
        let _ = writeln!(logger, "NanVix: staging_dir={:?}", staging.path());
        let guest_args = Self::build_guest_args();

        let mut child = match Self::spawn_nanvixd(
            (&nanvixd_path, &bin_dir, &ramfs_path, &python_path),
            &guest_args,
            staging.path(),
        ) {
            Ok(c) => c,
            Err(e) => {
                let _ = writeln!(logger, "{}", e);
                return e.to_response();
            }
        };

        let staging_overhead = staging.staging_overhead_ms();
        let timeout_ms = Self::total_timeout_ms(request.script_timeout, staging_overhead);
        let (watchdog, cancel_pair, timed_out) =
            match Self::setup_watchdog(&mut child, timeout_ms, logger) {
                Ok(v) => v,
                Err(resp) => return resp,
            };

        Self::wait_and_respond(
            &mut child,
            watchdog,
            &cancel_pair,
            timed_out.as_ref(),
            timeout_ms,
            request.script_timeout,
            logger,
        )
        // staging is dropped here → cleanup
    }
```

- [ ] **Step 7: Update existing tests that call `total_timeout_ms`**

Replace the `total_timeout_adds_boot_and_script` test:

```rust
    #[test]
    fn total_timeout_adds_boot_staging_and_script() {
        // script_timeout=0 => infinite script timeout sentinel.
        assert_eq!(NanVixScriptRunner::total_timeout_ms(0, 0), u64::MAX);
        // script_timeout=30000, staging_overhead=500 -> 30s + 500ms + 60s boot = 90.5s
        assert_eq!(NanVixScriptRunner::total_timeout_ms(30_000, 500), 90_500);
        // script_timeout=30000, no staging -> 30s + 60s boot = 90s
        assert_eq!(NanVixScriptRunner::total_timeout_ms(30_000, 0), 90_000);
    }
```

Update `guest_args_format_is_correct`:

```rust
    #[test]
    fn guest_args_format_is_correct() {
        let expected = "/mnt/.mxc-bootstrap.py;PYTHONHOME=/sysroot";
        let actual = NanVixScriptRunner::build_guest_args();
        assert_eq!(actual, expected);
        // No spaces in the bootstrap path segment.
        let argv_part = actual.split(';').next().unwrap();
        assert!(
            !argv_part.contains(' '),
            "argv portion must not contain spaces for NanVix splitting"
        );
    }
```

- [ ] **Step 8: Run all tests**

Run: `cd src && cargo test -p wxc_common -- --nocapture`
Expected: All PASS

- [ ] **Step 9: Commit**

```bash
git add src/wxc_common/src/nanvix_runner.rs
git commit -m "feat(microvm): deliver script via -mount, inherit stdin for PTY

Replace stdin-piped script delivery with mount-based delivery.
Script is written to a staging directory and nanvixd reads it from
/mnt/.mxc-script.py via the bootstrap loader. stdin is now
Stdio::inherit() so the ConPTY relay works end-to-end.

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 4: Add Integration Test Configs

**Files:**
- Create: `test_configs/microvm_pty_input.json`
- Create: `test_configs/microvm_rw_path.json`
- Create: `test_configs/microvm_ro_path.json`
- Create: `test_configs/microvm_denied_paths.json`
- Create: `test_configs/microvm_no_fs_mount.json`

- [ ] **Step 1: Create `microvm_pty_input.json`**

```json
{
    "process": {
        "commandLine": "name = input('What is your name? ')\nprint(f'Hello, {name}!')",
        "timeout": 30000
    },
    "containment": "microvm"
}
```

- [ ] **Step 2: Create `microvm_rw_path.json`**

Note: This test requires a host directory to exist. The test harness must create it.

```json
{
    "process": {
        "commandLine": "import os\npath = os.environ['MXC_PATH_INPUT']\nwith open(os.path.join(path, 'data.txt')) as f:\n    print(f.read().strip())\nwith open(os.path.join(path, 'output.txt'), 'w') as f:\n    f.write('written by guest')",
        "timeout": 30000
    },
    "containment": "microvm",
    "filesystem": {
        "readwritePaths": []
    }
}
```

Note: `readwritePaths` must be filled in by the test harness with the actual temp dir path.

- [ ] **Step 3: Create `microvm_ro_path.json`**

```json
{
    "process": {
        "commandLine": "import os\npath = os.environ['MXC_PATH_REF']\ntry:\n    with open(os.path.join(path, 'test.txt'), 'w') as f:\n        f.write('should fail')\n    print('ERROR: write succeeded')\n    import sys; sys.exit(1)\nexcept (OSError, PermissionError) as e:\n    print(f'OK: {e}')",
        "timeout": 30000
    },
    "containment": "microvm",
    "filesystem": {
        "readonlyPaths": []
    }
}
```

- [ ] **Step 4: Create `microvm_denied_paths.json`**

```json
{
    "process": {
        "commandLine": "print('should not run')",
        "timeout": 30000
    },
    "containment": "microvm",
    "filesystem": {
        "deniedPaths": ["/secret"]
    }
}
```

- [ ] **Step 5: Create `microvm_no_fs_mount.json`**

Regression test: empty FS policy still works with mount-based script delivery.

```json
{
    "process": {
        "commandLine": "import sys\nprint(f'Python {sys.version_info[0]}.{sys.version_info[1]} on {sys.platform}')",
        "timeout": 30000
    },
    "containment": "microvm"
}
```

- [ ] **Step 6: Verify existing microvm test configs still parse**

Run: `cd src && cargo test -p wxc_common -- config_parser --nocapture`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add test_configs/microvm_pty_input.json test_configs/microvm_rw_path.json test_configs/microvm_ro_path.json test_configs/microvm_denied_paths.json test_configs/microvm_no_fs_mount.json
git commit -m "test(microvm): add integration test configs for PTY and FS policy

Add test configs for PTY input (stdin relay), readwrite paths with
copyback, readonly paths with EACCES enforcement, denied_paths
rejection, and a regression test for empty FS policy.

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 5: Add User-Facing Documentation

**Files:**
- Create: `docs/microvm.md`
- Modify: `docs/nanvix-integration-plan.md`

- [ ] **Step 1: Create `docs/microvm.md`**

```markdown
# MicroVM Backend (NanVix)

The MicroVM backend runs Python code inside a NanVix microkernel VM with hardware-enforced isolation via Windows Hypervisor Platform (WHP).

## Requirements

- Windows with WHP enabled (`bcdedit /set hypervisorlaunchtype auto`)
- NanVix runtime binaries (`nanvixd.exe`, `kernel.elf`, `python.elf`, `cpython-ramfs.img`) placed next to `wxc-exec.exe`
- `--experimental` flag (MicroVM is an experimental feature)

## Quick Start

```json
{
  "process": {
    "commandLine": "print('Hello from MicroVM!')",
    "timeout": 30000
  },
  "containment": "microvm"
}
```

```bash
wxc-exec.exe --experimental config.json
```

## Interactive Input (PTY)

The MicroVM backend supports interactive stdin input. Scripts can use `input()` and the data flows through the ConPTY relay from the SDK:

```json
{
  "process": {
    "commandLine": "name = input('Name: ')\nprint(f'Hello, {name}!')",
    "timeout": 30000
  },
  "containment": "microvm"
}
```

**Caveat:** `sys.stdin.isatty()` returns `False` inside the guest. NanVix forwards stdin via an IKC pipe, not a kernel TTY device. This means libraries that check `isatty()` (e.g., `readline`) may behave differently.

## Filesystem Policy

### readwrite_paths

Host directories listed in `readwritePaths` are staged into the guest VM at boot and copied back to the host on clean exit:

```json
{
  "process": {
    "commandLine": "import os\npath = os.environ['MXC_PATH_WORK']\nwith open(os.path.join(path, 'result.txt'), 'w') as f:\n    f.write('done')",
    "timeout": 30000
  },
  "containment": "microvm",
  "filesystem": {
    "readwritePaths": ["C:\\Users\\me\\work"]
  }
}
```

Inside the guest, the path is accessible via the `MXC_PATH_<SLUG>` environment variable. The slug is derived from the directory basename in UPPER_SNAKE_CASE.

| Host path | Env var | Guest path |
|-----------|---------|------------|
| `C:\Users\me\work` | `MXC_PATH_WORK` | `/mnt/rw/work` |
| `C:\data\ref-data` | `MXC_PATH_REF_DATA` | `/mnt/rw/ref_data` |

**Copyback semantics:** Modified files are written back to the original host path on clean exit (exit code 0 or non-zero). On timeout or crash, copyback is skipped — no partial state is leaked.

### readonly_paths

Host directories listed in `readonlyPaths` are staged read-only. Writes return `EACCES`:

```json
{
  "filesystem": {
    "readonlyPaths": ["C:\\data\\reference"]
  }
}
```

### denied_paths

Not supported for MicroVM. If `deniedPaths` is specified, the config is rejected with an error. The guest has no host filesystem visibility, so deny-listing is meaningless.

## Constraints

| Constraint | Value |
|-----------|-------|
| Total filesystem policy content | ≤ 16 MB |
| Single file size | < 4 GB (FAT32 limit) |
| Guest RAM | 128 MB |
| Symlinks in source paths | Not supported (rejected at preflight) |
| `workingDirectory` | Not supported (guest CWD is `/`) |
| Network policy | Not supported (NanVix has no network stack) |

## Supported Workloads

Pure computation, string processing, JSON/data manipulation, math, date/time, hash computation, and data structures using Python's standard library.

## Not Supported

| Workload | Error |
|----------|-------|
| Network I/O | `OSError: Function not implemented` |
| File writing outside `/mnt/rw/` | `OSError: Read-only file system` |
| Subprocess | `OSError: Function not implemented` |
| SSL/TLS | `ModuleNotFoundError: No module named '_ssl'` |
| Interactive `input()` after stdin EOF | `EOFError` (only if SDK closes the PTY) |
```

- [ ] **Step 2: Update `docs/nanvix-integration-plan.md` — supported table**

In `docs/nanvix-integration-plan.md`, in the "Not Supported" table, change the "Interactive input" row:

Replace:
```markdown
| Interactive input (`input()`) | stdin consumed for script delivery | `EOFError: EOF when reading a line` |
```

With:
```markdown
| Interactive input (`input()`) | ✅ **Now supported** — stdin is relayed via ConPTY | Works with mount-based script delivery |
```

And add a new "Supported" row for filesystem policy:

Add after the "Multi-line scripts" row:
```markdown
| Filesystem policy (readwrite/readonly) | `readwritePaths`/`readonlyPaths` | Staged via `-mount`, copyback on exit |
```

- [ ] **Step 3: Commit**

```bash
git add docs/microvm.md docs/nanvix-integration-plan.md
git commit -m "docs(microvm): add user-facing docs for PTY input and FS policy

Add docs/microvm.md covering interactive input, filesystem policy
(readwrite/readonly paths), MXC_PATH_* env vars, copyback semantics,
constraints, and supported workloads. Update nanvix-integration-plan.md
to reflect that input() is now supported and FS policy is available.

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 6: Full Build + Lint Check

**Files:**
- None (validation only)

- [ ] **Step 1: Full workspace build**

Run: `cd src && cargo build --release --target x86_64-pc-windows-msvc`
Expected: Build succeeds with no errors

- [ ] **Step 2: Clippy lint**

Run: `cd src && cargo clippy --workspace --all-targets -- -D warnings`
Expected: No warnings

- [ ] **Step 3: Format check**

Run: `cd src && cargo fmt --all -- --check`
Expected: No formatting issues

- [ ] **Step 4: Full test suite**

Run: `cd src && cargo test --workspace`
Expected: All tests pass

- [ ] **Step 5: Fix any issues found**

If any step above fails, fix the issue and re-run. Common issues:
- Unused imports → remove them
- Clippy suggestions → apply them
- Format issues → run `cargo fmt --all`

- [ ] **Step 6: Commit any fixes**

```bash
git add -A
git commit -m "fix(microvm): address lint and format issues

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Dependency Graph

```
Task 1 (StagingDir)
    ↓
Task 2 (validate_policies) ──→ Task 3 (spawn + run)
                                    ↓
                              Task 4 (test configs)
                                    ↓
                              Task 5 (docs)
                                    ↓
                              Task 6 (build + lint)
```

Tasks 1 and 2 can run in parallel. Task 3 depends on both. Tasks 4 and 5 depend on Task 3. Task 6 depends on all.
