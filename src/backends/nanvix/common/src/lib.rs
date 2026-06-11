// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared constants and configuration types for NanVix micro-VM binaries.
//!
//! This crate is the single source of truth for binary filenames, release
//! configuration, and checksum data. It is consumed as a `[build-dependency]`
//! by `nanvix_binaries` (download) and `wxc` (copy to output dir).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// All required NanVix binary filenames (flat, next to wxc-exec) — Windows.
#[cfg(target_os = "windows")]
pub const REQUIRED_BINARIES: &[&str] = &["nanvixd.exe", "nanvix_rootfs.img", "python3.initrd"];

/// All required NanVix binary filenames (flat, next to lxc-exec) — Linux.
#[cfg(target_os = "linux")]
pub const REQUIRED_BINARIES: &[&str] = &["nanvixd.elf", "nanvix_rootfs.img", "python3.initrd"];

/// NanVix daemon binary name (platform-conditional).
#[cfg(target_os = "windows")]
pub const NANVIXD_BINARY: &str = "nanvixd.exe";

/// NanVix daemon binary name (platform-conditional).
#[cfg(target_os = "linux")]
pub const NANVIXD_BINARY: &str = "nanvixd.elf";

/// Multi-binary initrd (daemons + CPython) loaded by NanVix at warm start.
pub const INITRD_BINARY: &str = "python3.initrd";

/// Combined rootfs image (NanVix kernel userspace + CPython stdlib).
pub const RAMFS_IMAGE: &str = "nanvix_rootfs.img";

/// Pre-built VM state snapshot (CBOR) for warm start (Windows/WHP only).
pub const SNAPSHOT_CBOR: &str = "kernel.whp.cbor";

/// Pre-built VM memory snapshot for warm start (Windows/WHP only).
pub const SNAPSHOT_VMEM: &str = "kernel.vmem";

/// Subdirectory holding kernel binary (nanvixd expects `./bin/kernel.elf`).
pub const BIN_SUBDIR: &str = "bin";

/// Subdirectory holding WHP snapshot files.
pub const SNAPSHOTS_SUBDIR: &str = "snapshots";

/// Files that live in a `bin/` subdirectory (nanvixd expects ./bin/kernel.elf).
pub const BIN_SUBDIR_FILES: &[&str] = &["kernel.elf"];

/// Snapshot files that live in a `snapshots/` subdirectory next to the exe.
pub const SNAPSHOT_FILES: &[&str] = &[SNAPSHOT_VMEM, SNAPSHOT_CBOR];

/// Binaries sourced from the `nanvix/nanvix-python` GitHub release.
pub const NANVIX_PYTHON_REPO_BINARIES: &[&str] = REQUIRED_BINARIES;

/// Number of bytes to retain from the end of nanvixd stderr when capturing
/// it for diagnostics. Bounds host memory growth in the face of an
/// untrusted/verbose child (availability / DoS hardening).
pub const STDERR_TAIL_BYTES: usize = 8 * 1024;

/// Render a bounded tail of nanvixd stderr bytes as a UTF-8 string,
/// prefixed with `...(truncated)` when truncation occurred.
///
/// `bytes` may be the full stderr buffer (post-hoc trim) or a buffer that
/// the caller already capped while streaming. The `truncated` flag tells
/// us that streaming-time bytes were dropped even when the resulting
/// buffer length is at or below [`STDERR_TAIL_BYTES`].
pub fn format_stderr_tail(bytes: &[u8], truncated: bool) -> String {
    if bytes.len() > STDERR_TAIL_BYTES {
        // Trim at the byte level *before* UTF-8 decoding. Slicing into the
        // `String` produced by `from_utf8_lossy` would panic if the byte
        // offset fell inside a multi-byte codepoint; `from_utf8_lossy` on
        // a raw byte slice tolerates a partial leading codepoint by
        // emitting U+FFFD replacement characters instead.
        let start = bytes.len() - STDERR_TAIL_BYTES;
        let tail = String::from_utf8_lossy(&bytes[start..]);
        format!("...(truncated){}", tail)
    } else if truncated {
        let text = String::from_utf8_lossy(bytes);
        format!("...(truncated){}", text)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// Drain `reader` to completion, retaining only the last
/// [`STDERR_TAIL_BYTES`] bytes. Returns `(tail, truncated)` where
/// `truncated` is set when any earlier bytes were dropped.
///
/// Used to bound host memory growth when capturing nanvixd stderr from a
/// potentially untrusted / verbose child (availability / DoS hardening).
/// Read errors terminate the drain and return whatever was captured so
/// far; this mirrors `read_to_end` failure semantics for our use case
/// where stderr is best-effort diagnostic data.
pub fn drain_stderr_tail<R: std::io::Read>(mut reader: R) -> (Vec<u8>, bool) {
    let mut tail: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8 * 1024];
    let mut truncated = false;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                tail.extend_from_slice(&chunk[..n]);
                if tail.len() > STDERR_TAIL_BYTES {
                    let drop = tail.len() - STDERR_TAIL_BYTES;
                    tail.drain(..drop);
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    (tail, truncated)
}

/// Release configuration loaded from `versions.json`.
#[derive(Debug, Deserialize)]
pub struct ReleaseConfig {
    /// Configuration for the `nanvix/nanvix-python` GitHub repo.
    pub nanvix_python: RepoConfig,
}

/// Configuration for a single upstream GitHub repo release.
#[derive(Debug, Deserialize)]
pub struct RepoConfig {
    /// Git tag of the pinned release (e.g., "v0.12.291").
    pub tag: String,
    /// Exact filename of the zip asset in the GitHub release (Windows).
    pub asset: String,
    /// Exact filename of the tar.gz asset in the GitHub release (Linux).
    #[serde(default)]
    pub asset_linux: Option<String>,
    /// List of binary filenames to extract from the zip (Windows).
    pub binaries: Vec<String>,
    /// List of binary filenames to extract from the tar.gz (Linux).
    #[serde(default)]
    pub binaries_linux: Option<Vec<String>>,
}

/// Load and deserialize a JSON file.
pub fn load_json<T: serde::de::DeserializeOwned>(path: &str) -> T {
    let content = std::fs::read_to_string(Path::new(path))
        .unwrap_or_else(|e| panic!("nanvix_common: failed to read {}: {}", path, e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("nanvix_common: failed to parse {}: {}", path, e))
}

/// Load checksums from `checksums.json`.
///
/// The file is a platform-keyed map of the form
/// `{ "windows": { "name": "hash", ... }, "linux": { ... } }`; `platform`
/// selects which sub-map to return.
pub fn load_checksums(path: &str, platform: &str) -> HashMap<String, String> {
    let mut value: HashMap<String, HashMap<String, String>> = load_json(path);
    value.remove(platform).unwrap_or_else(|| {
        panic!(
            "nanvix_common: {} does not contain a '{}' section",
            path, platform
        )
    })
}

/// Construct a deterministic GitHub release download URL.
///
/// Format: `https://github.com/{repo}/releases/download/{tag}/{asset}`
pub fn github_download_url(repo: &str, tag: &str, asset: &str) -> String {
    format!(
        "https://github.com/{}/releases/download/{}/{}",
        repo, tag, asset
    )
}

/// Generate WHP snapshots by cold-booting nanvixd.
///
/// `snapshot_home` is used as the process working directory. nanvixd writes
/// snapshot files to `<cwd>/snapshots/`, so the resulting files end up at
/// `<snapshot_home>/snapshots/kernel.vmem` and `kernel.whp.cbor`.
///
/// `bin_dir` is the directory containing `kernel.elf` (passed as `-bin-dir`).
///
/// Returns `Ok(())` on success. On failure, returns a human-readable error
/// message suitable for both build scripts (which panic) and runtime callers
/// (which wrap in their own error type).
pub fn generate_snapshot(
    snapshot_home: &Path,
    nanvixd: &Path,
    bin_dir: &Path,
    ramfs: &Path,
    initrd: &Path,
) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let output = Command::new(nanvixd)
        .current_dir(snapshot_home)
        .arg("-bin-dir")
        .arg(bin_dir)
        .arg("-ramfs")
        .arg(ramfs)
        .arg("-kernel-args")
        .arg("snapshot")
        .arg("--")
        .arg(initrd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("failed to run nanvixd for snapshot generation: {}", e))?;

    if !output.status.success() {
        // Include a bounded tail of stderr so callers (build script panic
        // or runtime preflight error) can surface actionable diagnostics
        // without growing host memory unboundedly.
        let tail = format_stderr_tail(&output.stderr, false);
        let trimmed = tail.trim_end();
        if trimmed.is_empty() {
            return Err(format!(
                "snapshot generation failed (exit code: {})",
                output.status
            ));
        }
        return Err(format!(
            "snapshot generation failed (exit code: {})\nnanvixd stderr:\n{}",
            output.status, trimmed
        ));
    }

    let snap_dir = snapshot_home.join(SNAPSHOTS_SUBDIR);
    for name in SNAPSHOT_FILES {
        if !snap_dir.join(name).exists() {
            return Err(format!(
                "snapshot generation completed but '{}' not found in {:?}",
                name, snap_dir
            ));
        }
    }

    Ok(())
}

/// Category of a staged NanVix artifact.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArtifactKind {
    /// Flat binary next to the executable (e.g. `nanvixd.exe`).
    Binary,
    /// File under the `bin/` subdirectory (e.g. `bin/kernel.elf`).
    BinFile,
    /// WHP warm-start snapshot under `snapshots/` (used by the Windows runner).
    Snapshot,
}

/// Relative paths (from the nanvix binary directory) of every artifact the
/// backend stages, paired with its [`ArtifactKind`].
///
/// This is the single source of truth that drives both copying
/// ([`copy_artifacts_to_target`]) and `cargo:rerun-if-changed` emission
/// ([`emit_rerun_for_copied_artifacts`]) so the two can never drift apart.
pub fn artifact_rel_paths() -> Vec<(ArtifactKind, PathBuf)> {
    let mut paths = Vec::new();
    for name in REQUIRED_BINARIES {
        paths.push((ArtifactKind::Binary, PathBuf::from(name)));
    }
    for name in BIN_SUBDIR_FILES {
        paths.push((ArtifactKind::BinFile, Path::new(BIN_SUBDIR).join(name)));
    }
    for name in SNAPSHOT_FILES {
        paths.push((
            ArtifactKind::Snapshot,
            Path::new(SNAPSHOTS_SUBDIR).join(name),
        ));
    }
    paths
}

/// Copy NanVix artifacts from the build cache (`src_dir`) to the target
/// directory next to the output executable.
///
/// Binaries and `bin/` files are copied whenever the source exists (the build
/// script only re-runs when a tracked input changed, so this is not a
/// per-build cost — and a modification-time comparison would silently skip a
/// legitimate override or rollback to an older cache).
///
/// `trust_snapshots` governs WHP warm-start snapshots, which are **not**
/// covered by `checksums.json` (they are normally host-generated, not pinned
/// release artifacts):
/// - `true` (normal online build, snapshots produced locally): snapshots are
///   mirrored — present ones are copied and target snapshots absent from the
///   source are purged, so a stale warm-start image is never used against
///   mismatched binaries.
/// - `false` (source is an externally supplied `NANVIX_BIN` prefetch dir):
///   snapshots are never copied and any stale target snapshot is removed, so
///   the runtime falls back to a verified cold boot instead of warm-booting an
///   unverified VM memory image.
pub fn copy_artifacts_to_target(src_dir: &Path, target_dir: &Path, trust_snapshots: bool) {
    use std::fs;

    for (kind, rel) in artifact_rel_paths() {
        let src = src_dir.join(&rel);
        let dst = target_dir.join(&rel);

        // Snapshots from an untrusted (prefetched) source are never copied; we
        // must also guarantee no stale snapshot is left behind so the runtime
        // does not warm-boot an unverified image.
        if kind == ArtifactKind::Snapshot && !trust_snapshots {
            remove_stale_snapshot(&dst);
            continue;
        }

        if src.exists() {
            if let Some(parent) = dst.parent() {
                let _ = fs::create_dir_all(parent);
            }
            eprintln!("nanvix: copying {} -> {}", src.display(), dst.display());
            if let Err(e) = fs::copy(&src, &dst) {
                // Never leave a partial/stale file behind.
                if kind == ArtifactKind::Snapshot {
                    remove_stale_snapshot(&dst);
                    panic!("nanvix: failed to copy {}: {}", rel.display(), e);
                }
                let _ = fs::remove_file(&dst);
                eprintln!("nanvix: WARNING: failed to copy {}: {}", rel.display(), e);
            }
        } else if kind == ArtifactKind::Snapshot {
            // Trusted source is missing this snapshot — purge any stale target
            // copy so an incomplete set forces a clean cold boot.
            remove_stale_snapshot(&dst);
        }
    }
}

/// Remove a target snapshot file if present, failing the build if it cannot be
/// removed. A leftover stale snapshot would be warm-booted by the runner
/// (which trusts a complete exe-side snapshot set on presence alone) against
/// mismatched binaries, so a failure here must not be swallowed.
fn remove_stale_snapshot(dst: &Path) {
    if dst.exists() {
        eprintln!(
            "nanvix: removing stale {} (absent or untrusted in source)",
            dst.display()
        );
        if let Err(e) = std::fs::remove_file(dst) {
            panic!(
                "nanvix: failed to remove stale snapshot {}: {} — refusing to \
                 leave an unverified warm-start image that would be booted \
                 against mismatched binaries",
                dst.display(),
                e
            );
        }
    }
}

/// Emit `cargo:rerun-if-changed` for every artifact that
/// [`copy_artifacts_to_target`] reads from `src_dir`. Call this from a
/// consuming crate's build script so the copy reruns when the source contents
/// change in place — for example when an offline `NANVIX_BIN` prefetch
/// directory is updated at the same path. Without it, the consumer only reruns
/// when the source *path* changes, leaving stale artifacts next to the exe.
pub fn emit_rerun_for_copied_artifacts(src_dir: &Path) {
    for (_, rel) in artifact_rel_paths() {
        println!("cargo:rerun-if-changed={}", src_dir.join(rel).display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_stderr_tail_short_buffer_no_prefix() {
        let out = format_stderr_tail(b"hello", false);
        assert_eq!(out, "hello");
    }

    #[test]
    fn format_stderr_tail_short_buffer_with_truncated_flag() {
        let out = format_stderr_tail(b"hello", true);
        assert_eq!(out, "...(truncated)hello");
    }

    #[test]
    fn format_stderr_tail_trims_oversized_ascii_buffer() {
        let big = vec![b'A'; STDERR_TAIL_BYTES + 16];
        let out = format_stderr_tail(&big, false);
        assert!(out.starts_with("...(truncated)"));
        // 14 chars for the prefix + STDERR_TAIL_BYTES trailing ASCII bytes.
        assert_eq!(out.len(), "...(truncated)".len() + STDERR_TAIL_BYTES);
    }

    /// Regression test for PR review comment r3283559877: an oversized
    /// buffer containing multi-byte UTF-8 must not panic when the
    /// truncation byte offset falls inside a codepoint.
    #[test]
    fn format_stderr_tail_oversized_multibyte_does_not_panic() {
        // 4-byte UTF-8 emoji repeated until well past the cap.
        let unit = "🦀"; // 4 bytes
        let repeats = (STDERR_TAIL_BYTES / unit.len()) + 64;
        let big = unit.repeat(repeats).into_bytes();
        assert!(big.len() > STDERR_TAIL_BYTES);
        let out = format_stderr_tail(&big, false);
        assert!(out.starts_with("...(truncated)"));
        // Ensure the result is still valid UTF-8 (String guarantees this);
        // partial leading codepoints become U+FFFD via `from_utf8_lossy`.
        assert!(out.len() >= "...(truncated)".len());
    }

    #[test]
    fn format_stderr_tail_oversized_with_truncated_flag_uses_byte_trim() {
        // When the buffer is oversized, the explicit `truncated` flag
        // should not change behavior — byte-level trim still applies.
        let big = vec![b'B'; STDERR_TAIL_BYTES + 1];
        let out = format_stderr_tail(&big, true);
        assert!(out.starts_with("...(truncated)"));
        assert_eq!(out.len(), "...(truncated)".len() + STDERR_TAIL_BYTES);
    }

    // -- copy_artifacts_to_target snapshot handling --------------------------

    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Create a unique, empty scratch directory under the OS temp dir.
    fn scratch(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "nanvix_copy_test_{}_{}_{}",
            tag,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_snapshot(root: &Path, name: &str, contents: &[u8]) {
        let dir = root.join(SNAPSHOTS_SUBDIR);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(name), contents).unwrap();
    }

    fn snapshot_path(root: &Path, name: &str) -> PathBuf {
        root.join(SNAPSHOTS_SUBDIR).join(name)
    }

    #[test]
    fn trusted_source_lacking_snapshot_purges_stale_target() {
        let src = scratch("purge_src");
        let target = scratch("purge_tgt");
        // Target has both snapshots; source has none.
        write_snapshot(&target, SNAPSHOT_VMEM, b"stale-vmem");
        write_snapshot(&target, SNAPSHOT_CBOR, b"stale-cbor");

        copy_artifacts_to_target(&src, &target, /* trust_snapshots = */ true);

        assert!(!snapshot_path(&target, SNAPSHOT_VMEM).exists());
        assert!(!snapshot_path(&target, SNAPSHOT_CBOR).exists());

        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&target).ok();
    }

    #[test]
    fn trusted_source_with_snapshots_copies_into_target() {
        let src = scratch("copy_src");
        let target = scratch("copy_tgt");
        write_snapshot(&src, SNAPSHOT_VMEM, b"new-vmem");
        write_snapshot(&src, SNAPSHOT_CBOR, b"new-cbor");

        copy_artifacts_to_target(&src, &target, true);

        assert_eq!(
            fs::read(snapshot_path(&target, SNAPSHOT_VMEM)).unwrap(),
            b"new-vmem"
        );
        assert_eq!(
            fs::read(snapshot_path(&target, SNAPSHOT_CBOR)).unwrap(),
            b"new-cbor"
        );

        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&target).ok();
    }

    #[test]
    fn trusted_partial_source_copies_present_and_purges_absent() {
        let src = scratch("partial_src");
        let target = scratch("partial_tgt");
        // Source has only vmem; target starts with both.
        write_snapshot(&src, SNAPSHOT_VMEM, b"fresh-vmem");
        write_snapshot(&target, SNAPSHOT_VMEM, b"old-vmem");
        write_snapshot(&target, SNAPSHOT_CBOR, b"old-cbor");

        copy_artifacts_to_target(&src, &target, true);

        // Present-in-source file is overwritten; absent-in-source file purged.
        assert_eq!(
            fs::read(snapshot_path(&target, SNAPSHOT_VMEM)).unwrap(),
            b"fresh-vmem"
        );
        assert!(!snapshot_path(&target, SNAPSHOT_CBOR).exists());

        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&target).ok();
    }

    #[test]
    fn untrusted_source_never_copies_snapshots_and_purges_target() {
        let src = scratch("untrusted_src");
        let target = scratch("untrusted_tgt");
        // Source ships snapshots, but they are untrusted (prefetched).
        write_snapshot(&src, SNAPSHOT_VMEM, b"attacker-vmem");
        write_snapshot(&src, SNAPSHOT_CBOR, b"attacker-cbor");
        // Target has stale snapshots from a prior build.
        write_snapshot(&target, SNAPSHOT_VMEM, b"stale-vmem");
        write_snapshot(&target, SNAPSHOT_CBOR, b"stale-cbor");

        copy_artifacts_to_target(&src, &target, /* trust_snapshots = */ false);

        // Untrusted snapshots are neither copied nor left behind.
        assert!(!snapshot_path(&target, SNAPSHOT_VMEM).exists());
        assert!(!snapshot_path(&target, SNAPSHOT_CBOR).exists());

        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&target).ok();
    }
}
