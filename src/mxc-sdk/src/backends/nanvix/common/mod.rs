// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared constants and configuration types for NanVix micro-VM binaries.
//!
//! This crate is the single source of truth for binary filenames, release
//! configuration, and checksum data. It is consumed as a `[build-dependency]`
//! by `nanvix_binaries` (download) and `wxc` (copy to output dir).

use std::collections::HashMap;
use std::path::Path;

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
}
