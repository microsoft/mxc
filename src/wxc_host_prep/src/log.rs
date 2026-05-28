// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Best-effort JSON-Lines file log.
//!
//! One record per invocation, appended to a file. Used by
//! `prepare-null-device` so debugging a misbehaving box from the
//! scheduled-task history doesn't require Procmon. Failure to write
//! the log never blocks the actual ACL operation — we cannot afford
//! to make a logging error cause an apply failure, because the log
//! is itself a debugging aid for failed applies.
//!
//! Path defaults:
//!
//! * `prepare-null-device`: `%ProgramData%\mxc\null-device-acl.log`
//! * `prepare-system-drive`: no log file (output goes to stdout/stderr;
//!   the operation is interactive enough that the user sees it).
//!
//! A simple 1 MB rotation is implemented: when the file exceeds the
//! threshold, it's renamed to `<file>.1` (overwriting any previous
//! backup) and a fresh file starts. One generation kept; older history
//! is discarded — sufficient for a single-box debug session, and
//! intentionally dumb (no log shipping, no compression, no enterprise
//! deployment story).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Default log location for null-device operations.
pub fn default_null_device_log_path() -> PathBuf {
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    program_data.join("mxc").join("null-device-acl.log")
}

/// Append `line` to `path`, rotating at 1 MB. Errors are swallowed —
/// the caller must not rely on log durability.
pub fn append_jsonl(path: &Path, line: &str) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    rotate_if_oversize(path);

    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

const ROTATE_THRESHOLD_BYTES: u64 = 1_048_576; // 1 MiB

fn rotate_if_oversize(path: &Path) {
    let Ok(meta) = fs::metadata(path) else {
        return; // file doesn't exist yet; nothing to rotate
    };
    if meta.len() <= ROTATE_THRESHOLD_BYTES {
        return;
    }
    let backup = {
        let mut p = path.to_path_buf();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        p.set_file_name(format!("{name}.1"));
        p
    };
    // Best-effort: ignore errors. If rename fails the next append just
    // keeps growing the file, which is benign.
    let _ = fs::remove_file(&backup);
    let _ = fs::rename(path, &backup);
}
