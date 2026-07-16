// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Canonical host-path resolution ("full alias canonicalization").
//!
//! The lexical path folding used by backend overlap checks (e.g. WSLC's
//! `validate_denied_path_overlap`) collapses `.`/`..` and case, but cannot see
//! *on-disk* aliases: a symlink, junction, 8.3 short name, or `\\?\` prefix that
//! redirects one path into another tree only diverges once the OS resolves it.
//! [`canonicalize_path`] opens the object and asks Windows for its final path
//! ([`GetFinalPathNameByHandleW`]), collapsing every such alias to one canonical
//! DOS spelling that callers can compare structurally.
//!
//! Like [`crate::filesystem_object`] this does file I/O, so it lives in
//! `wxc_common` and is invoked by backend runners close to the point of
//! enforcement. A path that exists but cannot be resolved is reported as
//! [`PathCanonical::Unknown`] (distinct from a cleanly-missing
//! [`PathCanonical::Absent`]) so callers can **fail closed** when `deniedPaths`
//! are present rather than fall back to a weaker textual compare.

/// Result of resolving a host path to its canonical on-disk form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathCanonical {
    /// Resolved to a canonical DOS path with aliases (symlinks, junctions, 8.3
    /// names, `\\?\` prefixes) collapsed.
    Canonical(String),
    /// Cleanly missing — no object exists, so there is nothing to alias.
    Absent,
    /// Present (or maybe present) but unresolvable: access denied, I/O error, or
    /// an unsupported build target. Callers fail closed on this when denies apply.
    Unknown,
}

/// Resolve `path` to its canonical on-disk form, collapsing alias spellings.
///
/// Returns [`PathCanonical::Absent`] for a cleanly-missing path and
/// [`PathCanonical::Unknown`] when the object exists but cannot be examined.
#[cfg(windows)]
pub fn canonicalize_path(path: &str) -> PathCanonical {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, HANDLE,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, GetFinalPathNameByHandleW, FILE_FLAG_BACKUP_SEMANTICS, FILE_NAME_NORMALIZED,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GETFINALPATHNAMEBYHANDLE_FLAGS, OPEN_EXISTING, VOLUME_NAME_DOS,
    };

    // RAII guard so the handle is closed on every exit path, including an
    // allocation unwind between the two GetFinalPathNameByHandleW calls.
    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: only constructed from a valid CreateFileW handle.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    // Open without data access; FILE_FLAG_BACKUP_SEMANTICS lets the same call
    // open directories as well as files. SAFETY: `wide` is a local
    // NUL-terminated buffer; all other pointers are NULL.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            share,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    };
    let handle = match handle {
        Ok(h) if !h.is_invalid() => OwnedHandle(h),
        _ => {
            // Distinguish a cleanly-missing path from an unexaminable one.
            // SAFETY: reads the thread-local last error set by the failed call.
            let err = unsafe { GetLastError() };
            return if err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND {
                PathCanonical::Absent
            } else {
                PathCanonical::Unknown
            };
        }
    };

    let flags = GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0);
    // Probe the required length (incl. NUL) with an empty buffer, then fetch.
    // SAFETY: `handle.0` is valid; an empty slice is a valid zero-length buffer.
    let needed = unsafe { GetFinalPathNameByHandleW(handle.0, &mut [], flags) };
    if needed == 0 {
        return PathCanonical::Unknown;
    }

    let mut buf = vec![0u16; needed as usize];
    // SAFETY: `handle.0` is valid; `buf` holds `needed` elements.
    let written = unsafe { GetFinalPathNameByHandleW(handle.0, &mut buf, flags) };
    // 0 = failure; `>= len` means the path grew between calls (race) — treat
    // either as unresolvable rather than returning a truncated path.
    if written == 0 || written as usize >= buf.len() {
        return PathCanonical::Unknown;
    }

    let resolved = String::from_utf16_lossy(&buf[..written as usize]);
    PathCanonical::Canonical(strip_extended_prefix(&resolved))
}

/// Non-Windows builds have no final-path resolution; report every existing path
/// as unresolvable so callers fail closed when `deniedPaths` are present.
#[cfg(not(windows))]
pub fn canonicalize_path(_path: &str) -> PathCanonical {
    PathCanonical::Unknown
}

/// Like [`canonicalize_path`] but tolerates a not-yet-created leaf: when the
/// full path is missing it resolves the deepest existing ancestor (collapsing
/// its aliases) and re-appends the missing components. This lets callers compare
/// a denied path that does not exist yet but whose parent is an alias
/// (symlink/junction) into a mounted tree. Mirrors the bubblewrap runner's
/// `resolve_through_symlinks`. Returns [`PathCanonical::Absent`] only when no
/// ancestor resolves.
#[cfg(windows)]
pub fn canonicalize_allowing_absent_tail(path: &str) -> PathCanonical {
    use std::path::{Path, PathBuf};

    match canonicalize_path(path) {
        PathCanonical::Canonical(resolved) => return PathCanonical::Canonical(resolved),
        PathCanonical::Unknown => return PathCanonical::Unknown,
        PathCanonical::Absent => {}
    }

    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    let mut cur = Path::new(path);
    while let Some(parent) = cur.parent() {
        if let Some(name) = cur.file_name() {
            tail.push(name);
        }
        match canonicalize_path(&parent.to_string_lossy()) {
            PathCanonical::Canonical(base) => {
                let mut result = PathBuf::from(base);
                result.extend(tail.iter().rev());
                return PathCanonical::Canonical(result.to_string_lossy().into_owned());
            }
            PathCanonical::Unknown => return PathCanonical::Unknown,
            PathCanonical::Absent => {}
        }
        cur = parent;
    }
    PathCanonical::Absent
}

/// Non-Windows stub — see the [`canonicalize_path`] non-Windows variant.
#[cfg(not(windows))]
pub fn canonicalize_allowing_absent_tail(_path: &str) -> PathCanonical {
    PathCanonical::Unknown
}

/// Strip a Win32 extended-length prefix from a canonical path:
/// `\\?\C:\dir` → `C:\dir`, `\\?\UNC\server\share` → `\\server\share`.
#[cfg(windows)]
fn strip_extended_prefix(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn strip_prefix_drive() {
        assert_eq!(strip_extended_prefix(r"\\?\C:\dir\file"), r"C:\dir\file");
    }

    #[cfg(windows)]
    #[test]
    fn strip_prefix_unc() {
        assert_eq!(
            strip_extended_prefix(r"\\?\UNC\server\share\file"),
            r"\\server\share\file"
        );
    }

    #[cfg(windows)]
    #[test]
    fn strip_prefix_absent_is_passthrough() {
        assert_eq!(strip_extended_prefix(r"C:\dir"), r"C:\dir");
    }

    #[cfg(windows)]
    #[test]
    fn canonicalizes_existing_dir() {
        let dir = std::env::temp_dir();
        let dir = dir.to_string_lossy();
        match canonicalize_path(&dir) {
            PathCanonical::Canonical(resolved) => {
                // The resolved form carries no extended prefix and names a drive.
                assert!(!resolved.starts_with(r"\\?\"), "{resolved}");
                assert!(resolved.contains(':'), "{resolved}");
            }
            other => panic!("expected Canonical for temp dir, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn missing_path_is_absent() {
        let missing = format!(r"C:\mxc-canonical-nonexistent-{}\child", std::process::id());
        assert_eq!(canonicalize_path(&missing), PathCanonical::Absent);
    }

    #[cfg(windows)]
    #[test]
    fn absent_tail_resolves_under_existing_ancestor() {
        // An existing directory with a not-yet-created child: the leaf is
        // Absent to `canonicalize_path` but the tail-tolerant resolver returns
        // the canonical ancestor with the missing child re-appended.
        let dir = std::env::temp_dir();
        let dir = dir.to_string_lossy();
        let child = format!(
            r"{}\mxc-absent-leaf-{}",
            dir.trim_end_matches('\\'),
            std::process::id()
        );
        assert_eq!(canonicalize_path(&child), PathCanonical::Absent);
        match canonicalize_allowing_absent_tail(&child) {
            PathCanonical::Canonical(resolved) => {
                assert!(
                    resolved.ends_with(&format!("mxc-absent-leaf-{}", std::process::id())),
                    "{resolved}"
                );
                assert!(!resolved.starts_with(r"\\?\"), "{resolved}");
            }
            other => panic!("expected Canonical for absent leaf, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn absent_tail_on_missing_drive_is_absent() {
        // No ancestor resolves (drive absent) → Absent, not a spurious Unknown.
        let missing = r"Q:\mxc-no-such-drive\child";
        assert_eq!(
            canonicalize_allowing_absent_tail(missing),
            PathCanonical::Absent
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_is_unknown() {
        assert_eq!(canonicalize_path("/tmp"), PathCanonical::Unknown);
        assert_eq!(
            canonicalize_allowing_absent_tail("/tmp/child"),
            PathCanonical::Unknown
        );
    }
}
