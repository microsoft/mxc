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

/// RAII wrapper closing a `CreateFileW` handle, shared with
/// [`crate::filesystem_object`].
#[cfg(windows)]
pub(crate) struct OwnedHandle(pub(crate) windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: only constructed from a valid CreateFileW handle.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// Classification of a failed [`open_path_for_metadata`].
#[cfg(windows)]
pub(crate) enum OpenClass {
    /// The object does not exist.
    NotFound,
    /// The object exists (or may) but could not be opened; callers fail closed.
    Unexaminable,
}

/// Open the NUL-terminated wide path `wide` for metadata access (no data read).
///
/// Pass `FILE_FLAG_OPEN_REPARSE_POINT` in `extra_flags` to open a reparse point
/// without following it. Shared by [`canonicalize_wide`] and
/// [`crate::filesystem_object`].
#[cfg(windows)]
pub(crate) fn open_path_for_metadata(
    wide: &[u16],
    extra_flags: windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES,
) -> Result<OwnedHandle, OpenClass> {
    use windows::core::{HRESULT, PCWSTR};
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    // `PCWSTR` scans to the first NUL; reject an empty/unterminated slice so the
    // FFI never reads past `wide`.
    if wide.last() != Some(&0) {
        return Err(OpenClass::Unexaminable);
    }
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    // SAFETY: `wide` is NUL-terminated (checked above); other pointers are NULL.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            share,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | extra_flags,
            None,
        )
    };
    match handle {
        Ok(h) if !h.is_invalid() => Ok(OwnedHandle(h)),
        Ok(_) => Err(OpenClass::Unexaminable),
        Err(e) => {
            let code = e.code();
            if code == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0)
                || code == HRESULT::from_win32(ERROR_PATH_NOT_FOUND.0)
            {
                Err(OpenClass::NotFound)
            } else {
                Err(OpenClass::Unexaminable)
            }
        }
    }
}

/// Resolve `path` to its canonical on-disk form, collapsing alias spellings.
/// A dangling reparse point (target missing) returns [`PathCanonical::Unknown`]
/// so callers fail closed.
#[cfg(windows)]
pub fn canonicalize_path(path: &str) -> PathCanonical {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    canonicalize_wide(&wide)
}

/// Resolve a pre-encoded NUL-terminated wide path (see [`canonicalize_path`]);
/// separate so the absent-tail walk can probe ancestors without re-encoding.
#[cfg(windows)]
fn canonicalize_wide(wide: &[u16]) -> PathCanonical {
    use windows::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_NAME_NORMALIZED, GETFINALPATHNAMEBYHANDLE_FLAGS, VOLUME_NAME_DOS,
    };

    let handle = match open_path_for_metadata(wide, FILE_FLAGS_AND_ATTRIBUTES(0)) {
        Ok(h) => h,
        Err(OpenClass::Unexaminable) => return PathCanonical::Unknown,
        Err(OpenClass::NotFound) => {
            // A dangling reparse point also reports NOT_FOUND when followed;
            // re-open it without following — success means it exists (Unknown).
            return match open_path_for_metadata(wide, FILE_FLAG_OPEN_REPARSE_POINT) {
                Ok(_) => PathCanonical::Unknown,
                Err(OpenClass::NotFound) => PathCanonical::Absent,
                Err(OpenClass::Unexaminable) => PathCanonical::Unknown,
            };
        }
    };

    let flags = GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0);
    // Stack buffer covers most paths in one syscall; heap-fallback if longer.
    let mut stack = [0u16; 512];
    // SAFETY: `handle.0` is valid; `stack` is a valid buffer.
    let written = unsafe { GetFinalPathNameByHandleW(handle.0, &mut stack, flags) };
    if written == 0 {
        return PathCanonical::Unknown;
    }
    let resolved = if (written as usize) < stack.len() {
        // Fit: `written` excludes the NUL.
        String::from_utf16_lossy(&stack[..written as usize])
    } else {
        // Too small: `written` includes the NUL; refetch (0 or a grown value = race).
        let mut buf = vec![0u16; written as usize];
        // SAFETY: `handle.0` is valid; `buf` holds `written` elements.
        let n = unsafe { GetFinalPathNameByHandleW(handle.0, &mut buf, flags) };
        if n == 0 || n as usize >= buf.len() {
            return PathCanonical::Unknown;
        }
        String::from_utf16_lossy(&buf[..n as usize])
    };

    PathCanonical::Canonical(strip_extended_prefix(&resolved).into_owned())
}

/// Non-Windows builds have no final-path resolution; report every existing path
/// as unresolvable so callers fail closed when `deniedPaths` are present.
#[cfg(not(windows))]
pub fn canonicalize_path(_path: &str) -> PathCanonical {
    PathCanonical::Unknown
}

/// Like [`canonicalize_path`] but tolerates a not-yet-created leaf: it resolves
/// the deepest existing ancestor and replays the missing tail (folding `.`/`..`)
/// onto it, so a denied path whose parent is an alias into a mounted tree is
/// still comparable. Returns [`PathCanonical::Absent`] only when no ancestor
/// resolves.
///
/// The path is UTF-16-encoded once and each ancestor probed by NUL-terminating
/// that buffer in place, so copying is O(depth), not O(depth²).
#[cfg(windows)]
pub fn canonicalize_allowing_absent_tail(path: &str) -> PathCanonical {
    let mut wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    // Map each queryable byte-offset (a char boundary) to its index in `wide`.
    let mut byte_to_u16: Vec<(usize, usize)> = Vec::with_capacity(path.len() + 1);
    let mut u = 0usize;
    for (bi, ch) in path.char_indices() {
        byte_to_u16.push((bi, u));
        u += ch.len_utf16();
    }
    byte_to_u16.push((path.len(), u));
    let total_u16 = u;

    let resolve = |prefix: &str| -> PathCanonical {
        let idx = byte_to_u16
            .binary_search_by_key(&prefix.len(), |&(b, _)| b)
            .map(|i| byte_to_u16[i].1)
            .unwrap_or(total_u16);
        let saved = wide[idx];
        wide[idx] = 0;
        let r = canonicalize_wide(&wide[..=idx]);
        wide[idx] = saved;
        r
    };
    canonicalize_allowing_absent_tail_with(path, resolve)
}

/// Non-Windows: every path resolves `Unknown`, so the walk short-circuits.
#[cfg(not(windows))]
pub fn canonicalize_allowing_absent_tail(path: &str) -> PathCanonical {
    canonicalize_allowing_absent_tail_with(path, canonicalize_path)
}

/// Platform-independent core of [`canonicalize_allowing_absent_tail`] with an
/// injected `resolve` (deepest ancestor first, then tail replay). Splitting the
/// resolver out lets the fold logic be unit-tested cross-platform without disk.
pub fn canonicalize_allowing_absent_tail_with(
    path: &str,
    mut resolve: impl FnMut(&str) -> PathCanonical,
) -> PathCanonical {
    match resolve(path) {
        PathCanonical::Canonical(resolved) => return PathCanonical::Canonical(resolved),
        PathCanonical::Unknown => return PathCanonical::Unknown,
        PathCanonical::Absent => {}
    }

    let (anchor, rest) = split_anchor(path);
    let base_off = path.len() - rest.len();
    // Segment slices of `rest` + the byte offset in `path` where each ends.
    let mut segs: Vec<&str> = Vec::new();
    let mut ends: Vec<usize> = Vec::new();
    let rb = rest.as_bytes();
    let is_sep = |c: u8| c == b'\\' || c == b'/';
    let mut i = 0usize;
    while i < rb.len() {
        while i < rb.len() && is_sep(rb[i]) {
            i += 1;
        }
        let start = i;
        while i < rb.len() && !is_sep(rb[i]) {
            i += 1;
        }
        if i > start {
            segs.push(&rest[start..i]);
            ends.push(base_off + i);
        }
    }

    // Deepest existing ancestor first; k = 0 is the bare anchor.
    let n = segs.len();
    for k in (0..n).rev() {
        let ancestor: &str = if k == 0 { anchor } else { &path[..ends[k - 1]] };
        if ancestor.is_empty() {
            continue;
        }
        match resolve(ancestor) {
            PathCanonical::Canonical(base) => {
                return PathCanonical::Canonical(fold_tail(&base, &segs[k..]));
            }
            PathCanonical::Unknown => return PathCanonical::Unknown,
            PathCanonical::Absent => {}
        }
    }
    PathCanonical::Absent
}

/// Split a Windows path into its anchor (drive root `C:\`, UNC share
/// `\\server\share\`, or leading separators) and the remainder.
fn split_anchor(path: &str) -> (&str, &str) {
    let b = path.as_bytes();
    let is_sep = |c: u8| c == b'\\' || c == b'/';
    // UNC: \\server\share
    if b.len() >= 2 && is_sep(b[0]) && is_sep(b[1]) {
        let mut i = 2;
        while i < b.len() && !is_sep(b[i]) {
            i += 1; // server
        }
        while i < b.len() && is_sep(b[i]) {
            i += 1;
        }
        while i < b.len() && !is_sep(b[i]) {
            i += 1; // share
        }
        while i < b.len() && is_sep(b[i]) {
            i += 1; // trailing separators
        }
        return (&path[..i], &path[i..]);
    }
    // Drive: X:
    if b.len() >= 2 && (b[0] as char).is_ascii_alphabetic() && b[1] == b':' {
        let mut i = 2;
        while i < b.len() && is_sep(b[i]) {
            i += 1;
        }
        return (&path[..i], &path[i..]);
    }
    // Rooted (leading separator run).
    if !b.is_empty() && is_sep(b[0]) {
        let mut i = 0;
        while i < b.len() && is_sep(b[i]) {
            i += 1;
        }
        return (&path[..i], &path[i..]);
    }
    ("", path)
}

/// Replay `tail` onto canonical `base`, folding `.`/`..` (clamped at the anchor).
fn fold_tail(base: &str, tail: &[&str]) -> String {
    let (anchor, rest) = split_anchor(base);
    let mut comps: Vec<&str> = rest.split(['\\', '/']).filter(|s| !s.is_empty()).collect();
    for &seg in tail {
        match seg {
            "." => {}
            ".." => {
                comps.pop();
            }
            other => comps.push(other),
        }
    }
    let mut out = String::with_capacity(base.len() + 16);
    out.push_str(anchor);
    let anchor_has_sep = anchor.ends_with(['\\', '/']);
    for (idx, c) in comps.iter().enumerate() {
        if idx == 0 {
            if !anchor.is_empty() && !anchor_has_sep {
                out.push('\\');
            }
        } else {
            out.push('\\');
        }
        out.push_str(c);
    }
    out
}

/// Strip a Win32 extended-length prefix: `\\?\C:\dir` → `C:\dir`,
/// `\\?\UNC\server\share` → `\\server\share`, `\\?\Volume{…}` → `Volume{…}`.
#[cfg(windows)]
fn strip_extended_prefix(path: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        Cow::Owned(format!(r"\\{rest}"))
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        Cow::Borrowed(rest)
    } else {
        Cow::Borrowed(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(s: &str) -> PathCanonical {
        PathCanonical::Canonical(s.to_string())
    }

    /// Fixed-table resolver (case- and trailing-separator-insensitive like the
    /// real FS); unlisted paths are `Absent`. Exercises the fold without disk.
    fn mock_resolver(
        entries: Vec<(&'static str, PathCanonical)>,
    ) -> impl Fn(&str) -> PathCanonical {
        move |p: &str| {
            let q = p.trim_end_matches(['\\', '/']);
            for (k, v) in &entries {
                if k.trim_end_matches(['\\', '/']).eq_ignore_ascii_case(q) {
                    return v.clone();
                }
            }
            PathCanonical::Absent
        }
    }

    #[test]
    fn seam_folds_dotdot_onto_resolved_ancestor() {
        let resolve = mock_resolver(vec![(r"C:\link", canon(r"C:\real"))]);
        assert_eq!(
            canonicalize_allowing_absent_tail_with(r"C:\link\sub\..\Z", &resolve),
            canon(r"C:\real\Z")
        );
    }

    #[test]
    fn seam_dotdot_clamps_at_anchor() {
        let resolve = mock_resolver(vec![(r"C:\real", canon(r"C:\real"))]);
        assert_eq!(
            canonicalize_allowing_absent_tail_with(r"C:\real\..\..\X", &resolve),
            canon(r"C:\X")
        );
    }

    #[test]
    fn seam_handles_dot_and_interior_dotdot() {
        let resolve = mock_resolver(vec![(r"C:\a", canon(r"C:\a"))]);
        assert_eq!(
            canonicalize_allowing_absent_tail_with(r"C:\a\.\b\..\c", &resolve),
            canon(r"C:\a\c")
        );
    }

    #[test]
    fn seam_unknown_ancestor_fails_closed() {
        let resolve = mock_resolver(vec![(r"C:\a\b", PathCanonical::Unknown)]);
        assert_eq!(
            canonicalize_allowing_absent_tail_with(r"C:\a\b\c\d", &resolve),
            PathCanonical::Unknown
        );
    }

    #[test]
    fn seam_all_absent_is_absent() {
        let resolve = mock_resolver(vec![]);
        assert_eq!(
            canonicalize_allowing_absent_tail_with(r"C:\none\here", &resolve),
            PathCanonical::Absent
        );
    }

    #[test]
    fn seam_full_path_canonical_passthrough() {
        let resolve = mock_resolver(vec![(r"C:\x\y", canon(r"D:\real\y"))]);
        assert_eq!(
            canonicalize_allowing_absent_tail_with(r"C:\x\y", &resolve),
            canon(r"D:\real\y")
        );
    }

    #[test]
    fn seam_unc_anchor_folds() {
        let resolve = mock_resolver(vec![(r"\\srv\share", canon(r"\\srv\share"))]);
        assert_eq!(
            canonicalize_allowing_absent_tail_with(r"\\srv\share\a\..\..\b", &resolve),
            canon(r"\\srv\share\b")
        );
    }

    #[cfg(windows)]
    #[test]
    fn open_path_rejects_unterminated_wide() {
        use windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
        assert!(matches!(
            open_path_for_metadata(&[], FILE_FLAGS_AND_ATTRIBUTES(0)),
            Err(OpenClass::Unexaminable)
        ));
        let unterminated: [u16; 3] = [b'C' as u16, b':' as u16, b'\\' as u16];
        assert!(matches!(
            open_path_for_metadata(&unterminated, FILE_FLAGS_AND_ATTRIBUTES(0)),
            Err(OpenClass::Unexaminable)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn strip_prefix_drive() {
        assert_eq!(
            strip_extended_prefix(r"\\?\C:\dir\file").as_ref(),
            r"C:\dir\file"
        );
    }

    #[cfg(windows)]
    #[test]
    fn strip_prefix_unc() {
        assert_eq!(
            strip_extended_prefix(r"\\?\UNC\server\share\file").as_ref(),
            r"\\server\share\file"
        );
    }

    #[cfg(windows)]
    #[test]
    fn strip_prefix_device_forms() {
        assert_eq!(
            strip_extended_prefix(r"\\?\Volume{12345678-0000-0000-0000-000000000000}\x").as_ref(),
            r"Volume{12345678-0000-0000-0000-000000000000}\x"
        );
        assert_eq!(
            strip_extended_prefix(r"\\?\GLOBALROOT\Device\HarddiskVolume3\x").as_ref(),
            r"GLOBALROOT\Device\HarddiskVolume3\x"
        );
    }

    #[cfg(windows)]
    #[test]
    fn strip_prefix_absent_is_passthrough() {
        assert_eq!(strip_extended_prefix(r"C:\dir").as_ref(), r"C:\dir");
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
        // Pick a genuinely unassigned drive letter at runtime rather than
        // hard-coding one: on a host where the chosen drive exists (mapped
        // network share, USB, subst) the root would resolve and the tail would
        // replay to Canonical, not Absent.
        let Some(free) = first_free_drive_letter() else {
            eprintln!("skipping: no free drive letter available on this host");
            return;
        };
        let missing = format!(r"{free}:\mxc-no-such-drive\child");
        assert_eq!(
            canonicalize_allowing_absent_tail(&missing),
            PathCanonical::Absent
        );
    }

    /// Returns a drive letter (`D`..=`Z`) with no assigned volume, or `None` if
    /// every letter is in use. Skips `A`/`B`/`C` to avoid floppy/system drives.
    #[cfg(windows)]
    fn first_free_drive_letter() -> Option<char> {
        use windows::Win32::Storage::FileSystem::GetLogicalDrives;
        // Bit i (0 = A) is set when that drive letter is assigned.
        let mask = unsafe { GetLogicalDrives() };
        ('D'..='Z').find(|letter| {
            let bit = (*letter as u32) - ('A' as u32);
            mask & (1 << bit) == 0
        })
    }

    #[cfg(windows)]
    #[test]
    fn absent_tail_folds_dotdot_across_aliased_ancestor() {
        // Regression: `sub\..\Z` under a junction must fold to `real\Z`, not
        // `sub\Z`. mklink /J needs no admin, so assert rather than skip.
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("create tempdir");
        let real = tmp.path().join("real");
        let link = tmp.path().join("link");
        std::fs::create_dir_all(&real).unwrap();

        let status = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .status()
            .expect("spawn cmd for mklink");
        assert!(
            status.success(),
            "mklink /J failed (directory junctions require no admin); status={status:?}"
        );

        let denied = format!(r"{}\sub\..\Z", link.display());
        match canonicalize_allowing_absent_tail(&denied) {
            PathCanonical::Canonical(resolved) => {
                let lc = resolved.to_lowercase();
                assert!(
                    lc.ends_with(r"\real\z"),
                    "tail `sub\\..\\Z` must fold to `real\\Z`, got {resolved}"
                );
                assert!(
                    !lc.contains(r"\sub\"),
                    "`..` must cancel `sub`, got {resolved}"
                );
            }
            other => panic!("expected Canonical, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn dangling_junction_fails_closed() {
        // A dangling junction (target deleted) still names an object, so it must
        // fail closed (Unknown), not read as Absent.
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("create tempdir");
        let target = tmp.path().join("target");
        let link = tmp.path().join("dangling");
        std::fs::create_dir_all(&target).unwrap();
        let status = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .status()
            .expect("spawn cmd for mklink");
        assert!(status.success(), "mklink /J failed; status={status:?}");
        std::fs::remove_dir_all(&target).unwrap();

        assert_eq!(
            canonicalize_path(&link.to_string_lossy()),
            PathCanonical::Unknown,
            "a dangling junction must fail closed, not read as Absent"
        );
    }

    #[cfg(windows)]
    #[test]
    fn dangling_junction_ancestor_is_unknown_not_canonical() {
        // Chain-level guard where the security property lives: a deny under a
        // dangling-junction *ancestor* must fail closed, never replay the absent
        // tail onto a resolved grandparent and return Canonical(<path with the
        // junction>) — which the overlap check would then miss.
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("create tempdir");
        let target = tmp.path().join("target");
        let link = tmp.path().join("dangling");
        std::fs::create_dir_all(&target).unwrap();
        let status = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .status()
            .expect("spawn cmd for mklink");
        assert!(status.success(), "mklink /J failed; status={status:?}");
        std::fs::remove_dir_all(&target).unwrap();

        let leaf = link.join("file");
        assert_eq!(
            canonicalize_allowing_absent_tail(&leaf.to_string_lossy()),
            PathCanonical::Unknown,
            "a deny under a dangling-junction ancestor must fail closed, not \
             resolve to a Canonical path still containing the junction"
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
