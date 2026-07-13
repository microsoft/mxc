// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filesystem-policy **delegation check** (roadmap item D3).
//!
//! Enforces that the sandbox is never granted more filesystem access than the
//! invoking user already holds: every `readwritePaths` entry requires the user
//! to have read+write access, and every `readonlyPaths` entry requires read
//! access. `deniedPaths` are unbounded (denying access needs no access) and are
//! not checked. A path the user cannot access is **rejected** so a sandboxed
//! process can't reach files the caller themselves couldn't.
//!
//! This does file I/O (`access(2)` / `CreateFileW`), so it runs
//! in each backend runner **close to the point of enforcement**, NOT in
//! `config_parser` (which stays string-only). Two reasons:
//!
//! - **Correctness:** mount targets may not exist when the config is parsed
//!   (they can be created between parse and launch), so a parse-time check would
//!   skip them; checking just before the backend builds its mounts sees the real
//!   filesystem state.
//! - **TOCTOU:** doing the check adjacent to enforcement shrinks the window in
//!   which the filesystem can change between the check and the mount.
//!
//! When object-based filesystem normalization is also wired into a runner
//! (tightening conflicting path intents to the most restrictive), it must run
//! **first**, so delegation is checked against the already-tightened intents (a
//! path moved `rw → denied` must not then be required to have write access).

use crate::models::ContainerPolicy;

/// The access the invoking user must hold to delegate a path to the sandbox.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AccessMode {
    /// Read access only (for `readonlyPaths`).
    Read,
    /// Read and write access (for `readwritePaths`).
    ReadWrite,
}

impl AccessMode {
    /// The JSON list name this mode maps to, and the access phrase, for the
    /// rejection message.
    fn list_name(self) -> &'static str {
        match self {
            AccessMode::Read => "readonlyPaths",
            AccessMode::ReadWrite => "readwritePaths",
        }
    }

    fn access_phrase(self) -> &'static str {
        match self {
            AccessMode::Read => "read",
            AccessMode::ReadWrite => "read+write",
        }
    }
}

/// Checks whether the invoking user holds the requested access to `path`.
///
/// Returns `Some(true)` / `Some(false)` when the result is determinable, or
/// `None` when it cannot be determined (e.g. the path does not exist — that case
/// is surfaced separately by the existence warning, so delegation skips it).
///
/// On Unix this uses `access(2)`, which checks the requested permissions
/// against the process's **real** UID/GID (the invoking user) and covers both
/// files and directories. This has full effect for **Bubblewrap**, which runs
/// unprivileged.
///
/// Caveat — **root**: `access(2)` short-circuits for the superuser, so `R_OK`
/// (and, on most filesystems, `W_OK`) always succeed for a real UID of 0
/// regardless of the file mode. The **LXC** backend runs as root, so the
/// delegation check is effectively a no-op there; it only has teeth for an
/// unprivileged caller (Bubblewrap). Meaningfully enforcing delegation under a
/// root LXC would require checking against the pre-elevation user (e.g.
/// `SUDO_UID`/`SUDO_GID`) — tracked as a follow-up.
///
/// On Windows it probes the caller's effective access with `CreateFileW`
/// (requesting `GENERIC_READ` / `GENERIC_READ | GENERIC_WRITE`, opened with
/// `FILE_FLAG_BACKUP_SEMANTICS` so directories are covered too). A successful
/// open means the access is granted. Matching the Unix posture, the check
/// **fails closed**: only a genuinely missing path (`ERROR_FILE_NOT_FOUND` /
/// `ERROR_PATH_NOT_FOUND` — surfaced separately by the existence warning) is
/// skipped (`None`); every other failure, including `ERROR_ACCESS_DENIED` and
/// ambiguous errors (sharing/lock violation, transient I/O), is treated as
/// "cannot confirm access" and rejected (`Some(false)`) rather than silently
/// allowed. This covers files *and* directories — including the common WSLC
/// `readwritePaths` directory case — implementing spec D3 for the WSLC backend.
#[cfg(unix)]
fn user_can_access(path: &str, mode: AccessMode) -> Option<bool> {
    use std::ffi::CString;

    let c_path = CString::new(path).ok()?;
    let mask = match mode {
        AccessMode::Read => libc::R_OK,
        AccessMode::ReadWrite => libc::R_OK | libc::W_OK,
    };
    // SAFETY: `c_path` is a valid NUL-terminated C string for the duration of the call.
    let rc = unsafe { libc::access(c_path.as_ptr(), mask) };
    if rc == 0 {
        return Some(true);
    }
    // access(2) failed. Distinguish genuine non-existence — which is skipped
    // here and surfaced separately by the existence warning — from an access
    // denial, which is the exact case delegation must catch (including a parent
    // directory the caller cannot traverse, reported as EACCES). Only a missing
    // path yields `None`; every other errno is treated as "not accessible".
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOENT) | Some(libc::ENOTDIR) => None,
        _ => Some(false),
    }
}

#[cfg(windows)]
fn user_can_access(path: &str, mode: AccessMode) -> Option<bool> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GENERIC_READ,
        GENERIC_WRITE,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    // Probe the caller's effective access by asking the OS to open the object
    // with the required rights. FILE_FLAG_BACKUP_SEMANTICS lets the same call
    // open directories as well as files, so — unlike a plain `File::open` — this
    // covers directory WRITE access (mapped by the OS to FILE_ADD_FILE /
    // FILE_ADD_SUBDIRECTORY), which is the common WSLC `readwritePaths` case.
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let desired = match mode {
        AccessMode::Read => GENERIC_READ.0,
        AccessMode::ReadWrite => GENERIC_READ.0 | GENERIC_WRITE.0,
    };
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    // SAFETY: `wide` is a local NUL-terminated buffer; all other pointers are NULL.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            desired,
            share,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    };
    match handle {
        Ok(h) if !h.is_invalid() => {
            // SAFETY: `h` is a valid handle returned by CreateFileW.
            unsafe {
                let _ = CloseHandle(h);
            }
            Some(true)
        }
        _ => {
            // Fail closed, mirroring the Unix posture: skip ONLY a genuinely
            // missing path (surfaced separately by the existence warning). Every
            // other failure — access denied, sharing/lock violation, transient
            // I/O — means we cannot confirm the caller has the access, which for
            // a security delegation gate must reject rather than silently allow.
            // SAFETY: reads the thread-local last error set by the failed call above.
            let err = unsafe { GetLastError() };
            if err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND {
                None
            } else {
                Some(false)
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn user_can_access(_path: &str, _mode: AccessMode) -> Option<bool> {
    None
}

/// Validates the delegation constraint (spec D3): the sandbox receives no more
/// access than the invoking user holds. `readwritePaths` require the user to
/// have read+write access and `readonlyPaths` require read access; `deniedPaths`
/// are unbounded and not checked. Paths whose access cannot be determined (e.g.
/// non-existent paths) are skipped rather than rejected.
///
/// Returns the rejection message for the first path that fails, or `Ok(())` when
/// every checkable path is within the caller's access. Callers surface the
/// message as their backend-appropriate error (e.g. `ScriptResponse::error`).
pub fn check_delegation(policy: &ContainerPolicy) -> Result<(), String> {
    for (paths, mode) in [
        (&policy.readonly_paths, AccessMode::Read),
        (&policy.readwrite_paths, AccessMode::ReadWrite),
    ] {
        for path in paths {
            if user_can_access(path, mode) == Some(false) {
                return Err(format!(
                    "Filesystem path '{}' ({}): the invoking user does not have {} access, \
                     so it cannot be delegated to the sandbox",
                    path,
                    mode.list_name(),
                    mode.access_phrase(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(rw: &[&str], ro: &[&str]) -> ContainerPolicy {
        ContainerPolicy {
            readwrite_paths: rw.iter().map(|s| s.to_string()).collect(),
            readonly_paths: ro.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn accessible_file_is_delegable() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("data.txt");
        std::fs::write(&file, b"test").unwrap();
        let f = file.to_str().unwrap();

        assert_eq!(user_can_access(f, AccessMode::Read), Some(true));
        assert_eq!(user_can_access(f, AccessMode::ReadWrite), Some(true));
        assert!(check_delegation(&policy(&[f], &[])).is_ok());
    }

    #[test]
    fn accessible_directory_is_delegable() {
        // Directory read+write is the common WSLC `readwritePaths` case; it must
        // be enforced on both Unix and Windows.
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();

        assert_eq!(user_can_access(d, AccessMode::Read), Some(true));
        assert_eq!(user_can_access(d, AccessMode::ReadWrite), Some(true));
        assert!(check_delegation(&policy(&[d], &[])).is_ok());
    }

    #[test]
    fn nonexistent_path_is_skipped() {
        // A non-existent path can't be access-checked; delegation skips it
        // (existence is surfaced separately as a warning, not a delegation error).
        assert_eq!(
            user_can_access("/definitely/not/here/mxc-xyz", AccessMode::Read),
            None
        );
        assert!(check_delegation(&policy(&["/definitely/not/here/mxc-xyz"], &[])).is_ok());
    }

    #[test]
    fn empty_policy_is_ok() {
        assert!(check_delegation(&ContainerPolicy::default()).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn ambiguous_error_fails_closed() {
        // A path Windows rejects for a reason OTHER than not-found or
        // access-denied (here an invalid name containing an illegal `<`
        // character → ERROR_INVALID_NAME) must fail closed — `Some(false)` →
        // rejected — not be silently skipped. This locks the Unix/Windows
        // posture alignment: only a genuinely-missing path is skipped; every
        // other failure is treated as "cannot confirm access" and rejected.
        let invalid = "C:\\mxc_invalid<name";
        assert_eq!(user_can_access(invalid, AccessMode::Read), Some(false));
        assert!(check_delegation(&policy(&[], &[invalid])).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_path_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        // Root bypasses permission checks, so this case is only meaningful as a
        // non-root user.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secret.txt");
        std::fs::write(&file, b"secret").unwrap();
        // Remove all permissions so the invoking user cannot read it.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        let f = file.to_str().unwrap();

        assert_eq!(user_can_access(f, AccessMode::Read), Some(false));
        let err = check_delegation(&policy(&[], &[f])).unwrap_err();
        assert!(
            err.contains("does not have read access"),
            "expected delegation rejection, got: {err}"
        );

        // Restore permissions so the tempdir can be cleaned up.
        let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
    }

    #[cfg(unix)]
    #[test]
    fn untraversable_parent_is_rejected_not_skipped() {
        use std::os::unix::fs::PermissionsExt;

        // Root bypasses permission checks, so this case is only meaningful as a
        // non-root user.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        // A readable file inside a directory the caller cannot traverse. The file
        // exists, but reaching it requires execute (traversal) on the parent —
        // which we remove. access(2) then reports EACCES, and the check must
        // treat that as "not accessible" (a real delegation failure), NOT skip it
        // as if the path were missing.
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let file = locked.join("data.txt");
        std::fs::write(&file, b"data").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let f = file.to_str().unwrap();

        assert_eq!(
            user_can_access(f, AccessMode::Read),
            Some(false),
            "an untraversable parent (EACCES) must be reported as inaccessible, not skipped"
        );
        assert!(check_delegation(&policy(&[], &[f])).is_err());

        // Restore traversal so the tempdir can recurse in during cleanup.
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755));
    }

    #[cfg(windows)]
    #[test]
    fn unreadable_path_is_rejected() {
        use std::process::Command;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secret.txt");
        std::fs::write(&file, b"secret").unwrap();
        let f = file.to_str().unwrap();

        // Deny read to Everyone (well-known SID S-1-1-0 — locale/domain
        // independent). A deny ACE blocks FILE_READ_DATA even for the owner
        // (whose implicit rights are only READ_CONTROL / WRITE_DAC), so a
        // GENERIC_READ open must fail with ERROR_ACCESS_DENIED. Parent-dir full
        // control still lets the tempdir delete the child on cleanup.
        let status = Command::new("icacls")
            .args([f, "/deny", "*S-1-1-0:(R)"])
            .output()
            .expect("icacls should run");
        assert!(
            status.status.success(),
            "icacls deny failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );

        assert_eq!(
            user_can_access(f, AccessMode::Read),
            Some(false),
            "a path with an explicit deny-read ACE must be reported as inaccessible"
        );
        let err = check_delegation(&policy(&[], &[f])).unwrap_err();
        assert!(
            err.contains("does not have read access"),
            "expected delegation rejection, got: {err}"
        );

        // Remove the deny ACE so the tempdir can clean up without surprises.
        let _ = Command::new("icacls")
            .args([f, "/remove:d", "*S-1-1-0"])
            .output();
    }
}
