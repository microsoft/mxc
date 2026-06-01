// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `prepare-system-drive` / `unprepare-system-drive`.
//!
//! Adds (or removes) metadata-only allow ACEs for the well-known
//! AppContainer groups "ALL APPLICATION PACKAGES" (S-1-15-2-1) and
//! "ALL RESTRICTED APPLICATION PACKAGES" (S-1-15-2-2) on the
//! system-drive root.
//!
//! # Why
//!
//! AppContainer processes can't, by default, read metadata of the
//! system-drive root via APIs such as `GetFileAttributesW`, `_stat`,
//! or `[IO.DirectoryInfo]::GetAccessControl`. Common tools (cmd.exe,
//! powershell.exe, pwsh.exe, node.exe) hit these during startup and
//! fail with `ERROR_ACCESS_DENIED` inside an AppContainer. Granting
//! the two AppContainer SIDs a tiny metadata-only access mask on `C:\`
//! unblocks those tools without exposing the contents of the drive.
//!
//! # What we grant
//!
//! Mask: `FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE`
//! (`0x00120088`). This is the metadata-read set used by
//! `GetFileAttributesW`, `_stat`, and `GetAccessControl`. Notably
//! *not* `FILE_LIST_DIRECTORY` (the AppContainer still cannot
//! enumerate `C:\`) and *not* `FILE_READ_DATA`.
//!
//! Inheritance: none. Only the directory object itself is modified;
//! descendant files and subdirectories are unaffected.
//!
//! # Elevation
//!
//! Modifying the DACL on `C:\` requires `WRITE_DAC`, which normal
//! users don't hold. Elevation is declared in the application
//! manifest (`requireAdministrator`) — the OS loader prompts for
//! UAC at process start, and the binary either runs elevated or
//! fails to start. The module entry points below assume the
//! process is already elevated and fail fast otherwise (the
//! defence-in-depth check lives in `crate::elevation_check`).

use std::path::{Path, PathBuf};

use wxc_common::filesystem_dacl::{
    apply_explicit_ace, revoke_specific_aces_for_sid, scan_explicit_aces_for_sid, AceType,
    DaclError,
};

/// Well-known SID for the AppContainer "ALL APPLICATION PACKAGES" group.
const SID_ALL_APP_PACKAGES: &str = "S-1-15-2-1";

/// Well-known SID for the AppContainer "ALL RESTRICTED APPLICATION PACKAGES" group.
const SID_ALL_RESTRICTED_APP_PACKAGES: &str = "S-1-15-2-2";

/// Trustees iterated by [`run_prepare`] / [`run_unprepare`]: (display name, SID string).
const TRUSTEES: &[(&str, &str)] = &[
    ("ALL APPLICATION PACKAGES", SID_ALL_APP_PACKAGES),
    (
        "ALL RESTRICTED APPLICATION PACKAGES",
        SID_ALL_RESTRICTED_APP_PACKAGES,
    ),
];

/// Access mask granted on the target path: metadata read only.
///
/// `FILE_READ_ATTRIBUTES (0x80) | FILE_READ_EA (0x08) | READ_CONTROL (0x20000) | SYNCHRONIZE (0x100000)`
const STAT_ACCESS_MASK: u32 = 0x0012_0088;

/// Internal env var used by unit tests to redirect the target path
/// onto a tempdir. The security boundary is enforced on the **use
/// sites** in `resolve_target_path` and `validate_target_path` (both
/// `#[cfg(debug_assertions)]`-gated), so release builds never honour
/// this override regardless of whether the constant exists.
#[allow(dead_code)]
const PATH_OVERRIDE_ENV: &str = "MXC_PREPARE_PATH_OVERRIDE";

/// Errors produced by the prepare/unprepare flow.
#[derive(Debug, thiserror::Error)]
pub enum PrepError {
    /// The DACL operation against the system drive root failed.
    #[error("DACL operation failed: {0}")]
    Dacl(#[from] DaclError),
    /// Could not resolve `%SystemDrive%`.
    #[error("could not resolve system drive root: {0}")]
    SystemDriveUnresolved(String),
    /// The target path failed the drive-root sanity check. The check
    /// applies both to the default-resolved path and to any explicit
    /// `--target` value supplied on the CLI.
    #[error(
        "target path must be a drive root (e.g. `C:\\`); got `{0}`. Refusing to ACL arbitrary paths."
    )]
    InvalidTargetPath(String),
    /// The target path already has an explicit Allow ACE for one of our
    /// well-known SIDs with a different `(mask, type, inheritance)`
    /// tuple than what `prepare-system-drive` would write. Refusing
    /// avoids silently coalescing — `SetEntriesInAclW(GRANT_ACCESS)`
    /// would merge the masks and clobber inheritance flags, and the
    /// tuple-precise revoke would then fail to undo the change.
    #[error(
        "{path} already has an explicit Allow ACE for {sid} with mask 0x{existing_mask:08X}, \
         type {existing_type:?}, inherit_flags 0x{existing_flags:02X} — different from what \
         prepare-system-drive would write (mask 0x{expected_mask:08X}, type Allow, \
         inherit_flags 0x00). Remove the conflicting ACE first, e.g.: \
         icacls \"{path}\" /remove:g \"*{sid}\""
    )]
    ConflictingAce {
        /// The SID with the conflicting ACE.
        sid: String,
        /// Path where the conflict was found.
        path: PathBuf,
        /// Mask of the existing ACE.
        existing_mask: u32,
        /// Type of the existing ACE.
        existing_type: AceType,
        /// Inherit flags of the existing ACE.
        existing_flags: u8,
        /// Mask we would have written.
        expected_mask: u32,
    },
}

/// Resolve the target path used by the subcommand.
///
/// Precedence:
///
///  1. Explicit `--target <PATH>`, if provided. Still validated as a
///     drive root via [`validate_target_path`].
///  2. `MXC_PREPARE_PATH_OVERRIDE` (debug-only test seam).
///  3. `%SystemDrive%`, normalised to `<letter>:\`.
fn resolve_target_path(explicit: Option<&str>) -> Result<PathBuf, PrepError> {
    if let Some(p) = explicit {
        return Ok(PathBuf::from(p));
    }
    #[cfg(debug_assertions)]
    if let Ok(p) = std::env::var(PATH_OVERRIDE_ENV) {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    let raw = std::env::var("SystemDrive")
        .map_err(|e| PrepError::SystemDriveUnresolved(e.to_string()))?;
    if raw.is_empty() {
        return Err(PrepError::SystemDriveUnresolved(
            "%SystemDrive% is empty".to_string(),
        ));
    }
    // %SystemDrive% is canonically `<letter>:` (no trailing backslash
    // per Windows convention), but some shells / scripts set it as
    // `<letter>:\`. Tolerate the trailing-backslash variant; reject
    // any other shape — `C:\Windows`, `\\server\share`, a multi-
    // character drive, etc. — so a tampered or misconfigured env var
    // can't steer the ACL write at the wrong directory.
    let trimmed = raw.trim_end_matches('\\');
    let b = trimmed.as_bytes();
    if b.len() != 2 || !b[0].is_ascii_alphabetic() || b[1] != b':' {
        return Err(PrepError::SystemDriveUnresolved(format!(
            "%SystemDrive% must be `<letter>:` or `<letter>:\\`, got {raw:?}"
        )));
    }
    Ok(PathBuf::from(format!("{trimmed}\\")))
}

/// Sanity-check that `p` is a literal drive root (`X:\`).
///
/// In debug builds the check is bypassed when
/// `MXC_PREPARE_PATH_OVERRIDE` is set — needed so tests can drive the
/// operation against tempdirs without crafting a fake drive root.
fn validate_target_path(p: &Path) -> Result<(), PrepError> {
    #[cfg(debug_assertions)]
    if std::env::var(PATH_OVERRIDE_ENV).is_ok_and(|v| !v.is_empty()) {
        return Ok(());
    }
    let s = p.to_string_lossy();
    let bytes = s.as_bytes();
    let ok =
        bytes.len() == 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    if ok {
        Ok(())
    } else {
        Err(PrepError::InvalidTargetPath(s.into_owned()))
    }
}

/// Apply allow ACEs for every well-known trustee on `path`.
///
/// Refuses if any trustee already has an explicit Allow ACE on `path`
/// that differs from what we'd write — `SetEntriesInAclW(GRANT_ACCESS)`
/// would silently merge the masks and clobber inheritance flags,
/// breaking the tuple-precise revoke's ability to undo the change.
/// Idempotent on hosts where our exact ACE already exists.
fn apply_all(path: &Path) -> Result<(), PrepError> {
    for (name, sid) in TRUSTEES {
        // Scan-before-apply: catch hosts where a third party (icacls,
        // SDK sample, EDR, etc.) already authored an explicit Allow
        // ACE for this SID with a different shape. Coalescing would
        // mutate the host's prior ACE and break reversibility.
        let priors = scan_explicit_aces_for_sid(path, sid)?;
        for p in &priors {
            let exact_match = p.access_mask == STAT_ACCESS_MASK
                && p.ace_type == AceType::Allow
                && p.inherit_flags == 0;
            if !exact_match {
                return Err(PrepError::ConflictingAce {
                    sid: (*sid).to_string(),
                    path: path.to_path_buf(),
                    existing_mask: p.access_mask,
                    existing_type: p.ace_type,
                    existing_flags: p.inherit_flags,
                    expected_mask: STAT_ACCESS_MASK,
                });
            }
        }

        println!("  + {name:<45} ({sid})");
        apply_explicit_ace(path, sid, STAT_ACCESS_MASK, AceType::Allow, false)?;
    }
    Ok(())
}

/// Revoke ACEs matching our exact `(mask, type, inheritance)` tuple
/// for every well-known trustee on `path`. Non-matching explicit ACEs
/// for the same SIDs (e.g. ones authored by `icacls C:\ /grant
/// "ALL APPLICATION PACKAGES":(R)`) are preserved.
fn revoke_all(path: &Path) -> Result<(), PrepError> {
    for (name, sid) in TRUSTEES {
        let removed =
            revoke_specific_aces_for_sid(path, sid, STAT_ACCESS_MASK, AceType::Allow, false)?;
        if removed > 0 {
            println!("  - {name:<45} ({sid}) [{removed} ACE(s) removed]");
        } else {
            println!("  · {name:<45} ({sid}) [no matching ACE; nothing to do]");
        }
    }
    Ok(())
}

enum Action {
    Prepare,
    Unprepare,
}

impl Action {
    fn description(&self) -> &'static str {
        match self {
            Action::Prepare => "Adding metadata-read ACEs",
            Action::Unprepare => "Removing metadata-read ACEs",
        }
    }
}

fn run_action(action: Action, explicit_target: Option<&str>) -> Result<(), PrepError> {
    let path = resolve_target_path(explicit_target)?;
    validate_target_path(&path)?;

    println!("{} on {}", action.description(), path.display());
    println!(
        "  mask : 0x{:08X} (FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE)",
        STAT_ACCESS_MASK
    );

    match action {
        Action::Prepare => apply_all(&path)?,
        Action::Unprepare => revoke_all(&path)?,
    }

    println!("Done.");
    Ok(())
}

fn finish(result: Result<(), PrepError>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            // Use distinct exit codes for the two large failure
            // families so callers can react: filesystem-DACL trouble
            // (6) vs target-path / configuration trouble (everything
            // else mapped to 1).
            match e {
                PrepError::Dacl(_) => 6,
                _ => 1,
            }
        }
    }
}

/// Entry point for the `prepare-system-drive` subcommand. Returns the
/// process exit code to propagate.
pub fn run_prepare(explicit_target: Option<&str>) -> i32 {
    finish(run_action(Action::Prepare, explicit_target))
}

/// Entry point for the `unprepare-system-drive` subcommand. Returns
/// the process exit code to propagate.
pub fn run_unprepare(explicit_target: Option<&str>) -> i32 {
    finish(run_action(Action::Unprepare, explicit_target))
}

#[cfg(test)]
mod tests {
    // These tests cover the apply/revoke pair against a tempdir
    // (redirected via MXC_PREPARE_PATH_OVERRIDE).

    use super::*;
    use std::sync::Mutex;

    // Serialize tests that mutate process-wide env vars.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct OverrideGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl OverrideGuard {
        fn set(p: &Path) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            // SAFETY: serialized against our own writes via ENV_LOCK.
            // We assume no other concurrent reader/writer of env in
            // this process during the guard's lifetime (test threads
            // sharing env vars are the actual race Rust 1.81 flagged
            // by marking set_var unsafe).
            unsafe {
                std::env::set_var(PATH_OVERRIDE_ENV, p);
            }
            OverrideGuard { _lock: lock }
        }
    }
    impl Drop for OverrideGuard {
        fn drop(&mut self) {
            // SAFETY: see set().
            unsafe {
                std::env::remove_var(PATH_OVERRIDE_ENV);
            }
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    fn target_path_honors_override() {
        let tmp = tempfile::tempdir().unwrap();
        let _g = OverrideGuard::set(tmp.path());
        let resolved = resolve_target_path(None).unwrap();
        assert_eq!(resolved, tmp.path());
    }

    /// Holds the ENV_LOCK and temporarily overrides `%SystemDrive%`
    /// (and ensures `PATH_OVERRIDE_ENV` is cleared) so a test can
    /// drive `resolve_target_path()` through its production code
    /// path without the debug short-circuit firing.
    struct SystemDriveGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        prior: Option<String>,
    }
    impl SystemDriveGuard {
        fn set(value: &str) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let prior = std::env::var("SystemDrive").ok();
            // SAFETY: serialized via ENV_LOCK; see OverrideGuard::set.
            unsafe {
                std::env::remove_var(PATH_OVERRIDE_ENV);
                std::env::set_var("SystemDrive", value);
            }
            SystemDriveGuard { _lock: lock, prior }
        }
    }
    impl Drop for SystemDriveGuard {
        fn drop(&mut self) {
            // SAFETY: see set().
            unsafe {
                match &self.prior {
                    Some(v) => std::env::set_var("SystemDrive", v),
                    None => std::env::remove_var("SystemDrive"),
                }
            }
        }
    }

    #[test]
    fn target_path_normalizes_canonical_form() {
        let _g = SystemDriveGuard::set("C:");
        let resolved = resolve_target_path(None).unwrap();
        assert_eq!(resolved, PathBuf::from("C:\\"));
    }

    #[test]
    fn target_path_normalizes_trailing_backslash_form() {
        let _g = SystemDriveGuard::set("D:\\");
        let resolved = resolve_target_path(None).unwrap();
        assert_eq!(resolved, PathBuf::from("D:\\"));
        assert_eq!(
            resolved.to_string_lossy().len(),
            3,
            "must not double-backslash"
        );
    }

    #[test]
    fn target_path_rejects_non_drive_root() {
        for bad in [
            "C:\\Windows",
            "\\\\server\\share",
            "C",
            "CD:",
            "::",
            " C:",
            "1:",
        ] {
            let _g = SystemDriveGuard::set(bad);
            let err = resolve_target_path(None);
            assert!(
                matches!(err, Err(PrepError::SystemDriveUnresolved(_))),
                "%SystemDrive% = {bad:?} must be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn explicit_target_takes_precedence() {
        let _g = SystemDriveGuard::set("C:");
        let resolved = resolve_target_path(Some("Z:\\")).unwrap();
        assert_eq!(resolved, PathBuf::from("Z:\\"));
    }

    #[test]
    fn apply_then_revoke_round_trip_on_tempdir() {
        let tmp = tempfile::tempdir().unwrap();
        let _g = OverrideGuard::set(tmp.path());

        // Start clean: a fresh tempdir has no S-1-15-2-* ACEs, so the
        // first revoke is a no-op.
        revoke_all(tmp.path()).unwrap();

        // Apply both ACEs.
        apply_all(tmp.path()).unwrap();
        // Re-applying is idempotent (SetEntriesInAclW merges).
        apply_all(tmp.path()).unwrap();

        // Revoke removes the ACEs.
        revoke_all(tmp.path()).unwrap();
        // Revoke is idempotent.
        revoke_all(tmp.path()).unwrap();
    }

    #[test]
    fn revoke_preserves_non_matching_ace_for_same_sid() {
        // A sysadmin previously ran
        // `icacls <path> /grant "ALL APPLICATION PACKAGES":(R)` and
        // we must not nuke that ACE.
        let tmp = tempfile::tempdir().unwrap();
        let _g = OverrideGuard::set(tmp.path());

        // Apply our metadata-only ACE.
        apply_all(tmp.path()).unwrap();

        // Independently grant the same SID a different mask
        // (FILE_GENERIC_READ = 0x00120089 — differs from ours by the
        // FILE_READ_DATA bit). This simulates a pre-existing
        // third-party ACE.
        const FILE_GENERIC_READ: u32 = 0x0012_0089;
        apply_explicit_ace(
            tmp.path(),
            SID_ALL_APP_PACKAGES,
            FILE_GENERIC_READ,
            AceType::Allow,
            false,
        )
        .unwrap();

        // Our revoke must only remove the metadata-only ACE, not the
        // GENERIC_READ one.
        revoke_all(tmp.path()).unwrap();

        // The exact-tuple `FILE_GENERIC_READ` ACE is still present —
        // a follow-up revoke with that mask removes it cleanly.
        let removed = revoke_specific_aces_for_sid(
            tmp.path(),
            SID_ALL_APP_PACKAGES,
            FILE_GENERIC_READ,
            AceType::Allow,
            false,
        )
        .unwrap();
        assert_eq!(
            removed, 1,
            "the pre-existing third-party ACE must survive our revoke_all"
        );
    }

    #[test]
    fn validate_target_path_accepts_drive_roots() {
        // Bypass the debug short-circuit: clear any test override
        // while holding the lock.
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized by ENV_LOCK.
        unsafe { std::env::remove_var(PATH_OVERRIDE_ENV) };

        for p in ["C:\\", "D:\\", "Z:\\", "a:\\"] {
            validate_target_path(Path::new(p))
                .unwrap_or_else(|e| panic!("expected `{p}` to validate, got {e}"));
        }
        for p in [
            "C:\\Windows",
            "C:",
            "\\\\server\\share",
            "C:\\\\",
            "",
            "1:\\",
        ] {
            assert!(
                validate_target_path(Path::new(p)).is_err(),
                "expected `{p}` to be rejected"
            );
        }
    }

    #[test]
    fn apply_refuses_when_existing_same_sid_ace_has_different_mask() {
        // `SetEntriesInAclW(GRANT_ACCESS)` would silently merge our
        // metadata mask with a pre-existing same-SID Allow ACE (e.g.
        // one installed by a third-party tool or `icacls`),
        // permanently mutating that ACE. Tuple-precise revoke would
        // then fail to undo the change. `apply_all` detects this and
        // refuses with a clear error.
        let tmp = tempfile::tempdir().unwrap();
        let _g = OverrideGuard::set(tmp.path());

        // Pre-existing third-party ACE: FILE_GENERIC_READ (differs
        // from STAT_ACCESS_MASK by the FILE_READ_DATA bit).
        const FILE_GENERIC_READ: u32 = 0x0012_0089;
        apply_explicit_ace(
            tmp.path(),
            SID_ALL_APP_PACKAGES,
            FILE_GENERIC_READ,
            AceType::Allow,
            false,
        )
        .unwrap();

        // apply_all must refuse rather than coalesce.
        let err = apply_all(tmp.path()).expect_err("expected ConflictingAce");
        match err {
            PrepError::ConflictingAce {
                sid,
                existing_mask,
                expected_mask,
                ..
            } => {
                assert_eq!(sid, SID_ALL_APP_PACKAGES);
                assert_eq!(existing_mask, FILE_GENERIC_READ);
                assert_eq!(expected_mask, STAT_ACCESS_MASK);
            }
            other => panic!("expected ConflictingAce, got {other:?}"),
        }
    }
}
