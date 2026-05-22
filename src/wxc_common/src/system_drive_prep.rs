// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-prep tooling: `--prepare-system-drive` / `--unprepare-system-drive`.
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
//! # Elevation model
//!
//! Modifying the DACL on `C:\` requires `WRITE_DAC`, which normal
//! users don't hold. Windows does not allow a running process to
//! elevate its own token, so the unelevated parent re-launches itself
//! via `ShellExecuteExW(runas)` with the `--internal-elevated-helper`
//! flag, waits for the elevated child, and propagates the exit code.
//! A UAC prompt is expected on the first invocation.
//!
//! The parent resolves the target path *once* (before elevation) and
//! passes it to the child via `--internal-target-path` so the
//! elevated child does not re-read `%SystemDrive%` from a potentially
//! attacker-controlled environment. The child validates the received
//! path is a literal drive root (`X:\`) before touching its DACL.

#![cfg(target_os = "windows")]

use std::fs;
use std::path::{Path, PathBuf};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, WAIT_OBJECT_0};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
};
use windows::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};

use crate::filesystem_dacl::{
    apply_explicit_ace, revoke_specific_aces_for_sid, AceType, DaclError,
};
use crate::string_util::to_wide;

/// `SW_SHOWNORMAL` is defined in `Win32_UI_WindowsAndMessaging`, which
/// is not currently enabled in this workspace's `windows` features. Use
/// the documented integer value directly to avoid a feature-set change.
const SW_SHOWNORMAL_I32: i32 = 1;

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
/// onto a tempdir. Debug builds only — release ignores it. Mirrors
/// the `MXC_FORCE_TIER` test seam in `fallback_detector`.
#[cfg(debug_assertions)]
const PATH_OVERRIDE_ENV: &str = "MXC_PREPARE_PATH_OVERRIDE";

/// Errors produced by the prepare/unprepare flow.
#[derive(Debug, thiserror::Error)]
pub enum PrepError {
    /// Querying the current process token failed.
    #[error("could not query process token: {0}")]
    TokenQuery(String),
    /// Re-launch with the `runas` verb failed.
    #[error("elevation failed: {0}")]
    Elevation(String),
    /// The elevated child exited non-zero. The log path the child
    /// wrote diagnostic output to is included.
    #[error("elevated helper exited with code {code}; see {log_path}")]
    ChildFailed { code: i32, log_path: PathBuf },
    /// The DACL operation against the system drive root failed.
    #[error("DACL operation failed: {0}")]
    Dacl(#[from] DaclError),
    /// `--internal-elevated-helper` was set on a non-elevated process.
    /// Defense in depth: should not be reachable in practice because
    /// `ShellExecuteExW(runas)` either elevates or returns `Err`.
    #[error(
        "--internal-elevated-helper invoked without an elevated token; aborting to avoid loops"
    )]
    UnelevatedReentry,
    /// Could not resolve `%SystemDrive%`.
    #[error("could not resolve system drive root: {0}")]
    SystemDriveUnresolved(String),
    /// Could not determine `current_exe`.
    #[error("could not resolve current executable path: {0}")]
    CurrentExeUnresolved(String),
    /// `--internal-target-path` was set but the value did not pass the
    /// drive-root sanity check.
    #[error(
        "--internal-target-path must be a drive root (e.g. `C:\\`); got `{0}`. Refusing to ACL \
         arbitrary paths via the elevated helper."
    )]
    InvalidTargetPath(String),
}

/// Resolve the target path in the unelevated parent.
///
/// Production: `%SystemDrive%\`. Debug + `MXC_PREPARE_PATH_OVERRIDE`
/// set: honored verbatim (for unit tests).
fn target_path() -> Result<PathBuf, PrepError> {
    #[cfg(debug_assertions)]
    if let Ok(p) = std::env::var(PATH_OVERRIDE_ENV) {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    match std::env::var("SystemDrive") {
        Ok(d) if !d.is_empty() => Ok(PathBuf::from(format!("{d}\\"))),
        Ok(_) => Err(PrepError::SystemDriveUnresolved(
            "%SystemDrive% is empty".to_string(),
        )),
        Err(e) => Err(PrepError::SystemDriveUnresolved(e.to_string())),
    }
}

/// Sanity-check a path received from `--internal-target-path`.
///
/// Production allows only literal drive roots (`X:\`). This prevents
/// an attacker who can control the unelevated parent's CLI invocation
/// (or who finds a way to forge the internal flag) from steering the
/// elevated helper at arbitrary paths.
///
/// In debug builds the check is bypassed when `MXC_PREPARE_PATH_OVERRIDE`
/// is set in the *child* — needed so tests can drive the helper
/// against tempdirs without crafting a fake drive root.
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

/// Apply allow ACEs for every well-known trustee on `path`. Idempotent.
fn apply_all(path: &Path) -> Result<(), PrepError> {
    for (name, sid) in TRUSTEES {
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

/// Returns whether the current process is running with an elevated
/// token (`TokenIsElevated != 0`).
fn is_token_elevated() -> Result<bool, PrepError> {
    let mut token: HANDLE = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| PrepError::TokenQuery(format!("OpenProcessToken: {e}")))?;
    }
    let mut info = TOKEN_ELEVATION::default();
    let mut size = 0u32;
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut info as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
    };
    unsafe {
        let _ = CloseHandle(token);
    }
    result.map_err(|e| PrepError::TokenQuery(format!("GetTokenInformation: {e}")))?;
    Ok(info.TokenIsElevated != 0)
}

/// Path the elevated child writes its console output to, so the
/// unelevated parent can surface it on failure. The child's console
/// window closes immediately on exit; without this redirection the
/// user sees only `ChildFailed(<code>)` with no diagnostic.
fn helper_log_path() -> PathBuf {
    std::env::temp_dir().join("wxc-exec-prepare-system-drive.log")
}

/// Re-launch the current executable with `action_flag`, the resolved
/// `target_path` (passed via `--internal-target-path` so the child
/// does not re-read `%SystemDrive%`), and `--internal-elevated-helper`.
/// Uses `ShellExecuteExW` with the `runas` verb (UAC prompt). Waits
/// for the elevated child to exit and returns its exit code.
fn spawn_elevated_self_and_wait(action_flag: &str, target_path: &Path) -> Result<i32, PrepError> {
    let exe =
        std::env::current_exe().map_err(|e| PrepError::CurrentExeUnresolved(e.to_string()))?;
    let exe_str = exe
        .to_str()
        .ok_or_else(|| PrepError::CurrentExeUnresolved("non-UTF-8 path".to_string()))?;
    let exe_w = to_wide(exe_str);

    let target_str = target_path
        .to_str()
        .ok_or_else(|| PrepError::CurrentExeUnresolved("non-UTF-8 target path".to_string()))?;
    let params =
        format!("{action_flag} --internal-elevated-helper --internal-target-path \"{target_str}\"");
    let params_w = to_wide(&params);
    let verb_w = to_wide("runas");

    // Truncate the log file so the parent only reports output from
    // this elevated invocation. Best-effort: if the temp dir is
    // unwritable the child will discover that itself.
    let _ = fs::write(helper_log_path(), b"");

    // SAFETY: zero-initializing SHELLEXECUTEINFOW is the documented
    // pattern; cbSize is required to be set before the call. The
    // PCWSTR pointers reference local `Vec<u16>` buffers that live
    // until the end of this function, which is past the synchronous
    // `ShellExecuteExW` call (SEE_MASK_NOASYNC).
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.hwnd = HWND::default();
    info.lpVerb = PCWSTR(verb_w.as_ptr());
    info.lpFile = PCWSTR(exe_w.as_ptr());
    info.lpParameters = PCWSTR(params_w.as_ptr());
    info.lpDirectory = PCWSTR::null();
    info.nShow = SW_SHOWNORMAL_I32;

    unsafe {
        ShellExecuteExW(&mut info)
            .map_err(|e| PrepError::Elevation(format!("ShellExecuteExW: {e}")))?;
    }

    let process = info.hProcess;
    let wait = unsafe { WaitForSingleObject(process, INFINITE) };
    if wait != WAIT_OBJECT_0 {
        unsafe {
            let _ = CloseHandle(process);
        }
        return Err(PrepError::Elevation(format!(
            "WaitForSingleObject returned 0x{:08X} (expected WAIT_OBJECT_0)",
            wait.0
        )));
    }
    let mut exit_code = 0u32;
    let exit_result = unsafe { GetExitCodeProcess(process, &mut exit_code) };
    unsafe {
        let _ = CloseHandle(process);
    }
    exit_result.map_err(|e| PrepError::Elevation(format!("GetExitCodeProcess: {e}")))?;
    Ok(exit_code as i32)
}

/// Append a single line to the helper log file. Best-effort: errors
/// are swallowed because the alternative — propagating an I/O error
/// from the elevated child — would corrupt the exit-code signal the
/// parent uses for success/failure.
fn helper_log(line: &str) {
    use std::io::Write;
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(helper_log_path())
    {
        let _ = writeln!(f, "{line}");
    }
}

/// CLI entry point for `--prepare-system-drive`. Returns the process
/// exit code to propagate (0 = success, 1 = failure).
///
/// `internal_elevated_helper` reflects whether the caller passed
/// `--internal-elevated-helper`; `internal_target_path` reflects the
/// optional `--internal-target-path <PATH>` arg the unelevated parent
/// passes to the elevated child (so the child does not re-read
/// `%SystemDrive%`).
pub fn run_prepare(internal_elevated_helper: bool, internal_target_path: Option<&str>) -> i32 {
    finish(run_action(
        Action::Prepare,
        internal_elevated_helper,
        internal_target_path,
    ))
}

/// CLI entry point for `--unprepare-system-drive`. Returns the process
/// exit code to propagate (0 = success, 1 = failure).
pub fn run_unprepare(internal_elevated_helper: bool, internal_target_path: Option<&str>) -> i32 {
    finish(run_action(
        Action::Unprepare,
        internal_elevated_helper,
        internal_target_path,
    ))
}

fn finish(result: Result<(), PrepError>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            // If the failure was a ChildFailed, dump the captured
            // helper-log contents so the user sees what went wrong.
            if let PrepError::ChildFailed { log_path, .. } = &e {
                if let Ok(contents) = fs::read_to_string(log_path) {
                    if !contents.trim().is_empty() {
                        eprintln!("--- elevated helper log ({}) ---", log_path.display());
                        eprintln!("{}", contents.trim_end());
                        eprintln!("--- end log ---");
                    }
                }
            }
            1
        }
    }
}

enum Action {
    Prepare,
    Unprepare,
}

impl Action {
    fn flag(&self) -> &'static str {
        match self {
            Action::Prepare => "--prepare-system-drive",
            Action::Unprepare => "--unprepare-system-drive",
        }
    }
    fn description(&self) -> &'static str {
        match self {
            Action::Prepare => "Adding metadata-read ACEs",
            Action::Unprepare => "Removing metadata-read ACEs",
        }
    }
}

fn run_action(
    action: Action,
    internal_elevated_helper: bool,
    internal_target_path: Option<&str>,
) -> Result<(), PrepError> {
    // Resolve the path differently depending on which side of the
    // elevation boundary we're on:
    //   - Elevated child (helper flag set): use the path the parent
    //     passed in, validate it's a drive root, do not consult env.
    //   - Unelevated parent: read %SystemDrive% (or test override).
    let (path, in_child_role) = if internal_elevated_helper {
        let p = internal_target_path.ok_or_else(|| {
            PrepError::Elevation(
                "--internal-elevated-helper requires --internal-target-path".to_string(),
            )
        })?;
        let path = PathBuf::from(p);
        validate_target_path(&path)?;
        (path, true)
    } else {
        (target_path()?, false)
    };

    if is_token_elevated()? {
        // We hold the elevated token (either as the actual user, or
        // as the spawned helper). Do the work.
        let header = format!("{} on {}", action.description(), path.display());
        let mask_line = format!(
            "  mask : 0x{:08X} (FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE)",
            STAT_ACCESS_MASK
        );
        println!("{header}");
        println!("{mask_line}");
        if in_child_role {
            helper_log(&header);
            helper_log(&mask_line);
        }

        let work = match action {
            Action::Prepare => apply_all(&path),
            Action::Unprepare => revoke_all(&path),
        };
        if let Err(e) = &work {
            let msg = format!("error during ACL operation: {e}");
            eprintln!("{msg}");
            if in_child_role {
                helper_log(&msg);
            }
        }
        work?;

        println!("Done.");
        if in_child_role {
            helper_log("Done.");
        }
        return Ok(());
    }

    if internal_elevated_helper {
        // Re-launched with the helper flag but our token isn't
        // elevated. Refuse to recurse.
        return Err(PrepError::UnelevatedReentry);
    }

    println!(
        "This operation modifies the DACL of {} and requires elevation.",
        path.display()
    );
    println!("Requesting elevation (UAC prompt)…");
    let exit = spawn_elevated_self_and_wait(action.flag(), &path)?;
    if exit == 0 {
        println!("Elevated helper completed successfully.");
        Ok(())
    } else {
        Err(PrepError::ChildFailed {
            code: exit,
            log_path: helper_log_path(),
        })
    }
}

#[cfg(test)]
mod tests {
    // These tests cover the apply/revoke pair against a tempdir
    // (redirected via MXC_PREPARE_PATH_OVERRIDE). They do *not*
    // exercise the elevation flow, which requires UAC and is verified
    // manually with the PowerShell scripts in `scripts/host-prep/`.

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
    fn target_path_honors_override() {
        let tmp = tempfile::tempdir().unwrap();
        let _g = OverrideGuard::set(tmp.path());
        let resolved = target_path().unwrap();
        assert_eq!(resolved, tmp.path());
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
        // The reviewer's MF-1 concern: a sysadmin previously ran
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
}
