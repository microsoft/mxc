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
//!
//! (This module is `#[cfg(target_os = "windows")]`-gated by its
//! parent in `lib.rs`; do not duplicate the gate as an inner
//! attribute — clippy's `duplicated_attributes` lint will reject it.)

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
    apply_explicit_ace, revoke_specific_aces_for_sid, scan_explicit_aces_for_sid, AceType,
    DaclError,
};
use crate::string_util::to_wide;

/// `SW_HIDE` is defined in `Win32_UI_WindowsAndMessaging`, which is not
/// currently enabled in this workspace's `windows` features. Use the
/// documented integer value directly to avoid a feature-set change.
///
/// We launch the elevated child with `SW_HIDE` because the child's
/// output is captured to the explicit `--internal-log-path` and
/// surfaced by the parent on failure — there's no UX value in a
/// visible console flash, and the UAC consent dialog itself is system-
/// rendered (unaffected by `nShow`).
const SW_HIDE_I32: i32 = 0;

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
/// sites** in `target_path` and `validate_target_path` (both `#[cfg(
/// debug_assertions)]`-gated), so release builds never honour this
/// override regardless of whether the constant exists. Mirrors the
/// `MXC_FORCE_TIER` test seam in `fallback_detector`.
///
/// `#[allow(dead_code)]`: in `--profile release` the use sites are
/// elided by their `cfg(debug_assertions)` gates, so the lint flags
/// the constant as unused even though the test module references it.
#[allow(dead_code)]
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
    /// The target path already has an explicit Allow ACE for one of our
    /// well-known SIDs with a different `(mask, type, inheritance)`
    /// tuple than what `--prepare-system-drive` would write. Refusing
    /// avoids silently coalescing — `SetEntriesInAclW(GRANT_ACCESS)`
    /// would merge the masks and clobber inheritance flags, and the
    /// tuple-precise revoke would then fail to undo the change.
    #[error(
        "{path} already has an explicit Allow ACE for {sid} with mask 0x{existing_mask:08X}, \
         type {existing_type:?}, inherit_flags 0x{existing_flags:02X} — different from what \
         --prepare-system-drive would write (mask 0x{expected_mask:08X}, type Allow, \
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

/// Resolve the target path in the unelevated parent.
///
/// Production: reads `%SystemDrive%` and returns `<letter>:\`. The
/// value is normalized (a trailing `\` is stripped before being re-
/// appended) and validated as a drive root — `%SystemDrive% = C:\`
/// and `%SystemDrive% = C:` both resolve to `C:\`, but values like
/// `C:\Windows`, `\\server\share`, or empty are rejected. This
/// closes a defense-in-depth gap on the already-elevated invocation
/// path, where the resolved value is used directly for ACL writes.
///
/// Debug + `MXC_PREPARE_PATH_OVERRIDE` set: honored verbatim (for
/// unit tests pointing at tempdirs).
fn target_path() -> Result<PathBuf, PrepError> {
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

/// Apply allow ACEs for every well-known trustee on `path`.
///
/// Refuses if any trustee already has an explicit Allow ACE on `path`
/// that differs from what we'd write — `SetEntriesInAclW(GRANT_ACCESS)`
/// would silently merge the masks and clobber inheritance flags,
/// breaking the tuple-precise revoke's ability to undo the change.
/// Idempotent on hosts where our exact ACE already exists (re-running
/// `--prepare-system-drive` after a successful first run is fine).
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

/// Default helper-log filename. The full path is chosen by the
/// unelevated parent (see [`mint_helper_log_path`]) and passed to the
/// elevated child via `--internal-log-path`, so both processes agree
/// on the path even when UAC consents under a different user than the
/// parent (over-the-shoulder UAC).
fn helper_log_path() -> PathBuf {
    std::env::temp_dir().join("wxc-exec-prepare-system-drive.log")
}

/// Mint a unique helper-log path in the unelevated parent's `%TEMP%`.
///
/// Uses the parent's PID + a coarse timestamp suffix. Two motivations:
///
///  * Two parallel `--prepare-system-drive` invocations from the same
///    user can each have their own log file.
///  * On over-the-shoulder UAC (where the elevated child runs as a
///    different user than the parent), the parent picks the path in
///    its own profile's TEMP — readable by both — and the child writes
///    there. Without this, the child's `%TEMP%` resolves against the
///    admin profile, and the parent reads from its own profile's TEMP
///    and finds nothing.
fn mint_helper_log_path() -> PathBuf {
    let pid = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    std::env::temp_dir().join(format!("wxc-exec-prepare-system-drive-{pid}-{nonce:x}.log"))
}

/// Quote a single argument for inclusion in a `CommandLineToArgvW`-
/// compatible command-line string, per Microsoft's documented rules.
///
/// Critically: any run of backslashes immediately preceding the closing
/// quote must be doubled. Otherwise inputs like `C:\` would emit
/// `"C:\"` — the parser sees `\"` as an escaped literal quote and
/// continues consuming, mangling the argument. This is the same rule
/// implemented by the Rust standard library's `CommandExt`-internal
/// quoter and by MSVCRT's `argv` parser.
///
/// See:
///  * <https://learn.microsoft.com/cpp/cpp/main-function-command-line-args>
///  * <https://learn.microsoft.com/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw>
fn quote_for_command_line(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    let mut i = 0;
    while i < bytes.len() {
        let mut backslashes = 0;
        while i < bytes.len() && bytes[i] == b'\\' {
            backslashes += 1;
            i += 1;
        }
        if i == bytes.len() {
            // Trailing backslashes immediately before the closing
            // quote: double them so the literal value survives the
            // round-trip through CommandLineToArgvW.
            for _ in 0..backslashes * 2 {
                out.push('\\');
            }
        } else if bytes[i] == b'"' {
            // Embedded literal quote: double the preceding backslashes
            // and escape the quote with one additional backslash.
            for _ in 0..(backslashes * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            i += 1;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            // Safe: `bytes[i]` is ASCII range when not '"' or '\' here.
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out.push('"');
    out
}

/// Re-launch the current executable with `action_flag`, the resolved
/// `target_path` (passed via `--internal-target-path` so the child
/// does not re-read `%SystemDrive%`), and `--internal-elevated-helper`.
/// Uses `ShellExecuteExW` with the `runas` verb (UAC prompt). Waits
/// for the elevated child to exit and returns its exit code.
///
/// `log_path` is the parent-chosen helper-log file; passed to the
/// child via `--internal-log-path` so both sides agree on the file
/// even under over-the-shoulder UAC.
fn spawn_elevated_self_and_wait(
    action_flag: &str,
    target_path: &Path,
    log_path: &Path,
) -> Result<i32, PrepError> {
    let exe =
        std::env::current_exe().map_err(|e| PrepError::CurrentExeUnresolved(e.to_string()))?;
    let exe_str = exe
        .to_str()
        .ok_or_else(|| PrepError::CurrentExeUnresolved("non-UTF-8 path".to_string()))?;
    let exe_w = to_wide(exe_str);

    let target_str = target_path
        .to_str()
        .ok_or_else(|| PrepError::CurrentExeUnresolved("non-UTF-8 target path".to_string()))?;
    let log_str = log_path
        .to_str()
        .ok_or_else(|| PrepError::CurrentExeUnresolved("non-UTF-8 log path".to_string()))?;
    // CRITICAL: do not use a naive `"{target_str}"` format. Paths like
    // `C:\` end in a backslash; under `CommandLineToArgvW`, `\"` is
    // interpreted as an escaped literal quote, mangling the argument.
    // `quote_for_command_line` doubles trailing backslashes so the
    // value survives the round-trip.
    let params = format!(
        "{action_flag} --internal-elevated-helper --internal-target-path {target_q} \
         --internal-log-path {log_q}",
        target_q = quote_for_command_line(target_str),
        log_q = quote_for_command_line(log_str),
    );
    let params_w = to_wide(&params);
    let verb_w = to_wide("runas");

    // Truncate the log file so the parent only reports output from
    // this elevated invocation. Best-effort: if the temp dir is
    // unwritable the child will discover that itself.
    let _ = fs::write(log_path, b"");

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
    // SW_HIDE: the child's output is captured to `log_path` and the
    // parent re-emits it on failure, so a visible console window
    // would only briefly flash and add no diagnostic value.
    info.nShow = SW_HIDE_I32;

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

/// Append a single line to a helper log file. Best-effort: errors are
/// swallowed because the alternative — propagating an I/O error from
/// the elevated child — would corrupt the exit-code signal the parent
/// uses for success/failure.
fn helper_log(log_path: &Path, line: &str) {
    use std::io::Write;
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
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
/// `%SystemDrive%`); `internal_log_path` reflects the optional
/// `--internal-log-path <PATH>` arg the parent passes so both sides
/// agree on the helper-log file under any UAC mode.
pub fn run_prepare(
    internal_elevated_helper: bool,
    internal_target_path: Option<&str>,
    internal_log_path: Option<&str>,
) -> i32 {
    finish(run_action(
        Action::Prepare,
        internal_elevated_helper,
        internal_target_path,
        internal_log_path,
    ))
}

/// CLI entry point for `--unprepare-system-drive`. Returns the process
/// exit code to propagate (0 = success, 1 = failure).
pub fn run_unprepare(
    internal_elevated_helper: bool,
    internal_target_path: Option<&str>,
    internal_log_path: Option<&str>,
) -> i32 {
    finish(run_action(
        Action::Unprepare,
        internal_elevated_helper,
        internal_target_path,
        internal_log_path,
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
    internal_log_path: Option<&str>,
) -> Result<(), PrepError> {
    // Resolve the path differently depending on which side of the
    // elevation boundary we're on:
    //   - Elevated child (helper flag set): use the path the parent
    //     passed in, do not consult env.
    //   - Unelevated parent (or already-elevated direct invocation):
    //     read %SystemDrive% (or test override). `target_path` itself
    //     normalizes and rejects malformed values.
    let (path, in_child_role) = if internal_elevated_helper {
        let p = internal_target_path.ok_or_else(|| {
            PrepError::Elevation(
                "--internal-elevated-helper requires --internal-target-path".to_string(),
            )
        })?;
        (PathBuf::from(p), true)
    } else {
        (target_path()?, false)
    };

    // Defense in depth: validate the drive-root shape immediately
    // before any destructive operation, regardless of which role we
    // are in. Covers (a) the elevated child receiving an attacker-
    // crafted `--internal-target-path`, and (b) the already-elevated
    // direct invocation where `target_path()` produced the value
    // (normalization there should already guarantee a drive root,
    // but a second check here ensures the contract holds at the
    // single point of trust).
    validate_target_path(&path)?;

    // Helper-log path:
    //   - In the elevated child, take the path the parent passed via
    //     `--internal-log-path` (fall back to the legacy fixed path
    //     under `%TEMP%` if the parent didn't supply one — only
    //     reachable via manually invoking the internal flags).
    //   - In the unelevated parent role, mint a fresh per-invocation
    //     path so two parallel runs don't trample each other and so
    //     the path is rooted in *the parent's* `%TEMP%` (important
    //     under over-the-shoulder UAC).
    let log_path = if in_child_role {
        internal_log_path
            .map(PathBuf::from)
            .unwrap_or_else(helper_log_path)
    } else {
        internal_log_path
            .map(PathBuf::from)
            .unwrap_or_else(mint_helper_log_path)
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
            helper_log(&log_path, &header);
            helper_log(&log_path, &mask_line);
        }

        let work = match action {
            Action::Prepare => apply_all(&path),
            Action::Unprepare => revoke_all(&path),
        };
        if let Err(e) = &work {
            let msg = format!("error during ACL operation: {e}");
            eprintln!("{msg}");
            if in_child_role {
                helper_log(&log_path, &msg);
            }
        }
        work?;

        println!("Done.");
        if in_child_role {
            helper_log(&log_path, "Done.");
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
    let exit = spawn_elevated_self_and_wait(action.flag(), &path, &log_path)?;
    if exit == 0 {
        println!("Elevated helper completed successfully.");
        Ok(())
    } else {
        Err(PrepError::ChildFailed {
            code: exit,
            log_path,
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
    #[cfg(debug_assertions)]
    fn target_path_honors_override() {
        // The MXC_PREPARE_PATH_OVERRIDE seam in `target_path` is
        // intentionally `#[cfg(debug_assertions)]`-gated, so this
        // test only makes sense in debug builds. Release builds
        // elide the override branch and `target_path()` always
        // returns `%SystemDrive%\\`.
        let tmp = tempfile::tempdir().unwrap();
        let _g = OverrideGuard::set(tmp.path());
        let resolved = target_path().unwrap();
        assert_eq!(resolved, tmp.path());
    }

    /// Holds the ENV_LOCK and temporarily overrides `%SystemDrive%`
    /// (and ensures `PATH_OVERRIDE_ENV` is cleared) so a test can
    /// drive `target_path()` through its production code path
    /// without the debug short-circuit firing.
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
        // `%SystemDrive% = C:` (the documented canonical form) →
        // resolves to `C:\`.
        let _g = SystemDriveGuard::set("C:");
        let resolved = target_path().unwrap();
        assert_eq!(resolved, PathBuf::from("C:\\"));
    }

    #[test]
    fn target_path_normalizes_trailing_backslash_form() {
        // `%SystemDrive% = D:\` (the variant some shells set) →
        // also resolves to `D:\`, not `D:\\`.
        let _g = SystemDriveGuard::set("D:\\");
        let resolved = target_path().unwrap();
        assert_eq!(resolved, PathBuf::from("D:\\"));
        assert_eq!(
            resolved.to_string_lossy().len(),
            3,
            "must not double-backslash"
        );
    }

    #[test]
    fn target_path_rejects_non_drive_root() {
        // Anything other than `<letter>:` or `<letter>:\` is a config
        // error (or attacker-tampered env) and must not silently steer
        // an ACL write at the wrong target.
        for bad in [
            "C:\\Windows",       // path under the drive
            "\\\\server\\share", // UNC
            "C",                 // missing colon
            "CD:",               // multi-char drive
            "::",                // malformed
            " C:",               // leading space
            "1:",                // non-alpha drive letter
        ] {
            let _g = SystemDriveGuard::set(bad);
            let err = target_path();
            assert!(
                matches!(err, Err(PrepError::SystemDriveUnresolved(_))),
                "%SystemDrive% = {bad:?} must be rejected, got {err:?}"
            );
        }
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

    #[test]
    fn apply_refuses_when_existing_same_sid_ace_has_different_mask() {
        // Reviewer's MF-B: `SetEntriesInAclW(GRANT_ACCESS)` would
        // silently merge our metadata mask with a pre-existing same-
        // SID Allow ACE (e.g. one installed by a third-party tool or
        // `icacls`), permanently mutating that ACE. Tuple-precise
        // revoke would then fail to undo the change. `apply_all`
        // detects this and refuses with a clear error.
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

        // Clean up the conflict; now apply_all should succeed.
        revoke_specific_aces_for_sid(
            tmp.path(),
            SID_ALL_APP_PACKAGES,
            FILE_GENERIC_READ,
            AceType::Allow,
            false,
        )
        .unwrap();
        apply_all(tmp.path()).expect("apply_all should succeed after conflict is removed");
        // And re-applying with our exact mask in place must be
        // idempotent (the scan finds an exact-match prior, allows
        // the re-apply).
        apply_all(tmp.path()).expect("re-apply with exact-match prior must be idempotent");
    }

    #[test]
    fn quote_for_command_line_handles_trailing_backslashes() {
        // The MF-A regression. `CommandLineToArgvW` interprets `\"` as
        // an escaped literal quote, so a naive `format!("\"{p}\"")`
        // for `p = "C:\\"` produces `"C:\"` which the parser reads as
        // a single 3-char arg `C:"` — *not* `C:\`. The quoter must
        // double trailing backslashes.
        //
        // The expected outputs below match Microsoft's documented
        // `CommandLineToArgvW` rules:
        //   * Backslashes immediately before the closing `"` are
        //     doubled (so 1 → 2, 2 → 4, etc).
        //   * Backslashes immediately before an embedded literal `"`
        //     are doubled, then one more `\` is appended to escape
        //     the embedded quote.
        //   * Backslashes preceding any other character are emitted
        //     verbatim.
        assert_eq!(quote_for_command_line("C:\\"), r#""C:\\""#);
        assert_eq!(quote_for_command_line("C:\\\\"), r#""C:\\\\""#);
        assert_eq!(quote_for_command_line("D:\\Windows"), r#""D:\Windows""#);
        assert_eq!(quote_for_command_line("simple"), r#""simple""#);
        assert_eq!(quote_for_command_line(""), r#""""#);
        // Embedded literal quote: backslashes preceding it must be
        // doubled + one more escape backslash.
        assert_eq!(
            quote_for_command_line(r#"a"b"#),
            r#""a\"b""#,
            "embedded quote with no preceding backslash needs one escape"
        );
        assert_eq!(
            quote_for_command_line(r#"a\"b"#),
            r#""a\\\"b""#,
            "embedded quote with 1 preceding backslash: doubled + escape"
        );
        assert_eq!(
            quote_for_command_line(r#"a\\b"#),
            r#""a\\b""#,
            "literal backslashes followed by non-quote, non-EOF: preserved verbatim"
        );
        // Trailing-backslash path with a space: the path must be
        // quoted (`"C:\\Program Files\\"`) and the trailing `\`
        // doubled.
        assert_eq!(
            quote_for_command_line("C:\\Program Files\\"),
            r#""C:\Program Files\\""#
        );
    }
}
