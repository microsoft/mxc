// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Post-failure launch diagnostics.
//!
//! When a process-creation call (`CreateProcessW` or
//! `Experimental_CreateProcessInSandbox`) fails, or when the child exits
//! with a non-zero code immediately, the caller can invoke
//! [`diagnose_create_process_failure`] or [`diagnose_process_exit`] to check
//! for well-known environment conditions and produce an actionable message.
//!
//! This module is intentionally decoupled from the runner implementations
//! so both `AppContainerScriptRunner` and `BaseContainerRunner` share the
//! same detection logic.

use std::path::Path;

/// A structured diagnostic describing *why* a sandboxed process launch failed
/// and what the user can do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchDiagnostic {
    /// Machine-readable discriminator (e.g. `"packaged_app"`,
    /// `"missing_filesystem_access"`).
    pub kind: &'static str,
    /// Human-readable explanation of the failure including remediation guidance.
    pub message: String,
}

// -- Public API --------------------------------------------------------------

/// Diagnose a failed `CreateProcess` / `Experimental_CreateProcessInSandbox`
/// call. Inspects the Win32 error code and the command line to identify known
/// failure conditions.
///
/// Always returns a `LaunchDiagnostic` -- if no specific heuristic matches,
/// a generic message is produced from the raw error code.
pub fn diagnose_create_process_failure(
    win32_error: u32,
    command_line: &str,
    readonly_paths: &[String],
) -> LaunchDiagnostic {
    // Check for feature-not-enabled (velocity keys).
    if win32_error == ERROR_CALL_NOT_IMPLEMENTED.0 || win32_error == E_NOTIMPL.0 as u32 {
        return diagnose_api_not_implemented();
    }

    // Resolve the exe from the command line for further heuristics.
    let bare_exe = Path::new(extract_exe_from_command_line(command_line));
    let resolved_exe = resolve_exe_on_path(bare_exe);

    if let Some(diag) = check_exe_heuristics(&resolved_exe, readonly_paths, None) {
        return diag;
    }

    // Generic fallback.
    LaunchDiagnostic {
        kind: "create_process_failed",
        message: format!(
            "CreateProcessInSandbox failed with error code {win32_error} (0x{win32_error:08X})."
        ),
    }
}

/// Returns `true` when the Win32 error is `ERROR_NOT_SUPPORTED` (0x32) and
/// the caller passed a non-null environment block. Downlevel OS builds that
/// predate environment-parameter support in `Experimental_CreateProcessInSandbox`
/// surface this error; the caller should retry without the environment block.
pub fn is_environment_not_supported(win32_error: u32, has_environment: bool) -> bool {
    win32_error == ERROR_NOT_SUPPORTED.0 && has_environment
}

/// Produce a [`LaunchDiagnostic`] for the environment-not-supported case.
pub fn diagnose_environment_not_supported() -> LaunchDiagnostic {
    LaunchDiagnostic {
        kind: "environment_not_supported_downlevel",
        message: "WARNING: The `environment` parameter is not supported on this OS build. \
                  Retrying without explicit environment variables."
            .to_string(),
    }
}

/// Diagnose a process that launched successfully but exited with a non-zero
/// code. Returns `None` when no recognized condition matches.
pub fn diagnose_process_exit(
    command_line: &str,
    readonly_paths: &[String],
    readwrite_paths: &[String],
    exit_code: u32,
) -> Option<LaunchDiagnostic> {
    let bare_exe = Path::new(extract_exe_from_command_line(command_line));
    let resolved_exe = resolve_exe_on_path(bare_exe);
    if let Some(diag) = check_exe_heuristics(&resolved_exe, readonly_paths, Some(exit_code)) {
        return Some(diag);
    }
    check_refs_volumes(readonly_paths, readwrite_paths)
}

// -- Constants ---------------------------------------------------------------

/// Velocity key IDs required by the BaseContainer feature.
const REQUIRED_VELOCITY_KEYS: &[(u32, &str)] = &[
    (61389575, "BaseContainer core"),
    (61155944, "BaseContainer sandbox spec"),
];

// `ERROR_CALL_NOT_IMPLEMENTED`, `E_NOTIMPL`, and `STATUS_DLL_INIT_FAILED`
// are re-exported from the `windows` crate. Comparisons against them
// flow through `u32`, which matches the existing public surface of
// this module (`diagnose_create_process_failure` takes `u32`).
use windows::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_NOT_SUPPORTED, E_NOTIMPL, STATUS_DLL_INIT_FAILED,
};

// -- Internal heuristics -----------------------------------------------------

/// Checks exe-path-based heuristics (packaged app, DLL init failure, missing
/// root access). Returns `None` if nothing matches.
fn check_exe_heuristics(
    exe_path: &Path,
    readonly_paths: &[String],
    exit_code: Option<u32>,
) -> Option<LaunchDiagnostic> {
    if is_packaged_app(exe_path) {
        return Some(LaunchDiagnostic {
            kind: "packaged_app",
            message: format!(
                "The target executable '{}' appears to be a packaged (MSIX) app. \
                 Packaged apps cannot be launched inside a sandboxed container. \
                 Uninstall the packaged version and install an unpackaged build.",
                exe_path.display()
            ),
        });
    }

    if exit_code == Some(STATUS_DLL_INIT_FAILED.0 as u32) && is_powershell(exe_path) {
        return Some(LaunchDiagnostic {
            kind: "dll_init_failed_ui_required",
            message: "PowerShell exited with STATUS_DLL_INIT_FAILED (0xC0000142). \
                      This typically means the sandbox is blocking Win32k system calls \
                      (UI subsystem access), which PowerShell requires to initialize. \
                      Enable UI access in your sandbox policy (set `ui.allowWindows: true`)."
                .to_string(),
        });
    }

    if missing_root_readonly(exe_path, readonly_paths) {
        let root = drive_root(exe_path);
        return Some(LaunchDiagnostic {
            kind: "missing_filesystem_access",
            message: format!(
                "pwsh.exe versions before 7.7 require read-only access to the \
                 root drive ({root}) to start. The current sandbox policy does \
                 not grant this access. Add \"{root}\" to `readonlyPaths` in your \
                 sandbox policy, or upgrade to pwsh 7.7+."
            ),
        });
    }

    None
}

/// Produces a diagnostic when the API returns E_NOTIMPL/ERROR_CALL_NOT_IMPLEMENTED,
/// indicating the feature is gated behind velocity keys.
fn diagnose_api_not_implemented() -> LaunchDiagnostic {
    let key_status = check_velocity_keys();

    let message = if key_status.is_empty() {
        "Experimental_CreateProcessInSandbox returned E_NOTIMPL. \
         The BaseContainer feature is not enabled on this OS build. \
         It may be possible to enable it through the Windows experimental \
         features settings, or run on a host that supports the BaseContainer \
         backend (MXC falls back to AppContainer automatically on builds \
         without it)."
            .to_string()
    } else {
        let disabled: Vec<_> = key_status.iter().filter(|(_, enabled)| !enabled).collect();
        if disabled.is_empty() {
            "Experimental_CreateProcessInSandbox returned E_NOTIMPL. \
             The BaseContainer feature is not enabled on this OS build; it may \
             require additional enablement. MXC falls back to AppContainer \
             automatically on builds without BaseContainer support."
                .to_string()
        } else {
            let disabled_list: Vec<String> =
                disabled.iter().map(|(id, _)| id.to_string()).collect();
            format!(
                "Experimental_CreateProcessInSandbox returned E_NOTIMPL. \
                 The BaseContainer feature is not enabled on this OS build \
                 (disabled feature flags: {}). It may be possible to enable it \
                 through the Windows experimental features settings, or run on a \
                 host that supports the BaseContainer backend (MXC falls back to \
                 AppContainer automatically on builds without it).",
                disabled_list.join(", ")
            )
        }
    };

    LaunchDiagnostic {
        kind: "feature_not_enabled",
        message,
    }
}

/// Query the Windows Feature Store registry to check whether each required
/// velocity key is enabled. Returns a list of `(key_id, is_enabled)` pairs.
/// Returns an empty vec if the registry cannot be read.
fn check_velocity_keys() -> Vec<(u32, bool)> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;

        let mut results = Vec::new();
        for &(key_id, _label) in REQUIRED_VELOCITY_KEYS {
            let enabled = [4u32, 8].iter().any(|priority| {
                let path = format!(
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\FeatureManagement\Overrides\{}\{}",
                    priority, key_id
                );
                if let Ok(reg_key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(&path) {
                    if let Ok(state) = reg_key.get_value::<u32, _>("EnabledState") {
                        return state == 2;
                    }
                }
                false
            });
            results.push((key_id, enabled));
        }
        results
    }
    #[cfg(not(target_os = "windows"))]
    {
        Vec::new()
    }
}

/// Pre-launch check: detect if any sandbox policy paths reference ReFS volumes
/// (e.g. Dev Drives). BFS (Bind Filter) does not work correctly on ReFS, so
/// filesystem policy will not be enforced on those volumes.
///
/// Call this **before** launching the sandboxed process. If it returns `Some`,
/// the caller should abort launch and surface the diagnostic to the user.
pub fn check_refs_volumes(
    readonly_paths: &[String],
    readwrite_paths: &[String],
) -> Option<LaunchDiagnostic> {
    #[cfg(target_os = "windows")]
    {
        let system_drive = std::env::var("SystemDrive")
            .unwrap_or_else(|_| "C:".to_string())
            .to_uppercase();

        // Collect unique non-system drive letters from all policy paths.
        let mut non_system_drives: Vec<char> = Vec::new();
        for path in readonly_paths.iter().chain(readwrite_paths.iter()) {
            if let Some(drive_letter) = extract_drive_letter(path) {
                let upper = drive_letter.to_ascii_uppercase();
                let drive_prefix = format!("{}:", upper);
                if drive_prefix != system_drive && !non_system_drives.contains(&upper) {
                    non_system_drives.push(upper);
                }
            }
        }

        if non_system_drives.is_empty() {
            return None;
        }

        // Check which of these drives are ReFS.
        let refs_drives: Vec<char> = non_system_drives
            .into_iter()
            .filter(|&d| is_refs_volume(d))
            .collect();

        if refs_drives.is_empty() {
            return None;
        }

        let drive_list: String = refs_drives
            .iter()
            .map(|d| format!("{d}:"))
            .collect::<Vec<_>>()
            .join(", ");
        Some(LaunchDiagnostic {
            kind: "refs_volume_unsupported",
            message: format!(
                "The sandbox policy references paths on ReFS volume(s) ({drive_list}) which \
                 may be a Dev Drive. The Bind Filter (BFS) used to enforce filesystem policy \
                 does not work correctly on ReFS volumes, so sandboxed processes may not be \
                 able to access files on those paths. Move your working directory to an NTFS \
                 volume, or remove those paths from readonlyPaths/readwritePaths."
            ),
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (readonly_paths, readwrite_paths);
        None
    }
}

/// Extract the drive letter from a path like "D:\foo" or "d:/bar".
fn extract_drive_letter(path: &str) -> Option<char> {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        Some(bytes[0] as char)
    } else {
        None
    }
}

/// Check if a volume uses ReFS by calling GetVolumeInformationW.
#[cfg(target_os = "windows")]
fn is_refs_volume(drive_letter: char) -> bool {
    use windows::Win32::Storage::FileSystem::GetVolumeInformationW;

    let root = format!("{}:\\", drive_letter);
    let root_wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();

    let mut fs_name_buf = [0u16; 64];
    let success = unsafe {
        GetVolumeInformationW(
            windows::core::PCWSTR(root_wide.as_ptr()),
            None,                   // volume name (not needed)
            None,                   // serial number
            None,                   // max component length
            None,                   // filesystem flags
            Some(&mut fs_name_buf), // filesystem name
        )
    };

    if success.is_err() {
        return false;
    }

    let fs_name = String::from_utf16_lossy(
        &fs_name_buf[..fs_name_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(fs_name_buf.len())],
    );
    fs_name.eq_ignore_ascii_case("ReFS")
}

/// Attempt to resolve a potentially bare executable name (e.g. `pwsh.exe`)
/// to its full path by searching the system PATH. Returns the original path
/// if resolution fails or the input is already absolute.
pub fn resolve_exe_on_path(exe: &Path) -> std::path::PathBuf {
    if exe.is_absolute() {
        return exe.to_path_buf();
    }
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(exe);
            if candidate.exists() {
                return candidate;
            }
        }
    }
    exe.to_path_buf()
}

/// Extract the executable path from a command line string.
///
/// Handles both quoted paths (`"C:\Program Files\...\pwsh.exe" -args`) and
/// unquoted paths (`pwsh.exe -args`). Strips surrounding quotes if present.
pub fn extract_exe_from_command_line(command_line: &str) -> &str {
    let trimmed = command_line.trim();
    if let Some(after_quote) = trimmed.strip_prefix('"') {
        match after_quote.find('"') {
            Some(end) => &after_quote[..end],
            None => trimmed.split_whitespace().next().unwrap_or(""),
        }
    } else {
        trimmed.split_whitespace().next().unwrap_or("")
    }
}

// -- Internal detection helpers ----------------------------------------------

fn is_packaged_app(exe_path: &Path) -> bool {
    let normalized = exe_path.to_string_lossy().to_lowercase();
    normalized.contains("\\windowsapps\\") || normalized.contains("/windowsapps/")
}

fn is_powershell(exe_path: &Path) -> bool {
    let filename = exe_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    filename == "pwsh.exe" || filename == "powershell.exe"
}

fn missing_root_readonly(exe_path: &Path, readonly_paths: &[String]) -> bool {
    let filename = exe_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    if filename != "pwsh.exe" {
        return false;
    }
    let root = drive_root(exe_path);
    !readonly_paths
        .iter()
        .any(|p| p.eq_ignore_ascii_case(&root) || p == "\\")
}

fn drive_root(exe_path: &Path) -> String {
    let s = exe_path.to_string_lossy();
    if s.len() >= 3 && s.as_bytes()[1] == b':' {
        format!("{}\\", &s[..2])
    } else {
        "C:\\".to_string()
    }
}

// -- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- diagnose_create_process_failure tests --

    #[test]
    fn api_not_implemented_triggers_feature_diagnostic() {
        let diag = diagnose_create_process_failure(ERROR_CALL_NOT_IMPLEMENTED.0, "pwsh.exe", &[]);
        assert_eq!(diag.kind, "feature_not_enabled");
        assert!(diag
            .message
            .contains("BaseContainer feature is not enabled"));
    }

    #[test]
    fn e_notimpl_triggers_feature_diagnostic() {
        let diag = diagnose_create_process_failure(E_NOTIMPL.0 as u32, "pwsh.exe", &[]);
        assert_eq!(diag.kind, "feature_not_enabled");
    }

    #[test]
    fn packaged_app_detected_from_command_line() {
        let cmd =
            r#""C:\Program Files\WindowsApps\Microsoft.PowerShell_7.4.0\pwsh.exe" -NoProfile"#;
        let diag = diagnose_create_process_failure(87, cmd, &[]);
        assert_eq!(diag.kind, "packaged_app");
        assert!(diag.message.contains("packaged"));
    }

    #[test]
    fn generic_fallback_for_unknown_error() {
        let diag = diagnose_create_process_failure(5, "cmd.exe", &["C:\\".to_string()]);
        assert_eq!(diag.kind, "create_process_failed");
        assert!(diag.message.contains("5"));
    }

    // -- diagnose_process_exit tests --

    #[test]
    fn dll_init_failed_pwsh_triggers_ui_diagnostic() {
        let diag = diagnose_process_exit(
            r#""C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile"#,
            &["C:\\".to_string()],
            &[],
            STATUS_DLL_INIT_FAILED.0 as u32,
        );
        assert!(diag.is_some());
        let d = diag.unwrap();
        assert_eq!(d.kind, "dll_init_failed_ui_required");
        assert!(d.message.contains("STATUS_DLL_INIT_FAILED"));
        assert!(d.message.contains("UI access"));
    }

    #[test]
    fn dll_init_failed_powershell_exe_triggers_ui_diagnostic() {
        let diag = diagnose_process_exit(
            r#""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe""#,
            &["C:\\".to_string()],
            &[],
            STATUS_DLL_INIT_FAILED.0 as u32,
        );
        assert!(diag.is_some());
        assert_eq!(diag.unwrap().kind, "dll_init_failed_ui_required");
    }

    #[test]
    fn dll_init_failed_non_powershell_does_not_trigger() {
        let diag = diagnose_process_exit(
            r"C:\tools\myapp.exe",
            &["C:\\".to_string()],
            &[],
            STATUS_DLL_INIT_FAILED.0 as u32,
        );
        assert!(diag.is_none());
    }

    #[test]
    fn different_exit_code_pwsh_does_not_trigger_ui_diagnostic() {
        let diag = diagnose_process_exit(
            r#""C:\Program Files\PowerShell\7\pwsh.exe""#,
            &["C:\\".to_string()],
            &[],
            1,
        );
        assert!(diag.is_none());
    }

    #[test]
    fn missing_root_readonly_from_exit() {
        let diag =
            diagnose_process_exit(r#""C:\Program Files\PowerShell\7\pwsh.exe""#, &[], &[], 1);
        assert!(diag.is_some());
        assert_eq!(diag.unwrap().kind, "missing_filesystem_access");
    }

    #[test]
    fn pwsh_with_root_readonly_no_diagnostic() {
        let diag = diagnose_process_exit(
            r#""C:\Program Files\PowerShell\7\pwsh.exe""#,
            &["C:\\".to_string()],
            &[],
            1,
        );
        assert!(diag.is_none());
    }

    #[test]
    fn packaged_app_takes_priority_over_missing_access() {
        let cmd = r#""C:\Program Files\WindowsApps\Microsoft.PowerShell_7.4.0\pwsh.exe""#;
        let diag = diagnose_process_exit(cmd, &[], &[], 1);
        assert!(diag.is_some());
        assert_eq!(diag.unwrap().kind, "packaged_app");
    }

    // -- extract_exe_from_command_line tests --

    #[test]
    fn extract_exe_quoted_path_with_spaces() {
        let cmd = r#""C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.1.0_x64__8wekyb3d8bbwe\pwsh.exe" -NoProfile -NoLogo"#;
        let exe = extract_exe_from_command_line(cmd);
        assert_eq!(
            exe,
            r"C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.1.0_x64__8wekyb3d8bbwe\pwsh.exe"
        );
    }

    #[test]
    fn extract_exe_unquoted() {
        assert_eq!(
            extract_exe_from_command_line("pwsh.exe -NoProfile"),
            "pwsh.exe"
        );
    }

    #[test]
    fn extract_exe_quoted_no_args() {
        let cmd = r#""C:\Program Files\PowerShell\7\pwsh.exe""#;
        assert_eq!(
            extract_exe_from_command_line(cmd),
            r"C:\Program Files\PowerShell\7\pwsh.exe"
        );
    }

    #[test]
    fn extract_exe_empty() {
        assert_eq!(extract_exe_from_command_line(""), "");
    }

    // -- case sensitivity / edge cases --

    #[test]
    fn case_insensitive_root_path_match() {
        let diag = diagnose_process_exit(
            r#""C:\Program Files\PowerShell\7\pwsh.exe""#,
            &["c:\\".to_string()],
            &[],
            1,
        );
        assert!(diag.is_none());
    }

    #[test]
    fn backslash_only_matches_as_root() {
        let diag = diagnose_process_exit(
            r#""C:\Program Files\PowerShell\7\pwsh.exe""#,
            &["\\".to_string()],
            &[],
            1,
        );
        assert!(diag.is_none());
    }

    // -- extract_drive_letter tests --

    #[test]
    fn extract_drive_letter_absolute() {
        assert_eq!(extract_drive_letter(r"D:\myrepo"), Some('D'));
        assert_eq!(extract_drive_letter(r"c:\users"), Some('c'));
    }

    #[test]
    fn extract_drive_letter_none_for_unc() {
        assert_eq!(extract_drive_letter(r"\\server\share"), None);
    }

    #[test]
    fn extract_drive_letter_none_for_relative() {
        assert_eq!(extract_drive_letter("relative/path"), None);
    }
}
