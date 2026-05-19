// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Post-failure launch diagnostics.
//!
//! When a process-creation call (`CreateProcessW` or
//! `Experimental_CreateProcessInSandbox`) fails, or when the child exits
//! with a non-zero code immediately, the caller can invoke
//! [`diagnose_launch_failure`] to check for well-known environment
//! conditions and produce an actionable remediation message for the user.
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
    /// Human-readable explanation of the failure.
    pub message: String,
    /// Actionable remediation guidance for the user.
    pub remediation: String,
}

/// Attempts to diagnose a known failure condition after a process launch has
/// failed. Returns `None` when no recognized condition matches -- the caller
/// should fall through to its existing generic error message in that case.
///
/// # Arguments
///
/// * `exe_path` -- Resolved path to the executable that was launched.
/// * `readonly_paths` -- The `readonlyPaths` from the sandbox policy.
/// * `_exit_code` -- The child's exit code (if available). Reserved for future
///   heuristics that key off specific exit codes.
pub fn diagnose_launch_failure(
    exe_path: &Path,
    readonly_paths: &[String],
    _exit_code: Option<u32>,
) -> Option<LaunchDiagnostic> {
    if is_packaged_app(exe_path) {
        return Some(LaunchDiagnostic {
            kind: "packaged_app",
            message: format!(
                "The target executable '{}' appears to be a packaged (MSIX) app. \
                 Packaged apps cannot be launched inside a sandboxed container.",
                exe_path.display()
            ),
            remediation: "Uninstall the packaged version and install an unpackaged build, \
                 e.g. `winget install Microsoft.PowerShell`."
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
                 not grant this access."
            ),
            remediation: format!(
                "Add \"{root}\" to `readonlyPaths` in your sandbox policy, \
                 or upgrade to pwsh 7.7+ which does not require root drive access."
            ),
        });
    }

    None
}

/// Format a `LaunchDiagnostic` into a string suitable for appending to an
/// error message displayed to the user.
pub fn format_diagnostic(diag: &LaunchDiagnostic) -> String {
    format!(
        "\n\n--- Diagnostic: {} ---\n{}\n\nRemediation: {}",
        diag.kind, diag.message, diag.remediation
    )
}

/// Attempt to resolve a potentially bare executable name (e.g. `pwsh.exe`)
/// to its full path by searching the system PATH. Returns the original path
/// if resolution fails or the input is already absolute.
pub fn resolve_exe_on_path(exe: &Path) -> std::path::PathBuf {
    // If already absolute, return as-is.
    if exe.is_absolute() {
        return exe.to_path_buf();
    }

    // Search PATH for the executable.
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(exe);
            if candidate.exists() {
                return candidate;
            }
        }
    }

    // Fallback: return the original (detection will be best-effort).
    exe.to_path_buf()
}

// --- Internal detection heuristics ---

/// MSIX/packaged apps are installed under `WindowsApps`.
fn is_packaged_app(exe_path: &Path) -> bool {
    let normalized = exe_path.to_string_lossy().to_lowercase();
    normalized.contains("\\windowsapps\\")
}

/// Returns `true` when the executable is `pwsh.exe` and the sandbox policy
/// does not grant read-only access to the drive root.
///
/// Note: This does NOT apply to `powershell.exe` (inbox Windows PowerShell 5.x)
/// and does NOT apply to `pwsh.exe` >= 7.7-preview1.
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

/// Extract the drive root (e.g. `C:\`) from an absolute path. Falls back to
/// `C:\` when the path is relative or otherwise cannot be parsed.
fn drive_root(exe_path: &Path) -> String {
    let s = exe_path.to_string_lossy();
    if s.len() >= 3 && s.as_bytes()[1] == b':' {
        format!("{}\\", &s[..2])
    } else {
        "C:\\".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn packaged_app_detected() {
        let path =
            PathBuf::from(r"C:\Program Files\WindowsApps\Microsoft.PowerShell_7.4.0\pwsh.exe");
        let diag = diagnose_launch_failure(&path, &[], None);
        assert!(diag.is_some());
        let d = diag.unwrap();
        assert_eq!(d.kind, "packaged_app");
        assert!(d.message.contains("packaged"));
    }

    #[test]
    fn unpackaged_pwsh_without_root_readonly() {
        let path = PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe");
        let diag = diagnose_launch_failure(&path, &[], None);
        assert!(diag.is_some());
        let d = diag.unwrap();
        assert_eq!(d.kind, "missing_filesystem_access");
        assert!(d.remediation.contains("readonlyPaths"));
    }

    #[test]
    fn unpackaged_pwsh_with_root_readonly() {
        let path = PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe");
        let readonly = vec!["C:\\".to_string()];
        let diag = diagnose_launch_failure(&path, &readonly, None);
        assert!(diag.is_none());
    }

    #[test]
    fn powershell_5_not_flagged() {
        let path = PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        let diag = diagnose_launch_failure(&path, &[], None);
        assert!(diag.is_none());
    }

    #[test]
    fn non_powershell_not_flagged() {
        let path = PathBuf::from(r"C:\Windows\System32\cmd.exe");
        let diag = diagnose_launch_failure(&path, &[], None);
        assert!(diag.is_none());
    }

    #[test]
    fn packaged_app_takes_priority_over_missing_access() {
        // A packaged pwsh.exe should report "packaged_app", not "missing_filesystem_access"
        let path =
            PathBuf::from(r"C:\Program Files\WindowsApps\Microsoft.PowerShell_7.4.0\pwsh.exe");
        let diag = diagnose_launch_failure(&path, &[], None);
        assert!(diag.is_some());
        assert_eq!(diag.unwrap().kind, "packaged_app");
    }

    #[test]
    fn case_insensitive_root_path_match() {
        let path = PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe");
        let readonly = vec!["c:\\".to_string()];
        let diag = diagnose_launch_failure(&path, &readonly, None);
        assert!(diag.is_none());
    }

    #[test]
    fn backslash_only_matches_as_root() {
        let path = PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe");
        let readonly = vec!["\\".to_string()];
        let diag = diagnose_launch_failure(&path, &readonly, None);
        assert!(diag.is_none());
    }
}
