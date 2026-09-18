// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Launch validation and post-failure diagnostics.
//!
//! Before launch, [`validate_required_child_env`] rejects caller-owned
//! environment blocks that cannot satisfy the Windows process-container
//! contract. If process creation still fails, or the child exits with a
//! non-zero code immediately, the caller can invoke
//! [`diagnose_create_process_failure`] or [`diagnose_process_exit`] to check
//! for well-known conditions and produce an actionable message.
//!
//! This module is intentionally decoupled from the runner implementations
//! so both `AppContainerScriptRunner` and `BaseContainerRunner` share the
//! same detection logic.

use std::path::Path;

use wxc_common::models::{ExecutionRequest, FailurePhase, ScriptResponse};

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

/// Environment variable names Windows requires to be *present* in the child's
/// environment block when creating a contained (AppContainer / PSEC) process.
///
/// Determined empirically against `CreateProcessW` with
/// `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT`: with either name absent the
/// call fails `ERROR_ENVVAR_NOT_FOUND` (203) before the workload ever starts.
/// The check is presence-only and case-insensitive — an empty or nonsense value
/// satisfies it — which is the fingerprint of a name lookup rather than path
/// resolution.
///
/// MXC does not inject these into a caller-supplied environment when
/// `process.inheritDefaultEnv` is false. Such a block is validated before
/// launch; this list is also used to diagnose a bare 203 defensively.
pub const REQUIRED_CHILD_ENV_VARS: [&str; 2] = ["SYSTEMROOT", "LOCALAPPDATA"];

fn missing_required_child_env_vars(supplied_env: &[String]) -> Vec<&'static str> {
    REQUIRED_CHILD_ENV_VARS
        .iter()
        .copied()
        .filter(|required| {
            !supplied_env.iter().any(|entry| {
                entry
                    .split_once('=')
                    .is_some_and(|(key, _)| key.eq_ignore_ascii_case(required))
            })
        })
        .collect()
}

fn missing_required_env_diagnostic(supplied_env: &[String]) -> Option<LaunchDiagnostic> {
    let missing = missing_required_child_env_vars(supplied_env);
    if missing.is_empty() {
        return None;
    }

    let described = if supplied_env.is_empty() {
        "an empty environment".to_string()
    } else {
        format!("an environment of {} variable(s)", supplied_env.len())
    };

    Some(LaunchDiagnostic {
        kind: "missing_required_env",
        message: format!(
            "The supplied `process.env` cannot launch a Windows process container because it is \
             missing the required variable(s): {}. MXC uses your `process.env` ({described}) \
             verbatim when `process.inheritDefaultEnv` is false. Set \
             `process.inheritDefaultEnv` to true to layer these entries on the default user \
             environment. Alternatively, add the missing variable(s) to `process.env` — any \
             value will do because the Windows requirement is presence-only — or omit \
             `process.env` entirely to use the default user environment.",
            missing.join(", ")
        ),
    })
}

/// Reject a caller-owned environment block that omits variables required by
/// Windows process-container launch APIs.
///
/// An omitted environment and `process.inheritDefaultEnv = true` are valid
/// because MXC supplies the default user environment in those cases.
pub fn validate_required_child_env(request: &ExecutionRequest) -> Result<(), ScriptResponse> {
    if request.inherit_default_env {
        return Ok(());
    }
    let Some(supplied_env) = request.env.as_deref() else {
        return Ok(());
    };
    let Some(diagnostic) = missing_required_env_diagnostic(supplied_env) else {
        return Ok(());
    };

    Err(ScriptResponse {
        failure_phase: FailurePhase::Rejected,
        ..ScriptResponse::error(&diagnostic.message)
    })
}

/// Diagnose `ERROR_ENVVAR_NOT_FOUND` from a contained-process launch.
///
/// `supplied_env` is the caller's `process.env` — `None` when they supplied
/// none, in which case MXC built the block itself and a missing variable is not
/// the caller's doing, so no diagnostic is produced.
///
/// Returns `None` unless the error is 203 *and* a caller-supplied block is
/// missing at least one of [`REQUIRED_CHILD_ENV_VARS`]; the generic
/// [`diagnose_create_process_failure`] handles every other case.
pub fn diagnose_missing_required_env(
    win32_error: u32,
    supplied_env: Option<&[String]>,
) -> Option<LaunchDiagnostic> {
    if win32_error != ERROR_ENVVAR_NOT_FOUND.0 {
        return None;
    }
    let supplied = supplied_env?;
    missing_required_env_diagnostic(supplied)
}

/// Diagnose a failed process launch. Inspects the Win32 error code and the command line to identify known
/// failure conditions.
///
/// Always returns a `LaunchDiagnostic` -- if no specific heuristic matches,
/// a generic message is produced from the raw error code.
pub fn diagnose_create_process_failure(
    win32_error: u32,
    command_line: &str,
    readonly_paths: &[String],
) -> LaunchDiagnostic {
    if win32_error == ERROR_ACCESS_DISABLED_BY_POLICY.0 {
        return LaunchDiagnostic {
            kind: "launch_blocked_by_policy",
            message:
                "Windows blocked the sandboxed process launch because of an IT-managed policy rule \
                      (ERROR_ACCESS_DISABLED_BY_POLICY, 1260). Contact your system administrator \
                      to allow the target executable to run in an MXC sandbox."
                    .to_string(),
        };
    }

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
            "CreateProcessW failed with error code {win32_error} (0x{win32_error:08X})."
        ),
    }
}

/// Diagnose a process that launched successfully but exited with a non-zero
/// code. Returns `None` when no recognized condition matches.
pub fn diagnose_process_exit(
    command_line: &str,
    readonly_paths: &[String],
    _readwrite_paths: &[String],
    exit_code: u32,
) -> Option<LaunchDiagnostic> {
    let bare_exe = Path::new(extract_exe_from_command_line(command_line));
    let resolved_exe = resolve_exe_on_path(bare_exe);
    if let Some(diag) = check_exe_heuristics(&resolved_exe, readonly_paths, Some(exit_code)) {
        return Some(diag);
    }
    None
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
    ERROR_ACCESS_DISABLED_BY_POLICY, ERROR_CALL_NOT_IMPLEMENTED, ERROR_ENVVAR_NOT_FOUND, E_NOTIMPL,
    STATUS_DLL_INIT_FAILED,
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

    if exit_code == Some(STATUS_DLL_INIT_FAILED.0 as u32) {
        return Some(LaunchDiagnostic {
            kind: "dll_init_failed_ui_required",
            message: "The target executable exited with STATUS_DLL_INIT_FAILED (0xC0000142). \
                      This often means the sandbox is blocking Win32k system calls \
                      (UI subsystem access), which is often required to initialize. \
                      Enable UI access in your sandbox policy: set `ui.disable: false` \
                      in the JSON config, or `ui.allowWindows: true` if you are using \
                      the SDK's SandboxPolicy."
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
        "CreateProcessSecurityEnvironment returned E_NOTIMPL. \
         The process security environment feature is not enabled on this OS build. \
         It may be possible to enable it through the Windows experimental \
         features settings, or run on a host that supports the BaseContainer \
         backend (MXC falls back to AppContainer automatically on builds \
         without it)."
            .to_string()
    } else {
        let disabled: Vec<_> = key_status.iter().filter(|(_, enabled)| !enabled).collect();
        if disabled.is_empty() {
            "CreateProcessSecurityEnvironment returned E_NOTIMPL. \
             The process security environment feature is not enabled on this OS build; it may \
             require additional enablement. MXC falls back to AppContainer \
             automatically on builds without BaseContainer support."
                .to_string()
        } else {
            let disabled_list: Vec<String> =
                disabled.iter().map(|(id, _)| id.to_string()).collect();
            format!(
                "CreateProcessSecurityEnvironment returned E_NOTIMPL. \
                 The process security environment feature is not enabled on this OS build \
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

    // -- diagnose_missing_required_env tests --

    fn env(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn missing_required_env_names_the_absent_variables() {
        let supplied = env(&["PATH=C:\\Windows"]);
        let diag = diagnose_missing_required_env(ERROR_ENVVAR_NOT_FOUND.0, Some(&supplied))
            .expect("203 with a sparse caller env must produce a diagnostic");

        assert_eq!(diag.kind, "missing_required_env");
        assert!(diag.message.contains("SYSTEMROOT"));
        assert!(diag.message.contains("LOCALAPPDATA"));
        assert!(diag.message.contains("supplied `process.env`"));
        assert!(diag.message.contains("verbatim"));
        assert!(diag.message.contains("1 variable(s)"));
        assert!(diag
            .message
            .contains("Set `process.inheritDefaultEnv` to true"));
    }

    #[test]
    fn missing_required_env_reports_only_what_is_absent() {
        let supplied = env(&["SystemRoot=C:\\Windows"]);
        let diag =
            diagnose_missing_required_env(ERROR_ENVVAR_NOT_FOUND.0, Some(&supplied)).unwrap();

        // Presence is case-insensitive, so SystemRoot satisfies SYSTEMROOT.
        assert!(!diag.message.contains("SYSTEMROOT"));
        assert!(diag.message.contains("LOCALAPPDATA"));
    }

    #[test]
    fn missing_required_env_describes_an_explicitly_empty_environment() {
        let diag = diagnose_missing_required_env(ERROR_ENVVAR_NOT_FOUND.0, Some(&[])).unwrap();
        assert!(diag.message.contains("an empty environment"));
    }

    #[test]
    fn missing_required_env_ignores_other_error_codes() {
        let supplied = env(&["PATH=C:\\Windows"]);
        assert!(diagnose_missing_required_env(5, Some(&supplied)).is_none());
    }

    #[test]
    fn missing_required_env_ignores_a_caller_supplied_complete_environment() {
        // 203 with both names present is not the sparse-env failure; let the
        // generic diagnostic describe it rather than emitting a wrong cause.
        let supplied = env(&[
            "SYSTEMROOT=C:\\Windows",
            "LOCALAPPDATA=C:\\Users\\u\\AppData\\Local",
        ]);
        assert!(diagnose_missing_required_env(ERROR_ENVVAR_NOT_FOUND.0, Some(&supplied)).is_none());
    }

    #[test]
    fn missing_required_env_ignores_a_block_mxc_built_itself() {
        // `None` means the caller supplied no environment, so MXC built the
        // block; a 203 there is not something the caller can fix in config.
        assert!(diagnose_missing_required_env(ERROR_ENVVAR_NOT_FOUND.0, None).is_none());
    }

    #[test]
    fn validation_rejects_a_sparse_verbatim_environment() {
        let request = ExecutionRequest {
            env: Some(env(&["PATH=C:\\Windows"])),
            ..Default::default()
        };

        let error = validate_required_child_env(&request)
            .expect_err("a sparse verbatim environment must be rejected");
        assert_eq!(error.failure_phase, FailurePhase::Rejected);
        assert!(error.error_message.contains("SYSTEMROOT"));
        assert!(error.error_message.contains("LOCALAPPDATA"));
    }

    #[test]
    fn validation_accepts_a_complete_verbatim_environment_case_insensitively() {
        let request = ExecutionRequest {
            env: Some(env(&[
                "systemroot=C:\\Windows",
                "LocalAppData=C:\\Users\\u\\AppData\\Local",
            ])),
            ..Default::default()
        };

        assert!(validate_required_child_env(&request).is_ok());
    }

    #[test]
    fn validation_accepts_an_inherited_sparse_environment() {
        let request = ExecutionRequest {
            env: Some(env(&["MYVAR=hello"])),
            inherit_default_env: true,
            ..Default::default()
        };

        assert!(validate_required_child_env(&request).is_ok());
    }

    #[test]
    fn validation_accepts_an_omitted_environment() {
        assert!(validate_required_child_env(&ExecutionRequest::default()).is_ok());
    }

    // -- diagnose_create_process_failure tests --

    #[test]
    fn api_not_implemented_triggers_feature_diagnostic() {
        let diag = diagnose_create_process_failure(ERROR_CALL_NOT_IMPLEMENTED.0, "pwsh.exe", &[]);
        assert_eq!(diag.kind, "feature_not_enabled");
        assert!(diag
            .message
            .contains("process security environment feature is not enabled"));
    }

    #[test]
    fn e_notimpl_triggers_feature_diagnostic() {
        let diag = diagnose_create_process_failure(E_NOTIMPL.0 as u32, "pwsh.exe", &[]);
        assert_eq!(diag.kind, "feature_not_enabled");
    }

    #[test]
    fn policy_block_takes_priority_over_executable_heuristics() {
        let diag = diagnose_create_process_failure(
            ERROR_ACCESS_DISABLED_BY_POLICY.0,
            r#""C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile"#,
            &[],
        );
        assert_eq!(diag.kind, "launch_blocked_by_policy");
        assert!(diag.message.contains("IT-managed"));
        assert!(diag.message.contains("1260"));
        assert!(diag.message.contains("system administrator"));
        assert!(!diag.message.contains("readonlyPaths"));
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
}
