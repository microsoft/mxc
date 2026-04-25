// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Registry-based per-executable config override for wxc-exec.
//!
//! Allows administrators to provide custom JSON configs for specific executables
//! via the registry at `HKLM\SOFTWARE\Microsoft\MXC\Diagnostics\Exec\{exe_name}`.
//!
//! Each subkey names an executable (e.g., `pwsh.exe`) and contains:
//! - `(Default)` REG_SZ: path to a JSON configuration file
//! - `OverrideConfig` REG_DWORD (optional): when 1, the registry config replaces
//!   the original entirely. When 0 or absent, merge mode is used.
//!
//! In merge mode, execution context (command line, working directory, env, timeout,
//! container ID) always comes from the original request. Policies default to keeping
//! the original unless a per-policy override flag is set:
//! - `OverrideFilesystemPolicy` REG_DWORD: when 1, use the registry config's filesystem policy
//! - `OverrideNetworkPolicy` REG_DWORD: when 1, use the registry config's network policy
//! - `OverrideUiPolicy` REG_DWORD: when 1, use the registry config's UI policy

use std::fmt::Write;
use std::path::Path;

use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;

use crate::config_parser::load_request;
use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::CodexRequest;

/// Registry path for per-executable config overrides.
const REGISTRY_BASE_PATH: &str = r"SOFTWARE\Microsoft\MXC\Diagnostics\Exec";

/// Checks for a registry-based config override for the executable in the request's
/// command line. If found, the request is modified according to the override mode.
///
/// Returns `Ok(true)` if an override was applied, `Ok(false)` if no override was
/// found, or `Err` if an override was found but could not be loaded.
pub fn check_registry_override(
    request: &mut CodexRequest,
    logger: &mut Logger,
) -> Result<bool, WxcError> {
    let exe_name = match resolve_exe_name_from_command_line(&request.script_code) {
        Some(name) => name,
        None => {
            let _ = writeln!(
                logger,
                "Registry override: could not parse executable name from command line"
            );
            return Ok(false);
        }
    };

    let _ = writeln!(
        logger,
        "Registry override: resolved executable name '{}'",
        exe_name
    );

    let subkey_path = format!("{}\\{}", REGISTRY_BASE_PATH, exe_name);

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let exe_key = match hklm.open_subkey(&subkey_path) {
        Ok(k) => k,
        Err(_) => {
            let _ = writeln!(
                logger,
                "Registry override: no override key found for '{}'",
                exe_name
            );
            return Ok(false);
        }
    };

    let config_path: String = match exe_key.get_value::<String, _>("") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            let _ = writeln!(
                logger,
                "Registry override: key for '{}' exists but has no config path",
                exe_name
            );
            return Ok(false);
        }
    };

    let _ = writeln!(
        logger,
        "Registry override: loading config from '{}'",
        config_path
    );

    let override_config: u32 = exe_key.get_value("OverrideConfig").unwrap_or(0);

    let mut registry_request = load_request(&config_path, logger, false)?;

    if override_config != 0 {
        let _ = writeln!(
            logger,
            "Registry override: OverrideConfig=1, using registry config as-is for '{}'",
            exe_name
        );
        *request = registry_request;
    } else {
        let _ = writeln!(
            logger,
            "Registry override: merging into registry config for '{}'",
            exe_name
        );

        // Always carry over execution context from the original request.
        registry_request.script_code = request.script_code.clone();
        registry_request.working_directory = request.working_directory.clone();
        registry_request.env = request.env.clone();
        registry_request.script_timeout = request.script_timeout;
        registry_request.container_id = request.container_id.clone();
        registry_request.experimental_enabled = request.experimental_enabled;

        // Per-policy override flags: when 0 (default), keep the original policy.
        // When 1, use the registry config's policy for that area.
        let override_fs: u32 = exe_key.get_value("OverrideFilesystemPolicy").unwrap_or(0);
        let override_net: u32 = exe_key.get_value("OverrideNetworkPolicy").unwrap_or(0);
        let override_ui: u32 = exe_key.get_value("OverrideUiPolicy").unwrap_or(0);

        if override_fs == 0 {
            registry_request.policy.readwrite_paths = request.policy.readwrite_paths.clone();
            registry_request.policy.readonly_paths = request.policy.readonly_paths.clone();
            registry_request.policy.denied_paths = request.policy.denied_paths.clone();
        } else {
            let _ = writeln!(logger, "Registry override: overriding filesystem policy");
        }

        if override_net == 0 {
            registry_request.policy.default_network_policy =
                request.policy.default_network_policy.clone();
            registry_request.policy.network_enforcement_mode =
                request.policy.network_enforcement_mode.clone();
            registry_request.policy.allowed_hosts = request.policy.allowed_hosts.clone();
            registry_request.policy.blocked_hosts = request.policy.blocked_hosts.clone();
            registry_request.policy.network_proxy = request.policy.network_proxy.clone();
        } else {
            let _ = writeln!(logger, "Registry override: overriding network policy");
        }

        if override_ui == 0 {
            registry_request.policy.ui = request.policy.ui.clone();
            registry_request.policy.base_process_ui = request.policy.base_process_ui.clone();
        } else {
            let _ = writeln!(logger, "Registry override: overriding UI policy");
        }

        *request = registry_request;
    }

    Ok(true)
}

/// Parses the executable name from a command line string using Windows
/// `CreateProcess`-style resolution rules.
///
/// - If the command line starts with `"`, the path between the first pair of
///   quotes is treated as the executable path.
/// - Otherwise the first space-delimited token is used.
///
/// The filename (last path component) is extracted and lowercased. If it does
/// not already end with `.exe`, the suffix is appended.
///
/// Returns `None` if the command line is empty.
pub fn resolve_exe_name_from_command_line(command_line: &str) -> Option<String> {
    let trimmed = command_line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let exe_path = if let Some(after_quote) = trimmed.strip_prefix('"') {
        // Quoted: extract path between first pair of quotes.
        match after_quote.find('"') {
            Some(end) => &after_quote[..end],
            // No closing quote — take up to the first space as a best effort.
            None => after_quote.split_whitespace().next().unwrap_or(after_quote),
        }
    } else {
        // Unquoted: first space-delimited token.
        trimmed.split_whitespace().next().unwrap_or(trimmed)
    };

    // Extract filename from the path.
    let filename = Path::new(exe_path)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(exe_path);

    let mut name = filename.to_lowercase();
    if !name.ends_with(".exe") {
        name.push_str(".exe");
    }

    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_path_with_spaces() {
        let result = resolve_exe_name_from_command_line(
            r#""C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -Command "echo hi""#,
        );
        assert_eq!(result, Some("pwsh.exe".to_string()));
    }

    #[test]
    fn quoted_path_no_closing_quote() {
        // Malformed: no closing quote. Best-effort takes first space-delimited token.
        let result = resolve_exe_name_from_command_line(r#""C:\apps\app.exe -arg"#);
        assert_eq!(result, Some("app.exe".to_string()));
    }

    #[test]
    fn unquoted_simple_exe() {
        let result = resolve_exe_name_from_command_line("pwsh.exe -c echo hello");
        assert_eq!(result, Some("pwsh.exe".to_string()));
    }

    #[test]
    fn unquoted_full_path() {
        let result =
            resolve_exe_name_from_command_line(r"C:\Windows\System32\cmd.exe /c echo test");
        assert_eq!(result, Some("cmd.exe".to_string()));
    }

    #[test]
    fn unquoted_no_extension() {
        let result = resolve_exe_name_from_command_line("python -c print('hi')");
        assert_eq!(result, Some("python.exe".to_string()));
    }

    #[test]
    fn unquoted_path_no_extension() {
        let result = resolve_exe_name_from_command_line(r"C:\Python314\python -c print('hi')");
        assert_eq!(result, Some("python.exe".to_string()));
    }

    #[test]
    fn empty_command_line() {
        assert_eq!(resolve_exe_name_from_command_line(""), None);
    }

    #[test]
    fn whitespace_only() {
        assert_eq!(resolve_exe_name_from_command_line("   "), None);
    }

    #[test]
    fn case_insensitive_result() {
        let result = resolve_exe_name_from_command_line("PWSH.EXE -NoProfile");
        assert_eq!(result, Some("pwsh.exe".to_string()));
    }

    #[test]
    fn exe_name_only_no_args() {
        let result = resolve_exe_name_from_command_line("notepad.exe");
        assert_eq!(result, Some("notepad.exe".to_string()));
    }

    #[test]
    fn quoted_path_forward_slashes() {
        let result =
            resolve_exe_name_from_command_line(r#""C:/Program Files/Python/python.exe" -c "1+1""#);
        assert_eq!(result, Some("python.exe".to_string()));
    }
}
