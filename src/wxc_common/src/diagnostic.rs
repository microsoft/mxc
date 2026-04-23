// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Diagnostic configuration for MXC real-time logging.
//!
//! Reads settings from the Windows registry (`HKLM\SOFTWARE\Microsoft\MXC\Diagnostics`)
//! and environment variables. Environment variables take precedence over registry values.
//!
//! ## Registry keys
//! - `ConsoleEnabled` (DWORD): 1 = send logs to the shared diagnostic console
//!
//! ## Environment variables
//! - `MXC_DIAG_CONSOLE=1` — enable diagnostic console (named pipe)

use std::env;

use crate::models::CodexRequest;

use windows::Win32::System::Registry::{
    RegCloseKey, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_DWORD,
};
use windows_core::PCWSTR;

const REGISTRY_SUBKEY: &str = r"SOFTWARE\Microsoft\MXC\Diagnostics";
const ENV_CONSOLE: &str = "MXC_DIAG_CONSOLE";

/// Well-known named pipe for the shared diagnostic console.
pub const DIAGNOSTIC_PIPE_NAME: &str = r"\\.\pipe\mxc-diagnostics";

/// Maximum number of characters to include from `script_code` in diagnostic output.
const SCRIPT_CODE_TRUNCATE_LEN: usize = 200;

/// Resolved diagnostic configuration.
#[derive(Debug, Clone)]
pub struct DiagnosticConfig {
    /// Whether to send log messages to the shared diagnostic console via named pipe.
    pub console_enabled: bool,
}

impl DiagnosticConfig {
    /// Returns true if any diagnostic sink is enabled.
    pub fn any_enabled(&self) -> bool {
        self.console_enabled
    }

    /// Read diagnostic settings from the registry and environment variables.
    /// Environment variables take precedence over registry values.
    pub fn from_environment() -> Self {
        let reg_console = read_registry_console_setting();

        let console_enabled = env_bool(ENV_CONSOLE).unwrap_or(reg_console);

        Self { console_enabled }
    }

    /// Check whether `ForceLearningMode` is enabled via registry.
    ///
    /// When `HKLM\SOFTWARE\Microsoft\MXC\Diagnostics\ForceLearningMode` is set
    /// to DWORD 1, the `learningModeLogging` capability is injected into the
    /// container policy regardless of what the config specifies.
    pub fn force_learning_mode() -> bool {
        let subkey_wide: Vec<u16> = REGISTRY_SUBKEY
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut hkey = HKEY::default();
        let result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey_wide.as_ptr()),
                Some(0),
                KEY_READ,
                &mut hkey,
            )
        };

        if result.is_err() {
            return false;
        }

        let val = read_reg_dword(hkey, "ForceLearningMode").unwrap_or(0) == 1;
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        val
    }
}

/// Produce a redacted JSON representation of a `CodexRequest` suitable for diagnostic logging.
///
/// - Environment variable values are replaced with `<redacted>`.
/// - `script_code` is truncated to [`SCRIPT_CODE_TRUNCATE_LEN`] characters.
/// - `network_proxy` (which is `#[serde(skip)]`) is logged separately.
pub fn redacted_request_json(request: &CodexRequest) -> String {
    // Build a redacted copy for serialization.
    let mut redacted = request.clone();

    // Redact env values: keep keys, replace values.
    redacted.env = redacted
        .env
        .iter()
        .map(|entry| {
            if let Some(pos) = entry.find('=') {
                format!("{}=<redacted>", &entry[..pos])
            } else {
                entry.clone()
            }
        })
        .collect();

    // Truncate script_code.
    if redacted.script_code.len() > SCRIPT_CODE_TRUNCATE_LEN {
        let total_len = redacted.script_code.len();
        redacted.script_code.truncate(SCRIPT_CODE_TRUNCATE_LEN);
        redacted
            .script_code
            .push_str(&format!("... ({total_len} chars total)"));
    }

    // Serialize the redacted request.
    let json = serde_json::to_string_pretty(&redacted)
        .unwrap_or_else(|e| format!("{{\"error\": \"failed to serialize request: {e}\"}}"));

    // Append network_proxy info (skipped by serde).
    let proxy_info = if request.policy.network_proxy.is_enabled() {
        let addr = request
            .policy
            .network_proxy
            .address
            .as_ref()
            .map(|a| a.to_url())
            .unwrap_or_else(|| "<builtin test server, not yet resolved>".to_string());
        format!(
            "\n[network_proxy: enabled, builtin_test_server={}, address={}]",
            request.policy.network_proxy.builtin_test_server, addr
        )
    } else {
        "\n[network_proxy: disabled]".to_string()
    };

    format!("{json}{proxy_info}")
}

/// Get the parent process name and PID (e.g. `"node.exe:67890"`).
///
/// Returns `"unknown"` if the parent PID cannot be determined, or
/// `"?:<pid>"` if the parent process name cannot be resolved.
pub fn get_parent_process_info() -> String {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let my_pid = std::process::id();

    // Take a snapshot to find our parent PID.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let snapshot = match snapshot {
        Ok(h) => h,
        Err(_) => return "unknown".to_string(),
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut parent_pid = None;
    unsafe {
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == my_pid {
                    parent_pid = Some(entry.th32ParentProcessID);
                    break;
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }

    let ppid = match parent_pid {
        Some(p) => p,
        None => return "unknown".to_string(),
    };

    // Resolve the parent's full image path.
    let exe_name = unsafe {
        let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, ppid);
        match proc {
            Ok(handle) => {
                let mut buf = [0u16; 1024];
                let mut len = buf.len() as u32;
                let name = if QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_FORMAT(0),
                    windows::core::PWSTR(buf.as_mut_ptr()),
                    &mut len,
                )
                .is_ok()
                {
                    let full = String::from_utf16_lossy(&buf[..len as usize]);
                    full.rsplit('\\').next().unwrap_or(&full).to_string()
                } else {
                    "?".to_string()
                };
                let _ = CloseHandle(handle);
                name
            }
            Err(_) => "?".to_string(),
        }
    };

    format!("{exe_name}:{ppid}")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Read a boolean from an environment variable ("1" or "true" = true).
fn env_bool(name: &str) -> Option<bool> {
    env::var(name)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Read the `ConsoleEnabled` setting from the Windows registry.
fn read_registry_console_setting() -> bool {
    let subkey_wide: Vec<u16> = REGISTRY_SUBKEY
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut hkey = HKEY::default();
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_wide.as_ptr()),
            Some(0),
            KEY_READ,
            &mut hkey,
        )
    };

    if result.is_err() {
        return false;
    }

    let console = read_reg_dword(hkey, "ConsoleEnabled").unwrap_or(0) == 1;

    unsafe {
        let _ = RegCloseKey(hkey);
    }

    console
}

/// Read a DWORD value from an open registry key.
fn read_reg_dword(hkey: HKEY, value_name: &str) -> Option<u32> {
    let name_wide: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut data: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;

    let result = unsafe {
        RegGetValueW(
            hkey,
            None,
            PCWSTR(name_wide.as_ptr()),
            RRF_RT_DWORD,
            None,
            Some(std::ptr::addr_of_mut!(data).cast()),
            Some(&mut size),
        )
    };

    if result.is_ok() {
        Some(data)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ProxyAddress, ProxyConfig};

    #[test]
    fn redacted_request_hides_env_values() {
        let request = CodexRequest {
            env: vec![
                "PATH=C:\\Windows".to_string(),
                "SECRET_TOKEN=abc123".to_string(),
            ],
            ..Default::default()
        };
        let json = redacted_request_json(&request);
        assert!(json.contains("PATH=<redacted>"));
        assert!(json.contains("SECRET_TOKEN=<redacted>"));
        assert!(!json.contains("abc123"));
        assert!(!json.contains("C:\\\\Windows"));
    }

    #[test]
    fn redacted_request_truncates_script_code() {
        let request = CodexRequest {
            script_code: "x".repeat(500),
            ..Default::default()
        };
        let json = redacted_request_json(&request);
        assert!(json.contains("500 chars total"));
        assert!(!json.contains(&"x".repeat(500)));
    }

    #[test]
    fn redacted_request_shows_proxy_info() {
        let mut request = CodexRequest::default();
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };
        let json = redacted_request_json(&request);
        assert!(json.contains("network_proxy: enabled"));
        assert!(json.contains("http://127.0.0.1:8080"));
    }

    #[test]
    fn redacted_request_shows_proxy_disabled() {
        let request = CodexRequest::default();
        let json = redacted_request_json(&request);
        assert!(json.contains("network_proxy: disabled"));
    }

    #[test]
    fn env_bool_parses_correctly() {
        // env_bool on non-existent var returns None
        assert!(env_bool("MXC_TEST_NONEXISTENT_VAR_12345").is_none());
    }
}
