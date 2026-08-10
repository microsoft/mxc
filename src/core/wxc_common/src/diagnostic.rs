// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Diagnostic configuration for MXC real-time logging.
//!
//! ## Environment variables
//! - `MXC_DIAG_CONSOLE=1` — enable diagnostic console (named pipe)

use std::env;

use crate::models::ExecutionRequest;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const ENV_CONSOLE: &str = "MXC_DIAG_CONSOLE";
const ENV_PIPE_TOKEN: &str = "MXC_DIAG_PIPE_TOKEN";
const PIPE_NAME_PREFIX: &str = r"\\.\pipe\mxc-diagnostics";

/// Build the per-user, per-session diagnostic pipe name.
pub fn diagnostic_pipe_name() -> String {
    let suffix = diagnostic_pipe_token()
        .map(|token| format!("-{token}"))
        .unwrap_or_default();
    match current_user_sid() {
        Some(sid) => format!("{PIPE_NAME_PREFIX}-{sid}{suffix}"),
        None => format!("{PIPE_NAME_PREFIX}{suffix}"),
    }
}

/// Return the caller-provided per-session pipe token when it has sufficient
/// entropy for a pipe name.
pub fn diagnostic_pipe_token() -> Option<String> {
    let token = env::var(ENV_PIPE_TOKEN).ok()?;
    if !is_valid_pipe_token(&token) {
        return None;
    }
    Some(token)
}

fn is_valid_pipe_token(token: &str) -> bool {
    token.len() >= 32
        && token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        && token
            .bytes()
            .filter(|byte| *byte != b'-')
            .collect::<std::collections::HashSet<_>>()
            .len()
            >= 4
}

/// Retrieve the SID string for the current process token's user.
pub fn current_user_sid() -> Option<String> {
    use crate::string_util::sid_to_string;
    use windows::Win32::Foundation::HANDLE;

    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a pseudo-handle always valid.
    // OpenProcessToken with TOKEN_QUERY is safe on a valid process handle.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
    }

    let mut buf = vec![0u8; 256];
    let mut returned: u32 = 0;
    // SAFETY: token is valid (from OpenProcessToken above); buf is large enough for TOKEN_USER.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            buf.len() as u32,
            &mut returned,
        )
    };

    if ok.is_err() {
        unsafe {
            let _ = CloseHandle(token);
        }
        return None;
    }

    // SAFETY: GetTokenInformation succeeded with TokenUser, so buf contains a valid TOKEN_USER.
    let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid_str = unsafe { sid_to_string(token_user.User.Sid.0) };

    unsafe {
        let _ = CloseHandle(token);
    }

    sid_str
}

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

    /// Read diagnostic settings from environment variables.
    pub fn from_environment() -> Self {
        let console_enabled = env_bool(ENV_CONSOLE).unwrap_or(false);

        Self { console_enabled }
    }

    /// Check whether learning mode should be force-injected.
    ///
    /// When the diagnostic console is enabled (`MXC_DIAG_CONSOLE=1`), the
    /// `learningModeLogging` capability is automatically injected into the
    /// container policy so that access-check ETW events are captured.
    pub fn force_learning_mode() -> bool {
        env_bool(ENV_CONSOLE).unwrap_or(false)
    }
}

/// Produce a redacted JSON representation of an `ExecutionRequest` suitable for diagnostic logging.
///
/// - Environment variable values are replaced with `<redacted>`.
/// - `script_code` is truncated to [`SCRIPT_CODE_TRUNCATE_LEN`] characters.
/// - `network_proxy` (which is `#[serde(skip)]`) is logged separately.
pub fn redacted_request_json(request: &ExecutionRequest) -> String {
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
            .map(|a| crate::proxy_env::redact_proxy_url(&a.to_url()))
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

/// Parse caller-supplied raw config JSON and redact secret-bearing fields
/// (same closed set of markers as [`crate::config_deserialize`]'s error-path
/// redaction, e.g. `token`, `secret`, and the whole `user` credential bundle
/// used by `experimental.isolationSession.user.{upn,wamToken}`) before it is
/// safe to write to a diagnostic sink.
///
/// This must run *before* any policy validation: an `IsolationSession`
/// one-shot request's credential bundle is only rejected by the runner after
/// the request has already been parsed and logged, so the raw text emitted
/// here cannot rely on downstream validation having stripped it first.
///
/// If the text fails to parse as JSON, a placeholder is returned instead of
/// the raw text, since malformed input cannot be proven free of embedded
/// credentials.
pub fn redact_raw_config_json(raw: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(mut value) => {
            redact_secret_fields(&mut value);
            serde_json::to_string_pretty(&value)
                .unwrap_or_else(|_| "<unable to re-serialize redacted config>".to_string())
        }
        Err(_) => "<unparsable JSON config, omitted from diagnostics>".to_string(),
    }
}

/// Recursively blank JSON object values whose key is secret-bearing (see
/// [`crate::config_deserialize::is_secret_path_field`]). Over-redaction fails
/// safe: e.g. blanking the whole `user` object (rather than only `upn`/
/// `wamToken` within it) never leaks a credential.
fn redact_secret_fields(value: &mut serde_json::Value) {
    redact_secret_fields_at_path(value, &[]);
}

fn redact_secret_fields_at_path(value: &mut serde_json::Value, path: &[String]) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, entry) in map.iter_mut() {
                let key_lower = key.to_ascii_lowercase();
                if crate::config_deserialize::is_secret_path_field(&key_lower) {
                    *entry = serde_json::Value::String("<redacted>".to_string());
                } else if key_lower == "env" {
                    redact_environment_values(entry);
                } else if key_lower == "url" && path.iter().any(|parent| parent == "proxy") {
                    if let serde_json::Value::String(url) = entry {
                        *url = crate::proxy_env::redact_proxy_url(url);
                    }
                } else {
                    let mut child_path = path.to_vec();
                    child_path.push(key_lower);
                    redact_secret_fields_at_path(entry, &child_path);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                redact_secret_fields_at_path(item, path);
            }
        }
        _ => {}
    }
}

fn redact_environment_values(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                if let serde_json::Value::String(entry) = item {
                    if let Some(separator) = entry.find('=') {
                        entry.truncate(separator);
                        entry.push_str("=<redacted>");
                    }
                }
            }
        }
        other => redact_secret_fields_at_path(other, &[]),
    }
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
    // SAFETY: CreateToolhelp32Snapshot with TH32CS_SNAPPROCESS and pid 0
    // takes a snapshot of all processes. No invalid memory access is possible.
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
    // SAFETY: `entry` is initialized with correct `dwSize` and `snapshot` is a valid handle
    // returned by CreateToolhelp32Snapshot above. CloseHandle is called on the valid snapshot.
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
    // SAFETY: OpenProcess returns a valid handle or an error (checked via match).
    // QueryFullProcessImageNameW writes into a stack-allocated buffer with bounded length.
    // CloseHandle is called on the valid process handle before returning.
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
                    let full = crate::string_util::from_wide(&buf[..len as usize]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ProxyAddress, ProxyConfig};

    #[test]
    fn redacted_request_hides_env_values() {
        let request = ExecutionRequest {
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
        let request = ExecutionRequest {
            script_code: "x".repeat(500),
            ..Default::default()
        };
        let json = redacted_request_json(&request);
        assert!(json.contains("500 chars total"));
        assert!(!json.contains(&"x".repeat(500)));
    }

    #[test]
    fn redacted_request_shows_proxy_info() {
        let mut request = ExecutionRequest::default();
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
        let request = ExecutionRequest::default();
        let json = redacted_request_json(&request);
        assert!(json.contains("network_proxy: disabled"));
    }

    #[test]
    fn redact_raw_config_json_hides_isolation_session_user_bundle() {
        let raw = r#"{
            "process": {"commandLine": "echo hi"},
            "containment": "isolation_session",
            "experimental": {
                "isolationSession": {
                    "user": {"upn": "alice@contoso.com", "wamToken": "super-secret-bearer-token"}
                }
            }
        }"#;
        let redacted = redact_raw_config_json(raw);
        assert!(!redacted.contains("alice@contoso.com"));
        assert!(!redacted.contains("super-secret-bearer-token"));
        assert!(redacted.contains("<redacted>"));
        // Non-secret fields survive untouched.
        assert!(redacted.contains("echo hi"));
        assert!(redacted.contains("isolation_session"));
    }

    #[test]
    fn redact_raw_config_json_hides_bare_token_and_secret_fields() {
        let raw = r#"{"apiKey": "abc123", "clientSecret": "xyz", "commandLine": "run"}"#;
        let redacted = redact_raw_config_json(raw);
        assert!(!redacted.contains("abc123"));
        assert!(!redacted.contains("xyz"));
        assert!(redacted.contains("run"));
    }

    #[test]
    fn redact_raw_config_json_hides_environment_values_and_proxy_userinfo() {
        let raw = r#"{
            "process": {
                "env": ["API_KEY=hunter2", "PATH=C:\\Windows"]
            },
            "network": {
                "proxy": {
                    "url": "http://user:password@proxy.example:8080"
                }
            }
        }"#;
        let redacted = redact_raw_config_json(raw);
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("C:\\Windows"));
        assert!(redacted.contains("API_KEY=<redacted>"));
        assert!(redacted.contains("http://***@proxy.example:8080"));
        assert!(!redacted.contains("user:password"));
    }

    #[test]
    fn redact_raw_config_json_falls_back_on_malformed_json() {
        let redacted = redact_raw_config_json("{ not valid json");
        assert_eq!(
            redacted,
            "<unparsable JSON config, omitted from diagnostics>"
        );
    }

    #[test]
    fn env_bool_parses_correctly() {
        // env_bool on non-existent var returns None
        assert!(env_bool("MXC_TEST_NONEXISTENT_VAR_12345").is_none());
    }

    #[test]
    fn pipe_tokens_require_length_and_safe_characters() {
        assert!(is_valid_pipe_token("0123456789abcdef0123456789abcdef"));
        assert!(is_valid_pipe_token("0123456789abcdef0123456789ab-cdef"));
        assert!(!is_valid_pipe_token("0123456789abcdef"));
        assert!(!is_valid_pipe_token("0123456789abcdef0123456789abcde!"));
        assert!(!is_valid_pipe_token("--------------------------------"));
    }
}
