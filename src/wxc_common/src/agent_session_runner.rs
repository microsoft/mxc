// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `AgentSessionRunner` — executes scripts in an IsoEnvBroker Agent Session.
//!
//! Uses the `Windows.AI.IsolationEnvironment.Session` WinRT API to create an
//! isolated Windows session with a dedicated agent user account and run
//! processes within it.
//!
//! This module has two layers:
//! - `AgentSessionManager`: reusable core, methods map 1:1 to the Session API lifecycle.
//! - `AgentSessionRunner`: thin `ScriptRunner` impl for v0.1 that calls all lifecycle
//!   steps per invocation.

use std::fmt::Write;

use crate::logger::Logger;
use crate::models::{CodexRequest, NetworkPolicy, ScriptResponse};
use crate::script_runner::ScriptRunner;
use agent_session_bindings::bindings::IsolationSessionClient;

// -- Error messages for unsupported policy fields ----------------------------

pub(crate) const ERR_FILESYSTEM_POLICY: &str =
    "filesystem policy is not supported by the agent session backend";
pub(crate) const ERR_NETWORK_POLICY: &str =
    "network policy is not supported by the agent session backend";
pub(crate) const ERR_PROXY_POLICY: &str =
    "network proxy is not supported by the agent session backend";

/// Validates that the request does not contain policy fields unsupported by
/// the agent session backend. Returns `Ok(())` if valid, or `Err(message)`.
pub(crate) fn validate_policy(request: &CodexRequest) -> Result<(), String> {
    if !request.policy.readwrite_paths.is_empty()
        || !request.policy.readonly_paths.is_empty()
        || !request.policy.denied_paths.is_empty()
    {
        return Err(ERR_FILESYSTEM_POLICY.to_string());
    }
    if !request.policy.allowed_hosts.is_empty()
        || !request.policy.blocked_hosts.is_empty()
        || request.policy.default_network_policy != NetworkPolicy::Allow
    {
        return Err(ERR_NETWORK_POLICY.to_string());
    }
    if request.policy.network_proxy.is_enabled() {
        return Err(ERR_PROXY_POLICY.to_string());
    }
    Ok(())
}

// -- Process options (intermediate struct for testability) --------------------

/// Redirect flags for worker process I/O.
pub(crate) const REDIRECT_STDOUT: u32 = 0x2;
pub(crate) const REDIRECT_STDERR: u32 = 0x4;

/// Intermediate representation of process creation options, decoupled from
/// both `CodexRequest` (MXC-specific) and WinRT types (OS-specific).
/// Built from `CodexRequest`, later converted to WinRT options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessOptions {
    /// Full path to the executable (e.g., `C:\Windows\System32\cmd.exe`).
    pub process_path: String,
    /// Command-line arguments (e.g., `/c echo hello`).
    pub arguments: String,
    /// Execution timeout in milliseconds. 0 = no timeout.
    pub timeout_ms: u32,
    /// Working directory for the child process. Empty = default.
    pub working_directory: String,
    /// Environment variables as (name, value) pairs.
    pub env_vars: Vec<(String, String)>,
    /// Bitfield of I/O redirect flags.
    pub redirect_flags: u32,
}

/// Builds `ProcessOptions` from a `CodexRequest`.
///
/// The command line is wrapped with `cmd.exe /c` so that shell features
/// (pipes, redirections, chained commands) work correctly — same pattern
/// as the LXC backend's `/bin/sh -c`.
pub(crate) fn build_process_options(request: &CodexRequest) -> ProcessOptions {
    let env_vars: Vec<(String, String)> = request
        .env
        .iter()
        .filter_map(|entry| {
            let mut parts = entry.splitn(2, '=');
            let name = parts.next()?.to_string();
            let value = parts.next().unwrap_or("").to_string();
            if name.is_empty() {
                None
            } else {
                Some((name, value))
            }
        })
        .collect();

    ProcessOptions {
        process_path: r"C:\Windows\System32\cmd.exe".to_string(),
        arguments: format!("/c {}", request.script_code),
        timeout_ms: request.script_timeout,
        working_directory: request.working_directory.clone(),
        env_vars,
        redirect_flags: REDIRECT_STDOUT | REDIRECT_STDERR,
    }
}

// -- Service availability check ----------------------------------------------

/// Attempts to activate the IsoEnvBroker Session API factory.
/// Returns `Ok(())` if the service is available, or `Err(message)` if not.
///
/// This is the first call in `AgentSessionManager::new()` — factored out
/// for testability.
pub(crate) fn check_service_available() -> Result<(), String> {
    // Try the lightest possible call: RegisterClient with empty strings.
    // If the WinRT activation factory is not registered (feature disabled),
    // this fails with CLASS_E_CLASSNOTAVAILABLE or similar.
    match IsolationSessionClient::RegisterClient(
        &windows_core::HSTRING::new(),
        &windows_core::HSTRING::new(),
    ) {
        Ok(_) => Ok(()),
        Err(e) => {
            let code = e.code().0 as u32;
            // CLASS_E_CLASSNOTAVAILABLE (0x80040111) or REGDB_E_CLASSNOTREG (0x80040154)
            // indicate the service/feature is not present on this OS build.
            if code == 0x80040111 || code == 0x80040154 {
                Err(format!(
                    "IsoEnvBroker Session API is not available on this OS build (HRESULT: {:#010x}). \
                     Ensure Feature_IsoBrokerSessionApis is enabled.",
                    code
                ))
            } else {
                // Other errors (permission denied, cohort check failure, etc.)
                // mean the service IS present but the call failed for another reason.
                // That's fine — the service is available.
                Ok(())
            }
        }
    }
}

// -- AgentSessionManager (lifecycle core) ------------------------------------

/// Manages the IsoEnvBroker Session API lifecycle. Methods map 1:1 to the
/// Session API steps. Currently stubs — real COM calls come in CP7.
pub struct AgentSessionManager {
    // These fields will be populated by register_client/provision_agent_user in CP7.
    _registration_id: String,
    _provision_id: String,
}

impl AgentSessionManager {
    /// Activate the WinRT factory and verify the service is available.
    pub fn new() -> Result<Self, String> {
        check_service_available()?;
        Ok(Self {
            _registration_id: String::new(),
            _provision_id: String::new(),
        })
    }

    /// Step 0: Register as a client with the IsoEnvBroker service.
    pub fn register_client(&self) -> Result<(), String> {
        Err("AgentSessionManager::register_client not yet implemented".to_string())
    }

    /// Step 1: Provision an agent user account.
    pub fn provision_agent_user(&mut self, _destroy_on_exit: bool) -> Result<String, String> {
        Err("AgentSessionManager::provision_agent_user not yet implemented".to_string())
    }

    /// Step 2: Start the agent session (log the agent user into a Windows session).
    pub fn start_session(&self) -> Result<(), String> {
        Err("AgentSessionManager::start_session not yet implemented".to_string())
    }

    /// Step 3: Create an isolated process and capture its output.
    pub(crate) fn create_process(&self, _options: &ProcessOptions) -> Result<ProcessResult, String> {
        Err("AgentSessionManager::create_process not yet implemented".to_string())
    }

    /// Step 4: Stop the agent session.
    pub fn stop_session(&self) -> Result<(), String> {
        Err("AgentSessionManager::stop_session not yet implemented".to_string())
    }

    /// Step 5: Deprovision the agent user account.
    pub fn deprovision_agent_user(&self) -> Result<(), String> {
        Err("AgentSessionManager::deprovision_agent_user not yet implemented".to_string())
    }

    /// Step 6: Unregister the client.
    pub fn unregister_client(&self) -> Result<(), String> {
        Err("AgentSessionManager::unregister_client not yet implemented".to_string())
    }
}

/// Result of a process execution in the agent session.
pub struct ProcessResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

// -- AgentSessionRunner (ScriptRunner impl) ----------------------------------

/// Thin `ScriptRunner` wrapper that performs the full agent session lifecycle
/// per invocation. For v0.1, each `run()` call does:
/// register → provision → start → execute → stop → deprovision → unregister.
pub struct AgentSessionRunner;

impl AgentSessionRunner {
    pub fn new() -> Self {
        Self
    }
}

impl ScriptRunner for AgentSessionRunner {
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        // Validate unsupported policy fields.
        if let Err(msg) = validate_policy(request) {
            return ScriptResponse::error(&msg);
        }

        let options = build_process_options(request);
        let _ = writeln!(logger, "Agent Session: process={}", options.process_path);
        let _ = writeln!(logger, "Agent Session: arguments={}", options.arguments);

        // Create the session manager (activates the WinRT factory).
        let mut manager = match AgentSessionManager::new() {
            Ok(m) => m,
            Err(e) => return ScriptResponse::error(&e),
        };

        // Full lifecycle: register → provision → start → execute → stop → deprovision → unregister.
        if let Err(e) = manager.register_client() {
            return ScriptResponse::error(&format!("register_client failed: {}", e));
        }

        let destroy_on_exit = request.lifecycle.destroy_on_exit;
        match manager.provision_agent_user(destroy_on_exit) {
            Ok(agent_name) => {
                let _ = writeln!(logger, "Agent Session: agent user = {}", agent_name);
            }
            Err(e) => return ScriptResponse::error(&format!("provision_agent_user failed: {}", e)),
        }

        if let Err(e) = manager.start_session() {
            return ScriptResponse::error(&format!("start_session failed: {}", e));
        }

        let result = match manager.create_process(&options) {
            Ok(r) => r,
            Err(e) => {
                // Attempt cleanup even on failure.
                let _ = manager.stop_session();
                let _ = manager.deprovision_agent_user();
                let _ = manager.unregister_client();
                return ScriptResponse::error(&format!("create_process failed: {}", e));
            }
        };

        // Cleanup: stop → deprovision → unregister.
        if let Err(e) = manager.stop_session() {
            let _ = writeln!(logger, "Warning: stop_session failed: {}", e);
        }
        if let Err(e) = manager.deprovision_agent_user() {
            let _ = writeln!(logger, "Warning: deprovision_agent_user failed: {}", e);
        }
        if let Err(e) = manager.unregister_client() {
            let _ = writeln!(logger, "Warning: unregister_client failed: {}", e);
        }

        ScriptResponse {
            exit_code: result.exit_code,
            standard_out: result.stdout,
            standard_err: result.stderr.clone(),
            error_message: result.stderr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CodexRequest, ContainerPolicy, NetworkPolicy, ProxyAddress, ProxyConfig};

    #[test]
    fn policy_rejects_readwrite_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_FILESYSTEM_POLICY));
    }

    #[test]
    fn policy_rejects_readonly_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_FILESYSTEM_POLICY));
    }

    #[test]
    fn policy_rejects_denied_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                denied_paths: vec!["C:\\secret".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_FILESYSTEM_POLICY));
    }

    #[test]
    fn policy_rejects_allowed_hosts() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                allowed_hosts: vec!["example.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_NETWORK_POLICY));
    }

    #[test]
    fn policy_rejects_blocked_hosts() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                blocked_hosts: vec!["evil.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_NETWORK_POLICY));
    }

    #[test]
    fn policy_rejects_network_block_policy() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Block,
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_NETWORK_POLICY));
    }

    #[test]
    fn policy_rejects_proxy() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                network_proxy: ProxyConfig {
                    address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
                    builtin_test_server: false,
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_PROXY_POLICY));
    }

    #[test]
    fn policy_allows_defaults() {
        let request = CodexRequest::default();
        assert!(validate_policy(&request).is_ok());
    }

    // ====== ProcessOptions / option building tests ======

    #[test]
    fn options_wraps_command_with_cmd_exe() {
        let request = CodexRequest {
            script_code: "echo hello".to_string(),
            ..Default::default()
        };
        let opts = build_process_options(&request);
        assert_eq!(opts.process_path, r"C:\Windows\System32\cmd.exe");
        assert_eq!(opts.arguments, "/c echo hello");
    }

    #[test]
    fn options_maps_timeout() {
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            script_timeout: 30000,
            ..Default::default()
        };
        let opts = build_process_options(&request);
        assert_eq!(opts.timeout_ms, 30000);
    }

    #[test]
    fn options_maps_working_directory() {
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            working_directory: r"C:\Windows".to_string(),
            ..Default::default()
        };
        let opts = build_process_options(&request);
        assert_eq!(opts.working_directory, r"C:\Windows");
    }

    #[test]
    fn options_parses_env_vars() {
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            env: vec![
                "FOO=bar".to_string(),
                "PATH=C:\\bin;C:\\tools".to_string(),
            ],
            ..Default::default()
        };
        let opts = build_process_options(&request);
        assert_eq!(opts.env_vars.len(), 2);
        assert_eq!(opts.env_vars[0], ("FOO".to_string(), "bar".to_string()));
        assert_eq!(
            opts.env_vars[1],
            ("PATH".to_string(), r"C:\bin;C:\tools".to_string())
        );
    }

    #[test]
    fn options_skips_malformed_env_vars() {
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            env: vec![
                "GOOD=value".to_string(),
                "=no_name".to_string(),
                "ALSO_GOOD=".to_string(),
            ],
            ..Default::default()
        };
        let opts = build_process_options(&request);
        assert_eq!(opts.env_vars.len(), 2);
        assert_eq!(opts.env_vars[0].0, "GOOD");
        assert_eq!(opts.env_vars[1], ("ALSO_GOOD".to_string(), String::new()));
    }

    #[test]
    fn options_sets_redirect_flags() {
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            ..Default::default()
        };
        let opts = build_process_options(&request);
        assert_eq!(opts.redirect_flags, REDIRECT_STDOUT | REDIRECT_STDERR);
    }

    // ====== Service availability test ======

    #[test]
    fn feature_unavailable_returns_clean_error() {
        // Initialize COM (required for WinRT activation).
        let _ = unsafe {
            windows::Win32::System::Com::CoInitializeEx(
                None,
                windows::Win32::System::Com::COINIT_MULTITHREADED,
            )
        };

        match check_service_available() {
            Ok(()) => {
                // Service IS available on this machine (e.g., a test VM with
                // the feature enabled). The test is not applicable — skip.
            }
            Err(msg) => {
                // Service is NOT available. Verify the error is clean and
                // descriptive (not a panic or cryptic COM error).
                assert!(
                    msg.contains("not available"),
                    "Expected descriptive error message, got: {}",
                    msg
                );
            }
        }
    }
}
