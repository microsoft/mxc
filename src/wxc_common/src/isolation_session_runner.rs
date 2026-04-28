// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `IsolationSessionRunner` — executes scripts in an IsoEnvBroker Isolation Session.
//!
//! Uses the `Windows.AI.IsolationEnvironment.Session` WinRT API to create an
//! isolated Windows session with a dedicated agent user account and run
//! processes within it.
//!
//! This module has two layers:
//! - `IsolationSessionManager`: reusable core, methods map 1:1 to the Session API lifecycle.
//! - `IsolationSessionRunner`: thin `ScriptRunner` impl for v0.1 that calls all lifecycle
//!   steps per invocation.

use std::fmt::Write;

use crate::logger::Logger;
use crate::models::{CodexRequest, IsolationSessionConfigurationId, NetworkPolicy, ScriptResponse};
use crate::script_runner::ScriptRunner;
use isolation_session_bindings::bindings::{
    IsolationSessionClient, IsolationSessionConfigurationId as BindingsConfigurationId,
    IsolationSessionOperationStatus, IsolationSessionProvisionLifetimePolicy,
    IsolationSessionProvisionOptions, IsolationSessionProvisionStatus,
    IsolationSessionRegistrationStatus, IsolationSessionWorkerProcessCreateOptions,
    IsolationSessionWorkerProcessOperationStatus, IsolationSessionWorkerProcessRedirectFlags,
};
use windows::Win32::Foundation::{
    CloseHandle, CLASS_E_CLASSNOTAVAILABLE, HANDLE, REGDB_E_CLASSNOTREG,
};
use windows::Win32::Storage::FileSystem::ReadFile;

impl From<IsolationSessionConfigurationId> for BindingsConfigurationId {
    fn from(value: IsolationSessionConfigurationId) -> Self {
        match value {
            IsolationSessionConfigurationId::Small => BindingsConfigurationId::Small,
            IsolationSessionConfigurationId::Medium => BindingsConfigurationId::Medium,
            IsolationSessionConfigurationId::Large => BindingsConfigurationId::Large,
            IsolationSessionConfigurationId::CommandLine => BindingsConfigurationId::CommandLine,
        }
    }
}

// -- Error messages for unsupported policy fields ----------------------------

pub(crate) const ERR_FILESYSTEM_POLICY: &str =
    "filesystem policy is not supported by the isolation session backend";
pub(crate) const ERR_NETWORK_POLICY: &str =
    "network policy is not supported by the isolation session backend";
pub(crate) const ERR_PROXY_POLICY: &str =
    "network proxy is not supported by the isolation session backend";

/// Validates that the request does not contain policy fields unsupported by
/// the isolation session backend. Returns `Ok(())` if valid, or `Err(message)`.
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

/// Activates the IsoEnvBroker Session API factory and verifies the service
/// is available on this OS build.
///
/// Returns `Ok(())` if the service is available, or `Err(message)` if not.
/// This is called once from `IsolationSessionManager::new()`.
pub(crate) fn check_service_available() -> Result<(), String> {
    // Try the lightest possible call: RegisterClient with an empty registration id.
    // If the WinRT activation factory is not registered (feature disabled),
    // this fails with CLASS_E_CLASSNOTAVAILABLE or similar.
    match IsolationSessionClient::RegisterClient(&windows_core::HSTRING::new()) {
        Ok(_) => Ok(()),
        Err(e) => {
            let code = e.code();
            // CLASS_E_CLASSNOTAVAILABLE / REGDB_E_CLASSNOTREG indicate the
            // service/feature is not present on this OS build.
            if code == CLASS_E_CLASSNOTAVAILABLE || code == REGDB_E_CLASSNOTREG {
                Err(format!(
                    "IsoEnvBroker Session API is not available on this OS build (HRESULT: {:#010x}). \
                     Ensure Feature_IsoBrokerSessionApis is enabled.",
                    code.0 as u32
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

// -- IsolationSessionManager (lifecycle core) --------------------------------

/// Manages the IsoEnvBroker Session API lifecycle. Methods map 1:1 to the
/// Session API steps.
pub struct IsolationSessionManager {
    /// Cohort/registration identifier passed to every Session API call.
    /// The broker accepts an empty `HSTRING` as the default cohort, which
    /// is what the v0.1 one-shot runner uses.
    registration_id: windows_core::HSTRING,
    /// Provision identifier scoping the agent user across the lifecycle
    /// steps. An empty `HSTRING` selects the broker's single default slot
    /// per registration — sufficient for the v0.1 single-session-per-process
    /// lifecycle.
    provision_id: windows_core::HSTRING,
}

impl IsolationSessionManager {
    /// Activate the WinRT factory and verify the service is available.
    pub fn new() -> Result<Self, String> {
        check_service_available()?;
        Ok(Self {
            registration_id: windows_core::HSTRING::new(),
            provision_id: windows_core::HSTRING::new(),
        })
    }

    /// Step 0: Register as a client with the IsoEnvBroker service.
    pub fn register_client(&self) -> Result<(), String> {
        let status = IsolationSessionClient::RegisterClient(&self.registration_id)
            .map_err(|e| format!("RegisterClient failed: {}", e))?;

        match status {
            IsolationSessionRegistrationStatus::New
            | IsolationSessionRegistrationStatus::AlreadyRegistered
            | IsolationSessionRegistrationStatus::Updated => Ok(()),
            _ => Err(format!(
                "RegisterClient returned unexpected status: {}",
                status.0
            )),
        }
    }

    /// Step 1: Provision an agent user account.
    pub fn provision_agent_user(&mut self, destroy_on_exit: bool) -> Result<String, String> {
        let lifetime = if destroy_on_exit {
            IsolationSessionProvisionLifetimePolicy::CallerProcess
        } else {
            IsolationSessionProvisionLifetimePolicy::Indefinite
        };

        let options = IsolationSessionProvisionOptions {
            LifetimePolicy: lifetime,
        };

        let async_op = IsolationSessionClient::ProvisionAgentUserAsync(
            &self.registration_id,
            &self.provision_id,
            options,
        )
        .map_err(|e| format!("ProvisionAgentUserAsync failed: {}", e))?;

        let result = async_op
            .join()
            .map_err(|e| format!("ProvisionAgentUserAsync: {}", e))?;

        let status = result
            .Status()
            .map_err(|e| format!("get Status failed: {}", e))?;
        if status != IsolationSessionProvisionStatus::Succeeded {
            let ext = result.ExtendedError().unwrap_or_default();
            return Err(format!(
                "ProvisionAgentUserAsync status: {} (extended: {:#010x})",
                status.0, ext.0
            ));
        }

        let name = result
            .AgentUserName()
            .map_err(|e| format!("get AgentUserName failed: {}", e))?;
        Ok(name.to_string())
    }

    /// Step 2: Start the isolation session (log the agent user into a Windows session).
    pub fn start_session(&self, config_id: IsolationSessionConfigurationId) -> Result<(), String> {
        let config_id_com: BindingsConfigurationId = config_id.into();
        let async_op = IsolationSessionClient::StartSessionAsync(
            &self.registration_id,
            &self.provision_id,
            config_id_com,
        )
        .map_err(|e| format!("StartSessionAsync failed: {}", e))?;

        let status = async_op
            .join()
            .map_err(|e| format!("StartSessionAsync: {}", e))?;

        match status {
            IsolationSessionOperationStatus::Succeeded
            | IsolationSessionOperationStatus::SessionAlreadyStarted => Ok(()),
            _ => Err(format!("StartSessionAsync returned status: {}", status.0)),
        }
    }

    /// Step 3: Create a process inside the started isolation session and
    /// capture its output.
    pub(crate) fn create_process(&self, options: &ProcessOptions) -> Result<ProcessResult, String> {
        // Build the WinRT create options.
        let create_opts = IsolationSessionWorkerProcessCreateOptions::new()
            .map_err(|e| format!("Failed to create WorkerProcessCreateOptions: {}", e))?;

        create_opts
            .SetRedirectFlags(IsolationSessionWorkerProcessRedirectFlags(
                options.redirect_flags,
            ))
            .map_err(|e| format!("SetRedirectFlags: {}", e))?;

        if options.timeout_ms > 0 {
            create_opts
                .SetTimeoutMilliseconds(options.timeout_ms)
                .map_err(|e| format!("SetTimeoutMilliseconds: {}", e))?;
        }

        if !options.working_directory.is_empty() {
            create_opts
                .SetWorkingDirectory(&windows_core::HSTRING::from(&options.working_directory))
                .map_err(|e| format!("SetWorkingDirectory: {}", e))?;
        }

        if !options.env_vars.is_empty() {
            let names: Vec<windows_core::HSTRING> = options
                .env_vars
                .iter()
                .map(|(k, _)| windows_core::HSTRING::from(k.as_str()))
                .collect();
            let values: Vec<windows_core::HSTRING> = options
                .env_vars
                .iter()
                .map(|(_, v)| windows_core::HSTRING::from(v.as_str()))
                .collect();
            create_opts
                .SetEnvironmentVariables(&names, &values)
                .map_err(|e| format!("SetEnvironmentVariables: {}", e))?;
        }

        // Launch the process.
        let async_op = IsolationSessionClient::CreateIsolatedProcessAsync2(
            &self.registration_id,
            &self.provision_id,
            &windows_core::HSTRING::from(&options.process_path),
            &windows_core::HSTRING::from(&options.arguments),
            &create_opts,
        )
        .map_err(|e| format!("CreateIsolatedProcessAsync2 failed: {}", e))?;

        let result = async_op
            .join()
            .map_err(|e| format!("CreateIsolatedProcessAsync2: {}", e))?;

        let status = result
            .Status()
            .map_err(|e| format!("get process Status failed: {}", e))?;
        if status != IsolationSessionWorkerProcessOperationStatus::Succeeded {
            let ext = result.ExtendedError().unwrap_or_default();
            return Err(format!(
                "CreateIsolatedProcessAsync2 status: {} (extended: {:#010x})",
                status.0, ext.0
            ));
        }

        let worker = result
            .Process()
            .map_err(|e| format!("get Process failed: {}", e))?;

        // Read stdout/stderr via pipe handles.
        let stdout = {
            let out_handle = worker
                .CreateStandardOutputHandle()
                .map_err(|e| format!("CreateStandardOutputHandle: {}", e))?;
            if out_handle != 0 {
                read_pipe_and_close(out_handle)
            } else {
                String::new()
            }
        };

        let stderr = {
            let err_handle = worker
                .CreateStandardErrorHandle()
                .map_err(|e| format!("CreateStandardErrorHandle: {}", e))?;
            if err_handle != 0 {
                read_pipe_and_close(err_handle)
            } else {
                String::new()
            }
        };

        // Wait for exit and get exit code.
        let wait_op = worker
            .WaitForExitAsync()
            .map_err(|e| format!("WaitForExitAsync: {}", e))?;
        wait_op
            .join()
            .map_err(|e| format!("WaitForExitAsync: {}", e))?;

        let exit_code = worker
            .ExitCode()
            .map_err(|e| format!("get ExitCode: {}", e))?;

        Ok(ProcessResult {
            exit_code,
            stdout,
            stderr,
        })
    }

    /// Step 4: Stop the isolation session.
    pub fn stop_session(&self) -> Result<(), String> {
        let async_op =
            IsolationSessionClient::StopSessionAsync(&self.registration_id, &self.provision_id)
                .map_err(|e| format!("StopSessionAsync failed: {}", e))?;

        let status = async_op
            .join()
            .map_err(|e| format!("StopSessionAsync: {}", e))?;

        match status {
            IsolationSessionOperationStatus::Succeeded
            | IsolationSessionOperationStatus::SessionNotStarted => Ok(()),
            _ => Err(format!("StopSessionAsync returned status: {}", status.0)),
        }
    }

    /// Step 5: Deprovision the agent user account.
    pub fn deprovision_agent_user(&self) -> Result<(), String> {
        let async_op = IsolationSessionClient::DeprovisionAgentUserAsync(
            &self.registration_id,
            &self.provision_id,
        )
        .map_err(|e| format!("DeprovisionAgentUserAsync failed: {}", e))?;

        let status = async_op
            .join()
            .map_err(|e| format!("DeprovisionAgentUserAsync: {}", e))?;

        match status {
            IsolationSessionProvisionStatus::Succeeded => Ok(()),
            _ => Err(format!(
                "DeprovisionAgentUserAsync returned status: {}",
                status.0
            )),
        }
    }

    /// Step 6: Unregister the client.
    pub fn unregister_client(&self) -> Result<(), String> {
        let async_op = IsolationSessionClient::UnregisterClientAsync(&self.registration_id)
            .map_err(|e| format!("UnregisterClientAsync failed: {}", e))?;

        let _status = async_op
            .join()
            .map_err(|e| format!("UnregisterClientAsync: {}", e))?;

        Ok(())
    }
}

/// Reads all data from a pipe handle and closes it.
fn read_pipe_and_close(handle_value: u64) -> String {
    let handle = HANDLE(handle_value as *mut core::ffi::c_void);
    let mut output = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let mut bytes_read = 0u32;
        // SAFETY: `handle` is a kernel handle returned to this function by
        // the IsoEnvBroker (`CreateStandardOutputHandle` /
        // `CreateStandardErrorHandle`); we own it for the duration of this
        // call. `buffer` and `bytes_read` are stack-allocated and live for
        // the entire `ReadFile` call.
        let ok = unsafe { ReadFile(handle, Some(&mut buffer), Some(&mut bytes_read), None) };
        if ok.is_err() || bytes_read == 0 {
            break;
        }
        output.extend_from_slice(&buffer[..bytes_read as usize]);
    }
    // SAFETY: `handle` was used in `ReadFile` above and is closed exactly
    // once here at end-of-scope, matching the kernel-handle teardown contract.
    unsafe {
        let _ = CloseHandle(handle);
    }
    String::from_utf8_lossy(&output).to_string()
}

/// Result of a process execution in the isolation session.
pub struct ProcessResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

// -- IsolationSessionRunner (ScriptRunner impl) ------------------------------

/// Thin `ScriptRunner` wrapper that performs the full isolation session lifecycle
/// per invocation. For v0.1, each `run()` call does:
/// register → provision → start → execute → stop → deprovision → unregister.
pub struct IsolationSessionRunner;

impl IsolationSessionRunner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IsolationSessionRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptRunner for IsolationSessionRunner {
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        // Validate unsupported policy fields.
        if let Err(msg) = validate_policy(request) {
            return ScriptResponse::error(&msg);
        }

        let options = build_process_options(request);
        let _ = writeln!(
            logger,
            "Isolation Session: process={}",
            options.process_path
        );
        let _ = writeln!(logger, "Isolation Session: arguments={}", options.arguments);

        // Read isolation_session config (configuration id).
        let session_cfg = request.experimental.isolation_session.as_ref();
        let config_id: IsolationSessionConfigurationId = session_cfg
            .map(|cfg| cfg.configuration_id)
            .unwrap_or_default();

        // Create the session manager (activates the WinRT factory).
        let mut manager = match IsolationSessionManager::new() {
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
                let _ = writeln!(logger, "Isolation Session: agent user = {}", agent_name);
            }
            Err(e) => {
                // provision_agent_user may return Err *after* a successful broker-side
                // provision (e.g., the AgentUserName fetch fails on a Succeeded result).
                // Defensively deprovision so an Indefinite-lifetime agent user does not
                // leak. The broker no-ops these calls on absent state.
                let _ = manager.deprovision_agent_user();
                let _ = manager.unregister_client();
                return ScriptResponse::error(&format!("provision_agent_user failed: {}", e));
            }
        }

        if let Err(e) = manager.start_session(config_id) {
            // Provision succeeded; start did not. Clean up the provisioned agent
            // user. stop_session is a no-op on an unstarted session.
            let _ = manager.stop_session();
            let _ = manager.deprovision_agent_user();
            let _ = manager.unregister_client();
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
            env: vec!["FOO=bar".to_string(), "PATH=C:\\bin;C:\\tools".to_string()],
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
