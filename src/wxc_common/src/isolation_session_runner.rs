// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `IsolationSessionRunner` — executes scripts in an IsoEnvBroker Isolation Session.
//!
//! Uses the in-proc `Windows.AI.IsolationSession` `IsoSessionOps` API to
//! create an isolated Windows session with a dedicated agent user account
//! and run processes within it.
//!
//! This module has two layers:
//! - `IsolationSessionManager`: reusable core, methods map 1:1 to the
//!   `IsoSessionOps` granular lifecycle.
//! - `IsolationSessionRunner`: thin `ScriptRunner` impl for v0.1 that runs
//!   the full lifecycle per invocation.

use std::fmt::Write;

use crate::logger::Logger;
use crate::models::{CodexRequest, IsolationSessionConfigurationId, NetworkPolicy, ScriptResponse};
use crate::script_runner::ScriptRunner;
use isolation_session_bindings::bindings::{
    IsoSessionConfigId, IsoSessionError, IsoSessionOps, IsoSessionProcess,
    IsoSessionProcessOptions, IsoSessionProcessResult, IsoSessionResult, IsoSessionUserResult,
};
use windows::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, HANDLE, REGDB_E_CLASSNOTREG};
use windows::Win32::Storage::FileSystem::ReadFile;
use windows_core::HSTRING;

// -- Identifiers -------------------------------------------------------------

/// Cohort registration ID used with the `IsoSessionOps` wrapper.
///
/// The wrapper hardcodes `L"regid"` internally for every agent-name-keyed op
/// (`ApiIsoSessionOps.cpp` lines 80, 90, 106, 115, 132, 187 in the OS repo),
/// so callers must register with the literal `"regid"` or subsequent calls
/// hit the wrong cohort.
const REGISTRATION_ID: &str = "regid";

/// Provision identifier scoping the agent user across the lifecycle.
///
/// Reused as the `agentName` parameter on every subsequent op — the wrapper
/// aliases agentName to provisionId at the COM layer (per the comment in
/// `CommandSession.cpp:64` in the OS repo, `IsoSessionOps` callers pass
/// `provisionId` where the IDL says `agentName`).
const PROVISION_ID: &str = "wxc-provid";

impl From<IsolationSessionConfigurationId> for IsoSessionConfigId {
    fn from(value: IsolationSessionConfigurationId) -> Self {
        match value {
            IsolationSessionConfigurationId::Small => IsoSessionConfigId::Small,
            IsolationSessionConfigurationId::Medium => IsoSessionConfigId::Medium,
            IsolationSessionConfigurationId::Large => IsoSessionConfigId::Large,
            IsolationSessionConfigurationId::Composable => IsoSessionConfigId::Composable,
        }
    }
}

// -- IsolationSessionError ---------------------------------------------------

/// Categorised errors from the IsolationSession backend.
#[derive(Debug)]
pub enum IsolationSessionError {
    /// The caller-supplied container policy contains a field this backend
    /// does not support (filesystem rules, network rules, proxy).
    Policy(String),
    /// The in-proc `Windows.AI.IsolationSession` `IsoSessionOps` API is
    /// not available on this host (DLL not registered or
    /// `Feature_IsoBrokerSessionApis` disabled).
    ServiceUnavailable(String),
    /// A broker-side lifecycle step (register / provision / start / exec /
    /// stop / deprovision / unregister) returned a failure.
    Lifecycle(String),
}

impl std::fmt::Display for IsolationSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(msg) => write!(f, "Isolation Session policy error: {}", msg),
            Self::ServiceUnavailable(msg) => {
                write!(f, "Isolation Session service unavailable: {}", msg)
            }
            Self::Lifecycle(msg) => write!(f, "Isolation Session lifecycle error: {}", msg),
        }
    }
}

impl From<IsolationSessionError> for ScriptResponse {
    fn from(err: IsolationSessionError) -> Self {
        ScriptResponse::error(&err.to_string())
    }
}

/// Helper to construct an `IsolationSessionError::Lifecycle` from a formatted message.
fn lifecycle_err(msg: impl Into<String>) -> IsolationSessionError {
    IsolationSessionError::Lifecycle(msg.into())
}

// -- Error messages for unsupported policy fields ----------------------------

pub(crate) const ERR_FILESYSTEM_POLICY: &str =
    "filesystem policy is not supported by the isolation session backend";
pub(crate) const ERR_NETWORK_POLICY: &str =
    "network policy is not supported by the isolation session backend";
pub(crate) const ERR_PROXY_POLICY: &str =
    "network proxy is not supported by the isolation session backend";

/// Validates that the request does not contain policy fields unsupported by
/// the isolation session backend. Returns `Ok(())` if valid, or a
/// `Policy`-variant error on rejection.
pub(crate) fn validate_policy(request: &CodexRequest) -> Result<(), IsolationSessionError> {
    if !request.policy.readwrite_paths.is_empty()
        || !request.policy.readonly_paths.is_empty()
        || !request.policy.denied_paths.is_empty()
    {
        return Err(IsolationSessionError::Policy(
            ERR_FILESYSTEM_POLICY.to_string(),
        ));
    }
    if !request.policy.allowed_hosts.is_empty()
        || !request.policy.blocked_hosts.is_empty()
        || request.policy.default_network_policy != NetworkPolicy::Allow
    {
        return Err(IsolationSessionError::Policy(
            ERR_NETWORK_POLICY.to_string(),
        ));
    }
    if request.policy.network_proxy.is_enabled() {
        return Err(IsolationSessionError::Policy(ERR_PROXY_POLICY.to_string()));
    }
    Ok(())
}

// -- Process options (intermediate struct for testability) -------------------

/// Redirect flags for worker process I/O. The bitfield is internal to MXC;
/// the conversion to per-stream booleans on `IsoSessionProcessOptions`
/// happens inside `build_iso_process_options`.
pub(crate) const REDIRECT_STDIN: u32 = 0x1;
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
    /// Bitfield of I/O redirect flags (`REDIRECT_STDIN | REDIRECT_STDOUT | REDIRECT_STDERR`).
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

    // Resolve the cmd.exe path off the host's `SystemDrive` (which the agent
    // session inherits since it runs on the same OS host) rather than
    // hardcoding `C:`. Falls back to `C:` on the unlikely chance the env
    // var is absent.
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let process_path = format!(r"{}\Windows\System32\cmd.exe", system_drive);

    ProcessOptions {
        process_path,
        arguments: format!("/c {}", request.script_code),
        timeout_ms: request.script_timeout,
        working_directory: request.working_directory.clone(),
        env_vars,
        redirect_flags: REDIRECT_STDOUT | REDIRECT_STDERR,
    }
}

// -- Service availability check ----------------------------------------------

/// Activates the in-proc `IsoSessionOps` factory and returns the instance.
///
/// Returns the activated `IsoSessionOps` on success, or a
/// `ServiceUnavailable` variant if not. This is called once from
/// `IsolationSessionManager::new()`.
pub(crate) fn check_service_available_and_activate() -> Result<IsoSessionOps, IsolationSessionError>
{
    match IsoSessionOps::new() {
        Ok(ops) => Ok(ops),
        Err(e) => {
            let code = e.code();
            if code == CLASS_E_CLASSNOTAVAILABLE || code == REGDB_E_CLASSNOTREG {
                Err(IsolationSessionError::ServiceUnavailable(format!(
                    "in-proc Windows.AI.IsolationSession IsoSessionOps API is not available \
                     on this OS build (HRESULT: {:#010x}). Ensure IsoSessionApp.dll is \
                     registered and Feature_IsoBrokerSessionApis is enabled.",
                    code.0 as u32
                )))
            } else {
                Err(IsolationSessionError::ServiceUnavailable(format!(
                    "IsoSessionOps activation failed (HRESULT: {:#010x}): {}",
                    code.0 as u32, e
                )))
            }
        }
    }
}

// -- Helper: structured error checks -----------------------------------------

/// Formats an `IsoSessionError` (the WinRT result type) into a lifecycle
/// error string with HRESULT, message, and remediation hint where present.
fn format_iso_error(op: &str, err: &IsoSessionError) -> IsolationSessionError {
    let msg = err.Message().map(|h| h.to_string()).unwrap_or_default();
    let code = err.Code().map(|h| h.0 as u32).unwrap_or(0);
    let remediation = err.Remediation().map(|h| h.to_string()).unwrap_or_default();
    let suffix = if remediation.is_empty() {
        String::new()
    } else {
        format!(" — remediation: {}", remediation)
    };
    lifecycle_err(format!(
        "{} failed: {} (HRESULT: {:#010x}){}",
        op, msg, code, suffix
    ))
}

/// Checks the `Error` property of an `IsoSessionResult` and returns
/// `Ok(())` when there's no error, or a lifecycle error with the formatted
/// details otherwise.
fn check_result(result: &IsoSessionResult, op: &str) -> Result<(), IsolationSessionError> {
    let err = result
        .Error()
        .map_err(|e| lifecycle_err(format!("{}: get Error failed: {}", op, e)))?;
    let is_error = err
        .IsError()
        .map_err(|e| lifecycle_err(format!("{}: get IsError failed: {}", op, e)))?;
    if is_error {
        Err(format_iso_error(op, &err))
    } else {
        Ok(())
    }
}

// -- IsolationSessionManager (lifecycle core) --------------------------------

/// Manages the `IsoSessionOps` lifecycle. Methods map 1:1 to the granular
/// API steps.
pub struct IsolationSessionManager {
    /// Cohort/registration identifier used in `RegisterApp` / `AddUserAsync`
    /// / `UnregisterAppAsync`. Pegged to the literal `"regid"` per the
    /// wrapper's internal hardcode.
    registration_id: HSTRING,
    /// Provision identifier. Used as the `provisionId` argument to
    /// `AddUserAsync` and as the `agentName` argument to every subsequent
    /// op (the wrapper aliases them at the COM layer).
    provision_id: HSTRING,
    /// The activated `IsoSessionOps` instance. Held for the lifetime of the
    /// manager so the WinRT factory is reused across calls.
    ops: IsoSessionOps,
}

impl IsolationSessionManager {
    /// Activates the `IsoSessionOps` factory and verifies the service is
    /// available.
    pub fn new() -> Result<Self, IsolationSessionError> {
        let ops = check_service_available_and_activate()?;
        Ok(Self {
            registration_id: HSTRING::from(REGISTRATION_ID),
            provision_id: HSTRING::from(PROVISION_ID),
            ops,
        })
    }

    /// Step 0: Register the app with the broker.
    pub fn register_client(&self) -> Result<(), IsolationSessionError> {
        let result = self
            .ops
            .RegisterApp(&self.registration_id)
            .map_err(|e| lifecycle_err(format!("RegisterApp call failed: {}", e)))?;
        check_result(&result, "RegisterApp")
    }

    /// Step 1: Provision an agent user. Returns the OS-assigned agent
    /// account name (e.g., `Adib-IEB-000`) for logging only — addressing
    /// for subsequent ops continues to use the configured `provision_id`.
    ///
    /// Note: `lifecycle.destroyOnExit` is silently ignored on this backend.
    /// The in-proc API hardcodes `Indefinite` lifetime in `AddUserAsync`
    /// (`IsoSessionServerClient.cpp:147` in the OS repo) and the wrapper's
    /// `RemoveUserAsync` papers over the Indefinite-deprovision bug.
    pub fn provision_agent_user(&self) -> Result<String, IsolationSessionError> {
        let async_op = self
            .ops
            .AddUserAsync(&self.registration_id, &self.provision_id)
            .map_err(|e| lifecycle_err(format!("AddUserAsync call failed: {}", e)))?;
        let user_result: IsoSessionUserResult = async_op
            .join()
            .map_err(|e| lifecycle_err(format!("AddUserAsync wait failed: {}", e)))?;

        let err = user_result
            .Error()
            .map_err(|e| lifecycle_err(format!("AddUserAsync: get Error failed: {}", e)))?;
        let is_error = err.IsError().unwrap_or(false);
        if is_error {
            return Err(format_iso_error("AddUserAsync", &err));
        }

        let name = user_result
            .AgentUserName()
            .map_err(|e| lifecycle_err(format!("AddUserAsync: get AgentUserName failed: {}", e)))?;
        Ok(name.to_string())
    }

    /// Step 2: Start the isolation session.
    pub fn start_session(
        &self,
        config_id: IsolationSessionConfigurationId,
    ) -> Result<(), IsolationSessionError> {
        let cfg: IsoSessionConfigId = config_id.into();
        let async_op = self
            .ops
            .StartSessionAsync(&self.provision_id, cfg)
            .map_err(|e| lifecycle_err(format!("StartSessionAsync call failed: {}", e)))?;
        let result = async_op
            .join()
            .map_err(|e| lifecycle_err(format!("StartSessionAsync wait failed: {}", e)))?;
        check_result(&result, "StartSessionAsync")
    }

    /// Step 3: Create a process inside the started isolation session and
    /// capture its output.
    pub(crate) fn create_process(
        &self,
        options: &ProcessOptions,
    ) -> Result<ProcessResult, IsolationSessionError> {
        let proc_options = build_iso_process_options(options)?;

        let async_op = self
            .ops
            .RunProcessWithOptionsAsync(
                &self.provision_id,
                &HSTRING::from(&options.process_path),
                &HSTRING::from(&options.arguments),
                &proc_options,
            )
            .map_err(|e| lifecycle_err(format!("RunProcessWithOptionsAsync call failed: {}", e)))?;
        let result: IsoSessionProcessResult = async_op
            .join()
            .map_err(|e| lifecycle_err(format!("RunProcessWithOptionsAsync wait failed: {}", e)))?;

        let err = result.Error().map_err(|e| {
            lifecycle_err(format!(
                "RunProcessWithOptionsAsync: get Error failed: {}",
                e
            ))
        })?;
        let is_error = err.IsError().unwrap_or(false);
        if is_error {
            return Err(format_iso_error("RunProcessWithOptionsAsync", &err));
        }

        let process: IsoSessionProcess = result.Process().map_err(|e| {
            lifecycle_err(format!(
                "RunProcessWithOptionsAsync: get Process failed: {}",
                e
            ))
        })?;

        // Read stdout/stderr via the pipe handles owned by `IsoSessionProcess`.
        // We do NOT close these handles here — `process.Close()` (or drop)
        // does (`ApiProcess.cpp:131` in the OS repo).
        let stdout_handle = process.OutputHandle().unwrap_or(0);
        let stderr_handle = process.ErrorHandle().unwrap_or(0);
        let stdout = read_pipe_to_string(stdout_handle);
        let stderr = read_pipe_to_string(stderr_handle);

        // Wait for exit. `WaitForExit` is a Win32 `WaitForSingleObject` on
        // a kernel handle owned by the in-proc DLL — no COM round-trip
        // (`ApiProcess.cpp:76` in the OS repo).
        let _ = process
            .WaitForExit(options.timeout_ms)
            .map_err(|e| lifecycle_err(format!("WaitForExit failed: {}", e)))?;
        let exit_code = process
            .ExitCode()
            .map_err(|e| lifecycle_err(format!("get ExitCode failed: {}", e)))?;

        // Release the handles owned by the process object.
        let _ = process.Close();

        Ok(ProcessResult {
            exit_code,
            stdout,
            stderr,
        })
    }

    /// Step 4: Stop the isolation session.
    pub fn stop_session(&self) -> Result<(), IsolationSessionError> {
        let async_op = self
            .ops
            .StopSessionAsync(&self.provision_id)
            .map_err(|e| lifecycle_err(format!("StopSessionAsync call failed: {}", e)))?;
        let result = async_op
            .join()
            .map_err(|e| lifecycle_err(format!("StopSessionAsync wait failed: {}", e)))?;
        check_result(&result, "StopSessionAsync")
    }

    /// Step 5: Deprovision the agent user.
    ///
    /// The wrapper's `RemoveUserAsync` internally re-provisions as
    /// `CallerProcess` first then deprovisions, papering over the
    /// Indefinite-deprovision broker bug
    /// (`IsoSessionServerClient.cpp:184` in the OS repo).
    pub fn deprovision_agent_user(&self) -> Result<(), IsolationSessionError> {
        let async_op = self
            .ops
            .RemoveUserAsync(&self.provision_id)
            .map_err(|e| lifecycle_err(format!("RemoveUserAsync call failed: {}", e)))?;
        let result = async_op
            .join()
            .map_err(|e| lifecycle_err(format!("RemoveUserAsync wait failed: {}", e)))?;
        check_result(&result, "RemoveUserAsync")
    }

    /// Step 6: Unregister the client.
    pub fn unregister_client(&self) -> Result<(), IsolationSessionError> {
        let async_op = self
            .ops
            .UnregisterAppAsync(&self.registration_id)
            .map_err(|e| lifecycle_err(format!("UnregisterAppAsync call failed: {}", e)))?;
        let result = async_op
            .join()
            .map_err(|e| lifecycle_err(format!("UnregisterAppAsync wait failed: {}", e)))?;
        check_result(&result, "UnregisterAppAsync")
    }
}

// -- Build IsoSessionProcessOptions from MXC ProcessOptions ------------------

/// Translates the MXC-internal `ProcessOptions` into a fresh
/// `IsoSessionProcessOptions` instance ready for `RunProcessWithOptionsAsync`.
fn build_iso_process_options(
    options: &ProcessOptions,
) -> Result<IsoSessionProcessOptions, IsolationSessionError> {
    let proc_options = IsoSessionProcessOptions::new()
        .map_err(|e| lifecycle_err(format!("IsoSessionProcessOptions::new failed: {}", e)))?;

    proc_options
        .SetTimeoutMilliseconds(options.timeout_ms)
        .map_err(|e| lifecycle_err(format!("SetTimeoutMilliseconds: {}", e)))?;

    if !options.working_directory.is_empty() {
        proc_options
            .SetWorkingDirectory(&HSTRING::from(&options.working_directory))
            .map_err(|e| lifecycle_err(format!("SetWorkingDirectory: {}", e)))?;
    }

    proc_options
        .SetInteractiveConsole(false)
        .map_err(|e| lifecycle_err(format!("SetInteractiveConsole: {}", e)))?;

    proc_options
        .SetRedirectStandardInput(options.redirect_flags & REDIRECT_STDIN != 0)
        .map_err(|e| lifecycle_err(format!("SetRedirectStandardInput: {}", e)))?;
    proc_options
        .SetRedirectStandardOutput(options.redirect_flags & REDIRECT_STDOUT != 0)
        .map_err(|e| lifecycle_err(format!("SetRedirectStandardOutput: {}", e)))?;
    proc_options
        .SetRedirectStandardError(options.redirect_flags & REDIRECT_STDERR != 0)
        .map_err(|e| lifecycle_err(format!("SetRedirectStandardError: {}", e)))?;

    if !options.env_vars.is_empty() {
        let env = proc_options
            .Environment()
            .map_err(|e| lifecycle_err(format!("get Environment IMap: {}", e)))?;
        for (name, value) in &options.env_vars {
            env.Insert(&HSTRING::from(name), &HSTRING::from(value))
                .map_err(|e| lifecycle_err(format!("Environment.Insert({}): {}", name, e)))?;
        }
    }

    Ok(proc_options)
}

// -- Pipe handle reading -----------------------------------------------------

/// Reads all data from a pipe handle into a UTF-8-lossy string. Does NOT
/// close the handle — ownership stays with the parent `IsoSessionProcess`,
/// which closes it via `Close()` (or drop).
fn read_pipe_to_string(handle_value: u64) -> String {
    if handle_value == 0 {
        return String::new();
    }
    let handle = HANDLE(handle_value as *mut core::ffi::c_void);
    let mut output = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let mut bytes_read = 0u32;
        // SAFETY: `handle` is a kernel handle owned by the in-proc DLL's
        // `IsoSessionProcess`. We only read; the DLL closes it on
        // `IsoSessionProcess::Close()`. `buffer` and `bytes_read` are
        // stack-allocated and live for the entire `ReadFile` call.
        let ok = unsafe { ReadFile(handle, Some(&mut buffer), Some(&mut bytes_read), None) };
        if ok.is_err() || bytes_read == 0 {
            break;
        }
        output.extend_from_slice(&buffer[..bytes_read as usize]);
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

/// Thin `ScriptRunner` wrapper that performs the full isolation session
/// lifecycle per invocation. For v0.1, each `run()` call does:
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
    fn validate_runner(&self, request: &CodexRequest) -> Result<(), ScriptResponse> {
        validate_policy(request).map_err(ScriptResponse::from)
    }

    fn execute(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
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

        // Activate the in-proc IsoSessionOps factory.
        let manager = match IsolationSessionManager::new() {
            Ok(m) => m,
            Err(e) => return e.into(),
        };

        // Full lifecycle: register → provision → start → execute → stop → deprovision → unregister.
        if let Err(e) = manager.register_client() {
            return e.into();
        }

        match manager.provision_agent_user() {
            Ok(agent_name) => {
                let _ = writeln!(logger, "Isolation Session: agent user = {}", agent_name);
            }
            Err(e) => {
                // provision_agent_user may return Err *after* a successful
                // broker-side provision (e.g., the AgentUserName fetch
                // fails on a non-error result). Defensively deprovision so
                // an Indefinite-lifetime agent user does not leak. The
                // wrapper no-ops these on absent state.
                let _ = manager.deprovision_agent_user();
                let _ = manager.unregister_client();
                return e.into();
            }
        }

        if let Err(e) = manager.start_session(config_id) {
            // Provision succeeded; start did not. Clean up the provisioned
            // agent user. stop_session is a no-op on an unstarted session.
            let _ = manager.stop_session();
            let _ = manager.deprovision_agent_user();
            let _ = manager.unregister_client();
            return e.into();
        }

        let result = match manager.create_process(&options) {
            Ok(r) => r,
            Err(e) => {
                let _ = manager.stop_session();
                let _ = manager.deprovision_agent_user();
                let _ = manager.unregister_client();
                return e.into();
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

    fn assert_policy_err_contains(err: IsolationSessionError, expected: &str) {
        match err {
            IsolationSessionError::Policy(msg) => {
                assert!(msg.contains(expected), "expected '{}' in {}", expected, msg)
            }
            other => panic!("expected Policy variant, got {:?}", other),
        }
    }

    #[test]
    fn policy_rejects_readwrite_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_policy(&request).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
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
        assert_policy_err_contains(
            validate_policy(&request).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
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
        assert_policy_err_contains(
            validate_policy(&request).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
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
        assert_policy_err_contains(validate_policy(&request).unwrap_err(), ERR_NETWORK_POLICY);
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
        assert_policy_err_contains(validate_policy(&request).unwrap_err(), ERR_NETWORK_POLICY);
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
        assert_policy_err_contains(validate_policy(&request).unwrap_err(), ERR_NETWORK_POLICY);
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
        assert_policy_err_contains(validate_policy(&request).unwrap_err(), ERR_PROXY_POLICY);
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
        // Host-relative — drive comes from %SYSTEMDRIVE% (typically `C:`),
        // so assert the trailing path shape rather than the full literal.
        assert!(
            opts.process_path.ends_with(r"\Windows\System32\cmd.exe"),
            "unexpected process_path: {}",
            opts.process_path
        );
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

        match check_service_available_and_activate() {
            Ok(_ops) => {
                // Service IS available on this machine (e.g., a test VM
                // with the feature enabled). The test is not applicable
                // — skip.
            }
            Err(IsolationSessionError::ServiceUnavailable(msg)) => {
                // Service is NOT available. Verify the error is clean and
                // descriptive (not a panic or cryptic COM error).
                assert!(
                    msg.contains("not available") || msg.contains("activation failed"),
                    "Expected descriptive error message, got: {}",
                    msg
                );
            }
            Err(other) => {
                panic!("expected ServiceUnavailable variant, got: {:?}", other);
            }
        }
    }
}
