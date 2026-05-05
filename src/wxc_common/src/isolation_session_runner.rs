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
use std::io::IsTerminal;

use crate::logger::Logger;
use crate::models::{CodexRequest, IsolationSessionConfigurationId, NetworkPolicy, ScriptResponse};
use crate::process_util::{
    create_relay_thread, create_relay_thread_with_stop, ConsoleModeRestorer, OwnedHandle,
    PipeRelayParams, PipeRelayWithStopParams,
};
use crate::script_runner::ScriptRunner;
use isolation_session_bindings::bindings::{
    IsoSessionConfigId, IsoSessionError, IsoSessionOps, IsoSessionProcess,
    IsoSessionProcessOptions, IsoSessionProcessResult, IsoSessionResult, IsoSessionUserResult,
};
use windows::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, HANDLE, REGDB_E_CLASSNOTREG};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject};
use windows_core::{HSTRING, PCWSTR};

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

/// Compute the canonical redirect-flags bitfield for the agent process I/O,
/// given whether wxc-exec is running in interactive (ConPTY) mode.
///
/// Policy (Commit 2 — TTY support):
/// - Stdin is always redirected. The runner spawns a relay so the parent's
///   input reaches the agent (interactive shells need this; batch stdin works
///   the same way).
/// - Stdout is always redirected.
/// - Stderr is redirected ONLY in non-interactive mode. In ConPTY mode the
///   broker merges stderr into stdout and refuses to populate the stderr
///   handle (predicate at `IsolationSessionWorkerProcess.cpp:309-310` in the
///   OS repo: `optStderrHandleResult && !m_pseudoConsole && m_stderrPipeRead`).
///   Setting `RedirectStandardError(true)` in ConPTY mode is benign but the
///   handle returns 0 — so we just don't ask for it.
pub(crate) fn compute_redirect_flags(interactive: bool) -> u32 {
    let mut flags = REDIRECT_STDIN | REDIRECT_STDOUT;
    if !interactive {
        flags |= REDIRECT_STDERR;
    }
    flags
}

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
    /// Whether to ask the broker to set up a ConPTY in the isolation session
    /// (`InteractiveConsole = true`). Decided at runtime by the runner based
    /// on `std::io::stdout().is_terminal()`. `build_process_options` returns
    /// `false` as a safe default; the runner overwrites before passing to
    /// `create_process`.
    pub interactive: bool,
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
        interactive: false,
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

        // Streaming + interactive I/O via three pipe relay threads bridging
        // wxc-exec's stdio with the broker's pipe handles. The relays cross
        // the desktop-session boundary that kernel console-handle inheritance
        // cannot (see `appcontainer_runner.rs:358-392` for the AppContainer
        // comparison).
        //
        // Handle ownership across four sources:
        //   - Broker pipe handles (`OutputHandle()` / `ErrorHandle()` /
        //     `InputHandle()`, returned as u64): owned by `IsoSessionProcess`.
        //     Released by `process.Close()` (`ApiProcess.cpp:131` in the OS
        //     repo). We do NOT close them.
        //   - wxc-exec's std handles (`GetStdHandle(STD_*_HANDLE)`): owned by
        //     the OS for the process lifetime. We do NOT close them.
        //   - Stop event for stdin relay (`CreateEventW`): RAII-closed via
        //     `OwnedHandle`.
        //   - Relay thread handles: RAII-closed via `OwnedHandle` after we
        //     `WaitForSingleObject` on each.
        //
        // Lifetime: relay-param structs are stack-allocated; we wait on every
        // spawned thread (INFINITE for stdout/stderr, bounded for stdin)
        // before this function returns.
        let stdout_handle_val = process.OutputHandle().unwrap_or(0);
        let stderr_handle_val = process.ErrorHandle().unwrap_or(0);
        let stdin_handle_val = process.InputHandle().unwrap_or(0);

        let wxc_stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }
            .map_err(|e| lifecycle_err(format!("GetStdHandle(stdout) failed: {}", e)))?;
        let wxc_stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) }
            .map_err(|e| lifecycle_err(format!("GetStdHandle(stderr) failed: {}", e)))?;
        let wxc_stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) }
            .map_err(|e| lifecycle_err(format!("GetStdHandle(stdin) failed: {}", e)))?;

        // In interactive mode, switch wxc-exec's local console to raw VT mode
        // so the agent's ConPTY does all the input echoing and rendering —
        // otherwise both consoles render the same input twice (duplicate
        // echos, doubled prompts, broken `\r\n` handling). RAII-restored on
        // scope exit. No-op when stdio is not a console (the guard records
        // itself as inactive).
        let _console_guard = if options.interactive {
            Some(ConsoleModeRestorer::install_raw_vt())
        } else {
            None
        };

        // Manual-reset stop event for the stdin relay. Effective for waitable
        // `h_read` (console = TTY mode); for pipe handles (non-TTY) it has no
        // effect on a blocked `ReadFile`, so we use a bounded
        // `WaitForSingleObject` after process exit and rely on
        // `process.Close()` invalidating the broker handle (next WriteFile
        // fails) plus OS cleanup on wxc-exec exit.
        let stdin_stop_event = unsafe {
            CreateEventW(None, true, false, PCWSTR::null())
                .map_err(|e| lifecycle_err(format!("CreateEventW(stdin stop): {}", e)))?
        };
        let stdin_stop_owned = OwnedHandle::new(stdin_stop_event);

        let mut stdout_params = PipeRelayParams {
            h_read: HANDLE(stdout_handle_val as *mut core::ffi::c_void),
            h_write: wxc_stdout,
        };
        let mut stderr_params = PipeRelayParams {
            h_read: HANDLE(stderr_handle_val as *mut core::ffi::c_void),
            h_write: wxc_stderr,
        };
        let mut stdin_params = PipeRelayWithStopParams {
            h_read: wxc_stdin,
            h_write: HANDLE(stdin_handle_val as *mut core::ffi::c_void),
            h_stop_event: stdin_stop_owned.get(),
        };

        let stdout_relay: Option<OwnedHandle> = if stdout_handle_val != 0 {
            Some(
                unsafe { create_relay_thread(&mut stdout_params) }
                    .map_err(|e| lifecycle_err(format!("create stdout relay: {}", e)))?,
            )
        } else {
            None
        };
        let stderr_relay: Option<OwnedHandle> = if stderr_handle_val != 0 {
            Some(
                unsafe { create_relay_thread(&mut stderr_params) }
                    .map_err(|e| lifecycle_err(format!("create stderr relay: {}", e)))?,
            )
        } else {
            None
        };
        let stdin_relay: Option<OwnedHandle> = if stdin_handle_val != 0 {
            Some(
                unsafe { create_relay_thread_with_stop(&mut stdin_params) }
                    .map_err(|e| lifecycle_err(format!("create stdin relay: {}", e)))?,
            )
        } else {
            None
        };

        // Wait for the agent process to exit. `WaitForExit` is a Win32
        // `WaitForSingleObject` on a kernel handle (`ApiProcess.cpp:76` — no
        // COM round-trip). On timeout it returns -1; otherwise the exit code.
        let _ = process
            .WaitForExit(options.timeout_ms)
            .map_err(|e| lifecycle_err(format!("WaitForExit failed: {}", e)))?;

        // Detect timeout via `ExitCode()` returning `STILL_ACTIVE` (the agent
        // is still running). Trigger the 3-tier graceful shutdown pattern from
        // `CommandTty.cpp:226-263` in the OS repo. In the natural-exit path,
        // none of the tiers fire.
        const STILL_ACTIVE: i32 = 0x103;
        let mut exit_code = process
            .ExitCode()
            .map_err(|e| lifecycle_err(format!("get ExitCode failed: {}", e)))?;

        if exit_code == STILL_ACTIVE {
            // Tier 1: close stdin — many REPLs (powershell, cmd, bash) exit
            // on EOF alone.
            let _ = process.CloseStandardInput();
            let _ = process.WaitForExit(5000);
            exit_code = process.ExitCode().unwrap_or(STILL_ACTIVE);

            // Tier 2: `SendCtrlClose` is ConPTY-only (`E_NOTIMPL` otherwise
            // per `IsolationSessionWorkerProcess.cpp:414-416`); benign call
            // in non-ConPTY mode, just skips ahead.
            if exit_code == STILL_ACTIVE {
                let _ = process.SendCtrlClose();
                let _ = process.WaitForExit(3000);
                exit_code = process.ExitCode().unwrap_or(STILL_ACTIVE);
            }

            // Tier 3: force-terminate. Wait infinitely for the kill to land
            // (timeout 0 == INFINITE per `ApiProcess.cpp:85`).
            if exit_code == STILL_ACTIVE {
                let _ = process.Terminate();
                let _ = process.WaitForExit(0);
                exit_code = process.ExitCode().unwrap_or(-1);
            }
        }

        // Signal the stdin relay to exit. Effective for waitable (console)
        // handles; for pipe handles the bounded wait below expires and we
        // proceed.
        unsafe {
            let _ = SetEvent(stdin_stop_owned.get());
        }

        // Drain stdout / stderr relays (INFINITE — they exit on broker-pipe
        // EOF once the agent's write ends close at OS-level handle cleanup;
        // the broker's own timeout at
        // `IsolationSessionWorkerProcess.cpp:153-170` is the safety net).
        if let Some(t) = stdout_relay {
            unsafe { WaitForSingleObject(t.get(), u32::MAX) };
        }
        if let Some(t) = stderr_relay {
            unsafe { WaitForSingleObject(t.get(), u32::MAX) };
        }

        // Drain stdin relay with a 1s bound. TTY mode exits via the stop
        // event; non-TTY may still be in `ReadFile` — that's fine, the
        // thread exits when wxc-exec exits and the OS cleans it up.
        if let Some(t) = stdin_relay {
            unsafe { WaitForSingleObject(t.get(), 1000) };
        }

        // Now safe to release the broker handles.
        let _ = process.Close();

        Ok(ProcessResult {
            exit_code,
            stdout: String::new(),
            stderr: String::new(),
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
        .SetInteractiveConsole(options.interactive)
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
        let mut options = build_process_options(request);

        // Detect at runtime whether wxc-exec's stdout is a TTY. This flips the
        // backend into ConPTY mode (`InteractiveConsole = true`) and adjusts
        // the redirect flags (no separate stderr in ConPTY mode — the broker
        // merges it into stdout). The check sees the handle wxc-exec was
        // given by its immediate parent: ConPTY when launched by node-pty
        // (`spawnSandbox`), pipe when launched by `child_process.spawn`
        // (`spawnSandboxFromConfig({usePty: false})`), console when launched
        // directly from a shell.
        let interactive = std::io::stdout().is_terminal();
        options.interactive = interactive;
        options.redirect_flags = compute_redirect_flags(interactive);

        let _ = writeln!(
            logger,
            "Isolation Session: process={}",
            options.process_path
        );
        let _ = writeln!(logger, "Isolation Session: arguments={}", options.arguments);
        let _ = writeln!(logger, "Isolation Session: interactive={}", interactive);

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

        // Output already streamed live to wxc-exec's stdio via relay threads in
        // `IsolationSessionManager::create_process` — captured fields are intentionally
        // empty (matching the AppContainer pattern at `appcontainer_runner.rs:455-456`).
        ScriptResponse {
            exit_code: result.exit_code,
            standard_out: String::new(),
            standard_err: String::new(),
            error_message: String::new(),
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

    #[test]
    fn compute_redirect_flags_interactive_omits_stderr() {
        let flags = compute_redirect_flags(true);
        assert!(
            flags & REDIRECT_STDIN != 0,
            "stdin should be redirected even in interactive mode"
        );
        assert!(flags & REDIRECT_STDOUT != 0, "stdout should be redirected");
        assert!(
            flags & REDIRECT_STDERR == 0,
            "stderr should NOT be redirected in interactive (ConPTY) mode \
             — broker won't populate ErrorHandle"
        );
    }

    #[test]
    fn compute_redirect_flags_noninteractive_includes_stderr() {
        let flags = compute_redirect_flags(false);
        assert!(flags & REDIRECT_STDIN != 0, "stdin should be redirected");
        assert!(flags & REDIRECT_STDOUT != 0, "stdout should be redirected");
        assert!(
            flags & REDIRECT_STDERR != 0,
            "stderr should be redirected in non-interactive (plain pipes) mode"
        );
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

    // ====== IsoSessionConfigId conversion tests ======
    //
    // The `From<IsolationSessionConfigurationId> for IsoSessionConfigId` impl is the
    // sole bridge between MXC's internal enum and the WinRT enum. If a new variant is
    // added to either side without updating the impl, these tests catch the drift.

    #[test]
    fn config_id_conversion_small() {
        let iso_id: IsoSessionConfigId = IsolationSessionConfigurationId::Small.into();
        assert_eq!(iso_id, IsoSessionConfigId::Small);
    }

    #[test]
    fn config_id_conversion_medium() {
        let iso_id: IsoSessionConfigId = IsolationSessionConfigurationId::Medium.into();
        assert_eq!(iso_id, IsoSessionConfigId::Medium);
    }

    #[test]
    fn config_id_conversion_large() {
        let iso_id: IsoSessionConfigId = IsolationSessionConfigurationId::Large.into();
        assert_eq!(iso_id, IsoSessionConfigId::Large);
    }

    #[test]
    fn config_id_conversion_composable() {
        let iso_id: IsoSessionConfigId = IsolationSessionConfigurationId::Composable.into();
        assert_eq!(iso_id, IsoSessionConfigId::Composable);
    }
}
