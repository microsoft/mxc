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

use serde::Serialize;

use crate::id::mint_random_token;
use crate::logger::Logger;
use crate::models::{
    CodexRequest, IsolationSessionConfig, IsolationSessionConfigurationId, NetworkPolicy,
    ScriptResponse,
};
use crate::mxc_error::MxcError;
use crate::process_util::{
    create_relay_thread, create_relay_thread_with_stop, get_local_console_size,
    ConsoleModeRestorer, OwnedHandle, PipeRelayParams, PipeRelayWithStopParams,
};
use crate::script_runner::ScriptRunner;
use crate::state_aware_backend::{
    DeprovisionResult, ExecHandle, ProvisionResult, StartResult, StatefulSandboxBackend, StopResult,
};
use isolation_session_bindings::bindings::{
    IsoSessionConfigId, IsoSessionError, IsoSessionFolderSharingAccessLevel,
    IsoSessionFolderSharingRequest, IsoSessionFolderSharingResult, IsoSessionFolderSharingStatus,
    IsoSessionOps, IsoSessionProcess, IsoSessionProcessOptions, IsoSessionProcessResult,
    IsoSessionResult, IsoSessionUserResult,
};
use windows::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, HANDLE, REGDB_E_CLASSNOTREG};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject};
use windows_collections::IVectorView;
use windows_core::{HSTRING, PCWSTR};

// -- Identifiers -------------------------------------------------------------

/// Registration ID used with the `IsoSessionOps` wrapper.
///
/// The `IsoSessionOps` wrapper hardcodes `L"regid"` internally for every
/// agent-name-keyed op, so callers must register with this exact literal
/// or subsequent calls hit the wrong registration.
const REGISTRATION_ID: &str = "regid";

/// Default provisionId used by the one-shot backend path. State-aware
/// callers mint their own dynamic ids (e.g. `wxc-<8-hex>`) instead.
///
/// `provisionId` scopes the agent user across the lifecycle and is reused as
/// the `agentName` parameter on every subsequent op — the `IsoSessionOps`
/// wrapper aliases `agentName` to this `provisionId` at the COM layer, so
/// callers pass `provisionId` where the IDL says `agentName`.
pub const DEFAULT_PROVISION_ID: &str = "wxc-provid";

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
    /// An OS-side lifecycle step (register / provision / start / exec /
    /// stop / deprovision / unregister) returned a failure.
    Lifecycle(String),
    /// The OS-side service could not find the provisionId — the sandbox
    /// has been deprovisioned (or never provisioned in this user's
    /// session) and any further state-aware op against it is a stale-id
    /// reference. Surfaces as `MxcError::StaleId` at the dispatch boundary.
    Stale(String),
}

impl std::fmt::Display for IsolationSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(msg) => write!(f, "Isolation Session policy error: {}", msg),
            Self::ServiceUnavailable(msg) => {
                write!(f, "Isolation Session service unavailable: {}", msg)
            }
            Self::Lifecycle(msg) => write!(f, "Isolation Session lifecycle error: {}", msg),
            Self::Stale(msg) => write!(f, "Isolation Session stale id: {}", msg),
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

/// Validates the request for the provision phase. Filesystem `rw` and
/// `ro` paths are honored at provision (applied via `share_folders`);
/// `denied_paths` is rejected because the underlying API has no
/// equivalent primitive. Network and proxy policy are always rejected.
pub(crate) fn validate_provision_policy(
    request: &CodexRequest,
) -> Result<(), IsolationSessionError> {
    if !request.policy.denied_paths.is_empty() {
        return Err(IsolationSessionError::Policy(
            ERR_FILESYSTEM_POLICY.to_string(),
        ));
    }
    validate_network_and_proxy_policy(request)
}

/// Validates the request for any non-provision phase (start / exec / stop
/// / deprovision). All filesystem fields are rejected because filesystem
/// policy is bound to provision and immutable thereafter.
pub(crate) fn validate_post_provision_policy(
    request: &CodexRequest,
) -> Result<(), IsolationSessionError> {
    if !request.policy.readwrite_paths.is_empty()
        || !request.policy.readonly_paths.is_empty()
        || !request.policy.denied_paths.is_empty()
    {
        return Err(IsolationSessionError::Policy(
            ERR_FILESYSTEM_POLICY.to_string(),
        ));
    }
    validate_network_and_proxy_policy(request)
}

/// Network and proxy validation is identical at every phase: the backend
/// honors neither.
fn validate_network_and_proxy_policy(request: &CodexRequest) -> Result<(), IsolationSessionError> {
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
///   OS-side service merges stderr into stdout and does not populate the
///   stderr handle. Setting `RedirectStandardError(true)` in ConPTY mode
///   is benign but the handle returns 0 — so we just don't ask for it.
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
    /// Whether to ask the OS-side service to set up a ConPTY in the
    /// isolation session (`InteractiveConsole = true`). Decided at runtime
    /// by the runner based on `std::io::stdout().is_terminal()`.
    /// `build_process_options` returns `false` as a safe default; the
    /// runner overwrites before passing to `create_process`.
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

/// `HRESULT_FROM_WIN32(ERROR_NOT_FOUND)` — returned by the OS-side service's
/// `AgentManager::FindActiveAgentUserByProvisionId` when the provisionId is
/// missing from both the in-memory cache and the persisted registry. Every
/// non-provision lifecycle op (start / exec / stop / deprovision) goes
/// through this lookup, so a `0x80070490` from any of them means the
/// sandbox_id is stale.
const ERROR_NOT_FOUND_HRESULT: u32 = 0x80070490;

/// Formats an `IsoSessionError` (the WinRT result type) into a typed
/// `IsolationSessionError`. Detects the ERROR_NOT_FOUND HRESULT and
/// promotes it to `Stale` so callers (and ultimately the wire envelope)
/// can return `MxcError::StaleId` for a deprovisioned sandbox_id.
fn format_iso_error(op: &str, err: &IsoSessionError) -> IsolationSessionError {
    let msg = err.Message().map(|h| h.to_string()).unwrap_or_default();
    let code = err.Code().map(|h| h.0 as u32).unwrap_or(0);
    let remediation = err.Remediation().map(|h| h.to_string()).unwrap_or_default();
    let suffix = if remediation.is_empty() {
        String::new()
    } else {
        format!(" -- remediation: {}", remediation)
    };
    let formatted = format!("{} failed: {} (HRESULT: {:#010x}){}", op, msg, code, suffix);
    if code == ERROR_NOT_FOUND_HRESULT {
        IsolationSessionError::Stale(formatted)
    } else {
        IsolationSessionError::Lifecycle(formatted)
    }
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

// -- Folder-sharing helpers --------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShareFolderFailure {
    pub message: String,
    pub remediation: String,
    pub hresult: u32,
}

/// Per-path outcome from a folder-share batch. The batch result type is a
/// COM runtime class that can't be built in unit tests; this struct is the
/// test-friendly equivalent that aggregation logic operates on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShareFolderOutcome {
    pub folder_path: String,
    /// `Some` iff the per-path status was `Failed`.
    pub failure: Option<ShareFolderFailure>,
}

/// Builds the per-path WinRT requests with rw paths first, ro paths second.
/// A path appearing in both slices ends up read-only (the ro request is
/// applied second and overwrites the earlier rw ACE for the same SID).
/// Callers should keep the slices disjoint to avoid relying on this.
pub(crate) fn build_share_folder_requests(
    rw: &[String],
    ro: &[String],
) -> Vec<IsoSessionFolderSharingRequest> {
    let mut requests = Vec::with_capacity(rw.len() + ro.len());
    for path in rw {
        requests.push(IsoSessionFolderSharingRequest {
            FolderPath: HSTRING::from(path),
            AccessLevel: IsoSessionFolderSharingAccessLevel::ReadWrite,
        });
    }
    for path in ro {
        requests.push(IsoSessionFolderSharingRequest {
            FolderPath: HSTRING::from(path),
            AccessLevel: IsoSessionFolderSharingAccessLevel::Read,
        });
    }
    requests
}

/// Extracts MXC-internal per-path outcomes from the WinRT
/// `IVectorView<IsoSessionFolderSharingResult>` returned by the API.
fn extract_share_folder_outcomes(
    results: &IVectorView<IsoSessionFolderSharingResult>,
) -> Result<Vec<ShareFolderOutcome>, IsolationSessionError> {
    let size = results
        .Size()
        .map_err(|e| lifecycle_err(format!("ShareFolderBatch results.Size: {}", e)))?;
    let mut outcomes = Vec::with_capacity(size as usize);
    for i in 0..size {
        let result = results
            .GetAt(i)
            .map_err(|e| lifecycle_err(format!("ShareFolderBatch results.GetAt({}): {}", i, e)))?;
        let folder_path = result
            .FolderPath()
            .map_err(|e| lifecycle_err(format!("ShareFolderBatch result.FolderPath: {}", e)))?
            .to_string();
        let status = result
            .Status()
            .map_err(|e| lifecycle_err(format!("ShareFolderBatch result.Status: {}", e)))?;
        let failure = if status == IsoSessionFolderSharingStatus::Failed {
            let err = result
                .Error()
                .map_err(|e| lifecycle_err(format!("ShareFolderBatch result.Error: {}", e)))?;
            Some(ShareFolderFailure {
                message: err.Message().map(|h| h.to_string()).unwrap_or_default(),
                remediation: err.Remediation().map(|h| h.to_string()).unwrap_or_default(),
                hresult: err.Code().map(|h| h.0 as u32).unwrap_or(0),
            })
        } else {
            None
        };
        outcomes.push(ShareFolderOutcome {
            folder_path,
            failure,
        });
    }
    Ok(outcomes)
}

/// Aggregates per-path outcomes into a single Result. Ok iff every path
/// succeeded; otherwise a `Lifecycle` error with each failed path's
/// message and HRESULT. The batch call does not fail as a whole on
/// per-path errors, so this is where per-path failures become a single
/// MXC error.
pub(crate) fn aggregate_share_folder_outcomes(
    outcomes: &[ShareFolderOutcome],
) -> Result<(), IsolationSessionError> {
    let any_failure = outcomes.iter().any(|o| o.failure.is_some());
    if !any_failure {
        return Ok(());
    }
    let mut msg = String::from("ShareFolderBatchAsync had per-path failures:");
    for outcome in outcomes {
        let Some(f) = &outcome.failure else {
            continue;
        };
        let _ = write!(
            msg,
            "\n  {}: {} (HRESULT: {:#010x})",
            outcome.folder_path, f.message, f.hresult,
        );
        if !f.remediation.is_empty() {
            let _ = write!(msg, " -- remediation: {}", f.remediation);
        }
    }
    Err(IsolationSessionError::Lifecycle(msg))
}

// -- IsolationSessionManager (lifecycle core) --------------------------------

/// Manages the `IsoSessionOps` lifecycle. Methods map 1:1 to the granular
/// API steps.
pub struct IsolationSessionManager {
    /// Registration identifier used in `RegisterApp` / `AddUserAsync`
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
    /// Activates the `IsoSessionOps` factory, verifies the service is
    /// available, and pegs the manager to the supplied `provisionId`.
    /// One-shot callers pass `DEFAULT_PROVISION_ID`; state-aware callers
    /// mint a dynamic id per provision (e.g. `wxc-<8-hex>`).
    pub fn new(provision_id: &str) -> Result<Self, IsolationSessionError> {
        let ops = check_service_available_and_activate()?;
        Ok(Self {
            registration_id: HSTRING::from(REGISTRATION_ID),
            provision_id: HSTRING::from(provision_id),
            ops,
        })
    }

    /// Step 0: Register the app with the OS-side service.
    pub fn register_client(&self) -> Result<(), IsolationSessionError> {
        let result = self
            .ops
            .RegisterApp(&self.registration_id)
            .map_err(|e| lifecycle_err(format!("RegisterApp call failed: {}", e)))?;
        check_result(&result, "RegisterApp")
    }

    /// Step 1: Provision an agent user. Returns the OS-assigned agent
    /// account name (e.g., `RealUser-IEB-000`) for logging only — addressing
    /// for subsequent ops continues to use the configured `provision_id`.
    ///
    /// Note: `lifecycle.destroyOnExit` is silently ignored on this backend.
    /// The in-proc API hardcodes `Indefinite` lifetime in `AddUserAsync`,
    /// and `RemoveUserAsync` papers over the Indefinite-deprovision bug.
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

    /// Grants the agent user access to host folders. `readwrite_paths`
    /// get read+write access, `readonly_paths` get read-only. Both apply
    /// recursively to each subtree.
    ///
    /// Independent of session start: requires only that the agent user
    /// exists (call after `provision_agent_user`, before
    /// `deprovision_agent_user`).
    ///
    /// The MXC process needs `WRITE_DAC` on each target folder. On
    /// all-success returns `Ok`; on any per-path failure returns a
    /// `Lifecycle` error listing every failed path. Empty input on both
    /// slices is a no-op.
    pub fn share_folders(
        &self,
        readwrite_paths: &[String],
        readonly_paths: &[String],
    ) -> Result<(), IsolationSessionError> {
        let requests = build_share_folder_requests(readwrite_paths, readonly_paths);
        if requests.is_empty() {
            return Ok(());
        }
        let view: IVectorView<IsoSessionFolderSharingRequest> = requests.into();
        let async_op = self
            .ops
            .ShareFolderBatchAsync(&self.provision_id, &view)
            .map_err(|e| lifecycle_err(format!("ShareFolderBatchAsync call failed: {}", e)))?;
        let results: IVectorView<IsoSessionFolderSharingResult> = async_op
            .join()
            .map_err(|e| lifecycle_err(format!("ShareFolderBatchAsync wait failed: {}", e)))?;
        let outcomes = extract_share_folder_outcomes(&results)?;
        aggregate_share_folder_outcomes(&outcomes)
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
        // wxc-exec's stdio with the pipe handles owned by `IsoSessionProcess`.
        // The relays cross the desktop-session boundary that kernel
        // console-handle inheritance cannot.
        //
        // Handle ownership across four sources:
        //   - Pipe handles owned by `IsoSessionProcess` (`OutputHandle()` /
        //     `ErrorHandle()` / `InputHandle()`, returned as u64): released
        //     by `process.Close()`. We do NOT close them.
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

        // Push the local console's current viewport size into the agent's
        // inner ConPTY. Without this, the inner HPCON keeps its default
        // dimensions and VT-aware agents (e.g. PSReadLine) anchor their
        // prompt to that smaller-than-local last row, overlaying text once
        // they reach it. Mid-session resize is not handled here.
        if options.interactive {
            if let Some((cols, rows)) = get_local_console_size() {
                let _ = process.ResizeConsole(cols, rows);
            }
        }

        // Manual-reset stop event for the stdin relay. Effective for waitable
        // `h_read` (console = TTY mode); for pipe handles (non-TTY) it has no
        // effect on a blocked `ReadFile`, so we use a bounded
        // `WaitForSingleObject` after process exit and rely on
        // `process.Close()` invalidating the `IsoSessionProcess` handle
        // (next WriteFile fails) plus OS cleanup on wxc-exec exit.
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
        // `WaitForSingleObject` on a kernel handle — no COM round-trip. On
        // timeout it returns -1; otherwise the exit code.
        let _ = process
            .WaitForExit(options.timeout_ms)
            .map_err(|e| lifecycle_err(format!("WaitForExit failed: {}", e)))?;

        // Detect timeout via `ExitCode()` returning `STILL_ACTIVE` (the agent
        // is still running). Run a 3-tier graceful shutdown — escalating from
        // stdin-close to control signal to terminate — so well-behaved agents
        // exit cleanly. In the natural-exit path none of the tiers fire.
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

            // Tier 2: `SendCtrlClose` is ConPTY-only — `E_NOTIMPL` in
            // non-ConPTY mode, which is benign and skips ahead.
            if exit_code == STILL_ACTIVE {
                let _ = process.SendCtrlClose();
                let _ = process.WaitForExit(3000);
                exit_code = process.ExitCode().unwrap_or(STILL_ACTIVE);
            }

            // Tier 3: force-terminate. Wait infinitely for the kill to land
            // (`WaitForExit(0)` = INFINITE).
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

        // Drain stdout / stderr relays (INFINITE — they exit when the
        // `IsoSessionProcess` pipe-read EOFs once the agent's write ends
        // close at OS-level cleanup. The OS-side per-process timeout is
        // the safety net.
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

        // Now safe to release the `IsoSessionProcess` handles.
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
    /// `RemoveUserAsync` internally re-provisions as `CallerProcess` first
    /// then deprovisions, papering over the Indefinite-deprovision bug in
    /// the OS-side service.
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
        // One-shot runs the full provision -> start -> exec -> stop ->
        // deprovision lifecycle in a single process, so provision-phase
        // semantics apply to the whole call.
        validate_provision_policy(request).map_err(ScriptResponse::from)
    }

    fn execute(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        let mut options = build_process_options(request);

        // Detect at runtime whether wxc-exec's stdout is a TTY. This flips the
        // backend into ConPTY mode (`InteractiveConsole = true`) and adjusts
        // the redirect flags (no separate stderr in ConPTY mode — the OS-side
        // service merges it into stdout). The check sees the handle wxc-exec
        // was given by its immediate parent: ConPTY when launched by node-pty
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

        // Activate the in-proc IsoSessionOps factory. One-shot uses the
        // hardcoded default provisionId; state-aware mints a dynamic one.
        let manager = match IsolationSessionManager::new(DEFAULT_PROVISION_ID) {
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
                // OS-side provision (e.g., the AgentUserName fetch fails on
                // a non-error result). Defensively deprovision so an
                // Indefinite-lifetime agent user does not leak.
                // `IsoSessionOps` no-ops these on absent state.
                let _ = manager.deprovision_agent_user();
                let _ = manager.unregister_client();
                return e.into();
            }
        }

        if let Err(e) = manager.share_folders(
            &request.policy.readwrite_paths,
            &request.policy.readonly_paths,
        ) {
            let _ = manager.deprovision_agent_user();
            let _ = manager.unregister_client();
            return e.into();
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
        // empty (same pattern as AppContainer).
        ScriptResponse {
            exit_code: result.exit_code,
            standard_out: String::new(),
            standard_err: String::new(),
            error_message: String::new(),
        }
    }
}

// -- StatefulSandboxBackend impl --------------------------------------------

/// Provision-phase metadata. Carries the OS-assigned agent account name
/// (e.g. `<CallingUser>-IEB-NNN`) for diagnostics; the SID is omitted (can
/// be added later when a caller needs it).
#[derive(Debug, Clone, Serialize)]
pub struct IsolationSessionProvisionMetadata {
    #[serde(rename = "agentUserName")]
    pub agent_user_name: String,
}

/// Parses the `iso:<provisionId>` form of a state-aware sandbox_id and
/// returns the inner `provisionId` segment. Surfaces format mismatches as
/// `MxcError::MalformedId` so callers can return the right wire-format
/// error code.
fn extract_provision_id(sandbox_id: &str) -> Result<&str, MxcError> {
    let prefix = <IsolationSessionRunner as StatefulSandboxBackend>::ID_PREFIX;
    match sandbox_id.split_once(':') {
        Some((p, rest)) if p == prefix && !rest.is_empty() => Ok(rest),
        _ => Err(MxcError::malformed_id(format!(
            "expected {}:<provisionId>, got {:?}",
            prefix, sandbox_id
        ))),
    }
}

impl StatefulSandboxBackend for IsolationSessionRunner {
    const ID_PREFIX: &'static str = "iso";
    const BACKEND_KEY: &'static str = "isolation_session";

    type ProvisionConfig = ();
    /// `experimental.isolation_session.start` mirrors the one-shot
    /// `experimental.isolation_session` shape — same `IsolationSessionConfig`
    /// type, same wire keys.
    type StartConfig = IsolationSessionConfig;
    type ExecConfig = ();
    type StopConfig = ();
    type DeprovisionConfig = ();
    type ProvisionMetadata = IsolationSessionProvisionMetadata;
    type StartMetadata = ();
    type StopMetadata = ();
    type DeprovisionMetadata = ();

    fn provision(
        &mut self,
        request: &CodexRequest,
        _config: Option<()>,
    ) -> Result<ProvisionResult<IsolationSessionProvisionMetadata>, MxcError> {
        let provision_id = format!("wxc-{}", mint_random_token());
        let manager = IsolationSessionManager::new(&provision_id).map_err(map_lifecycle_error)?;
        manager.register_client().map_err(map_lifecycle_error)?;
        let agent_user_name = match manager.provision_agent_user() {
            Ok(name) => name,
            Err(e) => {
                // Defensive cleanup mirrors the one-shot path: provision_agent_user
                // can fail after the OS-side provision succeeded, leaving an
                // Indefinite-lifetime agent user. Calls no-op on absent state.
                let _ = manager.deprovision_agent_user();
                let _ = manager.unregister_client();
                return Err(map_lifecycle_error(e));
            }
        };

        // Apply filesystem policy (rw + ro paths) before returning. A
        // failure here leaves the agent user provisioned but no folders
        // accessible to it; tear it down so the caller does not see a
        // half-provisioned sandboxId.
        if let Err(e) = manager.share_folders(
            &request.policy.readwrite_paths,
            &request.policy.readonly_paths,
        ) {
            let _ = manager.deprovision_agent_user();
            let _ = manager.unregister_client();
            return Err(map_lifecycle_error(e));
        }

        Ok(ProvisionResult {
            sandbox_id: format!("{}:{}", Self::ID_PREFIX, provision_id),
            metadata: Some(IsolationSessionProvisionMetadata { agent_user_name }),
        })
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        _request: &CodexRequest,
        config: Option<IsolationSessionConfig>,
    ) -> Result<StartResult<()>, MxcError> {
        let provision_id = extract_provision_id(sandbox_id)?;
        let manager = IsolationSessionManager::new(provision_id).map_err(map_lifecycle_error)?;
        // Config absent → Composable, mirroring the one-shot default. The
        // OS-side service does not call back into MXC after start, so a
        // return here means the session is ready to host process launches.
        let configuration_id = config.map(|c| c.configuration_id).unwrap_or_default();
        manager
            .start_session(configuration_id)
            .map_err(map_lifecycle_error)?;
        Ok(StartResult { metadata: None })
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &CodexRequest,
        _config: Option<()>,
    ) -> Result<StopResult<()>, MxcError> {
        let provision_id = extract_provision_id(sandbox_id)?;
        let manager = IsolationSessionManager::new(provision_id).map_err(map_lifecycle_error)?;
        manager.stop_session().map_err(map_lifecycle_error)?;
        Ok(StopResult { metadata: None })
    }

    /// Removes the agent user, then unregisters the client. Mirrors the
    /// one-shot teardown sequence so a state-aware lifecycle leaves the
    /// OS-side service in the same end state as a one-shot run.
    ///
    /// `unregister_client` tears down the client registration that
    /// `provision` set up via `register_client`. v1 does not target
    /// concurrent state-aware sessions, which would share that
    /// registration -- if that becomes a real requirement, this will
    /// need either a refcount or a "leave-registration-alone" mode.
    fn deprovision(
        &mut self,
        sandbox_id: &str,
        _request: &CodexRequest,
        _config: Option<()>,
    ) -> Result<DeprovisionResult<()>, MxcError> {
        let provision_id = extract_provision_id(sandbox_id)?;
        let manager = IsolationSessionManager::new(provision_id).map_err(map_lifecycle_error)?;
        manager
            .deprovision_agent_user()
            .map_err(map_lifecycle_error)?;
        manager.unregister_client().map_err(map_lifecycle_error)?;
        Ok(DeprovisionResult { metadata: None })
    }

    // -- Validation hooks ----------------------------------------------------
    //
    // Filesystem rw/ro paths are honoured at provision (applied via
    // `share_folders`) and rejected at every later phase, because the
    // grant lifecycle is bound to the agent user. `denied_paths`,
    // network, and proxy policy are rejected at every phase: the
    // backend has no equivalent primitive. Anything rejected produces
    // a `policy_validation` envelope rather than silent ignore.

    fn validate_provision(
        &self,
        request: &CodexRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_provision_policy(request).map_err(map_lifecycle_error)
    }

    fn validate_start(
        &self,
        _sandbox_id: &str,
        request: &CodexRequest,
        _config: Option<&IsolationSessionConfig>,
    ) -> Result<(), MxcError> {
        validate_post_provision_policy(request).map_err(map_lifecycle_error)
    }

    fn validate_exec(
        &self,
        _sandbox_id: &str,
        request: &CodexRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_post_provision_policy(request).map_err(map_lifecycle_error)
    }

    fn validate_stop(
        &self,
        _sandbox_id: &str,
        request: &CodexRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_post_provision_policy(request).map_err(map_lifecycle_error)
    }

    fn validate_deprovision(
        &self,
        _sandbox_id: &str,
        request: &CodexRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_post_provision_policy(request).map_err(map_lifecycle_error)
    }

    /// Reuses `IsolationSessionManager::create_process` — the same path the
    /// one-shot runner uses. Output streams to wxc-exec's stdout/stderr via
    /// internal relay threads while the call is in flight; the call returns
    /// once the process has exited and the relays have drained. The
    /// resulting `ExecHandle` carries sentinel pipe handles plus a waiter
    /// closure that yields the already-captured exit code, so the
    /// dispatcher's `relay_exec_to_stdio` is a thin call-through.
    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &CodexRequest,
        _config: Option<()>,
    ) -> Result<ExecHandle, MxcError> {
        let provision_id = extract_provision_id(sandbox_id)?;
        let manager = IsolationSessionManager::new(provision_id).map_err(map_lifecycle_error)?;

        let mut options = build_process_options(request);
        let interactive = std::io::stdout().is_terminal();
        options.interactive = interactive;
        options.redirect_flags = compute_redirect_flags(interactive);

        let result = manager
            .create_process(&options)
            .map_err(map_lifecycle_error)?;
        let exit_code = result.exit_code;

        // The output relay completed inside `create_process`. The dispatcher
        // sees zero pipe handles, skips its own relay setup, and gets the
        // exit code from the waiter closure.
        let null = HANDLE(std::ptr::null_mut());
        Ok(ExecHandle {
            stdout: null,
            stderr: null,
            stdin: null,
            waiter: Box::new(move || Ok(exit_code)),
            terminator: Box::new(|| {}),
        })
    }
}

fn map_lifecycle_error(err: IsolationSessionError) -> MxcError {
    let message = err.to_string();
    match err {
        IsolationSessionError::Policy(_) => MxcError::policy_validation(message),
        IsolationSessionError::ServiceUnavailable(_) => MxcError::backend_unavailable(message),
        IsolationSessionError::Lifecycle(_) => MxcError::backend_error(message),
        IsolationSessionError::Stale(_) => MxcError::stale_id(message),
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
    fn extract_provision_id_unwraps_iso_prefix() {
        assert_eq!(
            extract_provision_id("iso:wxc-abcd1234").unwrap(),
            "wxc-abcd1234"
        );
    }

    #[test]
    fn extract_provision_id_rejects_other_prefix() {
        let err = extract_provision_id("wsb:abc").unwrap_err();
        assert_eq!(err.code, crate::mxc_error::MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_provision_id_rejects_missing_colon() {
        let err = extract_provision_id("no-colon").unwrap_err();
        assert_eq!(err.code, crate::mxc_error::MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_provision_id_rejects_empty_payload() {
        let err = extract_provision_id("iso:").unwrap_err();
        assert_eq!(err.code, crate::mxc_error::MxcErrorCode::MalformedId);
    }

    #[test]
    fn map_lifecycle_error_categorises_each_variant() {
        use crate::mxc_error::MxcErrorCode;
        assert_eq!(
            map_lifecycle_error(IsolationSessionError::Policy("x".into())).code,
            MxcErrorCode::PolicyValidation,
        );
        assert_eq!(
            map_lifecycle_error(IsolationSessionError::ServiceUnavailable("x".into())).code,
            MxcErrorCode::BackendUnavailable,
        );
        assert_eq!(
            map_lifecycle_error(IsolationSessionError::Lifecycle("x".into())).code,
            MxcErrorCode::BackendError,
        );
        assert_eq!(
            map_lifecycle_error(IsolationSessionError::Stale("x".into())).code,
            MxcErrorCode::StaleId,
        );
    }

    fn request_with_filesystem_policy() -> CodexRequest {
        CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\workspace".into()],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn validate_provision_hook_accepts_filesystem_policy() {
        let runner = IsolationSessionRunner::new();
        let req = request_with_filesystem_policy();
        runner.validate_provision(&req, None).unwrap();
    }

    #[test]
    fn validate_provision_hook_rejects_denied_paths() {
        use crate::mxc_error::MxcErrorCode;
        let runner = IsolationSessionRunner::new();
        let req = CodexRequest {
            policy: ContainerPolicy {
                denied_paths: vec!["C:\\secret".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = runner.validate_provision(&req, None).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_post_provision_hooks_reject_filesystem_policy() {
        use crate::mxc_error::MxcErrorCode;
        let runner = IsolationSessionRunner::new();
        let req = request_with_filesystem_policy();

        let s = runner.validate_start("iso:abc", &req, None).unwrap_err();
        assert_eq!(s.code, MxcErrorCode::PolicyValidation);

        let e = runner.validate_exec("iso:abc", &req, None).unwrap_err();
        assert_eq!(e.code, MxcErrorCode::PolicyValidation);

        let st = runner.validate_stop("iso:abc", &req, None).unwrap_err();
        assert_eq!(st.code, MxcErrorCode::PolicyValidation);

        let d = runner
            .validate_deprovision("iso:abc", &req, None)
            .unwrap_err();
        assert_eq!(d.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_phase_hooks_accept_clean_request() {
        let runner = IsolationSessionRunner::new();
        let req = CodexRequest::default();

        runner.validate_provision(&req, None).unwrap();
        runner.validate_start("iso:abc", &req, None).unwrap();
        runner.validate_exec("iso:abc", &req, None).unwrap();
        runner.validate_stop("iso:abc", &req, None).unwrap();
        runner.validate_deprovision("iso:abc", &req, None).unwrap();
    }

    #[test]
    fn error_not_found_hresult_constant_matches_win32() {
        // Sanity check: HRESULT_FROM_WIN32(ERROR_NOT_FOUND) =
        //   0x80070000 | (1168 & 0xFFFF) = 0x80070490.
        // The OS-side AgentManager::FindActiveAgentUserByProvisionId returns
        // exactly this when the provisionId is gone, so a regression in the
        // constant would silently downgrade stale-id detection to backend_error.
        const ERROR_NOT_FOUND: u32 = 1168;
        let expected = 0x8007_0000u32 | (ERROR_NOT_FOUND & 0xFFFF);
        assert_eq!(ERROR_NOT_FOUND_HRESULT, expected);
        assert_eq!(ERROR_NOT_FOUND_HRESULT, 0x80070490);
    }

    // ====== Phase-specific policy validation ======
    //
    // Filesystem fields behave differently per phase; network and proxy
    // policy share `validate_network_and_proxy_policy` and behave the
    // same at every phase. Coverage strategy: filesystem tests on both
    // phase-specific helpers; network/proxy tests split across them so
    // every branch of the shared helper runs at least once.

    #[test]
    fn provision_policy_accepts_readwrite_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_provision_policy(&request).is_ok());
    }

    #[test]
    fn provision_policy_accepts_readonly_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_provision_policy(&request).is_ok());
    }

    #[test]
    fn provision_policy_accepts_readwrite_and_readonly_together() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                readonly_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_provision_policy(&request).is_ok());
    }

    #[test]
    fn provision_policy_rejects_denied_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                denied_paths: vec!["C:\\secret".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_denied_even_with_rw() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                denied_paths: vec!["C:\\secret".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_network_policy() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                allowed_hosts: vec!["example.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_provision_policy(&request).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn provision_policy_rejects_proxy() {
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
        assert_policy_err_contains(
            validate_provision_policy(&request).unwrap_err(),
            ERR_PROXY_POLICY,
        );
    }

    #[test]
    fn post_provision_policy_rejects_readwrite_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    #[test]
    fn post_provision_policy_rejects_readonly_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    #[test]
    fn post_provision_policy_rejects_denied_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                denied_paths: vec!["C:\\secret".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            ERR_FILESYSTEM_POLICY,
        );
    }

    #[test]
    fn post_provision_policy_rejects_blocked_hosts() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                blocked_hosts: vec!["evil.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn post_provision_policy_rejects_network_block_policy() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Block,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_policy_err_contains(
            validate_post_provision_policy(&request).unwrap_err(),
            ERR_NETWORK_POLICY,
        );
    }

    #[test]
    fn post_provision_policy_allows_defaults() {
        let request = CodexRequest::default();
        assert!(validate_post_provision_policy(&request).is_ok());
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
             — ErrorHandle is not populated by the OS-side service"
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

    // ====== Folder-sharing helpers ======
    //
    // The runtime path (`share_folders` itself) needs a live IsoSessionOps,
    // which is only available on a configured VM — covered by the C6
    // integration tests. These unit tests cover the two pure helpers that
    // bracket the COM call: request-building and outcome aggregation.

    #[test]
    fn build_requests_empty_inputs_returns_empty_vec() {
        let requests = build_share_folder_requests(&[], &[]);
        assert!(requests.is_empty());
    }

    #[test]
    fn build_requests_rw_only() {
        let rw = vec!["C:\\rw1".to_string(), "C:\\rw2".to_string()];
        let requests = build_share_folder_requests(&rw, &[]);
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].FolderPath.to_string(), "C:\\rw1");
        assert_eq!(
            requests[0].AccessLevel,
            IsoSessionFolderSharingAccessLevel::ReadWrite
        );
        assert_eq!(requests[1].FolderPath.to_string(), "C:\\rw2");
        assert_eq!(
            requests[1].AccessLevel,
            IsoSessionFolderSharingAccessLevel::ReadWrite
        );
    }

    #[test]
    fn build_requests_ro_only() {
        let ro = vec!["C:\\ro1".to_string()];
        let requests = build_share_folder_requests(&[], &ro);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].FolderPath.to_string(), "C:\\ro1");
        assert_eq!(
            requests[0].AccessLevel,
            IsoSessionFolderSharingAccessLevel::Read
        );
    }

    #[test]
    fn build_requests_rw_then_ro_in_input_order() {
        let rw = vec!["C:\\a".to_string()];
        let ro = vec!["C:\\b".to_string(), "C:\\c".to_string()];
        let requests = build_share_folder_requests(&rw, &ro);
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].FolderPath.to_string(), "C:\\a");
        assert_eq!(
            requests[0].AccessLevel,
            IsoSessionFolderSharingAccessLevel::ReadWrite
        );
        assert_eq!(requests[1].FolderPath.to_string(), "C:\\b");
        assert_eq!(
            requests[1].AccessLevel,
            IsoSessionFolderSharingAccessLevel::Read
        );
        assert_eq!(requests[2].FolderPath.to_string(), "C:\\c");
        assert_eq!(
            requests[2].AccessLevel,
            IsoSessionFolderSharingAccessLevel::Read
        );
    }

    fn ok_outcome(path: &str) -> ShareFolderOutcome {
        ShareFolderOutcome {
            folder_path: path.to_string(),
            failure: None,
        }
    }

    fn fail_outcome(path: &str, msg: &str, hr: u32, remediation: &str) -> ShareFolderOutcome {
        ShareFolderOutcome {
            folder_path: path.to_string(),
            failure: Some(ShareFolderFailure {
                message: msg.to_string(),
                remediation: remediation.to_string(),
                hresult: hr,
            }),
        }
    }

    #[test]
    fn aggregate_empty_outcomes_is_ok() {
        // Defensive: the runtime path returns Ok early on empty inputs, but
        // if extract_share_folder_outcomes ever returns an empty Vec, the
        // aggregator should still report success.
        assert!(matches!(aggregate_share_folder_outcomes(&[]), Ok(())));
    }

    #[test]
    fn aggregate_all_succeeded_is_ok() {
        let outcomes = vec![ok_outcome("C:\\a"), ok_outcome("C:\\b")];
        assert!(matches!(aggregate_share_folder_outcomes(&outcomes), Ok(())));
    }

    #[test]
    fn aggregate_single_failure_includes_path_message_and_hresult() {
        let outcomes = vec![fail_outcome("C:\\bad", "denied", 0x80070005, "")];
        let err = aggregate_share_folder_outcomes(&outcomes).unwrap_err();
        let IsolationSessionError::Lifecycle(msg) = err else {
            panic!("expected Lifecycle, got {:?}", err);
        };
        assert!(msg.contains("C:\\bad"), "missing path in: {}", msg);
        assert!(msg.contains("denied"), "missing message in: {}", msg);
        assert!(msg.contains("0x80070005"), "missing hresult in: {}", msg);
    }

    #[test]
    fn aggregate_mixed_outcomes_includes_all_failures_only() {
        let outcomes = vec![
            ok_outcome("C:\\good"),
            fail_outcome("C:\\bad1", "first failure", 0xdeadbeef, ""),
            ok_outcome("C:\\good2"),
            fail_outcome("C:\\bad2", "second failure", 0xfeedface, ""),
        ];
        let err = aggregate_share_folder_outcomes(&outcomes).unwrap_err();
        let IsolationSessionError::Lifecycle(msg) = err else {
            panic!("expected Lifecycle, got {:?}", err);
        };
        assert!(msg.contains("C:\\bad1"), "missing bad1 in: {}", msg);
        assert!(
            msg.contains("first failure"),
            "missing first msg in: {}",
            msg
        );
        assert!(msg.contains("C:\\bad2"), "missing bad2 in: {}", msg);
        assert!(
            msg.contains("second failure"),
            "missing second msg in: {}",
            msg
        );
        // Successful paths must not appear in the error message.
        assert!(
            !msg.contains("C:\\good"),
            "good path leaked into error: {}",
            msg
        );
        assert!(
            !msg.contains("C:\\good2"),
            "good2 path leaked into error: {}",
            msg
        );
    }

    #[test]
    fn aggregate_failure_with_remediation_appends_remediation() {
        let outcomes = vec![fail_outcome("C:\\rd", "denied", 0x80070005, "run as admin")];
        let err = aggregate_share_folder_outcomes(&outcomes).unwrap_err();
        let IsolationSessionError::Lifecycle(msg) = err else {
            panic!("expected Lifecycle, got {:?}", err);
        };
        assert!(
            msg.contains("remediation: run as admin"),
            "missing remediation in: {}",
            msg
        );
    }

    #[test]
    fn aggregate_failure_with_empty_remediation_omits_suffix() {
        let outcomes = vec![fail_outcome("C:\\nor", "msg", 0x80004005, "")];
        let err = aggregate_share_folder_outcomes(&outcomes).unwrap_err();
        let IsolationSessionError::Lifecycle(msg) = err else {
            panic!("expected Lifecycle, got {:?}", err);
        };
        assert!(
            !msg.contains("remediation:"),
            "unexpected remediation suffix in: {}",
            msg
        );
    }
}
