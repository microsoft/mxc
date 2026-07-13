// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `IsolationSessionManager` — granular wrapper over the in-proc
//! `IsoSessionOps` lifecycle. Each method maps 1:1 to a single WinRT op,
//! plus the `share_folders` non-lifecycle op. `create_process` also drives
//! the ConPTY relay setup + shutdown ladder against the local console.

use wxc_common::models::IsolationSessionConfigurationId;
use wxc_common::process_util::OwnedHandle;

use isolation_session_bindings::bindings::{
    IsoSessionConfigId, IsoSessionFolderSharingRequest, IsoSessionFolderSharingResult,
    IsoSessionOps, IsoSessionProcess, IsoSessionProcessResult, IsoSessionUserResult,
};
use windows::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, E_NOINTERFACE, HANDLE, REGDB_E_CLASSNOTREG,
};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject};
use windows_collections::IVectorView;
use windows_core::{HSTRING, PCWSTR};

use super::console_mode::{get_local_console_size, ConsoleModeRestorer, CtrlHandlerGuard};
use super::console_relay::{create_console_relay_thread, ConsoleRelayParams};
use super::error::{check_result, format_iso_error, lifecycle_err, IsolationSessionError};
use super::folder_sharing::{
    aggregate_share_folder_outcomes, build_share_folder_requests, extract_share_folder_outcomes,
};
use super::pipe_relay::{
    create_relay_thread, create_relay_thread_with_stop, PipeRelayParams, PipeRelayWithStopParams,
};
use super::process_options::{build_iso_process_options, ProcessOptions};
use super::protected_paths_filter::filter_protected_paths;

/// Registration ID used with the in-proc `IsoSessionOps` API. Must be the
/// literal string `"regid"`: the in-proc API uses the same string
/// internally for every agent-name-keyed op, so registering under any
/// other value causes subsequent calls to miss the registration. Do not
/// parameterise.
///
/// The id is effectively shared across all concurrent MXC isolation-session
/// sandboxes for the calling user; see `IsolationSessionManager::register_client`
/// (idempotent) and `unregister_client` (intentional no-op) for the
/// lifecycle implications.
const REGISTRATION_ID: &str = "regid";

fn to_iso_config_id(value: IsolationSessionConfigurationId) -> IsoSessionConfigId {
    match value {
        IsolationSessionConfigurationId::Small => IsoSessionConfigId::Small,
        IsolationSessionConfigurationId::Medium => IsoSessionConfigId::Medium,
        IsolationSessionConfigurationId::Large => IsoSessionConfigId::Large,
        IsolationSessionConfigurationId::Composable => IsoSessionConfigId::Composable,
    }
}

/// Activates the in-proc `IsoSessionOps` factory and returns the instance.
fn check_service_available_and_activate() -> Result<IsoSessionOps, IsolationSessionError> {
    match IsoSessionOps::new() {
        Ok(ops) => Ok(ops),
        Err(e) => {
            let code = e.code();
            if code == CLASS_E_CLASSNOTAVAILABLE || code == REGDB_E_CLASSNOTREG {
                Err(IsolationSessionError::ServiceUnavailable(format!(
                    "in-proc Windows.AI.IsolationSession IsoSessionOps API is not available \
                     on this OS build (HRESULT: {:#010x}). Ensure IsoSessionApp.dll is \
                     registered and the OS feature gate is enabled.",
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

/// Manages the `IsoSessionOps` lifecycle. Methods map 1:1 to the granular
/// API steps.
pub struct IsolationSessionManager {
    /// Registration identifier used in `RegisterApp` / `AddUserAsync` /
    /// `UnregisterAppAsync`. Pegged to the literal `"regid"` — required
    /// by the OS API.
    registration_id: HSTRING,
    /// Provision identifier. Used as `provisionId` to `AddUserAsync` and
    /// as the `agentName` argument to every subsequent op (the OS API
    /// aliases them at the COM layer).
    provision_id: HSTRING,
    /// The activated `IsoSessionOps` instance. Held for the manager's
    /// lifetime so the WinRT factory is reused across calls.
    ops: IsoSessionOps,
}

impl IsolationSessionManager {
    /// Activates the `IsoSessionOps` factory, verifies the service is
    /// available, and pegs the manager to the supplied `provisionId`.
    /// Both one-shot and state-aware callers mint a dynamic id per
    /// invocation (e.g. `wxc-<8-hex>`).
    pub(super) fn new(provision_id: &str) -> Result<Self, IsolationSessionError> {
        let ops = check_service_available_and_activate()?;
        Ok(Self {
            registration_id: HSTRING::from(REGISTRATION_ID),
            provision_id: HSTRING::from(provision_id),
            ops,
        })
    }

    /// Registers the app with the OS API. Safe to call repeatedly with
    /// the same regid — the OS API treats duplicates as success.
    pub(super) fn register_client(&self) -> Result<(), IsolationSessionError> {
        let result = self
            .ops
            .RegisterApp(&self.registration_id)
            .map_err(|e| lifecycle_err(format!("RegisterApp call failed: {}", e)))?;
        check_result(&result, "RegisterApp")
    }

    /// Step 1: Provision an agent user. Returns the OS-assigned agent
    /// account name for logging only — addressing for subsequent ops
    /// continues to use the configured `provision_id`.
    ///
    /// Note: `lifecycle.destroyOnExit` is silently ignored on this backend.
    /// The in-proc API hardcodes `Indefinite` lifetime in `AddUserAsync`.
    pub(super) fn provision_agent_user(&self) -> Result<String, IsolationSessionError> {
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
        let is_error = err
            .IsError()
            .map_err(|e| lifecycle_err(format!("AddUserAsync: get IsError failed: {}", e)))?;
        if is_error {
            return Err(format_iso_error("AddUserAsync", &err));
        }

        let name = user_result
            .AgentUserName()
            .map_err(|e| lifecycle_err(format!("AddUserAsync: get AgentUserName failed: {}", e)))?;
        Ok(name.to_string())
    }

    /// Step 1 (Entra): Provision an agent user backed by Entra cloud
    /// credentials. Calls `IIsoSessionOps2::AddUserAsync2` with the
    /// caller-supplied `wam_token`. Returns `ServiceUnavailable` when the
    /// host OS lacks the v2 interface; the caller does not fall back to v1.
    pub(super) fn provision_agent_user_v2(
        &self,
        wam_token: &str,
    ) -> Result<String, IsolationSessionError> {
        let async_op = match self.ops.AddUserAsync2(
            &self.registration_id,
            &self.provision_id,
            &HSTRING::from(wam_token),
        ) {
            Ok(op) => op,
            Err(e) if e.code() == E_NOINTERFACE => {
                return Err(IsolationSessionError::ServiceUnavailable(
                    "IsoSessionOps2 (Entra agent support) is not available on this OS build"
                        .to_string(),
                ));
            }
            Err(e) => return Err(lifecycle_err(format!("AddUserAsync2 call failed: {}", e))),
        };
        let user_result: IsoSessionUserResult = async_op
            .join()
            .map_err(|e| lifecycle_err(format!("AddUserAsync2 wait failed: {}", e)))?;

        let err = user_result
            .Error()
            .map_err(|e| lifecycle_err(format!("AddUserAsync2: get Error failed: {}", e)))?;
        let is_error = err
            .IsError()
            .map_err(|e| lifecycle_err(format!("AddUserAsync2: get IsError failed: {}", e)))?;
        if is_error {
            return Err(format_iso_error("AddUserAsync2", &err));
        }

        let name = user_result.AgentUserName().map_err(|e| {
            lifecycle_err(format!("AddUserAsync2: get AgentUserName failed: {}", e))
        })?;
        Ok(name.to_string())
    }

    /// Grants the agent user access to host folders. `readwrite_paths` get
    /// read+write access, `readonly_paths` get read-only. Both apply
    /// recursively to each subtree.
    ///
    /// Independent of session start: requires only that the agent user
    /// exists (call after `provision_agent_user`, before
    /// `deprovision_agent_user`).
    ///
    /// The MXC process needs `WRITE_DAC` on each target folder. Returns
    /// `Ok` on all-success; on any per-path failure returns a `Lifecycle`
    /// error listing every failed path. Empty input on both slices is a
    /// no-op.
    pub(super) fn share_folders(
        &self,
        readwrite_paths: &[String],
        readonly_paths: &[String],
        logger: Option<&mut wxc_common::logger::Logger>,
    ) -> Result<(), IsolationSessionError> {
        // Emergency mitigation (MXC issue #330): drop protected paths
        // before forwarding. See `protected_paths_filter.rs`.
        let (rw_kept, ro_kept) = filter_protected_paths(readwrite_paths, readonly_paths, logger);
        let requests = build_share_folder_requests(&rw_kept, &ro_kept);
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
    pub(super) fn start_session(
        &self,
        config_id: IsolationSessionConfigurationId,
    ) -> Result<(), IsolationSessionError> {
        let cfg: IsoSessionConfigId = to_iso_config_id(config_id);
        let async_op = self
            .ops
            .StartSessionAsync(&self.provision_id, cfg)
            .map_err(|e| lifecycle_err(format!("StartSessionAsync call failed: {}", e)))?;
        let result = async_op
            .join()
            .map_err(|e| lifecycle_err(format!("StartSessionAsync wait failed: {}", e)))?;
        check_result(&result, "StartSessionAsync")
    }

    /// Step 2 (Entra): Start an Entra-backed isolation session via
    /// `IIsoSessionOps2::StartSessionAsync2`. Returns `ServiceUnavailable`
    /// when the host OS lacks the v2 interface.
    pub(super) fn start_session_v2(
        &self,
        config_id: IsolationSessionConfigurationId,
        wam_token: &str,
    ) -> Result<(), IsolationSessionError> {
        let cfg: IsoSessionConfigId = to_iso_config_id(config_id);
        let async_op =
            match self
                .ops
                .StartSessionAsync2(&self.provision_id, cfg, &HSTRING::from(wam_token))
            {
                Ok(op) => op,
                Err(e) if e.code() == E_NOINTERFACE => {
                    return Err(IsolationSessionError::ServiceUnavailable(
                        "IsoSessionOps2 (Entra agent support) is not available on this OS build"
                            .to_string(),
                    ));
                }
                Err(e) => {
                    return Err(lifecycle_err(format!(
                        "StartSessionAsync2 call failed: {}",
                        e
                    )));
                }
            };
        let result = async_op
            .join()
            .map_err(|e| lifecycle_err(format!("StartSessionAsync2 wait failed: {}", e)))?;
        check_result(&result, "StartSessionAsync2")
    }

    /// Step 3: Create a process inside the started isolation session.
    /// Output is streamed live to wxc-exec's stdio via internal relay
    /// threads; only the exit code is returned to the caller.
    pub(super) fn create_process(
        &self,
        options: &ProcessOptions,
    ) -> Result<i32, IsolationSessionError> {
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
        let is_error = err.IsError().map_err(|e| {
            lifecycle_err(format!(
                "RunProcessWithOptionsAsync: get IsError failed: {}",
                e
            ))
        })?;
        if is_error {
            return Err(format_iso_error("RunProcessWithOptionsAsync", &err));
        }

        let process: IsoSessionProcess = result.Process().map_err(|e| {
            lifecycle_err(format!(
                "RunProcessWithOptionsAsync: get Process failed: {}",
                e
            ))
        })?;

        // Three pipe relay threads bridge wxc-exec's stdio with the pipe
        // handles owned by `IsoSessionProcess`, crossing the desktop-session
        // boundary that kernel console-handle inheritance cannot.
        //
        // Handle ownership across four sources:
        //   - Pipe handles owned by `IsoSessionProcess` (`OutputHandle()` /
        //     `ErrorHandle()` / `InputHandle()`, returned as u64): released
        //     by `process.Close()`. We do NOT close them.
        //   - wxc-exec's std handles (`GetStdHandle(STD_*_HANDLE)`): owned
        //     by the OS for the process lifetime. We do NOT close them.
        //   - Stop event for stdin relay (`CreateEventW`): RAII-closed via
        //     `OwnedHandle`.
        //   - Relay thread handles: RAII-closed via `OwnedHandle` after we
        //     `WaitForSingleObject` on each.
        //
        // Lifetime: relay-param structs are stack-allocated; we wait on
        // every spawned thread (INFINITE for stdout/stderr, bounded for
        // stdin) before this function returns.
        // A getter that errors is a backend failure, not an absent stream:
        // propagate it rather than coercing to 0, which downstream treats as
        // "no handle" and silently skips the corresponding stdio relay. A
        // genuinely returned 0 still means absent and is preserved.
        let stdout_handle_val = process.OutputHandle().map_err(|e| {
            lifecycle_err(format!(
                "RunProcessWithOptionsAsync: get OutputHandle failed: {}",
                e
            ))
        })?;
        let stderr_handle_val = process.ErrorHandle().map_err(|e| {
            lifecycle_err(format!(
                "RunProcessWithOptionsAsync: get ErrorHandle failed: {}",
                e
            ))
        })?;
        let stdin_handle_val = process.InputHandle().map_err(|e| {
            lifecycle_err(format!(
                "RunProcessWithOptionsAsync: get InputHandle failed: {}",
                e
            ))
        })?;

        let wxc_stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }
            .map_err(|e| lifecycle_err(format!("GetStdHandle(stdout) failed: {}", e)))?;
        let wxc_stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) }
            .map_err(|e| lifecycle_err(format!("GetStdHandle(stderr) failed: {}", e)))?;
        let wxc_stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) }
            .map_err(|e| lifecycle_err(format!("GetStdHandle(stdin) failed: {}", e)))?;

        // In interactive mode, switch wxc-exec's local console to raw VT
        // mode so the agent's ConPTY does all the input echoing and
        // rendering — otherwise both consoles render the same input twice
        // (duplicate echos, doubled prompts, broken `\r\n` handling).
        // RAII-restored on scope exit. No-op when stdio is not a console.
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

        // Manual-reset stop event for the stdin relay. Effective for
        // waitable `h_read` (console = TTY mode); for pipe handles
        // (non-TTY) it has no effect on a blocked `ReadFile`, so we use a
        // bounded `WaitForSingleObject` after process exit and rely on
        // `process.Close()` invalidating the `IsoSessionProcess` handle
        // (next WriteFile fails) plus OS cleanup on wxc-exec exit.
        let stdin_stop_event = unsafe {
            CreateEventW(None, true, false, PCWSTR::null())
                .map_err(|e| lifecycle_err(format!("CreateEventW(stdin stop): {}", e)))?
        };
        let stdin_stop_owned = OwnedHandle::new(stdin_stop_event);

        // Install a console Ctrl handler that signals `stdin_stop_owned`
        // on Ctrl-C or terminal-close events, so the relay loops drain
        // cleanly instead of being terminated by the OS default
        // `ExitProcess`. Interactive mode only — non-interactive mode
        // wants the default behavior so the parent can terminate
        // wxc-exec via Ctrl-C. Drop order is LIFO: `_ctrl_guard` drops
        // before `stdin_stop_owned`, ensuring the handler can no longer
        // reference the event after the guard is gone.
        let _ctrl_guard = if options.interactive {
            Some(CtrlHandlerGuard::install(stdin_stop_owned.get()))
        } else {
            None
        };

        let mut stdout_params = PipeRelayParams {
            h_read: HANDLE(stdout_handle_val as *mut core::ffi::c_void),
            h_write: wxc_stdout,
        };
        let mut stderr_params = PipeRelayParams {
            h_read: HANDLE(stderr_handle_val as *mut core::ffi::c_void),
            h_write: wxc_stderr,
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
        // Stdin: in interactive mode use the console-aware relay so
        // `WINDOW_BUFFER_SIZE_EVENT` records propagate as
        // `ResizeConsole(cols, rows)` calls on the agent's inner ConPTY.
        // In non-interactive mode the agent's stdin is plain byte-oriented
        // and the simpler stop-aware pipe relay is appropriate. The two
        // params shapes share `h_read` / `h_write` / `h_stop_event` but
        // differ in extras (the console variant carries the resize
        // callback), so we wrap them in a sum type and pattern-match on
        // it when spawning the thread.
        enum StdinRelayKind {
            None,
            Pipe(PipeRelayWithStopParams),
            Console(ConsoleRelayParams),
        }

        let stdin_h_write = HANDLE(stdin_handle_val as *mut core::ffi::c_void);
        let stdin_h_stop = stdin_stop_owned.get();
        let mut stdin_relay_state = if stdin_handle_val == 0 {
            StdinRelayKind::None
        } else if options.interactive {
            // Clone the WinRT process handle so the relay thread holds
            // its own ref-counted reference (WinRT clone = AddRef). The
            // closure is `'static + Send`; the cloned ref moves onto the
            // relay thread with the closure.
            let process_for_resize = process.clone();
            StdinRelayKind::Console(ConsoleRelayParams {
                h_read: wxc_stdin,
                h_write: stdin_h_write,
                h_stop_event: stdin_h_stop,
                resize_callback: Box::new(move |cols, rows| {
                    // Ignore failures: best-effort delivery.
                    let _ = process_for_resize.ResizeConsole(cols, rows);
                }),
            })
        } else {
            StdinRelayKind::Pipe(PipeRelayWithStopParams {
                h_read: wxc_stdin,
                h_write: stdin_h_write,
                h_stop_event: stdin_h_stop,
            })
        };

        let stdin_relay: Option<OwnedHandle> = match &mut stdin_relay_state {
            StdinRelayKind::None => None,
            StdinRelayKind::Pipe(params) => Some(
                unsafe { create_relay_thread_with_stop(params) }
                    .map_err(|e| lifecycle_err(format!("create stdin relay: {}", e)))?,
            ),
            StdinRelayKind::Console(params) => {
                Some(unsafe { create_console_relay_thread(params) }.map_err(|e| {
                    lifecycle_err(format!("create console-aware stdin relay: {}", e))
                })?)
            }
        };

        // `WaitForExit` is a Win32 `WaitForSingleObject` on a kernel handle
        // — no COM round-trip. On timeout it returns -1; otherwise the exit
        // code.
        let _ = process
            .WaitForExit(options.timeout_ms)
            .map_err(|e| lifecycle_err(format!("WaitForExit failed: {}", e)))?;

        let exit_code = wait_with_graceful_shutdown(&process)?;

        // Signal the stdin relay to exit. Effective for waitable (console)
        // handles; for pipe handles the bounded wait below expires and we
        // proceed.
        unsafe {
            let _ = SetEvent(stdin_stop_owned.get());
        }

        // Drain stdout / stderr relays (INFINITE — they exit when the
        // `IsoSessionProcess` pipe-read EOFs once the agent's write ends
        // close at OS-level cleanup). The OS-side per-process timeout is
        // the safety net.
        if let Some(t) = stdout_relay {
            unsafe { WaitForSingleObject(t.get(), u32::MAX) };
        }
        if let Some(t) = stderr_relay {
            unsafe { WaitForSingleObject(t.get(), u32::MAX) };
        }

        // Drain stdin relay with a 1s bound. TTY mode exits via the stop
        // event; non-TTY may still be in `ReadFile` — the thread exits
        // when wxc-exec exits and the OS cleans it up.
        if let Some(t) = stdin_relay {
            unsafe { WaitForSingleObject(t.get(), 1000) };
        }

        // Now safe to release the `IsoSessionProcess` handles.
        let _ = process.Close();

        Ok(exit_code)
    }

    /// Step 4: Stop the isolation session.
    pub(super) fn stop_session(&self) -> Result<(), IsolationSessionError> {
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
    pub(super) fn deprovision_agent_user(&self) -> Result<(), IsolationSessionError> {
        let async_op = self
            .ops
            .RemoveUserAsync(&self.provision_id)
            .map_err(|e| lifecycle_err(format!("RemoveUserAsync call failed: {}", e)))?;
        let result = async_op
            .join()
            .map_err(|e| lifecycle_err(format!("RemoveUserAsync wait failed: {}", e)))?;
        check_result(&result, "RemoveUserAsync")
    }

    /// Tears down the client registration set up by `register_client` —
    /// currently a no-op.
    pub(super) fn unregister_client(&self) -> Result<(), IsolationSessionError> {
        // Intentional no-op. The `"regid"` literal is shared across all
        // concurrent MXC isolation-session sandboxes for the calling user;
        // calling `UnregisterAppAsync` would tear down the registration for
        // every other still-running one. Reversible when the OS API
        // eliminates registration IDs entirely; do not uncomment without
        // verifying OS API behavior has changed.
        //
        // let async_op = self
        //     .ops
        //     .UnregisterAppAsync(&self.registration_id)
        //     .map_err(|e| lifecycle_err(format!("UnregisterAppAsync call failed: {}", e)))?;
        // let result = async_op
        //     .join()
        //     .map_err(|e| lifecycle_err(format!("UnregisterAppAsync wait failed: {}", e)))?;
        // check_result(&result, "UnregisterAppAsync")
        Ok(())
    }
}

/// Three-tier graceful shutdown for an `IsoSessionProcess` that's still
/// running after `WaitForExit(timeout_ms)` returns. Tier 1: close stdin —
/// many REPLs exit on EOF alone. Tier 2: `SendCtrlClose` — ConPTY-only;
/// `E_NOTIMPL` outside ConPTY, benign. Tier 3: force-terminate, wait
/// infinitely (`WaitForExit(0)` = INFINITE) for the kill to land.
///
/// The first `ExitCode()` query is `?`-propagated: a failure there means
/// the kernel handle is broken, and the cleanup methods on the same
/// handle are unlikely to make progress — better to surface the COM error
/// than to fire blind. Per-tier subsequent queries fall back to
/// `STILL_ACTIVE` so a transient read failure does not short-circuit the
/// escalation.
fn wait_with_graceful_shutdown(process: &IsoSessionProcess) -> Result<i32, IsolationSessionError> {
    // `STILL_ACTIVE` (0x103) is exposed by the `windows` crate as
    // `STATUS_PENDING: NTSTATUS` — same numeric value, different name.
    use windows::Win32::Foundation::STATUS_PENDING;
    const STILL_ACTIVE: i32 = STATUS_PENDING.0;
    let mut exit_code = process
        .ExitCode()
        .map_err(|e| lifecycle_err(format!("get ExitCode failed: {}", e)))?;
    if exit_code != STILL_ACTIVE {
        return Ok(exit_code);
    }

    let _ = process.CloseStandardInput();
    let _ = process.WaitForExit(5000);
    exit_code = process.ExitCode().unwrap_or(STILL_ACTIVE);
    if exit_code != STILL_ACTIVE {
        return Ok(exit_code);
    }

    let _ = process.SendCtrlClose();
    let _ = process.WaitForExit(3000);
    exit_code = process.ExitCode().unwrap_or(STILL_ACTIVE);
    if exit_code != STILL_ACTIVE {
        return Ok(exit_code);
    }

    let _ = process.Terminate();
    let _ = process.WaitForExit(0);
    Ok(process.ExitCode().unwrap_or(-1))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // The `to_iso_config_id` free function is the sole bridge between
    // MXC's internal enum and the WinRT enum. If a new variant is added
    // to either side without updating the function, these tests catch
    // the drift.

    #[test]
    fn config_id_conversion_small() {
        let iso_id: IsoSessionConfigId = to_iso_config_id(IsolationSessionConfigurationId::Small);
        assert_eq!(iso_id, IsoSessionConfigId::Small);
    }

    #[test]
    fn config_id_conversion_medium() {
        let iso_id: IsoSessionConfigId = to_iso_config_id(IsolationSessionConfigurationId::Medium);
        assert_eq!(iso_id, IsoSessionConfigId::Medium);
    }

    #[test]
    fn config_id_conversion_large() {
        let iso_id: IsoSessionConfigId = to_iso_config_id(IsolationSessionConfigurationId::Large);
        assert_eq!(iso_id, IsoSessionConfigId::Large);
    }

    #[test]
    fn config_id_conversion_composable() {
        let iso_id: IsoSessionConfigId =
            to_iso_config_id(IsolationSessionConfigurationId::Composable);
        assert_eq!(iso_id, IsoSessionConfigId::Composable);
    }
}
