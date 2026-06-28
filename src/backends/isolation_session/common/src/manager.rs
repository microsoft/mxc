// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `IsolationSessionManager` — granular wrapper over the in-proc
//! isolation session lifecycle. Each method maps 1:1 to a single WinRT op.
//! `create_process` also drives the ConPTY relay setup + shutdown ladder
//! against the local console.

use wxc_common::process_util::OwnedHandle;

use isolation_session_bindings::bindings::{
    IsoSessionOps, IsoSessionProcess, IsoSessionProcessResult, IsoSessionUserResult,
};
use windows::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, HANDLE, REGDB_E_CLASSNOTREG};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject};
use windows_core::{HSTRING, PCWSTR};

use super::console_mode::{get_local_console_size, ConsoleModeRestorer, CtrlHandlerGuard};
use super::console_relay::{create_console_relay_thread, ConsoleRelayParams};
use super::error::{check_result, format_iso_error, lifecycle_err, IsolationSessionError};
use super::pipe_relay::{
    create_relay_thread, create_relay_thread_with_stop, PipeRelayParams, PipeRelayWithStopParams,
};
use super::process_options::{build_iso_process_options, ProcessOptions};

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

/// Returns `true` when the in-proc isolation session service can be
/// activated on this host. Used by the probe to advertise backend
/// availability without provisioning anything.
pub fn is_service_available() -> bool {
    check_service_available_and_activate().is_ok()
}

/// Manages the isolation session lifecycle. Methods map 1:1 to the granular
/// API steps.
pub struct IsolationSessionManager {
    /// The OS-assigned agent user name returned by `add_user`. Used as the
    /// `agentUserName` argument to every subsequent lifecycle op.
    agent_user_name: HSTRING,
    /// The activated service instance. Held for the manager's lifetime so
    /// the WinRT factory is reused across calls.
    ops: IsoSessionOps,
}

impl IsolationSessionManager {
    /// Pegs a manager to an existing OS-assigned agent user name (the value
    /// returned by `add_user`). Activates the service factory once and
    /// reuses it for the manager's lifetime.
    pub(super) fn new(agent_user_name: &str) -> Result<Self, IsolationSessionError> {
        let ops = check_service_available_and_activate()?;
        Ok(Self {
            agent_user_name: HSTRING::from(agent_user_name),
            ops,
        })
    }

    /// Provisions an agent user and returns the OS-assigned account name,
    /// which addresses every subsequent lifecycle op.
    ///
    /// Pass empty strings for a local agent user, or the Entra account name
    /// and its WAM token for an Entra-backed agent; the OS validates
    /// token/identity consistency. Because the account name is not known
    /// until this returns, the caller constructs the manager via `new`
    /// afterward — hence an associated function rather than a method.
    ///
    /// Note: `lifecycle.destroyOnExit` is silently ignored on this backend.
    /// The in-proc API hardcodes `Indefinite` lifetime.
    pub(super) fn add_user(
        opt_entra_account_name: &str,
        opt_wam_token: &str,
    ) -> Result<String, IsolationSessionError> {
        let ops = check_service_available_and_activate()?;
        let async_op = ops
            .AddUserAsync(
                &HSTRING::from(opt_entra_account_name),
                &HSTRING::from(opt_wam_token),
            )
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

    /// Step 2: Start the isolation session for the pegged agent user.
    ///
    /// `opt_wam_token` is empty for a local agent or the Entra WAM token for
    /// an Entra-backed agent.
    pub(super) fn start_session(&self, opt_wam_token: &str) -> Result<(), IsolationSessionError> {
        let async_op = self
            .ops
            .StartSessionAsync(&self.agent_user_name, &HSTRING::from(opt_wam_token))
            .map_err(|e| lifecycle_err(format!("StartSessionAsync call failed: {}", e)))?;
        let result = async_op
            .join()
            .map_err(|e| lifecycle_err(format!("StartSessionAsync wait failed: {}", e)))?;
        check_result(&result, "StartSessionAsync")
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
                &self.agent_user_name,
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
            .StopSessionAsync(&self.agent_user_name)
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
            .RemoveUserAsync(&self.agent_user_name)
            .map_err(|e| lifecycle_err(format!("RemoveUserAsync call failed: {}", e)))?;
        let result = async_op
            .join()
            .map_err(|e| lifecycle_err(format!("RemoveUserAsync wait failed: {}", e)))?;
        check_result(&result, "RemoveUserAsync")
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
}
