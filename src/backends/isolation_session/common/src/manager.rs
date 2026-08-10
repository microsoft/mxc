// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `IsolationSessionManager` — granular wrapper over the in-proc
//! isolation session lifecycle. Each method maps 1:1 to a single WinRT op.
//! `create_process` also drives the ConPTY relay setup + shutdown ladder
//! against the local console.

use wxc_common::audit::{AuditEvent, AuditEventName, KillMethod, TeardownStatus};
use wxc_common::logger::Logger;
use wxc_common::process_util::OwnedHandle;

use isolation_session_bindings::bindings::{
    IsoSessionOps, IsoSessionProcess, IsoSessionProcessResult, IsoSessionUserResult,
};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject};
use windows_core::{HSTRING, PCWSTR};

use super::console_mode::{get_local_console_size, ConsoleModeRestorer, CtrlHandlerGuard};
use super::console_relay::{create_console_relay_thread, ConsoleRelayParams};
use super::error::{
    activation_error, check_result, format_iso_error, lifecycle_err, op, transport_err,
    IsolationSessionError, StalePromotion,
};
use super::pipe_relay::{
    create_relay_thread, create_relay_thread_with_stop, PipeRelayParams, PipeRelayWithStopParams,
};
use super::process_options::{build_iso_process_options, ProcessOptions};

/// Activates the in-proc IsolationSession runtime factory and returns the
/// instance.
fn check_service_available_and_activate() -> Result<IsoSessionOps, IsolationSessionError> {
    match IsoSessionOps::new() {
        Ok(ops) => Ok(ops),
        // The HRESULT→error mapping lives in `activation_error` so it stays
        // testable without depending on whether this host can activate the
        // API at all.
        Err(e) => Err(activation_error(e.code().0 as u32, &e.message())),
    }
}

/// The provision-time facts the OS assigns to a freshly-created agent user,
/// read from `IsoSessionUserResult` at `add_user`. The addressing key for
/// every later lifecycle op remains `agent_user_name`; the other two fields
/// are provision metadata surfaced to the caller.
pub(super) struct ProvisionedUser {
    /// The OS-assigned agent account name (also the `sandboxId` tail).
    pub agent_user_name: String,
    /// The security identifier (SID) of the agent user. Diagnostic only.
    pub agent_user_sid: String,
    /// A directory shared between the calling user and this isolated agent
    /// user, through which the caller can stage files into the session. Each
    /// isolated user can access only its own workspace; the caller can access
    /// all of them. Deleted when the agent user is deprovisioned.
    pub ephemeral_workspace_path: String,
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

    /// Provisions an agent user and returns its provision-time facts (the
    /// OS-assigned account name — which addresses every subsequent lifecycle
    /// op — plus the agent SID and the shared ephemeral workspace path),
    /// together with a manager already pegged to that account.
    ///
    /// The manager is returned rather than left to the caller to build with
    /// [`Self::new`] because building it separately would activate the service
    /// a second time. That second activation can fail *after* the agent user
    /// has been minted, and at that point the account cannot be removed —
    /// removal needs the very service instance that just failed to activate —
    /// so the sandbox would leak with no way to clean it up. Handing back the
    /// instance `add_user` already holds removes that window entirely.
    ///
    /// Once the API reports success the account exists, so every failure after
    /// that point deprovisions best-effort rather than abandoning it. The sole
    /// exception is a failure to read the account name itself, which leaves
    /// nothing to address a removal to.
    ///
    /// The OS interface takes an optional account name and token; MXC always
    /// passes empty strings, which selects a local agent user.
    ///
    /// Note: the in-proc API exposes no session-lifetime knob, so `lifecycle`
    /// cannot be honored here. Unsupported values are refused by the calling
    /// surface rather than ignored — one-shot rejects `destroyOnExit: false`
    /// and `preservePolicy: true` in `validate_runner`, and the state-aware
    /// parser rejects the whole `lifecycle` section.
    pub(super) fn add_user() -> Result<(ProvisionedUser, Self), IsolationSessionError> {
        let ops = check_service_available_and_activate()?;
        let async_op = ops
            .AddUserAsync(&HSTRING::new(), &HSTRING::new())
            .map_err(|e| transport_err(op::ADD_USER, "call failed", &e))?;
        let user_result: IsoSessionUserResult = async_op
            .join()
            .map_err(|e| transport_err(op::ADD_USER, "wait failed", &e))?;

        let err = user_result
            .Error()
            .map_err(|e| transport_err(op::ADD_USER, "get Error failed", &e))?;
        let is_error = err
            .IsError()
            .map_err(|e| transport_err(op::ADD_USER, "get IsError failed", &e))?;
        if is_error {
            // Provision mints the agent user, so `ERROR_NOT_FOUND` here can
            // never mean "the sandbox is gone" — there is no sandbox id yet.
            return Err(format_iso_error(
                op::ADD_USER,
                &err,
                StalePromotion::NotEligible,
            ));
        }

        let agent_user_name = user_result
            .AgentUserName()
            .map_err(|e| transport_err(op::ADD_USER, "get AgentUserName failed", &e))?;

        // Past this point the OS account exists and `agent_user_name` is the
        // key that removes it, so build the manager now rather than after the
        // remaining getters. That makes every subsequent failure recoverable:
        // the removal key and a live service instance are both already in hand.
        //
        // A failure of `AgentUserName()` above is the one case with no
        // in-process remedy — without the name there is nothing to address a
        // removal to — so it is left to propagate.
        let manager = Self {
            agent_user_name: agent_user_name.clone(),
            ops,
        };

        let provisioned = match Self::read_remaining_facts(&user_result, &agent_user_name) {
            Ok(provisioned) => provisioned,
            Err(e) => {
                // Best-effort: returning here without this would abandon an
                // account we are still able to remove.
                let _ = manager.deprovision_agent_user();
                return Err(e);
            }
        };

        Ok((provisioned, manager))
    }

    /// Reads the provision-time facts that remain after the agent user name.
    ///
    /// Split out of [`Self::add_user`] so that a failure in any of them lands
    /// on one error path, where the freshly created account can be removed
    /// instead of orphaned.
    fn read_remaining_facts(
        user_result: &IsoSessionUserResult,
        agent_user_name: &HSTRING,
    ) -> Result<ProvisionedUser, IsolationSessionError> {
        let agent_user_sid = user_result
            .AgentUserSid()
            .map_err(|e| transport_err(op::ADD_USER, "get AgentUserSid failed", &e))?;
        let ephemeral_workspace_path = user_result
            .EphemeralWorkspacePath()
            .map_err(|e| transport_err(op::ADD_USER, "get EphemeralWorkspacePath failed", &e))?;

        Ok(ProvisionedUser {
            agent_user_name: agent_user_name.to_string(),
            agent_user_sid: agent_user_sid.to_string(),
            ephemeral_workspace_path: ephemeral_workspace_path.to_string(),
        })
    }

    /// Step 2: Start the isolation session for the pegged agent user.
    ///
    /// The OS interface takes an optional token; MXC always passes an empty
    /// string, which selects a local agent session.
    pub(super) fn start_session(&self) -> Result<(), IsolationSessionError> {
        let async_op = self
            .ops
            .StartSessionAsync(&self.agent_user_name, &HSTRING::new())
            .map_err(|e| transport_err(op::START_SESSION, "call failed", &e))?;
        let result = async_op
            .join()
            .map_err(|e| transport_err(op::START_SESSION, "wait failed", &e))?;
        check_result(&result, op::START_SESSION, StalePromotion::Eligible)
    }

    /// Step 3: Create a process inside the started isolation session.
    /// Output is streamed live to wxc-exec's stdio via internal relay
    /// threads; only the exit code is returned to the caller.
    pub(super) fn create_process(
        &self,
        options: &ProcessOptions,
        logger: Option<&mut Logger>,
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
            .map_err(|e| transport_err(op::RUN_PROCESS, "call failed", &e))?;
        let result: IsoSessionProcessResult = async_op
            .join()
            .map_err(|e| transport_err(op::RUN_PROCESS, "wait failed", &e))?;

        let err = result
            .Error()
            .map_err(|e| transport_err(op::RUN_PROCESS, "get Error failed", &e))?;
        let is_error = err
            .IsError()
            .map_err(|e| transport_err(op::RUN_PROCESS, "get IsError failed", &e))?;
        if is_error {
            return Err(format_iso_error(
                op::RUN_PROCESS,
                &err,
                StalePromotion::Eligible,
            ));
        }

        let process: IsoSessionProcess = result
            .Process()
            .map_err(|e| transport_err(op::RUN_PROCESS, "get Process failed", &e))?;

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
        // Lifetime: each relay's param struct is moved to the heap and owned
        // by its thread, which frees it on exit. Joining is therefore not
        // required for memory safety — an early return that abandons a relay
        // leaves it reading memory it owns, not a dead frame. We still join on
        // the normal path (INFINITE for stdout/stderr, bounded for stdin) so
        // all output is drained before the call returns.
        // A getter that errors is a backend failure, not an absent stream:
        // propagate it rather than coercing to 0, which downstream treats as
        // "no handle" and silently skips the corresponding stdio relay. A
        // genuinely returned 0 still means absent and is preserved.
        let stdout_handle_val = process
            .OutputHandle()
            .map_err(|e| transport_err(op::RUN_PROCESS, "get OutputHandle failed", &e))?;
        let stderr_handle_val = process
            .ErrorHandle()
            .map_err(|e| transport_err(op::RUN_PROCESS, "get ErrorHandle failed", &e))?;
        let stdin_handle_val = process
            .InputHandle()
            .map_err(|e| transport_err(op::RUN_PROCESS, "get InputHandle failed", &e))?;

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

        let stdout_relay: Option<OwnedHandle> = if stdout_handle_val != 0 {
            Some(
                unsafe {
                    create_relay_thread(PipeRelayParams {
                        h_read: HANDLE(stdout_handle_val as *mut core::ffi::c_void),
                        h_write: wxc_stdout,
                    })
                }
                .map_err(|e| lifecycle_err(format!("create stdout relay: {}", e)))?,
            )
        } else {
            None
        };
        let stderr_relay: Option<OwnedHandle> = if stderr_handle_val != 0 {
            Some(
                unsafe {
                    create_relay_thread(PipeRelayParams {
                        h_read: HANDLE(stderr_handle_val as *mut core::ffi::c_void),
                        h_write: wxc_stderr,
                    })
                }
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
        let stdin_relay_state = if stdin_handle_val == 0 {
            StdinRelayKind::None
        } else if options.interactive {
            // Clone the WinRT process handle so the relay thread holds
            // its own ref-counted reference (WinRT clone = AddRef). The
            // closure is `'static + Send`; the cloned ref moves onto the
            // relay thread with the closure, and is released when the
            // thread frees the params it owns.
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

        // Matched by value: the params move into the spawn call, which puts
        // them on the heap under the relay thread's ownership.
        let stdin_relay: Option<OwnedHandle> = match stdin_relay_state {
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
            .map_err(|e| transport_err(op::RUN_PROCESS, "WaitForExit failed", &e))?;

        let identity = self.agent_user_name.to_string();
        let exit_code =
            wait_with_graceful_shutdown(&process, options.timeout_ms, &identity, logger)?;

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
            .map_err(|e| transport_err(op::STOP_SESSION, "call failed", &e))?;
        let result = async_op
            .join()
            .map_err(|e| transport_err(op::STOP_SESSION, "wait failed", &e))?;
        check_result(&result, op::STOP_SESSION, StalePromotion::Eligible)
    }

    /// Step 5: Deprovision the agent user.
    pub(super) fn deprovision_agent_user(&self) -> Result<(), IsolationSessionError> {
        let async_op = self
            .ops
            .RemoveUserAsync(&self.agent_user_name)
            .map_err(|e| transport_err(op::REMOVE_USER, "call failed", &e))?;
        let result = async_op
            .join()
            .map_err(|e| transport_err(op::REMOVE_USER, "wait failed", &e))?;
        check_result(&result, op::REMOVE_USER, StalePromotion::Eligible)
    }
}

/// Which lifecycle release steps a teardown pass actually attempted, and
/// whether each landed.
///
/// The isolation-session backend releases a *container* (the session plus the
/// agent user backing it), never firewall rules — the OS API exposes no network
/// primitive at all. So this carries the backend's own release facts rather
/// than the AppContainer tiers' firewall counters; `tier` is likewise absent
/// because this backend has no fallback ladder.
#[derive(Debug, Default, Clone, Copy)]
pub struct TeardownOutcome {
    /// `stop_session` was attempted, and whether it succeeded.
    pub session_stopped: Option<bool>,
    /// `deprovision_agent_user` was attempted, and whether it succeeded.
    pub agent_user_deprovisioned: Option<bool>,
}

impl TeardownOutcome {
    /// `failure` if any attempted step failed, `skipped` if nothing was
    /// attempted at all, `success` otherwise.
    fn status(&self) -> TeardownStatus {
        let steps = [self.session_stopped, self.agent_user_deprovisioned];
        if steps.contains(&Some(false)) {
            TeardownStatus::Failure
        } else if steps.iter().all(|s| s.is_none()) {
            TeardownStatus::Skipped
        } else {
            TeardownStatus::Success
        }
    }
}

/// Emit `mxc.SandboxTornDown` for an isolation-session teardown pass.
///
/// Shared by the one-shot runner (which tears the whole lifecycle down in one
/// pass) and the state-aware `stop` / `deprovision` phases (which each release
/// their own slice), so both surfaces produce the same record shape and a
/// cleanup failure is distinguishable from a success on either.
///
/// `phase` names which lifecycle surface produced the record, because a
/// state-aware `stop` legitimately releases the session without releasing the
/// container, and a consumer must be able to tell that apart from a one-shot
/// pass that failed to deprovision.
pub fn log_sandbox_torn_down(
    logger: &mut Logger,
    identity: &str,
    phase: &str,
    outcome: TeardownOutcome,
) {
    if !logger.has_diagnostic_sink() && !wxc_common::telemetry::is_active() {
        return;
    }
    wxc_common::telemetry::log_sandbox_torn_down(
        &wxc_common::policy_identity::redact_identity(identity),
        outcome.status().as_str(),
        &format!(
            "session_stopped={},agent_user_deprovisioned={}",
            outcome.session_stopped == Some(true),
            outcome.agent_user_deprovisioned == Some(true),
        ),
    );
    if !logger.has_diagnostic_sink() {
        return;
    }
    let record = AuditEvent::new(AuditEventName::SandboxTornDown)
        .str("backend", "isolation_session")
        .str(
            "identity",
            &wxc_common::policy_identity::redact_identity(identity),
        )
        .str("phase", phase)
        .str("status", outcome.status().as_str())
        .bool("session_stopped", outcome.session_stopped == Some(true))
        .bool(
            "agent_user_deprovisioned",
            outcome.agent_user_deprovisioned == Some(true),
        );
    logger.log_audit_event(&record);
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
fn wait_with_graceful_shutdown(
    process: &IsoSessionProcess,
    timeout_ms: u32,
    identity: &str,
    mut logger: Option<&mut Logger>,
) -> Result<i32, IsolationSessionError> {
    // `STILL_ACTIVE` (0x103) is exposed by the `windows` crate as
    // `STATUS_PENDING: NTSTATUS` — same numeric value, different name.
    use windows::Win32::Foundation::STATUS_PENDING;
    const STILL_ACTIVE: i32 = STATUS_PENDING.0;
    let mut exit_code = process
        .ExitCode()
        .map_err(|e| transport_err(op::RUN_PROCESS, "get ExitCode failed", &e))?;
    // The current IsolationSession process contract does not expose a process
    // identifier. Keep the required telemetry/audit field with zero as the
    // conventional unavailable-PID sentinel rather than inventing an ID.
    let pid = 0;
    if exit_code != STILL_ACTIVE {
        // Normal pre-timeout completion. Emit `mxc.ProcessExited` so a
        // clean run has a terminal audit record. Deliberately NOT emitted
        // on the graceful-shutdown tiers below — those already emitted
        // `ProcessTimedOut` and possibly `ProcessKillFailed`, and the run
        // is not a normal exit.
        wxc_common::telemetry::log_process_event(
            wxc_common::telemetry::ProcessEventKind::Exited,
            &wxc_common::policy_identity::redact_identity(identity),
            pid,
            wxc_common::telemetry::ProcessEventData::ExitCode(exit_code),
        );
        if let Some(logger) = logger.as_mut() {
            let record = AuditEvent::new(AuditEventName::ProcessExited)
                .str("backend", "isolation_session")
                .str(
                    "identity",
                    &wxc_common::policy_identity::redact_identity(identity),
                )
                .u64("pid", pid as u64)
                .i64("exit_code", exit_code as i64);
            logger.log_audit_event(&record);
        }
        return Ok(exit_code);
    }

    wxc_common::telemetry::log_process_event(
        wxc_common::telemetry::ProcessEventKind::TimedOut,
        &wxc_common::policy_identity::redact_identity(identity),
        pid,
        wxc_common::telemetry::ProcessEventData::TimeoutMs(timeout_ms as u64),
    );
    if let Some(logger) = logger.as_mut() {
        let record = AuditEvent::new(AuditEventName::ProcessTimedOut)
            .str("backend", "isolation_session")
            .str(
                "identity",
                &wxc_common::policy_identity::redact_identity(identity),
            )
            .u64("pid", pid as u64)
            .u64("timeout_ms", timeout_ms as u64);
        logger.log_audit_event(&record);
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

    if let Err(error) = process.Terminate() {
        wxc_common::telemetry::log_process_event(
            wxc_common::telemetry::ProcessEventKind::KillFailed,
            &wxc_common::policy_identity::redact_identity(identity),
            pid,
            wxc_common::telemetry::ProcessEventData::KillFailure("terminate_process"),
        );
        if let Some(logger) = logger.as_mut() {
            let record = AuditEvent::new(AuditEventName::ProcessKillFailed)
                .str("backend", "isolation_session")
                .str(
                    "identity",
                    &wxc_common::policy_identity::redact_identity(identity),
                )
                .u64("pid", pid as u64)
                .str("kill_method", KillMethod::TerminateProcess.as_str())
                .i64("error_code", error.code().0 as i64);
            logger.log_audit_event(&record);
        }
    }
    let _ = process.WaitForExit(0);
    Ok(process.ExitCode().unwrap_or(-1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M-ETW-5 acceptance: "a cleanup failure is distinguishable from success".
    /// `TeardownOutcome::status` is the function that makes that call for this
    /// backend, so each arm is pinned here.
    #[test]
    fn teardown_status_distinguishes_failure_success_and_skipped() {
        // Nothing attempted — reporting `success` here would claim a cleanup
        // that never ran.
        assert_eq!(TeardownOutcome::default().status(), TeardownStatus::Skipped);

        // Every attempted step succeeded.
        assert_eq!(
            TeardownOutcome {
                session_stopped: Some(true),
                agent_user_deprovisioned: Some(true),
            }
            .status(),
            TeardownStatus::Success
        );

        // A partial pass that succeeded as far as it went is still a success —
        // the per-step fields carry which steps ran.
        assert_eq!(
            TeardownOutcome {
                session_stopped: Some(true),
                ..Default::default()
            }
            .status(),
            TeardownStatus::Success
        );

        // Any failed step poisons the whole record, even when other steps
        // succeeded, so a failure can never be read as a clean teardown.
        for outcome in [
            TeardownOutcome {
                session_stopped: Some(false),
                ..Default::default()
            },
            TeardownOutcome {
                session_stopped: Some(true),
                agent_user_deprovisioned: Some(false),
            },
        ] {
            assert_eq!(
                outcome.status(),
                TeardownStatus::Failure,
                "a failed step must not report success: {outcome:?}"
            );
        }
    }

    /// The emitted record must satisfy the M-ETW-5 field contract, which is
    /// enforced for every backend by `AuditEvent::missing_required_fields`.
    #[test]
    fn teardown_record_satisfies_the_requirement_contract() {
        let outcome = TeardownOutcome {
            session_stopped: Some(true),
            agent_user_deprovisioned: Some(false),
        };
        let event = AuditEvent::new(AuditEventName::SandboxTornDown)
            .str("backend", "isolationsession")
            .str("identity", "iso:0123456789abcdef")
            .str("phase", "deprovision")
            .str("status", outcome.status().as_str())
            .bool("agent_user_deprovisioned", false);
        assert!(
            event.missing_required_fields().is_empty(),
            "missing {:?}",
            event.missing_required_fields()
        );
        let line = event.to_json_line();
        assert!(line.contains(r#""status":"failure""#), "got: {line}");
    }

    /// M-ETW-6 fallback coverage: IsolationSession uses the shared local audit
    /// sink when no usable ETW provider exists for the API.
    #[test]
    fn isolation_session_teardown_is_emitted_to_the_local_audit_sink() {
        let path = std::env::temp_dir().join(format!(
            "mxc-isolation-session-audit-{}.log",
            std::process::id()
        ));
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        logger.enable_file_sink(&path).expect("file sink");

        log_sandbox_torn_down(
            &mut logger,
            "iso:0123456789abcdef",
            "stop",
            TeardownOutcome {
                session_stopped: Some(true),
                agent_user_deprovisioned: None,
            },
        );
        drop(logger);

        let contents = std::fs::read_to_string(&path).expect("read audit log");
        assert!(contents.contains(r#""event":"mxc.SandboxTornDown""#));
        assert!(contents.contains(r#""backend":"isolation_session""#));
        assert!(contents.contains(r#""phase":"stop""#));
        assert!(!contents.contains(r#""container_released""#));
        let _ = std::fs::remove_file(path);
    }

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
            Err(IsolationSessionError::ServiceUnavailable(failure)) => {
                // Service is NOT available. Verify the error is clean and
                // descriptive (not a panic or cryptic COM error), and that
                // it names the activation operation it failed on.
                assert!(
                    failure.message.contains("not available")
                        || failure.message.contains("activation failed"),
                    "Expected descriptive error message, got: {}",
                    failure.message
                );
                assert_eq!(failure.operation, op::ACTIVATE);
                assert!(
                    failure.code.is_some(),
                    "activation failure carries no HRESULT"
                );
            }
            Err(other) => {
                panic!("expected ServiceUnavailable variant, got: {:?}", other);
            }
        }
    }
}
