// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `IsolationSessionManager` — granular wrapper over the in-proc
//! isolation session lifecycle. Each method maps 1:1 to a single WinRT op.
//! `create_process` also drives the ConPTY relay setup + shutdown ladder
//! against the local console.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::mxc_common::audit::{AuditEvent, AuditEventName, TeardownStatus};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::process_util::{OwnedHandle, PipeReadCanceller};
use crate::mxc_common::sandbox_process::StreamCloser;
use crate::mxc_common::state_aware_backend::{ExecHandle, ExecOutcome};

use crate::isolation_session_bindings::bindings::{
    IsoSessionFeature, IsoSessionOps, IsoSessionProcess, IsoSessionProcessResult,
    IsoSessionUserResult,
};
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_CHAR};
use windows::Win32::System::Com::{CoDecrementMTAUsage, CoIncrementMTAUsage, CO_MTA_USAGE_COOKIE};
use windows::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, CONSOLE_MODE, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject};
use windows::UI::WindowId;
use windows_core::{HSTRING, PCWSTR};

use super::console_mode::{get_local_console_size, ConsoleModeRestorer, CtrlHandlerGuard};
use super::console_relay::{create_console_relay_thread, ConsoleRelayParams};
use super::error::{
    activation_error, check_result, format_iso_error, lifecycle_err, op, transport_err,
    IsolationSessionError, StalePromotion,
};
use super::owned_thread::{self, Impersonation};
use super::pipe_relay::{
    create_relay_thread, create_relay_thread_with_stdin_closer, create_relay_thread_with_stop,
    drain_output_relays_within, duplicate_handle, OutputRelayDrain, PipeRelay,
    PipeRelayWithStopParams, StdinCloser,
};
use super::process::{ClosingProcess, StartedProcess};
use super::process_options::{
    build_iso_process_options, with_service_timeout_grace, ProcessOptions,
};

// The OS account name is lifecycle addressing data, not diagnostic identity.
const AGENT_IDENTITY_MARKER: &str = "isolation-session-agent";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StdinHandleKind {
    Console,
    PipeOrFile,
}

fn classify_stdin_handle(handle: HANDLE) -> StdinHandleKind {
    let file_type = unsafe { GetFileType(handle) };
    if file_type == FILE_TYPE_CHAR {
        let mut mode = CONSOLE_MODE(0);
        if unsafe { GetConsoleMode(handle, &mut mode) }.is_ok() {
            return StdinHandleKind::Console;
        }
    }
    StdinHandleKind::PipeOrFile
}

fn stdin_closer_with_diagnostics(
    callback: impl FnOnce() -> Result<(), IsolationSessionError> + Send + 'static,
    mut diagnostics: Logger,
) -> StdinCloser {
    Box::new(move || match catch_unwind(AssertUnwindSafe(callback)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            diagnostics.log_diagnostic_line(&format!("Closing stdin at EOF failed: {error}"))
        }
        Err(_) => diagnostics.log_diagnostic_line("Closing stdin at EOF panicked"),
    })
}

/// # Safety
/// Handles must be valid during setup. Console input is borrowed and must
/// remain valid until the relay exits; the other handles are duplicated.
unsafe fn create_stdin_relay(
    stdin: HANDLE,
    destination: HANDLE,
    stop_event: HANDLE,
    interactive: bool,
    stdin_closer: Option<StdinCloser>,
    resize_callback: impl Fn(u16, u16) + Send + 'static,
) -> Result<(OwnedHandle, Option<PipeReadCanceller>), IsolationSessionError> {
    // Choose the relay from stdin itself; `interactive` describes stdout.
    if classify_stdin_handle(stdin) == StdinHandleKind::PipeOrFile {
        let stdin_closer = if !interactive { stdin_closer } else { None };
        let (thread, canceller) =
            unsafe { create_relay_thread_with_stdin_closer(stdin, destination, stdin_closer) }
                .map_err(|e| lifecycle_err(format!("create stdin relay: {e}")))?
                .into_thread_and_canceller();
        return Ok((thread, Some(canceller)));
    }

    // process.Close() can release the original while the relay is still writing.
    let h_write = duplicate_handle(destination)
        .map_err(|e| lifecycle_err(format!("duplicate stdin handle: {e}")))?;
    let h_stop_event = duplicate_handle(stop_event)
        .map_err(|e| lifecycle_err(format!("duplicate stdin stop event: {e}")))?;
    let thread = if interactive {
        unsafe {
            create_console_relay_thread(ConsoleRelayParams {
                h_read: stdin,
                h_write,
                h_stop_event,
                resize_callback: Box::new(resize_callback),
            })
        }
        .map_err(|e| lifecycle_err(format!("create console-aware stdin relay: {e}")))?
    } else {
        unsafe {
            create_relay_thread_with_stop(PipeRelayWithStopParams {
                h_read: stdin,
                h_write,
                h_stop_event,
            })
        }
        .map_err(|e| lifecycle_err(format!("create stdin relay: {e}")))?
    };
    Ok((thread, None))
}

/// Keeps the process's MTA alive for as long as the lifecycle's WinRT objects,
/// which outlive the call that created them.
/// `CoIncrementMTAUsage` holds a reference releasable from any thread;
/// `CoUninitialize` is thread-affine and would tear the apartment down under a
/// live object.
pub(super) struct MtaReference {
    cookie: CO_MTA_USAGE_COOKIE,
}

impl MtaReference {
    pub(super) fn acquire() -> Result<Self, IsolationSessionError> {
        // SAFETY: the out-parameter is a valid, writable local.
        let cookie = unsafe { CoIncrementMTAUsage() }.map_err(|e| {
            transport_err(
                op::CO_INCREMENT_MTA_USAGE,
                "could not keep a multi-threaded apartment alive",
                &e,
            )
        })?;
        Ok(Self { cookie })
    }
}

impl Drop for MtaReference {
    fn drop(&mut self) {
        // SAFETY: balances the `CoIncrementMTAUsage` in `acquire`. The cookie is
        // not thread-affine, so this is sound on whichever thread drops it.
        unsafe {
            let _ = CoDecrementMTAUsage(self.cookie);
        }
    }
}

// SAFETY: the cookie is an opaque token, never dereferenced, and
// `CoDecrementMTAUsage` accepts it from any thread.
unsafe impl Send for MtaReference {}
unsafe impl Sync for MtaReference {}

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

/// `GetFeatureLevel` fails on a host that does not recognize the feature
/// value, so an error reads as not supported.
fn feature_supported_from(level: windows_core::Result<i32>) -> bool {
    matches!(level, Ok(level) if level > 0)
}

const ZERO_WINDOW_ID: WindowId = WindowId { Value: 0 };

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
    /// The impersonation of the thread that created this manager: every call
    /// the manager makes, and every call for a process it starts, is made
    /// under it.
    impersonation: Impersonation,
    /// Declared after `ops` so it drops last: the apartment outlives every
    /// object activated in it.
    _mta: MtaReference,
}

impl IsolationSessionManager {
    /// Start an interactive process whose ConPTY handles remain caller-driven.
    pub(super) fn pty_process(
        &self,
        options: &ProcessOptions,
        logger: Option<&Logger>,
    ) -> Result<Arc<ClosingProcess>, IsolationSessionError> {
        owned_thread::call(&self.impersonation, || {
            let mta = MtaReference::acquire()?;
            Ok(Arc::new(ClosingProcess::new(
                self.start_process(options, logger)?,
                self.impersonation.clone(),
                mta,
            )))
        })
    }

    /// Pegs a manager to an existing OS-assigned agent user name (the value
    /// returned by `add_user`). Activates the service factory once and
    /// reuses it for the manager's lifetime.
    pub(super) fn new(agent_user_name: &str) -> Result<Self, IsolationSessionError> {
        let impersonation = Impersonation::of_this_thread()?;
        owned_thread::call(&impersonation, || {
            let mta = MtaReference::acquire()?;
            let ops = check_service_available_and_activate()?;
            Ok(Self {
                agent_user_name: HSTRING::from(agent_user_name),
                ops,
                impersonation: impersonation.clone(),
                _mta: mta,
            })
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
    /// Note: the in-proc API exposes no session-lifetime knob, so `lifecycle`
    /// cannot be honored here. Unsupported values are refused by the calling
    /// surface rather than ignored — one-shot rejects `destroyOnExit: false`
    /// and `preservePolicy: true` in `validate_runner`, and the state-aware
    /// parser rejects the whole `lifecycle` section.
    pub(super) fn add_user(
        app_id: Option<&str>,
    ) -> Result<(ProvisionedUser, Self), IsolationSessionError> {
        let impersonation = Impersonation::of_this_thread()?;
        owned_thread::call(&impersonation, || {
            let mta = MtaReference::acquire()?;
            let ops = check_service_available_and_activate()?;
            // Prefer the newest overload the host advertises.
            let (op_add_user, started) = if feature_supported_from(
                ops.GetFeatureLevel(IsoSessionFeature::DeducedEnterpriseAgentUser),
            ) {
                (
                    op::ADD_USER_DEDUCED,
                    ops.AddUserAsync3(&HSTRING::from(app_id.unwrap_or_default()), ZERO_WINDOW_ID),
                )
            } else if feature_supported_from(
                ops.GetFeatureLevel(IsoSessionFeature::AppScopedRegistration),
            ) {
                (
                    op::ADD_USER,
                    ops.AddUserAsync2(
                        &HSTRING::from(app_id.unwrap_or_default()),
                        &HSTRING::new(),
                        &HSTRING::new(),
                    ),
                )
            } else {
                (
                    op::ADD_USER_LEGACY,
                    ops.AddUserAsync(&HSTRING::new(), &HSTRING::new()),
                )
            };
            let user_result: IsoSessionUserResult = owned_thread::wait_for(op_add_user, started)?;

            let err = user_result
                .Error()
                .map_err(|e| transport_err(op_add_user, "get Error failed", &e))?;
            let is_error = err
                .IsError()
                .map_err(|e| transport_err(op_add_user, "get IsError failed", &e))?;
            if is_error {
                // Provision mints the agent user, so `ERROR_NOT_FOUND` here can
                // never mean "the sandbox is gone" — there is no sandbox id yet.
                return Err(format_iso_error(
                    op_add_user,
                    &err,
                    StalePromotion::NotEligible,
                ));
            }

            let agent_user_name = user_result
                .AgentUserName()
                .map_err(|e| transport_err(op_add_user, "get AgentUserName failed", &e))?;

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
                impersonation: impersonation.clone(),
                _mta: mta,
            };

            let provisioned =
                match Self::read_remaining_facts(&user_result, &agent_user_name, op_add_user) {
                    Ok(provisioned) => provisioned,
                    Err(e) => {
                        // Best-effort: returning here without this would abandon an
                        // account we are still able to remove.
                        let _ = manager.deprovision_agent_user();
                        return Err(e);
                    }
                };

            Ok((provisioned, manager))
        })
    }

    /// Reads the provision-time facts that remain after the agent user name.
    ///
    /// Split out of [`Self::add_user`] so that a failure in any of them lands
    /// on one error path, where the freshly created account can be removed
    /// instead of orphaned. `op_add_user` is the operation label of the
    /// provisioning overload actually invoked, so these getters' failures are
    /// attributed to the same API call in telemetry.
    fn read_remaining_facts(
        user_result: &IsoSessionUserResult,
        agent_user_name: &HSTRING,
        op_add_user: &'static str,
    ) -> Result<ProvisionedUser, IsolationSessionError> {
        let agent_user_sid = user_result
            .AgentUserSid()
            .map_err(|e| transport_err(op_add_user, "get AgentUserSid failed", &e))?;
        let ephemeral_workspace_path = user_result
            .EphemeralWorkspacePath()
            .map_err(|e| transport_err(op_add_user, "get EphemeralWorkspacePath failed", &e))?;

        Ok(ProvisionedUser {
            agent_user_name: agent_user_name.to_string(),
            agent_user_sid: agent_user_sid.to_string(),
            ephemeral_workspace_path: ephemeral_workspace_path.to_string(),
        })
    }

    /// Step 2: Start the isolation session for the pegged agent user.
    pub(super) fn start_session(&self) -> Result<(), IsolationSessionError> {
        owned_thread::call(&self.impersonation, || {
            // Prefer the newest overload the host advertises.
            let (op_start_session, started) = if feature_supported_from(
                self.ops
                    .GetFeatureLevel(IsoSessionFeature::DeducedEnterpriseAgentUser),
            ) {
                (
                    op::START_SESSION_DEDUCED,
                    self.ops
                        .StartSessionAsync2(&self.agent_user_name, ZERO_WINDOW_ID),
                )
            } else {
                (
                    op::START_SESSION,
                    self.ops
                        .StartSessionAsync(&self.agent_user_name, &HSTRING::new()),
                )
            };
            let result = owned_thread::wait_for(op_start_session, started)?;
            check_result(&result, op_start_session, StalePromotion::Eligible)
        })
    }

    /// Step 3a: Start a process inside the started isolation session, and
    /// return it **without waiting**.
    ///
    /// Split out of [`Self::create_process`] so the caller chooses how the
    /// streams are consumed: the relayed path bridges them with its own relay
    /// threads and blocks (see `create_process`), while an in-process SDK
    /// caller takes the raw handles and drives them itself.
    fn start_process(
        &self,
        options: &ProcessOptions,
        logger: Option<&Logger>,
    ) -> Result<StartedProcess, IsolationSessionError> {
        let proc_options = build_iso_process_options(options)?;

        let result: IsoSessionProcessResult = owned_thread::wait_for(
            op::RUN_PROCESS,
            self.ops.RunProcessWithOptionsAsync(
                &self.agent_user_name,
                &HSTRING::from(&options.process_path),
                &HSTRING::from(&options.arguments),
                &proc_options,
            ),
        )?;

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

        StartedProcess::new(process, AGENT_IDENTITY_MARKER, logger)
    }

    /// Step 3: Create a process inside the started isolation session and run it
    /// to completion. Output is streamed live to the calling process's stdio via
    /// internal relay threads; only the exit code or timeout is returned.
    ///
    /// `options.timeout_ms` is enforced locally; the service-side timer is armed
    /// with [`with_service_timeout_grace`] so a timeout is never reported as an
    /// ordinary exit.
    ///
    /// This is the **relay** path, reached by `wxc-exec` and by an in-process
    /// caller that asked to attach. A caller that wants the streams handed back
    /// uses [`Self::piped_exec_handle`] instead.
    ///
    /// [`with_service_timeout_grace`]: super::process_options::with_service_timeout_grace
    pub(super) fn create_process(
        &self,
        options: &ProcessOptions,
        logger: Option<&mut Logger>,
    ) -> Result<ExecOutcome, IsolationSessionError> {
        owned_thread::call(&self.impersonation, || {
            // Everything fallible that does not need the workload runs first, so no
            // failure can strand a running one.
            let wxc_stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }
                .map_err(|e| lifecycle_err(format!("GetStdHandle(stdout) failed: {}", e)))?;
            let wxc_stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) }
                .map_err(|e| lifecycle_err(format!("GetStdHandle(stderr) failed: {}", e)))?;
            let wxc_stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) }
                .map_err(|e| lifecycle_err(format!("GetStdHandle(stdin) failed: {}", e)))?;

            // Manual-reset stop event for console-backed stdin relays.
            let stdin_stop_event = unsafe {
                CreateEventW(None, true, false, PCWSTR::null())
                    .map_err(|e| lifecycle_err(format!("CreateEventW(stdin stop): {}", e)))?
            };
            // Declared before `scope`, which holds a raw copy: it must drop last.
            let stdin_stop_owned = OwnedHandle::new(stdin_stop_event);

            // Relay threads bridge the calling process's stdio to
            // `IsoSessionProcess`'s pipes: console-handle inheritance cannot cross
            // the desktop-session boundary.
            //
            // Handle ownership across four sources:
            //   - Pipe handles owned by `IsoSessionProcess` (`OutputHandle()` /
            //     `ErrorHandle()` / `InputHandle()`, returned as u64): released
            //     by `process.Close()`. We do NOT close them. The output relays
            //     read their own duplicates, so `Close()` does not disturb them.
            //   - The calling process's std handles (`GetStdHandle`): OS-owned.
            //     We do NOT close them.
            //   - Stop event for stdin relay (`CreateEventW`): RAII-closed via
            //     `OwnedHandle`.
            //   - Relay thread handles: RAII-closed via `OwnedHandle` after we
            //     `WaitForSingleObject` on each.
            //
            // Lifetime: each relay's param struct is moved to the heap and owned
            // by its thread, which frees it on exit, so joining is not required
            // for memory safety.
            let service_options = with_service_timeout_grace(options.clone());
            let started = self.start_process(&service_options, logger.as_deref())?;
            let process = &started.process;
            let stdout_handle_val = started.stdout;
            let stderr_handle_val = started.stderr;
            let stdin_handle_val = started.stdin;

            let mut scope = RelayScope::new(&started, stdin_stop_owned.get());

            // In interactive mode, switch the calling process's console to raw VT
            // so only the agent's ConPTY echoes and renders; otherwise both do.
            // RAII-restored on scope exit. No-op when stdio is not a console.
            let _console_guard = if options.interactive {
                Some(ConsoleModeRestorer::install_raw_vt())
            } else {
                None
            };

            // Install a console Ctrl handler that signals `stdin_stop_owned`
            // on Ctrl-C or terminal-close events, so the relay loops drain
            // cleanly instead of being terminated by the OS default
            // `ExitProcess`. Interactive mode only — non-interactive mode
            // wants the default behavior so the parent can terminate
            // wxc-exec via Ctrl-C. Installed after the workload starts: the
            // event is manual-reset and never cleared, so an earlier Ctrl-C
            // would stop the stdin relay for the session's lifetime.
            let _ctrl_guard = if options.interactive {
                Some(CtrlHandlerGuard::install(stdin_stop_owned.get()))
            } else {
                None
            };

            // Push the local console's viewport size into the agent's inner ConPTY.
            // Without it the inner HPCON keeps its default dimensions and VT-aware
            // agents (e.g. PSReadLine) anchor their prompt to that smaller last row,
            // overlaying text once they reach it. Mid-session resize is not handled
            // here.
            if options.interactive {
                if let Some((cols, rows)) = get_local_console_size() {
                    let _ = process.ResizeConsole(cols, rows);
                }
            }

            scope.stdout = if stdout_handle_val != 0 {
                Some(
                    unsafe {
                        create_relay_thread(
                            HANDLE(stdout_handle_val as *mut core::ffi::c_void),
                            wxc_stdout,
                        )
                    }
                    .map_err(|e| lifecycle_err(format!("create stdout relay: {}", e)))?,
                )
            } else {
                None
            };
            scope.stderr = if stderr_handle_val != 0 {
                Some(
                    unsafe {
                        create_relay_thread(
                            HANDLE(stderr_handle_val as *mut core::ffi::c_void),
                            wxc_stderr,
                        )
                    }
                    .map_err(|e| lifecycle_err(format!("create stderr relay: {}", e)))?,
                )
            } else {
                None
            };
            if stdin_handle_val != 0 {
                // Callback used to close stdin on end of input.
                let stdin_closer = {
                    let process = process.clone();
                    let impersonation = self.impersonation.clone();
                    let close_lock = Arc::clone(&started.close_lock);
                    stdin_closer_with_diagnostics(
                        move || {
                            owned_thread::call(&impersonation, || {
                                let _close =
                                    close_lock.lock().unwrap_or_else(PoisonError::into_inner);
                                process.CloseStandardInput().map_err(|error| {
                                    transport_err(
                                        op::RUN_PROCESS,
                                        "CloseStandardInput failed",
                                        &error,
                                    )
                                })
                            })
                        },
                        logger
                            .as_deref()
                            .map(Logger::clone_diagnostic_sink)
                            .unwrap_or_else(Logger::inherit_thread_diagnostic_sink),
                    )
                };

                // The console relay needs its own process reference for resize calls.
                let process_for_resize = process.clone();
                let impersonation = self.impersonation.clone();
                // SAFETY: process and standard handles outlive relay setup;
                // the host's console input remains valid during execution.
                let (thread, canceller) = unsafe {
                    create_stdin_relay(
                        wxc_stdin,
                        HANDLE(stdin_handle_val as *mut core::ffi::c_void),
                        stdin_stop_owned.get(),
                        options.interactive,
                        Some(stdin_closer),
                        move |cols, rows| {
                            let _ = owned_thread::call(&impersonation, || {
                                let _ = process_for_resize.ResizeConsole(cols, rows);
                                Ok(())
                            });
                        },
                    )
                }?;
                scope.stdin = Some(thread);
                scope.stdin_canceller = canceller;
            }

            let outcome = started.wait(options.timeout_ms, || scope.stop_stdin())?;
            scope.finish()?;

            Ok(outcome)
        })
    }

    /// Start a process and hand back its live pipes as an [`ExecHandle`].
    ///
    /// Shared by the state-aware `Piped` exec and the one-shot streaming
    /// backend.
    ///
    /// `timeout_ms` is the caller's deadline, enforced by the waiter. Arm the
    /// service-side timer with [`with_service_timeout_grace`] before calling:
    /// without that margin the two deadlines coincide, and a timeout can arrive
    /// as an ordinary exit.
    ///
    /// [`with_service_timeout_grace`]: super::process_options::with_service_timeout_grace
    pub(super) fn piped_exec_handle(
        &self,
        options: &ProcessOptions,
        timeout_ms: u32,
        logger: Option<&Logger>,
    ) -> Result<ExecHandle, IsolationSessionError> {
        let started = owned_thread::call(&self.impersonation, || {
            // Acquired before the workload starts, so a failure here cannot
            // leave one running with no handle to reach it.
            let mta = MtaReference::acquire()?;
            Ok(Arc::new(ClosingProcess::new(
                self.start_process(options, logger)?,
                self.impersonation.clone(),
                mta,
            )))
        })?;

        // Read the handles before the closures take ownership. A zero means the
        // stream is genuinely absent, which is exactly the sentinel the
        // consumer already treats as "no stream".
        let stdout = HANDLE(started.stdout as *mut std::ffi::c_void);
        let stderr = HANDLE(started.stderr as *mut std::ffi::c_void);
        let stdin = HANDLE(started.stdin as *mut std::ffi::c_void);

        // `IsoSessionProcess` answers `IAgileObject`, so the closures may hold it
        // on whatever thread runs them; the calls they make go through
        // `owned_thread`.
        let waiter_process = Arc::clone(&started);
        let stdin_process = Arc::clone(&started);
        Ok(ExecHandle {
            stdout,
            stderr,
            stdin,
            stdin_closer: Some(Box::new(move || {
                let _ = stdin_process.close_standard_input();
            })),
            // Reports `TimedOut` when the deadline elapsed with the process
            // still running — see `StartedProcess::wait`, which samples that
            // before the shutdown ladder destroys the evidence.
            waiter: Box::new(move || {
                waiter_process
                    .wait_for_exit(timeout_ms)
                    .map_err(super::error::map_lifecycle_error)
            }),
            // Reports whether the platform *accepted* the kill: `terminate`'s
            // bounded post-kill wait is not consulted, so a `Terminate` that
            // was accepted and then did not take effect still reports success.
            terminator: Box::new(move || {
                started
                    .terminate_process()
                    .map_err(super::error::map_lifecycle_error)
            }),
        })
    }

    /// Step 4: Stop the isolation session.
    pub(super) fn stop_session(&self) -> Result<(), IsolationSessionError> {
        owned_thread::call(&self.impersonation, || {
            let result = owned_thread::wait_for(
                op::STOP_SESSION,
                self.ops.StopSessionAsync(&self.agent_user_name),
            )?;
            check_result(&result, op::STOP_SESSION, StalePromotion::Eligible)
        })
    }

    /// Step 5: Deprovision the agent user.
    pub(super) fn deprovision_agent_user(&self) -> Result<(), IsolationSessionError> {
        owned_thread::call(&self.impersonation, || {
            let result = owned_thread::wait_for(
                op::REMOVE_USER,
                self.ops.RemoveUserAsync(&self.agent_user_name),
            )?;
            check_result(&result, op::REMOVE_USER, StalePromotion::Eligible)
        })
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TeardownOutcome {
    pub session_stopped: Option<bool>,
    pub agent_user_deprovisioned: Option<bool>,
}

impl TeardownOutcome {
    fn status(&self) -> TeardownStatus {
        let steps = [self.session_stopped, self.agent_user_deprovisioned];
        if steps.contains(&Some(false)) {
            TeardownStatus::Failure
        } else if steps.iter().all(Option::is_none) {
            TeardownStatus::Skipped
        } else {
            TeardownStatus::Success
        }
    }
}

pub fn log_sandbox_torn_down(logger: &mut Logger, phase: &str, outcome: TeardownOutcome) {
    if !logger.has_diagnostic_sink() && !crate::mxc_common::telemetry::is_active() {
        return;
    }
    crate::mxc_common::telemetry::log_sandbox_torn_down(
        AGENT_IDENTITY_MARKER,
        outcome.status().as_str(),
        &format!(
            "session_stopped={},agent_user_deprovisioned={}",
            outcome.session_stopped == Some(true),
            outcome.agent_user_deprovisioned == Some(true),
        ),
    );
    let record = AuditEvent::new(AuditEventName::SandboxTornDown)
        .str("backend", "isolation_session")
        .str("identity", AGENT_IDENTITY_MARKER)
        .str("phase", phase)
        .str("status", outcome.status().as_str())
        .bool("session_stopped", outcome.session_stopped == Some(true))
        .bool(
            "agent_user_deprovisioned",
            outcome.agent_user_deprovisioned == Some(true),
        );
    logger.log_audit_event(&record);
}

/// Owns the relay threads and the workload for the span of `create_process`.
///
/// [`finish`](Self::finish) tears down a workload that has already exited.
/// Dropping without it cancels output reads and terminates the workload.
/// Every join is bounded; cancellation does not interrupt destination writes.
struct RelayScope<'a> {
    process: &'a IsoSessionProcess,
    close_lock: &'a Mutex<()>,
    stop_event: HANDLE,
    stdout: Option<PipeRelay>,
    stderr: Option<PipeRelay>,
    stdin: Option<OwnedHandle>,
    /// Ends a pipe/file-backed stdin relay. Console stdin relays use the stop
    /// event instead because `CancelSynchronousIo` has console-handle edge
    /// cases.
    stdin_canceller: Option<PipeReadCanceller>,
    finished: bool,
}

impl<'a> RelayScope<'a> {
    const JOIN_MS: u32 = 1000;
    /// Stop waiting only after all output relays are idle for this long.
    const IDLE_MS: u64 = 5000;
    /// Overall cap so a pathological one-byte-forever trickle still returns.
    const ABSOLUTE_CAP_MS: u64 = 60_000;

    fn new(started: &'a StartedProcess, stop_event: HANDLE) -> Self {
        Self {
            process: &started.process,
            close_lock: &started.close_lock,
            stop_event,
            stdout: None,
            stderr: None,
            stdin: None,
            stdin_canceller: None,
            finished: false,
        }
    }

    fn signal_stop(&self) {
        // SAFETY: the event outlives this scope.
        unsafe {
            let _ = SetEvent(self.stop_event);
        }
    }

    fn cancel_stdin_read(&self) {
        if let Some(canceller) = &self.stdin_canceller {
            canceller.close();
        }
    }

    /// Whether the relay exited. An absent relay was never spawned.
    fn join(relay: Option<&OwnedHandle>, timeout_ms: u32) -> bool {
        wait_for_relay(relay, timeout_ms).unwrap_or(false)
    }

    fn join_output(relay: &Option<PipeRelay>, timeout_ms: u32) -> bool {
        Self::join(relay.as_ref().map(PipeRelay::thread), timeout_ms)
    }

    fn output_relays(&self) -> Vec<&PipeRelay> {
        [&self.stdout, &self.stderr]
            .into_iter()
            .filter_map(Option::as_ref)
            .collect()
    }

    /// Release the process's handles. Surviving relays own their duplicates
    /// independently.
    fn close_handles(&self) {
        let _close = self
            .close_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let _ = self.process.Close();
    }

    fn stop_stdin(&mut self) -> Result<bool, IsolationSessionError> {
        self.signal_stop();
        self.cancel_stdin_read();
        let exited = wait_for_relay(self.stdin.as_ref(), Self::JOIN_MS)?;
        if exited {
            self.stdin = None;
            self.stdin_canceller = None;
        }
        Ok(exited)
    }

    /// Teardown for a workload that has already exited.
    fn finish(&mut self) -> Result<(), IsolationSessionError> {
        self.signal_stop();
        self.cancel_stdin_read();
        let output_relays = self.output_relays();
        let output_drain = drain_output_relays_within(
            &output_relays,
            Duration::from_millis(Self::IDLE_MS),
            Duration::from_millis(Self::ABSOLUTE_CAP_MS),
        )
        .map_err(|error| lifecycle_err(format!("drain output relays: {error}")))?;
        if output_drain == OutputRelayDrain::GaveUp {
            Self::join_output(&self.stdout, Self::JOIN_MS);
            Self::join_output(&self.stderr, Self::JOIN_MS);
        }
        Self::join(self.stdin.as_ref(), Self::JOIN_MS);
        self.close_handles();
        self.finished = true;
        Ok(())
    }
}

impl Drop for RelayScope<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.signal_stop();
        self.cancel_stdin_read();
        for relay in self.output_relays() {
            relay.cancel_read();
        }
        let _ = self.process.Terminate();
        Self::join_output(&self.stdout, Self::JOIN_MS);
        Self::join_output(&self.stderr, Self::JOIN_MS);
        Self::join(self.stdin.as_ref(), Self::JOIN_MS);
        self.close_handles();
    }
}

fn wait_for_relay(
    relay: Option<&OwnedHandle>,
    timeout_ms: u32,
) -> Result<bool, IsolationSessionError> {
    let Some(relay) = relay else {
        return Ok(true);
    };
    // SAFETY: the relay's owned thread handle remains valid throughout the wait.
    match unsafe { WaitForSingleObject(relay.get(), timeout_ms) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(lifecycle_err(format!(
            "waiting for relay failed: {}",
            std::io::Error::last_os_error()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::logger::Mode;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counting_stdin_closer(calls: Arc<AtomicUsize>) -> StdinCloser {
        Box::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
        })
    }

    #[test]
    fn stdin_closer_reports_errors_and_panics() {
        for panic in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("stdin.log");
            let mut logger = Logger::new(Mode::Buffer);
            logger.enable_file_sink(&path).unwrap();
            let closer = stdin_closer_with_diagnostics(
                move || {
                    if panic {
                        panic!("injected stdin close panic");
                    }
                    Err(lifecycle_err("injected stdin close error"))
                },
                logger,
            );
            closer();
            let logged = std::fs::read_to_string(path).unwrap();
            assert_eq!(logged.lines().count(), 1, "{logged}");
            assert!(
                logged.contains(if panic {
                    "Closing stdin at EOF panicked"
                } else {
                    "Closing stdin at EOF failed:"
                }),
                "{logged}"
            );
            if !panic {
                assert!(logged.contains("injected stdin close error"), "{logged}");
            }
        }
    }

    fn read_stdin_test_payload(handle: HANDLE, size: usize) -> Vec<u8> {
        use std::time::{Duration, Instant};
        use windows::Win32::Storage::FileSystem::ReadFile;
        use windows::Win32::System::Pipes::PeekNamedPipe;

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut available = 0;
            unsafe { PeekNamedPipe(handle, None, 0, None, Some(&mut available), None) }
                .expect("destination pipe should remain readable");
            if available as usize >= size {
                let mut payload = vec![0; size];
                let mut read = 0;
                unsafe { ReadFile(handle, Some(&mut payload), Some(&mut read), None) }.unwrap();
                payload.truncate(read as usize);
                return payload;
            }
            assert!(
                Instant::now() < deadline,
                "selected stdin relay did not deliver the payload"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn stdin_routing_delivers_pipe_input_and_releases_writer_for_both_output_modes() {
        use crate::mxc_common::process_util::{create_local_pipe, PipeWriter};
        use std::io::Write;
        use windows::Win32::Foundation::ERROR_BROKEN_PIPE;
        use windows::Win32::System::Pipes::PeekNamedPipe;

        for (interactive, cancel) in [(true, true), (true, false), (false, true), (false, false)] {
            let (source_read, source_write) = create_local_pipe().unwrap();
            let mut source_write = PipeWriter::new(source_write);
            let (dest_read, dest_write) = create_local_pipe().unwrap();
            let stop = OwnedHandle::new(unsafe {
                CreateEventW(None, true, false, PCWSTR::null()).unwrap()
            });
            let calls = Arc::new(AtomicUsize::new(0));
            // SAFETY: all handles remain valid until the relay has exited.
            let (relay, canceller) = unsafe {
                create_stdin_relay(
                    source_read.get(),
                    dest_write.get(),
                    stop.get(),
                    interactive,
                    Some(counting_stdin_closer(Arc::clone(&calls))),
                    |_, _| panic!("pipe input must not handle console resize"),
                )
            }
            .unwrap();

            let payload = b"stdin payload\r\n";
            source_write.write_all(payload).unwrap();
            let received = read_stdin_test_payload(dest_read.get(), payload.len());
            assert!(!wait_for_relay(Some(&relay), 0).unwrap());
            if cancel {
                canceller
                    .expect("pipe input must have a read canceller")
                    .close();
            } else {
                drop(source_write);
            }
            assert!(wait_for_relay(Some(&relay), 5000).unwrap());
            assert_eq!(received, payload);

            assert_eq!(
                calls.load(Ordering::SeqCst),
                if !interactive && !cancel { 1 } else { 0 }
            );
            drop(dest_write);
            let error = unsafe { PeekNamedPipe(dest_read.get(), None, 0, None, None, None) }
                .expect_err("the selected relay must release its write duplicate");
            assert_eq!(error.code(), ERROR_BROKEN_PIPE.to_hresult());
        }
    }

    #[test]
    fn stdin_routing_delivers_file_input_for_both_output_modes() {
        use crate::mxc_common::process_util::create_local_pipe;
        use std::io::{Seek, Write};
        use std::os::windows::io::AsRawHandle;

        for interactive in [true, false] {
            let mut input = tempfile::tempfile().unwrap();
            let payload = b"file input\r\n";
            input.write_all(payload).unwrap();
            input.rewind().unwrap();
            let (dest_read, dest_write) = create_local_pipe().unwrap();
            let stop = OwnedHandle::new(unsafe {
                CreateEventW(None, true, false, PCWSTR::null()).unwrap()
            });
            let calls = Arc::new(AtomicUsize::new(0));
            // SAFETY: all handles remain valid until the relay has exited.
            let (relay, canceller) = unsafe {
                create_stdin_relay(
                    HANDLE(input.as_raw_handle()),
                    dest_write.get(),
                    stop.get(),
                    interactive,
                    Some(counting_stdin_closer(Arc::clone(&calls))),
                    |_, _| panic!("file input must not handle console resize"),
                )
            }
            .unwrap();
            let received = read_stdin_test_payload(dest_read.get(), payload.len());
            assert!(wait_for_relay(Some(&relay), 5000).unwrap());
            assert!(
                canceller.is_some(),
                "file input must select the cancellable relay"
            );
            assert_eq!(received, payload);
            assert_eq!(
                calls.load(Ordering::SeqCst),
                if interactive { 0 } else { 1 }
            );
        }
    }

    #[test]
    fn stdin_routing_console_uses_stop_event_for_both_output_modes() {
        use crate::mxc_common::process_util::create_local_pipe;
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };
        use windows::Win32::System::Threading::CREATE_NEW_CONSOLE;

        const CHILD: &str = "MXC_STDIN_ROUTING_CONSOLE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            // Restart this test with a real console; the runner may have none.
            let test_name = "backend_modules::isolation_session::common::manager::tests::\
                stdin_routing_console_uses_stop_event_for_both_output_modes";
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test_name])
                .env(CHILD, "1")
                .creation_flags(CREATE_NEW_CONSOLE.0)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            while child.try_wait().unwrap().is_none() {
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    let output = child.wait_with_output().unwrap();
                    panic!("console routing child timed out: {output:?}");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "console routing child failed: {output:?}"
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }

        let console = OwnedHandle::new(unsafe {
            CreateFileW(
                windows_core::w!("CONIN$"),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            .unwrap()
        });
        assert_eq!(
            classify_stdin_handle(console.get()),
            StdinHandleKind::Console
        );
        for interactive in [true, false] {
            let (_dest_read, dest_write) = create_local_pipe().unwrap();
            let stop = OwnedHandle::new(unsafe {
                CreateEventW(None, true, false, PCWSTR::null()).unwrap()
            });
            let calls = Arc::new(AtomicUsize::new(0));
            // SAFETY: the private console and pipes outlive the relay.
            let (relay, canceller) = unsafe {
                create_stdin_relay(
                    console.get(),
                    dest_write.get(),
                    stop.get(),
                    interactive,
                    Some(counting_stdin_closer(Arc::clone(&calls))),
                    |_, _| {},
                )
            }
            .unwrap();
            assert!(canceller.is_none(), "console input must use the stop event");
            unsafe { SetEvent(stop.get()).unwrap() };
            assert!(wait_for_relay(Some(&relay), 5000).unwrap());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn stdin_shutdown_reports_wait_failure() {
        let invalid = OwnedHandle::new(HANDLE::default());
        let error = wait_for_relay(Some(&invalid), 0).unwrap_err();
        assert!(error.to_string().contains("waiting for relay failed"));
        assert!(wait_for_relay(None, 0).unwrap());
    }

    #[test]
    fn teardown_status_distinguishes_failure_success_and_skipped() {
        assert_eq!(TeardownOutcome::default().status(), TeardownStatus::Skipped);
        assert_eq!(
            TeardownOutcome {
                session_stopped: Some(true),
                agent_user_deprovisioned: Some(true),
            }
            .status(),
            TeardownStatus::Success
        );
        assert_eq!(
            TeardownOutcome {
                session_stopped: Some(true),
                ..Default::default()
            }
            .status(),
            TeardownStatus::Success
        );
        assert_eq!(
            TeardownOutcome {
                session_stopped: Some(true),
                agent_user_deprovisioned: Some(false),
            }
            .status(),
            TeardownStatus::Failure
        );
    }

    #[test]
    fn teardown_record_satisfies_the_requirement_contract() {
        let outcome = TeardownOutcome {
            session_stopped: Some(true),
            agent_user_deprovisioned: Some(false),
        };
        let event = AuditEvent::new(AuditEventName::SandboxTornDown)
            .str("backend", "isolation_session")
            .str("identity", AGENT_IDENTITY_MARKER)
            .str("phase", "deprovision")
            .str("status", outcome.status().as_str())
            .bool("agent_user_deprovisioned", false);
        assert!(event.missing_required_fields().is_empty());
        assert!(event.to_json_line().contains(r#""status":"failure""#));
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

    #[test]
    fn feature_support_requires_a_positive_feature_level() {
        // Supported: any positive level.
        assert!(feature_supported_from(Ok(1)));
        assert!(feature_supported_from(Ok(7)));

        // Not supported: the host knows the feature but does not offer it.
        assert!(!feature_supported_from(Ok(0)));
        assert!(!feature_supported_from(Ok(-1)));

        // Not supported: an older host rejects the unknown feature value.
        assert!(!feature_supported_from(Err(
            windows_core::Error::from_hresult(
                windows_core::HRESULT(0x8007_0057u32 as i32), // E_INVALIDARG
            )
        )));
    }
}
