// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `IsolationSessionManager` — granular wrapper over the in-proc
//! isolation session lifecycle. Each method maps 1:1 to a single WinRT op.
//! `create_process` also drives the ConPTY relay setup + shutdown ladder
//! against the local console.

use wxc_common::process_util::{OwnedHandle, PipeReadCanceller};
use wxc_common::sandbox_process::StreamCloser;
use wxc_common::state_aware_backend::ExecOutcome;

use isolation_session_bindings::bindings::{
    IsoSessionFeature, IsoSessionOps, IsoSessionProcess, IsoSessionProcessResult,
    IsoSessionUserResult,
};
use windows::Win32::Foundation::{CO_E_NOTINITIALIZED, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Com::{
    CoDecrementMTAUsage, CoGetApartmentType, CoIncrementMTAUsage, APTTYPE, APTTYPEQUALIFIER,
    APTTYPEQUALIFIER_NA_ON_MAINSTA, APTTYPEQUALIFIER_NA_ON_STA, APTTYPE_MAINSTA, APTTYPE_NA,
    APTTYPE_STA, CO_MTA_USAGE_COOKIE,
};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject};
use windows_core::{HSTRING, PCWSTR};

use super::console_mode::{get_local_console_size, ConsoleModeRestorer, CtrlHandlerGuard};
use super::console_relay::{create_console_relay_thread, ConsoleRelayParams};
use super::error::{
    activation_error, check_result, format_iso_error, lifecycle_err, op, sta_refusal,
    transport_err, IsolationSessionError, StalePromotion,
};
use super::pipe_relay::{
    create_relay_thread, create_relay_thread_with_stop, duplicate_handle, PipeRelayWithStopParams,
};
use super::process_options::{build_iso_process_options, ProcessOptions};

/// `CoInitializeEx` returns this when the thread is already in a different
/// apartment model.
const RPC_E_CHANGED_MODE: u32 = 0x8001_0106;

/// Keeps the process's MTA alive for as long as the lifecycle's WinRT objects,
/// which outlive their creating call and are used from threads MXC does not own.
/// `CoIncrementMTAUsage` holds a reference releasable from any thread;
/// `CoUninitialize` is thread-affine and would tear the apartment down under a
/// live object.
pub(super) struct MtaReference {
    cookie: CO_MTA_USAGE_COOKIE,
}

impl MtaReference {
    pub(super) fn acquire() -> Result<Self, IsolationSessionError> {
        let apartment = current_apartment()?;
        if apartment.is_single_threaded() {
            // The lifecycle deadlocks in a single-threaded apartment: its
            // asynchronous calls block without pumping.
            return Err(sta_refusal(RPC_E_CHANGED_MODE));
        }

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

enum Apartment {
    SingleThreaded,
    Other,
}

impl Apartment {
    fn is_single_threaded(&self) -> bool {
        matches!(self, Self::SingleThreaded)
    }
}

/// A thread with no apartment reads as `CO_E_NOTINITIALIZED`, which is not a
/// refusal: `CoIncrementMTAUsage` gives it an implicit multi-threaded one.
fn current_apartment() -> Result<Apartment, IsolationSessionError> {
    let mut apartment = APTTYPE::default();
    let mut qualifier = APTTYPEQUALIFIER::default();

    // SAFETY: both out-parameters are valid, writable locals. Reads the calling
    // thread's apartment without altering it.
    match unsafe { CoGetApartmentType(&mut apartment, &mut qualifier) } {
        Ok(()) => {}
        Err(e) if e.code() == CO_E_NOTINITIALIZED => return Ok(Apartment::Other),
        Err(e) => {
            return Err(transport_err(
                op::CO_GET_APARTMENT_TYPE,
                "could not read this thread's COM apartment",
                &e,
            ))
        }
    }

    Ok(classify_apartment(apartment, qualifier))
}

/// Split from [`current_apartment`] so the rule is testable: the real read
/// returns process-global state a test cannot vary.
///
/// A neutral apartment inherits the thread's real one, so it is single-threaded
/// exactly when that is.
fn classify_apartment(apartment: APTTYPE, qualifier: APTTYPEQUALIFIER) -> Apartment {
    let single_threaded = apartment == APTTYPE_STA
        || apartment == APTTYPE_MAINSTA
        || (apartment == APTTYPE_NA
            && (qualifier == APTTYPEQUALIFIER_NA_ON_STA
                || qualifier == APTTYPEQUALIFIER_NA_ON_MAINSTA));
    if single_threaded {
        Apartment::SingleThreaded
    } else {
        Apartment::Other
    }
}

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

/// Decides whether the host supports app-scoped registration — i.e. the
/// `AddUserAsync2` overload that carries an `appId` — from the result of
/// `GetFeatureLevel(IsoSessionFeature::AppScopedRegistration)`.
fn app_scoped_supported_from(level: windows_core::Result<i32>) -> bool {
    matches!(level, Ok(level) if level > 0)
}

/// Maps the app-scoped support decision to the telemetry operation label of the
/// provisioning overload that will be invoked, so a failure is attributed to
/// the `AddUser` overload actually called.
fn add_user_op(app_scoped: bool) -> &'static str {
    if app_scoped {
        op::ADD_USER
    } else {
        op::ADD_USER_LEGACY
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
    /// Declared after `ops` so it drops last: the apartment outlives every
    /// object activated in it.
    _mta: MtaReference,
}

impl IsolationSessionManager {
    /// Pegs a manager to an existing OS-assigned agent user name (the value
    /// returned by `add_user`). Activates the service factory once and
    /// reuses it for the manager's lifetime.
    pub(super) fn new(agent_user_name: &str) -> Result<Self, IsolationSessionError> {
        let mta = MtaReference::acquire()?;
        let ops = check_service_available_and_activate()?;
        Ok(Self {
            agent_user_name: HSTRING::from(agent_user_name),
            ops,
            _mta: mta,
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
    /// The OS interface takes an app id plus an optional enterprise account
    /// name and token. MXC passes the caller-supplied `app_id` verbatim to the
    /// app-scoped [`AddUserAsync2`] overload, with empty strings for the
    /// enterprise account name and token — which selects a local agent user.
    ///
    /// Note: the in-proc API exposes no session-lifetime knob, so `lifecycle`
    /// cannot be honored here. Unsupported values are refused by the calling
    /// surface rather than ignored — one-shot rejects `destroyOnExit: false`
    /// and `preservePolicy: true` in `validate_runner`, and the state-aware
    /// parser rejects the whole `lifecycle` section.
    pub(super) fn add_user(
        app_id: Option<&str>,
    ) -> Result<(ProvisionedUser, Self), IsolationSessionError> {
        let mta = MtaReference::acquire()?;
        let ops = check_service_available_and_activate()?;
        // Prefer the app-scoped `AddUserAsync2` overload, but only when the host
        // advertises support for it. Else fall back to `AddUserAsync`.
        let app_scoped = app_scoped_supported_from(
            ops.GetFeatureLevel(IsoSessionFeature::AppScopedRegistration),
        );
        // The operation label reported in telemetry must name the overload
        // actually invoked, not always `AddUserAsync2`.
        let op_add_user = add_user_op(app_scoped);
        let async_op = if app_scoped {
            ops.AddUserAsync2(
                &HSTRING::from(app_id.unwrap_or_default()),
                &HSTRING::new(),
                &HSTRING::new(),
            )
        } else {
            ops.AddUserAsync(&HSTRING::new(), &HSTRING::new())
        }
        .map_err(|e| transport_err(op_add_user, "call failed", &e))?;
        let user_result: IsoSessionUserResult = async_op
            .join()
            .map_err(|e| transport_err(op_add_user, "wait failed", &e))?;

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

    /// Step 3a: Start a process inside the started isolation session, and
    /// return it **without waiting**.
    ///
    /// Split out of [`Self::create_process`] so the caller chooses how the
    /// streams are consumed: the executor path bridges them with its own relay
    /// threads and blocks (see `create_process`), while an in-process SDK
    /// caller takes the raw handles and drives them itself.
    pub(super) fn start_process(
        &self,
        options: &ProcessOptions,
    ) -> Result<StartedProcess, IsolationSessionError> {
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

        // A getter that errors is a backend failure, not an absent stream:
        // propagate it rather than coercing to 0, which downstream treats as
        // "no handle" and silently skips the corresponding stdio relay. A
        // genuinely returned 0 still means absent and is preserved.
        let stdout = process
            .OutputHandle()
            .map_err(|e| transport_err(op::RUN_PROCESS, "get OutputHandle failed", &e))?;
        let stderr = process
            .ErrorHandle()
            .map_err(|e| transport_err(op::RUN_PROCESS, "get ErrorHandle failed", &e))?;
        let stdin = process
            .InputHandle()
            .map_err(|e| transport_err(op::RUN_PROCESS, "get InputHandle failed", &e))?;

        Ok(StartedProcess {
            process,
            stdout,
            stderr,
            stdin,
        })
    }

    /// Step 3: Create a process inside the started isolation session and run it
    /// to completion. Output is streamed live to the calling process's stdio via
    /// internal relay threads; only the exit code is returned.
    ///
    /// This is the **relay** path, reached by `wxc-exec` and by an in-process
    /// caller that asked to attach. A caller that wants the streams handed back
    /// uses [`Self::start_process`] instead.
    pub(super) fn create_process(
        &self,
        options: &ProcessOptions,
    ) -> Result<i32, IsolationSessionError> {
        // Everything fallible that does not need the workload runs first, so no
        // failure can strand a running one.
        let wxc_stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }
            .map_err(|e| lifecycle_err(format!("GetStdHandle(stdout) failed: {}", e)))?;
        let wxc_stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) }
            .map_err(|e| lifecycle_err(format!("GetStdHandle(stderr) failed: {}", e)))?;
        let wxc_stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) }
            .map_err(|e| lifecycle_err(format!("GetStdHandle(stdin) failed: {}", e)))?;

        // Manual-reset stop event for the stdin relay. Effective for a waitable
        // `h_read` (console = TTY mode); for pipe handles it has no effect on a
        // blocked `ReadFile`, so that relay misses its join and ends only when
        // the calling process exits. Only `wxc-exec` reaches the non-TTY case.
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
        let started = self.start_process(options)?;
        let process = &started.process;
        let stdout_handle_val = started.stdout;
        let stderr_handle_val = started.stderr;
        let stdin_handle_val = started.stdin;

        let mut scope = RelayScope::new(process, stdin_stop_owned.get());

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
            let (thread, canceller) = unsafe {
                create_relay_thread(
                    HANDLE(stdout_handle_val as *mut core::ffi::c_void),
                    wxc_stdout,
                )
            }
            .map_err(|e| lifecycle_err(format!("create stdout relay: {}", e)))?;
            scope.output_cancellers.push(canceller);
            Some(thread)
        } else {
            None
        };
        scope.stderr = if stderr_handle_val != 0 {
            let (thread, canceller) = unsafe {
                create_relay_thread(
                    HANDLE(stderr_handle_val as *mut core::ffi::c_void),
                    wxc_stderr,
                )
            }
            .map_err(|e| lifecycle_err(format!("create stderr relay: {}", e)))?;
            scope.output_cancellers.push(canceller);
            Some(thread)
        } else {
            None
        };
        // Stdin: in interactive mode use the console-aware relay so
        // `WINDOW_BUFFER_SIZE_EVENT` records propagate as
        // `ResizeConsole(cols, rows)` calls on the agent's inner ConPTY.
        // In non-interactive mode the agent's stdin is plain byte-oriented
        // and the simpler stop-aware pipe relay is appropriate.
        enum StdinRelayKind {
            None,
            Pipe(PipeRelayWithStopParams),
            Console(ConsoleRelayParams),
        }

        let stdin_relay_state = if stdin_handle_val == 0 {
            StdinRelayKind::None
        } else {
            // Owned, like the output relays': `process.Close()` releases the
            // original while this relay may still be writing.
            let stdin_h_write =
                duplicate_handle(HANDLE(stdin_handle_val as *mut core::ffi::c_void))
                    .map_err(|e| lifecycle_err(format!("duplicate stdin handle: {}", e)))?;
            // Shares the event object, so `signal_stop` still reaches the relay.
            let stdin_h_stop = duplicate_handle(stdin_stop_owned.get())
                .map_err(|e| lifecycle_err(format!("duplicate stdin stop event: {}", e)))?;
            if options.interactive {
                // Clone the WinRT process handle so the relay thread holds
                // its own ref-counted reference (WinRT clone = AddRef),
                // released when the thread frees the params it owns.
                let process_for_resize = process.clone();
                StdinRelayKind::Console(ConsoleRelayParams {
                    h_read: wxc_stdin,
                    h_write: stdin_h_write,
                    h_stop_event: stdin_h_stop,
                    resize_callback: Box::new(move |cols, rows| {
                        let _ = process_for_resize.ResizeConsole(cols, rows);
                    }),
                })
            } else {
                StdinRelayKind::Pipe(PipeRelayWithStopParams {
                    h_read: wxc_stdin,
                    h_write: stdin_h_write,
                    h_stop_event: stdin_h_stop,
                })
            }
        };

        // Matched by value: the params move into the spawn call, which puts
        // them on the heap under the relay thread's ownership.
        scope.stdin = match stdin_relay_state {
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

        scope.stop_stdin();

        let exit_code = wait_with_graceful_shutdown(process)?;

        scope.finish();

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

/// A process started inside an isolation session but **not yet awaited**.
///
/// Separating start from wait is what makes streaming possible: the executor
/// path hands these handles to its own relay threads and blocks, while an
/// in-process SDK caller takes them and drives them itself.
///
/// **Handle ownership stays here.** The three pipe handles belong to the
/// `IsoSessionProcess` and are released by its `Close()`; a consumer duplicates
/// them and must never close the originals. A `0` means the stream is genuinely
/// absent, not that a getter failed — `start_process` propagates getter errors
/// rather than coercing them.
pub(super) struct StartedProcess {
    pub(super) process: IsoSessionProcess,
    pub(super) stdout: u64,
    pub(super) stderr: u64,
    pub(super) stdin: u64,
}

impl StartedProcess {
    /// Block until the process exits and yield its exit code, escalating
    /// through the graceful-shutdown ladder if it outlives `timeout_ms`.
    ///
    /// The *instruction sequence* is the one the executor path runs inline, but
    /// the ladder's first two tiers are **inert for a consumer that holds
    /// duplicates of the pipe handles**:
    ///
    /// - Tier 1 closes the backend's stdin write end, but a pipe reaches EOF
    ///   only when *every* write end is closed, so tier 1 alone does not
    ///   produce EOF.
    /// - Tier 2 (`SendCtrlClose`) is ConPTY-only and returns `E_NOTIMPL`
    ///   otherwise, and a library consumer never allocates one.
    ///
    /// The ladder therefore degrades to the full 5s + 3s stall followed by
    /// tier 3's hard terminate.
    ///
    /// # Telling a timeout from an exit
    ///
    /// Reported as [`ExecOutcome::TimedOut`] when the deadline elapsed with the
    /// process still running, and [`ExecOutcome::Exited`] otherwise.
    ///
    /// **Neither available signal is sound alone**, because each is also a legal
    /// exit code: `WaitForExit` answers `-1` on timeout, and a timed-out
    /// process still reads [`STILL_ACTIVE`] (259) from `ExitCode()`. A workload
    /// is untrusted code and can return either value at will.
    ///
    /// Their *conjunction* establishes **whether the process was still running
    /// when it was sampled**, which is what the ladder decision needs. A process
    /// that exited cannot have exited with both values at once, so requiring
    /// both pins the live case:
    ///
    /// | Case | `WaitForExit` | `ExitCode()` | Verdict |
    /// |---|---|---|---|
    /// | still running | `-1` | `259` | `TimedOut` (after the ladder confirms it died) |
    /// | exited after the deadline | `-1` | `7` | `TimedOut` (already gone; no ladder) |
    /// | ambiguous | `-1` | `-1` | `Exited(-1)` |
    /// | exited `259` | `259` | `259` | `Exited(259)` |
    ///
    /// # A spent deadline is sticky
    ///
    /// The two reads are not atomic, so a process can exit in the window between
    /// them. That still reports [`ExecOutcome::TimedOut`]: the sentinel proves
    /// the deadline elapsed while the process was running, and a later-observed
    /// exit code does not un-spend it. Reporting that code instead would hide a
    /// missed deadline from a caller who asked for one.
    ///
    /// `TimedOut` promises the process is **gone**, not that this code killed
    /// it — a process that died on its own satisfies that just as a killed one
    /// does. The sibling WSLc backend draws the same line, tracking
    /// `deadline_elapsed` separately from `timed_out` so a spent deadline is
    /// reported "stickily rather than a later-observed exit code", and treating
    /// an already-confirmed exit as satisfying its termination check.
    ///
    /// The one irreducible case is `-1`/`-1`, where the sentinel and the exit
    /// code collide: nothing distinguishes a timeout from a workload that
    /// exited with `-1`, so it is read as the exit.
    ///
    /// # How far "gone" reaches here
    ///
    /// Both timeout paths confirm **the foreground process only**, because that
    /// is the only thing this API exposes: `IsoSessionProcess` has `Terminate`
    /// and `ExitCode` for the process it represents and no tree primitive. A
    /// descendant the workload backgrounded can therefore outlive a reported
    /// timeout on either path — the live one, which checks `ExitCode()` after
    /// the ladder, and the late-exit one, which has nothing left to terminate.
    ///
    /// That is not a gap this layer can close: descendants live in the isolation
    /// session's own user context and are reclaimed when the session is stopped
    /// and deprovisioned. Stated rather than implied, because
    /// [`ExecOutcome::TimedOut`] leaves the reach to the backend and the SDK's
    /// `WaitOutcome::TimedOut` describes process-tree backends where the kill
    /// does cover the tree.
    ///
    /// A zero `timeout_ms` short-circuits the whole test: it means INFINITE, and
    /// a wait with no deadline cannot have missed one. This is the default, so
    /// without the guard the common configuration would be the one at risk.
    ///
    /// # Why the ladder does not run for an exit
    ///
    /// The ladder exists to kill a **survivor**. Running it for a process that
    /// already exited reintroduces the very ambiguity this function avoids: its
    /// first `ExitCode()` reads 259 for a workload that exited with 259, so it
    /// walks all three tiers and cannot then tell that exit from a live
    /// process. An exited process therefore returns its code directly.
    pub(super) fn wait(&self, timeout_ms: u32) -> Result<ExecOutcome, IsolationSessionError> {
        // `WaitForExit` is a Win32 `WaitForSingleObject` on a kernel handle —
        // no COM round-trip. On timeout it returns -1; the ladder below then
        // decides what to do about a process that is still running.
        let waited = self
            .process
            .WaitForExit(timeout_ms)
            .map_err(|e| transport_err(op::RUN_PROCESS, "WaitForExit failed", &e))?;

        // Sampled before the ladder, which kills a survivor and so destroys the
        // evidence. `?`-propagated for the same reason the ladder propagates its
        // first query: a failure here means the kernel handle is broken, and
        // guessing "it exited" would report a fabricated outcome.
        let plan = plan_wait(timeout_ms, waited, || {
            self.process
                .ExitCode()
                .map_err(|e| transport_err(op::RUN_PROCESS, "get ExitCode failed", &e))
        })?;

        // An exited process never reaches the ladder: the ladder cannot tell a
        // 259 exit from a live process, which is the ambiguity `plan_wait`
        // exists to resolve while the evidence is still intact.
        match plan {
            WaitPlan::Exited(exit_code) => return Ok(ExecOutcome::Exited(exit_code)),
            // The deadline was spent and the process is already gone, so there
            // is nothing to kill and nothing to confirm — the sample that
            // produced this plan is the confirmation.
            WaitPlan::TimedOutAfterDeadline => return Ok(ExecOutcome::TimedOut),
            WaitPlan::KillThenReportTimeout => {}
        }

        // Timed out: the process was still running, so it must be dead before
        // this reports `TimedOut`, which promises exactly that.
        wait_with_graceful_shutdown(&self.process)?;
        let after = self
            .process
            .ExitCode()
            .map_err(|e| transport_err(op::RUN_PROCESS, "get ExitCode failed", &e))?;
        if after == STILL_ACTIVE {
            // Unlike the general case, 259 is not ambiguous here: the sample
            // above established the process was running, so this is the same
            // process still running rather than a stale exit code. (The one
            // exception is a workload that exits with 259 inside the ladder's
            // own window, which yields a conservative "could not determine"
            // rather than a false claim that it was killed.)
            return Err(lifecycle_err(
                "the sandboxed process was still running after close-stdin, Ctrl-Close and \
                 terminate; it timed out but could not be confirmed killed",
            ));
        }
        Ok(ExecOutcome::TimedOut)
    }

    /// Kill the process now, reporting whether the kill request was *accepted*.
    ///
    /// Deliberately **not** the graceful ladder [`Self::wait`] uses. That ladder
    /// gives a well-behaved child up to eight seconds to notice a closed stdin
    /// or a Ctrl-Close, which is right for a shutdown and wrong for a caller who
    /// asked to terminate: `SandboxProcess::kill` promises to kill, and a
    /// cancellation path that takes eight seconds to act reads as a hang.
    ///
    /// The post-kill wait is **bounded**. `WaitForExit(0)` means INFINITE here,
    /// so waiting on the assumption that `Terminate` succeeded would wedge this
    /// call forever if it ever failed against a live process.
    ///
    /// That bound covers *this call only*, and does not make teardown as a whole
    /// bounded. The streaming adapter's `Drop` joins the waiter thread whenever
    /// it believes the process is dead — which includes the case where this
    /// function returned `Ok(())` for a `Terminate` the platform accepted but
    /// that never took effect, since the bounded wait's result is discarded. A
    /// process that survives the kill can then park that join by either of two
    /// routes, so supplying a timeout does not bound it:
    ///
    /// - With no timeout, the waiter is still sitting in its leading
    ///   `WaitForExit(timeout_ms)`, which is INFINITE for `0`.
    /// - With a timeout, that call returns and the waiter proceeds into
    ///   [`wait_with_graceful_shutdown`], which ends in `Terminate` followed by
    ///   `WaitForExit(0)` — INFINITE again.
    ///
    /// Neither route is *certain* to stall: the ladder's tier 3 is a fresh
    /// `Terminate` that may land where this one did not. The narrow claim is
    /// only that nothing in this function bounds that wait — so if the process
    /// does survive, it is the join that waits, not this call.
    ///
    /// **What this does not tell you.** The bounded wait's result is discarded,
    /// so a `Terminate` the platform accepted but that left the process running
    /// still yields `Ok(())`. What *is* now reported is the distinction between
    /// an accepted request and a refused one: the `Err` this returns reaches the
    /// caller through `ExecHandle::terminator` and `SandboxProcess::kill`.
    /// Confirming the process actually died would need the bounded wait's result
    /// as well, which this type does not carry.
    pub(super) fn terminate(&self) -> Result<(), IsolationSessionError> {
        self.process
            .Terminate()
            .map_err(|e| transport_err(op::RUN_PROCESS, "Terminate failed", &e))?;
        // Bounded rather than INFINITE so a `Terminate` that was accepted but
        // never took effect cannot park the caller inside this function. The
        // result is discarded because there is nowhere to report it; see the
        // note above, which also covers why this does not bound teardown.
        let _ = self.process.WaitForExit(TERMINATE_WAIT_MS);
        Ok(())
    }
}

/// Owns the relay threads and the workload for the span of `create_process`.
///
/// [`finish`](Self::finish) tears down a workload that has already exited.
/// Dropping without it abandons the run: the workload is terminated so the
/// output relays reach EOF. Every join is bounded, so a relay whose read never
/// returns cannot wedge the caller's thread.
struct RelayScope<'a> {
    process: &'a IsoSessionProcess,
    stop_event: HANDLE,
    stdout: Option<OwnedHandle>,
    stderr: Option<OwnedHandle>,
    stdin: Option<OwnedHandle>,
    /// Ends the output relays' reads. A descendant that inherited the write
    /// ends keeps them open past the workload's exit, so EOF alone is not a
    /// bound.
    output_cancellers: Vec<PipeReadCanceller>,
    finished: bool,
}

impl<'a> RelayScope<'a> {
    const JOIN_MS: u32 = 1000;
    /// Expiry cancels the read, dropping an in-flight chunk.
    const DRAIN_MS: u32 = 5000;

    fn new(process: &'a IsoSessionProcess, stop_event: HANDLE) -> Self {
        Self {
            process,
            stop_event,
            stdout: None,
            stderr: None,
            stdin: None,
            output_cancellers: Vec::new(),
            finished: false,
        }
    }

    fn signal_stop(&self) {
        // SAFETY: the event outlives this scope.
        unsafe {
            let _ = SetEvent(self.stop_event);
        }
    }

    fn cancel_output_reads(&self) {
        for canceller in &self.output_cancellers {
            canceller.close();
        }
    }

    /// Whether the relay exited. An absent relay was never spawned.
    fn join(relay: &Option<OwnedHandle>, timeout_ms: u32) -> bool {
        match relay {
            // SAFETY: an owned thread handle held by this scope.
            Some(t) => (unsafe { WaitForSingleObject(t.get(), timeout_ms) }) == WAIT_OBJECT_0,
            None => true,
        }
    }

    /// Each relay reads its own duplicate, so one still running does not keep
    /// the pipe handles alive.
    fn close_handles(&self) {
        let _ = self.process.Close();
    }

    fn stop_stdin(&self) {
        self.signal_stop();
        Self::join(&self.stdin, Self::JOIN_MS);
    }

    /// Teardown for a workload that has already exited.
    fn finish(&mut self) {
        self.signal_stop();
        let stdout_drained = Self::join(&self.stdout, Self::DRAIN_MS);
        let stderr_drained = Self::join(&self.stderr, Self::DRAIN_MS);
        if !(stdout_drained && stderr_drained) {
            self.cancel_output_reads();
            Self::join(&self.stdout, Self::JOIN_MS);
            Self::join(&self.stderr, Self::JOIN_MS);
        }
        Self::join(&self.stdin, Self::JOIN_MS);
        self.close_handles();
        self.finished = true;
    }
}

impl Drop for RelayScope<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.signal_stop();
        self.cancel_output_reads();
        let _ = self.process.Terminate();
        Self::join(&self.stdout, Self::JOIN_MS);
        Self::join(&self.stderr, Self::JOIN_MS);
        Self::join(&self.stdin, Self::JOIN_MS);
        self.close_handles();
    }
}

/// A [`StartedProcess`] that releases the session process's pipe handles when
/// it goes out of scope.
///
/// Close-on-drop is **opt-in per consumer** rather than a property of
/// [`StartedProcess`] itself, because the two consumers need opposite things:
///
/// - The streaming consumer has no other teardown point — it hands the handles
///   to an in-process caller and never returns to this crate — so without this
///   a long-lived host would leak three handles per exec, and that host is
///   exactly who the streaming path exists for.
/// - [`IsolationSessionManager::create_process`] must **not** close on the way
///   out: `RelayScope` owns that teardown and runs it once the relays are done.
pub(super) struct ClosingProcess {
    started: StartedProcess,
    /// Keeps the apartment alive: the threads that use the object may have none.
    _mta: MtaReference,
}

impl ClosingProcess {
    pub(super) fn new(started: StartedProcess, mta: MtaReference) -> Self {
        Self { started, _mta: mta }
    }
}

impl std::ops::Deref for ClosingProcess {
    type Target = StartedProcess;

    fn deref(&self) -> &Self::Target {
        &self.started
    }
}

impl Drop for ClosingProcess {
    fn drop(&mut self) {
        let _ = self.started.process.Close();
    }
}

/// `STILL_ACTIVE` (0x103) is exposed by the `windows` crate as
/// `STATUS_PENDING: NTSTATUS` — same numeric value, different name. A process
/// whose `ExitCode()` reads this has not exited.
///
/// **Not sufficient on its own to prove a process is running.** 259 is a legal
/// exit code, so a workload that exits with it is indistinguishable here from
/// one that never exited. Every liveness decision in this file therefore pairs
/// this with a second, independent signal; see [`StartedProcess::wait`].
const STILL_ACTIVE: i32 = windows::Win32::Foundation::STATUS_PENDING.0;

/// What `WaitForExit` returns when the deadline elapses before the process
/// exits. Like [`STILL_ACTIVE`] this is a legal exit code in its own right, so
/// it is never used alone to conclude a timeout.
const WAIT_FOR_EXIT_TIMEOUT: i32 = -1;

/// How long [`StartedProcess::terminate`] waits for a kill to land before
/// reporting success anyway. Bounded so a failed `Terminate` cannot wedge that
/// call; generous enough that a normal kill is observed synchronously.
const TERMINATE_WAIT_MS: u32 = 5_000;

/// What [`StartedProcess::wait`] should do once its wait has returned.
///
/// A value rather than a branch inside `wait`, because `wait` needs a live COM
/// process object and cannot be exercised on a host without the OS-side
/// service — so the decision it hinges on would otherwise be untestable, and a
/// regression in it silently undetectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WaitPlan {
    /// The process exited within its deadline, or there was no deadline. This
    /// is its exit code. **The shutdown ladder must not run** — it cannot
    /// distinguish a 259 exit from a live process.
    Exited(i32),
    /// The deadline elapsed and the process is **still running**. It must be
    /// killed and confirmed dead before a timeout is reported.
    KillThenReportTimeout,
    /// The deadline elapsed, and the process then exited on its own before it
    /// could be sampled. There is nothing left to kill — the exit-code read is
    /// itself the confirmation the process is gone — but the outcome is still a
    /// timeout, because the caller's deadline was spent while it ran.
    ///
    /// Reporting the later-observed exit code here instead would hide a missed
    /// deadline. The sibling WSLc backend makes the same distinction, tracking
    /// `deadline_elapsed` separately from `timed_out` so a spent deadline is
    /// "reported stickily rather than a later-observed exit code".
    TimedOutAfterDeadline,
}

/// Decides what a completed `WaitForExit` means.
///
/// Split out from [`StartedProcess::wait`] so the rule is exercisable without an
/// OS-side isolation session: every input here is a plain integer, while the
/// call it guards needs a live process object.
///
/// `exit_code` is a closure rather than a value so the ordinary case costs no
/// extra COM round-trip — it is consulted only for the one `waited` value that
/// could mean a timeout. See [`StartedProcess::wait`] for why one signal alone
/// is not enough.
fn plan_wait(
    timeout_ms: u32,
    waited: i32,
    exit_code: impl FnOnce() -> Result<i32, IsolationSessionError>,
) -> Result<WaitPlan, IsolationSessionError> {
    // INFINITE: there was no deadline to miss, so the wait returned because the
    // process exited, and `waited` is its code.
    if timeout_ms == 0 || waited != WAIT_FOR_EXIT_TIMEOUT {
        return Ok(WaitPlan::Exited(waited));
    }
    // The sentinel alone proves nothing — a workload may exit with -1 — so the
    // exit code is the second, independent signal.
    let code = exit_code()?;
    match code {
        // Still running: the deadline is spent and the process must be killed.
        STILL_ACTIVE => Ok(WaitPlan::KillThenReportTimeout),
        // Genuinely ambiguous, and the one case that cannot be resolved: the
        // wait returned -1 and the process's code *is* -1, so the sentinel is
        // indistinguishable from a natural exit. Read as the exit.
        WAIT_FOR_EXIT_TIMEOUT => Ok(WaitPlan::Exited(WAIT_FOR_EXIT_TIMEOUT)),
        // The process is gone, and its code is not -1 — so the -1 the wait
        // returned cannot have been that code, and was therefore the timeout
        // sentinel. The deadline provably elapsed while the process ran, and it
        // exited in the window before this sample.
        _ => Ok(WaitPlan::TimedOutAfterDeadline),
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
///
/// # What this does not tell you
///
/// The returned code cannot distinguish a process that exited with 259 from
/// one that is still running, because `ExitCode()` reports 259 for both. A
/// caller that needs that distinction must establish it separately —
/// [`StartedProcess::wait`] does, which is why it only calls this once it has
/// independently determined the process was still running.
fn wait_with_graceful_shutdown(process: &IsoSessionProcess) -> Result<i32, IsolationSessionError> {
    let mut exit_code = process
        .ExitCode()
        .map_err(|e| transport_err(op::RUN_PROCESS, "get ExitCode failed", &e))?;
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
    // Unchanged from before the exec-handle reshape: this path serves the
    // executor, which needs an exit code and has no timeout channel. Failing
    // here on a 259 read would turn a workload that legitimately exited with
    // 259 into a backend error on the CLI.
    Ok(process.ExitCode().unwrap_or(-1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Com::{
        APTTYPEQUALIFIER_NA_ON_MTA, APTTYPEQUALIFIER_NONE, APTTYPE_MTA,
    };

    /// The process's *first* STA reports `MAINSTA`, not `APTTYPE_STA`; admitting
    /// it deadlocks.
    #[test]
    fn only_single_threaded_apartments_are_classified_as_such() {
        for (apartment, qualifier) in [
            (APTTYPE_STA, APTTYPEQUALIFIER_NONE),
            (APTTYPE_MAINSTA, APTTYPEQUALIFIER_NONE),
            (APTTYPE_NA, APTTYPEQUALIFIER_NA_ON_STA),
            (APTTYPE_NA, APTTYPEQUALIFIER_NA_ON_MAINSTA),
        ] {
            assert!(
                classify_apartment(apartment, qualifier).is_single_threaded(),
                "{apartment:?} / {qualifier:?} must be refused"
            );
        }

        for (apartment, qualifier) in [
            (APTTYPE_MTA, APTTYPEQUALIFIER_NONE),
            (APTTYPE_NA, APTTYPEQUALIFIER_NA_ON_MTA),
        ] {
            assert!(
                !classify_apartment(apartment, qualifier).is_single_threaded(),
                "{apartment:?} / {qualifier:?} must be admitted"
            );
        }
    }

    /// The exit code a timed-out process reads, paired with the `WaitForExit`
    /// return that accompanies it.
    fn probe(value: i32) -> impl FnOnce() -> Result<i32, IsolationSessionError> {
        move || Ok(value)
    }

    #[test]
    fn timeout_needs_both_signals_not_either() {
        // The real timeout: both signals present, and the ladder must run.
        assert_eq!(
            plan_wait(5_000, WAIT_FOR_EXIT_TIMEOUT, probe(STILL_ACTIVE)).unwrap(),
            WaitPlan::KillThenReportTimeout
        );

        // A workload that exits with the wait sentinel's value. `WaitForExit`
        // reports the code rather than -1, so this is an exit.
        assert_eq!(
            plan_wait(5_000, -1, probe(-1)).unwrap(),
            WaitPlan::Exited(-1)
        );

        // A workload that exits 259 — the value `STILL_ACTIVE` also has. The
        // wait returned the code, not the sentinel, so this is an exit too.
        // Critically it must NOT be planned for the ladder: the ladder reads
        // 259 from `ExitCode()` and cannot tell it from a live process, which
        // is how a clean exit-259 became a backend error.
        assert_eq!(
            plan_wait(5_000, STILL_ACTIVE, probe(STILL_ACTIVE)).unwrap(),
            WaitPlan::Exited(STILL_ACTIVE)
        );

        // An ordinary exit.
        assert_eq!(plan_wait(5_000, 0, probe(0)).unwrap(), WaitPlan::Exited(0));
    }

    /// The sentinel with a non-`STILL_ACTIVE`, non-`-1` code means the deadline
    /// was spent and the process then exited on its own.
    ///
    /// The regression this pins: reporting that later-observed exit code hides
    /// a missed deadline. The `-1` the wait returned cannot have been the
    /// process's code (its code is 7), so it was the timeout sentinel and the
    /// deadline provably elapsed while the process ran.
    #[test]
    fn a_deadline_spent_before_a_late_exit_is_still_a_timeout() {
        assert_eq!(
            plan_wait(5_000, WAIT_FOR_EXIT_TIMEOUT, probe(7)).unwrap(),
            WaitPlan::TimedOutAfterDeadline
        );
        assert_eq!(
            plan_wait(5_000, WAIT_FOR_EXIT_TIMEOUT, probe(0)).unwrap(),
            WaitPlan::TimedOutAfterDeadline,
            "a clean exit past the deadline is still a missed deadline"
        );
    }

    /// The one irreducible collision: sentinel and exit code are both `-1`, so
    /// nothing distinguishes a timeout from a workload that exited with `-1`.
    #[test]
    fn the_sentinel_colliding_with_a_real_minus_one_exit_is_read_as_the_exit() {
        assert_eq!(
            plan_wait(5_000, WAIT_FOR_EXIT_TIMEOUT, probe(-1)).unwrap(),
            WaitPlan::Exited(-1)
        );
    }

    #[test]
    fn infinite_timeout_can_never_be_a_timeout() {
        // 0 means INFINITE. Even with the sentinel apparently present, a wait
        // with no deadline did not miss one. This is the default, so the guard
        // covers the common configuration rather than an exotic one.
        assert_eq!(
            plan_wait(0, WAIT_FOR_EXIT_TIMEOUT, probe(STILL_ACTIVE)).unwrap(),
            WaitPlan::Exited(WAIT_FOR_EXIT_TIMEOUT)
        );
    }

    #[test]
    fn exit_code_is_not_queried_unless_it_could_change_the_answer() {
        let calls = std::cell::Cell::new(0);
        let counting = || {
            calls.set(calls.get() + 1);
            Ok(STILL_ACTIVE)
        };
        assert_eq!(plan_wait(5_000, 0, counting).unwrap(), WaitPlan::Exited(0));
        assert_eq!(calls.get(), 0, "no COM round-trip for a plain exit");
    }

    #[test]
    fn unreadable_exit_code_propagates_rather_than_guessing() {
        let err = plan_wait(5_000, WAIT_FOR_EXIT_TIMEOUT, || {
            Err(lifecycle_err("handle is broken"))
        });
        assert!(
            err.is_err(),
            "a failed probe must not be reported as an exit"
        );
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
    fn app_scoped_support_requires_a_positive_feature_level() {
        // Supported: any positive level.
        assert!(app_scoped_supported_from(Ok(1)));
        assert!(app_scoped_supported_from(Ok(7)));

        // Not supported: the host knows the feature but does not offer it.
        assert!(!app_scoped_supported_from(Ok(0)));
        assert!(!app_scoped_supported_from(Ok(-1)));

        // Not supported: an older host rejects the unknown feature value.
        assert!(!app_scoped_supported_from(Err(
            windows_core::Error::from_hresult(
                windows_core::HRESULT(0x8007_0057u32 as i32), // E_INVALIDARG
            )
        )));
    }

    #[test]
    fn add_user_op_names_the_invoked_overload() {
        // App-scoped hosts use `AddUserAsync2`; older hosts fall back to the
        // legacy `AddUserAsync`. Telemetry must name whichever was invoked.
        assert_eq!(add_user_op(true), op::ADD_USER);
        assert_eq!(add_user_op(false), op::ADD_USER_LEGACY);
    }
}
