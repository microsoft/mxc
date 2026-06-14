// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows service integration for `mxc-diagnostic-console`.
//!
//! Provides the ability to run the diagnostic console as a Windows service
//! ("MxcDiagnosticService"), including install/uninstall registration with
//! the Service Control Manager and headless execution (no terminal output).
//!
//! # Denial-pipe deployment model (per-user pipe)
//!
//! The denial-capture feature targets the **interactive user session**: the
//! denial pipe name and SDDL are derived from the *current process* token (see
//! [`super::pipe_utils::build_pipe_sddl`] / [`super::pipe_utils::get_current_user_sid`]),
//! producing a per-user pipe `mxc-denials-{SID}`. The SDK computes the same name
//! from the interactive user's SID.
//!
//! When the diagnostic console runs **as a service** it is configured to start
//! as `LocalService` (see [`install_service`]), so its token SID is
//! `S-1-5-19`. The denial pipe it creates is therefore
//! `mxc-denials-S-1-5-19` -- reachable only by SYSTEM/service-context callers,
//! **not** by an interactive SDK process running as the logged-in user. This is
//! intentional and documented here rather than silently creating a mismatched
//! pipe: an interactive SDK should connect to the *console* (interactive)
//! instance of `mxc-diagnostic-console`, which creates the pipe under the
//! logged-in user's SID. The service instance serves SYSTEM/service-context
//! callers only.

use std::ffi::OsString;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::{client_reader, create_pipe_instance, DisplayEvent, ACTIVE_CLIENTS, MAX_CLIENTS, SHUTDOWN};
use std::sync::atomic::Ordering;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The service name registered with the SCM.
const SERVICE_NAME: &str = "MxcDiagnosticService";

/// Display name shown in `services.msc`.
const SERVICE_DISPLAY_NAME: &str = "MXC Diagnostic Service";

/// Service description.
const SERVICE_DESCRIPTION: &str =
    "Collects ETW and pipe-based diagnostics from MXC sandbox executions.";

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

// ---------------------------------------------------------------------------
// Service dispatcher entry point
// ---------------------------------------------------------------------------

/// Run the process as a Windows service. Called from `main()` when `--service`
/// is specified. This function does not return until the service stops.
pub fn run_as_service() -> Result<(), String> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| format!("Failed to start service dispatcher: {e}"))
}

// The service_main function must have this exact signature for the dispatcher.
windows_service::define_windows_service!(ffi_service_main, service_main);

/// The actual service main logic invoked by the SCM after dispatch.
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        // Cannot write to stdout/stderr in service mode; best-effort log to
        // the Windows event log would go here in the future.
        let _ = e;
    }
}

/// Core service logic: register the control handler, report status transitions,
/// start the ETW listener and pipe accept loop, and wait for a stop signal.
fn run_service() -> Result<(), String> {
    // Channel to receive stop events from the SCM.
    let (stop_tx, stop_rx) = mpsc::channel::<()>();

    // Register the control handler.
    let status_handle = service_control_handler::register(SERVICE_NAME, move |control| {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })
    .map_err(|e| format!("Failed to register service control handler: {e}"))?;

    // Report Starting.
    report_status(
        &status_handle,
        ServiceState::StartPending,
        Duration::from_secs(10),
    )?;

    // --- Start the headless diagnostic pipeline ---

    // Channel for reader threads to send display events (consumed but not printed).
    let (tx, rx) = mpsc::channel::<DisplayEvent>();

    // Start the Tier-1 denial pipe server (best-effort) and feed its sender to
    // the ETW listener so denial events decoded from ETW are forwarded to
    // clients.
    //
    // NOTE: Running as a service (LocalService), this denial pipe is created
    // under the service account's SID (`mxc-denials-S-1-5-19`) and is intended
    // for SYSTEM/service-context callers. Interactive SDK callers should use the
    // console instance instead. See the module-level deployment note.
    // `_denial_handle` is held until the service stops; binding it (rather than
    // `_`) avoids prematurely dropping the server's join handle.
    let (denial_tx, _denial_handle) = super::denial_pipe::start_denial_pipe_server();

    // Start ETW listener (best-effort; failure is non-fatal for the service).
    let _etw_result = super::etw::start_etw_listener(tx.clone(), Some(denial_tx));

    // Pipe accept loop in a background thread, using the same shared helper as
    // the interactive path (see [`super::pipe_utils::run_accept_loop`]).
    let pipe_name = wxc_common::diagnostic::diagnostic_pipe_name();
    let pipe_tx = tx.clone();
    let pipe_thread = thread::spawn(move || {
        super::pipe_utils::run_accept_loop(
            |first| create_pipe_instance(&pipe_name, first),
            move |pipe, pid| {
                let tx = pipe_tx.clone();
                let _ = tx.send(DisplayEvent::Connected { pid });
                client_reader(pipe, pid, tx);
            },
            MAX_CLIENTS,
            &ACTIVE_CLIENTS,
            &SHUTDOWN,
            false, // headless: run silently (no stderr output)
        );
    });

    // Sink thread: drain events without printing (headless mode).
    let sink_thread = thread::spawn(move || {
        headless_event_sink(rx);
    });

    // Report Running.
    report_status(&status_handle, ServiceState::Running, Duration::ZERO)?;

    // Wait for the stop signal from the SCM.
    let _ = stop_rx.recv();

    // Report StopPending.
    report_status(
        &status_handle,
        ServiceState::StopPending,
        Duration::from_secs(10),
    )?;

    // Signal shutdown to pipe loop and ETW.
    SHUTDOWN.store(true, Ordering::SeqCst);
    super::etw::stop_etw_listener();

    // Give threads a moment to wind down.
    let _ = pipe_thread.join();
    let _ = sink_thread.join();

    // Report Stopped.
    report_status(&status_handle, ServiceState::Stopped, Duration::ZERO)?;

    Ok(())
}

/// Report the service status to the SCM.
fn report_status(
    handle: &service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    wait_hint: Duration,
) -> Result<(), String> {
    let controls_accepted = if state == ServiceState::Running {
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
    } else {
        ServiceControlAccept::empty()
    };

    let status = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint,
        process_id: None,
    };

    handle
        .set_service_status(status)
        .map_err(|e| format!("Failed to set service status: {e}"))
}

// ---------------------------------------------------------------------------
// Headless operation (no terminal output)
// ---------------------------------------------------------------------------

/// Drain display events without printing anything (headless/service mode).
fn headless_event_sink(rx: mpsc::Receiver<DisplayEvent>) {
    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(_event) => {
                // In service mode we simply consume events. A future enhancement
                // could forward them to the Windows Event Log or a file.
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if SHUTDOWN.load(Ordering::Relaxed) {
                    // Drain remaining.
                    while rx.try_recv().is_ok() {}
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

// ---------------------------------------------------------------------------
// Install / Uninstall
// ---------------------------------------------------------------------------

/// Register the service with the Windows Service Control Manager.
///
/// The service is configured as:
/// - Start type: Auto (starts on boot)
/// - Account: LocalService
/// - Binary: current executable with `--service` argument
///
/// # Deployment note (per-user denial pipe)
///
/// Because the service runs as `LocalService` (SID `S-1-5-19`), the per-user
/// denial pipe it creates is `mxc-denials-S-1-5-19`, which is reachable only by
/// SYSTEM/service-context callers. An interactive SDK running as the logged-in
/// user will compute a different pipe name (from the interactive user's SID) and
/// must therefore connect to the *console* (interactive) instance of
/// `mxc-diagnostic-console` rather than this service instance. See the
/// module-level documentation for the full deployment model.
pub fn install_service() -> Result<(), String> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
            .map_err(|e| format!("Failed to open SCM: {e}"))?;

    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get current executable path: {e}"))?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        account_name: Some(OsString::from("NT AUTHORITY\\LocalService")),
        account_password: None,
    };

    let service = manager
        .create_service(&service_info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| format!("Failed to create service: {e}"))?;

    service
        .set_description(SERVICE_DESCRIPTION)
        .map_err(|e| format!("Failed to set service description: {e}"))?;

    println!("Service '{SERVICE_NAME}' installed successfully.");
    println!("  Display name: {SERVICE_DISPLAY_NAME}");
    println!("  Start type:   Auto");
    println!("  Account:      NT AUTHORITY\\LocalService");
    println!("  Binary:       <current exe> --service");
    println!();
    println!("Start with: sc start {SERVICE_NAME}");

    Ok(())
}

/// Remove the service registration from the SCM.
pub fn uninstall_service() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("Failed to open SCM: {e}"))?;

    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(|e| format!("Failed to open service '{SERVICE_NAME}': {e}"))?;

    // Stop the service if it's running.
    let status = service
        .query_status()
        .map_err(|e| format!("Failed to query service status: {e}"))?;

    if status.current_state != ServiceState::Stopped {
        let _ = service.stop();
        // Wait briefly for it to stop.
        thread::sleep(Duration::from_secs(2));
    }

    service
        .delete()
        .map_err(|e| format!("Failed to delete service: {e}"))?;

    println!("Service '{SERVICE_NAME}' uninstalled successfully.");

    Ok(())
}
