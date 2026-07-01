// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows service framework wiring for `mxc-learning-mode-broker`.
//!
//! Uses the `windows-service` crate to register a service control
//! handler with SCM, then runs the named-pipe server until the service
//! receives a `Stop` control. Idle shutdown (the SCM "stop after N
//! seconds idle" behavior) is configured at install time, not here —
//! the service simply runs `pipe_server::run_until_signal()` and exits
//! when signaled.

use std::error::Error;
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

use crate::pipe_server;

define_windows_service!(ffi_service_main, service_main);

/// Hands control to the SCM dispatcher under `service_name`. Blocks until
/// the service stops.
pub fn start_dispatcher(service_name: &str) -> Result<(), Box<dyn Error>> {
    service_dispatcher::start(service_name, ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("[mxc-learning-mode-broker] service exited with error: {e}");
    }
}

fn run_service() -> Result<(), Box<dyn Error>> {
    let stop_flag = Arc::new(AtomicBool::new(false));

    // Status handle holder so the control handler can update SCM as we
    // transition through stop.
    let stop_flag_for_handler = stop_flag.clone();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop_flag_for_handler.store(true, Ordering::SeqCst);
                // Unblock the accept loop's `ConnectNamedPipe` so the
                // service stops promptly instead of hanging until the next
                // client connects.
                pipe_server::wake_accept_loop();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register("MxcLearningModeBroker", event_handler)?;

    let set_status =
        |state: ServiceState, accept: ServiceControlAccept| -> Result<(), windows_service::Error> {
            status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: accept,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::from_secs(0),
                process_id: None,
            })
        };

    set_status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    )?;

    pipe_server::run_until_stop_flag(stop_flag.clone())?;

    set_status(ServiceState::Stopped, ServiceControlAccept::empty())?;
    Ok(())
}
