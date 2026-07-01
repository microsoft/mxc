// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc-learning-mode-broker` — privileged service that loans ETW session-creation
//! privilege to unelevated callers (e.g. `wxc-exec`) for per-PID denial
//! capture.
//!
//! ## Design
//!
//! The broker is a Windows service running as `LocalService`, registered with
//! manual start so SCM idle-shutdown can stop it ~60s after the last
//! request. It listens on a named pipe (see
//! `learning_mode_broker_protocol::PIPE_NAME`) with an ACL that admits only
//! interactive-logon users (and the broker's own `LocalService` account).
//!
//! Per request:
//! 1. Read an `OpenDenialSessionRequest` from the connected pipe.
//! 2. Verify, under the caller's impersonation token, that the caller may
//!    query the target PID (delegating "who may audit whom" to Windows'
//!    own ACLs).
//! 3. Create a private ETW session
//!    (`StartTraceW` + `EVENT_TRACE_PRIVATE_LOGGER_MODE`) filtered to the
//!    requested PID and (optionally) AppContainer package SID.
//! 4. Return the ETW session *name*; the caller opens and consumes the
//!    trace by name (`OpenTraceW`). Ownership of the session lifecycle is
//!    handed to the caller, which stops it at workload exit.
//!
//! ## Operating modes
//!
//! - `mxc-learning-mode-broker` (no flags) — service entry point. Invoked by SCM
//!   when the service starts. Begins the named-pipe accept loop.
//! - `mxc-learning-mode-broker --debug` — runs the service main interactively in
//!   the current console (no SCM). Useful for testing the pipe + RPC
//!   without registering as a service.

#![cfg(target_os = "windows")]

mod caller_context;
mod etw_session;
mod pipe_server;
mod service;

use std::env;

const SERVICE_NAME: &str = "MxcLearningModeBroker";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let debug = args.iter().any(|a| a == "--debug");

    if debug {
        eprintln!("[mxc-learning-mode-broker] running in --debug mode (no SCM)");
        pipe_server::run_until_signal()
    } else {
        // Hand control to SCM. `service::ffi_service_main` will be invoked
        // by the SCM dispatcher when the service is started.
        service::start_dispatcher(SERVICE_NAME)
    }
}
