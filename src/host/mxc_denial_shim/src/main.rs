// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc-denial-shim` — privileged service that loans ETW session-creation
//! privilege to unelevated callers (e.g. `wxc-exec`) for per-PID denial
//! capture.
//!
//! ## Design
//!
//! The shim is a Windows service running as `LocalSystem`, registered with
//! manual start so SCM idle-shutdown can stop it ~60s after the last
//! request. It listens on a named pipe (see
//! `denial_capture::wire::PIPE_NAME`) with an ACL that admits only
//! interactive-logon users.
//!
//! Per request:
//! 1. Read an `OpenDenialSessionRequest` from the connected pipe.
//! 2. Create a private ETW session
//!    (`StartTraceW` + `EVENT_TRACE_PRIVATE_LOGGER_MODE`) filtered to the
//!    requested PID and (optionally) AppContainer package SID. *(Phase
//!    2.2 — currently returns `notImplemented`.)*
//! 3. `DuplicateHandle` the resulting `TRACEHANDLE` into the caller's
//!    process and return its value. *(Phase 2.2.)*
//! 4. Disconnect; the caller now owns the session.
//!
//! ## Operating modes
//!
//! - `mxc-denial-shim` (no flags) — service entry point. Invoked by SCM
//!   when the service starts. Begins the named-pipe accept loop.
//! - `mxc-denial-shim --debug` — runs the service main interactively in
//!   the current console (no SCM). Useful for testing the pipe + RPC
//!   without registering as a service.

#![cfg(target_os = "windows")]

mod etw_session;
mod pipe_server;
mod service;

use std::env;

const SERVICE_NAME: &str = "MxcDenialShim";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let debug = args.iter().any(|a| a == "--debug");

    if debug {
        eprintln!("[mxc-denial-shim] running in --debug mode (no SCM)");
        pipe_server::run_until_signal()
    } else {
        // Hand control to SCM. `service::ffi_service_main` will be invoked
        // by the SCM dispatcher when the service is started.
        service::start_dispatcher(SERVICE_NAME)
    }
}
