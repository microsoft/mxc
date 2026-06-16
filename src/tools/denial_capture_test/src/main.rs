// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end smoke harness for per-PID denial capture.
//!
//! Drives the full client path:
//!   1. `open_via_shim(pid)` — handshake with the mxc-denial-shim service
//!   2. `start_collector()`  — OpenTraceW + ProcessTrace worker
//!   3. sleep N seconds (operator runs the target workload during this window)
//!   4. `stop_and_drain()`   — ControlTrace(STOP) + drain
//!   5. print the captured events as pretty JSON
//!
//! Intended to be deployed alongside the shim binary on a test VM
//! and run from an admin shell. The shim must be installed and
//! running.

#![cfg(target_os = "windows")]

use std::thread;
use std::time::Duration;

use clap::Parser;
use denial_capture::session::{open_via_shim, SessionError};

#[derive(Parser)]
#[command(
    name = "denial-capture-test",
    about = "End-to-end smoke harness for per-PID denial capture via the mxc-denial-shim service."
)]
struct Cli {
    /// PID of the target process whose denials should be captured.
    /// Pass the PID of an actively running sandboxed workload (or any
    /// PID; events for non-matching PIDs are dropped by the kernel
    /// filter, so no events == correct behavior).
    #[arg(long)]
    pid: u32,

    /// Optional AppContainer LowBox SID. When provided the shim also
    /// applies an EVENT_FILTER_TYPE_PACKAGE_ID filter (Phase 3
    /// follow-up; currently the shim accepts but doesn't act on it).
    #[arg(long = "package-sid")]
    package_sid: Option<String>,

    /// How long to consume events before stopping, in seconds.
    /// Default 10s. Operator triggers denied accesses on the target
    /// process during this window.
    #[arg(long, default_value_t = 10)]
    duration_secs: u64,
}

fn main() {
    let cli = Cli::parse();

    println!(
        "[1/5] Connecting to mxc-denial-shim and requesting session for PID {}…",
        cli.pid
    );
    let session = match open_via_shim(cli.pid, cli.package_sid.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FAILED at open_via_shim: {e}");
            print_session_error_details(&e);
            std::process::exit(1);
        }
    };
    println!("       OK: sessionName = {}", session.session_name);

    println!("[2/5] Opening trace + starting ProcessTrace worker…");
    let collector = match session.start_collector() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("FAILED at start_collector: {e}");
            print_session_error_details(&e);
            std::process::exit(2);
        }
    };
    println!("       OK: consumer thread running");

    println!(
        "[3/5] Capturing for {}s (trigger denied accesses on PID {} now)…",
        cli.duration_secs, cli.pid
    );
    thread::sleep(Duration::from_secs(cli.duration_secs));

    println!("[4/5] Stopping session + draining buffer…");
    let (events, truncated) = collector.stop_and_drain();
    println!(
        "       OK: {} events captured (truncated={})",
        events.len(),
        truncated
    );

    println!("[5/5] Captured DenialEvents (JSON):");
    match serde_json::to_string_pretty(&events) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("       (JSON formatting failed: {e})"),
    }

    std::process::exit(0);
}

fn print_session_error_details(e: &SessionError) {
    match e {
        SessionError::ShimError { code, message } => {
            eprintln!("  shim returned structured error:");
            eprintln!("    code:    {code}");
            eprintln!("    message: {message}");
        }
        SessionError::OpenTrace(name, err) => {
            eprintln!("  OpenTraceW failed for `{name}`: Win32 error {err}");
            eprintln!("  This usually means the calling identity lacks read access");
            eprintln!("  to the ETW session. Phase 3 follow-up: shim should call");
            eprintln!("  EventAccessControl to grant the caller's SID.");
        }
        _ => eprintln!("  (no further detail)"),
    }
}
