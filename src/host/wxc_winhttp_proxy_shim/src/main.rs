// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Elevated WinHTTP proxy policy shim.
//!
//! This binary is launched with UAC elevation by `wxc-exec` to set
//! per-AppContainer WinHTTP proxy policies. The WCM proxy policy APIs
//! require administrator privileges, so this shim runs elevated while
//! the rest of the pipeline stays non-elevated.
//!
//! Lifecycle:
//!   1. Parse CLI args (SID, proxy address/port, ready file, cleanup event, parent PID).
//!   2. Set the per-AppContainer proxy policy via `ActiveProxyPolicy::set()`.
//!   3. Write "READY" to the ready file so the launcher knows the policy is active.
//!   4. Wait for the cleanup event to be signaled or the parent process to exit.
//!   5. Delete the proxy policy and exit.

use clap::Parser;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED};
use windows::Win32::System::Threading::{
    OpenEventW, OpenProcess, WaitForMultipleObjects, EVENT_ALL_ACCESS, PROCESS_SYNCHRONIZE,
};

use wxc_common::logger::{Logger, Mode};
use wxc_common::string_util;
mod bindings;
mod proxy_policy;

use proxy_policy::ActiveProxyPolicy;

#[derive(Parser)]
#[command(
    name = "winhttp-proxy-shim",
    about = "Elevated WinHTTP proxy policy shim for AppContainer sandboxing"
)]
struct Cli {
    /// AppContainer SID string (e.g. "S-1-15-2-...")
    #[arg(long)]
    sid: String,

    /// Proxy server address (e.g. "127.0.0.1")
    #[arg(long)]
    proxy_address: String,

    /// Proxy server port
    #[arg(long)]
    proxy_port: u16,

    /// Path to the ready file — written when the policy is active
    #[arg(long)]
    ready_file: String,

    /// Name of the cleanup event created by the launcher
    #[arg(long)]
    cleanup_event: String,

    /// PID of the parent process — monitored for crash recovery
    #[arg(long)]
    parent_pid: u32,
}

/// Open the named cleanup event created by the parent process.
fn open_cleanup_event(event_name: &str) -> Result<HANDLE, String> {
    let event_name_wide = string_util::to_wide(event_name);
    unsafe {
        OpenEventW(EVENT_ALL_ACCESS, false, PCWSTR(event_name_wide.as_ptr()))
            .map_err(|err| format!("OpenEventW failed for '{}': {}", event_name, err))
    }
}

/// Open a handle to the parent process for crash-recovery monitoring.
fn open_parent_process(parent_pid: u32) -> Result<HANDLE, String> {
    unsafe {
        OpenProcess(PROCESS_SYNCHRONIZE, false, parent_pid)
            .map_err(|err| format!("OpenProcess failed for PID {}: {}", parent_pid, err))
    }
}

/// Block until the cleanup event is signaled or the parent process exits.
fn wait_for_cleanup_signal(event_handle: HANDLE, parent_handle: HANDLE) {
    let handles = [event_handle, parent_handle];
    let result = unsafe { WaitForMultipleObjects(&handles, false, u32::MAX) };
    if result == WAIT_FAILED {
        eprintln!(
            "[winhttp-proxy-shim] WaitForMultipleObjects failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

fn main() {
    let cli = Cli::parse();
    let mut logger = Logger::new(Mode::Console);

    // Open handles before setting the policy so failures are caught early.
    let event_handle = match open_cleanup_event(&cli.cleanup_event) {
        Ok(handle) => handle,
        Err(err) => {
            eprintln!("[winhttp-proxy-shim] {}", err);
            std::process::exit(1);
        }
    };

    let parent_handle = match open_parent_process(cli.parent_pid) {
        Ok(handle) => handle,
        Err(err) => {
            eprintln!("[winhttp-proxy-shim] {}", err);
            unsafe {
                let _ = CloseHandle(event_handle);
            }
            std::process::exit(1);
        }
    };

    // Set the per-AppContainer proxy policy (requires elevation).
    let policy =
        match ActiveProxyPolicy::set(&cli.sid, &cli.proxy_address, cli.proxy_port, &mut logger) {
            Ok(policy) => policy,
            Err(err) => {
                eprintln!("[winhttp-proxy-shim] Failed to set proxy policy: {}", err);
                unsafe {
                    let _ = CloseHandle(event_handle);
                    let _ = CloseHandle(parent_handle);
                }
                std::process::exit(1);
            }
        };

    // Signal readiness to the launcher.
    if let Err(err) = std::fs::write(&cli.ready_file, "READY") {
        eprintln!("[winhttp-proxy-shim] Failed to write ready file: {}", err);
        policy.delete(&mut logger);
        unsafe {
            let _ = CloseHandle(event_handle);
            let _ = CloseHandle(parent_handle);
        }
        std::process::exit(1);
    }

    eprintln!("[winhttp-proxy-shim] Proxy policy active — waiting for cleanup signal.");

    // Block until the launcher signals cleanup or the parent process exits.
    wait_for_cleanup_signal(event_handle, parent_handle);

    // Clean up the proxy policy before exiting.
    eprintln!("[winhttp-proxy-shim] Cleaning up proxy policy...");
    policy.delete(&mut logger);

    unsafe {
        let _ = CloseHandle(event_handle);
        let _ = CloseHandle(parent_handle);
    }

    eprintln!("[winhttp-proxy-shim] Done.");
}
