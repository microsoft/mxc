// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Standalone binary for the builtin test proxy.
//!
//! **This is a testing-only tool.** It launches a minimal HTTP CONNECT proxy
//! on an OS-assigned port, writes the port to a ready file, and waits for a
//! cleanup event or parent process exit before shutting down.

use std::fs;
use std::path::PathBuf;

use clap::Parser;

mod proxy;

#[derive(Parser)]
#[command(
    name = "wxc-test-proxy",
    about = "Builtin test proxy for wxc integration testing (NOT for production use)"
)]
struct Cli {
    /// Path where the proxy writes its port number once ready.
    #[arg(long = "ready-file")]
    ready_file: PathBuf,

    /// Name of the Windows event to wait on for cleanup signal.
    #[arg(long = "cleanup-event")]
    cleanup_event: String,

    /// PID of the parent process — proxy exits if the parent dies.
    #[arg(long = "parent-pid")]
    parent_pid: u32,
}

#[tokio::main]
async fn main() {
    eprintln!(
        "[wxc-test-proxy] WARNING: This is a testing-only proxy. \
         Do NOT use in production."
    );

    let cli = Cli::parse();

    let port = proxy::start().await;
    eprintln!("[wxc-test-proxy] Listening on 127.0.0.1:{}", port);

    if let Err(err) = fs::write(&cli.ready_file, port.to_string()) {
        eprintln!(
            "[wxc-test-proxy] Failed to write ready file {}: {}",
            cli.ready_file.display(),
            err
        );
        std::process::exit(1);
    }

    wait_for_shutdown(&cli.cleanup_event, cli.parent_pid);
    eprintln!("[wxc-test-proxy] Shutting down.");
}

/// Block until the cleanup event is signaled or the parent process exits.
fn wait_for_shutdown(event_name: &str, parent_pid: u32) {
    use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        OpenEventW, OpenProcess, WaitForMultipleObjects, PROCESS_SYNCHRONIZE,
        SYNCHRONIZATION_SYNCHRONIZE,
    };

    let event_name_wide: Vec<u16> = event_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let event_handle = unsafe {
        OpenEventW(
            SYNCHRONIZATION_SYNCHRONIZE,
            false,
            windows::core::PCWSTR(event_name_wide.as_ptr()),
        )
    };

    let parent_handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, parent_pid) };

    let mut handles: Vec<HANDLE> = Vec::new();
    match event_handle {
        Ok(handle) => handles.push(handle),
        Err(err) => eprintln!("[wxc-test-proxy] Could not open cleanup event: {}", err),
    }
    match parent_handle {
        Ok(handle) => handles.push(handle),
        Err(err) => eprintln!("[wxc-test-proxy] Could not open parent process: {}", err),
    }

    if handles.is_empty() {
        eprintln!(
            "[wxc-test-proxy] Could not open cleanup event or parent process — exiting immediately"
        );
        return;
    }

    let result = unsafe { WaitForMultipleObjects(&handles, false, u32::MAX) };

    if result == WAIT_OBJECT_0 {
        eprintln!("[wxc-test-proxy] Cleanup event signaled.");
    } else {
        eprintln!("[wxc-test-proxy] Parent process exited.");
    }

    for handle in handles {
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
    }
}
