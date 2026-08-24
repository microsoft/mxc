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
    /// Loopback port to listen on. Zero selects an OS-assigned port.
    #[arg(long, default_value_t = 0)]
    port: u16,

    /// Path where the proxy writes its port number once ready.
    #[arg(long = "ready-file")]
    ready_file: Option<PathBuf>,

    /// Name of the Windows event to wait on for cleanup signal.
    #[arg(long = "cleanup-event")]
    cleanup_event: Option<String>,

    /// PID of the parent process — proxy exits if the parent dies.
    #[arg(long = "parent-pid")]
    parent_pid: Option<u32>,

    /// Keep running until the process is terminated externally.
    #[arg(long)]
    standalone: bool,
}

#[tokio::main]
async fn main() {
    eprintln!(
        "[wxc-test-proxy] *** SECURITY WARNING ***: This is a testing-only proxy. \
         Do NOT use in production."
    );

    let cli = Cli::parse();

    let port = proxy::start(cli.port).await;
    eprintln!("[wxc-test-proxy] Listening on 127.0.0.1:{}", port);

    if let Some(ready_file) = &cli.ready_file {
        if let Err(err) = fs::write(ready_file, port.to_string()) {
            eprintln!(
                "[wxc-test-proxy] Failed to write ready file {}: {}",
                ready_file.display(),
                err
            );
            std::process::exit(1);
        }
    }

    if cli.standalone {
        std::future::pending::<()>().await;
    }

    let (Some(cleanup_event), Some(parent_pid)) = (cli.cleanup_event.as_deref(), cli.parent_pid)
    else {
        eprintln!(
            "[wxc-test-proxy] --cleanup-event and --parent-pid are required unless --standalone is used"
        );
        std::process::exit(2);
    };
    wait_for_shutdown(cleanup_event, parent_pid);
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
    let mut cleanup_event_index: Option<usize> = None;
    let mut parent_process_index: Option<usize> = None;

    match event_handle {
        Ok(handle) => {
            cleanup_event_index = Some(handles.len());
            handles.push(handle);
        }
        Err(err) => eprintln!("[wxc-test-proxy] Could not open cleanup event: {}", err),
    }

    match parent_handle {
        Ok(handle) => {
            parent_process_index = Some(handles.len());
            handles.push(handle);
        }
        Err(err) => eprintln!("[wxc-test-proxy] Could not open parent process: {}", err),
    }

    if handles.is_empty() {
        eprintln!(
            "[wxc-test-proxy] Could not open cleanup event or parent process — exiting immediately"
        );
        return;
    }

    let result = unsafe { WaitForMultipleObjects(&handles, false, u32::MAX) };
    let signaled_index = result.0.wrapping_sub(WAIT_OBJECT_0.0) as usize;

    if cleanup_event_index == Some(signaled_index) {
        eprintln!("[wxc-test-proxy] Cleanup event signaled.");
    } else if parent_process_index == Some(signaled_index) {
        eprintln!("[wxc-test-proxy] Parent process exited.");
    } else {
        eprintln!(
            "[wxc-test-proxy] WaitForMultipleObjects returned unexpected value: {}",
            result.0
        );
    }

    for handle in handles {
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
    }
}
