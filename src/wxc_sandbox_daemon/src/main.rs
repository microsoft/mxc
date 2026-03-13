//! Windows Sandbox Daemon (host-side)
//!
//! Long-lived process that manages the Windows Sandbox VM lifecycle:
//!   1. Listen on a named pipe for execution requests from wxc-exec
//!   2. Launch Windows Sandbox with a generated .wsb configuration
//!   3. Poll the rendezvous file to discover the guest agent's IP
//!   4. Connect outbound TCP to the guest agent (4 connections)
//!   5. Bridge named-pipe requests to TCP connections
//!   6. Tear down the sandbox after an idle timeout

mod pipe_server;
mod rendezvous;
mod sandbox_vm;
mod tcp_bridge;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Mutex;

/// Shared state for the daemon.
pub struct DaemonState {
    /// TCP connections to the guest agent, established after rendezvous.
    pub guest_connection: Option<tcp_bridge::GuestConnection>,
    /// Whether the sandbox VM is running.
    pub sandbox_running: bool,
    /// Instant of the last execution request (for idle timeout).
    pub last_activity: std::time::Instant,
}

impl DaemonState {
    fn new() -> Self {
        Self {
            guest_connection: None,
            sandbox_running: false,
            last_activity: std::time::Instant::now(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let pipe_name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "wxc-sandbox".to_string());
    let idle_timeout_ms: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300_000);

    eprintln!("[daemon] starting, pipe={}, idle_timeout={}ms", pipe_name, idle_timeout_ms);

    let state = Arc::new(Mutex::new(DaemonState::new()));

    // Spawn the idle-timeout watchdog.
    let watchdog_state = state.clone();
    let watchdog = tokio::spawn(async move {
        idle_watchdog(watchdog_state, idle_timeout_ms).await;
    });

    // Run the named-pipe server (blocks until shutdown).
    pipe_server::run(&pipe_name, state.clone())
        .await
        .context("pipe server failed")?;

    watchdog.abort();

    // Tear down sandbox on exit.
    {
        let mut s = state.lock().await;
        if s.sandbox_running {
            sandbox_vm::teardown().await;
            s.sandbox_running = false;
        }
    }

    eprintln!("[daemon] exiting");
    Ok(())
}

/// Periodically checks whether the daemon has been idle beyond the timeout.
async fn idle_watchdog(state: Arc<Mutex<DaemonState>>, timeout_ms: u64) {
    if timeout_ms == 0 {
        // No timeout — run forever.
        std::future::pending::<()>().await;
        return;
    }
    let timeout = std::time::Duration::from_millis(timeout_ms);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        let s = state.lock().await;
        if s.last_activity.elapsed() >= timeout {
            eprintln!("[daemon] idle timeout reached, shutting down");
            // Exit the process — the main function's cleanup will run.
            std::process::exit(0);
        }
    }
}
