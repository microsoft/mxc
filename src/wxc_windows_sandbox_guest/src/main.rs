//! Windows Sandbox Guest Process
//!
//! Runs inside Windows Sandbox as the LogonCommand. Startup sequence:
//!   1. Listen on a TCP port
//!   2. Write rendezvous file (IP + port) to the mapped folder
//!   3. Accept 4 connections from host (control, stdin, stdout, stderr)
//!   4. Lock down guest firewall (allow only host IP)
//!   5. Enter command loop: receive EXEC commands, spawn scripts, bridge stdio

mod executor;
mod firewall;
mod listener;

use anyhow::{Context, Result};

/// Path to the rendezvous folder mapped from the host.
const RENDEZVOUS_DIR: &str = r"C:\sandbox-rendezvous";

#[tokio::main]
async fn main() -> Result<()> {
    eprintln!("[guest] starting");

    // Step 1-2: bind TCP listener, write rendezvous file.
    let (tcp_listener, local_addr) = listener::bind_and_advertise(RENDEZVOUS_DIR)
        .await
        .context("failed to start TCP listener")?;
    eprintln!("[guest] listening on {}", local_addr);

    // Step 3: accept 4 connections from the host daemon.
    let (control, stdin_stream, stdout_stream, stderr_stream) =
        listener::accept_connections(&tcp_listener)
            .await
            .context("failed to accept host connections")?;
    let host_ip = control.peer_addr()?.ip();
    eprintln!("[guest] host connected from {}", host_ip);

    // Step 4: lock down firewall — only allow the host IP.
    firewall::lockdown(host_ip, local_addr.port())
        .await
        .context("firewall lockdown failed")?;
    eprintln!("[guest] firewall locked down");

    // Step 5: enter command loop.
    executor::run_command_loop(
        control,
        stdin_stream,
        stdout_stream,
        stderr_stream,
        &tcp_listener,
    )
    .await
}
