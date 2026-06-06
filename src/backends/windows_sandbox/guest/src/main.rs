//! Windows Sandbox Guest Process
//!
//! Runs inside Windows Sandbox as the LogonCommand. Startup sequence:
//!   0a. Read + delete the per-launch authentication nonce from the
//!       rendezvous folder (`nonce.bin`). The host wrote it before
//!       launching the VM; we delete it immediately so an in-VM compromise
//!       AFTER bind cannot recover it from disk.
//!   0b. Pre-authorize self in Windows Firewall (avoid interactive prompt)
//!   1. Listen on a TCP port
//!   2. Write rendezvous file (IP + port) to the mapped folder
//!   3. Accept 4 connections from host (control, stdin, stdout, stderr)
//!      — each first sends the per-launch nonce, which we constant-time
//!      verify before keeping the connection.
//!   4. Lock down guest firewall (allow only host IP)
//!   5. Enter command loop: receive EXEC commands, spawn scripts, bridge stdio

mod executor;
mod firewall;
mod job;
mod listener;

use anyhow::{Context, Result};

/// Path to the rendezvous folder mapped from the host.
const RENDEZVOUS_DIR: &str = r"C:\sandbox-rendezvous";

#[tokio::main]
async fn main() -> Result<()> {
    eprintln!("[guest] starting");

    // Step 0a: read & immediately delete the per-launch authentication
    // nonce from the rendezvous folder. A missing / malformed file is a
    // fatal configuration error: without the nonce we cannot authenticate
    // any host connection and would have to either accept-by-order
    // (defeating C2) or refuse every connection (deadlock).
    let nonce = windows_sandbox_common::auth::read_and_consume_nonce_file(
        std::path::Path::new(RENDEZVOUS_DIR),
        windows_sandbox_common::auth::NONCE_READ_TIMEOUT,
    )
    .await
    .context("read per-launch authentication nonce")?;
    eprintln!(
        "[guest] authentication nonce loaded ({} bytes)",
        windows_sandbox_common::auth::NONCE_LEN
    );

    // Step 0b: pre-authorize ourselves in Windows Firewall before binding, so
    // the host's inbound connection does not trigger an interactive "allow
    // this app?" prompt (which would block unattended runs). Best-effort: a
    // netsh hiccup should not abort an otherwise-working agent — the prompt
    // reappearing is a degradation, not a hard failure.
    if let Err(err) = firewall::pre_authorize().await {
        eprintln!("[guest] firewall pre-authorization failed (continuing): {err:#}");
    } else {
        eprintln!("[guest] firewall pre-authorized");
    }

    // Step 1-2: bind TCP listener, write rendezvous file.
    let (tcp_listener, local_addr) = listener::bind_and_advertise(RENDEZVOUS_DIR)
        .await
        .context("failed to start TCP listener")?;
    eprintln!("[guest] listening on {}", local_addr);

    // Step 3: accept 4 connections from the host daemon, verifying the
    // per-launch nonce on each.
    let (control, stdin_stream, stdout_stream, stderr_stream) =
        listener::accept_connections(&tcp_listener, &nonce)
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
        &nonce,
    )
    .await
}
