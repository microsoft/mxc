//! Windows Sandbox guest agent.

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

    // Without the nonce, host connections cannot be authenticated.
    let nonce = windows_sandbox_common::auth::read_and_consume_nonce_file(
        std::path::Path::new(RENDEZVOUS_DIR),
        windows_sandbox_common::auth::NONCE_READ_TIMEOUT,
    )
    .await
    .context("read per-launch authentication nonce")?;
    eprintln!(
        "[guest] authentication nonce loaded ({} bytes)",
        windows_sandbox_common::auth::NONCE_LEN_IN_BYTES
    );

    // Pre-authorise before binding to avoid an interactive firewall prompt.
    if let Err(err) = firewall::pre_authorize().await {
        eprintln!("[guest] firewall pre-authorization failed (continuing): {err:#}");
    } else {
        eprintln!("[guest] firewall pre-authorized");
    }

    let (tcp_listener, local_addr) = listener::bind_and_advertise(RENDEZVOUS_DIR)
        .await
        .context("failed to start TCP listener")?;
    eprintln!("[guest] listening on {}", local_addr);

    let (control, stdin_stream, stdout_stream, stderr_stream) =
        listener::accept_connections(&tcp_listener, &nonce)
            .await
            .context("failed to accept host connections")?;
    let host_ip = control.peer_addr()?.ip();
    eprintln!("[guest] host connected from {}", host_ip);

    firewall::lockdown(host_ip, local_addr.port())
        .await
        .context("firewall lockdown failed")?;
    eprintln!("[guest] firewall locked down");

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
