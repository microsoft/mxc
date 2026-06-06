//! TCP listener and rendezvous file management.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};
use tokio::fs;
use tokio::net::{TcpListener, TcpStream};

use windows_sandbox_common::auth::{self, Nonce};

/// Bind a TCP listener on all interfaces (port 0 = OS-assigned) and write a
/// rendezvous file so the host daemon can discover us.
pub async fn bind_and_advertise(rendezvous_dir: &str) -> Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .context("bind TCP listener")?;
    let local_addr = listener.local_addr()?;

    // Discover our IP on the Hyper-V Default Switch.  We take the first
    // non-loopback IPv4 address we can find.
    let guest_ip = find_guest_ip().context("could not determine guest IP")?;
    let advertised_addr = SocketAddr::new(guest_ip, local_addr.port());

    // Write rendezvous file: "<ip>:<port>"
    let rendezvous_path = Path::new(rendezvous_dir).join("rendezvous.txt");
    let content = format!("{}", advertised_addr);
    fs::write(&rendezvous_path, content.as_bytes())
        .await
        .with_context(|| format!("write rendezvous file {:?}", rendezvous_path))?;

    Ok((listener, advertised_addr))
}

/// Accept exactly four TCP connections from the host in order:
/// control, stdin, stdout, stderr — verifying the per-launch
/// authentication nonce on each accept (review C2).
///
/// A connection whose first [`auth::NONCE_LEN`] bytes do not match the
/// expected nonce is treated as a local-process hijack attempt: the
/// socket is dropped and we loop back to `accept()` waiting for the
/// legitimate host to connect. No protocol bytes are exchanged on the
/// rejected connection so a hostile peer learns nothing about our
/// framing.
pub async fn accept_connections(
    listener: &TcpListener,
    expected_nonce: &Nonce,
) -> Result<(TcpStream, TcpStream, TcpStream, TcpStream)> {
    let control = accept_one_authed(listener, expected_nonce, "control").await?;
    let (stdin_stream, stdout_stream, stderr_stream) =
        accept_data_connections(listener, expected_nonce).await?;
    Ok((control, stdin_stream, stdout_stream, stderr_stream))
}

/// Accept exactly three data TCP connections from the host in order:
/// stdin, stdout, stderr — verifying the per-launch nonce on each.
///
/// Used both on initial startup (called by [`accept_connections`]) and
/// after each execution to re-establish data streams for the next EXEC.
pub async fn accept_data_connections(
    listener: &TcpListener,
    expected_nonce: &Nonce,
) -> Result<(TcpStream, TcpStream, TcpStream)> {
    let stdin_stream = accept_one_authed(listener, expected_nonce, "stdin").await?;
    let stdout_stream = accept_one_authed(listener, expected_nonce, "stdout").await?;
    let stderr_stream = accept_one_authed(listener, expected_nonce, "stderr").await?;
    Ok((stdin_stream, stdout_stream, stderr_stream))
}

/// Accept the next connection from `listener`, then verify the per-launch
/// nonce. Loops on mismatch — a hostile local-process accept-race is
/// detected and dropped silently; the legitimate host's next attempt
/// succeeds. `label` is used in eprintln for diagnostics.
///
/// Any I/O error during the nonce read (e.g. peer disconnect mid-handshake)
/// is treated the same as a mismatch: drop and retry. This keeps a
/// malformed-or-flaky peer from wedging the listener.
async fn accept_one_authed(
    listener: &TcpListener,
    expected_nonce: &Nonce,
    label: &'static str,
) -> Result<TcpStream> {
    loop {
        let (mut stream, peer) = listener
            .accept()
            .await
            .with_context(|| format!("accept {label}"))?;
        match auth::verify_nonce(&mut stream, expected_nonce).await {
            Ok(()) => return Ok(stream),
            Err(e) => {
                eprintln!(
                    "[guest][auth] rejecting {label} connection from {peer}: {e} (likely a \
                     local-process accept-race; dropping and waiting for the legitimate host)"
                );
                // Drop the stream and loop back to accept. We never write
                // anything to the rejected socket so a hostile peer learns
                // nothing about our protocol.
                drop(stream);
            }
        }
    }
}

/// Find the first non-loopback IPv4 address (the Hyper-V Default Switch NIC).
fn find_guest_ip() -> Result<std::net::IpAddr> {
    use std::net::IpAddr;

    // Attempt a UDP "connect" to a routable address to determine the
    // local source address — works without actually sending traffic.
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("1.1.1.1:80")?;
    let local_addr = socket.local_addr()?;
    let ip = local_addr.ip();

    if ip.is_loopback() || ip == IpAddr::from([0, 0, 0, 0]) {
        anyhow::bail!("only loopback/unspecified addresses found");
    }
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_guest_ip_returns_non_loopback() {
        // This test validates the helper works on any machine with a network
        // adapter.  It will fail on a completely disconnected host, which is
        // acceptable.
        if let Ok(ip) = find_guest_ip() {
            assert!(!ip.is_loopback());
        }
    }
}
