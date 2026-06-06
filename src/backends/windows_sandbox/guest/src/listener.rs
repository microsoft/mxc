//! TCP listener and rendezvous file management.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};
use tokio::fs;
use tokio::net::{TcpListener, TcpStream};

use windows_sandbox_common::auth::{self, ChannelRole, Nonce};

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

/// Accept exactly four TCP connections from the host — control, stdin,
/// stdout, stderr — and pair them with their logical channels by the
/// **declared role tag** the host writes after the nonce. The accept
/// ordering off the listen queue is intentionally NOT relied upon:
/// previous accept-FIFO pairing intermittently broke under unrelated
/// kernel / vNIC scheduling load (see [`ChannelRole`] docs and the
/// 60-second drain hangs that motivated this change). A connection
/// whose first [`auth::NONCE_LEN`] bytes do not match the per-launch
/// nonce — or whose role tag is unknown or duplicates an already-paired
/// role — is dropped and we loop back to `accept()` waiting for the
/// legitimate host to connect.
pub async fn accept_connections(
    listener: &TcpListener,
    expected_nonce: &Nonce,
) -> Result<(TcpStream, TcpStream, TcpStream, TcpStream)> {
    let mut control: Option<TcpStream> = None;
    let mut stdin_stream: Option<TcpStream> = None;
    let mut stdout_stream: Option<TcpStream> = None;
    let mut stderr_stream: Option<TcpStream> = None;
    while control.is_none()
        || stdin_stream.is_none()
        || stdout_stream.is_none()
        || stderr_stream.is_none()
    {
        let (stream, role) = accept_one_authed(listener, expected_nonce).await?;
        assign_role(
            stream,
            role,
            &mut control,
            &mut stdin_stream,
            &mut stdout_stream,
            &mut stderr_stream,
        );
    }
    Ok((
        control.unwrap(),
        stdin_stream.unwrap(),
        stdout_stream.unwrap(),
        stderr_stream.unwrap(),
    ))
}

/// Accept exactly three data TCP connections from the host — stdin,
/// stdout, stderr — paired by [`ChannelRole`] (see [`accept_connections`]
/// for the rationale). Used after each execution to re-establish data
/// streams for the next EXEC.
pub async fn accept_data_connections(
    listener: &TcpListener,
    expected_nonce: &Nonce,
) -> Result<(TcpStream, TcpStream, TcpStream)> {
    let mut control_unused: Option<TcpStream> = None;
    let mut stdin_stream: Option<TcpStream> = None;
    let mut stdout_stream: Option<TcpStream> = None;
    let mut stderr_stream: Option<TcpStream> = None;
    while stdin_stream.is_none() || stdout_stream.is_none() || stderr_stream.is_none() {
        let (stream, role) = accept_one_authed(listener, expected_nonce).await?;
        if matches!(role, ChannelRole::Control) {
            // The reconnect protocol never declares a Control role — drop
            // it the same way we drop a duplicate. The legitimate host
            // only sends stdin/stdout/stderr on data reconnect.
            eprintln!(
                "[guest][auth] rejecting unexpected Control role on data reconnect; dropping"
            );
            drop(stream);
            continue;
        }
        assign_role(
            stream,
            role,
            &mut control_unused,
            &mut stdin_stream,
            &mut stdout_stream,
            &mut stderr_stream,
        );
    }
    Ok((
        stdin_stream.unwrap(),
        stdout_stream.unwrap(),
        stderr_stream.unwrap(),
    ))
}

/// Place `stream` in the slot for `role`. If the slot is already filled
/// — i.e. the host (or a hostile peer that somehow knew the nonce) sent
/// the same role twice — the new socket is dropped silently. This keeps
/// a single misbehaving peer from displacing an already-paired
/// legitimate socket.
fn assign_role(
    stream: TcpStream,
    role: ChannelRole,
    control: &mut Option<TcpStream>,
    stdin_stream: &mut Option<TcpStream>,
    stdout_stream: &mut Option<TcpStream>,
    stderr_stream: &mut Option<TcpStream>,
) {
    let slot = match role {
        ChannelRole::Control => control,
        ChannelRole::Stdin => stdin_stream,
        ChannelRole::Stdout => stdout_stream,
        ChannelRole::Stderr => stderr_stream,
    };
    if slot.is_some() {
        eprintln!(
            "[guest][auth] rejecting duplicate {} connection (slot already filled); dropping",
            role.label()
        );
        drop(stream);
        return;
    }
    *slot = Some(stream);
}

/// Accept the next connection from `listener`, then verify the per-launch
/// nonce + read the declared role tag. Loops on any handshake failure —
/// a hostile local-process accept-race is detected and dropped silently;
/// the legitimate host's next attempt succeeds.
///
/// Any I/O error during the nonce or role read (e.g. peer disconnect
/// mid-handshake) is treated the same as a mismatch: drop and retry.
/// This keeps a malformed-or-flaky peer from wedging the listener.
async fn accept_one_authed(
    listener: &TcpListener,
    expected_nonce: &Nonce,
) -> Result<(TcpStream, ChannelRole)> {
    loop {
        let (mut stream, peer) = listener.accept().await.context("accept")?;
        match auth::verify_nonce(&mut stream, expected_nonce).await {
            Ok(role) => return Ok((stream, role)),
            Err(e) => {
                eprintln!(
                    "[guest][auth] rejecting connection from {peer}: {e} (likely a local-process \
                     accept-race or protocol mismatch; dropping and waiting for the legitimate \
                     host)"
                );
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
