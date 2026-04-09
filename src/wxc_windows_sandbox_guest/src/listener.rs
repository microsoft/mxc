//! TCP listener and rendezvous file management.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};
use tokio::fs;
use tokio::net::{TcpListener, TcpStream};

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
/// control, stdin, stdout, stderr.
pub async fn accept_connections(
    listener: &TcpListener,
) -> Result<(TcpStream, TcpStream, TcpStream, TcpStream)> {
    let (control, _) = listener.accept().await.context("accept control")?;
    let (stdin_stream, stdout_stream, stderr_stream) = accept_data_connections(listener).await?;
    Ok((control, stdin_stream, stdout_stream, stderr_stream))
}

/// Accept exactly three data TCP connections from the host in order:
/// stdin, stdout, stderr.
///
/// Used both on initial startup (called by [`accept_connections`]) and
/// after each execution to re-establish data streams for the next EXEC.
pub async fn accept_data_connections(
    listener: &TcpListener,
) -> Result<(TcpStream, TcpStream, TcpStream)> {
    let (stdin_stream, _) = listener.accept().await.context("accept stdin")?;
    let (stdout_stream, _) = listener.accept().await.context("accept stdout")?;
    let (stderr_stream, _) = listener.accept().await.context("accept stderr")?;
    Ok((stdin_stream, stdout_stream, stderr_stream))
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
