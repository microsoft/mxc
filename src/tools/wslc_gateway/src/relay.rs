// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TCP relays: port mappings, a custom proxy and host loopback.

use crate::gateway_policy::{CustomProxy, PortMapping, HOST_LOOPBACK_NAME};
use crate::netlink;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A relayed connection with no data either way for this long is closed, so
/// idle clients can't hold every connection slot.
const IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Per listener, so one listener's clients can't starve the others.
const MAX_CONNECTIONS: usize = 512;
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// How the gateway reaches the network. Tests substitute local listeners.
pub trait Network: Send + Sync + 'static {
    /// IPv4 addresses for `host`, in resolver order.
    fn lookup(&self, host: &str, port: u16) -> impl Future<Output = Vec<Ipv4Addr>> + Send;

    fn connect(&self, host: &str, port: u16) -> impl Future<Output = io::Result<TcpStream>> + Send;

    /// Destination before the host loopback redirect.
    fn original_destination(&self, stream: &TcpStream) -> io::Result<(Ipv4Addr, u16)>;
}

pub struct System;

impl Network for System {
    async fn lookup(&self, host: &str, port: u16) -> Vec<Ipv4Addr> {
        let mut ips = Vec::new();
        for address in tokio::net::lookup_host((host, port))
            .await
            .into_iter()
            .flatten()
        {
            if let SocketAddr::V4(v4) = address {
                if !ips.contains(v4.ip()) {
                    ips.push(*v4.ip());
                }
            }
        }
        ips
    }

    async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
            .await
            .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
    }

    fn original_destination(&self, stream: &TcpStream) -> io::Result<(Ipv4Addr, u16)> {
        netlink::original_destination(stream.as_raw_fd())
    }
}

pub async fn bind(address: SocketAddrV4) -> Result<TcpListener, String> {
    TcpListener::bind(address)
        .await
        .map_err(|e| format!("bind {address}: {e}"))
}

/// Copies both ways until both sides finish, either fails, or the connection
/// is idle for [`IDLE_TIMEOUT`]. A write the peer doesn't read counts as idle.
pub async fn splice(a: impl AsyncRead + AsyncWrite, b: impl AsyncRead + AsyncWrite) {
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);
    let start = Instant::now();
    let active_ms = AtomicU64::new(0);
    let copy = async {
        tokio::try_join!(
            pump(&mut a_read, &mut b_write, start, &active_ms),
            pump(&mut b_read, &mut a_write, start, &active_ms),
        )
    };
    let idle = async {
        loop {
            let deadline =
                start + Duration::from_millis(active_ms.load(Ordering::Relaxed)) + IDLE_TIMEOUT;
            if deadline <= Instant::now() {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    };
    tokio::select! {
        _ = copy => {}
        () = idle => {}
    }
}

async fn pump(
    from: &mut (impl AsyncRead + Unpin),
    to: &mut (impl AsyncWrite + Unpin),
    start: Instant,
    active_ms: &AtomicU64,
) -> io::Result<()> {
    let mut buf = vec![0u8; 8 * 1024];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return to.shutdown().await;
        }
        let mut data = &buf[..n];
        while !data.is_empty() {
            let written = to.write(data).await?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            data = &data[written..];
            active_ms.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
        }
    }
}

/// Runs `handle` on each connection, at most [`MAX_CONNECTIONS`] at a time.
/// Returns only when the listener itself is unusable.
pub async fn accept_loop<F, Fut>(
    listener: TcpListener,
    what: &'static str,
    handle: F,
) -> Result<(), String>
where
    F: Fn(TcpStream, SocketAddr) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let permit = slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| format!("{what}: {e}"))?;
        match listener.accept().await {
            Ok((client, peer)) => {
                let connection = handle(client, peer);
                tokio::spawn(async move {
                    connection.await;
                    drop(permit);
                });
            }
            Err(e) if is_listener_error(&e) => return Err(format!("{what}: accept: {e}")),
            // Per-connection errors and descriptor exhaustion clear up.
            Err(e) => {
                log!("{what}: accept failed, retrying: {e}");
                tokio::time::sleep(ACCEPT_RETRY).await;
            }
        }
    }
}

fn is_listener_error(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EBADF | libc::EINVAL | libc::ENOTSOCK)
    )
}

#[derive(Clone)]
pub struct Target {
    host: Arc<str>,
    port: u16,
}

impl Target {
    pub fn custom_proxy(proxy: &CustomProxy) -> Self {
        let host = proxy
            .address
            .map_or_else(|| HOST_LOOPBACK_NAME.to_string(), |a| a.to_string());
        Self {
            host: host.into(),
            port: proxy.port,
        }
    }

    pub fn port_mapping(mapping: &PortMapping) -> Self {
        Self {
            host: mapping.workload_address.to_string().into(),
            port: mapping.workload_port,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Relays every connection on `listener` to `target`.
pub async fn fixed<N: Network>(
    listener: TcpListener,
    target: Target,
    what: &'static str,
    net: Arc<N>,
) -> Result<(), String> {
    accept_loop(listener, what, move |client, peer| {
        let (target, net) = (target.clone(), net.clone());
        async move {
            match net.connect(&target.host, target.port).await {
                Ok(upstream) => splice(client, upstream).await,
                Err(e) => log!("RELAY {what} {peer} -> {target} failed: {e}"),
            }
        }
    })
    .await
}

/// Relays connections redirected from `relay` to the same port on Windows
/// loopback. Connections made directly to the listener are dropped.
pub async fn host_loopback<N: Network>(
    listener: TcpListener,
    relay: Ipv4Addr,
    net: Arc<N>,
) -> Result<(), String> {
    accept_loop(listener, "host loopback", move |client, peer| {
        let net = net.clone();
        async move {
            let (destination, port) = match net.original_destination(&client) {
                Ok(d) => d,
                Err(e) => return log!("RELAY host loopback {peer}: no original destination: {e}"),
            };
            if destination != relay {
                return log!("RELAY host loopback {peer} -> {destination}:{port} dropped");
            }
            match net.connect(HOST_LOOPBACK_NAME, port).await {
                Ok(upstream) => splice(client, upstream).await,
                Err(e) => {
                    log!("RELAY host loopback {peer} -> {HOST_LOOPBACK_NAME}:{port} failed: {e}")
                }
            }
        }
    })
    .await
}

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Answers lookups from `names`, connects only to `routes` (keyed
    /// `host:port`) and records every lookup and connection attempt.
    #[derive(Default)]
    pub struct Fake {
        pub names: HashMap<String, Vec<Ipv4Addr>>,
        pub routes: HashMap<String, SocketAddr>,
        pub original_destination: Option<(Ipv4Addr, u16)>,
        pub lookups: Mutex<Vec<String>>,
        pub dialed: Mutex<Vec<String>>,
    }

    impl Network for Fake {
        async fn lookup(&self, host: &str, _port: u16) -> Vec<Ipv4Addr> {
            self.lookups.lock().unwrap().push(host.to_string());
            self.names.get(host).cloned().unwrap_or_default()
        }

        async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
            let key = format!("{host}:{port}");
            self.dialed.lock().unwrap().push(key.clone());
            let route = self.routes.get(&key).copied();
            match route {
                Some(address) => TcpStream::connect(address).await,
                None => Err(io::ErrorKind::ConnectionRefused.into()),
            }
        }

        fn original_destination(&self, _: &TcpStream) -> io::Result<(Ipv4Addr, u16)> {
            self.original_destination
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }
    }

    /// Accepts one connection, reads until the client finishes sending, then
    /// replies `reply` and closes. Yields what it received.
    pub async fn upstream() -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            stream.write_all(b"reply").await.unwrap();
            received
        });
        (address, task)
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{upstream, Fake};
    use super::*;

    const RELAY: Ipv4Addr = Ipv4Addr::new(10, 231, 1, 3);

    async fn send(address: SocketAddr, data: &[u8]) -> Vec<u8> {
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(data).await.unwrap();
        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        received
    }

    async fn start_host_loopback(net: Fake) -> (SocketAddr, Arc<Fake>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let net = Arc::new(net);
        tokio::spawn(host_loopback(listener, RELAY, net.clone()));
        (address, net)
    }

    #[tokio::test]
    async fn host_loopback_relays_only_redirected_relay_connections() {
        let (windows, received) = upstream().await;
        let mut net = Fake {
            original_destination: Some((RELAY, 5432)),
            ..Fake::default()
        };
        net.routes
            .insert(format!("{HOST_LOOPBACK_NAME}:5432"), windows);
        let (address, _) = start_host_loopback(net).await;
        assert_eq!(send(address, b"query").await, b"reply");
        assert_eq!(received.await.unwrap(), b"query");

        for original_destination in [Some((Ipv4Addr::new(10, 231, 1, 2), 5432)), None] {
            let (address, net) = start_host_loopback(Fake {
                original_destination,
                ..Fake::default()
            })
            .await;
            let mut client = TcpStream::connect(address).await.unwrap();
            let mut received = Vec::new();
            client.read_to_end(&mut received).await.unwrap();
            assert!(received.is_empty());
            assert!(net.dialed.lock().unwrap().is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn splice_copies_both_ways_and_closes_idle_connections() {
        let (a, mut a_peer) = tokio::io::duplex(64);
        let (b, mut b_peer) = tokio::io::duplex(64);
        let relay = tokio::spawn(splice(a, b));
        let mut buf = [0u8; 4];
        a_peer.write_all(b"ping").await.unwrap();
        b_peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        b_peer.write_all(b"pong").await.unwrap();
        a_peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        tokio::time::sleep(IDLE_TIMEOUT - Duration::from_secs(1)).await;
        assert!(!relay.is_finished());
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .expect("an idle connection is closed")
            .unwrap();
        assert_eq!(a_peer.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn splice_keeps_a_slowly_drained_connection_open() {
        let (a, mut a_peer) = tokio::io::duplex(64);
        let (b, mut b_peer) = tokio::io::duplex(1);
        let relay = tokio::spawn(splice(a, b));
        a_peer.write_all(b"abcd").await.unwrap();
        let mut received = Vec::new();
        let mut byte = [0u8; 1];
        for _ in 0..4 {
            tokio::time::sleep(IDLE_TIMEOUT - Duration::from_secs(60)).await;
            assert_eq!(b_peer.read(&mut byte).await.unwrap(), 1);
            received.push(byte[0]);
        }
        assert_eq!(received, b"abcd");
        assert!(!relay.is_finished());
    }
}
