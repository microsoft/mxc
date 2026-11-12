// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TCP relays: port mappings, a custom proxy and host loopback.

use crate::netlink;
use mxc_sdk::wslc_gateway_policy::{CustomProxy, PortMapping, HOST_LOOPBACK_NAME};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// Local port the host loopback redirect sends relay-address TCP to.
pub const HOST_LOOPBACK_PORT: u16 = 15001;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Per listener, so one listener's clients can't starve the others.
const MAX_CONNECTIONS: usize = 512;
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

pub async fn bind(address: SocketAddrV4) -> Result<TcpListener, String> {
    TcpListener::bind(address)
        .await
        .map_err(|e| format!("bind {address}: {e}"))
}

pub async fn connect(host: &str, port: u16) -> std::io::Result<TcpStream> {
    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()))
}

pub async fn splice(mut a: TcpStream, mut b: TcpStream) {
    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
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
                println!("{what}: accept failed, retrying: {e}");
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
pub async fn fixed(
    listener: TcpListener,
    target: Target,
    what: &'static str,
) -> Result<(), String> {
    accept_loop(listener, what, move |client, peer| {
        let target = target.clone();
        async move {
            match connect(&target.host, target.port).await {
                Ok(upstream) => {
                    println!("RELAY {what} {peer} -> {target}");
                    splice(client, upstream).await;
                }
                Err(e) => println!("RELAY {what} {peer} -> {target} failed: {e}"),
            }
        }
    })
    .await
}

/// Relays connections redirected from `relay` to the same port on Windows
/// loopback. Connections made directly to the listener are dropped.
pub async fn host_loopback(listener: TcpListener, relay: Ipv4Addr) -> Result<(), String> {
    accept_loop(listener, "host loopback", move |client, peer| async move {
        let (destination, port) = match netlink::original_destination(client.as_raw_fd()) {
            Ok(d) => d,
            Err(e) => return println!("RELAY host loopback {peer}: no original destination: {e}"),
        };
        if destination != relay {
            return println!("RELAY host loopback {peer} -> {destination}:{port} dropped");
        }
        match connect(HOST_LOOPBACK_NAME, port).await {
            Ok(upstream) => {
                println!("RELAY host loopback {peer} -> {HOST_LOOPBACK_NAME}:{port}");
                splice(client, upstream).await;
            }
            Err(e) => {
                println!("RELAY host loopback {peer} -> {HOST_LOOPBACK_NAME}:{port} failed: {e}")
            }
        }
    })
    .await
}
