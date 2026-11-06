// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Lets a workload in a container reach a proxy on the host's loopback at the
//! same address it names on the host.
//!
//! The host and the container each have their own loopback.  A connection to
//! `127.0.0.1:PORT` inside the container stays in the container.  The relay
//! accepts connections on the proxy's port inside the container and carries
//! them to the proxy on the host's loopback.  Nothing else on the host becomes
//! reachable through it.

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::ErrorKind;
#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::thread::{self, JoinHandle};
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use nix::sched::{setns, CloneFlags};

#[cfg(target_os = "linux")]
use crate::mxc_common::models::unbracket_host;

#[cfg(target_os = "linux")]
use super::connection::Connection;

#[cfg(target_os = "linux")]
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[cfg(target_os = "linux")]
const MAX_RELAYED_CONNECTIONS: usize = 64;

#[cfg(not(target_os = "linux"))]
pub(crate) struct LoopbackRelay;

#[cfg(not(target_os = "linux"))]
impl LoopbackRelay {
    pub(crate) fn start(_pid: u32, _host: &str, _port: u16) -> Result<Self, String> {
        Err("the loopback relay runs only on Linux".to_string())
    }
}

/// A running relay.  Dropping it stops accepting, closes every relayed
/// connection, and releases the container's network namespace.
#[cfg(target_os = "linux")]
pub(crate) struct LoopbackRelay {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl LoopbackRelay {
    /// Relay `host:port` from the network namespace of process `pid` to the
    /// same loopback endpoint on the host.
    pub(crate) fn start(pid: u32, host: &str, port: u16) -> Result<Self, String> {
        let host = unbracket_host(host);

        let proxy_addresses: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve the proxy host '{host}': {e}"))?
            .filter(|address| address.ip().is_loopback())
            .collect();
        if proxy_addresses.is_empty() {
            return Err(format!(
                "the proxy host '{host}' resolves to no loopback address on the host"
            ));
        }

        Self::spawn_accept_thread(bind_in_namespace(pid, host, port)?, proxy_addresses)
    }

    /// Relay each accepted connection to the first proxy address that answers.
    fn spawn_accept_thread(
        listeners: Vec<TcpListener>,
        proxy_addresses: Vec<SocketAddr>,
    ) -> Result<Self, String> {
        for listener in &listeners {
            listener
                .set_nonblocking(true)
                .map_err(|e| format!("cannot configure the relay listener: {e}"))?;
        }

        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("mxc-lxc-proxy-relay".to_string())
            .spawn(move || spin_and_accept_connections(listeners, proxy_addresses, worker_stop))
            .map_err(|e| format!("cannot start the relay thread: {e}"))?;

        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for LoopbackRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Open the listeners from a thread that joins the container's network
/// namespace and ends once they are bound.  Every other thread stays in the
/// host's.
#[cfg(target_os = "linux")]
fn bind_in_namespace(pid: u32, host: &str, port: u16) -> Result<Vec<TcpListener>, String> {
    let path = format!("/proc/{pid}/ns/net");
    let namespace =
        File::open(&path).map_err(|e| format!("cannot open the container's {path}: {e}"))?;

    thread::scope(|scope| {
        thread::Builder::new()
            .name("mxc-lxc-proxy-bind".to_string())
            .spawn_scoped(scope, || {
                setns(&namespace, CloneFlags::CLONE_NEWNET)
                    .map_err(|e| format!("cannot enter the container's network namespace: {e}"))?;
                bind_listeners(host, port)
            })
            .map_err(|e| format!("cannot start the relay listener thread: {e}"))?
            .join()
            .unwrap_or_else(|_| Err("the relay listener thread panicked".to_string()))
    })
}

#[cfg(target_os = "linux")]
fn bind_listeners(host: &str, port: u16) -> Result<Vec<TcpListener>, String> {
    let bind = |address: SocketAddr| {
        TcpListener::bind(address)
            .map_err(|e| format!("cannot listen on {address} inside the container: {e}"))
    };

    if host.eq_ignore_ascii_case("localhost") {
        let mut listeners = vec![bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?];
        let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
        match TcpListener::bind(v6) {
            Ok(listener) => listeners.push(listener),

            // A container with no IPv6 loopback, or a kernel with no IPv6 at
            // all, gives a workload nothing at ::1 to connect to either.
            Err(e)
                if e.kind() == ErrorKind::AddrNotAvailable
                    || e.raw_os_error() == Some(libc::EAFNOSUPPORT) => {}

            Err(e) => return Err(format!("cannot listen on {v6} inside the container: {e}")),
        }
        return Ok(listeners);
    }

    match host.parse::<IpAddr>() {
        Ok(ip) if ip.is_loopback() => Ok(vec![bind(SocketAddr::new(ip, port))?]),
        _ => Err(format!("'{host}' is not a loopback address")),
    }
}

#[cfg(target_os = "linux")]
fn spin_and_accept_connections(
    listeners: Vec<TcpListener>,
    proxy_addresses: Vec<SocketAddr>,
    stop: Arc<AtomicBool>,
) {
    let mut connections: Vec<Connection> = Vec::new();

    while !stop.load(Ordering::Acquire) {
        connections.retain(|connection| !connection.is_finished());

        let mut accepted = false;
        for listener in &listeners {
            if let Ok((inbound, _)) = listener.accept() {
                accepted = true;

                if connections.len() >= MAX_RELAYED_CONNECTIONS {
                    continue;
                }
                if let Ok(connection) = Connection::open(inbound, &proxy_addresses) {
                    connections.push(connection);
                }
            }
        }

        if !accepted {
            thread::sleep(ACCEPT_POLL_INTERVAL);
        }
    }

    for connection in connections {
        connection.close();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::{self, Read, Write};
    use std::net::TcpStream;
    use std::sync::mpsc;

    fn relay_to(proxy_address: SocketAddr) -> (LoopbackRelay, SocketAddr) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let relay =
            LoopbackRelay::spawn_accept_thread(vec![listener], vec![proxy_address]).unwrap();
        (relay, address)
    }

    fn stop_within_five_seconds(relay: LoopbackRelay) {
        let (stopped, wait) = mpsc::channel();
        thread::spawn(move || {
            drop(relay);
            let _ = stopped.send(());
        });
        wait.recv_timeout(Duration::from_secs(5))
            .expect("stopping the relay did not join its threads");
    }

    #[test]
    fn a_relayed_connection_round_trips_and_closes_when_the_relay_stops() {
        let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let (relay, address) = relay_to(echo.local_addr().unwrap());
        let echoing = thread::spawn(move || {
            let (mut stream, _) = echo.accept().unwrap();
            let _ = io::copy(&mut stream.try_clone().unwrap(), &mut stream);
        });

        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(b"ping").unwrap();
        let mut reply = [0; 4];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"ping");

        stop_within_five_seconds(relay);
        assert_eq!(client.read(&mut reply).unwrap(), 0);
        echoing.join().unwrap();
    }

    #[test]
    fn a_connection_over_the_limit_is_closed() {
        let unanswered = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let (relay, address) = relay_to(unanswered.local_addr().unwrap());

        let _held: Vec<TcpStream> = (0..MAX_RELAYED_CONNECTIONS)
            .map(|_| TcpStream::connect(address).unwrap())
            .collect();
        let mut over = TcpStream::connect(address).unwrap();
        over.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(matches!(over.read(&mut [0; 1]), Ok(0)));

        stop_within_five_seconds(relay);
    }
}
