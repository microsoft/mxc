// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// How long a connection waits for the host's proxy to accept it, which also
/// bounds how long stopping the relay can wait on a connection still opening.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// One accepted connection, carried to the host by a thread that connects
/// upstream and copies toward the host, and a second it starts that copies
/// back.
pub(super) struct Connection {
    inbound: TcpStream,
    upstream: Arc<Mutex<Upstream>>,
    worker: JoinHandle<()>,
}

/// The host-side stream once the worker has connected it, and whether the
/// relay has already asked the connection to close.
#[derive(Default)]
struct Upstream {
    closed: bool,
    stream: Option<TcpStream>,
}

impl Connection {
    pub(super) fn open(inbound: TcpStream, addresses: Arc<[SocketAddr]>) -> io::Result<Self> {
        let upstream = Arc::new(Mutex::new(Upstream::default()));
        let worker_inbound = inbound.try_clone()?;
        let worker_upstream = Arc::clone(&upstream);
        let worker = thread::Builder::new()
            .name("mxc-lxc-proxy-conn".to_string())
            .spawn(move || carry(worker_inbound, &addresses, &worker_upstream))?;

        Ok(Self {
            inbound,
            upstream,
            worker,
        })
    }

    pub(super) fn is_finished(&self) -> bool {
        self.worker.is_finished()
    }

    pub(super) fn close(self) {
        let _ = self.inbound.shutdown(Shutdown::Both);
        {
            let mut upstream = lock(&self.upstream);
            upstream.closed = true;
            if let Some(stream) = &upstream.stream {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        let _ = self.worker.join();
    }
}

fn lock(upstream: &Mutex<Upstream>) -> MutexGuard<'_, Upstream> {
    upstream.lock().unwrap_or_else(PoisonError::into_inner)
}

fn carry(inbound: TcpStream, addresses: &[SocketAddr], slot: &Mutex<Upstream>) {
    let connected = addresses
        .iter()
        .find_map(|address| TcpStream::connect_timeout(address, UPSTREAM_CONNECT_TIMEOUT).ok());
    let Some(upstream) = connected else {
        let _ = inbound.shutdown(Shutdown::Both);
        return;
    };

    let to_container = {
        let mut slot = lock(slot);
        if slot.closed {
            None
        } else {
            match (
                upstream.try_clone(),
                upstream.try_clone(),
                inbound.try_clone(),
            ) {
                (Ok(kept), Ok(from), Ok(to)) => {
                    slot.stream = Some(kept);
                    spawn_copy(from, to).ok()
                }
                _ => None,
            }
        }
    };
    let Some(to_container) = to_container else {
        let _ = inbound.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
        return;
    };

    copy_then_end(inbound, upstream);
    let _ = to_container.join();
}

fn spawn_copy(from: TcpStream, to: TcpStream) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("mxc-lxc-proxy-copy".to_string())
        .spawn(move || copy_then_end(from, to))
}

fn copy_then_end(mut from: TcpStream, mut to: TcpStream) {
    let _ = io::copy(&mut from, &mut to);

    // Tells the far side this direction has ended.
    let _ = to.shutdown(Shutdown::Write);
}
