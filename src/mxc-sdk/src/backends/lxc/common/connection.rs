// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const COPY_THREAD_NAME: &str = "mxc-lxc-proxy-copy";

pub(super) struct Connection {
    container_socket: TcpStream,
    proxy_socket: TcpStream,
    copying: JoinHandle<()>,
}

impl Connection {
    /// Blocks until a proxy address answers or every one has timed out.
    pub(super) fn open(
        container_socket: TcpStream,
        proxy_addresses: &[SocketAddr],
    ) -> io::Result<Self> {
        let proxy_socket = proxy_addresses
            .iter()
            .find_map(|address| TcpStream::connect_timeout(address, PROXY_CONNECT_TIMEOUT).ok())
            .ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionRefused))?;

        let container = container_socket.try_clone()?;
        let proxy = proxy_socket.try_clone()?;
        let copying = thread::Builder::new()
            .name(COPY_THREAD_NAME.to_string())
            .spawn(move || copy_both_ways(&container, &proxy))?;

        Ok(Self {
            container_socket,
            proxy_socket,
            copying,
        })
    }

    pub(super) fn is_finished(&self) -> bool {
        self.copying.is_finished()
    }

    pub(super) fn close(self) {
        let _ = self.container_socket.shutdown(Shutdown::Both);
        let _ = self.proxy_socket.shutdown(Shutdown::Both);
        let _ = self.copying.join();
    }
}

fn copy_both_ways(container: &TcpStream, proxy: &TcpStream) {
    thread::scope(|scope| {
        let to_proxy = thread::Builder::new()
            .name(COPY_THREAD_NAME.to_string())
            .spawn_scoped(scope, || copy_then_end(container, proxy));
        if to_proxy.is_ok() {
            copy_then_end(proxy, container);
        }
    });
}

fn copy_then_end(mut from: &TcpStream, mut to: &TcpStream) {
    let _ = io::copy(&mut from, &mut to);

    let _ = to.shutdown(Shutdown::Write);
}
