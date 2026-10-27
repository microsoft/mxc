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
    match io::copy(&mut from, &mut to) {
        Ok(_) => {
            let _ = to.shutdown(Shutdown::Write);
        }
        // A broken socket would otherwise leave the opposite copier blocked on its read.
        Err(_) => {
            let _ = from.shutdown(Shutdown::Both);
            let _ = to.shutdown(Shutdown::Both);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::os::fd::AsRawFd;
    use std::time::Instant;

    fn reset(stream: TcpStream) {
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        // SAFETY: `linger` outlives the call, and the length passed is its size.
        unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&linger as *const libc::linger).cast(),
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            );
        }
    }

    #[test]
    fn a_proxy_reset_ends_the_connection_while_the_client_stays_open() {
        let container = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let _client = TcpStream::connect(container.local_addr().unwrap()).unwrap();
        let (inbound, _) = container.accept().unwrap();
        let connection = Connection::open(inbound, &[proxy.local_addr().unwrap()]).unwrap();

        reset(proxy.accept().unwrap().0);

        let deadline = Instant::now() + Duration::from_secs(5);
        while !connection.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(connection.is_finished());
    }
}
