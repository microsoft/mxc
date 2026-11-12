// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::super::service::{with_transport_stack, Client, Identity, USER_AGENT};
use crate::mxc_common::mxc_error::MxcError;
use native_tls::{TlsConnector, TlsStream};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const HANDSHAKE_BUDGET: Duration = Duration::from_secs(30);
// One maximum-sized exec frame, with room for TLS records and control messages.
const MAX_PENDING_TLS_BYTES: usize = 128 * 1024;

pub(crate) struct UpgradeTarget {
    host: String,
    token: String,
    computer_id: String,
}

impl UpgradeTarget {
    pub(super) fn new(client: Client, identity: &Identity) -> Self {
        Self {
            host: client.host,
            token: client.token,
            computer_id: identity.session_id.clone(),
        }
    }
}

pub(crate) struct ExecConnection(TlsStream<ExecSocket>);

impl ExecConnection {
    pub(super) fn socket(&self) -> &TcpStream {
        &self.0.get_ref().socket
    }

    pub(super) fn enable_duplex(&mut self) -> std::io::Result<()> {
        let socket = self.0.get_mut();
        socket.socket.set_nonblocking(true)?;
        socket.socket.set_read_timeout(None)?;
        socket.socket.set_write_timeout(None)?;
        socket.pending = Some(PendingTlsOutput {
            bytes: Vec::new(),
            written: 0,
        });
        Ok(())
    }

    pub(super) fn has_pending_output(&self) -> bool {
        self.0
            .get_ref()
            .pending
            .as_ref()
            .is_some_and(|pending| pending.written < pending.bytes.len())
    }

    pub(super) fn flush_outgoing(&mut self) -> std::io::Result<bool> {
        self.0.get_mut().flush_outgoing()
    }
}

struct PendingTlsOutput {
    bytes: Vec<u8>,
    written: usize,
}

struct ExecSocket {
    socket: TcpStream,
    pending: Option<PendingTlsOutput>,
}

impl ExecSocket {
    fn flush_outgoing(&mut self) -> std::io::Result<bool> {
        let Some(pending) = &mut self.pending else {
            self.socket.flush()?;
            return Ok(false);
        };
        let mut progressed = false;
        while pending.written < pending.bytes.len() {
            match self.socket.write(&pending.bytes[pending.written..]) {
                Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
                Ok(count) => {
                    pending.written += count;
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(progressed)
                }
                Err(error) => return Err(error),
            }
        }
        pending.bytes.clear();
        pending.written = 0;
        Ok(progressed)
    }
}

impl Read for ExecSocket {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.socket.read(bytes)
    }
}

impl Write for ExecSocket {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(pending) = &mut self.pending else {
            return self.socket.write(bytes);
        };
        if bytes.len() > MAX_PENDING_TLS_BYTES - pending.bytes.len() {
            return Err(std::io::Error::other(
                "W365 pending TLS output exceeded 128 KiB",
            ));
        }
        // Accept complete ciphertext writes so TLS providers need not retain
        // partially sent records while the same owner reads incoming frames.
        pending.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_outgoing()?;
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.written < pending.bytes.len())
        {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        Ok(())
    }
}

impl Read for ExecConnection {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(bytes)
    }
}
impl Write for ExecConnection {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

fn error(code: &str) -> MxcError {
    MxcError::backend_error(format!(
        "W365 exec upgrade failed: {code}; no command frame sent"
    ))
    .with_details(serde_json::json!({"code":code, "operation":"exec", "possiblySucceeded":false}))
}

pub(super) fn connect_exec(target: &UpgradeTarget) -> Result<ExecConnection, MxcError> {
    with_transport_stack(|| connect_exec_inner(target))
}

fn connect_exec_inner(target: &UpgradeTarget) -> Result<ExecConnection, MxcError> {
    let mut tls = TlsConnector::builder();
    tls.min_protocol_version(Some(native_tls::Protocol::Tlsv12));
    let port = 443;
    #[cfg(feature = "test-support")]
    let port = {
        match (
            std::env::var("MXC_W365_TEST_CA"),
            std::env::var("MXC_W365_TEST_PORT"),
        ) {
            (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => port,
            (Ok(path), Ok(port)) if target.host == "localhost" => {
                let bytes = std::fs::read(path).map_err(|_| error("fixture_ca"))?;
                let cert =
                    native_tls::Certificate::from_pem(&bytes).map_err(|_| error("fixture_ca"))?;
                tls.disable_built_in_roots(true).add_root_certificate(cert);
                port.parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or_else(|| error("fixture_port"))?
            }
            _ => return Err(error("fixture_configuration")),
        }
    };
    let deadline = Instant::now() + HANDSHAKE_BUDGET;
    let addresses = (target.host.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| error("exec_dns"))?;
    let mut connected = None;
    for address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        if let Ok(socket) = TcpStream::connect_timeout(&address, remaining) {
            connected = Some(socket);
            break;
        }
    }
    let socket = connected.ok_or_else(|| error("exec_connect"))?;
    socket.set_nodelay(true).map_err(|_| error("exec_socket"))?;
    let tls = tls.build().map_err(|_| error("exec_tls"))?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(error("exec_upgrade_timeout"));
    }
    socket
        .set_read_timeout(Some(remaining))
        .map_err(|_| error("exec_socket"))?;
    socket
        .set_write_timeout(Some(remaining))
        .map_err(|_| error("exec_socket"))?;
    let mut stream = tls
        .connect(
            &target.host,
            ExecSocket {
                socket,
                pending: None,
            },
        )
        .map_err(|_| error("exec_upgrade_transport"))?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(error("exec_upgrade_timeout"));
    }
    stream
        .get_ref()
        .socket
        .set_write_timeout(Some(remaining))
        .map_err(|_| error("exec_socket"))?;
    // These fields have already passed the environment/identity validation.
    let request = format!(
        "GET /computers/{}/microsoft.exec?api-version=1.0 HTTP/1.1\r\nHost: {}:{port}\r\nUser-Agent: {USER_AGENT}\r\nConnection: Upgrade\r\nUpgrade: exec\r\nAuthorization: Bearer {}\r\nx-ms-computerId: {}\r\n\r\n",
        target.computer_id, target.host, target.token, target.computer_id
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|_| error("exec_upgrade_transport"))?;
    let mut header = Vec::new();
    let mut byte = [0];
    while !header.ends_with(b"\r\n\r\n") {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(error("exec_upgrade_timeout"));
        }
        stream
            .get_ref()
            .socket
            .set_read_timeout(Some(remaining))
            .map_err(|_| error("exec_socket"))?;
        if header.len() >= 32768 {
            return Err(error("exec_upgrade_headers"));
        }
        stream
            .read_exact(&mut byte)
            .map_err(|_| error("exec_upgrade_transport"))?;
        header.push(byte[0]);
    }
    let text = std::str::from_utf8(&header).map_err(|_| error("exec_upgrade_headers"))?;
    let mut status_line = text.lines().next().unwrap_or("").split_whitespace();
    let version = status_line.next();
    let status = status_line
        .next()
        .and_then(|value| value.parse::<u16>().ok());
    if !matches!(version, Some("HTTP/1.1") | Some("HTTP/1.0")) {
        return Err(error("exec_upgrade_headers"));
    }
    if status != Some(101) {
        let mut error = error(match status {
            Some(401 | 403) => "auth_denied",
            Some(404 | 410) => "reservation_or_capability_unavailable",
            _ => "exec_upgrade_refused",
        });
        if let Some(details) = &mut error.details {
            details["httpStatus"] = serde_json::json!(status);
            if let Some(id) = text
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("x-ms-request-id"))
                .map(|(_, value)| value.trim())
                .filter(|value| {
                    value.len() <= 128
                        && value
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                })
            {
                details["requestId"] = serde_json::json!(id);
            }
        }
        return Err(error);
    }
    // No buffered reader: bytes immediately following the header remain in TLS.
    stream
        .get_ref()
        .socket
        .set_write_timeout(Some(HANDSHAKE_BUDGET))
        .map_err(|_| error("exec_socket"))?;
    Ok(ExecConnection(stream))
}
