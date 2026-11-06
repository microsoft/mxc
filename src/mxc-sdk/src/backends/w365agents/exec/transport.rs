// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::super::service::{Client, Identity};
use crate::mxc_common::mxc_error::MxcError;
use rustls::{ClientConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HANDSHAKE_BUDGET: Duration = Duration::from_secs(30);
pub(super) const READ_POLL_TIMEOUT: Duration = Duration::from_millis(50);

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

pub(crate) struct ExecConnection(StreamOwned<ClientConnection, TcpStream>);

impl ExecConnection {
    pub(super) fn socket(&self) -> &TcpStream {
        &self.0.sock
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
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let port = 443;
    #[cfg(any(test, feature = "test-support"))]
    let port = {
        use rustls::pki_types::pem::PemObject;
        match (
            std::env::var("MXC_W365_TEST_CA"),
            std::env::var("MXC_W365_TEST_PORT"),
        ) {
            (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => port,
            (Ok(path), Ok(port)) if target.host == "localhost" => {
                let bytes = std::fs::read(path).map_err(|_| error("fixture_ca"))?;
                let cert = rustls::pki_types::CertificateDer::from_pem_slice(&bytes)
                    .map_err(|_| error("fixture_ca"))?;
                roots = rustls::RootCertStore::empty();
                roots.add(cert).map_err(|_| error("fixture_ca"))?;
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
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(target.host.clone())
        .map_err(|_| error("exec_host"))?;
    let session = ClientConnection::new(Arc::new(config), name).map_err(|_| error("exec_tls"))?;
    let mut stream = StreamOwned::new(session, socket);
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(error("exec_upgrade_timeout"));
    }
    stream
        .sock
        .set_read_timeout(Some(remaining))
        .map_err(|_| error("exec_socket"))?;
    stream
        .sock
        .set_write_timeout(Some(remaining))
        .map_err(|_| error("exec_socket"))?;
    // These fields have already passed the environment/identity validation.
    let request = format!(
        "GET /computers/{}/microsoft.exec?api-version=1.0 HTTP/1.1\r\nHost: {}:{port}\r\nConnection: Upgrade\r\nUpgrade: exec\r\nAuthorization: Bearer {}\r\nx-ms-computerId: {}\r\n\r\n",
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
            .sock
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
        .sock
        .set_read_timeout(Some(READ_POLL_TIMEOUT))
        .map_err(|_| error("exec_socket"))?;
    stream
        .sock
        .set_write_timeout(Some(HANDSHAKE_BUDGET))
        .map_err(|_| error("exec_socket"))?;
    Ok(ExecConnection(stream))
}
