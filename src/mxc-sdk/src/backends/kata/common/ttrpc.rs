// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A small blocking ttrpc client over a Unix socket.
//!
//! ttrpc is containerd's lightweight RPC protocol. Every message is a 10-byte
//! header (payload length, stream id, message type, flags; all big endian)
//! followed by a protobuf payload. A unary call sends one `Request` frame and
//! reads one `Response` frame carrying a status and the reply payload.
//!
//! Each call uses its own connection. The shim serves connections
//! independently, so a long `Wait` can be outstanding while another thread
//! sends a `Kill`, with no shared reader thread or stream bookkeeping.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::kata_common::protobuf::{DecodeError, Decoder, Encoder};

const HEADER_LEN: usize = 10;
/// ttrpc refuses messages larger than this in either direction.
pub(crate) const MESSAGE_LENGTH_MAX: usize = 4 << 20;
const MESSAGE_TYPE_REQUEST: u8 = 0x1;
const MESSAGE_TYPE_RESPONSE: u8 = 0x2;
/// Time allowed for the shim's socket to accept a connection. The shim binds
/// the socket before it starts, so a longer wait only delays the report that
/// the shim is gone.
const CONNECT_PATIENCE: Duration = Duration::from_secs(1);
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(25);
/// Slack beyond a call's own deadline before the client gives up reading.
const READ_SLACK: Duration = Duration::from_secs(10);

/// gRPC status codes that the callers distinguish.
pub(crate) mod code {
    pub(crate) const NOT_FOUND: i32 = 5;
}

/// Why a call failed.
#[derive(Debug)]
pub(crate) enum CallError {
    /// The socket could not be connected, written, or read.
    Io(io::Error),
    /// The call outlived its deadline without an answer.
    Timeout,
    /// The shim answered with a non-OK status.
    Status { code: i32, message: String },
    /// The shim's reply was not a well-formed ttrpc response.
    Protocol(String),
}

impl CallError {
    /// Whether the shim reported that the named task or process is unknown.
    pub(crate) fn is_not_found(&self) -> bool {
        matches!(self, Self::Status { code, .. } if *code == code::NOT_FOUND)
    }
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "shim connection failed: {e}"),
            Self::Timeout => f.write_str("the shim did not answer before the deadline"),
            Self::Status { code, message } => write!(f, "shim returned status {code}: {message}"),
            Self::Protocol(m) => write!(f, "malformed shim response: {m}"),
        }
    }
}

impl std::error::Error for CallError {}

impl From<io::Error> for CallError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Self::Timeout,
            _ => Self::Io(e),
        }
    }
}

impl From<DecodeError> for CallError {
    fn from(e: DecodeError) -> Self {
        Self::Protocol(e.to_string())
    }
}

/// The 10-byte frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) length: u32,
    pub(crate) stream_id: u32,
    pub(crate) message_type: u8,
    pub(crate) flags: u8,
}

impl Header {
    pub(crate) fn encode(self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..4].copy_from_slice(&self.length.to_be_bytes());
        out[4..8].copy_from_slice(&self.stream_id.to_be_bytes());
        out[8] = self.message_type;
        out[9] = self.flags;
        out
    }

    pub(crate) fn decode(raw: &[u8; HEADER_LEN]) -> Self {
        Self {
            length: u32::from_be_bytes(raw[..4].try_into().expect("4 bytes")),
            stream_id: u32::from_be_bytes(raw[4..8].try_into().expect("4 bytes")),
            message_type: raw[8],
            flags: raw[9],
        }
    }
}

/// The ttrpc `Request` message.
pub(crate) fn encode_request(
    service: &str,
    method: &str,
    payload: &[u8],
    timeout: Option<Duration>,
) -> Vec<u8> {
    let mut e = Encoder::new();
    e.string(1, service).string(2, method).bytes(3, payload);
    if let Some(timeout) = timeout {
        e.uint(4, u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX));
    }
    e.finish()
}

/// The ttrpc `Response` message: returns the reply payload, or the status the
/// shim reported.
pub(crate) fn decode_response(buf: &[u8]) -> Result<Vec<u8>, CallError> {
    let mut status_code = 0i32;
    let mut status_message = String::new();
    let mut payload = Vec::new();
    for field in Decoder::new(buf) {
        let field = field?;
        match field.number {
            1 => {
                for inner in Decoder::new(field.bytes()?) {
                    let inner = inner?;
                    match inner.number {
                        // gRPC codes are small non-negative enum values.
                        1 => status_code = i32::try_from(inner.varint()?).unwrap_or(i32::MAX),
                        2 => status_message = inner.string()?,
                        _ => {}
                    }
                }
            }
            2 => payload = field.bytes()?.to_vec(),
            _ => {}
        }
    }
    if status_code != 0 {
        return Err(CallError::Status {
            code: status_code,
            message: status_message,
        });
    }
    Ok(payload)
}

/// Address of a shim's ttrpc socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Client {
    socket: PathBuf,
    connect_patience: Duration,
}

impl Client {
    /// Accepts the `unix:///path` form the shim prints, or a bare path.
    pub(crate) fn new(address: &str) -> Self {
        let path = address.strip_prefix("unix://").unwrap_or(address);
        Self {
            socket: PathBuf::from(path),
            connect_patience: CONNECT_PATIENCE,
        }
    }

    #[cfg(test)]
    fn with_connect_patience(mut self, patience: Duration) -> Self {
        self.connect_patience = patience;
        self
    }

    fn connect(&self) -> io::Result<UnixStream> {
        let deadline = Instant::now() + self.connect_patience;
        loop {
            match UnixStream::connect(&self.socket) {
                Ok(stream) => return Ok(stream),
                // The shim binds the socket before it starts serving, so a
                // refusal or a missing path right after launch is transient.
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) && Instant::now() < deadline =>
                {
                    std::thread::sleep(CONNECT_RETRY_INTERVAL);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Calls `service/method` and returns the reply payload.
    ///
    /// With `timeout` the shim enforces the deadline itself and the client
    /// stops waiting shortly after it. With `None` the call may block for as
    /// long as the shim takes, which `Wait` relies on.
    pub(crate) fn call(
        &self,
        service: &str,
        method: &str,
        payload: &[u8],
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>, CallError> {
        let request = encode_request(service, method, payload, timeout);
        if request.len() > MESSAGE_LENGTH_MAX {
            return Err(CallError::Protocol(format!(
                "request of {} bytes exceeds the ttrpc limit of {MESSAGE_LENGTH_MAX}",
                request.len()
            )));
        }
        let mut stream = self.connect()?;
        stream.set_read_timeout(timeout.map(|t| t + READ_SLACK))?;
        stream.set_write_timeout(Some(READ_SLACK))?;

        let stream_id = 1;
        let header = Header {
            length: request.len() as u32,
            stream_id,
            message_type: MESSAGE_TYPE_REQUEST,
            flags: 0,
        };
        stream.write_all(&header.encode())?;
        stream.write_all(&request)?;

        loop {
            let mut raw = [0u8; HEADER_LEN];
            stream.read_exact(&mut raw)?;
            let reply = Header::decode(&raw);
            let length = reply.length as usize;
            if length > MESSAGE_LENGTH_MAX {
                return Err(CallError::Protocol(format!(
                    "reply of {length} bytes exceeds the ttrpc limit of {MESSAGE_LENGTH_MAX}"
                )));
            }
            let mut body = vec![0u8; length];
            stream.read_exact(&mut body)?;
            if reply.message_type == MESSAGE_TYPE_RESPONSE && reply.stream_id == stream_id {
                return decode_response(&body);
            }
            // Anything else (a data frame for another stream) is not ours.
        }
    }
}

/// A fake shim for tests: answers every call with an empty OK reply and
/// reports each called method name.
#[cfg(test)]
pub(crate) fn serve_methods(
    listener: std::os::unix::net::UnixListener,
) -> std::sync::mpsc::Receiver<String> {
    let (sender, calls) = std::sync::mpsc::channel();
    // Ends with the process: it waits in `accept` once the test is done.
    std::thread::spawn(move || {
        for connection in listener.incoming() {
            let Ok(mut connection) = connection else {
                break;
            };
            let mut raw = [0u8; HEADER_LEN];
            if connection.read_exact(&mut raw).is_err() {
                continue;
            }
            let header = Header::decode(&raw);
            let mut body = vec![0u8; header.length as usize];
            if connection.read_exact(&mut body).is_err() {
                continue;
            }
            let method = Decoder::new(&body)
                .filter_map(Result::ok)
                .find(|field| field.number == 2)
                .and_then(|field| field.string().ok())
                .unwrap_or_default();
            let _ = sender.send(method);
            let reply = Header {
                length: 0,
                stream_id: header.stream_id,
                message_type: MESSAGE_TYPE_RESPONSE,
                flags: 0,
            };
            let _ = connection.write_all(&reply.encode());
        }
    });
    calls
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// ttrpc `Request{service:"containerd.task.v2.Task", method:"Create",
    /// payload:[1,2], timeout_nano:1000000000}`, encoded with `buf convert`
    /// from the ttrpc project's `ttrpc.proto`.
    const GOLDEN_REQUEST: &str = "0a17636f6e7461696e6572642e7461736b2e76322e5461736b\
         12064372656174651a020102208094ebdc03";

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_request_matches_the_reference_encoding() {
        let got = encode_request(
            "containerd.task.v2.Task",
            "Create",
            &[1, 2],
            Some(Duration::from_secs(1)),
        );
        assert_eq!(got, unhex(GOLDEN_REQUEST));
    }

    #[test]
    fn the_header_is_big_endian() {
        let h = Header {
            length: 0x0102_0304,
            stream_id: 0x0a0b_0c0d,
            message_type: 2,
            flags: 4,
        };
        let raw = h.encode();
        assert_eq!(raw, [1, 2, 3, 4, 0x0a, 0x0b, 0x0c, 0x0d, 2, 4]);
        assert_eq!(Header::decode(&raw), h);
    }

    #[test]
    fn an_ok_response_returns_its_payload() {
        let mut e = Encoder::new();
        e.bytes(2, b"reply");
        assert_eq!(decode_response(&e.finish()).unwrap(), b"reply");
    }

    #[test]
    fn a_status_response_carries_code_and_message() {
        let mut status = Encoder::new();
        status.uint(1, 5).string(2, "task not found");
        let mut e = Encoder::new();
        e.message(1, &status);
        match decode_response(&e.finish()) {
            Err(CallError::Status { code, message }) => {
                assert_eq!(code, 5);
                assert_eq!(message, "task not found");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_response_from_the_reference_encoder_is_decoded() {
        // Response{status:{code:NOT_FOUND, message:"gone"}, payload:"x"}, from
        // `buf convert`. A non-OK status wins over the payload.
        match decode_response(&unhex("0a0808051204676f6e65120178")) {
            Err(CallError::Status { code, message }) => {
                assert_eq!((code, message.as_str()), (code::NOT_FOUND, "gone"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_malformed_response_is_a_protocol_error() {
        assert!(matches!(
            decode_response(&[0x0a, 0x05, 0x01]),
            Err(CallError::Protocol(_))
        ));
    }

    /// Serves one connection: reads a request frame, records it, and answers
    /// with `reply` on the given stream id after skipping an unrelated frame.
    fn serve_once(
        listener: UnixListener,
        reply: Vec<u8>,
        reply_stream: u32,
    ) -> std::thread::JoinHandle<(Header, Vec<u8>)> {
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut raw = [0u8; HEADER_LEN];
            conn.read_exact(&mut raw).unwrap();
            let header = Header::decode(&raw);
            let mut body = vec![0u8; header.length as usize];
            conn.read_exact(&mut body).unwrap();
            // A data frame for a different stream must be ignored.
            let noise = Header {
                length: 1,
                stream_id: 99,
                message_type: 3,
                flags: 0,
            };
            conn.write_all(&noise.encode()).unwrap();
            conn.write_all(&[0]).unwrap();
            let response = Header {
                length: reply.len() as u32,
                stream_id: reply_stream,
                message_type: MESSAGE_TYPE_RESPONSE,
                flags: 0,
            };
            conn.write_all(&response.encode()).unwrap();
            conn.write_all(&reply).unwrap();
            (header, body)
        })
    }

    #[test]
    fn a_call_round_trips_over_a_real_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("shim.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let mut reply = Encoder::new();
        reply.bytes(2, b"pong");
        let server = serve_once(listener, reply.finish(), 1);

        let client = Client::new(&format!("unix://{}", socket.display()));
        let got = client
            .call("svc", "Ping", b"ping", Some(Duration::from_secs(5)))
            .unwrap();
        assert_eq!(got, b"pong");

        let (header, body) = server.join().unwrap();
        assert_eq!(header.message_type, MESSAGE_TYPE_REQUEST);
        assert_eq!(header.stream_id, 1);
        assert_eq!(
            body,
            encode_request("svc", "Ping", b"ping", Some(Duration::from_secs(5)))
        );
    }

    #[test]
    fn a_status_reply_surfaces_as_an_error_with_not_found_helper() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("shim.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let mut status = Encoder::new();
        status.uint(1, 5).string(2, "gone");
        let mut reply = Encoder::new();
        reply.message(1, &status);
        let server = serve_once(listener, reply.finish(), 1);

        let err = Client::new(socket.to_str().unwrap())
            .call("svc", "Ping", b"", None)
            .unwrap_err();
        assert!(err.is_not_found(), "{err}");
        server.join().unwrap();
    }

    #[test]
    fn an_unanswered_call_times_out_instead_of_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("shim.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        // Accept but never answer.
        let holder = std::thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(1500));
            drop(conn);
        });
        let mut stream = Client::new(socket.to_str().unwrap()).connect().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let err = stream.read(&mut [0u8; 1]).unwrap_err();
        assert!(matches!(CallError::from(err), CallError::Timeout));
        drop(stream);
        holder.join().unwrap();
    }

    #[test]
    fn a_missing_socket_reports_an_io_error_after_the_patience_window() {
        let client = Client::new("/nonexistent-dir-for-mxc-kata-test/shim.sock")
            .with_connect_patience(Duration::from_millis(200));
        let started = Instant::now();
        let err = client.call("svc", "Ping", b"", None);
        assert!(matches!(err, Err(CallError::Io(_))), "{err:?}");
        assert!(started.elapsed() >= Duration::from_millis(150));
    }
}
