// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IPC exec sub-protocol between a state-aware `exec`-phase `wxc-exec` process
//! and the host daemon that holds the live guest connection.
//!
//! This is distinct from the guest control protocol ([`sandbox_protocol`]):
//! it runs over the daemon's localhost IPC port, *after* the line-based
//! `EXEC <nonce>\n` authentication handshake. The exchange is:
//!
//! 1. client → daemon: `EXEC <nonce>\n` (line; handled by the daemon's control
//!    server), immediately followed by one **request frame**: a 4-byte LE
//!    length prefix + JSON-encoded [`ExecStart`].
//! 2. daemon → client: a single **status line** — `OK\n` if the exec was
//!    admitted (single-flight slot acquired) or `ERR <reason>\n` if it was
//!    rejected (busy / not-ready / poisoned). No binary frames follow an `ERR`.
//! 3. daemon → client (only after `OK`): a stream of **data frames**
//!    `[kind: u8][len: u32 LE][payload]`, where `kind` is one of
//!    [`FRAME_STDOUT`] / [`FRAME_STDERR`] (payload = raw bytes, written live to
//!    the client's stdout/stderr) or [`FRAME_EXIT`] (payload = JSON
//!    [`ExecExit`]). [`FRAME_EXIT`] is always the final frame and is sent only
//!    after the guest's stdout and stderr have reached EOF and the guest has
//!    reported its exit, so no output is lost.
//!
//! Binary framing (rather than JSON/base64) keeps arbitrary binary stdout/stderr
//! byte-exact and avoids ~33% base64 bloat on the hot path. The small structured
//! payloads ([`ExecStart`], [`ExecExit`]) stay JSON for forward-compatibility.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Data-frame kind: raw stdout bytes from the guest child process.
pub const FRAME_STDOUT: u8 = 1;
/// Data-frame kind: raw stderr bytes from the guest child process.
pub const FRAME_STDERR: u8 = 2;
/// Data-frame kind: terminal exit frame (payload = JSON [`ExecExit`]).
pub const FRAME_EXIT: u8 = 3;
/// Data-frame kind: raw stdin bytes from the exec-phase client to the daemon,
/// forwarded onto the guest child's stdin. Zero-payload frames are valid (and
/// ignored); a clean EOF on the IPC reader is what triggers guest stdin
/// shutdown, not a special "end of stdin" frame. See [`crate::bridge::stream_exec_on_guest`].
pub const FRAME_STDIN: u8 = 4;

/// Upper bound on a single IPC frame's payload (defensive against a malformed
/// or hostile localhost client that holds the nonce). Matches the guest
/// control protocol's frame ceiling.
pub const MAX_IPC_FRAME: usize = 16 * 1024 * 1024;

/// Request payload sent by the exec-phase client to start an execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecStart {
    /// Command line to run inside the sandbox (passed to `cmd.exe /C`).
    pub script_code: String,
    /// Working directory inside the sandbox (empty = guest default).
    pub working_directory: String,
    /// Timeout in milliseconds (0 = no timeout). Enforced guest-side.
    pub timeout_ms: u32,
}

/// Terminal exit payload (the body of a [`FRAME_EXIT`] frame).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecExit {
    /// Child process exit code (negative = error/timeout).
    pub exit_code: i32,
    /// Optional error message (e.g. spawn failure or timeout).
    pub error_message: String,
}

/// Encode a binary data frame: `[kind][len: u32 LE][payload]`.
pub fn encode_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Encode the [`FRAME_EXIT`] frame for the given exit code / message.
pub fn encode_exit_frame(
    exit_code: i32,
    error_message: &str,
) -> Result<Vec<u8>, serde_json::Error> {
    let payload = serde_json::to_vec(&ExecExit {
        exit_code,
        error_message: error_message.to_string(),
    })?;
    Ok(encode_frame(FRAME_EXIT, &payload))
}

/// Encode the request frame (4-byte LE length prefix + JSON [`ExecStart`]).
pub fn encode_exec_start(req: &ExecStart) -> Result<Vec<u8>, serde_json::Error> {
    let json = serde_json::to_vec(req)?;
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/// Decode an [`ExecStart`] from a JSON payload (the bytes after the 4-byte
/// length prefix). Used by the daemon after reading the framed request.
pub fn decode_exec_start(payload: &[u8]) -> Result<ExecStart, serde_json::Error> {
    serde_json::from_slice(payload)
}

/// Write the [`ExecStart`] request frame to a synchronous stream.
pub fn write_exec_start<W: Write>(w: &mut W, req: &ExecStart) -> io::Result<()> {
    let frame = encode_exec_start(req).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("encode ExecStart: {e}"))
    })?;
    w.write_all(&frame)
}

/// One decoded data frame read from a synchronous stream.
#[derive(Debug, PartialEq, Eq)]
pub struct DataFrame {
    /// Frame kind ([`FRAME_STDOUT`] / [`FRAME_STDERR`] / [`FRAME_EXIT`]).
    pub kind: u8,
    /// Frame payload bytes.
    pub payload: Vec<u8>,
}

/// Read one data frame from a synchronous stream.
///
/// Returns `Ok(None)` on a *clean* EOF at a frame boundary (the daemon closed
/// the connection after the terminal frame, or without sending one). A partial
/// frame followed by EOF is surfaced as an `UnexpectedEof` error.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<DataFrame>> {
    let mut header = [0u8; 5];
    // Read the first header byte separately so a boundary EOF is reported as
    // "no more frames" rather than an error.
    match r.read(&mut header[..1])? {
        0 => return Ok(None),
        1 => {}
        _ => unreachable!("read into a 1-byte slice cannot exceed 1"),
    }
    r.read_exact(&mut header[1..])?;
    let kind = header[0];
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_IPC_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("IPC frame too large: {len} bytes"),
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some(DataFrame { kind, payload }))
}

/// Read one data frame from an async stream. The exact tokio mirror of
/// [`read_frame`] used by the daemon's [`crate::bridge::stream_exec_on_guest`]
/// to drain inbound [`FRAME_STDIN`] frames from the IPC client concurrently
/// with the guest's stdout/stderr/control streams.
///
/// Returns `Ok(None)` on a *clean* EOF at a frame boundary (the IPC client
/// closed its half of the connection — this is the daemon's signal to
/// shutdown the guest's stdin). A partial frame followed by EOF is surfaced
/// as `UnexpectedEof`.
pub async fn read_frame_async<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<DataFrame>> {
    let mut first = [0u8; 1];
    match r.read(&mut first).await? {
        0 => return Ok(None),
        1 => {}
        _ => unreachable!("read into a 1-byte slice cannot exceed 1"),
    }
    let mut tail = [0u8; 4];
    r.read_exact(&mut tail).await?;
    let kind = first[0];
    let len = u32::from_le_bytes(tail) as usize;
    if len > MAX_IPC_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("IPC frame too large: {len} bytes"),
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(Some(DataFrame { kind, payload }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn exec_start_roundtrips() {
        let req = ExecStart {
            script_code: "echo hi".into(),
            working_directory: "C:\\work".into(),
            timeout_ms: 30_000,
        };
        let frame = encode_exec_start(&req).unwrap();
        let declared = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(declared, frame.len() - 4);
        assert_eq!(decode_exec_start(&frame[4..]).unwrap(), req);
    }

    #[test]
    fn data_frame_roundtrips() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&encode_frame(FRAME_STDOUT, b"hello"));
        buf.extend_from_slice(&encode_frame(FRAME_STDERR, b"warn"));
        buf.extend_from_slice(&encode_exit_frame(42, "boom").unwrap());

        let mut cur = Cursor::new(buf);
        let f1 = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(f1.kind, FRAME_STDOUT);
        assert_eq!(f1.payload, b"hello");
        let f2 = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(f2.kind, FRAME_STDERR);
        assert_eq!(f2.payload, b"warn");
        let f3 = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(f3.kind, FRAME_EXIT);
        let exit: ExecExit = serde_json::from_slice(&f3.payload).unwrap();
        assert_eq!(
            exit,
            ExecExit {
                exit_code: 42,
                error_message: "boom".into()
            }
        );
        // Clean EOF at a frame boundary.
        assert_eq!(read_frame(&mut cur).unwrap(), None);
    }

    #[test]
    fn partial_frame_is_unexpected_eof() {
        // kind + truncated length header.
        let buf = vec![FRAME_STDOUT, 0x10, 0x00];
        let mut cur = Cursor::new(buf);
        let err = read_frame(&mut cur).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn oversize_frame_is_rejected() {
        let mut buf = Vec::new();
        buf.push(FRAME_STDOUT);
        buf.extend_from_slice(&((MAX_IPC_FRAME as u32) + 1).to_le_bytes());
        let mut cur = Cursor::new(buf);
        let err = read_frame(&mut cur).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
