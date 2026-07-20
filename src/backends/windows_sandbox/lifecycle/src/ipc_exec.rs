// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Binary exec framing between state-aware `wxc-exec` and the daemon.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Stdout = 1,
    Stderr = 2,
    Exit = 3,
    Stdin = 4,
}

impl FrameKind {
    pub fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Stdout),
            2 => Some(Self::Stderr),
            3 => Some(Self::Exit),
            4 => Some(Self::Stdin),
            _ => None,
        }
    }

    pub fn to_wire(self) -> u8 {
        self as u8
    }
}

/// Upper bound on a single IPC frame's payload.
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

/// Terminal exit payload (the body of a [`FrameKind::Exit`] frame).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecExit {
    /// Child process exit code (negative = error/timeout).
    pub exit_code: i32,
    /// Optional error message (e.g. spawn failure or timeout).
    pub error_message: String,
}

/// Encode a binary data frame: `[kind][len: u32 LE][payload]`.
pub fn encode_frame(kind: FrameKind, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind.to_wire());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// The 5-byte data-frame header (`[kind][len: u32 LE]`) without payload.
pub fn frame_header(kind: FrameKind, payload_len: usize) -> [u8; 5] {
    let mut h = [0u8; 5];
    h[0] = kind.to_wire();
    h[1..].copy_from_slice(&(payload_len as u32).to_le_bytes());
    h
}

/// Encode the [`FrameKind::Exit`] frame for the given exit code / message.
pub fn encode_exit_frame(
    exit_code: i32,
    error_message: &str,
) -> Result<Vec<u8>, serde_json::Error> {
    let payload = serde_json::to_vec(&ExecExit {
        exit_code,
        error_message: error_message.to_string(),
    })?;
    Ok(encode_frame(FrameKind::Exit, &payload))
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

/// Read the framed [`ExecStart`] request from an async stream.
pub async fn read_exec_start_async<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<ExecStart> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_IPC_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("ExecStart frame too large: {len} bytes"),
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    decode_exec_start(&payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("decode ExecStart: {e}")))
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
    /// Frame kind, if this peer knows it.
    pub kind: Option<FrameKind>,
    /// Raw wire frame kind byte, retained for diagnostics and forward-compatibility.
    pub raw_kind: u8,
    /// Frame payload bytes.
    pub payload: Vec<u8>,
}

/// Read one data frame from a synchronous stream.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<DataFrame>> {
    let mut header = [0u8; 5];
    match r.read(&mut header[..1])? {
        0 => return Ok(None),
        1 => {}
        _ => unreachable!("read into a 1-byte slice cannot exceed 1"),
    }
    r.read_exact(&mut header[1..])?;
    let raw_kind = header[0];
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_IPC_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("IPC frame too large: {len} bytes"),
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some(DataFrame {
        kind: FrameKind::from_wire(raw_kind),
        raw_kind,
        payload,
    }))
}

/// Async mirror of [`read_frame`].
pub async fn read_frame_async<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<DataFrame>> {
    let mut first = [0u8; 1];
    match r.read(&mut first).await? {
        0 => return Ok(None),
        1 => {}
        _ => unreachable!("read into a 1-byte slice cannot exceed 1"),
    }
    let mut tail = [0u8; 4];
    r.read_exact(&mut tail).await?;
    let raw_kind = first[0];
    let len = u32::from_le_bytes(tail) as usize;
    if len > MAX_IPC_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("IPC frame too large: {len} bytes"),
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(Some(DataFrame {
        kind: FrameKind::from_wire(raw_kind),
        raw_kind,
        payload,
    }))
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
        buf.extend_from_slice(&encode_frame(FrameKind::Stdout, b"hello"));
        buf.extend_from_slice(&encode_frame(FrameKind::Stderr, b"warn"));
        buf.extend_from_slice(&encode_exit_frame(42, "boom").unwrap());

        let mut cur = Cursor::new(buf);
        let f1 = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(f1.kind, Some(FrameKind::Stdout));
        assert_eq!(f1.payload, b"hello");
        let f2 = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(f2.kind, Some(FrameKind::Stderr));
        assert_eq!(f2.payload, b"warn");
        let f3 = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(f3.kind, Some(FrameKind::Exit));
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
        let buf = vec![FrameKind::Stdout.to_wire(), 0x10, 0x00];
        let mut cur = Cursor::new(buf);
        let err = read_frame(&mut cur).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn oversize_frame_is_rejected() {
        let mut buf = Vec::new();
        buf.push(FrameKind::Stdout.to_wire());
        buf.extend_from_slice(&((MAX_IPC_FRAME as u32) + 1).to_le_bytes());
        let mut cur = Cursor::new(buf);
        let err = read_frame(&mut cur).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
