// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire frame types, encoder, and incremental accumulator for the exec duplex.

use crate::mxc_common::mxc_error::MxcError;

/// Upper bound on a single frame payload (relay chunk size).
pub const MAX_FRAME_PAYLOAD: usize = 64 * 1024;

/// Binary relay frame type. Wire byte values are load-bearing and must match
/// the `DesktopControl.Exec` guest host.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FrameType {
    ExecStart = 0x01,
    Stdin = 0x02,
    StdinClose = 0x03,
    Cancel = 0x04,
    Resize = 0x05,
    Started = 0x11,
    Stdout = 0x12,
    Stderr = 0x13,
    Exit = 0x14,
    Error = 0x15,
}

impl FrameType {
    pub fn to_wire(self) -> u8 {
        self as u8
    }

    pub fn from_wire(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::ExecStart),
            0x02 => Some(Self::Stdin),
            0x03 => Some(Self::StdinClose),
            0x04 => Some(Self::Cancel),
            0x05 => Some(Self::Resize),
            0x11 => Some(Self::Started),
            0x12 => Some(Self::Stdout),
            0x13 => Some(Self::Stderr),
            0x14 => Some(Self::Exit),
            0x15 => Some(Self::Error),
            _ => None,
        }
    }
}

/// Encode one frame: `[type][len:u32 big-endian][payload]`.
pub fn encode_frame(kind: FrameType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind.to_wire());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// One decoded frame. `kind` is `None` for a valid-but-unknown type byte;
/// `raw_kind` is always the wire byte (retained for forward-compatibility).
#[derive(Debug, PartialEq, Eq)]
pub struct DataFrame {
    pub kind: Option<FrameType>,
    pub raw_kind: u8,
    pub payload: Vec<u8>,
}

/// Incremental frame parser: `extend` with received bytes, then pull complete
/// frames with `next_frame`. Tolerates partial reads (bytes accumulate across
/// calls), which is required for the timeout-poll relay loop.
#[derive(Default)]
pub struct FrameAccumulator {
    buf: Vec<u8>,
}

impl FrameAccumulator {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn extend(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Pull the next complete frame, or `Ok(None)` if more bytes are needed.
    /// Rejects an over-size declared length as a hard protocol error.
    pub fn next_frame(&mut self) -> Result<Option<DataFrame>, MxcError> {
        if self.buf.len() < 5 {
            return Ok(None);
        }
        let raw_kind = self.buf[0];
        let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
        if len > MAX_FRAME_PAYLOAD {
            return Err(MxcError::backend_error(format!(
                "exec frame too large: {len} bytes (max {MAX_FRAME_PAYLOAD})"
            )));
        }
        if self.buf.len() < 5 + len {
            return Ok(None);
        }
        let payload = self.buf[5..5 + len].to_vec();
        self.buf.drain(..5 + len);
        Ok(Some(DataFrame {
            kind: FrameType::from_wire(raw_kind),
            raw_kind,
            payload,
        }))
    }
}

#[cfg(test)]
mod encode_tests {
    use super::super::frame::{encode_frame, FrameType, MAX_FRAME_PAYLOAD};

    #[test]
    fn frame_type_wire_values_are_stable() {
        assert_eq!(FrameType::ExecStart.to_wire(), 0x01);
        assert_eq!(FrameType::Stdin.to_wire(), 0x02);
        assert_eq!(FrameType::StdinClose.to_wire(), 0x03);
        assert_eq!(FrameType::Cancel.to_wire(), 0x04);
        assert_eq!(FrameType::Resize.to_wire(), 0x05);
        assert_eq!(FrameType::Started.to_wire(), 0x11);
        assert_eq!(FrameType::Stdout.to_wire(), 0x12);
        assert_eq!(FrameType::Stderr.to_wire(), 0x13);
        assert_eq!(FrameType::Exit.to_wire(), 0x14);
        assert_eq!(FrameType::Error.to_wire(), 0x15);
        assert_eq!(FrameType::from_wire(0x12), Some(FrameType::Stdout));
        assert_eq!(FrameType::from_wire(0x99), None);
    }

    #[test]
    fn encode_frame_uses_big_endian_length() {
        let out = encode_frame(FrameType::Stdout, b"hi");
        // [type][len:u32 BE][payload]
        assert_eq!(out, vec![0x12, 0x00, 0x00, 0x00, 0x02, b'h', b'i']);
    }

    #[test]
    fn max_frame_payload_is_64_kib() {
        assert_eq!(MAX_FRAME_PAYLOAD, 64 * 1024);
    }
}

#[cfg(test)]
mod accumulator_tests {
    use super::super::frame::{encode_frame, FrameAccumulator, FrameType, MAX_FRAME_PAYLOAD};

    #[test]
    fn parses_a_whole_frame() {
        let mut acc = FrameAccumulator::new();
        acc.extend(&encode_frame(FrameType::Stdout, b"hello"));
        let f = acc.next_frame().unwrap().unwrap();
        assert_eq!(f.kind, Some(FrameType::Stdout));
        assert_eq!(f.payload, b"hello");
        assert!(acc.next_frame().unwrap().is_none());
    }

    #[test]
    fn assembles_across_partial_extends() {
        let bytes = encode_frame(FrameType::Stderr, b"warn");
        let mut acc = FrameAccumulator::new();
        for b in &bytes {
            assert!(acc.next_frame().unwrap().is_none());
            acc.extend(&[*b]);
        }
        let f = acc.next_frame().unwrap().unwrap();
        assert_eq!(f.kind, Some(FrameType::Stderr));
        assert_eq!(f.payload, b"warn");
    }

    #[test]
    fn parses_two_frames_from_one_buffer() {
        let mut buf = encode_frame(FrameType::Stdout, b"a");
        buf.extend(encode_frame(FrameType::Exit, b"{}"));
        let mut acc = FrameAccumulator::new();
        acc.extend(&buf);
        assert_eq!(
            acc.next_frame().unwrap().unwrap().kind,
            Some(FrameType::Stdout)
        );
        assert_eq!(
            acc.next_frame().unwrap().unwrap().kind,
            Some(FrameType::Exit)
        );
        assert!(acc.next_frame().unwrap().is_none());
    }

    #[test]
    fn retains_unknown_type_as_raw_kind() {
        // type 0x77 (unknown), len 1, payload [0xAB]
        let mut acc = FrameAccumulator::new();
        acc.extend(&[0x77, 0x00, 0x00, 0x00, 0x01, 0xAB]);
        let f = acc.next_frame().unwrap().unwrap();
        assert_eq!(f.kind, None);
        assert_eq!(f.raw_kind, 0x77);
        assert_eq!(f.payload, vec![0xAB]);
    }

    #[test]
    fn rejects_oversize_length() {
        let mut acc = FrameAccumulator::new();
        let bogus_len = (MAX_FRAME_PAYLOAD as u32) + 1;
        let mut header = vec![FrameType::Stdout.to_wire()];
        header.extend_from_slice(&bogus_len.to_be_bytes());
        acc.extend(&header);
        assert!(acc.next_frame().is_err());
    }
}
