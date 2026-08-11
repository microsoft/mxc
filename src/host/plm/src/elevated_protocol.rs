// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Framing shared by the unelevated PLM parent and its restricted elevated child.

use std::io::{self, Read, Write};

const MAGIC: &[u8; 8] = b"MXCPLM01";
const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 20;

pub const MAX_ERROR_BYTES: u64 = 64 * 1024;
pub const MAX_TRACE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ResponseKind {
    Success = 0,
    Trace = 1,
    Error = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseHeader {
    pub kind: ResponseKind,
    pub payload_len: u64,
}

pub fn write_header(
    writer: &mut impl Write,
    kind: ResponseKind,
    payload_len: u64,
) -> io::Result<()> {
    validate_payload(kind, payload_len)?;
    let mut header = [0u8; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8] = VERSION;
    header[9] = kind as u8;
    header[12..20].copy_from_slice(&payload_len.to_le_bytes());
    writer.write_all(&header)
}

pub fn read_header(reader: &mut impl Read) -> io::Result<ResponseHeader> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header)?;
    if &header[..8] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid PLM elevated-response magic",
        ));
    }
    if header[8] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported PLM elevated-response version",
        ));
    }
    if header[10] != 0 || header[11] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid PLM elevated-response reserved bytes",
        ));
    }
    let kind = match header[9] {
        0 => ResponseKind::Success,
        1 => ResponseKind::Trace,
        2 => ResponseKind::Error,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid PLM elevated-response kind",
            ))
        }
    };
    let payload_len = u64::from_le_bytes(
        header[12..20]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid frame length"))?,
    );
    validate_payload(kind, payload_len)?;
    Ok(ResponseHeader { kind, payload_len })
}

fn validate_payload(kind: ResponseKind, payload_len: u64) -> io::Result<()> {
    let valid = match kind {
        ResponseKind::Success => payload_len == 0,
        ResponseKind::Trace => payload_len <= MAX_TRACE_BYTES,
        ResponseKind::Error => payload_len <= MAX_ERROR_BYTES,
    };
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {kind:?} payload length {payload_len}"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_each_valid_header_kind() {
        for expected in [
            ResponseHeader {
                kind: ResponseKind::Success,
                payload_len: 0,
            },
            ResponseHeader {
                kind: ResponseKind::Trace,
                payload_len: 1234,
            },
            ResponseHeader {
                kind: ResponseKind::Error,
                payload_len: 42,
            },
        ] {
            let mut bytes = Vec::new();
            write_header(&mut bytes, expected.kind, expected.payload_len).unwrap();
            assert_eq!(read_header(&mut bytes.as_slice()).unwrap(), expected);
        }
    }

    #[test]
    fn rejects_unbounded_payloads_and_success_payloads() {
        assert!(write_header(&mut Vec::new(), ResponseKind::Success, 1).is_err());
        assert!(write_header(&mut Vec::new(), ResponseKind::Error, MAX_ERROR_BYTES + 1).is_err());
        assert!(write_header(&mut Vec::new(), ResponseKind::Trace, MAX_TRACE_BYTES + 1).is_err());
    }

    #[test]
    fn rejects_corrupt_magic_version_kind_and_reserved_bytes() {
        let mut valid = Vec::new();
        write_header(&mut valid, ResponseKind::Success, 0).unwrap();
        for index in [0usize, 8, 9, 10] {
            let mut corrupt = valid.clone();
            corrupt[index] = 0xff;
            assert!(
                read_header(&mut corrupt.as_slice()).is_err(),
                "index {index}"
            );
        }
    }
}
