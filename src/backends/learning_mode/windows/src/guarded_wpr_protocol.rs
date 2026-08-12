// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bounded framing shared by guarded WPR clients and the elevated guardian.

use std::io::{self, Read, Write};

const MAGIC: &[u8; 8] = b"MXCPLM01";
const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 20;
const ATTACH_HANDLES_MAGIC: &[u8; 8] = b"MXCATT01";
const ATTACH_HANDLES_LEN: usize = 24;

pub const MAX_ERROR_BYTES: u64 = 64 * 1024;
pub const MAX_TRACE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_ANALYSIS_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ResponseKind {
    Success = 0,
    Trace = 1,
    Error = 2,
    Stopped = 3,
    Analysis = 4,
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
            "invalid guarded WPR response magic",
        ));
    }
    if header[8] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported guarded WPR response version",
        ));
    }
    if header[10] != 0 || header[11] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid guarded WPR response reserved bytes",
        ));
    }
    let kind = match header[9] {
        0 => ResponseKind::Success,
        1 => ResponseKind::Trace,
        2 => ResponseKind::Error,
        3 => ResponseKind::Stopped,
        4 => ResponseKind::Analysis,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid guarded WPR response kind",
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
        ResponseKind::Success | ResponseKind::Stopped => payload_len == 0,
        ResponseKind::Trace => payload_len <= MAX_TRACE_BYTES,
        ResponseKind::Error => payload_len <= MAX_ERROR_BYTES,
        ResponseKind::Analysis => payload_len <= MAX_ANALYSIS_BYTES,
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

pub fn write_attach_handles(
    writer: &mut impl Write,
    job_handle: usize,
    root_process_handle: usize,
) -> io::Result<()> {
    validate_handle(job_handle, "job", io::ErrorKind::InvalidInput)?;
    validate_handle(
        root_process_handle,
        "root process",
        io::ErrorKind::InvalidInput,
    )?;
    let mut payload = [0u8; ATTACH_HANDLES_LEN];
    payload[..8].copy_from_slice(ATTACH_HANDLES_MAGIC);
    payload[8..16].copy_from_slice(&(job_handle as u64).to_le_bytes());
    payload[16..24].copy_from_slice(&(root_process_handle as u64).to_le_bytes());
    writer.write_all(&payload)
}

pub fn read_attach_handles(reader: &mut impl Read) -> io::Result<(usize, usize)> {
    let mut payload = [0u8; ATTACH_HANDLES_LEN];
    reader.read_exact(&mut payload)?;
    if &payload[..8] != ATTACH_HANDLES_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid guarded WPR attach-handles header",
        ));
    }
    let job_handle = decode_handle(&payload[8..16], "job")?;
    let root_process_handle = decode_handle(&payload[16..24], "root process")?;
    Ok((job_handle, root_process_handle))
}

fn decode_handle(bytes: &[u8], name: &str) -> io::Result<usize> {
    let raw = u64::from_le_bytes(bytes.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid guarded WPR {name} handle"),
        )
    })?);
    let handle = usize::try_from(raw).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("guarded WPR {name} handle does not fit the current architecture"),
        )
    })?;
    validate_handle(handle, name, io::ErrorKind::InvalidData)?;
    Ok(handle)
}

fn validate_handle(handle: usize, name: &str, kind: io::ErrorKind) -> io::Result<()> {
    if handle == 0 || handle == usize::MAX {
        return Err(io::Error::new(
            kind,
            format!("invalid guarded WPR {name} handle"),
        ));
    }
    Ok(())
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
            ResponseHeader {
                kind: ResponseKind::Stopped,
                payload_len: 0,
            },
            ResponseHeader {
                kind: ResponseKind::Analysis,
                payload_len: 5678,
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
        assert!(write_header(&mut Vec::new(), ResponseKind::Stopped, 1).is_err());
        assert!(write_header(&mut Vec::new(), ResponseKind::Error, MAX_ERROR_BYTES + 1).is_err());
        assert!(write_header(&mut Vec::new(), ResponseKind::Trace, MAX_TRACE_BYTES + 1).is_err());
        assert!(write_header(
            &mut Vec::new(),
            ResponseKind::Analysis,
            MAX_ANALYSIS_BYTES + 1
        )
        .is_err());
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

    #[test]
    fn round_trips_attach_handles() {
        let mut bytes = Vec::new();
        write_attach_handles(&mut bytes, 0x1234, 0x5678).unwrap();
        assert_eq!(
            read_attach_handles(&mut bytes.as_slice()).unwrap(),
            (0x1234, 0x5678)
        );
    }

    #[test]
    fn rejects_invalid_attach_handles_and_magic() {
        assert!(write_attach_handles(&mut Vec::new(), 0, 1).is_err());
        assert!(write_attach_handles(&mut Vec::new(), 1, 0).is_err());
        assert!(write_attach_handles(&mut Vec::new(), usize::MAX, 1).is_err());
        assert!(write_attach_handles(&mut Vec::new(), 1, usize::MAX).is_err());
        let mut bytes = Vec::new();
        write_attach_handles(&mut bytes, 42, 43).unwrap();
        bytes[0] ^= 0xff;
        assert!(read_attach_handles(&mut bytes.as_slice()).is_err());
    }
}
