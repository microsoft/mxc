// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bounded framing shared by guarded WPR clients and the elevated guardian.

use std::io::{self, Read, Write};

use learning_mode_core::ProcessLifetime;

const MAGIC: &[u8; 8] = b"MXCPLM01";
const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 20;
const SCOPE_MAGIC: &[u8; 8] = b"MXCSCP01";
const SCOPE_HEADER_LEN: usize = 16;
const PROCESS_LIFETIME_LEN: usize = 20;

pub const MAX_ERROR_BYTES: u64 = 64 * 1024;
pub const MAX_TRACE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_ANALYSIS_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_PROCESS_LIFETIMES: usize = 4096;

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

pub fn write_process_lifetimes(
    writer: &mut impl Write,
    lifetimes: &[ProcessLifetime],
) -> io::Result<()> {
    validate_process_lifetimes(lifetimes)?;
    let count = u32::try_from(lifetimes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many process lifetimes"))?;
    let mut header = [0u8; SCOPE_HEADER_LEN];
    header[..8].copy_from_slice(SCOPE_MAGIC);
    header[8..12].copy_from_slice(&count.to_le_bytes());
    writer.write_all(&header)?;
    for lifetime in lifetimes {
        writer.write_all(&lifetime.pid.to_le_bytes())?;
        writer.write_all(&lifetime.start_filetime.to_le_bytes())?;
        writer.write_all(&lifetime.end_filetime.to_le_bytes())?;
    }
    Ok(())
}

pub fn read_process_lifetimes(reader: &mut impl Read) -> io::Result<Vec<ProcessLifetime>> {
    let mut header = [0u8; SCOPE_HEADER_LEN];
    reader.read_exact(&mut header)?;
    if &header[..8] != SCOPE_MAGIC || header[12..16] != [0; 4] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid guarded WPR process-lifetime header",
        ));
    }
    let count = u32::from_le_bytes(
        header[8..12]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid lifetime count"))?,
    ) as usize;
    if count == 0 || count > MAX_PROCESS_LIFETIMES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid guarded WPR process-lifetime count {count}"),
        ));
    }
    let mut lifetimes = Vec::with_capacity(count);
    let mut record = [0u8; PROCESS_LIFETIME_LEN];
    for _ in 0..count {
        reader.read_exact(&mut record)?;
        lifetimes.push(ProcessLifetime {
            pid: u32::from_le_bytes(record[..4].try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid process identifier")
            })?),
            start_filetime: u64::from_le_bytes(record[4..12].try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid process start time")
            })?),
            end_filetime: u64::from_le_bytes(record[12..20].try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid process end time")
            })?),
        });
    }
    validate_process_lifetimes(&lifetimes)?;
    Ok(lifetimes)
}

fn validate_process_lifetimes(lifetimes: &[ProcessLifetime]) -> io::Result<()> {
    if lifetimes.is_empty() || lifetimes.len() > MAX_PROCESS_LIFETIMES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("guarded WPR requires between 1 and {MAX_PROCESS_LIFETIMES} process lifetimes"),
        ));
    }
    if let Some(lifetime) = lifetimes.iter().find(|lifetime| {
        lifetime.pid == 0
            || lifetime.start_filetime == 0
            || lifetime.end_filetime < lifetime.start_filetime
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "invalid guarded WPR process lifetime for PID {}",
                lifetime.pid
            ),
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
    fn round_trips_bounded_process_lifetimes() {
        let expected = vec![
            ProcessLifetime {
                pid: 42,
                start_filetime: 100,
                end_filetime: 200,
            },
            ProcessLifetime {
                pid: 42,
                start_filetime: 300,
                end_filetime: 400,
            },
        ];
        let mut bytes = Vec::new();
        write_process_lifetimes(&mut bytes, &expected).unwrap();
        assert_eq!(
            read_process_lifetimes(&mut bytes.as_slice()).unwrap(),
            expected
        );
    }

    #[test]
    fn rejects_empty_invalid_and_unbounded_process_lifetimes() {
        assert!(write_process_lifetimes(&mut Vec::new(), &[]).is_err());
        assert!(write_process_lifetimes(
            &mut Vec::new(),
            &[ProcessLifetime {
                pid: 0,
                start_filetime: 1,
                end_filetime: 2,
            }]
        )
        .is_err());
        assert!(write_process_lifetimes(
            &mut Vec::new(),
            &vec![
                ProcessLifetime {
                    pid: 1,
                    start_filetime: 1,
                    end_filetime: 2,
                };
                MAX_PROCESS_LIFETIMES + 1
            ]
        )
        .is_err());
    }
}
