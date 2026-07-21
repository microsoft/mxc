// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Framed NDJSON emitter for captureDenials output files.
//!
//! The output file follows the [RFC 7464] "JSON Text Sequences" framing:
//! every record is preceded by an ASCII Record Separator (`0x1E`) and
//! terminated by a line feed (`0x0A`):
//!
//! ```text
//! <RS>{"type":"denial", ...}<LF>
//! <RS>{"type":"denial", ...}<LF>
//! <RS>{"type":"summary", ...}<LF>
//! ```
//!
//! The `0x1E` prefix is load-bearing: it effectively never appears in
//! legitimate workload output, so a consumer can split on it to reliably
//! separate MXC envelopes from any interleaved bytes. The summary frame
//! terminates the stream for one `wxc-exec` invocation.
//!
//! This module is transport-agnostic — it writes to any [`io::Write`],
//! so the same code path serves the on-disk output file and in-memory
//! test buffers.
//!
//! [RFC 7464]: https://www.rfc-editor.org/rfc/rfc7464

use std::io::{self, Write};

use crate::frame::DenialFrame;
use crate::model::DeniedResource;
use crate::summary::DenialSummary;

/// ASCII Record Separator (`0x1E`), prefixed to every framed record.
pub const RECORD_SEPARATOR: u8 = 0x1E;

/// Writes one framed record: `RS` + compact JSON + `LF`.
///
/// # Errors
///
/// Returns any [`io::Error`] from the underlying writer, or a
/// serialisation error surfaced as [`io::ErrorKind::InvalidData`].
pub fn write_frame<W: Write>(writer: &mut W, frame: &DenialFrame) -> io::Result<()> {
    let json = serde_json::to_vec(frame).map_err(io::Error::other)?;
    writer.write_all(&[RECORD_SEPARATOR])?;
    writer.write_all(&json)?;
    writer.write_all(b"\n")
}

/// Writes a complete captureDenials stream: one `denial` frame per
/// resource, followed by exactly one terminating `summary` frame, then
/// flushes the writer.
///
/// The caller is responsible for having already de-duplicated
/// `resources`; `summary.total_denials` should equal `resources.len()`
/// for a non-truncated capture.
///
/// # Errors
///
/// Returns the first [`io::Error`] encountered while writing or flushing.
pub fn write_stream<W: Write>(
    writer: &mut W,
    resources: &[DeniedResource],
    summary: &DenialSummary,
) -> io::Result<()> {
    for resource in resources {
        let frame = DenialFrame::Denial(resource.clone());
        write_frame(writer, &frame)?;
    }
    write_frame(writer, &DenialFrame::Summary(*summary))?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AccessType, ResourceType};

    fn sample(path: &str) -> DeniedResource {
        DeniedResource {
            path: path.to_string(),
            resource_type: ResourceType::File,
            access_type: AccessType::Read,
            pid: 100,
            filetime: 200,
        }
    }

    #[test]
    fn write_frame_prefixes_rs_and_terminates_lf() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &DenialFrame::Denial(sample(r"C:\a"))).unwrap();
        assert_eq!(buf[0], RECORD_SEPARATOR);
        assert_eq!(*buf.last().unwrap(), b'\n');
        // Exactly one RS and one LF for a single record.
        assert_eq!(buf.iter().filter(|&&b| b == RECORD_SEPARATOR).count(), 1);
        assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);
    }

    #[test]
    fn write_stream_emits_denials_then_single_summary() {
        let resources = vec![sample(r"C:\a"), sample(r"C:\b")];
        let summary = DenialSummary::new(0, 2, false);
        let mut buf = Vec::new();
        write_stream(&mut buf, &resources, &summary).unwrap();

        let text = String::from_utf8(buf).unwrap();
        let records: Vec<&str> = text
            .split(RECORD_SEPARATOR as char)
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(records.len(), 3, "2 denials + 1 summary");
        assert!(records[0].contains("\"type\":\"denial\""));
        assert!(records[1].contains("\"type\":\"denial\""));
        assert!(records[2].contains("\"type\":\"summary\""));
        assert!(records[2].contains("\"totalDenials\":2"));
    }

    #[test]
    fn written_stream_round_trips_by_splitting_on_rs() {
        let resources = vec![sample(r"C:\a")];
        let summary = DenialSummary::new(7, 1, true);
        let mut buf = Vec::new();
        write_stream(&mut buf, &resources, &summary).unwrap();

        let text = String::from_utf8(buf).unwrap();
        let frames: Vec<DenialFrame> = text
            .split(RECORD_SEPARATOR as char)
            .filter(|s| !s.trim().is_empty())
            .map(|s| serde_json::from_str(s.trim()).unwrap())
            .collect();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], DenialFrame::Denial(sample(r"C:\a")));
        assert_eq!(frames[1], DenialFrame::Summary(summary));
    }

    #[test]
    fn empty_capture_still_writes_summary() {
        let summary = DenialSummary::new(0, 0, false);
        let mut buf = Vec::new();
        write_stream(&mut buf, &[], &summary).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("\"type\":\"summary\""));
        assert_eq!(text.matches('\n').count(), 1);
    }
}
