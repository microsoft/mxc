// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Plain-JSON emitter for captureDenials output files.
//!
//! The output file is a single JSON document with two fields — the array
//! of unique denials and a terminating summary:
//!
//! ```json
//! {
//!   "denials": [
//!     { "resource": "C:\\Users\\test\\secret.txt", "resourceType": "file",
//!       "accessType": "read", "pid": 1234, "filetime": 132847890123456789 }
//!   ],
//!   "summary": { "exitCode": 0, "totalDenials": 1,
//!                "deniedResourcesTruncated": false }
//! }
//! ```
//!
//! A host application reads the whole file, deserialises it into
//! [`DenialsDocument`], and regenerates its sandbox policy from the
//! `denials` array. The document is self-contained: one file is written
//! per `wxc-exec` invocation, so there is no record framing to parse.
//!
//! Separately, the runner prints a one-line [`DenialsOutputPointer`] to
//! its own stderr so a caller can locate the file without scanning the
//! filesystem — see that type for the pointer contract.
//!
//! This module is transport-agnostic — it writes to any [`io::Write`],
//! so the same code path serves the on-disk output file and in-memory
//! test buffers.

use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use crate::model::DeniedResource;
use crate::summary::DenialSummary;

/// The complete on-disk captureDenials output document.
///
/// Serialises to a single JSON object `{ "denials": [...], "summary": {...} }`.
/// `denials` is already de-duplicated by the decoder, so consumers can
/// treat every entry as a unique `(resource, accessType)` observation, and
/// `summary.total_denials` equals `denials.len()` for a non-truncated
/// capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DenialsDocument {
    /// The unique denials observed during the capture.
    pub denials: Vec<DeniedResource>,
    /// Terminating summary (exit code, count, truncation flag).
    pub summary: DenialSummary,
}

impl DenialsDocument {
    /// Builds a document from a de-duplicated denial set and its summary.
    #[must_use]
    pub fn new(denials: Vec<DeniedResource>, summary: DenialSummary) -> Self {
        Self { denials, summary }
    }
}

/// Writes the captureDenials document as pretty-printed JSON followed by a
/// trailing newline, then flushes the writer.
///
/// # Errors
///
/// Returns any [`io::Error`] from the underlying writer, or a
/// serialisation error surfaced as [`io::ErrorKind::Other`].
pub fn write_document<W: Write>(writer: &mut W, document: &DenialsDocument) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(document).map_err(io::Error::other)?;
    writer.write_all(&json)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

/// The single structured line a runner prints to its own stderr to point a
/// caller at a freshly written captureDenials output file.
///
/// It is one self-describing JSON object on its own line, tagged
/// `"type":"captureDenials"` so a consumer scanning `wxc-exec`'s stderr can
/// distinguish it from arbitrary workload output. It echoes the file's
/// [`DenialSummary`] so a caller can decide whether to open the file at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DenialsOutputPointer {
    /// Discriminator; always the string `"captureDenials"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Absolute path to the JSON denials output file.
    pub output_path: String,
    /// Exit code of the sandboxed child (mirrors the file's summary).
    pub exit_code: i32,
    /// Count of unique denials written (mirrors the file's summary).
    pub total_denials: usize,
    /// Whether the emitted denial set was truncated (mirrors the summary).
    pub denied_resources_truncated: bool,
}

impl DenialsOutputPointer {
    /// The fixed `type` discriminator value.
    pub const KIND: &'static str = "captureDenials";

    /// Builds a pointer for `output_path` echoing `summary`.
    #[must_use]
    pub fn new(output_path: impl Into<String>, summary: &DenialSummary) -> Self {
        Self {
            kind: Self::KIND.to_string(),
            output_path: output_path.into(),
            exit_code: summary.exit_code,
            total_denials: summary.total_denials,
            denied_resources_truncated: summary.denied_resources_truncated,
        }
    }

    /// Serialises the pointer to a single-line JSON string (no trailing
    /// newline). A fixed-shape struct of strings/ints/bools always
    /// serialises, so this is effectively infallible.
    #[must_use]
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                r#"{{"type":"{}","outputPath":"","exitCode":{},"totalDenials":{},"deniedResourcesTruncated":{}}}"#,
                Self::KIND,
                self.exit_code,
                self.total_denials,
                self.denied_resources_truncated
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AccessType, DeniedResource, ResourceType};

    fn sample(resource: &str) -> DeniedResource {
        DeniedResource {
            resource: resource.to_string(),
            resource_type: ResourceType::File,
            access_type: AccessType::Read,
            pid: 100,
            filetime: 200,
        }
    }

    #[test]
    fn write_document_emits_single_json_object_with_denials_and_summary() {
        let doc = DenialsDocument::new(
            vec![sample(r"C:\a"), sample(r"C:\b")],
            DenialSummary::new(0, 2, false),
        );
        let mut buf = Vec::new();
        write_document(&mut buf, &doc).unwrap();

        let text = String::from_utf8(buf).unwrap();
        assert!(text.ends_with('\n'));
        // No RFC 7464 record separators — this is a plain JSON document.
        assert!(!text.contains('\u{1e}'));
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["denials"].as_array().unwrap().len(), 2);
        assert_eq!(value["summary"]["totalDenials"], 2);
        assert_eq!(value["denials"][0]["resourceType"], "file");
    }

    #[test]
    fn write_document_round_trips() {
        let doc = DenialsDocument::new(vec![sample(r"C:\a")], DenialSummary::new(7, 1, true));
        let mut buf = Vec::new();
        write_document(&mut buf, &doc).unwrap();
        let parsed: DenialsDocument = serde_json::from_slice(&buf).unwrap();
        assert_eq!(doc, parsed);
    }

    #[test]
    fn empty_capture_still_writes_document_with_summary() {
        let doc = DenialsDocument::new(vec![], DenialSummary::new(0, 0, false));
        let mut buf = Vec::new();
        write_document(&mut buf, &doc).unwrap();
        let parsed: DenialsDocument = serde_json::from_slice(&buf).unwrap();
        assert!(parsed.denials.is_empty());
        assert_eq!(parsed.summary.total_denials, 0);
    }

    #[test]
    fn pointer_is_single_line_tagged_json_echoing_summary() {
        let summary = DenialSummary::new(3, 5, true);
        let pointer = DenialsOutputPointer::new(r"C:\out\denials.json", &summary);
        let line = pointer.to_line();

        assert!(!line.contains('\n'));
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["type"], "captureDenials");
        assert_eq!(value["outputPath"], r"C:\out\denials.json");
        assert_eq!(value["exitCode"], 3);
        assert_eq!(value["totalDenials"], 5);
        assert_eq!(value["deniedResourcesTruncated"], true);
    }

    #[test]
    fn pointer_round_trips_through_json() {
        let summary = DenialSummary::new(0, 0, false);
        let pointer = DenialsOutputPointer::new("out.json", &summary);
        let parsed: DenialsOutputPointer = serde_json::from_str(&pointer.to_line()).unwrap();
        assert_eq!(pointer, parsed);
    }
}
