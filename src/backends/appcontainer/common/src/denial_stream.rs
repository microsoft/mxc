// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared captureDenials stderr-streaming protocol used by both the
//! AppContainer and BaseContainer runners.
//!
//! Wire format on stderr (one denial per line):
//!
//! ```text
//! \x1e{"type":"denial","path":"...","resourceType":"...","accessType":"...","pid":N,"filetime":N}\n
//! ...
//! \x1e{"type":"summary","exitCode":N,"totalDenials":N,"deniedResourcesTruncated":bool}\n
//! ```
//!
//! Each line is prefixed with ASCII Record Separator (0x1E). This
//! byte effectively never appears in legitimate workload stderr, so
//! SDK consumers can split stderr on it to reliably separate MXC
//! envelopes from the workload's own stderr writes. The summary line
//! terminates the stream for a given `wxc-exec` invocation.

/// ASCII Record Separator (0x1E). Prefixed to every captureDenials
/// streaming line.
pub(crate) const DENIAL_STREAM_MARKER: u8 = 0x1E;

/// Drains `rx` until the channel closes, writing one
/// `\x1e<ndjson>\n` line to stderr per captured DeniedResource. Runs
/// on its own thread so the ETW callback never blocks on stderr I/O.
///
/// The channel closes when the `CollectorHandle` is dropped (the
/// sender lives inside its `CallbackContext`). Receiving `Err` is
/// the normal teardown signal.
pub(crate) fn stream_denials_to_stderr(
    rx: std::sync::mpsc::Receiver<denial_capture::DeniedResource>,
) {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();
    while let Ok(resource) = rx.recv() {
        let envelope = serde_json::json!({
            "type": "denial",
            "path": resource.path,
            "resourceType": resource.resource_type,
            "accessType": resource.access_type,
            "pid": resource.pid,
            "filetime": resource.filetime,
        });
        let json = match serde_json::to_string(&envelope) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let _ = stderr.write_all(&[DENIAL_STREAM_MARKER]);
        let _ = stderr.write_all(json.as_bytes());
        let _ = stderr.write_all(b"\n");
        let _ = stderr.flush();
    }
}

/// Emits the per-invocation summary line on stderr. SDK consumers
/// use this as the terminator marker for the captureDenials stream:
/// after the summary they can finalize the prompt list and either
/// drive the user-approval UX or hand control back to the workload's
/// caller.
pub(crate) fn emit_denial_summary_line(exit_code: i32, total_denials: usize, truncated: bool) {
    use std::io::Write;
    let envelope = serde_json::json!({
        "type": "summary",
        "exitCode": exit_code,
        "totalDenials": total_denials,
        "deniedResourcesTruncated": truncated,
    });
    let json = match serde_json::to_string(&envelope) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(&[DENIAL_STREAM_MARKER]);
    let _ = stderr.write_all(json.as_bytes());
    let _ = stderr.write_all(b"\n");
    let _ = stderr.flush();
}
