// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared captureDenials stderr-streaming protocol used by both the
//! AppContainer and BaseContainer runners.
//!
//! Wire format on stderr (one line per *unique* `(path, accessType)`):
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
//! terminates the stream for a given `wxc-exec` invocation;
//! `totalDenials` is the count of *unique* `(path, accessType)`
//! pairs (matches the number of streamed `denial` lines), which is
//! what the SDK's prompt UX cares about.
//!
//! Setting the environment variable `MXC_DENIAL_VERBOSE=1` adds a
//! `rawEventCount` field to the summary that exposes the pre-dedupe
//! kernel event count for diagnostics. This is gated because the
//! raw count is misleading for end-user reporting: a "10 denials"
//! workload typically generates several hundred kernel access-check
//! events for a handful of unique resources (e.g. locale-aware code
//! re-reading the same registry key on every `printf`).

/// ASCII Record Separator (0x1E). Prefixed to every captureDenials
/// streaming line.
pub(crate) const DENIAL_STREAM_MARKER: u8 = 0x1E;

/// Env var that opts into raw (pre-dedupe) event count in the summary.
const VERBOSE_ENV_VAR: &str = "MXC_DENIAL_VERBOSE";

/// Drains `rx` until the channel closes, writing one
/// `\x1e<ndjson>\n` line to stderr per *newly-seen*
/// `(path, accessType)` pair. Runs on its own thread so the ETW
/// callback never blocks on stderr I/O.
///
/// Returns the number of unique `(path, accessType)` pairs that were
/// streamed, so the caller can fold it into the summary line.
///
/// Stream-time dedupe rationale: in practice a single process run
/// can trigger the same denial hundreds of times in a tight loop
/// (e.g. locale-aware code re-reading
/// `\REGISTRY\USER\.DEFAULT\Control Panel\International` on every
/// `printf`). For the SDK's prompt-the-user UX every duplicate is
/// pure noise — the user has already been asked about that resource
/// — and emitting them all balloons stderr by ~100x. The dedupe set
/// is per-invocation (lives only as long as this writer thread).
///
/// The channel closes when the `CollectorHandle` is dropped (the
/// sender lives inside its `CallbackContext`). Receiving `Err` is
/// the normal teardown signal.
pub(crate) fn stream_denials_to_stderr(
    rx: std::sync::mpsc::Receiver<denial_capture::DeniedResource>,
) -> usize {
    use std::collections::HashSet;
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();
    let mut seen: HashSet<(String, denial_capture::AccessType)> = HashSet::new();
    while let Ok(resource) = rx.recv() {
        // Dedupe on (path, accessType). `resourceType` and `pid`
        // are deterministic given path; `filetime` would defeat
        // dedupe entirely if included.
        let key = (resource.path.clone(), resource.access_type);
        if !seen.insert(key) {
            continue;
        }
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
    seen.len()
}

/// Returns true when the user has opted into verbose summary output
/// via the `MXC_DENIAL_VERBOSE=1` environment variable. Any non-empty
/// value other than `"0"` or `"false"` counts as opt-in.
fn verbose_summary_enabled() -> bool {
    match std::env::var(VERBOSE_ENV_VAR) {
        Ok(v) => {
            let t = v.trim();
            !t.is_empty() && t != "0" && !t.eq_ignore_ascii_case("false")
        }
        Err(_) => false,
    }
}

/// Emits the per-invocation summary line on stderr. SDK consumers
/// use this as the terminator marker for the captureDenials stream:
/// after the summary they can finalize the prompt list and either
/// drive the user-approval UX or hand control back to the workload's
/// caller.
///
/// `unique_denials` is the count of distinct `(path, accessType)`
/// pairs that were streamed (== the number of `denial` lines a
/// consumer parsed). `raw_event_count` is the pre-dedupe kernel
/// event count and is only included in the wire format when the
/// caller has opted into verbose mode (`MXC_DENIAL_VERBOSE=1`).
pub(crate) fn emit_denial_summary_line(
    exit_code: i32,
    unique_denials: usize,
    raw_event_count: usize,
    truncated: bool,
) {
    use std::io::Write;
    let envelope = if verbose_summary_enabled() {
        serde_json::json!({
            "type": "summary",
            "exitCode": exit_code,
            "totalDenials": unique_denials,
            "deniedResourcesTruncated": truncated,
            "rawEventCount": raw_event_count,
        })
    } else {
        serde_json::json!({
            "type": "summary",
            "exitCode": exit_code,
            "totalDenials": unique_denials,
            "deniedResourcesTruncated": truncated,
        })
    };
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
