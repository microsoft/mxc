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
    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    stream_denials_to_writer(rx, &mut handle)
}

/// Test-friendly implementation of [`stream_denials_to_stderr`]. The
/// stderr-bound variant delegates here after locking; tests pass a
/// `Vec<u8>` to capture and assert against the rendered bytes.
fn stream_denials_to_writer<W: std::io::Write>(
    rx: std::sync::mpsc::Receiver<denial_capture::DeniedResource>,
    out: &mut W,
) -> usize {
    use std::collections::HashSet;
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
        let _ = out.write_all(&[DENIAL_STREAM_MARKER]);
        let _ = out.write_all(json.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }
    seen.len()
}

/// Returns true when the user has opted into verbose summary output
/// via the `MXC_DENIAL_VERBOSE=1` environment variable. Any non-empty
/// value other than `"0"` or `"false"` counts as opt-in.
fn verbose_summary_enabled() -> bool {
    verbose_summary_enabled_from(std::env::var(VERBOSE_ENV_VAR).ok().as_deref())
}

/// Pure helper for [`verbose_summary_enabled`] that takes the env-var
/// value as a parameter so tests can exercise it without touching
/// per-process global state.
fn verbose_summary_enabled_from(value: Option<&str>) -> bool {
    match value {
        Some(v) => {
            let t = v.trim();
            !t.is_empty() && t != "0" && !t.eq_ignore_ascii_case("false")
        }
        None => false,
    }
}

/// Builds the summary envelope as serde_json::Value. Split out so
/// the formatting can be exercised by tests without touching stderr.
fn build_summary_envelope(
    exit_code: i32,
    unique_denials: usize,
    raw_event_count: usize,
    truncated: bool,
    active: bool,
    child_processes_observed: usize,
    verbose: bool,
) -> serde_json::Value {
    // `captureDenialsActive` is always present in the summary so SDK
    // consumers can distinguish "feature ran cleanly, no denials" from
    // "feature couldn't be activated, no denials" -- the two look
    // identical in `totalDenials` but mean very different things to
    // the application's UX.
    //
    // `childProcessesObserved` is also always present: the per-PID
    // ETW filter we attach only sees events for the workload root,
    // so denials from any child process are silently dropped. This
    // count tells the SDK consumer whether the workload is a
    // launcher pattern (cargo, npm, cmake, ...) so they can warn
    // the user "N child processes ran; their denials are not in
    // this list."
    if verbose {
        serde_json::json!({
            "type": "summary",
            "exitCode": exit_code,
            "totalDenials": unique_denials,
            "deniedResourcesTruncated": truncated,
            "captureDenialsActive": active,
            "childProcessesObserved": child_processes_observed,
            "rawEventCount": raw_event_count,
        })
    } else {
        serde_json::json!({
            "type": "summary",
            "exitCode": exit_code,
            "totalDenials": unique_denials,
            "deniedResourcesTruncated": truncated,
            "captureDenialsActive": active,
            "childProcessesObserved": child_processes_observed,
        })
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
///
/// `active` is true when the runner successfully attached the ETW
/// collector for the workload. It's false when capture was requested
/// (`captureDenials: true` in the config) but the shim was
/// unreachable, the session failed to start, or any other reason the
/// collector ended up `None`. SDK consumers must check this to
/// distinguish "no denials because the workload was well-behaved"
/// from "no denials because we couldn't capture any" -- both produce
/// `totalDenials: 0` otherwise.
///
/// `child_processes_observed` is the count of distinct child-process
/// PIDs the workload spawned during the run, as a best-effort
/// Toolhelp poll. Per-PID ETW filtering means we don't capture
/// denials for these children today; the count is surfaced so SDK
/// consumers can warn the user when the workload looks like a
/// launcher.
pub(crate) fn emit_denial_summary_line(
    exit_code: i32,
    unique_denials: usize,
    raw_event_count: usize,
    truncated: bool,
    active: bool,
    child_processes_observed: usize,
) {
    let envelope = build_summary_envelope(
        exit_code,
        unique_denials,
        raw_event_count,
        truncated,
        active,
        child_processes_observed,
        verbose_summary_enabled(),
    );
    let json = match serde_json::to_string(&envelope) {
        Ok(s) => s,
        Err(_) => return,
    };
    use std::io::Write;
    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    let _ = handle.write_all(&[DENIAL_STREAM_MARKER]);
    let _ = handle.write_all(json.as_bytes());
    let _ = handle.write_all(b"\n");
    let _ = handle.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use denial_capture::{AccessType, DeniedResource, ResourceType};
    use std::sync::mpsc;

    fn make_resource(path: &str, access: AccessType, filetime: u64) -> DeniedResource {
        DeniedResource {
            path: path.to_string(),
            resource_type: ResourceType::File,
            access_type: access,
            pid: 1234,
            filetime,
        }
    }

    /// Parse the writer-thread output into (marker-prefix, json) pairs.
    /// Asserts every record begins with the 0x1E sentinel + ends with
    /// the newline terminator. Returns the JSON bodies for further
    /// assertions.
    fn split_segments(bytes: &[u8]) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        let mut rest: &[u8] = bytes;
        while !rest.is_empty() {
            assert_eq!(
                rest[0], DENIAL_STREAM_MARKER,
                "every segment must start with the 0x1E sentinel; saw {:#x}",
                rest[0]
            );
            let nl = rest
                .iter()
                .position(|&b| b == b'\n')
                .expect("segment must end with a newline");
            let body = &rest[1..nl];
            let v: serde_json::Value = serde_json::from_slice(body)
                .unwrap_or_else(|e| panic!("segment must be valid JSON: {} ({:?})", e, body));
            out.push(v);
            rest = &rest[nl + 1..];
        }
        out
    }

    // ---- writer-thread dedupe behavior ----------------------------------

    #[test]
    fn writer_dedupes_repeated_path_and_access() {
        let (tx, rx) = mpsc::channel();
        // Same (path, access) three times: should emit once.
        // Different filetime each time to confirm it doesn't defeat dedupe.
        tx.send(make_resource("C:\\a.txt", AccessType::Read, 10))
            .unwrap();
        tx.send(make_resource("C:\\a.txt", AccessType::Read, 20))
            .unwrap();
        tx.send(make_resource("C:\\a.txt", AccessType::Read, 30))
            .unwrap();
        drop(tx);

        let mut buf: Vec<u8> = Vec::new();
        let unique = stream_denials_to_writer(rx, &mut buf);

        assert_eq!(unique, 1);
        let segments = split_segments(&buf);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0]["type"], "denial");
        assert_eq!(segments[0]["path"], "C:\\a.txt");
        // The streamed `filetime` is the *first* observation. Later
        // dupes are dropped (and so is their filetime).
        assert_eq!(segments[0]["filetime"], 10);
    }

    #[test]
    fn writer_keeps_distinct_access_types_for_same_path() {
        // Same path, different access kinds — both should survive
        // because a read-denial and a write-denial are different
        // approval prompts to the user.
        let (tx, rx) = mpsc::channel();
        tx.send(make_resource("C:\\b.txt", AccessType::Read, 1))
            .unwrap();
        tx.send(make_resource("C:\\b.txt", AccessType::Write, 2))
            .unwrap();
        tx.send(make_resource("C:\\b.txt", AccessType::Read, 3))
            .unwrap();
        drop(tx);

        let mut buf: Vec<u8> = Vec::new();
        let unique = stream_denials_to_writer(rx, &mut buf);

        assert_eq!(unique, 2);
        let segments = split_segments(&buf);
        assert_eq!(segments.len(), 2);
        let accesses: Vec<_> = segments
            .iter()
            .map(|s| s["accessType"].as_str().unwrap())
            .collect();
        assert!(accesses.contains(&"read"));
        assert!(accesses.contains(&"write"));
    }

    #[test]
    fn writer_returns_zero_unique_when_channel_closes_immediately() {
        let (tx, rx) = mpsc::channel::<DeniedResource>();
        drop(tx);

        let mut buf: Vec<u8> = Vec::new();
        let unique = stream_denials_to_writer(rx, &mut buf);

        assert_eq!(unique, 0);
        assert!(buf.is_empty(), "no segments expected, got {:?}", buf);
    }

    #[test]
    fn writer_emits_camelcase_wire_field_names() {
        // Guards the consumer contract: SDK consumers depend on
        // `resourceType` / `accessType` (camelCase) field names, not
        // the Rust-side snake_case.
        let (tx, rx) = mpsc::channel();
        tx.send(make_resource("C:\\c.txt", AccessType::Execute, 42))
            .unwrap();
        drop(tx);

        let mut buf: Vec<u8> = Vec::new();
        stream_denials_to_writer(rx, &mut buf);
        let segments = split_segments(&buf);
        assert_eq!(segments.len(), 1);
        let obj = segments[0].as_object().unwrap();
        // Required wire-format keys, all camelCase:
        for key in &["type", "path", "resourceType", "accessType", "pid", "filetime"] {
            assert!(obj.contains_key(*key), "missing wire-format key '{}'", key);
        }
        // No snake_case bleed-through:
        for forbidden in &["resource_type", "access_type", "file_time"] {
            assert!(
                !obj.contains_key(*forbidden),
                "snake_case key '{}' leaked into wire format",
                forbidden
            );
        }
    }

    // ---- verbose-mode env-var parsing -----------------------------------

    #[test]
    fn verbose_summary_enabled_from_recognises_truthy_values() {
        for v in &["1", "true", "TRUE", "yes", "on"] {
            assert!(
                verbose_summary_enabled_from(Some(v)),
                "expected '{}' to enable verbose mode",
                v
            );
        }
    }

    #[test]
    fn verbose_summary_enabled_from_recognises_falsy_values() {
        // Explicitly off: "0", "false", "False", "FALSE", or empty.
        for v in &["0", "false", "False", "FALSE", "", "   "] {
            assert!(
                !verbose_summary_enabled_from(Some(v)),
                "expected '{}' to disable verbose mode",
                v
            );
        }
    }

    #[test]
    fn verbose_summary_enabled_from_unset_is_off() {
        assert!(!verbose_summary_enabled_from(None));
    }

    // ---- summary envelope shape -----------------------------------------

    #[test]
    fn summary_envelope_default_mode_omits_raw_event_count() {
        let env = build_summary_envelope(0, 8, 651, false, true, 0, false);
        let obj = env.as_object().unwrap();
        assert_eq!(obj["type"], "summary");
        assert_eq!(obj["exitCode"], 0);
        assert_eq!(obj["totalDenials"], 8);
        assert_eq!(obj["deniedResourcesTruncated"], false);
        assert_eq!(obj["captureDenialsActive"], true);
        assert_eq!(obj["childProcessesObserved"], 0);
        assert!(
            !obj.contains_key("rawEventCount"),
            "rawEventCount must be hidden in non-verbose mode (got {:?})",
            obj
        );
    }

    #[test]
    fn summary_envelope_verbose_mode_includes_raw_event_count() {
        let env = build_summary_envelope(0, 8, 651, false, true, 0, true);
        let obj = env.as_object().unwrap();
        assert_eq!(obj["totalDenials"], 8);
        assert_eq!(obj["rawEventCount"], 651);
        assert_eq!(obj["captureDenialsActive"], true);
    }

    #[test]
    fn summary_envelope_propagates_non_zero_exit_and_truncation() {
        let env = build_summary_envelope(-1, 0, 0, true, true, 0, false);
        let obj = env.as_object().unwrap();
        assert_eq!(obj["exitCode"], -1);
        assert_eq!(obj["deniedResourcesTruncated"], true);
    }

    #[test]
    fn summary_envelope_inactive_capture_surfaces_via_field() {
        // captureDenials was requested but the runner couldn't attach
        // the collector (shim unreachable, privilege missing, etc.).
        // The summary line still goes out -- with active=false -- so
        // the SDK consumer can distinguish "0 denials because the
        // feature isn't running" from "0 denials because the workload
        // is well-behaved". Otherwise both look like
        // `totalDenials: 0`.
        let env = build_summary_envelope(0, 0, 0, false, false, 0, false);
        let obj = env.as_object().unwrap();
        assert_eq!(obj["captureDenialsActive"], false);
        assert_eq!(obj["totalDenials"], 0);
    }

    #[test]
    fn summary_envelope_active_field_present_in_both_modes() {
        for verbose in &[false, true] {
            for active in &[false, true] {
                let env = build_summary_envelope(0, 0, 0, false, *active, 0, *verbose);
                let obj = env.as_object().unwrap();
                assert!(
                    obj.contains_key("captureDenialsActive"),
                    "captureDenialsActive must always be present (verbose={}, active={})",
                    verbose,
                    active
                );
                assert_eq!(obj["captureDenialsActive"], *active);
            }
        }
    }

    #[test]
    fn summary_envelope_child_processes_observed_propagates() {
        // The runner ran a launcher-style workload (e.g. cargo) and
        // observed 5 distinct child PIDs while it was alive. The
        // count must surface in the summary so SDK consumers can
        // warn the user that those children's denials are missing.
        let env = build_summary_envelope(0, 2, 2, false, true, 5, false);
        let obj = env.as_object().unwrap();
        assert_eq!(obj["childProcessesObserved"], 5);
        assert_eq!(obj["totalDenials"], 2);
    }

    #[test]
    fn summary_envelope_child_processes_field_always_present() {
        // Even when no children were observed (the common case),
        // the field must be present so consumers don't have to
        // distinguish "0 children" from "old binary that didn't
        // report children" -- the SDK can rely on its presence to
        // know it's looking at a new-format summary.
        for verbose in &[false, true] {
            for children in &[0_usize, 1, 5, 100] {
                let env = build_summary_envelope(0, 0, 0, false, true, *children, *verbose);
                let obj = env.as_object().unwrap();
                assert!(
                    obj.contains_key("childProcessesObserved"),
                    "childProcessesObserved must always be present (verbose={}, children={})",
                    verbose,
                    children
                );
                assert_eq!(obj["childProcessesObserved"], *children);
            }
        }
    }
}

