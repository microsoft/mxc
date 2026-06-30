// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared captureDenials streaming protocol used by both the
//! AppContainer and BaseContainer runners. The stream rides stderr by
//! default, or an inherited anonymous-pipe handle when the launcher
//! passes `--denials-fd` (see [`DenialSink`]).
//!
//! Wire format (one line per *unique* `(path, accessType)`):
//!
//! ```text
//! \x1e{"type":"denial","path":"...","resourceType":"...","accessType":"...","pid":N,"filetime":N}\n
//! ...
//! \x1e{"type":"summary","exitCode":N,"totalDenials":N,"deniedResourcesTruncated":bool,"deniedResources":[...]}\n
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
//! re-reading the same locale data file on every `printf`).

/// ASCII Record Separator (0x1E). Prefixed to every captureDenials
/// streaming line.
pub const DENIAL_STREAM_MARKER: u8 = 0x1E;

/// Env var that opts into raw (pre-dedupe) event count in the summary.
const VERBOSE_ENV_VAR: &str = "MXC_DENIAL_VERBOSE";

/// A shared, thread-safe handle to the captureDenials output sink
/// (the launcher's inherited anonymous-pipe handle when `--denials-fd`
/// is given, otherwise stderr).
///
/// The sink is opened exactly **once** per `wxc-exec` invocation and
/// shared (cheap `Arc` clone) between the denial-writer thread and the
/// summary-emit call. This is load-bearing: the per-denial lines and
/// the terminator summary line *must* ride the **same** handle, so the
/// consumer reads a single uninterrupted stream terminated by exactly
/// one summary. Sharing one handle keeps both the stderr and the
/// inherited-handle transports correct.
#[derive(Clone)]
pub struct DenialSink {
    inner: std::sync::Arc<std::sync::Mutex<Box<dyn std::io::Write + Send>>>,
}

impl std::fmt::Debug for DenialSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The inner Box<dyn Write> is not Debug; expose only the type.
        f.debug_struct("DenialSink").finish_non_exhaustive()
    }
}

impl DenialSink {
    /// Opens the destination the captureDenials stream should drain
    /// into for this invocation. When `denials_fd` carries an inherited,
    /// writable anonymous-pipe handle (from `--denials-fd`), the stream
    /// rides that handle out-of-band; otherwise it goes to stderr. Call
    /// this once and clone the result to share the same underlying
    /// handle across threads.
    pub fn open(denials_fd: Option<u64>) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(open_writer(denials_fd))),
        }
    }

    /// Writes one `\x1e<json>\n` framed line to the shared handle,
    /// recovering from a poisoned lock so a panicking peer thread can
    /// never wedge the summary write.
    fn write_line(&self, json: &str) {
        use std::io::Write;
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _ = guard.write_all(&[DENIAL_STREAM_MARKER]);
        let _ = guard.write_all(json.as_bytes());
        let _ = guard.write_all(b"\n");
        let _ = guard.flush();
    }
}

/// Open the writer the captureDenials stream should drain into for
/// this invocation. Returns a `Box<dyn Write>` so the call sites can
/// share one code path between the stderr-default and the
/// inherited-handle transports.
///
/// When the launcher passes `--denials-fd <HANDLE>` (an *inherited*,
/// writable anonymous-pipe handle), `wxc-exec` adopts that handle and
/// writes the denial stream to it out-of-band, leaving stderr/the PTY
/// clean. Inherited handles keep the same numeric value in the child,
/// so the launcher and `wxc-exec` agree on the value. `std::fs::File`
/// drives the handle through the Win32 file API (`WriteFile`), which
/// anonymous-pipe handles support. Taking ownership of the handle
/// means dropping the sink closes it, so the launcher's read end
/// observes EOF.
///
/// Anonymous pipes have no name in the object namespace, so no other
/// process can open or squat the channel -- only a process already
/// holding the inherited handle can write to it. The jailed workload
/// never receives the handle: the runner restricts the sandboxed
/// child's inherited handles to stdio via
/// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, so the denials handle is
/// excluded by construction.
///
/// If no fd is given (the common case) the stream goes to stderr. If a
/// fd is given but is null/invalid (or we're not on Windows), we log
/// and fall back to stderr -- the captureDenials feature staying
/// half-functional is strictly better than panicking the runner.
fn open_writer(denials_fd: Option<u64>) -> Box<dyn std::io::Write + Send> {
    if let Some(raw) = denials_fd {
        // 0 is never a valid handle; u64::MAX is INVALID_HANDLE_VALUE.
        if raw != 0 && raw != u64::MAX {
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::io::{FromRawHandle, RawHandle};
                // Safety: the launcher passed an inherited, writable
                // anonymous-pipe handle via `--denials-fd`. We take
                // ownership; dropping the sink closes the handle so the
                // launcher's read end sees EOF.
                let handle = raw as usize as RawHandle;
                let file = unsafe { std::fs::File::from_raw_handle(handle) };
                return Box::new(file);
            }
            #[cfg(not(target_os = "windows"))]
            {
                eprintln!(
                    "[learning_mode_windows] --denials-fd is Windows-only; ignoring on this platform"
                );
            }
        }
    }
    Box::new(std::io::stderr())
}

/// Drains `rx` until the channel closes, writing one
/// `\x1e<ndjson>\n` line to the shared `sink` per *newly-seen*
/// `(path, accessType)` pair. Runs on its own thread so the ETW
/// callback never blocks on the sink's I/O.
///
/// Returns the number of unique `(path, accessType)` pairs that were
/// streamed, so the caller can fold it into the summary line.
///
/// Stream-time dedupe rationale: in practice a single process run
/// can trigger the same denial hundreds of times in a tight loop
/// (e.g. locale-aware code re-reading the same locale data file on
/// every `printf`). For the SDK's prompt-the-user UX every duplicate is
/// pure noise — the user has already been asked about that resource
/// — and emitting them all balloons stderr by ~100x. The dedupe set
/// is per-invocation (lives only as long as this writer thread).
///
/// The channel closes when the `CollectorHandle` is dropped (the
/// sender lives inside its `CallbackContext`). Receiving `Err` is
/// the normal teardown signal.
pub fn stream_denials(
    rx: std::sync::mpsc::Receiver<crate::DeniedResource>,
    sink: DenialSink,
) -> usize {
    // Lock the shared handle for the lifetime of the drain. The
    // summary line is only emitted after this thread is joined (see
    // the runners), so the summary's `write_line` never contends for
    // this lock — holding it across `rx.recv()` blocks is therefore
    // safe and keeps every denial line atomic on the wire.
    let mut guard = match sink.inner.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    stream_denials_to_writer(rx, &mut *guard)
}

/// Test-friendly implementation of [`stream_denials`]. The
/// sink-bound variant delegates here after locking; tests pass a
/// `Vec<u8>` to capture and assert against the rendered bytes.
fn stream_denials_to_writer<W: std::io::Write>(
    rx: std::sync::mpsc::Receiver<crate::DeniedResource>,
    out: &mut W,
) -> usize {
    use std::collections::HashSet;
    let mut seen: HashSet<(String, crate::AccessType)> = HashSet::new();
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
#[allow(clippy::too_many_arguments)]
fn build_summary_envelope(
    exit_code: i32,
    unique_denials: usize,
    raw_event_count: usize,
    truncated: bool,
    active: bool,
    child_processes_observed: usize,
    descendant_pids_covered: usize,
    denied_resources: &[crate::DeniedResource],
    verbose: bool,
) -> serde_json::Value {
    // `captureDenialsActive` is always present in the summary so SDK
    // consumers can distinguish "feature ran cleanly, no denials" from
    // "feature couldn't be activated, no denials" -- the two look
    // identical in `totalDenials` but mean very different things to
    // the application's UX.
    //
    // `childProcessesObserved` is the Toolhelp-poll count of distinct
    // child-process PIDs the workload spawned during the run. It is a
    // best-effort signal kept for back-compat; with the descendant-
    // tracking work (Phases A-D of captureDenials), denials from
    // descendants now flow into the same stream as the root's, so this
    // count is no longer a "the denial list is incomplete" warning.
    //
    // `descendantPidsCovered` is the count of descendant PIDs the IOCP
    // listener attached to the live ETW filter via `extend_via_shim`.
    // This is the authoritative metric for "how many descendants
    // contributed to the denial stream", and SDK consumers should use
    // it (not childProcessesObserved) when deciding whether to surface
    // a "captured M denials across N descendants" message in the UI.
    if verbose {
        serde_json::json!({
            "type": "summary",
            "exitCode": exit_code,
            "totalDenials": unique_denials,
            "deniedResourcesTruncated": truncated,
            "captureDenialsActive": active,
            "childProcessesObserved": child_processes_observed,
            "descendantPidsCovered": descendant_pids_covered,
            "deniedResources": denied_resources,
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
            "descendantPidsCovered": descendant_pids_covered,
            "deniedResources": denied_resources,
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
/// Toolhelp poll. With the descendant-tracking work (Phases A-D),
/// denials from descendants flow into the same stream as the root's,
/// so this count is now a Toolhelp-side cross-check rather than a
/// "denials are missing" warning. See `descendant_pids_covered` for
/// the authoritative metric.
///
/// `descendant_pids_covered` is the count of descendant PIDs the
/// IOCP listener added to the live ETW filter via `extend_via_shim`.
/// SDK consumers should treat this as the "how many descendants
/// contributed to the captured denial list" metric.
///
/// `denied_resources` is the full deduped `(path, accessType)` list
/// (the same set the per-denial lines streamed). It is embedded in
/// the summary so a consumer can read the consolidated list in one
/// race-free shot after the workload exits, without having to
/// accumulate the live `denial` records itself. The array is always
/// present (empty when no denials), so an empty list unambiguously
/// means "ran, nothing denied" (cross-check `captureDenialsActive`).
#[allow(clippy::too_many_arguments)]
pub fn emit_denial_summary_line(
    sink: &DenialSink,
    exit_code: i32,
    unique_denials: usize,
    raw_event_count: usize,
    truncated: bool,
    active: bool,
    child_processes_observed: usize,
    descendant_pids_covered: usize,
    denied_resources: &[crate::DeniedResource],
) {
    let envelope = build_summary_envelope(
        exit_code,
        unique_denials,
        raw_event_count,
        truncated,
        active,
        child_processes_observed,
        descendant_pids_covered,
        denied_resources,
        verbose_summary_enabled(),
    );
    let json = match serde_json::to_string(&envelope) {
        Ok(s) => s,
        Err(_) => return,
    };
    // The summary is the wire-format terminator for the consumer, so
    // it has to land on the same channel (the same inherited handle, for
    // the `--denials-fd` transport) as the individual denial lines.
    // `sink` is the shared handle the denial-writer thread already
    // drained into; by the time this is called that thread has been
    // joined, so this write is uncontended.
    sink.write_line(&json);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessType, DeniedResource, ResourceType};
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

    /// In-memory `Write` whose bytes survive the writer being dropped,
    /// so a test can inspect everything a shared `DenialSink` wrote.
    #[derive(Clone)]
    struct SharedBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("buf lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Regression guard: the per-denial lines and the terminator
    /// summary line must land on the SAME `DenialSink` handle. The
    /// inherited-handle transport is a single pipe handle, so a summary
    /// written to a second handle would be lost. This mirrors the runner
    /// ordering: stream on a thread, join, then emit the summary on the
    /// shared sink.
    #[test]
    fn shared_sink_carries_denials_and_summary_on_one_handle() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let sink = DenialSink {
            inner: std::sync::Arc::new(std::sync::Mutex::new(Box::new(SharedBuf(buf.clone())))),
        };

        let (tx, rx) = mpsc::channel();
        tx.send(make_resource("C:\\dir\\a.txt", AccessType::Read, 1))
            .unwrap();
        tx.send(make_resource("C:\\dir\\a.txt", AccessType::Read, 2))
            .unwrap(); // dup
        tx.send(make_resource("C:\\dir\\b.txt", AccessType::Write, 3))
            .unwrap();
        drop(tx);

        let sink_for_thread = sink.clone();
        let unique = std::thread::spawn(move || stream_denials(rx, sink_for_thread))
            .join()
            .expect("writer thread");
        assert_eq!(unique, 2, "two unique (path, access) pairs");

        let summary_resources = vec![
            make_resource("C:\\dir\\a.txt", AccessType::Read, 1),
            make_resource("C:\\dir\\b.txt", AccessType::Write, 3),
        ];
        emit_denial_summary_line(&sink, 0, unique, 3, false, true, 0, 0, &summary_resources);

        let bytes = buf.lock().unwrap().clone();
        let segments = split_segments(&bytes);
        // Two denial lines followed by exactly one summary line, all on
        // the same underlying buffer.
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0]["type"], "denial");
        assert_eq!(segments[1]["type"], "denial");
        assert_eq!(segments[2]["type"], "summary");
        assert_eq!(segments[2]["totalDenials"], 2);
        // The summary terminator carries the consolidated deduped list so
        // a consumer can read it race-free without demuxing the stream.
        let summary_list = segments[2]["deniedResources"]
            .as_array()
            .expect("summary carries deniedResources array");
        assert_eq!(summary_list.len(), 2);
        assert_eq!(summary_list[0]["path"], "C:\\dir\\a.txt");
        assert_eq!(summary_list[0]["accessType"], "read");
        assert_eq!(summary_list[1]["path"], "C:\\dir\\b.txt");
        assert_eq!(summary_list[1]["accessType"], "write");
    }

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
        for key in &[
            "type",
            "path",
            "resourceType",
            "accessType",
            "pid",
            "filetime",
        ] {
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
        let env = build_summary_envelope(0, 8, 651, false, true, 0, 0, &[], false);
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
        let env = build_summary_envelope(0, 8, 651, false, true, 0, 0, &[], true);
        let obj = env.as_object().unwrap();
        assert_eq!(obj["totalDenials"], 8);
        assert_eq!(obj["rawEventCount"], 651);
        assert_eq!(obj["captureDenialsActive"], true);
    }

    #[test]
    fn summary_envelope_propagates_non_zero_exit_and_truncation() {
        let env = build_summary_envelope(-1, 0, 0, true, true, 0, 0, &[], false);
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
        let env = build_summary_envelope(0, 0, 0, false, false, 0, 0, &[], false);
        let obj = env.as_object().unwrap();
        assert_eq!(obj["captureDenialsActive"], false);
        assert_eq!(obj["totalDenials"], 0);
    }

    #[test]
    fn summary_envelope_active_field_present_in_both_modes() {
        for verbose in &[false, true] {
            for active in &[false, true] {
                let env = build_summary_envelope(0, 0, 0, false, *active, 0, 0, &[], *verbose);
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
        let env = build_summary_envelope(0, 2, 2, false, true, 5, 0, &[], false);
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
                let env = build_summary_envelope(0, 0, 0, false, true, *children, 0, &[], *verbose);
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
