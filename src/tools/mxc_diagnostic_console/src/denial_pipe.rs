// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Named pipe server for streaming denial events to SDK clients.
//!
//! Listens on `\\.\pipe\mxc-denials-{SID}` and serves buffered [`DenialEvent`]s
//! to non-elevated SDK processes. A single unified [`DenialQuery`] request
//! selects behavior via its `mode` field:
//!
//! - **Snapshot mode** ([`RequestMode::Snapshot`]): server responds with all
//!   matching buffered events as newline-delimited JSON and disconnects.
//! - **Stream mode** ([`RequestMode::Stream`]): server streams matching events
//!   as newline-delimited JSON until the client disconnects.
//!
//! The server runs on its own thread and receives events via an [`mpsc::Receiver`]
//! from the ETW consumer.

use std::collections::{HashMap, VecDeque};
use std::io::{BufWriter, Read, Write};
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Pipes::{ConnectNamedPipe, DisconnectNamedPipe, PeekNamedPipe};

use crate::denial_event::{DenialEvent, DenialQuery, RequestMode};
use crate::pipe_utils::build_pipe_sddl;

/// Pipe name prefix for the denial event pipe.
const PIPE_NAME_PREFIX: &str = r"\\.\pipe\mxc-denials";

/// Maximum buffer size for pipe I/O (64 KB).
const BUFFER_SIZE: u32 = 64 * 1024;

/// Maximum number of buffered events per PID key.
const MAX_EVENTS_PER_KEY: usize = 1024;

/// Maximum total events across all keys.
const MAX_TOTAL_EVENTS: usize = 10_000;

/// Maximum age for buffer keys (1 hour).
const MAX_KEY_AGE_SECS: u64 = 3600;

/// Maximum number of concurrent subscribers to prevent resource exhaustion.
const MAX_SUBSCRIBERS: usize = 32;

/// Maximum number of concurrent client handler threads.
const MAX_CLIENTS: usize = 64;

/// Maximum allowed length for a container name (in bytes). Events whose
/// container name exceeds this are dropped to bound buffer memory.
const MAX_CONTAINER_NAME_LEN: usize = 256;

/// How often the event receiver loop wakes when no events are arriving, so that
/// time-based maintenance (eviction, subscriber reaping) still runs during
/// quiet periods.
const RECEIVER_WAKE_INTERVAL: Duration = Duration::from_secs(5);

/// Run age-based buffer eviction at least this often, independent of event
/// arrival.
const EVICT_INTERVAL_SECS: u64 = 60;

/// How often a streaming subscriber's writer thread wakes to probe its pipe for
/// a disconnected client when no events are flowing.
const SUBSCRIBER_PROBE_INTERVAL: Duration = Duration::from_secs(10);

/// Bound on the per-subscriber fan-out channel. A subscriber that falls this
/// far behind is considered too slow and is dropped.
const SUBSCRIBER_CHANNEL_BOUND: usize = 100;

/// Key for the per-PID event buffer.
///
/// PID is the primary correlation key per the wire contract; container name is
/// only a secondary label and is therefore not part of the key.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct BufferKey {
    pid: u32,
}

/// A single entry in the event buffer, tracking events and last access time.
#[derive(Debug)]
struct BufferEntry {
    events: VecDeque<Arc<DenialEvent>>,
    last_access: Instant,
}

impl Default for BufferEntry {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            last_access: Instant::now(),
        }
    }
}

/// Shared event buffer protected by a mutex.
type EventBuffer = Arc<Mutex<HashMap<BufferKey, BufferEntry>>>;

/// A subscriber waiting for streamed events.
struct Subscriber {
    query: DenialQuery,
    /// Sender to push events to the subscriber's writer thread.
    tx: mpsc::SyncSender<Arc<DenialEvent>>,
    /// Liveness flag, cleared by the subscriber's writer thread when it exits
    /// (client disconnect or write failure). The receiver loop reaps
    /// subscribers whose flag is cleared, even if they never matched an event.
    alive: Arc<AtomicBool>,
    /// Set by fan-out when the subscriber is dropped because its channel was
    /// full (slow consumer), so the writer thread can emit a terminal message.
    slow: Arc<AtomicBool>,
}

/// Shared list of active subscribers.
type Subscribers = Arc<Mutex<Vec<Subscriber>>>;

/// Builds the denial pipe name for the current user: `\\.\pipe\mxc-denials-{SID}`.
///
/// Uses the same SID resolution as `wxc_common::diagnostic::diagnostic_pipe_name()`
/// but with the `mxc-denials` prefix.
pub fn denial_pipe_name() -> String {
    // Re-use the wxc_common utility to get the SID-suffixed name.
    // The diagnostic_pipe_name() returns `\\.\pipe\mxc-diagnostics-{SID}`.
    // We replace the prefix to get our denial pipe name.
    let diag_name = wxc_common::diagnostic::diagnostic_pipe_name();
    if let Some(sid_part) = diag_name.strip_prefix(r"\\.\pipe\mxc-diagnostics") {
        format!("{PIPE_NAME_PREFIX}{sid_part}")
    } else {
        PIPE_NAME_PREFIX.to_string()
    }
}

/// Starts the denial pipe server on a dedicated thread.
///
/// Returns:
/// - An [`mpsc::Sender<DenialEvent>`] that the ETW consumer uses to push events.
/// - A [`thread::JoinHandle`] for the server thread.
///
/// The server thread runs indefinitely until the process exits.
pub fn start_denial_pipe_server() -> (mpsc::Sender<DenialEvent>, thread::JoinHandle<()>) {
    let (event_tx, event_rx) = mpsc::channel::<DenialEvent>();

    let handle = thread::Builder::new()
        .name("denial-pipe-server".to_string())
        .spawn(move || {
            run_server(event_rx);
        })
        .expect("failed to spawn denial pipe server thread");

    (event_tx, handle)
}

/// Main server loop: buffers incoming events and accepts client connections.
fn run_server(event_rx: mpsc::Receiver<DenialEvent>) {
    let pipe_name = denial_pipe_name();
    let pipe_sddl = match build_pipe_sddl() {
        Some(sddl) => sddl,
        None => {
            eprintln!(
                "[denial-pipe] Failed to resolve current user SID; refusing to create pipe \
                 with weaker ACLs. Denial pipe server will not start."
            );
            return;
        }
    };
    let buffer: EventBuffer = Arc::new(Mutex::new(HashMap::new()));
    let subscribers: Subscribers = Arc::new(Mutex::new(Vec::new()));
    let active_clients = Arc::new(AtomicUsize::new(0));

    // Spawn a thread to receive events from the ETW consumer and buffer them.
    let buffer_for_receiver = Arc::clone(&buffer);
    let subscribers_for_receiver = Arc::clone(&subscribers);
    thread::Builder::new()
        .name("denial-event-receiver".to_string())
        .spawn(move || {
            event_receiver_loop(event_rx, buffer_for_receiver, subscribers_for_receiver);
        })
        .expect("failed to spawn event receiver thread");

    // Accept loop: create pipe instances and serve clients.
    let mut is_first = true;
    loop {
        let pipe = match create_denial_pipe_instance(&pipe_name, &pipe_sddl, is_first) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[denial-pipe] Failed to create pipe instance: {e}");
                if is_first {
                    return;
                }
                thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
        };
        is_first = false;

        // Block until a client connects.
        // SAFETY: `pipe` is a valid handle from create_denial_pipe_instance.
        let connected = unsafe { ConnectNamedPipe(pipe, None) };
        if connected.is_err() {
            let err = std::io::Error::last_os_error();
            // ERROR_PIPE_CONNECTED (535) means client already connected.
            if err.raw_os_error() != Some(535) {
                eprintln!("[denial-pipe] ConnectNamedPipe failed: {err}");
                // SAFETY: `pipe` is a valid handle.
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                continue;
            }
        }

        let buffer_clone = Arc::clone(&buffer);
        let subscribers_clone = Arc::clone(&subscribers);

        // Reject if at maximum client capacity.
        let current = active_clients.load(Ordering::Relaxed);
        if current >= MAX_CLIENTS {
            eprintln!("[denial-pipe] Max clients reached ({MAX_CLIENTS}), rejecting connection");
            // SAFETY: `pipe` is a valid, connected handle.
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
                let _ = CloseHandle(pipe);
            }
            continue;
        }
        active_clients.fetch_add(1, Ordering::Relaxed);

        let active_clients_clone = Arc::clone(&active_clients);

        // Transfer handle to client thread (HANDLE is !Send, use raw pointer).
        let raw_handle = pipe.0 as usize;
        thread::Builder::new()
            .name("denial-pipe-client".to_string())
            .spawn(move || {
                let pipe = HANDLE(raw_handle as *mut std::ffi::c_void);
                handle_client(pipe, buffer_clone, subscribers_clone);
                active_clients_clone.fetch_sub(1, Ordering::Relaxed);
            })
            .expect("failed to spawn client handler thread");
    }
}

/// Receives events from the ETW consumer, buffers them, and fans out to subscribers.
///
/// The loop wakes at least every [`RECEIVER_WAKE_INTERVAL`] even when no events
/// arrive, so that time-based maintenance runs during quiet periods:
/// - **Age-based eviction** of stale buffer keys (so a snapshot served in a
///   quiet period never returns events older than [`MAX_KEY_AGE_SECS`]).
/// - **Subscriber reaping** of subscribers whose writer thread has exited
///   (client gone), preventing idle no-match subscribers from exhausting
///   [`MAX_SUBSCRIBERS`].
fn event_receiver_loop(
    event_rx: mpsc::Receiver<DenialEvent>,
    buffer: EventBuffer,
    subscribers: Subscribers,
) {
    let mut total_events: usize = 0;
    let mut last_evict = Instant::now();

    loop {
        match event_rx.recv_timeout(RECEIVER_WAKE_INTERVAL) {
            Ok(event) => {
                // Reject container names that are too long (bounds buffer memory).
                if event.container_name.len() > MAX_CONTAINER_NAME_LEN {
                    continue;
                }
                // Wrap once in an Arc so the buffer and every subscriber share a
                // single allocation; fan-out only bumps the reference count.
                let event = Arc::new(event);
                buffer_event(&buffer, &mut total_events, &event);
                fan_out(&subscribers, &event);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        // Time-based maintenance, independent of event arrival.
        let now = Instant::now();
        if now.duration_since(last_evict) >= Duration::from_secs(EVICT_INTERVAL_SECS) {
            evict_aged_keys(&buffer, &mut total_events, now);
            last_evict = now;
        }
        // Reaping is cheap; run it on every wake so dead subscribers free their
        // slot promptly.
        reap_dead_subscribers(&subscribers);
    }
}

/// Insert `event` into the buffer keyed by PID, applying per-key and global
/// capacity eviction.
fn buffer_event(buffer: &EventBuffer, total_events: &mut usize, event: &Arc<DenialEvent>) {
    let key = BufferKey { pid: event.pid };
    let mut buf = buffer.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();

    // Evict the oldest key (by last_access) if over global capacity.
    if *total_events >= MAX_TOTAL_EVENTS {
        if let Some(oldest_key) = buf
            .iter()
            .min_by_key(|(_, entry)| entry.last_access)
            .map(|(k, _)| *k)
        {
            if let Some(removed) = buf.remove(&oldest_key) {
                *total_events -= removed.events.len();
            }
        }
    }

    let entry = buf.entry(key).or_default();
    entry.last_access = now;
    if entry.events.len() >= MAX_EVENTS_PER_KEY {
        // Evict oldest event — O(1) with VecDeque.
        entry.events.pop_front();
        *total_events -= 1;
    }
    entry.events.push_back(Arc::clone(event));
    *total_events += 1;
}

/// Remove buffer keys whose most recent access is older than [`MAX_KEY_AGE_SECS`].
fn evict_aged_keys(buffer: &EventBuffer, total_events: &mut usize, now: Instant) {
    let mut buf = buffer.lock().unwrap_or_else(|e| e.into_inner());
    buf.retain(|_, entry| {
        let keep = now.duration_since(entry.last_access).as_secs() < MAX_KEY_AGE_SECS;
        if !keep {
            *total_events -= entry.events.len();
        }
        keep
    });
}

/// Remove subscribers whose writer thread has exited (client disconnected).
fn reap_dead_subscribers(subscribers: &Subscribers) {
    let mut subs = subscribers.lock().unwrap_or_else(|e| e.into_inner());
    subs.retain(|sub| sub.alive.load(Ordering::Relaxed));
}

/// Fan out a single event to every matching subscriber.
///
/// Iterates the subscriber list under the lock and uses the non-blocking
/// `try_send` directly, avoiding a per-event snapshot allocation and per-
/// subscriber query clones. Blocking writes happen on each subscriber's own
/// writer thread, never under this lock, so holding it here is safe.
///
/// A subscriber is dropped when its channel is full (slow consumer) or
/// disconnected. For a slow consumer, the `slow` flag is set so the writer
/// thread can emit a best-effort terminal message before closing.
fn fan_out(subscribers: &Subscribers, event: &Arc<DenialEvent>) {
    let mut subs = subscribers.lock().unwrap_or_else(|e| e.into_inner());
    subs.retain(|sub| {
        if !event.matches_query(&sub.query) {
            return true;
        }
        match sub.tx.try_send(Arc::clone(event)) {
            Ok(()) => true,
            Err(mpsc::TrySendError::Full(_)) => {
                sub.slow.store(true, Ordering::Relaxed);
                false
            }
            Err(mpsc::TrySendError::Disconnected(_)) => false,
        }
    });
}

/// Handles a single client connection: reads the query/subscribe request and responds.
fn handle_client(pipe: HANDLE, buffer: EventBuffer, subscribers: Subscribers) {
    // Wrap the pipe handle in a File for Read/Write.
    // SAFETY: we own the handle and manage its lifetime.
    use std::os::windows::io::FromRawHandle;
    let mut file: std::fs::File = unsafe { FromRawHandle::from_raw_handle(pipe.0) };

    let mut buf = vec![0u8; BUFFER_SIZE as usize];
    let n = match file.read(&mut buf) {
        Ok(0) | Err(_) => {
            cleanup_pipe(file);
            return;
        }
        Ok(n) => n,
    };

    let request_text = String::from_utf8_lossy(&buf[..n]);
    let request_text = request_text.trim();

    // Parse the unified request once and route on its resolved mode. A missing
    // `mode` defaults to snapshot; a legacy `subscribe: true` selects stream.
    match serde_json::from_str::<DenialQuery>(request_text) {
        Ok(query) => match query.resolved_mode() {
            RequestMode::Stream => {
                handle_subscribe(file, query, subscribers);
            }
            RequestMode::Snapshot => {
                handle_query(&mut file, &query, &buffer);
                cleanup_pipe(file);
            }
        },
        Err(e) => {
            let error_json =
                serde_json::json!({"error": format!("invalid request: {e}")}).to_string();
            let _ = file.write_all(error_json.as_bytes());
            cleanup_pipe(file);
        }
    }
}

/// Handles a one-shot snapshot query: responds with all buffered events matching
/// the filter as newline-delimited JSON, using buffered I/O.
fn handle_query(file: &mut std::fs::File, query: &DenialQuery, buffer: &EventBuffer) {
    // PID is the primary key, so a query with a PID is an O(1) lookup; otherwise
    // gather across all keys. Container-name and `since` are applied as
    // secondary filters below.
    let mut matching_events: Vec<Arc<DenialEvent>> = {
        let buf = buffer.lock().unwrap_or_else(|e| e.into_inner());
        match query.pid {
            Some(pid) => buf
                .get(&BufferKey { pid })
                .map(|entry| entry.events.iter().map(Arc::clone).collect())
                .unwrap_or_default(),
            None => buf
                .values()
                .flat_map(|entry| entry.events.iter())
                .map(Arc::clone)
                .collect(),
        }
    };

    // Apply the optional container-name filter (empty string matches all).
    if let Some(ref name) = query.container_name {
        if !name.is_empty() {
            matching_events.retain(|event| event.container_name == *name);
        }
    }

    // Apply the optional `since` timestamp filter.
    if let Some(ref since) = query.since {
        matching_events.retain(|event| event.timestamp.as_str() >= since.as_str());
    }

    // Send events as newline-delimited JSON via a single buffered writer.
    let mut writer = BufWriter::new(file);
    for event in &matching_events {
        if serde_json::to_writer(&mut writer, event.as_ref()).is_err() {
            break;
        }
        if writer.write_all(b"\n").is_err() {
            break;
        }
    }
    let _ = writer.flush();
}

/// Handles a stream request: streams events as newline-delimited JSON until the
/// client disconnects.
fn handle_subscribe(mut file: std::fs::File, query: DenialQuery, subscribers: Subscribers) {
    let (tx, rx) = mpsc::sync_channel::<Arc<DenialEvent>>(SUBSCRIBER_CHANNEL_BOUND);
    let alive = Arc::new(AtomicBool::new(true));
    let slow = Arc::new(AtomicBool::new(false));

    // Register this subscriber (reject if at capacity).
    {
        let mut subs = subscribers.lock().unwrap_or_else(|e| e.into_inner());
        if subs.len() >= MAX_SUBSCRIBERS {
            let error_json = serde_json::json!({"error": "too many subscribers"}).to_string();
            let _ = file.write_all(error_json.as_bytes());
            cleanup_pipe(file);
            return;
        }
        subs.push(Subscriber {
            query,
            tx,
            alive: Arc::clone(&alive),
            slow: Arc::clone(&slow),
        });
    }

    // Raw handle used only to probe for a disconnected client during idle
    // periods; the `File` retains ownership.
    let raw_handle = file.as_raw_handle();

    // Stream events with buffered I/O. We use `recv_timeout` rather than a
    // blocking iterator so the writer thread wakes periodically even when no
    // events match this subscriber, letting it detect a vanished client and
    // exit (so the receiver loop can reap it — fixes idle-subscriber leaks).
    {
        let mut writer = BufWriter::new(&file);
        loop {
            match rx.recv_timeout(SUBSCRIBER_PROBE_INTERVAL) {
                Ok(event) => {
                    if serde_json::to_writer(&mut writer, event.as_ref()).is_err() {
                        break;
                    }
                    if writer.write_all(b"\n").is_err() {
                        break;
                    }
                    if writer.flush().is_err() {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if pipe_is_broken(raw_handle) {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    // Mark this subscriber dead so the receiver loop reaps it.
    alive.store(false, Ordering::Relaxed);

    // If we were dropped as a slow consumer, emit a best-effort terminal line so
    // the client can distinguish a drop from a normal close.
    if slow.load(Ordering::Relaxed) {
        let _ = file.write_all(b"{\"error\":\"slow consumer\"}\n");
    }

    cleanup_pipe(file);
}

/// Returns `true` if the named pipe appears disconnected/broken.
///
/// Uses a non-destructive `PeekNamedPipe`, which fails (e.g. with
/// `ERROR_BROKEN_PIPE`) once the client end has closed.
fn pipe_is_broken(raw_handle: std::os::windows::io::RawHandle) -> bool {
    let handle = HANDLE(raw_handle);
    let mut bytes_available: u32 = 0;
    // SAFETY: `handle` is a valid pipe handle owned by the caller's `File` for
    // the duration of this call. All out-pointers are optional and valid.
    let result = unsafe { PeekNamedPipe(handle, None, 0, None, Some(&mut bytes_available), None) };
    result.is_err()
}

/// Disconnects and closes a pipe handle owned by a File.
fn cleanup_pipe(file: std::fs::File) {
    use std::os::windows::io::IntoRawHandle;
    let raw = file.into_raw_handle();
    // SAFETY: `raw` is a valid pipe handle extracted from the File.
    unsafe {
        let h = HANDLE(raw);
        let _ = DisconnectNamedPipe(h);
        let _ = CloseHandle(h);
    }
}

/// Creates a named pipe instance for the denial pipe server.
///
/// Uses an SDDL-based security descriptor that denies access to AppContainer
/// processes (ALL_APP_PACKAGES) while granting access only to the current user
/// (by SID), SYSTEM, and Built-in Administrators. See [`build_pipe_sddl`].
fn create_denial_pipe_instance(pipe_name: &str, sddl: &str, first: bool) -> Result<HANDLE, String> {
    // PIPE_ACCESS_DUPLEX (0x3): server reads and writes (query/response + subscribe streaming).
    crate::pipe_utils::create_pipe_with_sddl(
        pipe_name,
        sddl,
        0x0000_0003, // PIPE_ACCESS_DUPLEX
        BUFFER_SIZE, // in buffer (server reads queries)
        BUFFER_SIZE, // out buffer (server writes responses)
        first,
    )
    .map_err(|e| format!("CreateNamedPipeW failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denial_pipe_name_contains_prefix() {
        let name = denial_pipe_name();
        assert!(
            name.starts_with(PIPE_NAME_PREFIX),
            "pipe name should start with '{PIPE_NAME_PREFIX}', got: {name}"
        );
    }

    #[test]
    fn denial_pipe_name_differs_from_diagnostic() {
        let denial = denial_pipe_name();
        let diag = wxc_common::diagnostic::diagnostic_pipe_name();
        assert_ne!(denial, diag);
    }

    #[test]
    fn buffer_key_equality() {
        let key1 = BufferKey { pid: 100 };
        let key2 = BufferKey { pid: 100 };
        let key3 = BufferKey { pid: 200 };
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn request_mode_explicit_snapshot_and_stream() {
        let snap: DenialQuery =
            serde_json::from_str(r#"{"mode": "snapshot", "pid": 7}"#).expect("deserialize");
        assert_eq!(snap.resolved_mode(), RequestMode::Snapshot);
        assert_eq!(snap.pid, Some(7));

        let stream: DenialQuery =
            serde_json::from_str(r#"{"mode": "stream", "containerName": "my-app"}"#)
                .expect("deserialize");
        assert_eq!(stream.resolved_mode(), RequestMode::Stream);
        assert_eq!(stream.container_name, Some("my-app".to_string()));
    }

    #[test]
    fn request_mode_defaults_to_snapshot_when_absent() {
        // No `mode` and no `subscribe` → snapshot (backward compatible).
        let req: DenialQuery =
            serde_json::from_str(r#"{"containerName": "my-app", "pid": 42}"#).expect("deserialize");
        assert_eq!(req.resolved_mode(), RequestMode::Snapshot);
        assert_eq!(req.container_name, Some("my-app".to_string()));
        assert_eq!(req.pid, Some(42));
    }

    #[test]
    fn request_mode_legacy_subscribe_is_stream() {
        let req: DenialQuery =
            serde_json::from_str(r#"{"subscribe": true, "pid": 42}"#).expect("deserialize");
        assert_eq!(req.resolved_mode(), RequestMode::Stream);
        assert_eq!(req.pid, Some(42));
    }

    #[test]
    fn request_mode_explicit_mode_wins_over_legacy_subscribe() {
        // An explicit `mode` takes precedence over a conflicting legacy field.
        let req: DenialQuery = serde_json::from_str(r#"{"mode": "snapshot", "subscribe": true}"#)
            .expect("deserialize");
        assert_eq!(req.resolved_mode(), RequestMode::Snapshot);
    }

    #[test]
    fn request_minimal_empty_object_is_snapshot_all() {
        let req: DenialQuery = serde_json::from_str("{}").expect("deserialize");
        assert_eq!(req.resolved_mode(), RequestMode::Snapshot);
        assert_eq!(req.container_name, None);
        assert_eq!(req.pid, None);
        assert_eq!(req.since, None);
    }

    #[test]
    fn pid_primary_matching() {
        use crate::denial_event::{AccessType, ResourceType};

        // Event with an empty container name (producer could not resolve it).
        let event = DenialEvent::new(
            String::new(),
            42,
            ResourceType::File,
            r"C:\file.txt".to_string(),
            AccessType::Read,
            "2026-01-15T10:30:00Z".to_string(),
            4907,
        );

        // PID is the primary key: a matching PID matches even with an empty
        // container name on the event.
        let by_pid = DenialQuery {
            mode: None,
            container_name: None,
            pid: Some(42),
            since: None,
            subscribe: None,
        };
        assert!(event.matches_query(&by_pid));

        let wrong_pid = DenialQuery {
            mode: None,
            container_name: None,
            pid: Some(99),
            since: None,
            subscribe: None,
        };
        assert!(!event.matches_query(&wrong_pid));

        // An empty container-name filter matches all events (does not reject the
        // empty-container event).
        let empty_name = DenialQuery {
            mode: None,
            container_name: Some(String::new()),
            pid: Some(42),
            since: None,
            subscribe: None,
        };
        assert!(event.matches_query(&empty_name));

        // A non-empty container-name filter must match exactly.
        let named = DenialQuery {
            mode: None,
            container_name: Some("some-name".to_string()),
            pid: Some(42),
            since: None,
            subscribe: None,
        };
        assert!(!event.matches_query(&named));
    }

    #[test]
    fn evict_aged_keys_removes_stale_entries_on_timer() {
        let buffer: EventBuffer = Arc::new(Mutex::new(HashMap::new()));
        let mut total_events: usize = 0;

        // Insert a key whose last access is well beyond MAX_KEY_AGE_SECS.
        {
            let mut buf = buffer.lock().unwrap();
            let stale = buf.entry(BufferKey { pid: 1 }).or_default();
            stale.last_access = Instant::now()
                .checked_sub(Duration::from_secs(MAX_KEY_AGE_SECS + 10))
                .expect("instant in range");
            stale.events.push_back(Arc::new(DenialEvent::new(
                String::new(),
                1,
                crate::denial_event::ResourceType::File,
                "old".to_string(),
                crate::denial_event::AccessType::Read,
                "2026-01-01T00:00:00Z".to_string(),
                4907,
            )));
            total_events += 1;
        }

        // Eviction runs on a timer independent of event arrival.
        evict_aged_keys(&buffer, &mut total_events, Instant::now());

        assert_eq!(total_events, 0);
        assert!(buffer.lock().unwrap().is_empty());
    }

    #[test]
    fn reap_dead_subscribers_removes_only_dead() {
        let subscribers: Subscribers = Arc::new(Mutex::new(Vec::new()));
        let query = DenialQuery {
            mode: None,
            container_name: None,
            pid: None,
            since: None,
            subscribe: None,
        };

        let (live_tx, _live_rx) = mpsc::sync_channel(SUBSCRIBER_CHANNEL_BOUND);
        let live_alive = Arc::new(AtomicBool::new(true));
        let (dead_tx, _dead_rx) = mpsc::sync_channel(SUBSCRIBER_CHANNEL_BOUND);
        let dead_alive = Arc::new(AtomicBool::new(false));

        {
            let mut subs = subscribers.lock().unwrap();
            subs.push(Subscriber {
                query: query.clone(),
                tx: live_tx,
                alive: Arc::clone(&live_alive),
                slow: Arc::new(AtomicBool::new(false)),
            });
            subs.push(Subscriber {
                query,
                tx: dead_tx,
                alive: Arc::clone(&dead_alive),
                slow: Arc::new(AtomicBool::new(false)),
            });
        }

        reap_dead_subscribers(&subscribers);

        let subs = subscribers.lock().unwrap();
        assert_eq!(subs.len(), 1);
        assert!(subs[0].alive.load(Ordering::Relaxed));
    }

    #[test]
    fn fan_out_marks_slow_consumer_and_drops_it() {
        let subscribers: Subscribers = Arc::new(Mutex::new(Vec::new()));
        let query = DenialQuery {
            mode: None,
            container_name: None,
            pid: None,
            since: None,
            subscribe: None,
        };

        // Channel bound of 1, never drained → second send fills it.
        let (tx, _rx) = mpsc::sync_channel(1);
        let slow = Arc::new(AtomicBool::new(false));
        {
            let mut subs = subscribers.lock().unwrap();
            subs.push(Subscriber {
                query,
                tx,
                alive: Arc::new(AtomicBool::new(true)),
                slow: Arc::clone(&slow),
            });
        }

        let event = Arc::new(DenialEvent::new(
            String::new(),
            1,
            crate::denial_event::ResourceType::File,
            "p".to_string(),
            crate::denial_event::AccessType::Read,
            "2026-01-01T00:00:00Z".to_string(),
            4907,
        ));

        // First send fills the single channel slot; subscriber stays.
        fan_out(&subscribers, &event);
        assert_eq!(subscribers.lock().unwrap().len(), 1);
        assert!(!slow.load(Ordering::Relaxed));

        // Second send finds the channel full → subscriber flagged slow and dropped.
        fan_out(&subscribers, &event);
        assert!(subscribers.lock().unwrap().is_empty());
        assert!(slow.load(Ordering::Relaxed));
    }

    #[test]
    fn max_events_per_key_eviction() {
        use crate::denial_event::{AccessType, ResourceType};

        let buffer: EventBuffer = Arc::new(Mutex::new(HashMap::new()));
        let key = BufferKey { pid: 1 };

        let mut buf = buffer.lock().unwrap();
        let entry = buf.entry(key).or_default();

        // Fill beyond capacity.
        for i in 0..MAX_EVENTS_PER_KEY + 10 {
            if entry.events.len() >= MAX_EVENTS_PER_KEY {
                entry.events.pop_front();
            }
            entry.events.push_back(Arc::new(DenialEvent::new(
                String::new(),
                1,
                ResourceType::File,
                format!("path_{i}"),
                AccessType::Read,
                "2026-01-01T00:00:00Z".to_string(),
                4907,
            )));
        }

        assert_eq!(entry.events.len(), MAX_EVENTS_PER_KEY);
        // Oldest should have been evicted; newest is the last inserted.
        assert_eq!(
            entry.events.back().unwrap().object_name,
            format!("path_{}", MAX_EVENTS_PER_KEY + 9)
        );
    }
}
