//! Walks a sequence of WinEvent records produced by the permissive
//! learning-mode trace and returns the file-access events that survived
//! filtering.
//!
//! This PR introduces filesystem extraction only. Capability extraction
//! (`EventID=14` DACL ACE blobs) lands in a later PR; UI relaxation
//! (`EventID=27`) lands in a later PR. `requested_capabilities` is
//! exposed today as an always-empty placeholder so call-sites in
//! `stop`/`log` can stay stable.

use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "windows")]
use std::path::Path;

#[cfg(target_os = "windows")]
use windows::core::{w, PCWSTR};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
#[cfg(target_os = "windows")]
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryFilePath, EvtQueryForwardDirection, EvtRender,
    EvtRenderEventXml, EVT_HANDLE,
};

use crate::access_event::LearningModeAccessEvent;

/// EventID the PLM provider emits for a file/capability access that
/// *would* have been denied. Decoded by `crate::access_failure`.
pub(crate) const EVENT_ID_ACCESS_FAILURE: u32 = 14;
/// EventID the PLM provider emits for a UI-subsystem violation.
/// (Recognized by the XPath filter today; UI relaxation lands in a
/// later PR.)
pub(crate) const EVENT_ID_UI_VIOLATION: u32 = 27;

/// RAII wrapper that calls `EvtClose` on drop. A panic or `?`-early
/// return inside the rendering loop no longer leaks kernel ETW handles.
#[cfg(target_os = "windows")]
struct EvtHandleOwned(EVT_HANDLE);

#[cfg(target_os = "windows")]
impl Drop for EvtHandleOwned {
    fn drop(&mut self) {
        // SAFETY: `self.0` is an `EVT_HANDLE` this wrapper took
        // ownership of at construction and never handed out; `EvtClose`
        // is the correct release call and runs exactly once (on drop).
        unsafe {
            let _ = EvtClose(self.0);
        }
    }
}

pub struct ParseResult {
    pub valid_access_events: Vec<LearningModeAccessEvent>,
    /// Placeholder for the capability-extraction PR. Always empty in
    /// this PR; the field exists today so `stop`/`log` call-sites stay
    /// stable across the split.
    pub requested_capabilities: HashSet<String>,
}

impl ParseResult {
    /// True when the trace produced nothing mergeable into a config.
    pub fn is_empty(&self) -> bool {
        self.valid_access_events.is_empty() && self.requested_capabilities.is_empty()
    }
}

/// Abstraction over the native ETW query used by `for_each_event_xml`.
///
/// Splitting the batch/render/handle-release control flow (in
/// `drive_event_stream`) from the raw `Evt*` FFI (in `NativeEtwSource`)
/// lets the loop's real behavior — multi-batch iteration, end-of-stream
/// vs. error distinction, render-failure skipping, and handle release
/// on every exit path — be exercised by a fake source in unit tests
/// without a live `.etl` trace. See the `etw_stream_tests` module.
///
/// A handle returned by `next_batch` is owned by the driver until the
/// driver calls `close` on it exactly once (which the driver guarantees
/// even on early return or panic, via a batch-scoped drop guard).
#[cfg(any(target_os = "windows", test))]
trait EtwEventSource {
    /// Opaque per-event handle. `Copy` so the driver can hold a batch in
    /// a `Vec` and still hand each handle to `render`/`close` by value.
    type Handle: Copy;

    /// Pull the next batch of up to `max` event handles. An empty `Vec`
    /// signals end-of-stream (the native impl maps both a zero count and
    /// `ERROR_NO_MORE_ITEMS` to this). Any `Err` is a real mid-stream
    /// failure the driver propagates rather than treating as EOF.
    fn next_batch(&mut self, max: usize) -> Result<Vec<Self::Handle>>;

    /// Render one event handle to its XML form, reusing `buf` as scratch
    /// so the driver can amortize the allocation across the whole trace.
    fn render(&self, handle: Self::Handle, buf: &mut Vec<u16>) -> Result<String>;

    /// Release one event handle. Called exactly once for every handle
    /// `next_batch` returned, including on the error/panic unwind paths.
    fn close(&self, handle: Self::Handle);
}

/// Drive an [`EtwEventSource`] to completion, invoking `on_xml` once per
/// successfully rendered event. This is the platform-independent core of
/// `for_each_event_xml`; the Windows path wraps a [`NativeEtwSource`],
/// and tests wrap a scripted fake.
///
/// Semantics preserved from the original inlined loop:
/// * `next_batch` is called repeatedly until it yields an empty batch
///   (end of stream); traces larger than one batch are fully drained.
/// * A `next_batch` `Err` is a batch-level failure (no events at all)
///   and is propagated with context, since silently treating it as EOF
///   would look like a short-but-successful trace and under-grant.
/// * A `render` `Err` is a single unparsable record: it is counted and
///   skipped so one corrupt event can't discard every later access grant.
/// * An `on_xml` `Err` aborts the walk, but the batch drop guard still
///   releases every remaining handle in the current batch first.
#[cfg(any(target_os = "windows", test))]
fn drive_event_stream<S, F>(
    mut source: S,
    batch_size: usize,
    verbose: bool,
    mut on_xml: F,
) -> Result<()>
where
    S: EtwEventSource,
    F: FnMut(&str) -> Result<()>,
{
    /// Owns a batch of handles and closes each one on drop, so an early
    /// return from the loop body (an `on_xml` error) or a panic still
    /// releases every handle in the current batch exactly once.
    struct BatchGuard<'s, S: EtwEventSource> {
        source: &'s S,
        handles: Vec<S::Handle>,
    }
    impl<S: EtwEventSource> Drop for BatchGuard<'_, S> {
        fn drop(&mut self) {
            for &h in &self.handles {
                self.source.close(h);
            }
        }
    }

    // Reusable scratch buffer for `render` so we don't allocate a fresh
    // Vec<u16> per event.
    let mut render_buf: Vec<u16> = Vec::new();
    let mut rendered_count: usize = 0;
    let mut render_failures: usize = 0;
    loop {
        let handles = source.next_batch(batch_size).map_err(|e| {
            anyhow::anyhow!(
                "EvtNext failed mid-stream (rendered {} events so far): {e}",
                rendered_count
            )
        })?;
        if handles.is_empty() {
            break;
        }

        // Own all returned handles up front so every one is released on
        // any exit path (normal completion, `on_xml` error, or panic).
        let guard = BatchGuard {
            source: &source,
            handles,
        };
        for &handle in &guard.handles {
            // A single unrenderable event is skipped rather than
            // aborting the whole trace: propagating here would discard
            // every subsequent valid access grant and cause PLM to
            // under-grant on the next run.
            let xml = match source.render(handle, &mut render_buf) {
                Ok(xml) => xml,
                Err(e) => {
                    render_failures += 1;
                    if verbose {
                        eprintln!(
                            "Skipping unrenderable event (index {}, {} rendered / {} skipped so far): {e}",
                            rendered_count + render_failures,
                            rendered_count,
                            render_failures
                        );
                    }
                    continue;
                }
            };
            on_xml(&xml)?;
            rendered_count += 1;
        }
    }
    if render_failures > 0 && verbose {
        eprintln!(
            "Event parsing finished: {} events rendered, {} unrenderable events skipped",
            rendered_count, render_failures
        );
    }
    Ok(())
}

/// Live ETW source backing `for_each_event_xml`: owns the `EvtQuery`
/// handle and translates the driver's `next_batch`/`render`/`close`
/// calls into the corresponding `Evt*` FFI.
#[cfg(target_os = "windows")]
struct NativeEtwSource {
    query: EvtHandleOwned,
}

#[cfg(target_os = "windows")]
impl EtwEventSource for NativeEtwSource {
    type Handle = EVT_HANDLE;

    fn next_batch(&mut self, max: usize) -> Result<Vec<EVT_HANDLE>> {
        let mut events: Vec<isize> = vec![0isize; max];
        let mut returned: u32 = 0;
        // SAFETY: `self.query.0` is a live query handle owned by this
        // source. `events` is a `max`-element buffer we own and pass by
        // mutable slice; `EvtNext` writes at most `max` handles and
        // reports the count through `returned`, which we own.
        let next_ok = unsafe {
            EvtNext(
                self.query.0,
                &mut events,
                u32::MAX, // INFINITE
                0,
                &mut returned as *mut _,
            )
        };
        if let Err(e) = &next_ok {
            // End-of-stream is reported as an error with this code; map
            // it to an empty batch. Any other error is a real failure.
            if e.code() == ERROR_NO_MORE_ITEMS.to_hresult() {
                return Ok(Vec::new());
            }
            return Err(anyhow::anyhow!("{e}"));
        }
        Ok(events
            .iter()
            .take(returned as usize)
            .map(|&slot| EVT_HANDLE(slot))
            .collect())
    }

    fn render(&self, handle: EVT_HANDLE, buf: &mut Vec<u16>) -> Result<String> {
        render_event_xml(handle, buf)
    }

    fn close(&self, handle: EVT_HANDLE) {
        // SAFETY: `handle` is an event handle the driver received from
        // `next_batch` and hands back to `close` exactly once; `EvtClose`
        // is the correct release call for it.
        unsafe {
            let _ = EvtClose(handle);
        }
    }
}

/// Stream every event matching the access-failure XPath query out of an
/// .etl file, invoking `on_xml` once per rendered event XML string. The
/// caller-supplied closure accumulates state; this keeps peak memory
/// bounded (the previous `Vec<String>` buffer could run into multi-GB
/// on hour-long traces). The batch/render/handle-release semantics live
/// in [`drive_event_stream`]; this function only builds the live
/// [`NativeEtwSource`] the driver walks.
#[cfg(target_os = "windows")]
fn for_each_event_xml<F>(trace_file: &Path, verbose: bool, on_xml: F) -> Result<()>
where
    F: FnMut(&str) -> Result<()>,
{
    let path_w = wxc_common::string_util::to_wide(&trace_file.to_string_lossy());
    // The event-id filter is a compile-time constant, so bake it into
    // the binary as a wide, NUL-terminated literal with `w!` rather than
    // formatting + re-encoding it on every call. The literal must stay
    // in sync with the `EVENT_ID_*` constants above.
    const _: () = assert!(EVENT_ID_ACCESS_FAILURE == 14 && EVENT_ID_UI_VIOLATION == 27);
    let query = w!("*[System[EventID=14 or EventID=27]]");

    // SAFETY: `path_w` is a NUL-terminated wide buffer that outlives
    // this call and `query` is a `'static` wide literal; the `PCWSTR`s
    // borrow them for the duration of `EvtQuery`. The flags are valid
    // `EvtQuery` bit constants. The returned handle is immediately
    // adopted by `EvtHandleOwned` so it is closed on every exit path.
    let h_query = EvtHandleOwned(unsafe {
        EvtQuery(
            None,
            PCWSTR(path_w.as_ptr()),
            query,
            EvtQueryFilePath.0 | EvtQueryForwardDirection.0,
        )
    }?);

    // `EvtNext` batch size is intentionally large to reduce user→kernel
    // transitions on traces with tens of thousands of events.
    const BATCH: usize = 256;
    drive_event_stream(NativeEtwSource { query: h_query }, BATCH, verbose, on_xml)
}

/// Convert a byte count reported by `EvtRender`'s `BufferUsed` /
/// `BufferSize` out-params into a u16 element count, rounding **up** so
/// a trailing odd byte still gets a slot rather than being truncated.
/// (`EvtRender` sizes are byte counts; our backing buffer is `Vec<u16>`.)
#[cfg(any(target_os = "windows", test))]
fn bytes_to_u16_ceil(bytes: usize) -> usize {
    bytes.div_ceil(std::mem::size_of::<u16>())
}

/// Number of initialized u16s to expose (via `set_len`) after a
/// successful render: the reported byte count converted to whole u16s,
/// clamped to the buffer's capacity so we never claim more initialized
/// elements than the allocation holds.
#[cfg(any(target_os = "windows", test))]
fn rendered_len_u16(needed_bytes: usize, capacity_u16: usize) -> usize {
    (needed_bytes / std::mem::size_of::<u16>()).min(capacity_u16)
}

/// Trim a rendered UTF-16 buffer at the first NUL. `EvtRender`
/// NUL-terminates its XML output and reports the size *including* the
/// terminator, so the trailing NUL (and anything after it) must be
/// dropped before decoding.
#[cfg(any(target_os = "windows", test))]
fn trim_utf16_nul(buf: &[u16]) -> &[u16] {
    match buf.iter().position(|&c| c == 0) {
        Some(n) => &buf[..n],
        None => buf,
    }
}

#[cfg(target_os = "windows")]
fn render_event_xml(event: EVT_HANDLE, buf: &mut Vec<u16>) -> Result<String> {
    use windows::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};

    // Keep `buf` at `len == 0` while `EvtRender` writes through the raw
    // pointer using the explicit byte-size argument; only extend `len`
    // to the returned u16 count on the SUCCESS path so callers reusing
    // `render_buf` across events never observe uninitialized u16s.
    //
    // `clear()` runs BEFORE the reserve so that `Vec::reserve` —
    // which guarantees `capacity ≥ len + additional`, not
    // `capacity ≥ additional` — actually reaches the
    // `INITIAL_GUESS_U16` target on the first call where `len` had
    // been left non-zero by the previous event.
    //
    // `EvtRender` writes UTF-16, so the backing buffer is `Vec<u16>`
    // to guarantee 2-byte alignment (`Vec<u8>` is only 1-byte-aligned
    // and casting `.as_ptr()` to `*const u16` would be UB even on x86).
    // Note: `EvtRender`'s `BufferSize` / `BufferUsed` parameters are
    // BYTE counts, so multiply/divide by `size_of::<u16>()` at the
    // Win32 boundary.
    const INITIAL_GUESS_U16: usize = 4 * 1024;
    buf.clear();
    if buf.capacity() < INITIAL_GUESS_U16 {
        buf.reserve(INITIAL_GUESS_U16);
    }
    let cap_u16 = buf.capacity();
    let cap_bytes = cap_u16 * std::mem::size_of::<u16>();

    let mut needed: u32 = 0;
    let mut count: u32 = 0;
    // SAFETY: `event` is a live rendered-event handle owned by the
    // caller's `EvtHandleOwned`. `buf` has `capacity() == cap_u16` and
    // `len == 0`; we pass its raw pointer with the matching byte size
    // `cap_bytes`, so `EvtRender` writes only within the allocation.
    // `needed`/`count` are owned out-params.
    let first = unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            cap_bytes as u32,
            Some(buf.as_mut_ptr() as *mut _),
            &mut needed as *mut _,
            &mut count as *mut _,
        )
    };

    if first.is_err() {
        // ERROR_INSUFFICIENT_BUFFER means `needed` is now valid (in
        // bytes); grow and retry once. Any other error is fatal.
        // SAFETY: `GetLastError` reads the calling thread's last-error
        // code set by the `EvtRender` call immediately above; it has no
        // preconditions and no memory-safety implications.
        let win_err = unsafe { GetLastError() };
        if win_err != ERROR_INSUFFICIENT_BUFFER {
            return Err(anyhow::anyhow!(
                "EvtRender failed (Win32 error {:?})",
                win_err
            ));
        }
        if needed == 0 {
            return Err(anyhow::anyhow!("EvtRender returned zero size"));
        }
        let needed_u16 = bytes_to_u16_ceil(needed as usize);
        if buf.capacity() < needed_u16 {
            // `Vec::reserve(additional)` measures from `len`, not
            // `capacity` — since `buf` is empty (cleared above),
            // `additional == needed_u16` gets us `capacity ≥ needed_u16`.
            buf.reserve(needed_u16);
        }
        let new_cap_u16 = buf.capacity();
        let new_cap_bytes = new_cap_u16 * std::mem::size_of::<u16>();
        // SAFETY: identical contract to the first `EvtRender` call, now
        // with a buffer grown to `new_cap_bytes` (≥ `needed`) so the
        // render fits. `buf` is still at `len == 0`.
        let second = unsafe {
            EvtRender(
                None,
                event,
                EvtRenderEventXml.0,
                new_cap_bytes as u32,
                Some(buf.as_mut_ptr() as *mut _),
                &mut needed as *mut _,
                &mut count as *mut _,
            )
        };
        // Propagate any error AFTER ensuring `buf` is still at len=0
        // (no uninit u16s exposed to the reused-buffer caller path).
        second?;
    }

    // `needed` is bytes written including the terminating NUL.
    let init_u16 = rendered_len_u16(needed as usize, buf.capacity());
    // SAFETY: a successful `EvtRender` initialized `init_u16` u16s at
    // the start of `buf` (clamped to `capacity()`), so extending `len`
    // to `init_u16` exposes only initialized elements.
    unsafe {
        buf.set_len(init_u16);
    }
    let trimmed = trim_utf16_nul(buf);
    Ok(String::from_utf16_lossy(trimmed))
}

/// Decoded XML view of a single event's interesting fields.
pub(crate) struct ParsedEvent {
    pub(crate) event_id: u32,
    pub(crate) time_created: DateTime<Utc>,
    pub(crate) process_id: u32,
    pub(crate) thread_id: u32,
    /// EventData/Data values in document order.
    pub(crate) event_data: Vec<String>,
}

pub(crate) fn parse_event_xml(xml: &str) -> Option<ParsedEvent> {
    let mut reader = Reader::from_str(xml);
    let mut acc = StreamAcc::default();

    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            // roxmltree rejected malformed input with `.ok()?`; mirror
            // that by bailing to `None` on any reader error.
            Err(_) => return None,
            Ok(Event::Start(e)) => acc.open(&e, false),
            Ok(Event::Empty(e)) => acc.open(&e, true),
            Ok(Event::End(e)) => acc.close(e.local_name().as_ref()),
            Ok(Event::Text(t)) => {
                if acc.capture.is_some() {
                    if let Ok(raw) = std::str::from_utf8(t.as_ref()) {
                        if let Ok(s) = quick_xml::escape::unescape(raw) {
                            acc.push_text(&s);
                        }
                    }
                }
            }
            Ok(Event::CData(t)) => {
                if acc.capture.is_some() {
                    acc.push_text(&String::from_utf8_lossy(t.as_ref()));
                }
            }
            _ => {}
        }
    }

    // `roxmltree` returned `None` when the `<System>` element was
    // absent (the `?` on `root.children().find(System)`); every other
    // field carried a default. Preserve that single hard requirement.
    if !acc.saw_system {
        return None;
    }

    Some(ParsedEvent {
        event_id: acc.event_id,
        time_created: acc
            .time_created
            .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap()),
        process_id: acc.process_id,
        thread_id: acc.thread_id,
        event_data: acc.event_data,
    })
}

/// Which leaf element's inner text the streaming parser is currently
/// accumulating. `<TimeCreated>`/`<Execution>` are attribute-only and
/// never captured here.
enum Capture {
    EventId,
    Data,
}

/// Streaming replacement for the former per-event roxmltree DOM. Walks
/// the WinEvent record with a `quick-xml` pull parser, extracting only
/// the handful of fields the decoders consume and allocating a `String`
/// solely for those captured leaf texts — no document tree, no
/// intermediate node objects. Field semantics mirror the old DOM
/// lookups exactly, including "first element wins" and the `unwrap_or`
/// defaults.
#[derive(Default)]
struct StreamAcc {
    saw_system: bool,
    in_system: bool,
    in_event_data: bool,
    // `seen_*` guards reproduce roxmltree's `find(..)` first-match
    // semantics: a second `<EventID>`/`<TimeCreated>`/`<Execution>`
    // must not overwrite the first, even when the first failed to parse.
    seen_event_id: bool,
    seen_time_created: bool,
    seen_execution: bool,
    event_id: u32,
    time_created: Option<DateTime<Utc>>,
    process_id: u32,
    thread_id: u32,
    event_data: Vec<String>,
    capture: Option<(Capture, String)>,
}

impl StreamAcc {
    fn open(&mut self, e: &BytesStart<'_>, is_empty: bool) {
        let name = e.name();
        match name.local_name().as_ref() {
            b"System" => {
                self.saw_system = true;
                if !is_empty {
                    self.in_system = true;
                }
            }
            b"EventData" => {
                if !is_empty {
                    self.in_event_data = true;
                }
            }
            b"EventID" if self.in_system && !self.seen_event_id => {
                self.seen_event_id = true;
                if is_empty {
                    // Empty `<EventID/>` -> no text -> parse fails -> 0.
                    self.event_id = 0;
                } else {
                    self.capture = Some((Capture::EventId, String::new()));
                }
            }
            b"TimeCreated" if self.in_system && !self.seen_time_created => {
                self.seen_time_created = true;
                if let Some(v) = attr_value(e, b"SystemTime") {
                    if let Ok(dt) = DateTime::parse_from_rfc3339(&v) {
                        self.time_created = Some(dt.with_timezone(&Utc));
                    }
                }
            }
            b"Execution" if self.in_system && !self.seen_execution => {
                self.seen_execution = true;
                if let Some(n) = attr_value(e, b"ProcessID").and_then(|v| v.parse().ok()) {
                    self.process_id = n;
                }
                if let Some(n) = attr_value(e, b"ThreadID").and_then(|v| v.parse().ok()) {
                    self.thread_id = n;
                }
            }
            b"Data" | b"ComplexData" if self.in_event_data => {
                if is_empty {
                    self.event_data.push(String::new());
                } else {
                    self.capture = Some((Capture::Data, String::new()));
                }
            }
            _ => {}
        }
    }

    fn push_text(&mut self, s: &str) {
        if let Some((_, buf)) = &mut self.capture {
            buf.push_str(s);
        }
    }

    fn close(&mut self, local: &[u8]) {
        match local {
            b"System" => self.in_system = false,
            b"EventData" => self.in_event_data = false,
            _ => {}
        }
        let matches = matches!(
            (&self.capture, local),
            (Some((Capture::EventId, _)), b"EventID")
                | (Some((Capture::Data, _)), b"Data" | b"ComplexData")
        );
        if !matches {
            return;
        }
        let (kind, text) = self.capture.take().unwrap();
        match kind {
            Capture::EventId => self.event_id = text.parse::<u32>().unwrap_or(0),
            Capture::Data => self.event_data.push(text),
        }
    }
}

/// Read a single attribute's unescaped value as an owned `String`.
fn attr_value(e: &BytesStart<'_>, name: &[u8]) -> Option<String> {
    let a = e.try_get_attribute(name).ok().flatten()?;
    let raw = std::str::from_utf8(a.value.as_ref()).ok()?;
    quick_xml::escape::unescape(raw)
        .ok()
        .map(|v| v.into_owned())
}

/// Mutable per-trace accumulator. Fields are `pub(crate)` so the
/// sibling event-type decoders can write into them directly without an
/// inflated method surface.
pub(crate) struct ParseAccumulator {
    /// Cached lowercase form of the trace's current directory with
    /// trailing `\\` trimmed (computed once at construction so the hot
    /// `is_skippable` path doesn't allocate two `String`s per event).
    /// `None` when `current_directory` is `None` or is a bare drive
    /// root.
    pub(crate) cwd_lc_trimmed: Option<String>,
    pub(crate) cwd_lc_prefix: Option<String>,
    pub(crate) verbose: bool,
    pub(crate) valid_access_events: Vec<LearningModeAccessEvent>,
    /// Maps a normalized (lowercased) file path to the index of its
    /// entry in `valid_access_events`, so repeated access failures for
    /// the same file collapse to a single entry whose `access_mask` is
    /// the OR of every observed mask. The provider emits the same denied
    /// access many times across a trace, and a file is frequently
    /// touched with different masks (read, then write); without this a
    /// long trace balloons `valid_access_events` — and the generated
    /// config — with hundreds of thousands of redundant near-identical
    /// entries.
    pub(crate) access_event_index: HashMap<String, usize>,
    pub(crate) requested_capabilities: HashSet<String>,
    /// Count of events whose XML failed to parse in `consume` (i.e.
    /// `parse_event_xml` returned `None`). A malformed record is skipped
    /// rather than aborting the trace, but the running total is surfaced
    /// at the end of a parse so silent data loss is observable.
    pub(crate) parse_failures: usize,
}

impl ParseAccumulator {
    pub(crate) fn new(current_directory: Option<&str>, verbose: bool) -> Self {
        let (cwd_lc_trimmed, cwd_lc_prefix) = match current_directory {
            Some(cwd) => {
                let trimmed = cwd.trim_end_matches('\\');
                // A bare drive root is exactly two bytes: an ASCII letter
                // followed by ':' (e.g. "C:"). Inspecting the bytes directly
                // — rather than folding an `Option` from `chars().next()`
                // down to `false` — states that intent plainly and drops an
                // unwrap whose fallback is unreachable once the length is
                // known to be 2.
                let trimmed_bytes = trimmed.as_bytes();
                let is_drive_root = trimmed_bytes.len() == 2
                    && trimmed_bytes[0].is_ascii_alphabetic()
                    && trimmed_bytes[1] == b':';
                let lc = trimmed.to_ascii_lowercase();
                let prefix = if is_drive_root {
                    None
                } else {
                    Some(format!("{lc}\\"))
                };
                (Some(lc), prefix)
            }
            None => (None, None),
        };
        Self {
            cwd_lc_trimmed,
            cwd_lc_prefix,
            verbose,
            valid_access_events: Vec::new(),
            access_event_index: HashMap::new(),
            requested_capabilities: HashSet::new(),
            parse_failures: 0,
        }
    }

    /// Hot-path CWD / drive-letter filter for access events. Uses
    /// precomputed lowercase forms of `current_directory` to avoid two
    /// `String` allocs per event.
    pub(crate) fn is_skippable(&self, file_path: &str) -> bool {
        if let (Some(cwd_lowercase), cwd_prefix) = (&self.cwd_lc_trimmed, &self.cwd_lc_prefix) {
            let normalized_path = file_path.trim_end_matches('\\');
            let path_bytes = normalized_path.as_bytes();
            let cwd_bytes = cwd_lowercase.as_bytes();
            let matches_cwd_exactly = path_bytes.len() == cwd_bytes.len()
                && path_bytes
                    .iter()
                    .zip(cwd_bytes)
                    .all(|(path_byte, cwd_byte)| path_byte.eq_ignore_ascii_case(cwd_byte));
            let is_under_cwd = cwd_prefix
                .as_deref()
                .map(|prefix| {
                    let prefix_bytes = prefix.as_bytes();
                    path_bytes.len() >= prefix_bytes.len()
                        && path_bytes[..prefix_bytes.len()]
                            .iter()
                            .zip(prefix_bytes)
                            .all(|(path_byte, prefix_byte)| {
                                path_byte.eq_ignore_ascii_case(prefix_byte)
                            })
                })
                .unwrap_or(false);
            if matches_cwd_exactly || is_under_cwd {
                if self.verbose {
                    println!("Skipping current-directory event: {file_path}");
                }
                return true;
            }
        }
        if file_path.len() < 4 {
            if self.verbose {
                println!("Skipping too-short path event: {file_path}");
            }
            return true;
        }
        let second = file_path.chars().nth(1);
        if second != Some(':') {
            if self.verbose {
                println!("Skipping non-drive-letter path event: {file_path}");
            }
            return true;
        }
        false
    }

    /// Per-event entry point. Decodes the XML, dispatches by event id,
    /// and silently swallows malformed records (so a bad event mid-trace
    /// doesn't abort the rest). EventID=27 (UI violation) is recognized
    /// by the XPath filter today but contributes no relaxation until the
    /// UI-policy PR.
    fn consume(&mut self, xml: &str) {
        let Some(ev) = parse_event_xml(xml) else {
            self.parse_failures += 1;
            if self.verbose {
                eprintln!("Warning: skipping malformed event record (could not parse XML)");
            }
            return;
        };
        match ev.event_id {
            EVENT_ID_ACCESS_FAILURE => crate::access_failure::consume_access_failure(self, ev),
            EVENT_ID_UI_VIOLATION => {
                // UI-violation dispatch arrives in a later PR.
            }
            _ => {}
        }
    }

    fn into_result(self) -> ParseResult {
        if self.parse_failures > 0 {
            eprintln!(
                "Warning: skipped {} malformed event record(s) that could not be parsed",
                self.parse_failures
            );
        }
        ParseResult {
            valid_access_events: self.valid_access_events,
            requested_capabilities: self.requested_capabilities,
        }
    }
}

#[cfg(target_os = "windows")]
pub fn parse_events(
    trace_file: &Path,
    current_directory: Option<&str>,
    verbose: bool,
) -> Result<ParseResult> {
    let mut acc = ParseAccumulator::new(current_directory, verbose);
    for_each_event_xml(trace_file, verbose, |xml| {
        acc.consume(xml);
        Ok(())
    })?;
    Ok(acc.into_result())
}

/// Fixture-test seam: drive the same per-event accumulator
/// `parse_events` uses, but pull XML strings from an iterator rather
/// than a live ETW session.
pub fn parse_events_from_xml<I, S>(
    xmls: I,
    current_directory: Option<&str>,
    verbose: bool,
) -> ParseResult
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut acc = ParseAccumulator::new(current_directory, verbose);
    for xml in xmls {
        acc.consume(xml.as_ref());
    }
    acc.into_result()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_failure::{make_event_xml, FILE_PATH_INDEX};

    const ACCESS_MASK_INDEX: usize = 5;

    #[test]
    fn parse_event_xml_extracts_event_id_and_data() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>14</EventID>
            <TimeCreated SystemTime="2024-01-02T03:04:05.000Z"/>
            <Execution ProcessID="111" ThreadID="222"/>
          </System>
          <EventData>
            <Data>Permissive</Data>
            <Data>File</Data>
            <Data>C:\Users\test\foo.txt</Data>
            <Data>App.exe</Data>
            <Data>0</Data>
            <Data>0x1</Data>
          </EventData>
        </Event>"#;
        let ev = parse_event_xml(xml).expect("xml should parse");
        assert_eq!(ev.event_id, 14);
        assert_eq!(ev.process_id, 111);
        assert_eq!(ev.thread_id, 222);
        assert_eq!(ev.event_data.len(), 6);
        assert_eq!(ev.event_data[FILE_PATH_INDEX], "C:\\Users\\test\\foo.txt");
        assert_eq!(ev.event_data[ACCESS_MASK_INDEX], "0x1");
    }

    #[test]
    fn parse_event_xml_returns_none_for_malformed() {
        assert!(parse_event_xml("not xml").is_none());
        assert!(parse_event_xml("<not-an-event/>").is_none());
    }

    #[test]
    fn parse_events_from_xml_drives_access_failure_dispatch() {
        // Single fs-only event; ensure the dispatcher runs and the
        // event is collected.
        let xml = make_event_xml("C:\\app\\foo.txt", "0x1");
        let result = parse_events_from_xml(vec![xml], None, false);
        assert_eq!(result.valid_access_events.len(), 1);
        assert_eq!(result.valid_access_events[0].file_path, "C:\\app\\foo.txt");
    }
}

/// Coverage for the ETW stream driver ([`drive_event_stream`]) and the
/// buffer-sizing arithmetic in the render path — the pieces MGudgin
/// flagged as having zero test coverage because every other test feeds
/// synthetic XML straight into `parse_events_from_xml`, bypassing the
/// live `EvtQuery`/`EvtNext`/`EvtRender` walk.
///
/// The native `Evt*` FFI can't run without a real `.etl` trace, so the
/// loop is exercised through a scripted [`FakeEtwSource`] that stands in
/// for the ETW query: it reproduces multi-batch traces (>256 events),
/// end-of-stream detection, batch-level `EvtNext` failures, per-event
/// `EvtRender` failures, and — critically — lets the test assert every
/// handle is released even when the consumer errors partway through a
/// batch. The pure buffer-sizing helpers are tested directly.
#[cfg(test)]
mod etw_stream_tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};
    use std::rc::Rc;

    type Recorder = Rc<RefCell<Vec<u64>>>;

    /// A scripted stand-in for the native ETW query. `batches` is the
    /// sequence returned by successive `next_batch` calls (an empty
    /// `Vec` — or exhausting the queue — signals end-of-stream; an `Err`
    /// simulates a mid-stream `EvtNext` failure). `render_outcomes` maps
    /// a handle id to the XML it renders, or to a simulated `EvtRender`
    /// failure. `closed`/`rendered` are shared with the test via `Rc`,
    /// so handle-release and render ordering can be asserted even though
    /// `drive_event_stream` consumes the source by value.
    struct FakeEtwSource {
        batches: VecDeque<std::result::Result<Vec<u64>, String>>,
        render_outcomes: HashMap<u64, std::result::Result<String, String>>,
        closed: Recorder,
        rendered: Recorder,
    }

    impl FakeEtwSource {
        /// Returns the source plus the shared `(rendered, closed)`
        /// recorders the test reads after the walk completes.
        fn new(
            batches: Vec<std::result::Result<Vec<u64>, String>>,
            render_outcomes: HashMap<u64, std::result::Result<String, String>>,
        ) -> (Self, Recorder, Recorder) {
            let rendered: Recorder = Rc::new(RefCell::new(Vec::new()));
            let closed: Recorder = Rc::new(RefCell::new(Vec::new()));
            let source = Self {
                batches: batches.into(),
                render_outcomes,
                closed: Rc::clone(&closed),
                rendered: Rc::clone(&rendered),
            };
            (source, rendered, closed)
        }
    }

    impl EtwEventSource for FakeEtwSource {
        type Handle = u64;

        fn next_batch(&mut self, _max: usize) -> Result<Vec<u64>> {
            match self.batches.pop_front() {
                None => Ok(Vec::new()),
                Some(Ok(handles)) => Ok(handles),
                Some(Err(msg)) => Err(anyhow::anyhow!(msg)),
            }
        }

        fn render(&self, handle: u64, _buf: &mut Vec<u16>) -> Result<String> {
            self.rendered.borrow_mut().push(handle);
            match self.render_outcomes.get(&handle) {
                Some(Ok(xml)) => Ok(xml.clone()),
                Some(Err(msg)) => Err(anyhow::anyhow!(msg.clone())),
                None => Ok(format!("<Event id=\"{handle}\"/>")),
            }
        }

        fn close(&self, handle: u64) {
            self.closed.borrow_mut().push(handle);
        }
    }

    #[test]
    fn drains_multiple_batches_over_256_events() {
        // Two batches totalling 300 events, then end-of-stream. The
        // original inlined loop used a fixed 256-element array; this
        // proves the driver keeps calling `next_batch` until it drains a
        // trace larger than a single batch, and releases every handle.
        let first: Vec<u64> = (0..256).collect();
        let second: Vec<u64> = (256..300).collect();
        let (source, _rendered, closed) =
            FakeEtwSource::new(vec![Ok(first), Ok(second)], HashMap::new());

        let seen = RefCell::new(Vec::<String>::new());
        let result = drive_event_stream(source, 256, false, |xml| {
            seen.borrow_mut().push(xml.to_string());
            Ok(())
        });

        assert!(result.is_ok());
        assert_eq!(
            seen.borrow().len(),
            300,
            "every event across both batches renders"
        );
        assert_eq!(seen.borrow()[0], "<Event id=\"0\"/>");
        assert_eq!(seen.borrow()[299], "<Event id=\"299\"/>");
        assert_eq!(closed.borrow().len(), 300, "every handle is released");
    }

    #[test]
    fn empty_first_batch_is_end_of_stream() {
        let (source, _rendered, closed) = FakeEtwSource::new(vec![Ok(Vec::new())], HashMap::new());
        let mut calls = 0usize;
        let result = drive_event_stream(source, 256, false, |_xml| {
            calls += 1;
            Ok(())
        });
        assert!(result.is_ok());
        assert_eq!(calls, 0, "no events delivered for an empty trace");
        assert!(closed.borrow().is_empty(), "no handles to release");
    }

    #[test]
    fn next_batch_error_propagates_with_context_and_closes_prior_handles() {
        // First batch succeeds, second batch fails mid-stream. The error
        // must propagate (not be treated as EOF) and carry the
        // rendered-so-far count, and the first batch's handles must have
        // been released before the failure surfaces.
        let (source, _rendered, closed) = FakeEtwSource::new(
            vec![
                Ok(vec![10, 11]),
                Err("simulated EvtNext failure".to_string()),
            ],
            HashMap::new(),
        );

        let result = drive_event_stream(source, 256, false, |_xml| Ok(()));

        let err = result.expect_err("mid-stream EvtNext failure must propagate");
        let msg = format!("{err}");
        assert!(
            msg.contains("EvtNext failed mid-stream"),
            "unexpected error message: {msg}"
        );
        assert!(
            msg.contains("rendered 2 events so far"),
            "error should report the rendered-so-far count: {msg}"
        );
        let mut closed_ids = closed.borrow().clone();
        closed_ids.sort_unstable();
        assert_eq!(
            closed_ids,
            vec![10, 11],
            "first batch's handles are released before the failure propagates"
        );
    }

    #[test]
    fn render_failure_is_skipped_and_stream_continues() {
        // A single unrenderable event in the middle of a batch must be
        // skipped, not abort the whole trace — and all three handles
        // (including the one that failed to render) must still be closed.
        let mut outcomes = HashMap::new();
        outcomes.insert(20u64, Ok("<Event id=\"20\"/>".to_string()));
        outcomes.insert(21u64, Err("simulated EvtRender failure".to_string()));
        outcomes.insert(22u64, Ok("<Event id=\"22\"/>".to_string()));
        let (source, _rendered, closed) = FakeEtwSource::new(vec![Ok(vec![20, 21, 22])], outcomes);

        let seen = RefCell::new(Vec::<String>::new());
        let result = drive_event_stream(source, 256, false, |xml| {
            seen.borrow_mut().push(xml.to_string());
            Ok(())
        });

        assert!(result.is_ok(), "one bad render must not fail the walk");
        assert_eq!(
            *seen.borrow(),
            vec![
                "<Event id=\"20\"/>".to_string(),
                "<Event id=\"22\"/>".to_string()
            ],
            "the unrenderable middle event is skipped, the rest survive"
        );
        let mut closed_ids = closed.borrow().clone();
        closed_ids.sort_unstable();
        assert_eq!(
            closed_ids,
            vec![20, 21, 22],
            "the unrenderable event's handle is still released"
        );
    }

    #[test]
    fn on_xml_error_releases_every_handle_in_the_batch() {
        // The reviewer's key case: the consumer errors partway through a
        // batch. The walk must abort, but the batch drop guard must still
        // release EVERY handle in the batch (including the one that
        // errored and the ones after it) — no ETW handle leak on the
        // error path.
        let (source, _rendered, closed) =
            FakeEtwSource::new(vec![Ok(vec![30, 31, 32])], HashMap::new());

        let result = drive_event_stream(source, 256, false, |xml| {
            if xml.contains("id=\"31\"") {
                Err(anyhow::anyhow!("consumer rejected event 31"))
            } else {
                Ok(())
            }
        });

        assert!(result.is_err(), "an on_xml error aborts the walk");
        let mut closed_ids = closed.borrow().clone();
        closed_ids.sort_unstable();
        assert_eq!(
            closed_ids,
            vec![30, 31, 32],
            "every handle in the batch is released even though on_xml errored on 31"
        );
    }

    // ---- pure buffer-sizing arithmetic (the `EvtRender` growth path) ----

    #[test]
    fn bytes_to_u16_ceil_rounds_up_odd_trailing_byte() {
        assert_eq!(bytes_to_u16_ceil(0), 0);
        assert_eq!(bytes_to_u16_ceil(1), 1);
        assert_eq!(bytes_to_u16_ceil(2), 1);
        assert_eq!(bytes_to_u16_ceil(3), 2);
        assert_eq!(bytes_to_u16_ceil(4), 2);
        // A large "oversized render" byte count still converts cleanly.
        assert_eq!(bytes_to_u16_ceil(16_384), 8_192);
    }

    #[test]
    fn rendered_len_u16_clamps_to_capacity() {
        // Reported bytes fit inside the buffer: expose exactly that many
        // whole u16s.
        assert_eq!(rendered_len_u16(100, 4096), 50);
        // Reported bytes exceed capacity (defensive clamp so `set_len`
        // never claims uninitialized elements past the allocation).
        assert_eq!(rendered_len_u16(16_384, 4096), 4096);
        // Exact fit.
        assert_eq!(rendered_len_u16(8192, 4096), 4096);
    }

    #[test]
    fn trim_utf16_nul_stops_at_first_terminator() {
        let no_nul: Vec<u16> = "abc".encode_utf16().collect();
        assert_eq!(trim_utf16_nul(&no_nul), no_nul.as_slice());

        let mut with_nul: Vec<u16> = "ab".encode_utf16().collect();
        with_nul.push(0);
        with_nul.extend("garbage".encode_utf16());
        assert_eq!(
            trim_utf16_nul(&with_nul),
            "ab".encode_utf16().collect::<Vec<u16>>().as_slice(),
            "everything from the NUL onward is dropped"
        );

        let leading_nul = [0u16, b'x' as u16];
        assert!(trim_utf16_nul(&leading_nul).is_empty());
    }
}
