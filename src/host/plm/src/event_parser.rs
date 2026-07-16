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

/// Stream every event matching the access-failure XPath query out of an
/// .etl file, invoking `on_xml` once per rendered event XML string. The
/// caller-supplied closure accumulates state; this keeps peak memory
/// bounded (a `Vec<String>` buffer could run into multi-GB on hour-long
/// traces).
///
/// `EvtNext` batch size is intentionally large (256) to reduce
/// user→kernel transitions on traces with tens of thousands of events.
/// End-of-stream is distinguished from real errors by matching
/// `ERROR_NO_MORE_ITEMS`.
///
/// A failure to *render* a single event (`EvtRender`) is treated as an
/// unparsable record: it is skipped and stream processing continues, so
/// one malformed/corrupt event in the middle of a trace can't discard
/// every subsequent valid access grant. A batch-level `EvtNext` failure
/// (which yields no events at all, not just an unparsable one) is still
/// propagated rather than silently dropped — swallowing it would look
/// like a successful but short trace and cause PLM to under-grant on
/// the next run.
#[cfg(target_os = "windows")]
fn for_each_event_xml<F>(trace_file: &Path, verbose: bool, mut on_xml: F) -> Result<()>
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

    // Reusable scratch buffer for `render_event_xml` so we don't
    // allocate a fresh Vec<u8> per event.
    let mut render_buf: Vec<u16> = Vec::new();
    let mut rendered_count: usize = 0;
    let mut render_failures: usize = 0;
    const BATCH: usize = 256;
    loop {
        let mut events: [isize; BATCH] = [0isize; BATCH];
        let mut returned: u32 = 0;
        // SAFETY: `h_query.0` is a live query handle owned by
        // `h_query`. `events` is a `BATCH`-element array we own and pass
        // by mutable reference; `EvtNext` writes at most `BATCH` handles
        // and reports the count through `returned`, which we own.
        let next_ok = unsafe {
            EvtNext(
                h_query.0,
                &mut events,
                u32::MAX, // INFINITE
                0,
                &mut returned as *mut _,
            )
        };
        if let Err(e) = &next_ok {
            if e.code() == ERROR_NO_MORE_ITEMS.to_hresult() {
                break;
            }
            return Err(anyhow::anyhow!(
                "EvtNext failed mid-stream (rendered {} events so far): {e}",
                rendered_count
            ));
        }
        if returned == 0 {
            break;
        }

        // Wrap ALL returned slots into `EvtHandleOwned` up front so an
        // early return from the loop body (an `on_xml` error, or a
        // panic) drops — and closes — the still-owned slots after the
        // current index. Render failures no longer early-return (they
        // `continue`), but the up-front wrapping keeps every remaining
        // handle owned so no ETW handle can leak on any exit path.
        let owned: Vec<EvtHandleOwned> = events
            .iter()
            .take(returned as usize)
            .map(|&slot| EvtHandleOwned(EVT_HANDLE(slot)))
            .collect();
        for handle in &owned {
            // A single unrenderable event is skipped rather than
            // aborting the whole trace: propagating here would discard
            // every subsequent valid access grant and cause PLM to
            // under-grant on the next run.
            let xml = match render_event_xml(handle.0, &mut render_buf) {
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
        let needed_u16 = (needed as usize).div_ceil(std::mem::size_of::<u16>());
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
    let init_u16 = (needed as usize / std::mem::size_of::<u16>()).min(buf.capacity());
    // SAFETY: a successful `EvtRender` initialized `init_u16` u16s at
    // the start of `buf` (clamped to `capacity()`), so extending `len`
    // to `init_u16` exposes only initialized elements.
    unsafe {
        buf.set_len(init_u16);
    }
    let trimmed = match buf.iter().position(|&c| c == 0) {
        Some(n) => &buf[..n],
        None => &buf[..],
    };
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
    let doc = roxmltree::Document::parse(xml).ok()?;
    let root = doc.root_element();

    let system = root.children().find(|n| n.has_tag_name("System"))?;
    let event_id = system
        .children()
        .find(|n| n.has_tag_name("EventID"))
        .and_then(|n| n.text())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    let time_created = system
        .children()
        .find(|n| n.has_tag_name("TimeCreated"))
        .and_then(|n| n.attribute("SystemTime"))
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap());

    let execution = system.children().find(|n| n.has_tag_name("Execution"));
    let process_id = execution
        .and_then(|n| n.attribute("ProcessID"))
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let thread_id = execution
        .and_then(|n| n.attribute("ThreadID"))
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    let mut event_data = Vec::new();
    if let Some(ed) = root.children().find(|n| n.has_tag_name("EventData")) {
        for child in ed.children().filter(|n| n.is_element()) {
            let tag = child.tag_name().name();
            if tag == "Data" || tag == "ComplexData" {
                event_data.push(child.text().unwrap_or("").to_string());
            }
        }
    }

    Some(ParsedEvent {
        event_id,
        time_created,
        process_id,
        thread_id,
        event_data,
    })
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
    fn new(current_directory: Option<&str>, verbose: bool) -> Self {
        let (cwd_lc_trimmed, cwd_lc_prefix) = match current_directory {
            Some(cwd) => {
                let trimmed = cwd.trim_end_matches('\\');
                let is_drive_root = trimmed.len() == 2
                    && trimmed.chars().nth(1) == Some(':')
                    && trimmed
                        .chars()
                        .next()
                        .map(|c| c.is_ascii_alphabetic())
                        .unwrap_or(false);
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
        if let (Some(cwd_lc), prefix_opt) = (&self.cwd_lc_trimmed, &self.cwd_lc_prefix) {
            let normalized = file_path.trim_end_matches('\\');
            let normalized_bytes = normalized.as_bytes();
            let cwd_bytes = cwd_lc.as_bytes();
            let cwd_equals = normalized_bytes.len() == cwd_bytes.len()
                && normalized_bytes
                    .iter()
                    .zip(cwd_bytes)
                    .all(|(lhs, rhs)| lhs.eq_ignore_ascii_case(rhs));
            let prefix_match = prefix_opt
                .as_deref()
                .map(|prefix| {
                    let prefix_bytes = prefix.as_bytes();
                    normalized_bytes.len() >= prefix_bytes.len()
                        && normalized_bytes[..prefix_bytes.len()]
                            .iter()
                            .zip(prefix_bytes)
                            .all(|(lhs, rhs)| lhs.eq_ignore_ascii_case(rhs))
                })
                .unwrap_or(false);
            if cwd_equals || prefix_match {
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
