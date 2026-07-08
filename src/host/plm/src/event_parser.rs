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
use std::collections::HashSet;
#[cfg(target_os = "windows")]
use std::path::Path;

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
#[cfg(target_os = "windows")]
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryFilePath, EvtQueryForwardDirection, EvtRender,
    EvtRenderEventXml, EVT_HANDLE,
};

use crate::access_event::LearningModeAccessEvent;

/// RAII wrapper that calls `EvtClose` on drop. A panic or `?`-early
/// return inside the rendering loop no longer leaks kernel ETW handles.
#[cfg(target_os = "windows")]
struct EvtHandleOwned(EVT_HANDLE);

#[cfg(target_os = "windows")]
impl Drop for EvtHandleOwned {
    fn drop(&mut self) {
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

#[cfg(target_os = "windows")]
fn to_wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
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
/// `ERROR_NO_MORE_ITEMS`; any other `EvtNext` / `EvtRender` failure is
/// propagated rather than silently dropped — silent failure would look
/// like a successful but short trace and cause PLM to under-grant on
/// the next run.
#[cfg(target_os = "windows")]
fn for_each_event_xml<F>(trace_file: &Path, mut on_xml: F) -> Result<()>
where
    F: FnMut(&str) -> Result<()>,
{
    let path_w = to_wide_z(&trace_file.to_string_lossy());
    let query_w = to_wide_z("*[System[EventID=14 or EventID=27]]");

    let h_query = EvtHandleOwned(unsafe {
        EvtQuery(
            None,
            PCWSTR(path_w.as_ptr()),
            PCWSTR(query_w.as_ptr()),
            EvtQueryFilePath.0 | EvtQueryForwardDirection.0,
        )
    }?);

    // Reusable scratch buffer for `render_event_xml` so we don't
    // allocate a fresh Vec<u8> per event.
    let mut render_buf: Vec<u16> = Vec::new();
    let mut rendered_count: usize = 0;
    const BATCH: usize = 256;
    loop {
        let mut events: [isize; BATCH] = [0isize; BATCH];
        let mut returned: u32 = 0;
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

        // Wrap ALL returned slots into `EvtHandleOwned` up front so a
        // mid-batch `?` propagation drops (and closes) the still-owned
        // slots after the failing index.
        let owned: Vec<EvtHandleOwned> = events
            .iter()
            .take(returned as usize)
            .map(|&slot| EvtHandleOwned(EVT_HANDLE(slot)))
            .collect();
        for handle in &owned {
            let xml = render_event_xml(handle.0, &mut render_buf).map_err(|e| {
                anyhow::anyhow!(
                    "EvtRender failed at event {} of batch (rendered {} so far): {e}",
                    rendered_count,
                    rendered_count
                )
            })?;
            on_xml(&xml)?;
            rendered_count += 1;
        }
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
    // `set_len(0)` runs BEFORE the reserve so that `Vec::reserve` —
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
    unsafe {
        buf.set_len(0);
    }
    if buf.capacity() < INITIAL_GUESS_U16 {
        buf.reserve(INITIAL_GUESS_U16);
    }
    let cap_u16 = buf.capacity();
    let cap_bytes = cap_u16 * std::mem::size_of::<u16>();

    let mut needed: u32 = 0;
    let mut count: u32 = 0;
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
            buf.reserve(needed_u16 - buf.capacity());
        }
        let new_cap_u16 = buf.capacity();
        let new_cap_bytes = new_cap_u16 * std::mem::size_of::<u16>();
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
    #[allow(dead_code)]
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
pub(crate) struct ParseAccumulator<'a> {
    #[allow(dead_code)]
    pub(crate) current_directory: Option<&'a str>,
    /// Cached lowercase form of `current_directory` with trailing `\\`
    /// trimmed (computed once at construction so the hot
    /// `is_skippable` path doesn't allocate two `String`s per event).
    /// `None` when `current_directory` is `None` or is a bare drive
    /// root.
    pub(crate) cwd_lc_trimmed: Option<String>,
    pub(crate) cwd_lc_prefix: Option<String>,
    pub(crate) verbose: bool,
    pub(crate) valid_access_events: Vec<LearningModeAccessEvent>,
    pub(crate) requested_capabilities: HashSet<String>,
}

impl<'a> ParseAccumulator<'a> {
    fn new(current_directory: Option<&'a str>, verbose: bool) -> Self {
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
            current_directory,
            cwd_lc_trimmed,
            cwd_lc_prefix,
            verbose,
            valid_access_events: Vec::new(),
            requested_capabilities: HashSet::new(),
        }
    }

    /// Hot-path CWD / drive-letter filter for access events. Uses
    /// precomputed lowercase forms of `current_directory` to avoid two
    /// `String` allocs per event.
    pub(crate) fn is_skippable(&self, file_path: &str) -> bool {
        if let (Some(cwd_lc), prefix_opt) = (&self.cwd_lc_trimmed, &self.cwd_lc_prefix) {
            let normalized = file_path.trim_end_matches('\\');
            let nb = normalized.as_bytes();
            let cwd_b = cwd_lc.as_bytes();
            let cwd_eq = nb.len() == cwd_b.len()
                && nb.iter().zip(cwd_b).all(|(a, b)| a.eq_ignore_ascii_case(b));
            let prefix_match = prefix_opt
                .as_deref()
                .map(|p| {
                    let pb = p.as_bytes();
                    nb.len() >= pb.len()
                        && nb[..pb.len()]
                            .iter()
                            .zip(pb)
                            .all(|(a, b)| a.eq_ignore_ascii_case(b))
                })
                .unwrap_or(false);
            if cwd_eq || prefix_match {
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
            return;
        };
        match ev.event_id {
            27 => {
                // UI-violation dispatch arrives in a later PR.
            }
            _ => crate::access_failure::consume_access_failure(self, ev),
        }
    }

    fn into_result(self) -> ParseResult {
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
    for_each_event_xml(trace_file, |xml| {
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
