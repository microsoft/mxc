//! Port of `event_dacl_parser.ps1`.
//!
//! Walks a sequence of WinEvent records produced by the permissive
//! learning-mode trace and returns:
//!   - `valid_access_events`: file-access events that survived filtering
//!     (real, non-self file paths).
//!   - `requested_capabilities`: capability names discovered by feeding
//!     each event's DACL ACE blob through `extract_caps`.
//!   - `need_ui`: true if any UI event (id 27) was observed.

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
use crate::extract_caps;

/// RAII wrapper that calls `EvtClose` on drop. Replaces the previous
/// manual `EvtClose` calls so a panic or `?`-early-return inside the
/// rendering loop no longer leaks kernel ETW handles.
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

// File path we treat as "no useful info" and skip.
const MOUNT_POINT_MANAGER: &str = "\\Device\\MountPointManager";

// Learning-mode violation categories + JOB_OBJECT_UILIMIT_* constants live
// in `crate::ui_limits` so they're reachable from cross-platform code
// (notably `config.rs` and its tests). Re-export them here so existing
// `crate::event_parser::*` call sites keep working.
pub use crate::ui_limits::{
    ui_limit_name, UiEvent, CONVERT_TO_GUI, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_IME,
    JOB_OBJECT_UILIMIT_INJECTION, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD, UI_OPERATION,
};

// Event property indexes for EventID=14 access events (matches the
// PowerShell parser's index map).
const LEARNING_MODE_INDEX: usize = 0;
const RESOURCE_TYPE_INDEX: usize = 1;
const FILE_PATH_INDEX: usize = 2;
const APP_PATH_INDEX: usize = 3;
const ACCESS_MASK_INDEX: usize = 5;

pub struct ParseResult {
    pub valid_access_events: Vec<LearningModeAccessEvent>,
    pub requested_capabilities: HashSet<String>,
    /// True when at least one `CONVERT_TO_GUI` violation was observed.
    /// Drives the legacy behavior of flipping `ui.disable` to `false`.
    pub need_ui: bool,
    /// Total number of EventID=27 records observed, regardless of category.
    pub ui_event_count: u32,
    pub ui_events: Vec<UiEvent>,
    /// OR of the `Detail` values from every `UI_OPERATION` violation.
    /// Each bit is one of the `JOB_OBJECT_UILIMIT_*` constants and
    /// indicates the specific UI limit the contained process tripped.
    pub ui_operation_flags: u32,
}

impl ParseResult {
    /// True when the trace produced nothing mergeable into a config:
    /// no access events, no capability requests, no `CONVERT_TO_GUI`
    /// hint, and no `UI_OPERATION` flags. Callers (notably `stop::run`)
    /// use this to skip the adjusted-config write rather than emit a
    /// file identical to the input.
    pub fn is_empty(&self) -> bool {
        self.valid_access_events.is_empty()
            && self.requested_capabilities.is_empty()
            && !self.need_ui
            && self.ui_operation_flags == 0
    }
}

/// Parsed payload of a UI-injection (EventID=27) event.
///
/// Pure data; the type itself lives in `crate::ui_limits::UiEvent` and is
/// re-exported above. The decoding paths
/// (`parse_ui_event_payload`, `parse_ui_event_from_named`) live in this
/// Windows-only module because they share a hex-decoding helper with the
/// ACE walker.
///
/// The provider emits these via a manifest whose schema isn't always
/// available to consumers, so the event commonly surfaces inside
/// `<ProcessingErrorData><EventPayload>` as an opaque hex blob. We
/// decode it manually using the documented layout:
///
/// * `process_name` — UTF-8 / ASCII bytes, null-terminated.
/// * `process_id` — 8 bytes, little-endian.
/// * `sequence_number` — 8 bytes, little-endian.
/// * `category` — 4 bytes, little-endian.
/// * `detail` — 4 bytes, little-endian.
/// * `denied` — 0, 1, or 4 trailing bytes; when present, non-zero means denied.
fn read_u32_le(bytes: &[u8], off: &mut usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    if end > bytes.len() {
        return None;
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes[*off..end]);
    let v = u32::from_le_bytes(arr);
    *off = end;
    Some(v)
}

fn read_u64_le(bytes: &[u8], off: &mut usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    if end > bytes.len() {
        return None;
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[*off..end]);
    let v = u64::from_le_bytes(arr);
    *off = end;
    Some(v)
}

/// Decode a UI-injection event payload from its hex representation.
/// Returns `None` if the hex is malformed or the payload is shorter
/// than the documented fixed-width tail.
pub fn parse_ui_event_payload(payload_hex: &str) -> Option<UiEvent> {
    let bytes = extract_caps::parse_hex_string(payload_hex).ok()?;

    // Process name: bytes up to (but not including) the first 0x00.
    // The terminator itself is consumed before the fixed-width tail.
    let null_pos = bytes.iter().position(|&b| b == 0)?;
    let process_name = String::from_utf8_lossy(&bytes[..null_pos]).into_owned();
    let mut off = null_pos + 1;

    let process_id = read_u64_le(&bytes, &mut off)?;
    let sequence_number = read_u64_le(&bytes, &mut off)?;
    let category = read_u32_le(&bytes, &mut off)?;
    let detail = read_u32_le(&bytes, &mut off)?;

    // `denied` is optional: payloads observed in the wild trail with 0, 1, or
    // 4 bytes for it. Anything else means the payload doesn't match.
    let denied = match bytes.len().checked_sub(off) {
        Some(0) => None,
        Some(1) => Some(bytes[off] != 0),
        Some(4) => {
            let mut a = [0u8; 4];
            a.copy_from_slice(&bytes[off..off + 4]);
            Some(u32::from_le_bytes(a) != 0)
        }
        _ => return None,
    };

    Some(UiEvent {
        process_name,
        process_id,
        sequence_number,
        category,
        detail,
        denied,
    })
}

/// Parse an integer that may be written as decimal or `0x`-prefixed hex.
fn parse_u64_loose(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Parse a UI-injection event whose `EventData` carries named `Data`
/// children (i.e. the consumer was able to resolve the provider manifest).
/// Recognised names: `ProcessName`, `ProcessId`, `SequenceNumber`,
/// `Category`, `Detail`, and optional `Denied` (`true`/`false`/integer).
pub fn parse_ui_event_from_named(named: &[(String, String)]) -> Option<UiEvent> {
    let mut process_name: Option<String> = None;
    let mut process_id: Option<u64> = None;
    let mut sequence_number: Option<u64> = None;
    let mut category: Option<u32> = None;
    let mut detail: Option<u32> = None;
    let mut denied: Option<bool> = None;

    for (name, val) in named {
        match name.as_str() {
            "ProcessName" => process_name = Some(val.clone()),
            "ProcessId" => process_id = parse_u64_loose(val),
            "SequenceNumber" => sequence_number = parse_u64_loose(val),
            "Category" => category = parse_u64_loose(val).map(|v| v as u32),
            "Detail" => detail = parse_u64_loose(val).map(|v| v as u32),
            "Denied" => {
                let t = val.trim();
                denied = match t.to_ascii_lowercase().as_str() {
                    "true" | "1" => Some(true),
                    "false" | "0" => Some(false),
                    _ => parse_u64_loose(t).map(|v| v != 0),
                };
            }
            _ => {}
        }
    }

    Some(UiEvent {
        process_name: process_name?,
        process_id: process_id?,
        sequence_number: sequence_number?,
        category: category?,
        detail: detail?,
        denied,
    })
}

#[cfg(target_os = "windows")]
fn to_wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Stream every event matching the access-failure XPath query out of an
/// .etl file, invoking `on_xml` once per rendered event XML string. The
/// caller-supplied closure is responsible for accumulating state; this
/// keeps peak memory bounded (the previous `Vec<String>` buffer could
/// run into multi-GB on hour-long traces).
///
/// The `EvtNext` batch size is intentionally large (256) to reduce
/// user→kernel transitions on traces with tens of thousands of events.
/// `EvtNext` returns fewer slots when the channel runs out, so this is
/// safe to oversize. End-of-stream is distinguished from real errors by
/// matching `ERROR_NO_MORE_ITEMS`; any other `EvtNext` or `EvtRender`
/// failure is propagated rather than silently dropped — silent failure
/// would look like a successful but short trace and cause PLM to
/// under-grant on the next run.
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

    // Reusable scratch buffer for `render_event_xml` so we don't allocate
    // a fresh Vec<u8> per event.
    let mut render_buf: Vec<u8> = Vec::new();
    let mut rendered_count: usize = 0;
    const BATCH: usize = 256;
    loop {
        // EvtNext takes an `&mut [isize]` of EVT_HANDLE-sized slots.
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
            // ERROR_NO_MORE_ITEMS is the documented end-of-stream signal;
            // anything else is a real failure and must not be silently
            // dropped.
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

        // R5-9 handle-leak fix: wrap ALL returned slots into
        // `EvtHandleOwned` up front. If `render_event_xml` or
        // `on_xml(&xml)` propagates mid-batch via `?`, the still-owned
        // slots after the failing index are dropped (and their
        // `EvtClose` runs) as part of unwinding `owned`. The
        // previous code only converted slots one at a time inside the
        // loop and leaked any unconverted slots on the early-return
        // path.
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
        // owned's Drop closes any remaining handles.
    }
    // h_query's Drop calls EvtClose.
    Ok(())
}

#[cfg(target_os = "windows")]
fn render_event_xml(event: EVT_HANDLE, buf: &mut Vec<u8>) -> Result<String> {
    use windows::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};

    // Round-3 performance: skip the probe-then-call EvtRender pattern.
    // Most events render comfortably under 8 KiB. We try with whatever
    // capacity the caller's reusable buffer already has (~probably the
    // peak size seen so far this trace, post-warmup) and only fall back
    // to a probe call when EvtRender reports ERROR_INSUFFICIENT_BUFFER.
    // This halves the EvtRender syscall count on the steady state and
    // leaves correctness untouched.
    const INITIAL_GUESS_BYTES: usize = 8 * 1024;
    if buf.capacity() < INITIAL_GUESS_BYTES {
        buf.reserve(INITIAL_GUESS_BYTES - buf.capacity());
    }
    // Round-6 reliability finding #3: keep `buf` at `len == 0` while we
    // call `EvtRender`. The Win32 API writes through the raw pointer
    // using the explicit size argument and does not care about Rust's
    // `Vec::len`, so we don't need to extend it up-front. Only extend
    // `len` to `needed` on the SUCCESS path; on every error path leave
    // the Vec empty so callers reusing `render_buf` across events
    // never observe uninitialized bytes (previously `set_len(cap)`
    // before the fallible call left the Vec exposing uninit memory
    // when EvtRender failed).
    unsafe {
        buf.set_len(0);
    }
    let cap = buf.capacity();

    let mut needed: u32 = 0;
    let mut count: u32 = 0;
    let first = unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            cap as u32,
            Some(buf.as_mut_ptr() as *mut _),
            &mut needed as *mut _,
            &mut count as *mut _,
        )
    };

    if first.is_err() {
        // ERROR_INSUFFICIENT_BUFFER means `needed` is now valid; grow
        // and retry once. Any other error is fatal.
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
        if buf.capacity() < needed as usize {
            buf.reserve(needed as usize - buf.capacity());
        }
        let new_cap = buf.capacity();
        let second = unsafe {
            EvtRender(
                None,
                event,
                EvtRenderEventXml.0,
                new_cap as u32,
                Some(buf.as_mut_ptr() as *mut _),
                &mut needed as *mut _,
                &mut count as *mut _,
            )
        };
        // Propagate any error AFTER ensuring `buf` is still at len=0
        // (no uninit bytes exposed to the reused-buffer caller path).
        second?;
    }

    // Both EvtRender calls succeeded: `needed` is the byte count
    // written into the buffer. Extend `len` so the slice below sees
    // initialized memory only (`needed` capped at capacity defensively
    // in case the kernel returned a value larger than the buffer it
    // wrote into — impossible in practice but cheap to guard).
    let init_bytes = (needed as usize).min(buf.capacity());
    unsafe {
        buf.set_len(init_bytes);
    }
    // Buffer is UTF-16; trim trailing NUL.
    let u16_count = init_bytes / 2;
    let u16_slice: &[u16] =
        unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u16, u16_count) };
    let trimmed = match u16_slice.iter().position(|&c| c == 0) {
        Some(n) => &u16_slice[..n],
        None => u16_slice,
    };
    Ok(String::from_utf16_lossy(trimmed))
}

/// Decoded XML view of a single event's interesting fields.
struct ParsedEvent {
    event_id: u32,
    time_created: DateTime<Utc>,
    process_id: u32,
    thread_id: u32,
    /// EventData/Data values in document order. May be Data or ComplexData.
    /// For Data nodes this is the inner text; for ComplexData this is
    /// also the inner text (concatenated hex-encoded blob).
    event_data: Vec<String>,
    /// Index into `event_data` of the 5th `<ComplexData>` sibling (the
    /// DACL ACE blob on EventID=14 access events). `None` if fewer than
    /// five ComplexData children were seen. Borrowed directly rather
    /// than cloned to avoid a second `String` allocation of the largest
    /// per-event field (round-6 perf finding #1).
    complex_data_4_idx: Option<usize>,
    /// EventData/Data entries paired with their `Name` attribute (when set),
    /// in document order. Used for events whose schema is resolved at render
    /// time (e.g. UI injection event_id=27 with provider manifest available).
    event_data_named: Vec<(String, String)>,
    /// Hex-encoded `<ProcessingErrorData><EventPayload>` body for events
    /// whose manifest schema can't be resolved at render time. UI
    /// injection events (id 27) are commonly delivered this way.
    processing_error_payload: Option<String>,
}

fn parse_event_xml(xml: &str) -> Option<ParsedEvent> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let root = doc.root_element();

    // <System> child
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

    // <EventData> child: zero or more Data/ComplexData nodes in order.
    let mut event_data = Vec::new();
    // R5-14: `event_data_named` is only consumed by the EventID=27 UI
    // event path. Skip building it for every other event (~99.99% of a
    // typical access trace). ~1.2M `(String,String)` allocs saved per
    // 100k events.
    let need_named = event_id == 27;
    let mut event_data_named: Vec<(String, String)> = Vec::new();
    // Round-6 perf finding #1: track the position of the 5th
    // `<ComplexData>` sibling (the DACL ACE blob) inside `event_data`
    // rather than allocating a second `String` copy of its inner text.
    // The blob is the largest single field on an EventID=14 access
    // event (multi-KB of hex), and previously we paid an unconditional
    // duplicate `to_string()` plus the wasted push into `event_data`
    // for it. The consumer at the call site borrows the slot directly.
    let mut complex_data_4_idx: Option<usize> = None;
    if let Some(ed) = root.children().find(|n| n.has_tag_name("EventData")) {
        let mut complex_index = 0usize;
        for child in ed.children().filter(|n| n.is_element()) {
            let tag = child.tag_name().name();
            if tag == "Data" || tag == "ComplexData" {
                let text = child.text().unwrap_or("").to_string();
                if need_named {
                    if let Some(name) = child.attribute("Name") {
                        // R5-15: clone only when we actually emit the named
                        // entry. Most <Data> children have no `Name=` so
                        // the clone was pure overhead.
                        event_data_named.push((name.to_string(), text.clone()));
                    }
                }
                let pushed_idx = event_data.len();
                event_data.push(text);
                if tag == "ComplexData" {
                    if complex_index == 4 {
                        complex_data_4_idx = Some(pushed_idx);
                    }
                    complex_index += 1;
                }
            }
        }
    }

    // <ProcessingErrorData> child carries an opaque hex EventPayload for
    // events the consumer can't render via the provider manifest.
    let processing_error_payload = root
        .children()
        .find(|n| n.has_tag_name("ProcessingErrorData"))
        .and_then(|n| n.children().find(|c| c.has_tag_name("EventPayload")))
        .and_then(|n| n.text())
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty());

    Some(ParsedEvent {
        event_id,
        time_created,
        process_id,
        thread_id,
        event_data,
        event_data_named,
        complex_data_4_idx,
        processing_error_payload,
    })
}

/// Strip Windows path-namespace prefixes so downstream filters that
/// expect a DOS form (`C:\...`) see one.
///
/// Round-6 correctness finding #2: previously this function only
/// handled `\??\` (the NT-object prefix). Paths emitted with the
/// verbatim (`\\?\C:\...`) or DOS-device (`\\.\C:\...`) prefixes
/// reached `is_skippable` which then rejected them on the "second
/// char is not `:`" gate, silently dropping the access event before
/// `config::normalize_path` ever got a chance to canonicalize it.
///
/// `\??\` and `\\?\` both unwrap to the same DOS-ish form by stripping
/// the 4-byte prefix. The same is true of `\\.\` for drive-letter
/// devices (`\\.\C:` -> `C:`); device names that aren't drive letters
/// (e.g. `\\.\PhysicalDrive0`) are still rejected downstream by the
/// `path[1] == ':'` gate which is the desired behavior.
fn normalize_file_path(p: &str) -> String {
    let trimmed = p.trim();
    if trimmed.len() >= 4 {
        let head = &trimmed[..4];
        if head.eq_ignore_ascii_case("\\??\\")
            || head.eq_ignore_ascii_case("\\\\?\\")
            || head.eq_ignore_ascii_case("\\\\.\\")
        {
            return trimmed[4..].to_string();
        }
    }
    trimmed.to_string()
}

// Kept for unit tests / external callers; the hot path uses
// `ParseAccumulator::is_skippable` which caches lowercased CWD forms.
#[cfg_attr(not(test), allow(dead_code))]
fn is_skippable(file_path: &str, current_directory: Option<&str>, verbose: bool) -> bool {
    if let Some(cwd) = current_directory {
        // Defensive: refuse to treat a bare drive root ("C:" / "C:\\") as a
        // CWD prefix — otherwise the `format!("{cwd}\\")` match below would
        // swallow every event under that drive. Equality match still applies.
        let cwd_trimmed = cwd.trim_end_matches('\\');
        let is_drive_root = cwd_trimmed.len() == 2
            && cwd_trimmed.chars().nth(1) == Some(':')
            && cwd_trimmed
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic())
                .unwrap_or(false);
        let normalized = file_path.trim_end_matches('\\');
        if normalized.eq_ignore_ascii_case(cwd_trimmed)
            || (!is_drive_root
                && normalized
                    .to_ascii_lowercase()
                    .starts_with(&format!("{}\\", cwd_trimmed.to_ascii_lowercase())))
        {
            if verbose {
                println!("Skipping current-directory event: {file_path}");
            }
            return true;
        }
    }
    if file_path.len() < 4 {
        if verbose {
            println!("Skipping too-short path event: {file_path}");
        }
        return true;
    }
    let second = file_path.chars().nth(1);
    if second != Some(':') {
        if verbose {
            println!("Skipping non-drive-letter path event: {file_path}");
        }
        return true;
    }
    false
}

/// `Test-Path -IsValid` equivalent: reject paths the OS would refuse.
/// We approximate by checking for invalid filename characters in path
/// segments after the drive letter.
fn looks_like_valid_path(path: &str) -> bool {
    // Drive-letter form already verified by caller; reject if it contains
    // ASCII control bytes or wildcards which Windows itself refuses.
    const BAD: &[char] = &['<', '>', '"', '|', '?', '*'];
    !path.chars().any(|c| (c as u32) < 32 || BAD.contains(&c))
}

/// Mutable per-trace accumulator state. Extracted so the per-event logic
/// is reachable from both the live-ETW callback path (`parse_events` →
/// `for_each_event_xml`) and the fixture-test seam
/// (`parse_events_from_xml`).
struct ParseAccumulator<'a> {
    #[allow(dead_code)]
    current_directory: Option<&'a str>,
    /// Cached lowercase form of `current_directory` with trailing `\` trimmed,
    /// plus that string with one trailing `\` appended. Computed once at
    /// construction so the hot `is_skippable` path doesn't allocate two
    /// `String`s per event on a 100k-event trace (round-4 finding K).
    /// `None` if `current_directory` is `None` or is a bare drive root.
    cwd_lc_trimmed: Option<String>,
    cwd_lc_prefix: Option<String>,
    verbose: bool,
    valid_access_events: Vec<LearningModeAccessEvent>,
    requested_capabilities: HashSet<String>,
    need_ui: bool,
    ui_event_count: u32,
    ui_events: Vec<UiEvent>,
    ui_operation_flags: u32,
    // Capability table is retained for tests / diagnostics that want to
    // inspect the source table, but per-event resolution always goes
    // through `capability_index` to avoid the O(table_size) HashMap
    // rebuild that `extract_caps_with_table` would otherwise pay per
    // ACE blob. On a 100k-event trace that's ~30M needless inserts.
    #[allow(dead_code)]
    capability_table: Vec<extract_caps::CapabilityEntry>,
    capability_index: extract_caps::CapabilityIndex,
}

impl<'a> ParseAccumulator<'a> {
    fn new(
        current_directory: Option<&'a str>,
        verbose: bool,
        capability_table: Vec<extract_caps::CapabilityEntry>,
    ) -> Self {
        let capability_index = extract_caps::CapabilityIndex::from_table(&capability_table);
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
            need_ui: false,
            ui_event_count: 0,
            ui_events: Vec::new(),
            ui_operation_flags: 0,
            capability_table,
            capability_index,
        }
    }

    /// Hot-path CWD/path filter. Uses precomputed lowercase forms of
    /// `current_directory` to avoid two `String` allocs per event
    /// (round-4 finding K). R5-12: byte-wise ASCII comparison
    /// against the cached lowercase forms — `to_ascii_lowercase` on
    /// every event allocated ~12 MB / 100k events for nothing.
    /// Logic must stay in sync with the free `is_skippable` function
    /// used by unit tests.
    fn is_skippable(&self, file_path: &str) -> bool {
        if let (Some(cwd_lc), prefix_opt) = (&self.cwd_lc_trimmed, &self.cwd_lc_prefix) {
            // Trim only trailing backslashes (single byte each).
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

    fn consume(&mut self, xml: &str) {
        let Some(mut ev) = parse_event_xml(xml) else {
            return;
        };

        if ev.event_id == 27 {
            self.ui_event_count += 1;

            // Prefer the manifest-resolved EventData form (named <Data>
            // children). Fall back to manual hex-payload decoding when the
            // event was rendered as opaque <ProcessingErrorData>.
            let ui_opt = parse_ui_event_from_named(&ev.event_data_named).or_else(|| {
                ev.processing_error_payload
                    .as_deref()
                    .and_then(parse_ui_event_payload)
            });

            match ui_opt {
                Some(ui) => {
                    // Classify by category so downstream code can apply the
                    // right relaxation: CONVERT_TO_GUI -> `ui.disable=false`;
                    // UI_OPERATION -> per-bit field relaxation.
                    match ui.category {
                        CONVERT_TO_GUI => self.need_ui = true,
                        UI_OPERATION => self.ui_operation_flags |= ui.detail,
                        _ => {}
                    }
                    if self.verbose {
                        let detail_name = if ui.category == UI_OPERATION {
                            ui_limit_name(ui.detail).unwrap_or("UNKNOWN")
                        } else {
                            "-"
                        };
                        println!(
                            "UI Injection event: process={} pid={} seq={} category=0x{:08X} detail=0x{:08X} ({}) denied={}",
                            ui.process_name,
                            ui.process_id,
                            ui.sequence_number,
                            ui.category,
                            ui.detail,
                            detail_name,
                            match ui.denied {
                                Some(true) => "true",
                                Some(false) => "false",
                                None => "(absent)",
                            },
                        );
                    }
                    self.ui_events.push(ui);
                }
                None => {
                    // Undecodable payload: surface in verbose mode but
                    // otherwise ignore. We can't tell the category, so
                    // there's no safe relaxation to apply -- assuming
                    // CONVERT_TO_GUI would over-grant `ui.disable=false`
                    // for traces whose only undecoded events were
                    // UI_OPERATION variants.
                    if self.verbose {
                        if let Some(hex) = ev.processing_error_payload.as_deref() {
                            println!(
                                "UI Injection event observed (payload did not match expected layout, ignored: {hex})"
                            );
                        } else {
                            println!(
                                "UI Injection event observed (no EventData / ProcessingErrorData, ignored)"
                            );
                        }
                    }
                }
            }
            return;
        }

        if let Some(idx) = ev.complex_data_4_idx {
            // Borrow rather than clone — `event_data[idx]` holds the
            // ACE hex blob already pushed in `parse_event_xml`; we
            // consume it in place. The other event_data slots taken
            // below (0/1/3) live at different indices.
            if let Some(blob) = ev.event_data.get(idx) {
                let blob_str = blob.as_str();
                if !blob_str.trim().is_empty() {
                    // R5-17: write directly into the accumulator's HashSet.
                    let _ = extract_caps::extract_caps_with_index_into(
                        blob_str,
                        &self.capability_index,
                        self.verbose,
                        &mut self.requested_capabilities,
                    );
                }
            }
        }

        // EventID=14 file-access event. Pull the file path; absent paths
        // typically indicate capability-resource access events whose
        // capabilities have already been collected from the DACL above.
        let raw_path = match ev.event_data.get(FILE_PATH_INDEX) {
            Some(s) if !s.is_empty() => s,
            _ => return,
        };

        if raw_path.eq_ignore_ascii_case(MOUNT_POINT_MANAGER) {
            return;
        }

        let file_path = normalize_file_path(raw_path);
        if self.is_skippable(&file_path) {
            return;
        }

        // Skip events where the app is just accessing its own binary --
        // the app path is stored without a drive letter (HardDiskVolume
        // form), so we compare against the file path minus its drive
        // letter. Use `get(3..)` rather than `&file_path[3..]` to avoid
        // a panic when the path contains non-ASCII bytes at indices 1-2
        // (e.g. `C:éx` where `é` is two UTF-8 bytes straddling the slice
        // boundary). A panic here would abort the whole parse, silently
        // discarding every other access this trace captured.
        // R5-13: take the strings out of `ev.event_data` rather than
        // cloning. `consume` owns `ev` and these slots are not read
        // again after this point. Saves ~3 allocs/event.
        let app_path = ev
            .event_data
            .get_mut(APP_PATH_INDEX)
            .map(std::mem::take)
            .unwrap_or_default();
        if !app_path.is_empty() {
            if let Some(tail) = file_path.get(3..) {
                if !tail.is_empty() && app_path.ends_with(tail) {
                    return;
                }
            }
        }

        if !looks_like_valid_path(&file_path) {
            return;
        }

        let learning_mode = ev
            .event_data
            .get_mut(LEARNING_MODE_INDEX)
            .map(std::mem::take)
            .unwrap_or_default();
        let resource_type = ev
            .event_data
            .get_mut(RESOURCE_TYPE_INDEX)
            .map(std::mem::take)
            .unwrap_or_default();
        let access_mask = ev
            .event_data
            .get(ACCESS_MASK_INDEX)
            .and_then(|s| parse_int_loose(s))
            .unwrap_or(0);

        if self.verbose {
            println!("{app_path}");
            println!("{file_path}");
        }

        self.valid_access_events.push(LearningModeAccessEvent {
            time_created: ev.time_created,
            process_id: ev.process_id,
            thread_id: ev.thread_id,
            learning_mode,
            resource_type,
            file_path: file_path.trim_matches('\\').to_string(),
            app_path,
            access_mask,
        });
    }

    fn into_result(self) -> ParseResult {
        ParseResult {
            valid_access_events: self.valid_access_events,
            requested_capabilities: self.requested_capabilities,
            need_ui: self.need_ui,
            ui_event_count: self.ui_event_count,
            ui_events: self.ui_events,
            ui_operation_flags: self.ui_operation_flags,
        }
    }
}

#[cfg(target_os = "windows")]
pub fn parse_events(
    trace_file: &Path,
    current_directory: Option<&str>,
    verbose: bool,
) -> Result<ParseResult> {
    // Build the capability table once up-front. Each entry requires a
    // `DeriveCapabilitySidsFromName` syscall + LocalAlloc/LocalFree pair;
    // the table is process-static so doing this per-event (the previous
    // behavior) dominated wall-time on large traces.
    let capability_table = extract_caps::build_capability_table();
    let mut acc = ParseAccumulator::new(current_directory, verbose, capability_table);
    for_each_event_xml(trace_file, |xml| {
        acc.consume(xml);
        Ok(())
    })?;
    Ok(acc.into_result())
}

/// Fixture-test seam: drive the same per-event accumulator the live
/// `parse_events` uses, but pull XML strings from an iterator rather than
/// a live ETW session. Lets tests exercise the full event-classification
/// pipeline with canned XML strings (no .etl file, no
/// `DeriveCapabilitySidsFromName` round-trip — pass an empty capability
/// table for tests that don't care about DACL ACE matching).
pub fn parse_events_from_xml<I, S>(
    xmls: I,
    current_directory: Option<&str>,
    verbose: bool,
    capability_table: Vec<extract_caps::CapabilityEntry>,
) -> ParseResult
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut acc = ParseAccumulator::new(current_directory, verbose, capability_table);
    for xml in xmls {
        acc.consume(xml.as_ref());
    }
    acc.into_result()
}

/// Accept decimal or 0x-prefixed hex.
fn parse_int_loose(s: &str) -> Option<u32> {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(rest, 16).ok()
    } else {
        t.parse::<u32>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_event_xml -------------------------------------------------

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

    // ---- normalize_file_path / is_skippable / looks_like_valid_path -----

    #[test]
    fn normalize_file_path_strips_nt_object_prefix() {
        assert_eq!(normalize_file_path("\\??\\C:\\foo"), "C:\\foo");
        assert_eq!(normalize_file_path("\\??\\c:\\foo"), "c:\\foo");
        assert_eq!(normalize_file_path("C:\\foo"), "C:\\foo");
    }

    /// Round-6 correctness finding #2: verbatim (`\\?\C:\...`) and
    /// DOS-device (`\\.\C:\...`) prefixes must be stripped before
    /// `is_skippable`'s drive-letter gate; otherwise the kernel
    /// provider's natural rendering of those forms drops every event.
    #[test]
    fn normalize_file_path_strips_verbatim_and_dos_device_prefixes() {
        // Verbatim "\\?\C:\..." form. Note: each `\` doubles in a
        // Rust string literal; the on-disk path is `\\?\C:\foo`.
        assert_eq!(normalize_file_path("\\\\?\\C:\\foo"), "C:\\foo");
        // DOS-device prefix for drive-letter access.
        assert_eq!(normalize_file_path("\\\\.\\C:\\foo"), "C:\\foo");
        // Case-insensitive guard against accidental tightening.
        assert_eq!(normalize_file_path("\\\\?\\c:\\foo"), "c:\\foo");
    }

    /// After the prefix strip, a normalized path with a drive letter
    /// must SURVIVE `is_skippable`. Catches the integration between
    /// normalize_file_path and the drive-letter gate.
    #[test]
    fn verbatim_prefix_path_survives_is_skippable() {
        let normalized = normalize_file_path("\\\\?\\C:\\Users\\test\\foo.txt");
        assert!(!is_skippable(&normalized, None, false));
    }

    #[test]
    fn is_skippable_rejects_short_and_non_drive_letter() {
        assert!(is_skippable("abc", None, false));
        assert!(is_skippable("\\\\server\\share", None, false));
        assert!(!is_skippable("C:\\foo", None, false));
    }

    #[test]
    fn is_skippable_filters_current_directory() {
        assert!(is_skippable(
            "C:\\repo\\src\\main.rs",
            Some("C:\\repo"),
            false
        ));
        assert!(!is_skippable(
            "C:\\not-repo\\src\\main.rs",
            Some("C:\\repo"),
            false
        ));
    }

    // Regression for round-4 finding M: a CWD of bare `C:\` (drive root)
    // must NOT swallow every event on that drive. Only an explicit
    // equality match against the drive root is honored.
    #[test]
    fn is_skippable_does_not_treat_drive_root_cwd_as_prefix() {
        assert!(!is_skippable(
            "C:\\Windows\\System32\\foo.dll",
            Some("C:\\"),
            false
        ));
        assert!(!is_skippable(
            "C:\\Windows\\System32\\foo.dll",
            Some("C:"),
            false
        ));
        // Exact equality match against drive root is still skipped
        // (it's the trace-driver's own enumeration of `C:\`).
        assert!(is_skippable("C:\\", Some("C:\\"), false));
    }

    #[test]
    fn looks_like_valid_path_rejects_control_and_wildcards() {
        assert!(!looks_like_valid_path("C:\\f\x00oo"));
        assert!(!looks_like_valid_path("C:\\foo*"));
        assert!(!looks_like_valid_path("C:\\foo?"));
        assert!(looks_like_valid_path("C:\\foo\\bar.txt"));
    }

    // ---- parse_ui_event_payload ------------------------------------------

    fn hex_for(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(s, "{:02X}", b);
        }
        s
    }

    #[test]
    fn parse_ui_event_payload_decodes_fixed_layout() {
        // process_name="test\0", pid=1, seq=2, category=UI_OPERATION,
        // detail=JOB_OBJECT_UILIMIT_GLOBALATOMS, denied trailing single byte 1.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"test");
        bytes.push(0);
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(&UI_OPERATION.to_le_bytes());
        bytes.extend_from_slice(&JOB_OBJECT_UILIMIT_GLOBALATOMS.to_le_bytes());
        bytes.push(1);
        let ui = parse_ui_event_payload(&hex_for(&bytes)).expect("should decode");
        assert_eq!(ui.process_name, "test");
        assert_eq!(ui.process_id, 1);
        assert_eq!(ui.sequence_number, 2);
        assert_eq!(ui.category, UI_OPERATION);
        assert_eq!(ui.detail, JOB_OBJECT_UILIMIT_GLOBALATOMS);
        assert_eq!(ui.denied, Some(true));
    }

    #[test]
    fn parse_ui_event_payload_rejects_truncated() {
        // Just "test\0" with no fixed tail.
        let bytes = b"test\0";
        assert!(parse_ui_event_payload(&hex_for(bytes)).is_none());
    }

    #[test]
    fn parse_ui_event_from_named_recognises_decimal_and_hex() {
        let named = vec![
            ("ProcessName".to_string(), "App".to_string()),
            ("ProcessId".to_string(), "42".to_string()),
            ("SequenceNumber".to_string(), "0x10".to_string()),
            ("Category".to_string(), "2".to_string()),
            ("Detail".to_string(), "0x20".to_string()),
            ("Denied".to_string(), "true".to_string()),
        ];
        let ui = parse_ui_event_from_named(&named).expect("should decode");
        assert_eq!(ui.process_name, "App");
        assert_eq!(ui.process_id, 42);
        assert_eq!(ui.sequence_number, 0x10);
        assert_eq!(ui.category, UI_OPERATION);
        assert_eq!(ui.detail, JOB_OBJECT_UILIMIT_GLOBALATOMS);
        assert_eq!(ui.denied, Some(true));
    }

    // ---- parse_events_from_xml seam --------------------------------------

    fn make_event_xml(file_path: &str, mask_hex: &str) -> String {
        format!(
            r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System>
                <EventID>14</EventID>
                <TimeCreated SystemTime="2024-01-02T03:04:05.000Z"/>
                <Execution ProcessID="111" ThreadID="222"/>
              </System>
              <EventData>
                <Data>Permissive</Data>
                <Data>File</Data>
                <Data>{file_path}</Data>
                <Data>App.exe</Data>
                <Data>0</Data>
                <Data>{mask_hex}</Data>
              </EventData>
            </Event>"#
        )
    }

    #[test]
    fn parse_events_from_xml_accumulates_access_events() {
        let xmls = [
            make_event_xml("C:\\Users\\test\\foo.txt", "0x1"),
            make_event_xml("C:\\Users\\test\\bar.txt", "0x2"),
        ];
        let result = parse_events_from_xml(xmls.iter(), None, false, Vec::new());
        assert_eq!(result.valid_access_events.len(), 2);
        assert_eq!(
            result.valid_access_events[0].file_path,
            "C:\\Users\\test\\foo.txt"
        );
        assert_eq!(result.valid_access_events[0].access_mask, 0x1);
        assert_eq!(result.valid_access_events[1].access_mask, 0x2);
    }

    /// Round-3 finding L: when a single rendered event is malformed we
    /// must not abort the whole trace — every subsequent valid event
    /// would silently disappear, leaving PLM under-granting on the next
    /// adjust pass. The accumulator's `consume` swallows parse failures
    /// per event; this test pins that behavior.
    #[test]
    fn parse_events_from_xml_skips_malformed_and_continues() {
        let valid_a = make_event_xml("C:\\Users\\test\\a.txt", "0x1");
        let valid_b = make_event_xml("C:\\Users\\test\\b.txt", "0x2");
        let xmls: Vec<String> = vec![
            valid_a,
            "not xml".to_string(),
            "<not-an-event/>".to_string(),
            valid_b,
        ];
        let result = parse_events_from_xml(xmls.iter(), None, false, Vec::new());
        assert_eq!(
            result.valid_access_events.len(),
            2,
            "malformed events should be skipped, valid ones still collected"
        );
        assert_eq!(
            result.valid_access_events[0].file_path,
            "C:\\Users\\test\\a.txt"
        );
        assert_eq!(
            result.valid_access_events[1].file_path,
            "C:\\Users\\test\\b.txt"
        );
    }

    // ---- UI EventID=27 -> apply_ui_flags end-to-end ----------------------

    /// Build a UI-injection `<Event EventID="27">` whose payload is
    /// emitted as a `<ProcessingErrorData><EventPayload>` hex blob
    /// (the rendering used when the consumer doesn't have the provider
    /// manifest — the common case for PLM consumers).
    fn make_ui_event_xml(category: u32, detail: u32) -> String {
        // Layout: process_name\0 | pid u64 | seq u64 | category u32 | detail u32 | denied u8
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"App");
        bytes.push(0);
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(&category.to_le_bytes());
        bytes.extend_from_slice(&detail.to_le_bytes());
        bytes.push(1);
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(hex, "{:02X}", b);
        }
        format!(
            r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System>
                <EventID>27</EventID>
                <TimeCreated SystemTime="2024-01-02T03:04:05.000Z"/>
                <Execution ProcessID="1" ThreadID="2"/>
              </System>
              <ProcessingErrorData>
                <EventPayload>{hex}</EventPayload>
              </ProcessingErrorData>
            </Event>"#
        )
    }

    /// Round-6 coverage finding #8: the parser produces a
    /// `ui_operation_flags` bitmap; `apply_ui_operation_flags` then
    /// rewrites the config's `ui.*` fields. The two halves are tested
    /// individually but their contract (bit values must match) is
    /// untested — this integration test pins it. A drift between
    /// `JOB_OBJECT_UILIMIT_*` here and in `config.rs` will fail this
    /// test even though both halves' unit tests still pass.
    #[test]
    fn ui_event_xml_drives_config_relaxation_through_apply_ui_flags() {
        // HANDLES violation: the default `ui.isolation = "handles"`
        // should widen to `"desktop"` (handles allowed, atoms still
        // restricted).
        let xmls = [make_ui_event_xml(UI_OPERATION, JOB_OBJECT_UILIMIT_HANDLES)];
        let parse = parse_events_from_xml(xmls.iter(), None, false, Vec::new());

        assert_eq!(
            parse.ui_event_count, 1,
            "EventID=27 should be counted as a UI event"
        );
        assert_eq!(
            parse.ui_operation_flags, JOB_OBJECT_UILIMIT_HANDLES,
            "UI_OPERATION detail must OR into ui_operation_flags",
        );
        assert!(
            !parse.need_ui,
            "UI_OPERATION (not CONVERT_TO_GUI) must not set need_ui",
        );

        // Drive the config through apply_ui_operation_flags. Starting
        // from the default `ui.isolation = "handles"` (the OS default),
        // a HANDLES relaxation should widen to "desktop".
        let mut config = serde_json::json!({ "ui": { "isolation": "handles" } });
        crate::config::apply_ui_operation_flags(&mut config, parse.ui_operation_flags)
            .expect("apply_ui_operation_flags");
        assert_eq!(
            config["ui"]["isolation"], "desktop",
            "HANDLES relaxation should widen ui.isolation handles -> desktop"
        );
    }

    /// CONVERT_TO_GUI violations flow through `set_ui_subsystem_enabled`
    /// rather than `apply_ui_operation_flags`. Pin that integration too.
    #[test]
    fn ui_convert_to_gui_event_sets_need_ui() {
        let xmls = [make_ui_event_xml(CONVERT_TO_GUI, 0)];
        let parse = parse_events_from_xml(xmls.iter(), None, false, Vec::new());

        assert_eq!(parse.ui_event_count, 1);
        assert!(parse.need_ui, "CONVERT_TO_GUI must set need_ui");
        assert_eq!(
            parse.ui_operation_flags, 0,
            "CONVERT_TO_GUI must NOT contribute to ui_operation_flags",
        );

        let mut config = serde_json::json!({});
        crate::config::set_ui_subsystem_enabled(&mut config).expect("set_ui_subsystem_enabled");
        assert_eq!(config["ui"]["disable"], false);
    }

    /// Round-6 coverage finding #4: `parse_events` (the live entry
    /// point that drives EvtQuery against a real .etl) can't run from
    /// unit tests, but the per-event accumulator it feeds is shared
    /// with `parse_events_from_xml`. Cover a heterogeneous mixed
    /// stream — multiple access events, a UI event, a malformed
    /// record in the middle, and a CWD-filtered noise event — so any
    /// regression in the mixed-stream dispatch (event-id routing,
    /// continue-on-malformed, CWD filter) surfaces from `cargo test`.
    #[test]
    fn parse_events_from_xml_mixed_stream_integration() {
        let xmls: Vec<String> = vec![
            // EventID=14 valid access event.
            make_event_xml("C:\\Workdir\\real_target.txt", "0x1"),
            // Malformed in the middle — must not abort the stream.
            "<not-an-event/>".to_string(),
            // CWD-filtered noise: under the supplied cwd, must be skipped.
            make_event_xml("C:\\Repo\\src\\test_scaffold.rs", "0x1"),
            // Another valid access event.
            make_event_xml("C:\\Workdir\\other.txt", "0x2"),
            // UI EventID=27 violation.
            make_ui_event_xml(UI_OPERATION, JOB_OBJECT_UILIMIT_WRITECLIPBOARD),
        ];
        let result = parse_events_from_xml(xmls.iter(), Some("C:\\Repo"), false, Vec::new());

        assert_eq!(
            result.valid_access_events.len(),
            2,
            "expected exactly two valid access events (the other two were \
             malformed and cwd-filtered respectively)",
        );
        assert_eq!(result.ui_event_count, 1);
        assert_eq!(result.ui_operation_flags, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,);
        assert!(!result.need_ui);

        // Pin the order so a regression in event-stream interleaving
        // (e.g. dropping the post-malformed events) fails loudly.
        assert_eq!(
            result.valid_access_events[0].file_path,
            "C:\\Workdir\\real_target.txt"
        );
        assert_eq!(
            result.valid_access_events[1].file_path,
            "C:\\Workdir\\other.txt"
        );
    }
}
