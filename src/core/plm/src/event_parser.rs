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
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryFilePath, EvtQueryForwardDirection, EvtRender,
    EvtRenderEventXml, EVT_HANDLE,
};

use crate::access_event::LearningModeAccessEvent;
use crate::extract_caps;

// File path we treat as "no useful info" and skip.
const MOUNT_POINT_MANAGER: &str = "\\Device\\MountPointManager";

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
    pub need_ui: bool,
    pub ui_event_count: u32,
}

fn to_wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read every event matching the access-failure XPath query out of an
/// .etl file and return their rendered XML strings.
fn read_event_xml(trace_file: &Path) -> Result<Vec<String>> {
    let path_w = to_wide_z(&trace_file.to_string_lossy());
    let query_w = to_wide_z("*[System[EventID=14 or EventID=27]]");

    let h_query = unsafe {
        EvtQuery(
            EVT_HANDLE::default(),
            PCWSTR(path_w.as_ptr()),
            PCWSTR(query_w.as_ptr()),
            EvtQueryFilePath.0 | EvtQueryForwardDirection.0,
        )
    }?;

    let mut out = Vec::new();
    loop {
        // EvtNext takes an `&mut [isize]` of EVT_HANDLE-sized slots.
        let mut events: [isize; 16] = [0isize; 16];
        let mut returned: u32 = 0;
        let next_ok = unsafe {
            EvtNext(
                h_query,
                &mut events,
                u32::MAX, // INFINITE
                0,
                &mut returned as *mut _,
            )
        };
        if next_ok.is_err() || returned == 0 {
            break;
        }

        for &slot in events.iter().take(returned as usize) {
            let handle = EVT_HANDLE(slot);
            if let Ok(xml) = render_event_xml(handle) {
                out.push(xml);
            }
            unsafe {
                let _ = EvtClose(handle);
            }
        }
    }
    unsafe {
        let _ = EvtClose(h_query);
    }
    Ok(out)
}

fn render_event_xml(event: EVT_HANDLE) -> Result<String> {
    // Two-call pattern: first call gets required buffer size, second call
    // fills it.
    let mut needed: u32 = 0;
    let mut count: u32 = 0;
    unsafe {
        let _ = EvtRender(
            EVT_HANDLE::default(),
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut needed as *mut _,
            &mut count as *mut _,
        );
    }
    if needed == 0 {
        return Err(anyhow::anyhow!("EvtRender returned zero size"));
    }
    let mut buf = vec![0u8; needed as usize];
    unsafe {
        EvtRender(
            EVT_HANDLE::default(),
            event,
            EvtRenderEventXml.0,
            needed,
            Some(buf.as_mut_ptr() as *mut _),
            &mut needed as *mut _,
            &mut count as *mut _,
        )?;
    }
    // Buffer is UTF-16; trim trailing NUL.
    let u16_count = (needed as usize) / 2;
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
    /// Inner text of the 5th EventData child (index 4) which carries the
    /// DACL ACE hex blob, when present.
    complex_data_4: Option<String>,
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
    let mut complex_data_4: Option<String> = None;
    if let Some(ed) = root.children().find(|n| n.has_tag_name("EventData")) {
        let mut complex_index = 0usize;
        for child in ed.children().filter(|n| n.is_element()) {
            let tag = child.tag_name().name();
            if tag == "Data" || tag == "ComplexData" {
                event_data.push(child.text().unwrap_or("").to_string());
            }
            if tag == "ComplexData" {
                if complex_index == 4 {
                    let txt = child.text().unwrap_or("").to_string();
                    if !txt.trim().is_empty() {
                        complex_data_4 = Some(txt);
                    }
                }
                complex_index += 1;
            }
        }
    }

    Some(ParsedEvent {
        event_id,
        time_created,
        process_id,
        thread_id,
        event_data,
        complex_data_4,
    })
}

fn normalize_file_path(p: &str) -> String {
    let trimmed = p.trim();
    if trimmed.len() >= 4 && trimmed[..4].eq_ignore_ascii_case("\\??\\") {
        trimmed[4..].to_string()
    } else {
        trimmed.to_string()
    }
}

fn is_skippable(file_path: &str, current_directory: Option<&str>, verbose: bool) -> bool {
    if let Some(cwd) = current_directory {
        let normalized = file_path.trim_end_matches('\\');
        if normalized.eq_ignore_ascii_case(cwd)
            || normalized
                .to_ascii_lowercase()
                .starts_with(&format!("{}\\", cwd.to_ascii_lowercase()))
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

pub fn parse_events(
    trace_file: &Path,
    current_directory: Option<&str>,
    verbose: bool,
) -> Result<ParseResult> {
    let xml_events = read_event_xml(trace_file)?;

    let mut valid_access_events = Vec::new();
    let mut requested_capabilities: HashSet<String> = HashSet::new();
    let mut need_ui = false;
    let mut ui_event_count: u32 = 0;

    for xml in &xml_events {
        let Some(ev) = parse_event_xml(xml) else {
            continue;
        };

        if ev.event_id == 27 {
            if verbose {
                println!("UI Injection event observed");
            }
            need_ui = true;
            ui_event_count += 1;
            continue;
        }

        if let Some(blob) = &ev.complex_data_4 {
            if let Ok(caps) = extract_caps::extract_caps(blob, verbose) {
                for c in caps {
                    requested_capabilities.insert(c);
                }
            }
        }

        // EventID=14 file-access event. Pull the file path; absent paths
        // typically indicate capability-resource access events whose
        // capabilities have already been collected from the DACL above.
        let raw_path = match ev.event_data.get(FILE_PATH_INDEX) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        if raw_path.eq_ignore_ascii_case(MOUNT_POINT_MANAGER) {
            continue;
        }

        let file_path = normalize_file_path(raw_path);
        if is_skippable(&file_path, current_directory, verbose) {
            continue;
        }

        // Skip events where the app is just accessing its own binary --
        // the app path is stored without a drive letter (HardDiskVolume
        // form), so we compare against the file path minus its drive
        // letter.
        let app_path = ev
            .event_data
            .get(APP_PATH_INDEX)
            .cloned()
            .unwrap_or_default();
        if !app_path.is_empty() && file_path.len() >= 3 && app_path.ends_with(&file_path[3..]) {
            continue;
        }

        if !looks_like_valid_path(&file_path) {
            continue;
        }

        let learning_mode = ev
            .event_data
            .get(LEARNING_MODE_INDEX)
            .cloned()
            .unwrap_or_default();
        let resource_type = ev
            .event_data
            .get(RESOURCE_TYPE_INDEX)
            .cloned()
            .unwrap_or_default();
        let access_mask = ev
            .event_data
            .get(ACCESS_MASK_INDEX)
            .and_then(|s| parse_int_loose(s))
            .unwrap_or(0);

        if verbose {
            println!("{app_path}");
            println!("{file_path}");
        }

        valid_access_events.push(LearningModeAccessEvent {
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

    Ok(ParseResult {
        valid_access_events,
        requested_capabilities,
        need_ui,
        ui_event_count,
    })
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
