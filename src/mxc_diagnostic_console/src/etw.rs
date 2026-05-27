// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Real-time ETW consumer for MXC diagnostic providers.
//!
//! Listens for events from:
//! - **Tessera** TraceLogging provider (all events)
//! - **Microsoft-Windows-Kernel-General** (all events -- AccessCheckLog, AppContainerTokenCheckLog,
//!   TokenSidManagementLog, learning-mode violations, etc.)
//!
//! Starts a trace session, enables the providers, and delivers decoded events
//! to the diagnostic console's display channel. Requires administrator privileges.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;

use windows::core::GUID;
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    TdhGetEventInformation, CONTROLTRACE_HANDLE, EVENT_PROPERTY_INFO, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
    TRACE_EVENT_INFO, TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
};

use super::{collect_mode, display_mode, DisplayEvent, DisplayMode};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Tessera TraceLogging provider GUID: {f6ec123e-314e-400b-9e0a-151365e23083}
const TESSERA_PROVIDER: GUID = GUID {
    data1: 0xf6ec123e,
    data2: 0x314e,
    data3: 0x400b,
    data4: [0x9e, 0x0a, 0x15, 0x13, 0x65, 0xe2, 0x30, 0x83],
};

/// Microsoft-Windows-Kernel-General provider GUID: {a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}
/// Used to capture learning-mode diagnostics (AccessCheckLog, AppContainerTokenCheckLog,
/// TokenSidManagementLog, learning-mode violations, etc.).
const KERNEL_GENERAL_PROVIDER: GUID = GUID {
    data1: 0xa68ca8b7,
    data2: 0x004f,
    data3: 0xd7b6,
    data4: [0xa6, 0x98, 0x07, 0xe2, 0xde, 0x0f, 0x1f, 0x5d],
};

const SESSION_NAME: &str = "MXC-Diagnostics-ETW";

/// Global trace session handle so we can stop the session from any thread.
static SESSION_HANDLE: AtomicU64 = AtomicU64::new(0);

// TDH InType constants for property decoding.
const TDH_INTYPE_UNICODESTRING: u16 = 1;
const TDH_INTYPE_ANSISTRING: u16 = 2;
const TDH_INTYPE_INT8: u16 = 3;
const TDH_INTYPE_UINT8: u16 = 4;
const TDH_INTYPE_INT16: u16 = 5;
const TDH_INTYPE_UINT16: u16 = 6;
const TDH_INTYPE_INT32: u16 = 7;
const TDH_INTYPE_UINT32: u16 = 8;
const TDH_INTYPE_INT64: u16 = 9;
const TDH_INTYPE_UINT64: u16 = 10;
const TDH_INTYPE_FLOAT: u16 = 11;
const TDH_INTYPE_DOUBLE: u16 = 12;
const TDH_INTYPE_BOOLEAN: u16 = 13;
const TDH_INTYPE_GUID: u16 = 15;
const TDH_INTYPE_POINTER: u16 = 16;
const TDH_INTYPE_FILETIME: u16 = 17;
const TDH_INTYPE_HEXINT32: u16 = 20;
const TDH_INTYPE_HEXINT64: u16 = 21;

/// Wrapper to send a raw pointer across thread boundaries.
/// SAFETY: the pointed-to Sender lives for the entire ProcessTrace duration.
struct SendPtr(*mut mpsc::Sender<DisplayEvent>);
unsafe impl Send for SendPtr {}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Start the ETW listener for diagnostic providers.
///
/// Enables the Tessera TraceLogging provider and the Kernel-General provider
/// (all events for learning-mode diagnostics).
/// Spawns a background thread that calls `ProcessTrace` (blocking). Returns
/// immediately on success. Events are delivered via `tx`.
pub fn start_etw_listener(tx: mpsc::Sender<DisplayEvent>) -> Result<(), String> {
    cleanup_stale_session();

    let handle = start_trace_session()?;
    SESSION_HANDLE.store(handle, Ordering::SeqCst);

    enable_provider(handle)?;

    let tx_box = Box::new(tx);
    let send_ptr = SendPtr(Box::into_raw(tx_box));

    std::thread::Builder::new()
        .name("etw-consumer".into())
        .spawn(move || {
            process_trace_loop(send_ptr);
        })
        .map_err(|e| format!("Failed to spawn ETW consumer thread: {e}"))?;

    Ok(())
}

/// Stop the trace session. Safe to call from a Ctrl+C handler.
pub fn stop_etw_listener() {
    let handle = SESSION_HANDLE.swap(0, Ordering::SeqCst);
    if handle != 0 {
        stop_session(handle);
    }
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

fn session_name_wide() -> Vec<u16> {
    SESSION_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

fn alloc_properties_buf() -> Vec<u8> {
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let name_wide_len = SESSION_NAME.encode_utf16().count() + 1;
    let name_bytes = name_wide_len * 2;
    let total = props_size + name_bytes + 2;

    let mut buf = vec![0u8; total];
    let props = buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
    unsafe {
        (*props).Wnode.BufferSize = total as u32;
        (*props).LoggerNameOffset = props_size as u32;
        (*props).LogFileNameOffset = (props_size + name_bytes) as u32;
    }
    buf
}

fn start_trace_session() -> Result<u64, String> {
    let name = session_name_wide();
    let mut buf = alloc_properties_buf();
    let props = buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();

    unsafe {
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).Wnode.ClientContext = 1; // QPC timestamps
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    }

    let mut handle = CONTROLTRACE_HANDLE::default();

    let status = unsafe { StartTraceW(&mut handle, windows_core::PCWSTR(name.as_ptr()), props) };

    if status != WIN32_ERROR(0) {
        return Err(format!(
            "StartTraceW failed: error {} (are you running as administrator?)",
            status.0
        ));
    }

    Ok(handle.Value)
}

fn enable_provider(session_handle: u64) -> Result<(), String> {
    let h = CONTROLTRACE_HANDLE {
        Value: session_handle,
    };

    // Enable the Tessera TraceLogging provider (all keywords, Verbose).
    let status = unsafe {
        EnableTraceEx2(
            h,
            &TESSERA_PROVIDER,
            1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
            TRACE_LEVEL_VERBOSE as u8,
            0xFFFF_FFFF_FFFF_FFFF, // all keywords
            0,
            0,
            None,
        )
    };

    if status != WIN32_ERROR(0) {
        return Err(format!(
            "EnableTraceEx2 (Tessera) failed: error {}",
            status.0
        ));
    }

    // Enable the Kernel-General provider for learning-mode diagnostic events.
    let status = unsafe {
        EnableTraceEx2(
            h,
            &KERNEL_GENERAL_PROVIDER,
            1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
            TRACE_LEVEL_VERBOSE as u8,
            0xFFFF_FFFF_FFFF_FFFF, // all keywords
            0,
            0,
            None,
        )
    };

    if status != WIN32_ERROR(0) {
        // Non-fatal: warn but continue (Tessera provider is already enabled).
        eprintln!(
            "[ETW] Warning: EnableTraceEx2 (Kernel-General) failed: error {}",
            status.0
        );
    }

    Ok(())
}

fn stop_session(handle: u64) {
    let name = session_name_wide();
    let mut buf = alloc_properties_buf();
    let props = buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
    let h = CONTROLTRACE_HANDLE { Value: handle };

    unsafe {
        let _ = ControlTraceW(
            h,
            windows_core::PCWSTR(name.as_ptr()),
            props,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

fn cleanup_stale_session() {
    let name = session_name_wide();
    let mut buf = alloc_properties_buf();
    let props = buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();

    unsafe {
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            windows_core::PCWSTR(name.as_ptr()),
            props,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

// ---------------------------------------------------------------------------
// ProcessTrace loop (runs on a dedicated thread)
// ---------------------------------------------------------------------------

#[allow(clippy::field_reassign_with_default)]
fn process_trace_loop(send_ptr: SendPtr) {
    let tx_ptr = send_ptr.0;
    let mut name = session_name_wide();

    let mut logfile = EVENT_TRACE_LOGFILEW::default();
    logfile.LoggerName = windows_core::PWSTR(name.as_mut_ptr());

    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
    logfile.Context = tx_ptr.cast::<c_void>();

    let trace_handle = unsafe { OpenTraceW(&mut logfile) };

    if trace_handle.Value == u64::MAX {
        eprintln!(
            "[ETW] OpenTraceW failed: {}",
            std::io::Error::last_os_error()
        );
        return;
    }

    let _ = unsafe { ProcessTrace(&[trace_handle], None, None) };

    unsafe {
        let _ = CloseTrace(trace_handle);
        // Clean up the boxed Sender.
        drop(Box::from_raw(tx_ptr));
    }
}

// ---------------------------------------------------------------------------
// Event record callback
// ---------------------------------------------------------------------------

unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    let event = unsafe { &*event_record };
    let provider = event.EventHeader.ProviderId;

    if provider == TESSERA_PROVIDER {
        // Tessera: accept all events.
    } else if provider == KERNEL_GENERAL_PROVIDER {
        // Kernel-General: accept all events (AccessCheckLog, AppContainerTokenCheckLog,
        // TokenSidManagementLog, learning-mode violations, etc.).
    } else {
        return;
    }

    let tx = unsafe { &*(event.UserContext as *const mpsc::Sender<DisplayEvent>) };
    let pid = event.EventHeader.ProcessId;
    let collecting = collect_mode();
    let current_mode = display_mode();

    if let Some(parts) = decode_event_parts(event_record) {
        let console_text = format_event_output(&parts, current_mode);

        let (verbose_text, minified_text) = if collecting {
            let verbose = format_event_output(&parts, DisplayMode::Full)
                .unwrap_or_else(|| fallback_event_text(event_record));
            let minified = format_event_output(&parts, DisplayMode::Minified);
            (Some(verbose), Some(minified))
        } else {
            (None, None)
        };

        // In collect mode, send even if console_text is None (suppressed) since
        // the verbose log still wants this event.
        if console_text.is_some() || collecting {
            let _ = tx.send(DisplayEvent::EtwEvent {
                pid,
                text: console_text.unwrap_or_else(|| fallback_event_text(event_record)),
                verbose_text,
                minified_text,
            });
        }
    } else {
        let fallback = fallback_event_text(event_record);
        let (verbose_text, minified_text) = if collecting {
            (Some(fallback.clone()), Some(Some(fallback.clone())))
        } else {
            (None, None)
        };
        let _ = tx.send(DisplayEvent::EtwEvent {
            pid,
            text: fallback,
            verbose_text,
            minified_text,
        });
    }
}

// ---------------------------------------------------------------------------
// Event decoding
// ---------------------------------------------------------------------------

/// Decoded ETW event parts (expensive TDH call done once, formatting done separately).
struct DecodedEventParts {
    event_name: Option<String>,
    event_id: u16,
    provider: GUID,
    level_tag: &'static str,
    props: Vec<(String, String)>,
}

/// Decode the raw event record via TDH into reusable parts.
/// Returns `None` only when TDH decoding fails entirely.
fn decode_event_parts(event_record: *mut EVENT_RECORD) -> Option<DecodedEventParts> {
    let mut buf_size: u32 = 0;
    let status = unsafe { TdhGetEventInformation(event_record, None, None, &mut buf_size) };

    // ERROR_INSUFFICIENT_BUFFER = 122
    if status != 122 {
        return None;
    }

    let mut buffer = vec![0u8; buf_size as usize];
    let info_ptr = buffer.as_mut_ptr().cast::<TRACE_EVENT_INFO>();
    let status =
        unsafe { TdhGetEventInformation(event_record, None, Some(info_ptr), &mut buf_size) };

    if status != 0 {
        return None;
    }

    let info = unsafe { &*info_ptr };

    let event_name_offset = unsafe { info.Anonymous1.EventNameOffset };
    let event_name = wide_str_at(&buffer, event_name_offset)
        .or_else(|| wide_str_at(&buffer, info.TaskNameOffset))
        .unwrap_or_default();

    let event_name = if event_name.is_empty() {
        None
    } else {
        Some(event_name)
    };

    let level = unsafe { (*event_record).EventHeader.EventDescriptor.Level };
    let event_id = unsafe { (*event_record).EventHeader.EventDescriptor.Id };
    let provider = unsafe { (*event_record).EventHeader.ProviderId };
    let level_tag = match level {
        1 => "\x1b[91mCRIT\x1b[0m",
        2 => "\x1b[91mERR\x1b[0m",
        3 => "\x1b[33mWARN\x1b[0m",
        4 => "INFO",
        5 => "VERB",
        _ => "",
    };

    let props = decode_properties(&buffer, info, event_record);

    Some(DecodedEventParts {
        event_name,
        event_id,
        provider,
        level_tag,
        props,
    })
}

/// Learning mode violation event ID from Kernel-General.
const LEARNING_MODE_VIOLATION_EVENT_ID: u16 = 27;

/// Human-readable names for learning mode violation categories.
fn learning_mode_category_name(category: &str) -> &str {
    match category {
        "0" => "None",
        "1" => "ConvertToGui",
        "2" => "UiOperation",
        _ => category,
    }
}

/// Format decoded event parts into a display string for the given mode.
/// Returns `None` when the event should be suppressed (e.g. empty ObjectType in minified mode).
fn format_event_output(parts: &DecodedEventParts, mode: DisplayMode) -> Option<String> {
    // Special handling for learning mode violation events (Kernel-General, Event ID 27).
    if parts.provider == KERNEL_GENERAL_PROVIDER
        && parts.event_id == LEARNING_MODE_VIOLATION_EVENT_ID
    {
        return Some(format_learning_mode_violation(&parts.props, mode));
    }

    let props = minify_kernel_general_props(parts.props.clone(), mode)?;

    let props_str = if props.is_empty() {
        String::new()
    } else {
        let joined: Vec<String> = props.iter().map(|(k, v)| format!("{k}={v}")).collect();
        format!(" {{ {} }}", joined.join(", "))
    };

    let name_part = parts.event_name.as_deref().unwrap_or("");

    match (parts.level_tag.is_empty(), name_part.is_empty()) {
        (true, true) => Some(props_str.trim_start().to_string()),
        (true, false) => Some(format!("{name_part}{props_str}")),
        (false, true) => Some(format!("[{}]{props_str}", parts.level_tag)),
        (false, false) => Some(format!("[{}] {name_part}{props_str}", parts.level_tag)),
    }
}

/// Format a learning mode violation event (Event ID 27) with warning colors and category name.
fn format_learning_mode_violation(props: &[(String, String)], mode: DisplayMode) -> String {
    let yellow = "\x1b[33m";
    let orange = "\x1b[38;5;208m";
    let reset = "\x1b[0m";

    // Replace the Category number with its human-readable name, colored orange.
    let formatted_props: Vec<(String, String)> = props
        .iter()
        .map(|(k, v)| {
            if k == "Category" {
                let raw = v.trim_matches('"');
                let name = learning_mode_category_name(raw);
                (k.clone(), format!("{orange}{name}{reset}"))
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect();

    // In minified mode, show a reduced set of properties.
    let display_props = if mode == DisplayMode::Minified {
        const MINIFIED_FIELDS: &[&str] = &["ProcessName", "Category", "Denied", "Detail"];
        let mut filtered: Vec<(String, String)> = formatted_props
            .into_iter()
            .filter(|(k, _)| MINIFIED_FIELDS.contains(&k.as_str()))
            .collect();
        // Strip ProcessName to just the exe name.
        for (k, v) in &mut filtered {
            if k == "ProcessName" {
                let stripped = v.trim_matches('"').rsplit('\\').next().unwrap_or(v);
                *v = format!("\"{stripped}\"");
            }
        }
        filtered
    } else {
        formatted_props
    };

    let props_str = if display_props.is_empty() {
        String::new()
    } else {
        let joined: Vec<String> = display_props
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        format!(" {{ {} }}", joined.join(", "))
    };

    format!("{yellow}[LearningModeViolation]{reset}{props_str}")
}

/// Produce a generic fallback string for events that TDH cannot decode.
fn fallback_event_text(event_record: *mut EVENT_RECORD) -> String {
    let event = unsafe { &*event_record };
    format!(
        "Event(Id={}, Level={}, DataLen={})",
        event.EventHeader.EventDescriptor.Id,
        event.EventHeader.EventDescriptor.Level,
        event.UserDataLength,
    )
}

fn decode_properties(
    info_buf: &[u8],
    info: &TRACE_EVENT_INFO,
    event_record: *mut EVENT_RECORD,
) -> Vec<(String, String)> {
    let event = unsafe { &*event_record };
    let user_data = event.UserData as *const u8;
    let user_data_len = event.UserDataLength as usize;

    if user_data.is_null() || user_data_len == 0 {
        return Vec::new();
    }

    let prop_count = info.TopLevelPropertyCount as usize;
    let mut results = Vec::with_capacity(prop_count);
    let mut offset: usize = 0;

    for i in 0..prop_count {
        let prop_info = unsafe {
            let base =
                std::ptr::addr_of!(info.EventPropertyInfoArray) as *const EVENT_PROPERTY_INFO;
            &*base.add(i)
        };

        let prop_name =
            wide_str_at(info_buf, prop_info.NameOffset).unwrap_or_else(|| format!("prop{i}"));

        // PropertyStruct = PROPERTY_FLAGS(1) -- the struct header itself holds no
        // data, but its N child members do occupy space in the user data buffer.
        // We must decode (and skip) each child member to keep `offset` in sync.
        if prop_info.Flags.0 & 1 != 0 {
            let num_members =
                unsafe { prop_info.Anonymous1.structType.NumOfStructMembers } as usize;
            let start_index = unsafe { prop_info.Anonymous1.structType.StructStartIndex } as usize;

            for j in 0..num_members {
                let child_prop = unsafe {
                    let base = std::ptr::addr_of!(info.EventPropertyInfoArray)
                        as *const EVENT_PROPERTY_INFO;
                    &*base.add(start_index + j)
                };
                let child_in_type = unsafe { child_prop.Anonymous1.nonStructType.InType };
                let child_length = unsafe { child_prop.Anonymous3.length } as usize;
                let remaining = user_data_len.saturating_sub(offset);
                let data_ptr = if remaining > 0 {
                    unsafe { user_data.add(offset) }
                } else {
                    std::ptr::null()
                };
                let (_, consumed) =
                    format_property_value(child_in_type, child_length, data_ptr, remaining);
                offset += consumed;
            }

            results.push((prop_name, "<struct>".to_string()));
            continue;
        }

        let in_type = unsafe { prop_info.Anonymous1.nonStructType.InType };
        let prop_length = unsafe { prop_info.Anonymous3.length } as usize;

        let remaining = user_data_len.saturating_sub(offset);
        let data_ptr = if remaining > 0 {
            unsafe { user_data.add(offset) }
        } else {
            std::ptr::null()
        };

        let (value_str, consumed) =
            format_property_value(in_type, prop_length, data_ptr, remaining);

        offset += consumed;
        results.push((prop_name, value_str));
    }

    results
}

/// Fields to keep in minified mode for AccessCheckLog events with
/// ObjectType="File" or ObjectType="Key", in the order they should appear.
const MINIFIED_FILE_FIELDS: &[&str] = &["LowBoxNumber", "ProcessName", "ObjectName"];

/// In minified mode, reduce Kernel-General events to a useful subset of properties.
/// For AccessCheckLog File/Key events: strip to LowBoxNumber, ProcessName, ObjectName.
/// For other events: pass all properties through unmodified.
/// Returns `None` to suppress the event entirely (e.g. empty ObjectType in AccessCheckLog).
fn minify_kernel_general_props(
    props: Vec<(String, String)>,
    mode: DisplayMode,
) -> Option<Vec<(String, String)>> {
    if mode != DisplayMode::Minified {
        return Some(props);
    }

    // Suppress events with ObjectType="" (empty).
    let object_type = props
        .iter()
        .find(|(k, _)| k == "ObjectType")
        .map(|(_, v)| v.trim_matches('"').to_string());
    if let Some(ref t) = object_type {
        if t.is_empty() {
            return None;
        }
    }

    // Only minify File and Key events; pass others through unmodified.
    let is_minifiable = matches!(object_type.as_deref(), Some("File") | Some("Key"));
    if !is_minifiable {
        return Some(props);
    }

    // Collect matching props, then sort by the order defined in MINIFIED_FILE_FIELDS.
    let mut filtered: Vec<(String, String)> = props
        .into_iter()
        .filter(|(k, _)| MINIFIED_FILE_FIELDS.contains(&k.as_str()))
        .map(|(k, v)| {
            if k == "ProcessName" {
                let stripped = v.trim_matches('"').rsplit('\\').next().unwrap_or(&v);
                (k, format!("\"{stripped}\""))
            } else if k == "LowBoxNumber" {
                ("LBN".to_string(), v)
            } else {
                (k, v)
            }
        })
        .collect();

    filtered.sort_by_key(|(k, _)| {
        let orig = if k == "LBN" {
            "LowBoxNumber"
        } else {
            k.as_str()
        };
        MINIFIED_FILE_FIELDS
            .iter()
            .position(|f| *f == orig)
            .unwrap_or(usize::MAX)
    });

    Some(filtered)
}

fn format_property_value(
    in_type: u16,
    declared_length: usize,
    data: *const u8,
    available: usize,
) -> (String, usize) {
    if data.is_null() || available == 0 {
        return ("<no data>".to_string(), 0);
    }

    match in_type {
        TDH_INTYPE_UNICODESTRING => {
            let max_wchars = available / 2;
            let wchars = unsafe { std::slice::from_raw_parts(data.cast::<u16>(), max_wchars) };
            let len = wchars.iter().position(|&c| c == 0).unwrap_or(max_wchars);
            let s = String::from_utf16_lossy(&wchars[..len]);
            let consumed = (len + 1).min(max_wchars) * 2;
            (format!("\"{s}\""), consumed)
        }

        TDH_INTYPE_ANSISTRING => {
            let bytes = unsafe { std::slice::from_raw_parts(data, available) };
            let len = bytes.iter().position(|&b| b == 0).unwrap_or(available);
            let s = String::from_utf8_lossy(&bytes[..len]);
            let consumed = (len + 1).min(available);
            (format!("\"{s}\""), consumed)
        }

        TDH_INTYPE_INT8 if available >= 1 => {
            let v = unsafe { *data } as i8;
            (v.to_string(), 1)
        }
        TDH_INTYPE_UINT8 if available >= 1 => {
            let v = unsafe { *data };
            (v.to_string(), 1)
        }
        TDH_INTYPE_INT16 if available >= 2 => {
            let v = i16::from_le_bytes(read_bytes::<2>(data));
            (v.to_string(), 2)
        }
        TDH_INTYPE_UINT16 if available >= 2 => {
            let v = u16::from_le_bytes(read_bytes::<2>(data));
            (v.to_string(), 2)
        }
        TDH_INTYPE_INT32 if available >= 4 => {
            let v = i32::from_le_bytes(read_bytes::<4>(data));
            (v.to_string(), 4)
        }
        TDH_INTYPE_UINT32 if available >= 4 => {
            let v = u32::from_le_bytes(read_bytes::<4>(data));
            (v.to_string(), 4)
        }
        TDH_INTYPE_INT64 if available >= 8 => {
            let v = i64::from_le_bytes(read_bytes::<8>(data));
            (v.to_string(), 8)
        }
        TDH_INTYPE_UINT64 if available >= 8 => {
            let v = u64::from_le_bytes(read_bytes::<8>(data));
            (v.to_string(), 8)
        }
        TDH_INTYPE_FLOAT if available >= 4 => {
            let v = f32::from_le_bytes(read_bytes::<4>(data));
            (format!("{v:.4}"), 4)
        }
        TDH_INTYPE_DOUBLE if available >= 8 => {
            let v = f64::from_le_bytes(read_bytes::<8>(data));
            (format!("{v:.4}"), 8)
        }
        TDH_INTYPE_BOOLEAN if available >= 4 => {
            let v = i32::from_le_bytes(read_bytes::<4>(data));
            ((v != 0).to_string(), 4)
        }
        TDH_INTYPE_GUID if available >= 16 => {
            let b = unsafe { std::slice::from_raw_parts(data, 16) };
            let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            let d2 = u16::from_le_bytes([b[4], b[5]]);
            let d3 = u16::from_le_bytes([b[6], b[7]]);
            let s = format!(
                "{{{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-\
                 {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
                b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
            );
            (s, 16)
        }
        TDH_INTYPE_HEXINT32 if available >= 4 => {
            let v = u32::from_le_bytes(read_bytes::<4>(data));
            (format!("0x{v:08X}"), 4)
        }
        TDH_INTYPE_HEXINT64 if available >= 8 => {
            let v = u64::from_le_bytes(read_bytes::<8>(data));
            (format!("0x{v:016X}"), 8)
        }
        TDH_INTYPE_POINTER if available >= 8 => {
            let v = u64::from_le_bytes(read_bytes::<8>(data));
            (format!("0x{v:016X}"), 8)
        }
        TDH_INTYPE_FILETIME if available >= 8 => {
            let v = u64::from_le_bytes(read_bytes::<8>(data));
            (format!("FILETIME(0x{v:016X})"), 8)
        }
        _ => {
            let len = if declared_length > 0 {
                declared_length.min(available)
            } else {
                available.min(32)
            };
            let bytes = unsafe { std::slice::from_raw_parts(data, len) };
            let hex: String = bytes
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            (hex, len)
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_bytes<const N: usize>(ptr: *const u8) -> [u8; N] {
    let mut out = [0u8; N];
    unsafe {
        std::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), N);
    }
    out
}

fn wide_str_at(buf: &[u8], offset: u32) -> Option<String> {
    let off = offset as usize;
    if off == 0 || off >= buf.len() {
        return None;
    }

    let remaining = &buf[off..];
    let max_wchars = remaining.len() / 2;
    if max_wchars == 0 {
        return None;
    }

    let wchars =
        unsafe { std::slice::from_raw_parts(remaining.as_ptr().cast::<u16>(), max_wchars) };
    let len = wchars.iter().position(|&c| c == 0).unwrap_or(max_wchars);
    if len == 0 {
        return None;
    }

    Some(String::from_utf16_lossy(&wchars[..len]))
}
