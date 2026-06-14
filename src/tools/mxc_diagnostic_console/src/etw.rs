// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Real-time ETW consumer for MXC diagnostic providers.
//!
//! Listens for events from:
//! - **MXC OS-side** TraceLogging provider (all events)
//! - **Microsoft-Windows-Kernel-General** (all events -- AccessCheckLog, AppContainerTokenCheckLog,
//!   TokenSidManagementLog, learning-mode violations, etc.)
//!
//! Starts a trace session, enables the providers, and delivers decoded events
//! to the diagnostic console's display channel. Requires administrator privileges.

use std::borrow::Cow;
use std::cell::RefCell;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::SystemTime;

use windows::core::GUID;
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    TdhGetEventInformation, CONTROLTRACE_HANDLE, EVENT_PROPERTY_INFO, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
    TRACE_EVENT_INFO, TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
};

use super::denial_event::{AccessType, DenialEvent, ResourceType};
use super::{collect_mode, display_mode, DisplayEvent, DisplayMode};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// MXC OS-side TraceLogging provider GUID: {f6ec123e-314e-400b-9e0a-151365e23083}
const MXC_OS_PROVIDER: GUID = GUID {
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

/// Handle for the ETW consumer thread so `stop_etw_listener` can join it,
/// ensuring the `CallbackContext` remains valid until `ProcessTrace` exits.
static ETW_THREAD_HANDLE: Mutex<Option<std::thread::JoinHandle<()>>> = Mutex::new(None);

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

/// Context passed through the ETW callback's `UserContext` pointer.
/// Both senders live for the entire `ProcessTrace` duration.
struct CallbackContext {
    display_tx: mpsc::Sender<DisplayEvent>,
    denial_tx: Option<mpsc::Sender<DenialEvent>>,
}

/// Wrapper to send a raw pointer across thread boundaries.
/// SAFETY: the pointed-to `CallbackContext` lives for the entire ProcessTrace duration.
struct SendPtr(*mut CallbackContext);
unsafe impl Send for SendPtr {}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Start the ETW listener for diagnostic providers.
///
/// Enables the MXC OS-side TraceLogging provider and the Kernel-General provider
/// (all events for learning-mode diagnostics).
/// Spawns a background thread that calls `ProcessTrace` (blocking). Returns
/// immediately on success. Events are delivered via `tx`.
///
/// If `denial_tx` is provided, structured [`DenialEvent`]s are extracted from
/// AccessCheckLog events (ObjectType="File" or "Key") and LearningModeViolation
/// events (Event ID 27) and sent to the denial pipe module.
pub fn start_etw_listener(
    tx: mpsc::Sender<DisplayEvent>,
    denial_tx: Option<mpsc::Sender<DenialEvent>>,
) -> Result<(), String> {
    cleanup_stale_session();

    let handle = start_trace_session()?;
    SESSION_HANDLE.store(handle, Ordering::SeqCst);

    enable_provider(handle)?;

    let ctx = Box::new(CallbackContext {
        display_tx: tx,
        denial_tx,
    });
    let send_ptr = SendPtr(Box::into_raw(ctx));

    let handle = std::thread::Builder::new()
        .name("etw-consumer".into())
        .spawn(move || {
            process_trace_loop(send_ptr);
        })
        .map_err(|e| format!("Failed to spawn ETW consumer thread: {e}"))?;

    *ETW_THREAD_HANDLE.lock().unwrap() = Some(handle);

    Ok(())
}

/// Stop the trace session. Safe to call from a Ctrl+C handler.
///
/// Stops the ETW session and then joins the consumer thread to ensure the
/// `CallbackContext` is not freed while `ProcessTrace` callbacks may still
/// be executing.
pub fn stop_etw_listener() {
    let handle = SESSION_HANDLE.swap(0, Ordering::SeqCst);
    if handle != 0 {
        stop_session(handle);
    }
    // Wait for the ProcessTrace thread to exit before returning.
    // This guarantees the CallbackContext outlives all ETW callbacks.
    if let Some(jh) = ETW_THREAD_HANDLE.lock().unwrap().take() {
        let _ = jh.join();
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

    // Enable the MXC OS-side TraceLogging provider (all keywords, Verbose).
    let status = unsafe {
        EnableTraceEx2(
            h,
            &MXC_OS_PROVIDER,
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
            "EnableTraceEx2 (MXC OS provider) failed: error {}",
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
        // Non-fatal: warn but continue (MXC OS-side provider is already enabled).
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

/// RAII guard that frees the boxed `CallbackContext` on drop, preventing leaks
/// if `process_trace_loop` returns early (e.g., `OpenTraceW` failure).
struct CtxGuard(*mut CallbackContext);

impl Drop for CtxGuard {
    fn drop(&mut self) {
        // SAFETY: The pointer was created via `Box::into_raw` and is only freed once here.
        unsafe {
            drop(Box::from_raw(self.0));
        }
    }
}

#[allow(clippy::field_reassign_with_default)]
fn process_trace_loop(send_ptr: SendPtr) {
    let ctx_ptr = send_ptr.0;
    // Guard ensures the CallbackContext is freed on all exit paths.
    let _guard = CtxGuard(ctx_ptr);
    let mut name = session_name_wide();

    let mut logfile = EVENT_TRACE_LOGFILEW::default();
    logfile.LoggerName = windows_core::PWSTR(name.as_mut_ptr());

    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
    logfile.Context = ctx_ptr.cast::<c_void>();

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
    }
}

// ---------------------------------------------------------------------------
// Event record callback
// ---------------------------------------------------------------------------

unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    let event = unsafe { &*event_record };
    let provider = event.EventHeader.ProviderId;

    if provider == MXC_OS_PROVIDER {
        // MXC OS-side: accept all events.
    } else if provider == KERNEL_GENERAL_PROVIDER {
        // Kernel-General: accept all events (AccessCheckLog, AppContainerTokenCheckLog,
        // TokenSidManagementLog, learning-mode violations, etc.).
    } else {
        return;
    }

    let ctx = unsafe { &*(event.UserContext as *const CallbackContext) };
    let tx = &ctx.display_tx;
    let pid = event.EventHeader.ProcessId;
    let collecting = collect_mode();
    let current_mode = display_mode();

    if let Some(parts) = decode_event_parts(event_record) {
        // Extract DenialEvent for AccessCheckLog (File/Key) and LearningModeViolation events.
        if provider == KERNEL_GENERAL_PROVIDER {
            try_send_denial_event(ctx, &parts, pid);
        }

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
    // Reuse a per-thread scratch buffer for the TDH event information instead
    // of allocating a fresh `Vec` for every event. The buffer is resized
    // (growing only as needed) so the underlying allocation is retained.
    thread_local! {
        static TDH_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4096));
    }

    let mut buf_size: u32 = 0;
    let status = unsafe { TdhGetEventInformation(event_record, None, None, &mut buf_size) };

    // ERROR_INSUFFICIENT_BUFFER = 122
    if status != 122 {
        return None;
    }

    TDH_BUFFER.with(|cell| {
        let mut buffer = cell.borrow_mut();
        buffer.resize(buf_size as usize, 0);

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
    })
}

/// Learning mode violation event ID from Kernel-General.
const LEARNING_MODE_VIOLATION_EVENT_ID: u16 = 27;

/// Attempt to extract and send a [`DenialEvent`] from the decoded event.
///
/// Only **AccessCheckLog** events with `ObjectType="File"` are forwarded — these
/// are the actionable denials SDK consumers can act on. Registry (`Key`),
/// network, and other denials map to [`ResourceType::Other`], which the SDK
/// discards, so they are not emitted. LearningModeViolation events (Event ID 27)
/// are likewise not forwarded to the denial pipe (see M2); they remain visible
/// only on the console/collect display path.
///
/// Does nothing if `denial_tx` is `None` or the event is not an actionable
/// File denial.
fn try_send_denial_event(ctx: &CallbackContext, parts: &DecodedEventParts, pid: u32) {
    let denial_tx = match ctx.denial_tx.as_ref() {
        Some(tx) => tx,
        None => return,
    };

    // Learning-mode violations are not actionable denials for SDK consumers.
    if parts.event_id == LEARNING_MODE_VIOLATION_EVENT_ID {
        return;
    }

    if let Some(event) = build_denial_from_access_check(parts, pid) {
        let _ = denial_tx.send(event);
    }
}

/// Build a [`DenialEvent`] from an AccessCheckLog event with `ObjectType="File"`.
///
/// `pid` is the process id of the denied process taken from the ETW event
/// header — this is the reliable correlation key and the contract's primary
/// match field. The AppContainer profile name is **not** resolvable from the
/// raw event (only a numeric `LowBoxNumber` is present, which consumers cannot
/// use), so `container_name` is left empty; PID matching is the contract.
fn build_denial_from_access_check(parts: &DecodedEventParts, pid: u32) -> Option<DenialEvent> {
    let object_type = find_prop(&parts.props, "ObjectType")?;
    let object_type_str = object_type.trim_matches('"');

    // Only File denials are actionable. Key (registry), network, and other
    // denials map to ResourceType::Other, which the SDK discards, so we do not
    // emit them.
    let resource_type = ResourceType::from_object_type(object_type_str);
    if resource_type != ResourceType::File {
        return None;
    }

    let object_name = find_prop(&parts.props, "ObjectName")
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default();

    // PID is the contract's match key; the profile name is not resolvable here.
    let container_name = String::new();
    let access_requested = access_type_from_props(&parts.props);

    Some(DenialEvent::new(
        container_name,
        pid,
        resource_type,
        object_name,
        access_requested,
        iso8601_now(),
        parts.event_id,
    ))
}

/// ETW property names that may carry the requested/granted access mask for an
/// AccessCheckLog event, in priority order.
const ACCESS_MASK_PROPS: &[&str] = &["DesiredAccess", "AccessMask", "GrantedAccess"];

/// Determine the [`AccessType`] from any available access-mask property.
///
/// Returns [`AccessType::Unknown`] when no recognizable mask property is present.
fn access_type_from_props(props: &[(String, String)]) -> AccessType {
    for name in ACCESS_MASK_PROPS {
        if let Some(value) = find_prop(props, name) {
            if let Some(mask) = parse_access_mask(value) {
                return access_type_from_mask(mask);
            }
        }
    }
    AccessType::Unknown
}

/// Parse an access mask rendered either as `0x...` hex (the common TDH hex-int
/// form) or as a decimal integer. Surrounding quotes/whitespace are tolerated.
fn parse_access_mask(value: &str) -> Option<u32> {
    let trimmed = value.trim().trim_matches('"').trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse::<u32>().ok()
    }
}

/// Classify an access mask into a coarse [`AccessType`].
///
/// Write is the most actionable signal, so it takes precedence over execute,
/// then read. Bit values follow the Win32 file access-rights constants.
fn access_type_from_mask(mask: u32) -> AccessType {
    // Write-implying rights: FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA,
    // FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE.
    const WRITE_BITS: u32 =
        0x0002 | 0x0004 | 0x0010 | 0x0100 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x4000_0000;
    // Execute rights: FILE_EXECUTE, GENERIC_EXECUTE.
    const EXEC_BITS: u32 = 0x0020 | 0x2000_0000;
    // Read rights: FILE_READ_DATA, FILE_READ_EA, FILE_READ_ATTRIBUTES, GENERIC_READ.
    const READ_BITS: u32 = 0x0001 | 0x0008 | 0x0080 | 0x8000_0000;

    if mask & WRITE_BITS != 0 {
        AccessType::Write
    } else if mask & EXEC_BITS != 0 {
        AccessType::Execute
    } else if mask & READ_BITS != 0 {
        AccessType::Read
    } else {
        AccessType::Unknown
    }
}

/// Find a property value by name in the decoded property list.
fn find_prop<'a>(props: &'a [(String, String)], name: &str) -> Option<&'a String> {
    props.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

/// Return the current time as an ISO 8601 formatted string.
///
/// The formatted string is cached per thread and only recomputed when the
/// wall-clock second changes, avoiding redundant formatting work when many
/// denial events arrive within the same second.
fn iso8601_now() -> String {
    thread_local! {
        static CACHED_TIMESTAMP: RefCell<(u64, String)> = const { RefCell::new((0, String::new())) };
    }

    let now = SystemTime::now();
    let duration = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    CACHED_TIMESTAMP.with(|cache| {
        let mut c = cache.borrow_mut();
        if c.0 == secs && !c.1.is_empty() {
            return c.1.clone();
        }

        // Simple ISO 8601 without external dependency.
        // Format: YYYY-MM-DDTHH:MM:SSZ
        let days = secs / 86400;
        let time_of_day = secs % 86400;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;

        // Compute year/month/day from days since epoch (1970-01-01).
        let (year, month, day) = days_to_ymd(days);

        let formatted =
            format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z");
        c.0 = secs;
        c.1 = formatted;
        c.1.clone()
    })
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil days algorithm (from Howard Hinnant).
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146097) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Human-readable names for learning mode violation categories.
fn learning_mode_category_name(category: &str) -> &str {
    match category {
        "0" => "None",
        "1" => "ConvertToGui",
        "2" => "UiOperation",
        _ => category,
    }
}

/// Map a UIOperation integral value (JOB_OBJECT_UILIMIT_* constant) to its name.
/// Returns `None` if the value does not match a known UIOperation.
fn ui_operation_name(value: u64) -> Option<&'static str> {
    match value {
        0x001 => Some("Handles"),
        0x002 => Some("ReadClipboard"),
        0x004 => Some("WriteClipboard"),
        0x008 => Some("SystemParameters"),
        0x010 => Some("DisplaySettings"),
        0x020 => Some("GlobalAtoms"),
        0x040 => Some("Desktop"),
        0x080 => Some("ExitWindows"),
        0x100 => Some("IME"),
        0x200 => Some("Injection"),
        _ => None,
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

    let props = minify_kernel_general_props(&parts.props, mode)?;

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

    // Determine if this is a UiOperation category so we can resolve Detail.
    let is_ui_operation = props
        .iter()
        .any(|(k, v)| k == "Category" && v.trim_matches('"') == "2");

    // Replace the Category number with its human-readable name (colored orange),
    // and resolve the Detail integer to its UIOperation name when Category is UiOperation.
    let formatted_props: Vec<(String, String)> = props
        .iter()
        .map(|(k, v)| {
            if k == "Category" {
                let raw = v.trim_matches('"');
                let name = learning_mode_category_name(raw);
                (k.clone(), format!("{orange}{name}{reset}"))
            } else if k == "Detail" && is_ui_operation {
                let raw = v.trim_matches('"');
                if let Ok(val) = raw.parse::<u64>() {
                    if let Some(name) = ui_operation_name(val) {
                        return (k.clone(), format!("{orange}{name}{reset}"));
                    }
                }
                (k.clone(), v.clone())
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
        // The property value above was decoded safely from the bounded
        // `remaining` slice, so record it before any further bounds check.
        results.push((prop_name, value_str));
        // Guard against malformed ETW events whose property lengths would
        // advance the cursor past the end of the user-data buffer; reading
        // beyond it via `user_data.add(offset)` on the next iteration would be
        // undefined behavior.
        if offset > user_data_len {
            break;
        }
    }

    results
}

/// Fields to keep in minified mode for AccessCheckLog events with
/// ObjectType="File" or ObjectType="Key", in the order they should appear.
const MINIFIED_FILE_FIELDS: &[&str] = &["LowBoxNumber", "ProcessName", "ObjectName"];

/// In minified mode, reduce Kernel-General events to a useful subset of properties.
/// For AccessCheckLog File/Key events: strip to LowBoxNumber, ProcessName, ObjectName.
/// For other events: pass all properties through unmodified (borrowed, no clone).
/// Returns `None` to suppress the event entirely (e.g. empty ObjectType in AccessCheckLog).
///
/// The input is borrowed; an owned `Vec` is only allocated when the props are
/// actually filtered/rewritten (minified File/Key events). Non-minified and
/// non-minifiable events return a borrow of the caller's slice.
fn minify_kernel_general_props<'a>(
    props: &'a [(String, String)],
    mode: DisplayMode,
) -> Option<Cow<'a, [(String, String)]>> {
    if mode != DisplayMode::Minified {
        return Some(Cow::Borrowed(props));
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
        return Some(Cow::Borrowed(props));
    }

    // Collect matching props, then sort by the order defined in MINIFIED_FILE_FIELDS.
    let mut filtered: Vec<(String, String)> = props
        .iter()
        .filter(|(k, _)| MINIFIED_FILE_FIELDS.contains(&k.as_str()))
        .map(|(k, v)| {
            if k == "ProcessName" {
                let stripped = v.trim_matches('"').rsplit('\\').next().unwrap_or(v);
                (k.clone(), format!("\"{stripped}\""))
            } else if k == "LowBoxNumber" {
                ("LBN".to_string(), v.clone())
            } else {
                (k.clone(), v.clone())
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

    Some(Cow::Owned(filtered))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parts_with(props: Vec<(String, String)>) -> DecodedEventParts {
        DecodedEventParts {
            event_name: Some("AccessCheckLog".to_string()),
            event_id: 4907,
            provider: KERNEL_GENERAL_PROVIDER,
            level_tag: "",
            props,
        }
    }

    #[test]
    fn parse_access_mask_hex_and_decimal() {
        assert_eq!(parse_access_mask("0x80000000"), Some(0x8000_0000));
        assert_eq!(parse_access_mask("\"0X00000002\""), Some(2));
        assert_eq!(parse_access_mask(" 32 "), Some(32));
        assert_eq!(parse_access_mask("not-a-number"), None);
    }

    #[test]
    fn access_type_from_mask_priority() {
        // Write takes precedence over read when both bits are present.
        assert_eq!(
            access_type_from_mask(0x8000_0000 | 0x4000_0000),
            AccessType::Write
        );
        // GENERIC_EXECUTE.
        assert_eq!(access_type_from_mask(0x2000_0000), AccessType::Execute);
        // GENERIC_READ.
        assert_eq!(access_type_from_mask(0x8000_0000), AccessType::Read);
        // No recognized bits.
        assert_eq!(access_type_from_mask(0), AccessType::Unknown);
    }

    #[test]
    fn access_type_from_props_reads_first_known_property() {
        let props = vec![
            ("ObjectType".to_string(), "\"File\"".to_string()),
            ("DesiredAccess".to_string(), "0x00000002".to_string()),
        ];
        assert_eq!(access_type_from_props(&props), AccessType::Write);

        // No mask property → Unknown.
        let props = vec![("ObjectType".to_string(), "\"File\"".to_string())];
        assert_eq!(access_type_from_props(&props), AccessType::Unknown);
    }

    #[test]
    fn build_denial_only_emits_file_with_empty_container_name() {
        // File denial → emitted; container name is empty (PID is the key).
        let parts = parts_with(vec![
            ("ObjectType".to_string(), "\"File\"".to_string()),
            ("ObjectName".to_string(), "\"C:\\\\f.txt\"".to_string()),
            ("LowBoxNumber".to_string(), "\"7\"".to_string()),
            ("DesiredAccess".to_string(), "0x80000000".to_string()),
        ]);
        let event = build_denial_from_access_check(&parts, 4567).expect("file denial");
        assert_eq!(event.pid, 4567);
        assert_eq!(event.resource_type, ResourceType::File);
        assert_eq!(event.container_name, "");
        assert_eq!(event.access_requested, AccessType::Read);

        // Key (registry) denial → not emitted (maps to Other, discarded by SDK).
        let parts = parts_with(vec![
            ("ObjectType".to_string(), "\"Key\"".to_string()),
            ("ObjectName".to_string(), "\"HKLM\\\\X\"".to_string()),
        ]);
        assert!(build_denial_from_access_check(&parts, 1).is_none());

        // Empty/network object type → not emitted.
        let parts = parts_with(vec![("ObjectType".to_string(), "\"\"".to_string())]);
        assert!(build_denial_from_access_check(&parts, 1).is_none());
    }
}
