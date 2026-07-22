// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Sealed-ETL decoder: turns the `.etl` that [`crate::CaptureSession::finish`]
//! produces into cross-platform [`DeniedResource`]s.
//!
//! The trace is opened in **file mode** (`EVENT_TRACE_LOGFILEW.LogFileName`,
//! without `PROCESS_TRACE_MODE_REAL_TIME`). `ProcessTrace` walks every
//! buffered event and returns on its own at end-of-file, so there is no
//! controller session to stop and no worker thread to join — we run it
//! synchronously, collect the decoded events, then extract and
//! de-duplicate denials.
//!
//! [`EtlDenialAnalyzer`] implements the cross-platform
//! [`learning_mode_core::DenialAnalyzer`] trait so the runner and tests can
//! depend on the abstraction rather than this Windows-specific decoder.

use std::collections::HashSet;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use learning_mode_core::{AnalyzeError, DenialAnalyzer, DeniedResource};
use windows::core::PWSTR;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, OpenTraceW, ProcessTrace, EVENT_RECORD, EVENT_TRACE_LOGFILEW,
    PROCESS_TRACE_MODE_EVENT_RECORD,
};

use crate::extractors::{extract_denial, DecodedEventParts, RawDenial};
use crate::{path_norm, tdh_decode};

/// `OpenTraceW` returns this sentinel (`(TRACEHANDLE)-1`) on failure.
const INVALID_PROCESSTRACE_HANDLE: u64 = u64::MAX;

/// One decoded ETW event, retaining the header context the extractors need.
struct CollectedEvent {
    pid: u32,
    filetime: u64,
    parts: DecodedEventParts,
}

/// Accumulates decoded events during a `ProcessTrace` pass. A pointer to
/// this is handed to ETW via `EVENT_TRACE_LOGFILEW.Context` and read back
/// in the record callback.
#[derive(Default)]
struct Accumulator {
    events: Vec<CollectedEvent>,
}

/// A [`DenialAnalyzer`] over a sealed learning-mode `.etl` file.
#[derive(Debug, Default, Clone, Copy)]
pub struct EtlDenialAnalyzer;

impl DenialAnalyzer for EtlDenialAnalyzer {
    fn analyze(&self, source_path: &Path) -> Result<Vec<DeniedResource>, AnalyzeError> {
        let events = process_trace_file(source_path)?;
        Ok(resources_from_events(&events))
    }
}

/// Runs the pure decode composition over already-collected events:
/// route each event through [`extract_denial`], then normalise +
/// de-duplicate into public [`DeniedResource`]s. Split out from
/// [`EtlDenialAnalyzer::analyze`] so it can be tested with hand-built events
/// that mirror real traces, without a live ETW/TDH read (which needs the
/// provider manifests registered on the machine).
fn resources_from_events(events: &[CollectedEvent]) -> Vec<DeniedResource> {
    dedup_to_resources(
        events
            .iter()
            .filter_map(|e| extract_denial(&e.parts, e.pid, e.filetime)),
    )
}

/// Decodes every event in the ETL into `(event_id, props)` pairs, for
/// schema discovery / diagnostics. Preserves the on-disk order.
///
/// # Errors
///
/// Returns [`AnalyzeError`] if the trace cannot be opened or processed.
pub fn decode_raw_events(source_path: &Path) -> Result<Vec<DecodedEventParts>, AnalyzeError> {
    Ok(process_trace_file(source_path)?
        .into_iter()
        .map(|e| e.parts)
        .collect())
}

/// De-duplicates raw denials by `(user-visible resource, accessType)`,
/// normalising kernel file paths to drive-letter form and preserving
/// first-seen order. Non-file resources (capabilities, registry keys, UI)
/// are not path-like, so normalisation is a no-op and their identifier is
/// carried through unchanged.
fn dedup_to_resources<I: IntoIterator<Item = RawDenial>>(raws: I) -> Vec<DeniedResource> {
    let mut seen: HashSet<(String, learning_mode_core::AccessType)> = HashSet::new();
    let mut out = Vec::new();
    for raw in raws {
        let resource =
            path_norm::to_user_visible(&raw.object_name).unwrap_or_else(|| raw.object_name.clone());
        if seen.insert((resource.clone(), raw.access_type)) {
            out.push(DeniedResource {
                resource,
                resource_type: raw.resource_type,
                access_type: raw.access_type,
                pid: raw.pid,
                filetime: raw.filetime,
            });
        }
    }
    out
}

/// Opens `source_path` as an ETL log file, runs `ProcessTrace` to
/// completion, and returns the decoded events.
fn process_trace_file(source_path: &Path) -> Result<Vec<CollectedEvent>, AnalyzeError> {
    // Fail fast with a clear error if the file is missing/unreadable,
    // rather than surfacing an opaque OpenTraceW Win32 code.
    std::fs::File::open(source_path).map_err(|source| AnalyzeError::Open {
        path: source_path.display().to_string(),
        source,
    })?;

    let mut name_wide: Vec<u16> = source_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut accumulator = Accumulator::default();

    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { core::mem::zeroed() };
    logfile.LogFileName = PWSTR(name_wide.as_mut_ptr());
    logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
    logfile.Context = std::ptr::addr_of_mut!(accumulator).cast();

    // SAFETY: `logfile` and `name_wide` outlive the OpenTraceW call; the
    // callback pointer is valid and the Context points at a live stack
    // value that outlives the ProcessTrace call below.
    let handle = unsafe { OpenTraceW(&mut logfile) };
    if handle.Value == INVALID_PROCESSTRACE_HANDLE {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) as u32;
        return Err(AnalyzeError::Decode(format!(
            "OpenTraceW failed for '{}': Win32 error {code}",
            source_path.display()
        )));
    }

    let handles = [handle];
    // SAFETY: `handles` is valid for the call. In file mode ProcessTrace
    // processes all buffered events (invoking our callback synchronously
    // on this thread) and returns at end-of-file.
    let status = unsafe { ProcessTrace(&handles, None, None) };

    // SAFETY: closing the consumer handle we opened above. Idempotent.
    unsafe {
        let _ = CloseTrace(handle);
    }

    // ERROR_SUCCESS (0) and ERROR_CANCELLED (1223) are both acceptable
    // terminal states for a completed file trace.
    if status.0 != 0 && status.0 != 1223 {
        return Err(AnalyzeError::Decode(format!(
            "ProcessTrace failed for '{}': Win32 error {}",
            source_path.display(),
            status.0
        )));
    }

    Ok(accumulator.events)
}

/// ETW record callback, invoked by `ProcessTrace` for every event in the
/// file. Decodes the event via TDH and appends it to the [`Accumulator`]
/// pointed to by `EVENT_RECORD.UserContext`.
///
/// # Safety
/// Invoked by ETW with a valid `EVENT_RECORD` whose `UserContext` is the
/// `Accumulator` pointer we set on `EVENT_TRACE_LOGFILEW.Context`.
unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }
    // SAFETY: ETW guarantees a valid record; we only read POD header fields.
    let header = unsafe { (*event_record).EventHeader };
    let context = unsafe { (*event_record).UserContext } as *mut Accumulator;
    if context.is_null() {
        return;
    }

    // SAFETY: `context` is the live Accumulator we passed via Context, and
    // ProcessTrace invokes this callback synchronously on our thread, so no
    // aliasing/concurrency with the owner occurs.
    let acc = unsafe { &mut *context };

    if let Some(parts) = unsafe { tdh_decode::decode_event_parts(event_record) } {
        acc.events.push(CollectedEvent {
            pid: header.ProcessId,
            filetime: header.TimeStamp as u64,
            parts,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use learning_mode_core::{AccessType, ResourceType};

    fn raw(path: &str, access: AccessType, rt: ResourceType) -> RawDenial {
        RawDenial {
            pid: 1,
            resource_type: rt,
            object_name: path.to_string(),
            access_type: access,
            filetime: 1,
            event_id: 4907,
        }
    }

    #[test]
    fn dedup_collapses_repeated_path_access_pairs() {
        let denials = vec![
            raw(r"C:\a", AccessType::Read, ResourceType::File),
            raw(r"C:\a", AccessType::Read, ResourceType::File),
            raw(r"C:\a", AccessType::Write, ResourceType::File),
            raw(r"C:\b", AccessType::Read, ResourceType::File),
        ];
        let out = dedup_to_resources(denials);
        assert_eq!(out.len(), 3, "unique (resource, access) pairs");
        assert_eq!(out[0].resource, r"C:\a");
        assert_eq!(out[0].access_type, AccessType::Read);
        assert_eq!(out[1].access_type, AccessType::Write);
        assert_eq!(out[2].resource, r"C:\b");
    }

    #[test]
    fn dedup_preserves_first_seen_order() {
        let denials = vec![
            raw(r"C:\z", AccessType::Read, ResourceType::File),
            raw(r"C:\a", AccessType::Read, ResourceType::File),
        ];
        let out = dedup_to_resources(denials);
        assert_eq!(out[0].resource, r"C:\z");
        assert_eq!(out[1].resource, r"C:\a");
    }

    #[test]
    fn analyze_missing_file_returns_open_error() {
        let analyzer = EtlDenialAnalyzer;
        let err = analyzer
            .analyze(Path::new(r"C:\does\not\exist\nope.etl"))
            .unwrap_err();
        assert!(matches!(err, AnalyzeError::Open { .. }), "got {err:?}");
    }

    // ---- decode composition over real event shapes ------------------------
    //
    // These exercise the full `analyze` pipeline minus the OS trace read:
    // `extract_denial` routing -> path normalisation -> dedup. The events
    // mirror captures taken on hardware for both learning modes (see the
    // module/extractor docs); a live ETW/TDH read isn't used because it
    // needs the provider manifests registered on the machine.

    fn event(event_id: u16, pid: u32, filetime: u64, kv: &[(&str, &str)]) -> CollectedEvent {
        CollectedEvent {
            pid,
            filetime,
            parts: DecodedEventParts {
                event_id,
                props: kv
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            },
        }
    }

    /// Mirrors the real `Mode="Normal"` (block-and-log) capture: file/registry
    /// access checks as event 14 plus a compact capability denial as event 28.
    #[test]
    fn block_and_log_shape_decodes_and_classifies() {
        let events = vec![
            // File write (DELETE | FILE_READ_DATA -> Write), \??\ prefix.
            event(
                14,
                5480,
                10,
                &[
                    ("Mode", "\"Normal\""),
                    ("ObjectType", "\"File\""),
                    ("ObjectName", "\"\\??\\C:\\data\\test\\bin\\\""),
                    ("AccessMask", "0x10001"),
                ],
            ),
            // Registry read (KEY_READ 0x20019 -> Read) stays kernel-form.
            event(
                14,
                6860,
                11,
                &[
                    ("Mode", "\"Normal\""),
                    ("ObjectType", "\"Key\""),
                    ("ObjectName", "\"\\REGISTRY\\USER\\.DEFAULT\\Console\""),
                    ("AccessMask", "0x20019"),
                ],
            ),
            // Capability denial (event 28) -> empty resource, unknown access.
            event(
                28,
                0,
                12,
                &[
                    ("ProcessName", "\"conhost.exe\""),
                    ("ProcessId", "0x1acc"),
                    ("Denied", "true"),
                ],
            ),
        ];

        let out = resources_from_events(&events);
        assert_eq!(out.len(), 3);

        assert_eq!(out[0].resource, r"C:\data\test\bin\");
        assert_eq!(out[0].resource_type, ResourceType::File);
        assert_eq!(out[0].access_type, AccessType::Write);
        assert_eq!(out[0].pid, 5480);

        assert_eq!(out[1].resource, r"\REGISTRY\USER\.DEFAULT\Console");
        assert_eq!(out[1].resource_type, ResourceType::Other);
        assert_eq!(out[1].access_type, AccessType::Read);

        assert_eq!(out[2].resource, "");
        assert_eq!(out[2].resource_type, ResourceType::Capability);
        assert_eq!(out[2].access_type, AccessType::Unknown);
        assert_eq!(out[2].pid, 0x1acc, "pid from payload ProcessId");
    }

    /// Mirrors the real `Mode="Permissive"` (allow-and-log) capture: the same
    /// file/registry checks plus a capability check folded into an
    /// empty-`ObjectType` event 14 (there is no event 28 in this mode).
    #[test]
    fn allow_and_log_shape_folds_capability_into_event_14() {
        let events = vec![
            event(
                14,
                2292,
                20,
                &[
                    ("Mode", "\"Permissive\""),
                    ("ObjectType", "\"File\""),
                    ("ObjectName", "\"\\??\\C:\\data\\test\\bin\\\""),
                    ("AccessMask", "0x10001"),
                ],
            ),
            // Empty ObjectType == brokered-capability check.
            event(
                14,
                5900,
                21,
                &[
                    ("Mode", "\"Permissive\""),
                    ("ObjectType", "\"\""),
                    ("ObjectName", "\"\""),
                    ("AccessMask", "0x1"),
                ],
            ),
        ];

        let out = resources_from_events(&events);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].resource, r"C:\data\test\bin\");
        assert_eq!(out[0].access_type, AccessType::Write);
        assert_eq!(out[1].resource_type, ResourceType::Capability);
        assert_eq!(out[1].resource, "");
        assert_eq!(out[1].access_type, AccessType::Unknown);
    }

    /// Both a permissive empty-`ObjectType` event 14 and a block-mode event 28
    /// capability denial reduce to the same `("", Unknown)` key, so they
    /// collapse to a single capability resource.
    #[test]
    fn empty_path_capabilities_collapse_to_one() {
        let events = vec![
            event(
                14,
                1,
                1,
                &[
                    ("ObjectType", "\"\""),
                    ("ObjectName", "\"\""),
                    ("AccessMask", "0x1"),
                ],
            ),
            event(28, 0, 2, &[("ProcessId", "0x10"), ("Denied", "true")]),
            event(28, 0, 3, &[("ProcessId", "0x20"), ("Denied", "true")]),
        ];
        let out = resources_from_events(&events);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].resource_type, ResourceType::Capability);
        assert_eq!(out[0].resource, "");
    }

    /// Non-actionable object types and not-denied capability records are
    /// dropped by the pipeline; unknown event IDs are ignored.
    #[test]
    fn non_actionable_events_are_dropped() {
        let events = vec![
            event(14, 1, 1, &[("ObjectType", "\"Section\"")]),
            event(28, 0, 2, &[("ProcessId", "0x10"), ("Denied", "false")]),
            event(9999, 1, 3, &[("Foo", "\"bar\"")]),
        ];
        assert!(resources_from_events(&events).is_empty());
    }
}
