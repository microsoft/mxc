// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Sealed-ETL decoder: turns the `.etl` that [`crate::CaptureSession::finish`]
//! produces into cross-platform [`DeniedResource`]s.
//!
//! The trace is opened in **file mode** (`EVENT_TRACE_LOGFILEW.LogFileName`,
//! without `PROCESS_TRACE_MODE_REAL_TIME`). `ProcessTrace` walks every
//! buffered event and returns on its own at end-of-file, so there is no
//! controller session to stop and no worker thread to join — we run it
//! synchronously and extract/de-duplicate denials inside the callback so large
//! traces do not accumulate every decoded event in memory.
//!
//! [`EtlDenialAnalyzer`] implements the cross-platform
//! [`mxc_alpha_learning_mode_core::DenialAnalyzer`] trait so the runner and tests can
//! depend on the abstraction rather than this Windows-specific decoder.
//!
//! The diagnostic console has a separate real-time, display-oriented ETW
//! consumer in `tools/mxc_diagnostic_console`. It is a binary-private module
//! that owns trace sessions and channels arbitrary provider events to a UI.
//! This backend instead reads sealed files synchronously, filters a fixed
//! provider/event vocabulary, bounds results, and skips malformed individual
//! events without invalidating the rest of the capture. Depending on the tool would invert the workspace dependency
//! direction; shared generic TDH primitives can be extracted later if another
//! runtime consumer needs them.

use std::collections::HashSet;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use mxc_alpha_learning_mode_core::{AnalysisResult, AnalyzeError, DenialAnalyzer, DeniedResource};
use windows::core::PWSTR;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, OpenTraceW, ProcessTrace, EVENT_RECORD, EVENT_TRACE_LOGFILEW,
    PROCESS_TRACE_MODE_EVENT_RECORD,
};

use crate::extractors::{extract_denial, is_learning_mode_event, DecodedEventParts, RawDenial};
use crate::{path_norm, tdh_decode};

/// `OpenTraceW` returns this sentinel (`(TRACEHANDLE)-1`) on failure.
const INVALID_PROCESSTRACE_HANDLE: u64 = u64::MAX;
const MAX_UNIQUE_DENIALS: usize = 10_000;
const MAX_PROCESSED_EVENTS: usize = 1_000_000;

/// One decoded ETW event, retaining the header context the extractors need.
#[cfg(test)]
struct CollectedEvent {
    pid: u32,
    filetime: u64,
    parts: DecodedEventParts,
}

#[derive(Clone, Copy)]
enum CollectionMode {
    Analyze,
    Raw,
}

type RawEventVisitor<'a> = dyn FnMut(&DecodedEventParts) -> std::io::Result<()> + 'a;

/// Accumulates bounded analysis results or streams raw diagnostic events
/// during a `ProcessTrace` pass.
struct Accumulator<'visitor> {
    mode: CollectionMode,
    denials: Vec<DeniedResource>,
    seen: HashSet<(String, mxc_alpha_learning_mode_core::AccessType)>,
    truncated: bool,
    raw_visitor: Option<&'visitor mut RawEventVisitor<'visitor>>,
    raw_event_count: usize,
    processed_event_count: usize,
    processing_limit_reached: bool,
    stop_requested: bool,
    decode_error: Option<String>,
    panic_payload: Option<Box<dyn std::any::Any + Send>>,
    schema_cache: tdh_decode::EventSchemaCache,
}

impl<'visitor> Accumulator<'visitor> {
    fn analyze() -> Self {
        Self {
            mode: CollectionMode::Analyze,
            denials: Vec::new(),
            seen: HashSet::new(),
            truncated: false,
            raw_visitor: None,
            raw_event_count: 0,
            processed_event_count: 0,
            processing_limit_reached: false,
            stop_requested: false,
            decode_error: None,
            panic_payload: None,
            schema_cache: tdh_decode::EventSchemaCache::default(),
        }
    }

    fn raw(visitor: &'visitor mut RawEventVisitor<'visitor>) -> Self {
        Self {
            mode: CollectionMode::Raw,
            denials: Vec::new(),
            seen: HashSet::new(),
            truncated: false,
            raw_visitor: Some(visitor),
            raw_event_count: 0,
            processed_event_count: 0,
            processing_limit_reached: false,
            stop_requested: false,
            decode_error: None,
            panic_payload: None,
            schema_cache: tdh_decode::EventSchemaCache::default(),
        }
    }

    fn add_raw_denial(&mut self, raw: RawDenial) {
        let resource = if raw.resource_type == mxc_alpha_learning_mode_core::ResourceType::File {
            match path_norm::to_user_visible(&raw.object_name) {
                Some(resource) if path_norm::is_user_visible_absolute(&resource) => resource,
                Some(_) => return,
                None if path_norm::is_user_visible_absolute(&raw.object_name) => {
                    raw.object_name.clone()
                }
                None => return,
            }
        } else {
            path_norm::to_user_visible(&raw.object_name).unwrap_or_else(|| raw.object_name.clone())
        };
        let dedup_resource = match raw.resource_type {
            mxc_alpha_learning_mode_core::ResourceType::File | mxc_alpha_learning_mode_core::ResourceType::Other => {
                resource.to_ascii_lowercase()
            }
            _ => resource.clone(),
        };
        if self
            .seen
            .contains(&(dedup_resource.clone(), raw.access_type))
        {
            return;
        }
        if self.denials.len() >= MAX_UNIQUE_DENIALS {
            self.truncated = true;
            self.stop_requested = true;
            return;
        }
        self.seen.insert((dedup_resource, raw.access_type));
        self.denials.push(DeniedResource {
            resource,
            resource_type: raw.resource_type,
            access_type: raw.access_type,
            pid: raw.pid,
            filetime: raw.filetime,
        });
    }

    fn begin_event(&mut self) -> bool {
        if self.processed_event_count >= MAX_PROCESSED_EVENTS {
            self.processing_limit_reached = true;
            self.truncated = true;
            self.stop_requested = true;
            return false;
        }
        self.processed_event_count += 1;
        true
    }

    fn visit_raw_event(&mut self, parts: &DecodedEventParts) {
        let Some(visitor) = self.raw_visitor.as_mut() else {
            return;
        };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| visitor(parts))) {
            Ok(Ok(())) => self.raw_event_count += 1,
            Ok(Err(error)) => {
                self.decode_error = Some(format!("raw event consumer failed: {error}"));
            }
            Err(payload) => self.panic_payload = Some(payload),
        }
    }

    fn record_event_decode_error(
        &mut self,
        provider: windows::core::GUID,
        event_id: u16,
        error: tdh_decode::DecodeError,
    ) {
        if (matches!(self.mode, CollectionMode::Raw) || error.is_schema_error())
            && self.decode_error.is_none()
        {
            self.decode_error = Some(format!("provider {:?} event {event_id}: {error}", provider));
        }
    }

    fn into_analysis(self) -> Result<AnalysisResult, AnalyzeError> {
        if let Some(error) = self.decode_error {
            return Err(AnalyzeError::Decode(error));
        }
        Ok(AnalysisResult {
            denials: self.denials,
            denied_resources_truncated: self.truncated,
        })
    }
}

/// A [`DenialAnalyzer`] over a sealed learning-mode `.etl` file.
#[derive(Debug, Default, Clone, Copy)]
pub struct EtlDenialAnalyzer;

impl DenialAnalyzer for EtlDenialAnalyzer {
    fn analyze(&self, source_path: &Path) -> Result<AnalysisResult, AnalyzeError> {
        let mut accumulator = Accumulator::analyze();
        process_trace_file(source_path, &mut accumulator)?;
        accumulator.into_analysis()
    }
}

/// Runs the pure decode composition over already-collected events:
/// route each event through [`extract_denial`], then normalise +
/// de-duplicate into public [`DeniedResource`]s. Split out from
/// [`EtlDenialAnalyzer::analyze`] so it can be tested with hand-built events
/// that mirror real traces, without a live ETW/TDH read (which needs the
/// provider manifests registered on the machine).
#[cfg(test)]
fn resources_from_events(events: &[CollectedEvent]) -> AnalysisResult {
    let mut raws = Vec::new();
    for event in events {
        if let Some(raw) = extract_denial(&event.parts, event.pid, event.filetime) {
            raws.push(raw);
        }
        raws.extend(crate::capability_dacl::extract_denials(
            &event.parts,
            event.pid,
            event.filetime,
        ));
    }
    dedup_to_resources(raws)
}

/// Streams every decoded event in the ETL to `visitor` for schema discovery
/// and diagnostics, preserving on-disk order without retaining the trace in
/// memory. Returns the number of events delivered.
///
/// # Errors
///
/// Returns [`AnalyzeError`] if the trace cannot be opened or processed.
pub fn visit_raw_events(
    source_path: &Path,
    visitor: &mut RawEventVisitor<'_>,
) -> Result<usize, AnalyzeError> {
    let mut accumulator = Accumulator::raw(visitor);
    process_trace_file(source_path, &mut accumulator)?;
    if accumulator.processing_limit_reached {
        return Err(AnalyzeError::Decode(format!(
            "trace exceeded the {MAX_PROCESSED_EVENTS}-event processing limit"
        )));
    }
    if let Some(error) = accumulator.decode_error {
        return Err(AnalyzeError::Decode(error));
    }
    Ok(accumulator.raw_event_count)
}

/// De-duplicates raw denials by `(user-visible resource, accessType)`,
/// normalising case-insensitive Windows file/registry identifiers while
/// preserving first-seen display spelling and order.
#[cfg(test)]
fn dedup_to_resources<I: IntoIterator<Item = RawDenial>>(raws: I) -> AnalysisResult {
    let mut accumulator = Accumulator::analyze();
    for raw in raws {
        accumulator.add_raw_denial(raw);
        if accumulator.stop_requested {
            break;
        }
    }
    accumulator
        .into_analysis()
        .expect("pure denial accumulation cannot decode-fail")
}

/// Opens `source_path` as an ETL log file, runs `ProcessTrace` to
/// completion, and returns the decoded events.
fn process_trace_file(
    source_path: &Path,
    accumulator: &mut Accumulator<'_>,
) -> Result<(), AnalyzeError> {
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

    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { core::mem::zeroed() };
    logfile.LogFileName = PWSTR(name_wide.as_mut_ptr());
    logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.BufferCallback = Some(trace_buffer_callback);
    logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
    logfile.Context = std::ptr::from_mut(accumulator).cast();

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

    if let Some(payload) = accumulator.panic_payload.take() {
        std::panic::resume_unwind(payload);
    }

    // ERROR_SUCCESS (0) is end-of-file. ERROR_CANCELLED (1223) is expected
    // when our buffer callback stops after a processing bound or fatal error.
    if status.0 != 0 && status.0 != 1223 {
        return Err(AnalyzeError::Decode(format!(
            "ProcessTrace failed for '{}': Win32 error {}",
            source_path.display(),
            status.0
        )));
    }

    Ok(())
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
    let context = unsafe { (*event_record).UserContext } as *mut Accumulator<'_>;
    if context.is_null() {
        return;
    }

    // SAFETY: `context` is the live Accumulator we passed via Context, and
    // ProcessTrace invokes this callback synchronously on our thread, so no
    // aliasing/concurrency with the owner occurs.
    let acc = unsafe { &mut *context };
    if acc.stop_requested || acc.decode_error.is_some() || acc.panic_payload.is_some() {
        return;
    }
    if !acc.begin_event() {
        return;
    }

    run_callback_guard(acc, |acc| {
        // SAFETY: ETW supplied a valid record, and `acc` is the live callback
        // context for this synchronous ProcessTrace invocation.
        unsafe { process_event_record(event_record, acc) };
    });
}

/// Stops `ProcessTrace` after the buffer containing the event that crossed an
/// analysis bound. Returning zero is the documented cancellation signal.
unsafe extern "system" fn trace_buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    if logfile.is_null() {
        return 0;
    }
    // SAFETY: ETW passes the same live logfile and Context configured in
    // `process_trace_file`; the callback is synchronous with ProcessTrace.
    let context = unsafe { (*logfile).Context } as *mut Accumulator<'_>;
    if context.is_null() {
        return 0;
    }
    // SAFETY: `context` points to the live accumulator for this trace.
    let accumulator = unsafe { &*context };
    u32::from(
        !accumulator.stop_requested
            && accumulator.decode_error.is_none()
            && accumulator.panic_payload.is_none(),
    )
}

fn run_callback_guard(acc: &mut Accumulator<'_>, process: impl FnOnce(&mut Accumulator<'_>)) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| process(acc)));
    if let Err(payload) = result {
        acc.panic_payload = Some(payload);
    }
}

unsafe fn process_event_record(event_record: *mut EVENT_RECORD, acc: &mut Accumulator<'_>) {
    // SAFETY: ETW guarantees a valid record; we only read POD header fields.
    let header = unsafe { (*event_record).EventHeader };
    let provider = header.ProviderId;
    let event_id = header.EventDescriptor.Id;
    if matches!(acc.mode, CollectionMode::Analyze) && !is_learning_mode_event(provider, event_id) {
        return;
    }

    match unsafe { tdh_decode::decode_event_parts(event_record, &mut acc.schema_cache) } {
        Ok(parts) => match acc.mode {
            CollectionMode::Analyze => {
                if let Some(raw) = extract_denial(&parts, header.ProcessId, header.TimeStamp as u64)
                {
                    acc.add_raw_denial(raw);
                }
                for raw in crate::capability_dacl::extract_denials(
                    &parts,
                    header.ProcessId,
                    header.TimeStamp as u64,
                ) {
                    acc.add_raw_denial(raw);
                }
            }
            CollectionMode::Raw => acc.visit_raw_event(&parts),
        },
        Err(error) => acc.record_event_decode_error(provider, event_id, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mxc_alpha_learning_mode_core::{AccessType, ResourceType};

    #[test]
    fn raw_visitor_panic_is_captured_inside_callback_state() {
        let mut visitor =
            |_: &DecodedEventParts| -> std::io::Result<()> { panic!("simulated visitor panic") };
        let mut accumulator = Accumulator::raw(&mut visitor);
        let parts = DecodedEventParts {
            provider: windows::core::GUID::from_u128(0),
            event_id: 1,
            props: Vec::new(),
        };

        accumulator.visit_raw_event(&parts);

        assert!(accumulator.panic_payload.is_some());
    }

    #[test]
    fn callback_guard_captures_production_processing_panics() {
        let mut accumulator = Accumulator::analyze();
        run_callback_guard(&mut accumulator, |_| {
            panic!("simulated decoder panic");
        });

        assert!(accumulator.panic_payload.is_some());
    }

    #[test]
    fn analyze_mode_skips_malformed_event_without_failing_trace() {
        let mut accumulator = Accumulator::analyze();
        accumulator.record_event_decode_error(
            windows::core::GUID::from_u128(1),
            14,
            tdh_decode::DecodeError::Event("malformed property".to_string()),
        );

        assert!(accumulator.into_analysis().is_ok());
    }

    #[test]
    fn raw_mode_reports_malformed_event_with_context() {
        let mut visitor = |_: &DecodedEventParts| Ok(());
        let mut accumulator = Accumulator::raw(&mut visitor);
        accumulator.record_event_decode_error(
            windows::core::GUID::from_u128(1),
            14,
            tdh_decode::DecodeError::Event("malformed property".to_string()),
        );

        let error = accumulator.decode_error.as_deref().unwrap();
        assert!(error.contains("event 14"));
        assert!(error.contains("malformed property"));
    }

    #[test]
    fn analyze_mode_reports_schema_lookup_failure() {
        let mut accumulator = Accumulator::analyze();
        accumulator.record_event_decode_error(
            windows::core::GUID::from_u128(1),
            14,
            tdh_decode::DecodeError::Schema("manifest unavailable".to_string()),
        );

        let error = accumulator.into_analysis().unwrap_err();
        assert!(error.to_string().contains("manifest unavailable"));
    }

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
        let out = dedup_to_resources(denials).denials;
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
        let out = dedup_to_resources(denials).denials;
        assert_eq!(out[0].resource, r"C:\z");
        assert_eq!(out[1].resource, r"C:\a");
    }

    #[test]
    fn file_denials_require_a_canonical_user_visible_path() {
        let denials = vec![
            raw(
                r"\Device\Mup\server\share\file.txt",
                AccessType::Read,
                ResourceType::File,
            ),
            raw(
                r"\Device\UnknownVolume\file.txt",
                AccessType::Read,
                ResourceType::File,
            ),
            raw(r"\??\C:relative.txt", AccessType::Read, ResourceType::File),
            raw(r"\??\PIPE\name", AccessType::Read, ResourceType::File),
            raw(
                r"\Device\Mup\server\pipe\name",
                AccessType::Read,
                ResourceType::File,
            ),
        ];

        let out = dedup_to_resources(denials).denials;

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].resource, r"\\server\share\file.txt");
    }

    #[test]
    fn dedup_is_case_insensitive_and_preserves_first_spelling() {
        let denials = vec![
            raw(r"C:\Data\File.txt", AccessType::Read, ResourceType::File),
            raw(r"c:\data\file.TXT", AccessType::Read, ResourceType::File),
        ];
        let out = dedup_to_resources(denials).denials;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].resource, r"C:\Data\File.txt");
    }

    #[test]
    fn result_is_bounded_and_reports_truncation() {
        let denials = (0..=MAX_UNIQUE_DENIALS).map(|index| {
            raw(
                &format!(r"C:\data\{index}.txt"),
                AccessType::Read,
                ResourceType::File,
            )
        });
        let out = dedup_to_resources(denials);
        assert_eq!(out.denials.len(), MAX_UNIQUE_DENIALS);
        assert!(out.denied_resources_truncated);
    }

    #[test]
    fn unique_denial_bound_requests_trace_stop() {
        let mut accumulator = Accumulator::analyze();
        accumulator.denials = (0..MAX_UNIQUE_DENIALS)
            .map(|index| DeniedResource {
                resource: format!(r"C:\data\{index}.txt"),
                resource_type: ResourceType::File,
                access_type: AccessType::Read,
                pid: 1,
                filetime: 1,
            })
            .collect();

        accumulator.add_raw_denial(raw(
            r"C:\data\overflow.txt",
            AccessType::Read,
            ResourceType::File,
        ));

        assert!(accumulator.stop_requested);
        assert!(accumulator.truncated);
    }

    #[test]
    fn event_processing_is_bounded_and_reports_truncation() {
        let mut accumulator = Accumulator {
            processed_event_count: MAX_PROCESSED_EVENTS - 1,
            ..Accumulator::analyze()
        };

        assert!(accumulator.begin_event());
        assert!(!accumulator.begin_event());
        assert_eq!(accumulator.processed_event_count, MAX_PROCESSED_EVENTS);
        assert!(accumulator.processing_limit_reached);
        assert!(accumulator.stop_requested);
        assert!(accumulator.truncated);
    }

    #[test]
    fn analyze_missing_file_returns_open_error() {
        let analyzer = EtlDenialAnalyzer;
        let err = analyzer
            .analyze(Path::new(r"C:\does\not\exist\nope.etl"))
            .unwrap_err();
        assert!(matches!(err, AnalyzeError::Open { .. }), "got {err:?}");
    }

    #[test]
    fn fatal_analysis_error_is_reported() {
        let accumulator = Accumulator {
            decode_error: Some("trace consumer failed".to_string()),
            ..Accumulator::analyze()
        };
        let error = accumulator.into_analysis().expect_err("decode must fail");
        assert!(matches!(error, AnalyzeError::Decode(_)));
        assert!(error.to_string().contains("trace consumer failed"));
    }

    // ---- decode composition over real event shapes ------------------------
    //
    // These exercise the full `analyze` pipeline minus the OS trace read:
    // `extract_denial` routing -> path normalisation -> dedup. The events
    // mirror captures taken on hardware for both learning modes (see the
    // module/extractor docs); a live ETW/TDH read isn't used because it
    // needs the provider manifests registered on the machine.

    fn event_with_provider(
        provider: windows::core::GUID,
        event_id: u16,
        pid: u32,
        filetime: u64,
        kv: &[(&str, &str)],
    ) -> CollectedEvent {
        CollectedEvent {
            pid,
            filetime,
            parts: DecodedEventParts {
                provider,
                event_id,
                props: kv
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            },
        }
    }

    fn kernel_event(event_id: u16, pid: u32, filetime: u64, kv: &[(&str, &str)]) -> CollectedEvent {
        event_with_provider(
            crate::extractors::KERNEL_GENERAL_PROVIDER,
            event_id,
            pid,
            filetime,
            kv,
        )
    }

    fn permissive_event(
        event_id: u16,
        pid: u32,
        filetime: u64,
        kv: &[(&str, &str)],
    ) -> CollectedEvent {
        event_with_provider(
            crate::extractors::PRIVACY_LEARNING_MODE_PROVIDER,
            event_id,
            pid,
            filetime,
            kv,
        )
    }

    /// Mirrors the real `Mode="Normal"` (`block`) capture: file/registry
    /// access checks as event 14 plus a compact capability denial as event 28.
    #[test]
    fn block_shape_decodes_and_classifies() {
        let events = vec![
            // File write (DELETE | FILE_READ_DATA -> Write), \??\ prefix.
            kernel_event(
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
            kernel_event(
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
            // Capability denial (event 28) with a decoded identifier.
            kernel_event(
                28,
                0,
                12,
                &[
                    ("ProcessName", "\"conhost.exe\""),
                    ("ProcessId", "0x1acc"),
                    ("Denied", "true"),
                    ("PackageSid", "S-1-15-3-1"),
                ],
            ),
            kernel_event(27, 5480, 13, &[("Category", "2"), ("Detail", "4")]),
        ];

        let out = resources_from_events(&events).denials;
        assert_eq!(out.len(), 4);

        assert_eq!(out[0].resource, r"C:\data\test\bin\");
        assert_eq!(out[0].resource_type, ResourceType::File);
        assert_eq!(out[0].access_type, AccessType::Write);
        assert_eq!(out[0].pid, 5480);

        assert_eq!(out[1].resource, r"\REGISTRY\USER\.DEFAULT\Console");
        assert_eq!(out[1].resource_type, ResourceType::Other);
        assert_eq!(out[1].access_type, AccessType::Read);

        assert_eq!(out[2].resource, "internetClient");
        assert_eq!(out[2].resource_type, ResourceType::Capability);
        assert_eq!(out[2].access_type, AccessType::Unknown);
        assert_eq!(out[2].pid, 0x1acc, "pid from payload ProcessId");

        assert_eq!(out[3].resource, "WriteClipboard");
        assert_eq!(out[3].resource_type, ResourceType::Ui);
        assert_eq!(out[3].access_type, AccessType::Unknown);
    }

    /// Mirrors the real `Mode="Permissive"` (`allow`) capture: the same
    /// file/registry checks plus a capability check folded into an
    /// empty-`ObjectType` event 14 (there is no event 28 in this mode).
    #[test]
    fn allow_shape_recovers_capability_from_dacl() {
        // DWORD-padded allow ACE carrying S-1-15-3-1 (internetClient).
        let dacl = "hex:000000000000000001000000010200000000000F0300000001000000";
        let events = vec![
            permissive_event(
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
            permissive_event(
                14,
                5900,
                21,
                &[
                    ("Mode", "\"Permissive\""),
                    ("ObjectType", "\"\""),
                    ("ObjectName", "\"\""),
                    ("AccessMask", "0x1"),
                    ("Dacl", dacl),
                ],
            ),
            // UI violations continue to come from Kernel-General while the
            // permissive provider supplies the access-check stream.
            kernel_event(27, 2292, 22, &[("Category", "1"), ("Detail", "0")]),
        ];

        let out = resources_from_events(&events).denials;
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].resource, r"C:\data\test\bin\");
        assert_eq!(out[0].access_type, AccessType::Write);
        assert_eq!(out[1].resource, "internetClient");
        assert_eq!(out[1].resource_type, ResourceType::Capability);
        assert_eq!(out[1].pid, 5900);
        assert_eq!(out[2].resource, "ConvertToGui");
        assert_eq!(out[2].resource_type, ResourceType::Ui);
    }

    #[test]
    fn unidentified_capability_events_are_omitted() {
        let events = vec![
            kernel_event(
                14,
                1,
                1,
                &[
                    ("ObjectType", "\"\""),
                    ("ObjectName", "\"\""),
                    ("AccessMask", "0x1"),
                ],
            ),
            kernel_event(28, 0, 2, &[("ProcessId", "0x10"), ("Denied", "true")]),
            kernel_event(28, 0, 3, &[("ProcessId", "0x20"), ("Denied", "true")]),
        ];
        assert!(resources_from_events(&events).denials.is_empty());
    }

    /// Non-actionable object types and not-denied capability records are
    /// dropped by the pipeline; unknown event IDs are ignored.
    #[test]
    fn non_actionable_events_are_dropped() {
        let events = vec![
            kernel_event(14, 1, 1, &[("ObjectType", "\"Section\"")]),
            kernel_event(28, 0, 2, &[("ProcessId", "0x10"), ("Denied", "false")]),
            kernel_event(9999, 1, 3, &[("Foo", "\"bar\"")]),
        ];
        assert!(resources_from_events(&events).denials.is_empty());
    }

    #[test]
    fn provider_event_vocabulary_is_enforced_in_composition() {
        let events = vec![
            permissive_event(
                28,
                0,
                1,
                &[("Denied", "true"), ("PackageSid", "S-1-15-3-1")],
            ),
            kernel_event(
                4907,
                1,
                2,
                &[
                    ("ObjectType", "\"File\""),
                    ("ObjectName", "\"C:\\wrong-provider.txt\""),
                    ("AccessMask", "0x1"),
                ],
            ),
        ];

        assert!(resources_from_events(&events).denials.is_empty());
    }
}
