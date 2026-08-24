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
//! [`learning_mode_core::DenialAnalyzer`] trait so the runner and tests can
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

use std::collections::{HashMap, HashSet};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use learning_mode_core::{
    AnalysisResult, AnalyzeError, DenialAnalyzer, DeniedResource, ProcessLifetime,
    VerboseLoggingExclusionReason, VerboseLoggingProvider, VerboseLoggingSignature,
    VerboseLoggingSummary, MAX_VERBOSE_LOGGING_SIGNATURE_BYTES,
};
use windows::core::PWSTR;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, OpenTraceW, ProcessTrace, EVENT_RECORD, EVENT_TRACE_LOGFILEW,
    PROCESS_TRACE_MODE_EVENT_RECORD,
};

use crate::extractors::{extract_denial, is_learning_mode_event, DecodedEventParts, RawDenial};
use crate::process_lifetime::{attested_process_lifetimes, JobMembershipSnapshot};
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
    SelectForRelogging,
}

type RawEventVisitor<'a> = dyn FnMut(&DecodedEventParts) -> std::io::Result<()> + 'a;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LifetimeRange {
    start_filetime: u64,
    end_filetime: u64,
}

#[derive(Debug, Default)]
pub(crate) struct ProcessLifetimeIndex {
    ranges_by_pid: HashMap<u32, Vec<LifetimeRange>>,
}

pub(crate) struct RelogSelection {
    pub(crate) selected_event_indices: Vec<usize>,
    pub(crate) selected_event_pids: Vec<u32>,
    pub(crate) total_event_count: usize,
}

impl ProcessLifetimeIndex {
    pub(crate) fn new(process_lifetimes: &[ProcessLifetime]) -> Self {
        let mut ranges_by_pid =
            HashMap::<u32, Vec<LifetimeRange>>::with_capacity(process_lifetimes.len());
        for lifetime in process_lifetimes {
            ranges_by_pid
                .entry(lifetime.pid)
                .or_default()
                .push(LifetimeRange {
                    start_filetime: lifetime.start_filetime,
                    end_filetime: lifetime.end_filetime,
                });
        }

        for ranges in ranges_by_pid.values_mut() {
            ranges.sort_unstable_by_key(|range| range.start_filetime);
            let mut merged = Vec::<LifetimeRange>::with_capacity(ranges.len());
            for range in ranges.drain(..) {
                if let Some(previous) = merged.last_mut() {
                    if range.start_filetime <= previous.end_filetime {
                        previous.end_filetime = previous.end_filetime.max(range.end_filetime);
                        continue;
                    }
                }
                merged.push(range);
            }
            *ranges = merged;
        }

        Self { ranges_by_pid }
    }

    pub(crate) fn contains(&self, pid: u32, filetime: u64) -> bool {
        let Some(ranges) = self.ranges_by_pid.get(&pid) else {
            return false;
        };
        let candidate = ranges.partition_point(|range| range.start_filetime <= filetime);
        candidate > 0 && filetime <= ranges[candidate - 1].end_filetime
    }
}

/// Accumulates bounded analysis results or streams raw diagnostic events
/// during a `ProcessTrace` pass.
struct Accumulator<'visitor> {
    mode: CollectionMode,
    process_lifetimes: Option<ProcessLifetimeIndex>,
    denials: Vec<DeniedResource>,
    seen: HashSet<(String, learning_mode_core::AccessType)>,
    truncated: bool,
    raw_visitor: Option<&'visitor mut RawEventVisitor<'visitor>>,
    relog_selected_event_indices: Vec<usize>,
    relog_selected_event_pids: Vec<u32>,
    relog_event_count: usize,
    raw_event_count: usize,
    processed_event_count: usize,
    processing_limit_reached: bool,
    stop_requested: bool,
    decode_error: Option<String>,
    panic_payload: Option<Box<dyn std::any::Any + Send>>,
    schema_cache: tdh_decode::EventSchemaCache,
    verbose_logging: VerboseLoggingSummary,
    verbose_logging_signature_bytes: usize,
}

impl<'visitor> Accumulator<'visitor> {
    fn analyze() -> Self {
        Self {
            mode: CollectionMode::Analyze,
            process_lifetimes: None,
            denials: Vec::new(),
            seen: HashSet::new(),
            truncated: false,
            raw_visitor: None,
            relog_selected_event_indices: Vec::new(),
            relog_selected_event_pids: Vec::new(),
            relog_event_count: 0,
            raw_event_count: 0,
            processed_event_count: 0,
            processing_limit_reached: false,
            stop_requested: false,
            decode_error: None,
            panic_payload: None,
            schema_cache: tdh_decode::EventSchemaCache::default(),
            verbose_logging: VerboseLoggingSummary::default(),
            verbose_logging_signature_bytes: 0,
        }
    }

    fn analyze_for_process_lifetimes(process_lifetimes: &[ProcessLifetime]) -> Self {
        Self {
            process_lifetimes: Some(ProcessLifetimeIndex::new(process_lifetimes)),
            ..Self::analyze()
        }
    }

    fn raw(visitor: &'visitor mut RawEventVisitor<'visitor>) -> Self {
        Self {
            mode: CollectionMode::Raw,
            process_lifetimes: None,
            denials: Vec::new(),
            seen: HashSet::new(),
            truncated: false,
            raw_visitor: Some(visitor),
            relog_selected_event_indices: Vec::new(),
            relog_selected_event_pids: Vec::new(),
            relog_event_count: 0,
            raw_event_count: 0,
            processed_event_count: 0,
            processing_limit_reached: false,
            stop_requested: false,
            decode_error: None,
            panic_payload: None,
            schema_cache: tdh_decode::EventSchemaCache::default(),
            verbose_logging: VerboseLoggingSummary::default(),
            verbose_logging_signature_bytes: 0,
        }
    }

    fn select_for_relogging(process_lifetimes: &[ProcessLifetime]) -> Self {
        Self {
            mode: CollectionMode::SelectForRelogging,
            process_lifetimes: Some(ProcessLifetimeIndex::new(process_lifetimes)),
            denials: Vec::new(),
            seen: HashSet::new(),
            truncated: false,
            raw_visitor: None,
            relog_selected_event_indices: Vec::new(),
            relog_selected_event_pids: Vec::new(),
            relog_event_count: 0,
            raw_event_count: 0,
            processed_event_count: 0,
            processing_limit_reached: false,
            stop_requested: false,
            decode_error: None,
            panic_payload: None,
            schema_cache: tdh_decode::EventSchemaCache::default(),
            verbose_logging: VerboseLoggingSummary::default(),
            verbose_logging_signature_bytes: 0,
        }
    }

    fn add_raw_denial(&mut self, raw: RawDenial) {
        if !self.event_in_scope(raw.pid, raw.filetime) {
            return;
        }
        let resource = if raw.resource_type == learning_mode_core::ResourceType::File {
            match path_norm::to_user_visible(&raw.object_name) {
                Some(resource) if path_norm::is_user_visible_absolute(&resource) => resource,
                Some(candidate) => {
                    self.record_raw_denial_outcome(
                        &raw,
                        &candidate,
                        VerboseLoggingExclusionReason::UnusableResourcePath,
                    );
                    return;
                }
                None if path_norm::is_user_visible_absolute(&raw.object_name) => {
                    raw.object_name.clone()
                }
                None => {
                    let candidate = raw.object_name.clone();
                    self.record_raw_denial_outcome(
                        &raw,
                        &candidate,
                        VerboseLoggingExclusionReason::UnusableResourcePath,
                    );
                    return;
                }
            }
        } else {
            path_norm::to_user_visible(&raw.object_name).unwrap_or_else(|| raw.object_name.clone())
        };
        self.record_raw_denial_outcome(&raw, &resource, VerboseLoggingExclusionReason::Actionable);
        let dedup_resource = match raw.resource_type {
            learning_mode_core::ResourceType::File | learning_mode_core::ResourceType::Other => {
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
        // The actionable unique-denial bound is reached: keep reading (up to
        // the processed-event bound) so every remaining outcome is still
        // aggregated into the verbose logging summary, rather than stopping the
        // trace early.
        if self.denials.len() >= MAX_UNIQUE_DENIALS {
            self.truncated = true;
            self.verbose_logging.mark_actionable_limit_reached();
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

    /// Records an outcome for an already-built [`RawDenial`]. Retains the
    /// resolved resource/capability identity plus the resource/access type,
    /// redacting complete file paths and never retaining the exact
    /// `filetime`.
    fn record_raw_denial_outcome(
        &mut self,
        raw: &RawDenial,
        resource: &str,
        reason: VerboseLoggingExclusionReason,
    ) {
        let mut properties = raw
            .verbose_logging_properties
            .iter()
            .cloned()
            .collect::<std::collections::BTreeMap<_, _>>();
        let has_object_name = properties
            .keys()
            .any(|name| name.eq_ignore_ascii_case("ObjectName"));
        if raw.resource_type == learning_mode_core::ResourceType::File {
            for (name, value) in &mut properties {
                if name.eq_ignore_ascii_case("ObjectName")
                    || name.to_ascii_lowercase().contains("path")
                    || name.to_ascii_lowercase().ends_with("filename")
                {
                    *value = crate::extractors::REDACTED_PATH.to_string();
                }
            }
        }
        if !matches!(
            raw.resource_type,
            learning_mode_core::ResourceType::File | learning_mode_core::ResourceType::Other
        ) || !has_object_name
        {
            properties.insert(
                "resource".to_string(),
                if raw.resource_type == learning_mode_core::ResourceType::File {
                    crate::extractors::REDACTED_PATH.to_string()
                } else {
                    resource.to_string()
                },
            );
        }
        let properties =
            crate::extractors::bound_properties(properties.into_iter().collect::<Vec<_>>());
        self.record_outcome(
            raw.provider,
            raw.event_id,
            reason,
            raw.pid,
            (Some(raw.access_type), Some(raw.resource_type)),
            properties,
        );
    }

    /// Records one excluded outcome as a deduplicated verbose logging signature:
    /// symbolic provider, provider GUID, event ID, reason, PID, and the
    /// already-sanitized/bounded property list all identify the group;
    /// repeats of the same signature only increment its `count`.
    fn record_exclusion(
        &mut self,
        provider: VerboseLoggingProvider,
        event_id: u16,
        reason: VerboseLoggingExclusionReason,
        pid: u32,
        properties: Vec<(String, String)>,
    ) {
        self.record_outcome(provider, event_id, reason, pid, (None, None), properties);
    }

    fn record_outcome(
        &mut self,
        provider: VerboseLoggingProvider,
        event_id: u16,
        reason: VerboseLoggingExclusionReason,
        pid: u32,
        classification: (
            Option<learning_mode_core::AccessType>,
            Option<learning_mode_core::ResourceType>,
        ),
        properties: Vec<(String, String)>,
    ) {
        let (access_type, resource_type) = classification;
        let signature = VerboseLoggingSignature {
            provider,
            provider_guid: crate::extractors::verbose_logging_provider_guid(provider),
            event_id,
            reason,
            pid,
            access_type,
            resource_type,
            properties,
        };
        self.verbose_logging.record_with_byte_budget(
            signature,
            &mut self.verbose_logging_signature_bytes,
            MAX_VERBOSE_LOGGING_SIGNATURE_BYTES,
        );
    }

    fn event_in_scope(&self, pid: u32, filetime: u64) -> bool {
        self.process_lifetimes
            .as_ref()
            .is_none_or(|lifetimes| lifetimes.contains(pid, filetime))
    }

    fn begin_event(&mut self) -> bool {
        if self.processed_event_count >= MAX_PROCESSED_EVENTS {
            self.processing_limit_reached = true;
            self.truncated = true;
            self.verbose_logging.mark_processed_events_truncated();
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

    /// Handles a TDH decode failure for one event.
    ///
    /// Schema-level failures (the event's manifest itself could not be
    /// resolved) are fatal in every mode: they indicate the trace/schema
    /// state is unreliable beyond this single event. Per-event decode
    /// failures are fatal only for the raw diagnostic visitor (which needs
    /// every event to succeed); in [`CollectionMode::Analyze`] they are
    /// aggregated into the verbose logging summary for a known provider instead of
    /// silently dropped.
    fn record_event_decode_error(
        &mut self,
        provider: windows::core::GUID,
        event_id: u16,
        pid: u32,
        error: tdh_decode::DecodeError,
    ) {
        let fatal = matches!(self.mode, CollectionMode::Raw) || error.is_schema_error();
        if fatal {
            if self.decode_error.is_none() {
                self.decode_error =
                    Some(format!("provider {:?} event {event_id}: {error}", provider));
            }
            return;
        }
        if let Some(category) = crate::extractors::verbose_logging_provider_for_guid(provider) {
            let reason = match error.event_kind() {
                Some(tdh_decode::EventDecodeKind::PayloadMalformed) => {
                    VerboseLoggingExclusionReason::EventPayloadMalformed
                }
                Some(tdh_decode::EventDecodeKind::DecoderLimitReached) => {
                    VerboseLoggingExclusionReason::DecoderLimitReached
                }
                Some(tdh_decode::EventDecodeKind::UnsupportedPropertyEncoding) => {
                    VerboseLoggingExclusionReason::UnsupportedPropertyEncoding
                }
                None => return,
            };
            // Retain only the bounded schema-declared name. The free-form
            // decoder message can include property values and is never emitted.
            let properties = error
                .event_name()
                .map(|name| vec![("EventName".to_string(), name.to_string())])
                .map(crate::extractors::bound_properties)
                .unwrap_or_default();
            let classification = match event_id {
                crate::extractors::LEARNING_MODE_VIOLATION_EVENT_ID => (
                    Some(learning_mode_core::AccessType::Unknown),
                    Some(learning_mode_core::ResourceType::Ui),
                ),
                crate::extractors::CAPABILITY_DENIAL_EVENT_ID => match error.event_name() {
                    Some(name) if name.eq_ignore_ascii_case("CapabilityDenial") => (
                        Some(learning_mode_core::AccessType::Unknown),
                        Some(learning_mode_core::ResourceType::Capability),
                    ),
                    Some(name) if name.eq_ignore_ascii_case("LearningModeViolation") => (
                        Some(learning_mode_core::AccessType::Unknown),
                        Some(learning_mode_core::ResourceType::Ui),
                    ),
                    _ => (None, None),
                },
                _ => (None, None),
            };
            self.record_outcome(category, event_id, reason, pid, classification, properties);
        }
    }

    fn into_analysis(self) -> Result<AnalysisResult, AnalyzeError> {
        if let Some(error) = self.decode_error {
            return Err(AnalyzeError::Decode(error));
        }
        let mut result = AnalysisResult {
            denials: self.denials,
            denied_resources_truncated: self.truncated,
            verbose_logging: self.verbose_logging,
        };
        match result.fit_verbose_logging_within_serialized_bytes(
            crate::guarded_wpr_protocol::MAX_ANALYSIS_BYTES as usize,
        ) {
            Ok(true) => Ok(result),
            Ok(false) => Err(AnalyzeError::Decode(
                "actionable Learning Mode analysis exceeds the guarded transport limit".to_string(),
            )),
            Err(error) => Err(AnalyzeError::Decode(format!(
                "failed to size Learning Mode analysis: {error}"
            ))),
        }
    }
}

/// A [`DenialAnalyzer`] over a sealed learning-mode `.etl` file.
#[derive(Debug, Default, Clone, Copy)]
pub struct EtlDenialAnalyzer;

impl EtlDenialAnalyzer {
    /// Analyzes only events belonging to the supplied process lifetimes.
    ///
    /// This is the mandatory decode path for host-wide WPR fallback traces.
    /// An empty lifetime set intentionally yields an empty analysis rather than
    /// exposing unscoped host events.
    ///
    /// # Errors
    ///
    /// Returns [`AnalyzeError`] if the trace cannot be opened or decoded.
    pub fn analyze_for_process_lifetimes(
        &self,
        source_path: &Path,
        process_lifetimes: &[ProcessLifetime],
    ) -> Result<AnalysisResult, AnalyzeError> {
        let mut accumulator = Accumulator::analyze_for_process_lifetimes(process_lifetimes);
        process_trace_file(source_path, &mut accumulator)?;
        accumulator.into_analysis()
    }

    /// Analyzes denials only for exact process generations attested by retained
    /// handles belonging to the sandbox job.
    ///
    /// # Errors
    ///
    /// Returns [`AnalyzeError`] when job evidence is incomplete or inconsistent,
    /// or when the trace cannot be decoded.
    pub fn analyze_for_job_membership(
        &self,
        source_path: &Path,
        membership: &JobMembershipSnapshot,
    ) -> Result<AnalysisResult, AnalyzeError> {
        let process_lifetimes = attested_process_lifetimes(membership)?;
        self.analyze_for_process_lifetimes(source_path, &process_lifetimes)
    }
}

impl DenialAnalyzer for EtlDenialAnalyzer {
    fn analyze(&self, source_path: &Path) -> Result<AnalysisResult, AnalyzeError> {
        let mut accumulator = Accumulator::analyze();
        process_trace_file(source_path, &mut accumulator)?;
        accumulator.into_analysis()
    }
}

/// Runs the pure decode composition over already-collected events, using the
/// same event-classification path ([`handle_decoded_event`]) as the real ETW
/// callback: provider/vocabulary gating, extraction, capability-DACL
/// fallback, and verbose logging aggregation. Split out from
/// [`EtlDenialAnalyzer::analyze`] so it can be tested with hand-built events
/// that mirror real traces, without a live ETW/TDH read (which needs the
/// provider manifests registered on the machine).
#[cfg(test)]
fn resources_from_events(events: &[CollectedEvent]) -> AnalysisResult {
    resources_from_events_for_process_lifetimes(events, None)
}

#[cfg(test)]
fn resources_from_events_for_process_lifetimes(
    events: &[CollectedEvent],
    process_lifetimes: Option<&[ProcessLifetime]>,
) -> AnalysisResult {
    let mut accumulator = match process_lifetimes {
        Some(lifetimes) => Accumulator::analyze_for_process_lifetimes(lifetimes),
        None => Accumulator::analyze(),
    };
    accumulate_collected_events(events, &mut accumulator);
    accumulator
        .into_analysis()
        .expect("pure denial accumulation cannot decode-fail")
}

#[cfg(test)]
fn accumulate_collected_events(events: &[CollectedEvent], accumulator: &mut Accumulator<'_>) {
    for event in events {
        handle_decoded_event(&event.parts, event.pid, event.filetime, accumulator);
        if accumulator.stop_requested {
            break;
        }
    }
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
            "trace exceeded the {MAX_PROCESSED_EVENTS}-event processing limit; \
             rerun a smaller workload or split it into multiple captureDenials runs"
        )));
    }
    if let Some(error) = accumulator.decode_error {
        return Err(AnalyzeError::Decode(error));
    }
    Ok(accumulator.raw_event_count)
}

/// Builds a bounded decision vector for known-provider Learning Mode events in
/// source order. `ProcessTrace` normalizes each timestamp to FILETIME before
/// the exact process-generation test, so Trace Relogger can replay these
/// decisions without comparing its raw trace-clock timestamps.
pub(crate) fn select_learning_mode_events_for_relogging(
    source_path: &Path,
    process_lifetimes: &[ProcessLifetime],
) -> Result<RelogSelection, AnalyzeError> {
    let mut accumulator = Accumulator::select_for_relogging(process_lifetimes);
    process_trace_file(source_path, &mut accumulator)?;
    if let Some(error) = accumulator.decode_error {
        return Err(AnalyzeError::Decode(error));
    }
    Ok(RelogSelection {
        selected_event_indices: accumulator.relog_selected_event_indices,
        selected_event_pids: accumulator.relog_selected_event_pids,
        total_event_count: accumulator.relog_event_count,
    })
}

/// De-duplicates raw denials by `(user-visible resource, accessType)`,
/// normalising case-insensitive Windows file/registry identifiers while
/// preserving first-seen display spelling and order.
#[cfg(test)]
fn dedup_to_resources<I: IntoIterator<Item = RawDenial>>(raws: I) -> AnalysisResult {
    let mut accumulator = Accumulator::analyze();
    for raw in raws {
        accumulator.add_raw_denial(raw);
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

    if matches!(acc.mode, CollectionMode::SelectForRelogging) {
        if crate::extractors::verbose_logging_provider_for_guid(provider).is_none() {
            return;
        }
        let event_index = acc.relog_event_count;
        let Some(next_event_count) = acc.relog_event_count.checked_add(1) else {
            acc.decode_error =
                Some("trace contained too many Learning Mode events to index".to_string());
            acc.stop_requested = true;
            return;
        };
        acc.relog_event_count = next_event_count;
        let Some(filetime) = normalized_filetime(header.TimeStamp, acc) else {
            return;
        };
        if event_id == crate::extractors::CAPABILITY_DENIAL_EVENT_ID
            && is_learning_mode_event(provider, event_id)
        {
            let process_id = unsafe {
                tdh_decode::decode_event_property(event_record, &mut acc.schema_cache, "ProcessId")
            };
            select_capability_decode_result_for_relogging(
                acc,
                event_index,
                process_id,
                header.ProcessId,
                filetime,
            );
        } else {
            select_event_for_relogging(acc, event_index, header.ProcessId, filetime);
        }
        return;
    }

    // Establish scope before charging the event against the shared processing
    // budget. Brokered capability events are scoped after decoding their
    // effective workload PID below; all other supported events can use the
    // header PID directly.
    let mut analyze_filetime = None;

    if matches!(acc.mode, CollectionMode::Analyze) {
        let Some(category) = crate::extractors::verbose_logging_provider_for_guid(provider) else {
            // Unrelated provider: unrelated host traffic, ignored entirely
            // (not aggregated as an excluded Learning Mode outcome).
            return;
        };
        let Some(filetime) = normalized_filetime(header.TimeStamp, acc) else {
            return;
        };
        analyze_filetime = Some(filetime);
        if !is_learning_mode_event(provider, event_id) {
            if !acc.event_in_scope(header.ProcessId, filetime) || !acc.begin_event() {
                return;
            }
            // A known provider, but outside its supported event vocabulary:
            // aggregate (as a signature with no decoded properties) without
            // paying for a TDH decode.
            acc.record_exclusion(
                category,
                event_id,
                VerboseLoggingExclusionReason::UnsupportedEventSchema,
                header.ProcessId,
                Vec::new(),
            );
            return;
        }
    }

    match unsafe { tdh_decode::decode_event_parts(event_record, &mut acc.schema_cache) } {
        Ok(parts) => match acc.mode {
            CollectionMode::Analyze => {
                let filetime = analyze_filetime.expect("analyze mode has normalized FILETIME");
                handle_decoded_event(&parts, header.ProcessId, filetime, acc);
            }
            CollectionMode::Raw => {
                if acc.begin_event() {
                    acc.visit_raw_event(&parts);
                }
            }
            CollectionMode::SelectForRelogging => unreachable!("relogging returns before decode"),
        },
        Err(error) => {
            if matches!(acc.mode, CollectionMode::Analyze) {
                if error.is_schema_error() {
                    acc.record_event_decode_error(provider, event_id, header.ProcessId, error);
                    return;
                }
                let filetime = analyze_filetime.expect("analyze mode has normalized FILETIME");
                let pid = if event_id == crate::extractors::CAPABILITY_DENIAL_EVENT_ID {
                    let process_id = unsafe {
                        tdh_decode::decode_event_property(
                            event_record,
                            &mut acc.schema_cache,
                            "ProcessId",
                        )
                    }
                    .ok()
                    .flatten();
                    decode_error_effective_pid(
                        process_id.as_deref(),
                        header.ProcessId,
                        acc.event_in_scope(header.ProcessId, filetime),
                    )
                } else {
                    Some(header.ProcessId)
                };
                let Some(pid) = pid else {
                    return;
                };
                if !acc.event_in_scope(pid, filetime) || !acc.begin_event() {
                    return;
                }
                acc.record_event_decode_error(provider, event_id, pid, error);
                return;
            } else if !acc.begin_event() {
                return;
            }
            acc.record_event_decode_error(provider, event_id, header.ProcessId, error);
        }
    }
}

fn decode_error_effective_pid(
    process_id: Option<&str>,
    header_pid: u32,
    header_in_scope: bool,
) -> Option<u32> {
    crate::extractors::effective_capability_event_pid(process_id)
        .or_else(|| header_in_scope.then_some(header_pid))
}

fn select_capability_decode_result_for_relogging(
    acc: &mut Accumulator<'_>,
    event_index: usize,
    process_id: Result<Option<String>, tdh_decode::DecodeError>,
    header_pid: u32,
    filetime: u64,
) {
    match process_id {
        Ok(process_id) => select_capability_event_for_relogging(
            acc,
            event_index,
            process_id.as_deref(),
            header_pid,
            filetime,
        ),
        Err(error) if error.is_schema_error() => {
            acc.decode_error = Some(format!(
                "failed to decode brokered capability event while scoping guarded trace: {error}"
            ));
            acc.stop_requested = true;
        }
        Err(_) => {
            select_capability_event_for_relogging(acc, event_index, None, header_pid, filetime);
        }
    }
}

fn select_capability_event_for_relogging(
    acc: &mut Accumulator<'_>,
    event_index: usize,
    process_id: Option<&str>,
    header_pid: u32,
    filetime: u64,
) {
    let Some(effective_pid) = crate::extractors::effective_capability_event_pid(process_id) else {
        // The event cannot be attributed to a workload without its brokered
        // payload PID. Retain it only when the emitter itself is in scope so
        // the analysis pass can classify the malformed payload.
        select_event_for_relogging(acc, event_index, header_pid, filetime);
        return;
    };
    select_event_for_relogging(acc, event_index, effective_pid, filetime);
}

fn select_event_for_relogging(
    acc: &mut Accumulator<'_>,
    event_index: usize,
    pid: u32,
    filetime: u64,
) {
    if !acc.event_in_scope(pid, filetime) {
        return;
    }
    if acc.relog_selected_event_indices.len() >= MAX_PROCESSED_EVENTS {
        acc.decode_error = Some(format!(
            "trace exceeded the {MAX_PROCESSED_EVENTS}-event process-scoped relogging limit; \
             rerun a smaller workload or split it into multiple captureDenials runs"
        ));
        acc.stop_requested = true;
        return;
    }
    acc.relog_selected_event_indices.push(event_index);
    acc.relog_selected_event_pids.push(pid);
}

/// Extracts denials from one decoded, in-vocabulary event and feeds them
/// (or their closed exclusion reason) into `acc`.
///
/// Re-checks the provider/event vocabulary so it stays a single source of
/// truth for both the real ETW path (which gates before decoding, above)
/// and pure-composition tests that hand this already-"decoded" fixtures.
fn handle_decoded_event(
    parts: &DecodedEventParts,
    header_pid: u32,
    filetime: u64,
    acc: &mut Accumulator<'_>,
) {
    let Some(category) = crate::extractors::verbose_logging_provider_for_guid(parts.provider)
    else {
        return;
    };
    if !is_learning_mode_event(parts.provider, parts.event_id) {
        if acc.event_in_scope(header_pid, filetime) && acc.begin_event() {
            acc.record_exclusion(
                category,
                parts.event_id,
                VerboseLoggingExclusionReason::UnsupportedEventSchema,
                header_pid,
                crate::extractors::sanitize_properties(&parts.props),
            );
        }
        return;
    }
    let Some(pid) = crate::extractors::effective_event_pid(parts, header_pid) else {
        if acc.event_in_scope(header_pid, filetime) && acc.begin_event() {
            acc.record_outcome(
                category,
                parts.event_id,
                VerboseLoggingExclusionReason::EventPayloadMalformed,
                header_pid,
                crate::extractors::verbose_logging_classification(parts),
                crate::extractors::sanitize_properties(&parts.props),
            );
        }
        return;
    };
    if !acc.event_in_scope(pid, filetime) || !acc.begin_event() {
        return;
    }

    let primary = extract_denial(parts, pid, filetime);
    // Some permissive Event 14 capability checks leave `ObjectType` and
    // `ObjectName` empty. `capability_dacl::KNOWN_CAPABILITIES` defines the
    // capability names recoverable from ACE SIDs in the DACL payload. Each
    // recovered candidate is fed independently, and the primary
    // `UnresolvedCapability` outcome is counted only when none are recovered.
    let capability_candidates = crate::capability_dacl::extract_denials(parts, pid, filetime);
    for raw in capability_candidates.iter().cloned() {
        acc.add_raw_denial(raw);
    }

    match primary {
        Ok(raw) => acc.add_raw_denial(raw),
        Err(reason) => {
            let recovered_by_dacl = reason == VerboseLoggingExclusionReason::UnresolvedCapability
                && !capability_candidates.is_empty();
            if !recovered_by_dacl {
                acc.record_outcome(
                    category,
                    parts.event_id,
                    reason,
                    pid,
                    crate::extractors::verbose_logging_classification(parts),
                    crate::extractors::sanitize_properties(&parts.props),
                );
            }
        }
    }
}

fn normalized_filetime(timestamp: i64, acc: &mut Accumulator<'_>) -> Option<u64> {
    // PROCESS_TRACE_MODE_RAW_TIMESTAMP is deliberately not set, so ProcessTrace
    // has already converted the record timestamp to 100-nanosecond FILETIME.
    match u64::try_from(timestamp) {
        Ok(filetime) => Some(filetime),
        Err(_) => {
            acc.decode_error = Some(format!(
                "ETW returned a negative normalized FILETIME timestamp ({timestamp})"
            ));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use learning_mode_core::{AccessType, ResourceType};

    const SCOPED_PID: u32 = 42;
    const SCOPED_START_FILETIME: u64 = 100;
    const SCOPED_END_FILETIME: u64 = 200;
    const SCOPED_EVENT_FILETIME: u64 = 150;

    #[test]
    fn process_lifetime_index_matches_pid_and_merged_time_ranges() {
        let index = ProcessLifetimeIndex::new(&[
            ProcessLifetime {
                pid: 7,
                start_filetime: 20,
                end_filetime: 30,
            },
            ProcessLifetime {
                pid: 7,
                start_filetime: 10,
                end_filetime: 25,
            },
            ProcessLifetime {
                pid: 7,
                start_filetime: 40,
                end_filetime: 50,
            },
            ProcessLifetime {
                pid: 8,
                start_filetime: 15,
                end_filetime: 45,
            },
        ]);

        assert!(index.contains(7, 10));
        assert!(index.contains(7, 30));
        assert!(!index.contains(7, 35));
        assert!(index.contains(7, 40));
        assert!(!index.contains(7, 51));
        assert!(index.contains(8, 35));
        assert!(!index.contains(9, 20));
    }

    #[test]
    fn empty_process_lifetime_index_fails_closed() {
        let index = ProcessLifetimeIndex::new(&[]);

        assert!(!index.contains(7, 10));
    }

    #[test]
    fn relog_selection_tracks_known_provider_ordinals_and_exact_lifetimes() {
        let mut accumulator = Accumulator::select_for_relogging(&[ProcessLifetime {
            pid: 42,
            start_filetime: 100,
            end_filetime: 200,
        }]);

        let mut visit = |provider, event_id, pid, filetime| {
            // SAFETY: these fixtures avoid the brokered capability event, so
            // selection reads only the initialized POD header fields below.
            let mut record: EVENT_RECORD = unsafe { core::mem::zeroed() };
            record.EventHeader.ProviderId = provider;
            record.EventHeader.EventDescriptor.Id = event_id;
            record.EventHeader.ProcessId = pid;
            record.EventHeader.TimeStamp = filetime;
            // SAFETY: `record` remains live for this synchronous call.
            unsafe { process_event_record(&mut record, &mut accumulator) };
        };

        visit(crate::extractors::KERNEL_GENERAL_PROVIDER, 14, 42, 100);
        visit(windows::core::GUID::from_u128(1), 14, 42, 150);
        visit(crate::extractors::KERNEL_GENERAL_PROVIDER, 27, 42, 201);
        visit(crate::extractors::KERNEL_GENERAL_PROVIDER, 999, 42, 200);
        visit(crate::extractors::KERNEL_GENERAL_PROVIDER, 14, 43, 150);

        assert_eq!(accumulator.relog_event_count, 4);
        assert_eq!(accumulator.relog_selected_event_indices, [0, 2]);
        assert!(accumulator.decode_error.is_none());
    }

    #[test]
    fn relog_selection_scopes_brokered_capability_events_by_payload_pid() {
        let mut accumulator = Accumulator::select_for_relogging(&[ProcessLifetime {
            pid: 42,
            start_filetime: 100,
            end_filetime: 200,
        }]);
        select_capability_event_for_relogging(&mut accumulator, 0, Some("42"), 9000, 150);

        assert_eq!(accumulator.relog_selected_event_indices, [0]);
    }

    #[test]
    fn relog_selection_skips_unscopable_brokered_capability_without_payload_pid() {
        let mut accumulator = Accumulator::select_for_relogging(&[ProcessLifetime {
            pid: 42,
            start_filetime: 100,
            end_filetime: 200,
        }]);
        select_capability_event_for_relogging(&mut accumulator, 0, None, 9000, 150);

        assert!(accumulator.relog_selected_event_indices.is_empty());
        assert!(!accumulator.stop_requested);
        assert!(accumulator.decode_error.is_none());
    }

    #[test]
    fn relog_selection_retains_malformed_capability_from_in_scope_emitter() {
        let mut accumulator = Accumulator::select_for_relogging(&[ProcessLifetime {
            pid: 42,
            start_filetime: 100,
            end_filetime: 200,
        }]);
        select_capability_event_for_relogging(&mut accumulator, 0, None, 42, 150);

        assert_eq!(accumulator.relog_selected_event_indices, [0]);
    }

    #[test]
    fn scoped_analysis_classifies_malformed_capability_from_in_scope_emitter() {
        let mut accumulator = Accumulator::analyze_for_process_lifetimes(&[ProcessLifetime {
            pid: SCOPED_PID,
            start_filetime: SCOPED_START_FILETIME,
            end_filetime: SCOPED_END_FILETIME,
        }]);
        let parts = DecodedEventParts {
            provider: crate::extractors::KERNEL_GENERAL_PROVIDER,
            event_id: crate::extractors::CAPABILITY_DENIAL_EVENT_ID,
            props: Vec::new(),
        };

        handle_decoded_event(&parts, SCOPED_PID, SCOPED_EVENT_FILETIME, &mut accumulator);
        let analysis = accumulator.into_analysis().unwrap();

        assert_eq!(
            find_signature(
                &analysis.verbose_logging,
                crate::extractors::CAPABILITY_DENIAL_EVENT_ID
            )
            .signature
            .reason,
            VerboseLoggingExclusionReason::EventPayloadMalformed
        );
    }

    #[test]
    fn relog_selection_skips_payload_decode_failure_from_unrelated_emitter() {
        let mut accumulator = Accumulator::select_for_relogging(&[ProcessLifetime {
            pid: 42,
            start_filetime: 100,
            end_filetime: 200,
        }]);
        let error = tdh_decode::DecodeError::event(
            tdh_decode::EventDecodeKind::PayloadMalformed,
            "truncated ProcessId".to_string(),
            None,
        );

        select_capability_decode_result_for_relogging(&mut accumulator, 0, Err(error), 9000, 150);

        assert!(accumulator.relog_selected_event_indices.is_empty());
        assert!(!accumulator.stop_requested);
        assert!(accumulator.decode_error.is_none());
    }

    #[test]
    fn relog_selection_stops_on_capability_schema_failure() {
        let mut accumulator = Accumulator::select_for_relogging(&[ProcessLifetime {
            pid: 42,
            start_filetime: 100,
            end_filetime: 200,
        }]);

        select_capability_decode_result_for_relogging(
            &mut accumulator,
            0,
            Err(tdh_decode::DecodeError::Schema(
                "manifest unavailable".to_string(),
            )),
            9000,
            150,
        );

        assert!(accumulator.relog_selected_event_indices.is_empty());
        assert!(accumulator.stop_requested);
        assert!(accumulator
            .decode_error
            .as_deref()
            .is_some_and(|error| error.contains("manifest unavailable")));
    }

    #[test]
    fn capability_decode_error_prefers_payload_pid_and_fails_closed_without_scope() {
        assert_eq!(
            decode_error_effective_pid(Some("42"), 9000, false),
            Some(42)
        );
        assert_eq!(
            decode_error_effective_pid(Some("\"broker\""), 42, true),
            Some(42)
        );
        assert_eq!(
            decode_error_effective_pid(Some("\"broker\""), 9000, false),
            None
        );
        assert_eq!(decode_error_effective_pid(None, 42, true), Some(42));
        assert_eq!(decode_error_effective_pid(None, 9000, false), None);
    }

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
            1,
            tdh_decode::DecodeError::event(
                tdh_decode::EventDecodeKind::PayloadMalformed,
                "malformed property".to_string(),
                None,
            ),
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
            1,
            tdh_decode::DecodeError::event(
                tdh_decode::EventDecodeKind::PayloadMalformed,
                "malformed property".to_string(),
                None,
            ),
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
            1,
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
            provider:
                learning_mode_core::VerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode,
            verbose_logging_properties: Vec::new(),
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

        let analysis = dedup_to_resources(denials);

        assert_eq!(
            analysis
                .denials
                .first()
                .map(|denial| denial.resource.as_str()),
            Some(r"\\server\share\file.txt")
        );
        let excluded = analysis
            .verbose_logging
            .signatures
            .iter()
            .filter(|group| {
                group.signature.reason == VerboseLoggingExclusionReason::UnusableResourcePath
            })
            .collect::<Vec<_>>();
        assert_eq!(excluded.len(), 1);
        assert!(excluded.iter().all(|group| {
            group.signature.access_type == Some(AccessType::Read)
                && group.signature.resource_type == Some(ResourceType::File)
                && group.count == 4
        }));
        assert_eq!(property(&excluded[0].signature, "resource"), "<REDACTED>");
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
    fn unique_denial_bound_marks_truncated_without_stopping() {
        fn exclusion_count(
            summary: &learning_mode_core::VerboseLoggingSummary,
            provider: learning_mode_core::VerboseLoggingProvider,
            event_id: u16,
            reason: VerboseLoggingExclusionReason,
        ) -> u64 {
            summary
                .signatures
                .iter()
                .filter(|group| {
                    group.signature.provider == provider
                        && group.signature.event_id == event_id
                        && group.signature.reason == reason
                })
                .map(|group| group.count)
                .sum()
        }

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
        accumulator.seen = (0..MAX_UNIQUE_DENIALS)
            .map(|index| (format!(r"c:\data\{index}.txt"), AccessType::Read))
            .collect();

        accumulator.add_raw_denial(raw(
            r"C:\data\overflow.txt",
            AccessType::Read,
            ResourceType::File,
        ));

        assert!(
            !accumulator.stop_requested,
            "hitting the unique-denial cap must not halt the trace early"
        );
        assert!(accumulator.truncated);
        assert!(accumulator.verbose_logging.actionable_limit_reached);
        assert_eq!(
            exclusion_count(
                &accumulator.verbose_logging,
                learning_mode_core::VerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode,
                4907,
                VerboseLoggingExclusionReason::Actionable
            ),
            1
        );

        // Processing continues past the cap: a further overflow candidate is
        // still aggregated (not silently discarded), and a duplicate of an
        // already-actionable denial retains the same actionable classification.
        accumulator.add_raw_denial(raw(
            r"C:\data\overflow-2.txt",
            AccessType::Read,
            ResourceType::File,
        ));
        accumulator.add_raw_denial(raw(r"C:\data\0.txt", AccessType::Read, ResourceType::File));

        assert!(!accumulator.stop_requested);
        assert_eq!(
            exclusion_count(
                &accumulator.verbose_logging,
                learning_mode_core::VerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode,
                4907,
                VerboseLoggingExclusionReason::Actionable
            ),
            3
        );
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
    fn out_of_scope_events_are_excluded_before_consuming_the_budget() {
        let lifetimes = [ProcessLifetime {
            pid: 7,
            start_filetime: 100,
            end_filetime: 200,
        }];
        let events = [
            kernel_event(
                14,
                9,
                150,
                &[
                    ("ObjectType", "\"File\""),
                    ("ObjectName", "\"C:\\unrelated.txt\""),
                    ("AccessMask", "0x1"),
                ],
            ),
            kernel_event(
                14,
                7,
                150,
                &[
                    ("ObjectType", "\"File\""),
                    ("ObjectName", "\"C:\\owned.txt\""),
                    ("AccessMask", "0x1"),
                ],
            ),
        ];
        let mut accumulator = Accumulator {
            processed_event_count: MAX_PROCESSED_EVENTS - 1,
            ..Accumulator::analyze_for_process_lifetimes(&lifetimes)
        };

        accumulate_collected_events(&events, &mut accumulator);

        assert_eq!(accumulator.processed_event_count, MAX_PROCESSED_EVENTS);
        assert!(!accumulator.processing_limit_reached);
        assert!(!accumulator.stop_requested);
        assert_eq!(accumulator.denials.len(), 1);
        assert_eq!(accumulator.denials[0].resource, r"C:\owned.txt");
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

    /// Mirrors the real `Mode="Normal"` (`block`) capture: an actionable file
    /// check, a non-actionable registry check, and a compact capability denial.
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
            // Registry write (KEY_SET_VALUE) remains verbose-only because MXC
            // has no policy grant that could make it actionable.
            kernel_event(
                14,
                6860,
                11,
                &[
                    ("Mode", "\"Normal\""),
                    ("ObjectType", "\"Key\""),
                    ("ObjectName", "\"\\REGISTRY\\USER\\.DEFAULT\\Console\""),
                    ("AccessMask", "0x2"),
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

        let analysis = resources_from_events(&events);
        let out = &analysis.denials;
        assert_eq!(out.len(), 3);

        assert_eq!(out[0].resource, r"C:\data\test\bin\");
        assert_eq!(out[0].resource_type, ResourceType::File);
        assert_eq!(out[0].access_type, AccessType::Write);
        assert_eq!(out[0].pid, 5480);

        assert_eq!(out[1].resource, "internetClient");
        assert_eq!(out[1].resource_type, ResourceType::Capability);
        assert_eq!(out[1].access_type, AccessType::Unknown);
        assert_eq!(out[1].pid, 0x1acc, "pid from payload ProcessId");

        assert_eq!(out[2].resource, "WriteClipboard");
        assert_eq!(out[2].resource_type, ResourceType::Ui);
        assert_eq!(out[2].access_type, AccessType::Unknown);

        let registry = analysis
            .verbose_logging
            .signatures
            .iter()
            .find(|group| property(&group.signature, "ObjectType") == "Key")
            .expect("registry event should remain in verbose logging");
        assert_eq!(
            registry.signature.reason,
            VerboseLoggingExclusionReason::NotActionable
        );
        assert_eq!(registry.signature.access_type, Some(AccessType::Write));
        assert_eq!(registry.signature.resource_type, Some(ResourceType::Other));
    }

    /// Mirrors the real `Mode="Permissive"` (`allow`) capture: the same
    /// file checks plus a capability check folded into an empty-`ObjectType`
    /// event 14 (there is no event 28 in this mode).
    #[test]
    fn allow_shape_recovers_capability_from_dacl() {
        // DWORD-padded allow ACE containing the decimal SID S-1-15-3-1
        // (`internetClient`).
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
        let out = resources_from_events(&events);
        assert!(out.denials.is_empty());

        // Every dropped candidate is still aggregated by closed reason, never
        // by raw payload: one unresolved access-check event (14) plus two
        // unresolved capability denials (28). The two event-28 signatures stay
        // distinct because their retained ProcessId properties differ.
        let groups = &out.verbose_logging.signatures;
        assert_eq!(groups.len(), 3);
        let event_14_group = groups
            .iter()
            .find(|group| group.signature.event_id == 14)
            .expect("event 14 exclusion group present");
        assert_eq!(
            event_14_group.signature.provider,
            VerboseLoggingProvider::KernelGeneral
        );
        assert_eq!(
            event_14_group.signature.reason,
            VerboseLoggingExclusionReason::UnresolvedCapability
        );
        assert_eq!(event_14_group.count, 1);
        let event_28_groups = groups
            .iter()
            .filter(|group| group.signature.event_id == 28)
            .collect::<Vec<_>>();
        assert_eq!(event_28_groups.len(), 2);
        assert!(event_28_groups.iter().all(|group| {
            group.signature.provider == VerboseLoggingProvider::KernelGeneral
                && group.signature.reason == VerboseLoggingExclusionReason::UnresolvedCapability
                && group.count == 1
        }));
    }

    #[test]
    fn process_lifetimes_filter_unrelated_events_and_pid_reuse() {
        let events = vec![
            kernel_event(
                14,
                42,
                99,
                &[
                    ("ObjectType", "\"File\""),
                    ("ObjectName", "\"C:\\before.txt\""),
                    ("AccessMask", "0x1"),
                ],
            ),
            kernel_event(9999, 43, 150, &[("Marker", "\"host\"")]),
            kernel_event(9999, 42, 151, &[("Marker", "\"owned\"")]),
            kernel_event(
                14,
                42,
                150,
                &[
                    ("ObjectType", "\"File\""),
                    ("ObjectName", "\"C:\\owned.txt\""),
                    ("AccessMask", "0x1"),
                ],
            ),
            kernel_event(
                14,
                43,
                150,
                &[
                    ("ObjectType", "\"File\""),
                    ("ObjectName", "\"C:\\unrelated.txt\""),
                    ("AccessMask", "0x1"),
                ],
            ),
            kernel_event(
                14,
                42,
                201,
                &[
                    ("ObjectType", "\"File\""),
                    ("ObjectName", "\"C:\\reused-pid.txt\""),
                    ("AccessMask", "0x1"),
                ],
            ),
        ];
        let lifetimes = [ProcessLifetime {
            pid: 42,
            start_filetime: 100,
            end_filetime: 200,
        }];

        let analysis = resources_from_events_for_process_lifetimes(&events, Some(&lifetimes));

        assert_eq!(analysis.denials.len(), 1);
        assert_eq!(analysis.denials[0].resource, r"C:\owned.txt");
        assert_eq!(analysis.verbose_logging.signatures.len(), 2);
        assert!(analysis
            .verbose_logging
            .signatures
            .iter()
            .all(|group| group.signature.pid == 42));
        let unsupported = analysis
            .verbose_logging
            .signatures
            .iter()
            .find(|group| {
                group.signature.reason == VerboseLoggingExclusionReason::UnsupportedEventSchema
            })
            .expect("owned unknown event retained");
        assert_eq!(property(&unsupported.signature, "Marker"), "owned");
    }

    #[test]
    fn brokered_capability_uses_payload_pid_for_process_scope() {
        let events = vec![kernel_event(
            28,
            900,
            150,
            &[
                ("Denied", "\"true\""),
                ("ProcessId", "0x2a"),
                ("CapabilityName", "\"internetClient\""),
            ],
        )];
        let lifetimes = [ProcessLifetime {
            pid: 42,
            start_filetime: 100,
            end_filetime: 200,
        }];

        let analysis = resources_from_events_for_process_lifetimes(&events, Some(&lifetimes));

        assert_eq!(analysis.denials.len(), 1);
        assert_eq!(analysis.denials[0].pid, 42);
        assert_eq!(analysis.denials[0].resource, "internetClient");
        let group = analysis
            .verbose_logging
            .signatures
            .iter()
            .find(|group| group.signature.reason == VerboseLoggingExclusionReason::Actionable)
            .expect("actionable capability event retained");
        assert_eq!(group.signature.pid, 42);
        assert_eq!(group.signature.access_type, Some(AccessType::Unknown));
        assert_eq!(
            group.signature.resource_type,
            Some(ResourceType::Capability)
        );
    }

    #[test]
    fn empty_process_lifetimes_fail_closed() {
        let events = vec![kernel_event(
            14,
            42,
            150,
            &[
                ("ObjectType", "\"File\""),
                ("ObjectName", "\"C:\\host.txt\""),
                ("AccessMask", "0x1"),
            ],
        )];

        let analysis = resources_from_events_for_process_lifetimes(&events, Some(&[]));

        assert!(analysis.denials.is_empty());
        assert!(analysis.verbose_logging.is_empty());
    }

    /// Non-actionable object types and not-denied capability records are
    /// dropped by the pipeline as closed extraction reasons; an unknown event
    /// ID from a known provider is classified `UnsupportedEventSchema`
    /// without ever reaching TDH-decoded extraction logic.
    #[test]
    fn non_actionable_events_are_dropped() {
        let events = vec![
            kernel_event(14, 1, 1, &[("ObjectType", "\"Process\"")]),
            kernel_event(28, 0, 2, &[("ProcessId", "0x10"), ("Denied", "false")]),
            kernel_event(9999, 1, 3, &[("Foo", "\"bar\"")]),
        ];
        let out = resources_from_events(&events);
        assert!(out.denials.is_empty());

        let reason_for = |event_id: u16| {
            out.verbose_logging
                .signatures
                .iter()
                .find(|group| group.signature.event_id == event_id)
                .map(|group| group.signature.reason)
        };
        assert_eq!(
            reason_for(14),
            Some(VerboseLoggingExclusionReason::UnsupportedObjectType)
        );
        assert_eq!(
            reason_for(28),
            Some(VerboseLoggingExclusionReason::NotActionable)
        );
        assert_eq!(
            reason_for(9999),
            Some(VerboseLoggingExclusionReason::UnsupportedEventSchema)
        );
    }

    #[test]
    fn device_namespace_file_is_retained_as_unusable_resource_path() {
        let events = vec![kernel_event(
            14,
            1996,
            134_309_021_955_593_414,
            &[
                ("Mode", "\"Permissive\""),
                ("ObjectType", "\"File\""),
                ("ObjectName", "\"\\Device\\MountPointManager\""),
                ("AccessMask", "0x100080"),
            ],
        )];

        let out = resources_from_events(&events);

        assert!(out.denials.is_empty());
        assert_eq!(out.verbose_logging.signatures.len(), 1);
        let group = &out.verbose_logging.signatures[0];
        assert_eq!(group.count, 1);
        assert_eq!(
            group.signature.provider,
            VerboseLoggingProvider::KernelGeneral
        );
        assert_eq!(
            group.signature.provider_guid,
            "{A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D}"
        );
        assert_eq!(group.signature.event_id, 14);
        assert_eq!(
            group.signature.reason,
            VerboseLoggingExclusionReason::UnusableResourcePath
        );
        assert_eq!(group.signature.pid, 1996);
        assert_eq!(group.signature.access_type, Some(AccessType::Read));
        assert_eq!(group.signature.resource_type, Some(ResourceType::File));
        assert_eq!(property(&group.signature, "ObjectName"), "<REDACTED>");
    }

    #[test]
    fn output_gap_object_types_are_individually_retained() {
        let cases = [
            ("Directory", r"\BaseNamedObjects"),
            (
                "ALPC Port",
                r"\Sessions\1\AppContainerNamedObjects\S-1-15-2-1\RPC Control\ubpmtaskhostchannel",
            ),
            ("RPC Interface", "f6beaff7-1e19-4fbb-9f8f-b89e2018337c"),
        ];
        let events = cases
            .iter()
            .enumerate()
            .map(|(index, (object_type, object_name))| CollectedEvent {
                pid: 42,
                filetime: index as u64 + 1,
                parts: DecodedEventParts {
                    provider: crate::extractors::KERNEL_GENERAL_PROVIDER,
                    event_id: 14,
                    props: vec![
                        ("Mode".to_string(), "\"Permissive\"".to_string()),
                        ("ObjectType".to_string(), format!("\"{object_type}\"")),
                        ("ObjectName".to_string(), format!("\"{object_name}\"")),
                        ("AccessMask".to_string(), "0x1".to_string()),
                    ],
                },
            })
            .collect::<Vec<_>>();

        let out = resources_from_events(&events);

        assert!(out.denials.is_empty());
        assert_eq!(out.verbose_logging.signatures.len(), cases.len());
        for (object_type, object_name) in cases {
            let group = out
                .verbose_logging
                .signatures
                .iter()
                .find(|group| property(&group.signature, "ObjectType") == object_type)
                .unwrap_or_else(|| panic!("missing verbose logging signature for {object_type}"));
            assert_eq!(
                group.signature.reason,
                VerboseLoggingExclusionReason::UnsupportedObjectType
            );
            assert_eq!(property(&group.signature, "ObjectName"), object_name);
            assert_eq!(group.count, 1);
        }
    }

    #[test]
    fn long_section_names_remain_distinct_verbose_diagnostics() {
        let prefix = format!(
            r"\Sessions\1\AppContainerNamedObjects\S-1-15-2-{}\C:*ProgramData*Microsoft*Windows*Caches*",
            "1-".repeat(100)
        );
        let names = [
            format!("{prefix}{{6AF0698E-D558-4F6E-9B3C-3716689AF493}}.db"),
            format!("{prefix}{{DDF571F2-BE98-426D-8288-1A9A39C3FDA2}}.db"),
            format!("{prefix}cversions.2.ro"),
        ];
        let events = names
            .iter()
            .enumerate()
            .map(|(index, object_name)| CollectedEvent {
                pid: 42,
                filetime: index as u64 + 1,
                parts: DecodedEventParts {
                    provider: crate::extractors::KERNEL_GENERAL_PROVIDER,
                    event_id: 14,
                    props: vec![
                        ("ObjectType".to_string(), "\"Section\"".to_string()),
                        ("ObjectName".to_string(), format!("\"{object_name}\"")),
                        ("AccessMask".to_string(), "0x6".to_string()),
                    ],
                },
            })
            .collect::<Vec<_>>();

        let out = resources_from_events(&events);

        assert!(out.denials.is_empty());
        assert_eq!(out.verbose_logging.signatures.len(), names.len());
        assert!(out.verbose_logging.signatures.iter().all(|group| {
            group.signature.reason == VerboseLoggingExclusionReason::NotActionable
                && group.signature.resource_type == Some(ResourceType::Other)
                && group.signature.access_type == Some(AccessType::Write)
                && group.count == 1
                && property(&group.signature, "ObjectName").contains("<sha256=")
        }));
    }

    #[test]
    fn observed_timer_is_verbose_only_while_event_28_ui_is_actionable() {
        let events = vec![
            kernel_event(
                14,
                9576,
                1,
                &[
                    ("Mode", "\"Permissive\""),
                    ("ObjectType", "\"Timer\""),
                    (
                        "ObjectName",
                        r#""\Sessions\1\BaseNamedObjects\MXC-NS20-Time-test""#,
                    ),
                    ("AccessMask", "0x1"),
                ],
            ),
            kernel_event(
                28,
                0x1594,
                2,
                &[
                    ("ProcessName", "\"powershell.exe\""),
                    ("ProcessId", "0x1594"),
                    ("SequenceNumber", "302"),
                    ("Category", "2"),
                    ("Detail", "1"),
                    ("Denied", "false"),
                    ("UserSid", "S-1-5-21-1-2-3-1000"),
                    ("PackageSid", "S-1-15-2-1-2-3-4-5-6-7"),
                ],
            ),
        ];

        let out = resources_from_events(&events);

        assert_eq!(out.denials.len(), 1);
        assert_eq!(out.denials[0].resource, "Handles");
        assert_eq!(out.denials[0].resource_type, ResourceType::Ui);
        assert_eq!(out.denials[0].access_type, AccessType::Unknown);

        let timer = out
            .verbose_logging
            .signatures
            .iter()
            .find(|group| property(&group.signature, "ObjectType") == "Timer")
            .expect("timer should remain in verbose logging");
        assert_eq!(
            timer.signature.reason,
            VerboseLoggingExclusionReason::NotActionable
        );
        assert_eq!(timer.signature.resource_type, Some(ResourceType::Other));
        assert_eq!(timer.signature.access_type, Some(AccessType::Read));

        let ui = out
            .verbose_logging
            .signatures
            .iter()
            .find(|group| group.signature.resource_type == Some(ResourceType::Ui))
            .expect("UI denial should remain actionable");
        assert_eq!(
            ui.signature.reason,
            VerboseLoggingExclusionReason::Actionable
        );
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

        let out = resources_from_events(&events);
        assert!(out.denials.is_empty());

        // Each event ID is valid for the *other* known provider, so both are
        // classified `UnsupportedEventSchema` for their own provider rather
        // than silently ignored or misrouted.
        assert_eq!(out.verbose_logging.signatures.len(), 2);
        assert!(out
            .verbose_logging
            .signatures
            .iter()
            .all(|group| group.signature.reason
                == VerboseLoggingExclusionReason::UnsupportedEventSchema));
        assert!(out
            .verbose_logging
            .signatures
            .iter()
            .any(|group| group.signature.provider
                == VerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode
                && group.signature.event_id == 28));
        assert!(out
            .verbose_logging
            .signatures
            .iter()
            .any(
                |group| group.signature.provider == VerboseLoggingProvider::KernelGeneral
                    && group.signature.event_id == 4907
            ));
    }

    #[test]
    fn unrelated_provider_is_ignored_without_accounting() {
        // A provider outside the known Learning Mode vocabulary must not
        // contribute any verbose logging accounting at all, even though its event
        // ID happens to collide with a known access-check ID.
        let events = vec![event_with_provider(
            windows::core::GUID::from_u128(0xdead_beef),
            14,
            1,
            1,
            &[
                ("ObjectType", "\"File\""),
                ("ObjectName", "\"C:\\unrelated.txt\""),
                ("AccessMask", "0x1"),
            ],
        )];

        let out = resources_from_events(&events);
        assert!(out.denials.is_empty());
        assert!(
            out.verbose_logging.is_empty(),
            "unrelated providers are ignored, not aggregated"
        );
    }

    #[test]
    fn actionable_candidates_and_duplicates_share_one_verbose_logging_signature() {
        let make_event = |sequence_no: u64| {
            kernel_event(
                14,
                7,
                sequence_no,
                &[
                    ("ObjectType", "\"File\""),
                    ("ObjectName", "\"D:\\profiles\\jsmith\\dup.txt\""),
                    ("AccessMask", "0x1"),
                    ("UserName", "\"jsmith\""),
                ],
            )
        };
        let events = vec![make_event(1), make_event(2), make_event(3)];

        let out = resources_from_events(&events);
        assert_eq!(out.denials.len(), 1, "duplicates collapse to one denial");
        assert_eq!(
            out.denials[0].resource, r"D:\profiles\jsmith\dup.txt",
            "actionable output must retain the actionable path"
        );

        let actionable_group = out
            .verbose_logging
            .signatures
            .iter()
            .find(|group| group.signature.reason == VerboseLoggingExclusionReason::Actionable)
            .expect("actionable outcome recorded");
        assert_eq!(
            actionable_group.signature.provider,
            VerboseLoggingProvider::KernelGeneral
        );
        assert_eq!(actionable_group.signature.event_id, 14);
        assert_eq!(
            actionable_group.count, 3,
            "all three occurrences are retained"
        );
        assert_eq!(
            actionable_group.signature.access_type,
            Some(AccessType::Read)
        );
        assert_eq!(
            actionable_group.signature.resource_type,
            Some(ResourceType::File)
        );
        assert_eq!(
            property(&actionable_group.signature, "ObjectName"),
            "<REDACTED>"
        );
        assert_eq!(
            property(&actionable_group.signature, "UserName"),
            "<redacted-user>"
        );
    }

    #[test]
    fn processing_continues_past_the_unique_denial_cap_through_the_full_pipeline() {
        let overflow_candidates = 5usize;
        let events: Vec<CollectedEvent> = (0..MAX_UNIQUE_DENIALS + overflow_candidates)
            .map(|index| {
                kernel_event(
                    14,
                    1,
                    index as u64,
                    &[
                        ("ObjectType", "\"File\""),
                        ("ObjectName", &format!("\"C:\\data\\{index}.txt\"")),
                        ("AccessMask", "0x1"),
                    ],
                )
            })
            .collect();

        let out = resources_from_events(&events);

        assert_eq!(out.denials.len(), MAX_UNIQUE_DENIALS);
        assert!(out.denied_resources_truncated);
        assert!(out.verbose_logging.actionable_limit_reached);
        assert!(!out.verbose_logging.processed_events_truncated);

        // If the trace had stopped as soon as the cap was reached, only the
        // The verbose logging accounts for every denial candidate, including those
        // observed after the actionable unique-denial cap.
        assert_eq!(
            out.verbose_logging.total_occurrences,
            (MAX_UNIQUE_DENIALS + overflow_candidates) as u64
        );
    }

    #[test]
    fn capability_denial_recovered_from_dacl_records_no_exclusion() {
        // Same shape as `allow_shape_recovers_capability_from_dacl`, but
        // asserting the verbose logging side: a successfully DACL-recovered
        // capability candidate must not also surface an `UnresolvedCapability`
        // exclusion for the same event.
        let dacl = "hex:000000000000000001000000010200000000000F0300000001000000";
        let events = vec![permissive_event(
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
        )];

        let out = resources_from_events(&events);
        assert_eq!(out.denials.len(), 1);
        assert_eq!(out.denials[0].resource, "internetClient");
        assert_eq!(out.verbose_logging.signatures.len(), 1);
        let signature = &out.verbose_logging.signatures[0].signature;
        assert_eq!(signature.reason, VerboseLoggingExclusionReason::Actionable);
        assert_eq!(signature.access_type, Some(AccessType::Unknown));
        assert_eq!(signature.resource_type, Some(ResourceType::Capability));
    }

    fn find_signature(
        summary: &learning_mode_core::VerboseLoggingSummary,
        event_id: u16,
    ) -> &learning_mode_core::VerboseLoggingAggregate {
        summary
            .signatures
            .iter()
            .find(|group| group.signature.event_id == event_id)
            .unwrap_or_else(|| panic!("expected a verbose logging signature for event {event_id}"))
    }

    fn property<'a>(
        signature: &'a learning_mode_core::VerboseLoggingSignature,
        name: &str,
    ) -> &'a str {
        signature
            .properties
            .iter()
            .find(|(key, _)| key == name)
            .unwrap_or_else(|| panic!("expected property {name:?} in signature {signature:?}"))
            .1
            .as_str()
    }

    #[test]
    fn verbose_logging_byte_budget_preserves_guarded_protocol_headroom() {
        let mut accumulator = Accumulator::analyze();
        let properties = (0..crate::extractors::MAX_SIGNATURE_PROPERTIES)
            .map(|index| {
                (
                    format!("Property{index:02}"),
                    "x".repeat(crate::extractors::MAX_SIGNATURE_VALUE_LEN),
                )
            })
            .collect::<Vec<_>>();
        for pid in 0..learning_mode_core::MAX_VERBOSE_LOGGING_GROUPS as u32 {
            accumulator.record_exclusion(
                VerboseLoggingProvider::KernelGeneral,
                14,
                VerboseLoggingExclusionReason::Actionable,
                pid,
                properties.clone(),
            );
        }

        assert!(accumulator.verbose_logging.aggregate_groups_truncated);
        assert!(accumulator.verbose_logging.overflow_occurrences > 0);
        assert!(accumulator.verbose_logging_signature_bytes <= MAX_VERBOSE_LOGGING_SIGNATURE_BYTES);
    }

    #[test]
    fn unknown_event_id_signature_redacts_the_entire_file_path() {
        let events = vec![kernel_event(
            9999,
            7,
            1,
            &[("ObjectName", "\"C:\\Users\\jsmith\\secret.txt\"")],
        )];

        let out = resources_from_events(&events);

        let group = find_signature(&out.verbose_logging, 9999);
        assert_eq!(
            group.signature.reason,
            VerboseLoggingExclusionReason::UnsupportedEventSchema
        );
        assert_eq!(
            property(&group.signature, "ObjectName"),
            "<REDACTED>",
            "no part of the path may survive redaction"
        );
    }

    #[test]
    fn unresolved_capability_signature_retains_sid_pid_and_provider_guid() {
        let events = vec![kernel_event(
            28,
            42,
            1,
            &[
                ("ProcessId", "0x2A"),
                ("Denied", "true"),
                ("CandidateSid", "\"S-1-15-3-1\""),
            ],
        )];

        let out = resources_from_events(&events);

        let group = find_signature(&out.verbose_logging, 28);
        assert_eq!(
            group.signature.reason,
            VerboseLoggingExclusionReason::UnresolvedCapability
        );
        assert_eq!(
            group.signature.provider,
            VerboseLoggingProvider::KernelGeneral
        );
        assert_eq!(
            group.signature.provider_guid,
            crate::extractors::verbose_logging_provider_guid(VerboseLoggingProvider::KernelGeneral)
        );
        assert_eq!(group.signature.pid, 42, "process identifier retained");
        assert_eq!(
            property(&group.signature, "CandidateSid"),
            "S-1-15-3-1",
            "capability SIDs are retained identifiers, never redacted"
        );
    }

    #[test]
    fn signatures_with_identical_properties_dedupe_across_differing_timestamps() {
        // Same event id/pid/properties, only `filetime` differs: the
        // signature must exclude the exact timestamp so both collapse into
        // one group with an incremented count, rather than two singletons.
        let events = vec![
            kernel_event(9999, 7, 10, &[("Foo", "\"bar\"")]),
            kernel_event(9999, 7, 20_000_000, &[("Foo", "\"bar\"")]),
        ];

        let out = resources_from_events(&events);

        assert_eq!(
            out.verbose_logging.signatures.len(),
            1,
            "differing only by timestamp must dedupe to a single signature"
        );
        assert_eq!(find_signature(&out.verbose_logging, 9999).count, 2);
    }

    #[test]
    fn timestamp_like_properties_are_excluded_from_the_signature() {
        let events = vec![kernel_event(
            9999,
            7,
            1,
            &[
                ("Foo", "\"bar\""),
                ("LastWriteTime", "\"132847890123456789\""),
            ],
        )];

        let out = resources_from_events(&events);

        let group = find_signature(&out.verbose_logging, 9999);
        assert!(
            group
                .signature
                .properties
                .iter()
                .all(|(name, _)| !name.to_ascii_lowercase().contains("time")),
            "timestamp-like properties must never reach the signature: {:?}",
            group.signature.properties
        );
    }

    #[test]
    fn event_decode_failures_use_closed_reasons_and_schema_names() {
        let mut accumulator = Accumulator::analyze();
        accumulator.record_event_decode_error(
            crate::extractors::KERNEL_GENERAL_PROVIDER,
            14,
            9,
            tdh_decode::DecodeError::event(
                tdh_decode::EventDecodeKind::PayloadMalformed,
                "property payload is malformed".to_string(),
                Some("AccessCheck".to_string()),
            ),
        );
        accumulator.record_event_decode_error(
            crate::extractors::KERNEL_GENERAL_PROVIDER,
            27,
            10,
            tdh_decode::DecodeError::event(
                tdh_decode::EventDecodeKind::DecoderLimitReached,
                "property decode work exceeds limit 100000".to_string(),
                Some("LearningModeViolation".to_string()),
            ),
        );
        accumulator.record_event_decode_error(
            crate::extractors::KERNEL_GENERAL_PROVIDER,
            28,
            11,
            tdh_decode::DecodeError::event(
                tdh_decode::EventDecodeKind::UnsupportedPropertyEncoding,
                "property has unsupported variable length".to_string(),
                Some("CapabilityDenial".to_string()),
            ),
        );
        let out = accumulator
            .into_analysis()
            .expect("per-event decode failures are non-fatal in Analyze mode");

        let malformed = find_signature(&out.verbose_logging, 14);
        assert_eq!(
            malformed.signature.reason,
            VerboseLoggingExclusionReason::EventPayloadMalformed
        );
        assert_eq!(malformed.signature.pid, 9);
        assert_eq!(property(&malformed.signature, "EventName"), "AccessCheck");
        assert_eq!(
            find_signature(&out.verbose_logging, 27).signature.reason,
            VerboseLoggingExclusionReason::DecoderLimitReached
        );
        assert_eq!(
            find_signature(&out.verbose_logging, 28).signature.reason,
            VerboseLoggingExclusionReason::UnsupportedPropertyEncoding
        );
        assert_eq!(
            find_signature(&out.verbose_logging, 28)
                .signature
                .resource_type,
            Some(ResourceType::Capability)
        );
        assert!(out.verbose_logging.signatures.iter().all(|aggregate| {
            aggregate
                .signature
                .properties
                .iter()
                .all(|(name, _)| name == "EventName")
        }));
    }

    #[test]
    fn event_28_decode_failure_classification_requires_a_known_schema_name() {
        let analyze = |event_name: Option<&str>| {
            let mut accumulator = Accumulator::analyze();
            accumulator.record_event_decode_error(
                crate::extractors::KERNEL_GENERAL_PROVIDER,
                28,
                11,
                tdh_decode::DecodeError::event(
                    tdh_decode::EventDecodeKind::PayloadMalformed,
                    "property payload is malformed".to_string(),
                    event_name.map(str::to_string),
                ),
            );
            accumulator.into_analysis().unwrap()
        };

        assert_eq!(
            find_signature(&analyze(Some("CapabilityDenial")).verbose_logging, 28)
                .signature
                .resource_type,
            Some(ResourceType::Capability)
        );
        assert_eq!(
            find_signature(&analyze(Some("LearningModeViolation")).verbose_logging, 28)
                .signature
                .resource_type,
            Some(ResourceType::Ui)
        );
        assert_eq!(
            find_signature(&analyze(Some("UnknownEvent28")).verbose_logging, 28)
                .signature
                .resource_type,
            None
        );
        assert_eq!(
            find_signature(&analyze(None).verbose_logging, 28)
                .signature
                .resource_type,
            None
        );
    }
}
