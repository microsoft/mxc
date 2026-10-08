// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Sealed-ETL decoder: turns the `.etl` delivered by the Learning Mode trace API
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
//! [`crate::learning_mode_core::DenialAnalyzer`] trait so the runner and tests can
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

use crate::learning_mode_core::{
    AnalysisResult, AnalyzeError, DenialAnalyzer, DeniedResource, ProcessLifetime,
    VerboseLoggingOutcomeReason, VerboseLoggingProvider, VerboseLoggingSignature,
    VerboseLoggingSummary, MAX_VERBOSE_LOGGING_SIGNATURE_BYTES,
};
use windows::core::PWSTR;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, EventTraceGuid, OpenTraceW, ProcessTrace, EVENT_RECORD, EVENT_TRACE_LOGFILEW,
    PROCESS_TRACE_MODE_EVENT_RECORD,
};

use crate::learning_mode_windows::extractors::{
    extract_denial, is_learning_mode_event, is_process_scoped_event, DecodedEventParts, RawDenial,
};
use crate::learning_mode_windows::process_lifetime::{
    attested_process_lifetimes, JobMembershipSnapshot,
};
use crate::learning_mode_windows::{path_norm, tdh_decode};

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
    seen: HashSet<(String, crate::learning_mode_core::AccessType)>,
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
    skip_relog_header: bool,
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
            skip_relog_header: false,
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
            skip_relog_header: false,
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
            skip_relog_header: false,
        }
    }

    fn selects(&self, provider: windows::core::GUID, event_id: u16) -> bool {
        if self.process_lifetimes.is_some() {
            is_process_scoped_event(provider, event_id)
        } else {
            is_learning_mode_event(provider, event_id)
        }
    }

    fn add_raw_denial(&mut self, raw: RawDenial, event_name: Option<&str>) {
        if !self.event_in_scope(raw.pid, raw.filetime) {
            return;
        }
        let resource = if raw.resource_type == crate::learning_mode_core::ResourceType::File {
            match path_norm::to_user_visible(&raw.object_name) {
                Some(resource) if path_norm::is_user_visible_absolute(&resource) => resource,
                Some(candidate) => {
                    self.record_raw_denial_outcome(
                        &raw,
                        &candidate,
                        VerboseLoggingOutcomeReason::UnusableResourcePath,
                        event_name,
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
                        VerboseLoggingOutcomeReason::UnusableResourcePath,
                        event_name,
                    );
                    return;
                }
            }
        } else {
            path_norm::to_user_visible(&raw.object_name).unwrap_or_else(|| raw.object_name.clone())
        };
        self.record_raw_denial_outcome(
            &raw,
            &resource,
            VerboseLoggingOutcomeReason::Actionable,
            event_name,
        );
        let dedup_resource = match raw.resource_type {
            crate::learning_mode_core::ResourceType::File
            | crate::learning_mode_core::ResourceType::Other => resource.to_ascii_lowercase(),
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
        reason: VerboseLoggingOutcomeReason,
        event_name: Option<&str>,
    ) {
        let mut properties = raw
            .verbose_logging_properties
            .iter()
            .cloned()
            .collect::<std::collections::BTreeMap<_, _>>();
        let has_object_name = properties
            .keys()
            .any(|name| name.eq_ignore_ascii_case("ObjectName"));
        if raw.resource_type == crate::learning_mode_core::ResourceType::File {
            for (name, value) in &mut properties {
                if name.eq_ignore_ascii_case("ObjectName")
                    || name.to_ascii_lowercase().contains("path")
                    || name.to_ascii_lowercase().ends_with("filename")
                {
                    *value = crate::learning_mode_windows::extractors::REDACTED_PATH.to_string();
                }
            }
        }
        if !matches!(
            raw.resource_type,
            crate::learning_mode_core::ResourceType::File
                | crate::learning_mode_core::ResourceType::Other
        ) || !has_object_name
        {
            properties.insert(
                "resource".to_string(),
                if raw.resource_type == crate::learning_mode_core::ResourceType::File {
                    crate::learning_mode_windows::extractors::REDACTED_PATH.to_string()
                } else {
                    resource.to_string()
                },
            );
        }
        let properties = crate::learning_mode_windows::extractors::bound_properties(
            properties.into_iter().collect::<Vec<_>>(),
        );
        self.record_outcome(
            raw.provider,
            (raw.event_id, event_name),
            reason,
            raw.pid,
            (Some(raw.access_type), Some(raw.resource_type)),
            properties,
        );
    }

    fn record_outcome(
        &mut self,
        provider: VerboseLoggingProvider,
        event: (u16, Option<&str>),
        reason: VerboseLoggingOutcomeReason,
        pid: u32,
        classification: (
            Option<crate::learning_mode_core::AccessType>,
            Option<crate::learning_mode_core::ResourceType>,
        ),
        properties: Vec<(String, String)>,
    ) {
        let (access_type, resource_type) = classification;
        let signature = VerboseLoggingSignature {
            provider,
            provider_guid: crate::learning_mode_windows::extractors::verbose_logging_provider_guid(
                provider,
            ),
            event_id: event.0,
            event_name: crate::learning_mode_windows::extractors::sanitize_event_name(event.1),
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
    fn record_event_decode_error(
        &mut self,
        provider: windows::core::GUID,
        event_id: u16,
        pid: u32,
        error: tdh_decode::DecodeError,
    ) {
        let fatal = matches!(self.mode, CollectionMode::Raw);
        if fatal {
            if self.decode_error.is_none() {
                self.decode_error =
                    Some(format!("provider {:?} event {event_id}: {error}", provider));
            }
            return;
        }
        if !is_learning_mode_event(provider, event_id) {
            return;
        }
        let pid = if is_process_scoped_event(provider, event_id) {
            pid
        } else {
            0
        };
        let reason = match error.event_kind() {
            Some(tdh_decode::EventDecodeKind::PayloadMalformed) => {
                VerboseLoggingOutcomeReason::EventPayloadMalformed
            }
            Some(tdh_decode::EventDecodeKind::DecoderLimitReached) => {
                VerboseLoggingOutcomeReason::DecoderLimitReached
            }
            Some(tdh_decode::EventDecodeKind::UnsupportedPropertyEncoding) => {
                VerboseLoggingOutcomeReason::UnsupportedPropertyEncoding
            }
            None => VerboseLoggingOutcomeReason::SchemaUnavailable,
        };
        if reason == VerboseLoggingOutcomeReason::SchemaUnavailable
            && is_process_scoped_event(provider, event_id)
        {
            self.truncated = true;
        }
        let event = (event_id, error.event_name());
        if let Some(category) =
            crate::learning_mode_windows::extractors::verbose_logging_provider_for_guid(provider)
        {
            let classification = match event_id {
                crate::learning_mode_windows::extractors::LEARNING_MODE_VIOLATION_EVENT_ID => (
                    Some(crate::learning_mode_core::AccessType::Unknown),
                    Some(crate::learning_mode_core::ResourceType::Ui),
                ),
                crate::learning_mode_windows::extractors::CAPABILITY_DENIAL_EVENT_ID => {
                    match error.event_name() {
                        Some(name) if name.eq_ignore_ascii_case("CapabilityDenial") => (
                            Some(crate::learning_mode_core::AccessType::Unknown),
                            Some(crate::learning_mode_core::ResourceType::Capability),
                        ),
                        Some(name) if name.eq_ignore_ascii_case("LearningModeViolation") => (
                            Some(crate::learning_mode_core::AccessType::Unknown),
                            Some(crate::learning_mode_core::ResourceType::Ui),
                        ),
                        _ => (None, None),
                    }
                }
                _ => (None, None),
            };
            self.record_outcome(category, event, reason, pid, classification, Vec::new());
        }
    }

    fn into_analysis(self) -> Result<AnalysisResult, AnalyzeError> {
        if let Some(error) = self.decode_error {
            return Err(AnalyzeError::Decode(error));
        }
        if self.skip_relog_header {
            return Err(AnalyzeError::Decode(
                "relogged trace has no transport header".into(),
            ));
        }
        let mut result = AnalysisResult {
            denials: self.denials,
            denied_resources_truncated: self.truncated,
            verbose_logging: self.verbose_logging,
        };
        match result.fit_verbose_logging_within_serialized_bytes(
            crate::learning_mode_windows::guarded_wpr_protocol::MAX_ANALYSIS_BYTES as usize,
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

    pub fn analyze_relogged_for_job_membership(
        &self,
        source_path: &Path,
        membership: &JobMembershipSnapshot,
    ) -> Result<AnalysisResult, AnalyzeError> {
        let lifetimes = attested_process_lifetimes(membership)?;
        self.analyze_relogged_for_process_lifetimes(source_path, &lifetimes)
    }

    pub(crate) fn analyze_relogged_for_process_lifetimes(
        &self,
        source_path: &Path,
        lifetimes: &[ProcessLifetime],
    ) -> Result<AnalysisResult, AnalyzeError> {
        let mut accumulator = Accumulator::analyze_for_process_lifetimes(lifetimes);
        accumulator.skip_relog_header = true;
        process_trace_file(source_path, &mut accumulator)?;
        accumulator.into_analysis()
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
        accumulator.add_raw_denial(raw, None);
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
    if !process_trace_succeeded(
        status.0,
        accumulator.stop_requested || accumulator.decode_error.is_some(),
    ) {
        return Err(AnalyzeError::Decode(format!(
            "ProcessTrace failed for '{}': Win32 error {}",
            source_path.display(),
            status.0
        )));
    }

    Ok(())
}

fn process_trace_succeeded(status: u32, cancelled_by_callback: bool) -> bool {
    status == 0 || (status == 1223 && cancelled_by_callback)
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

    if acc.skip_relog_header {
        acc.skip_relog_header = false;
        if provider != EventTraceGuid || event_id != 0 || header.EventDescriptor.Opcode != 0 {
            acc.decode_error = Some("relogged trace has an invalid transport header".into());
        }
        return;
    }

    if matches!(acc.mode, CollectionMode::SelectForRelogging) {
        if !acc.selects(provider, event_id) {
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
        if event_id == crate::learning_mode_windows::extractors::CAPABILITY_DENIAL_EVENT_ID {
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

    let mut analyze_filetime = None;

    if matches!(acc.mode, CollectionMode::Analyze) {
        if !acc.selects(provider, event_id) {
            return;
        }
        let Some(filetime) = normalized_filetime(header.TimeStamp, acc) else {
            return;
        };
        analyze_filetime = Some(filetime);
        let brokered =
            event_id == crate::learning_mode_windows::extractors::CAPABILITY_DENIAL_EVENT_ID;
        if !brokered && !acc.event_in_scope(header.ProcessId, filetime) {
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
                let filetime = analyze_filetime.expect("analyze mode has normalized FILETIME");
                let pid = if event_id
                    == crate::learning_mode_windows::extractors::CAPABILITY_DENIAL_EVENT_ID
                {
                    let process_id = if matches!(
                        &error,
                        tdh_decode::DecodeError::Schema(_)
                            | tdh_decode::DecodeError::SchemaNotFound
                    ) {
                        acc.truncated = true;
                        None
                    } else {
                        unsafe {
                            tdh_decode::decode_event_property(
                                event_record,
                                &mut acc.schema_cache,
                                "ProcessId",
                            )
                        }
                        .ok()
                        .flatten()
                    };
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
    crate::learning_mode_windows::extractors::effective_capability_event_pid(process_id)
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
        Err(tdh_decode::DecodeError::Schema(_) | tdh_decode::DecodeError::SchemaNotFound) => {
            acc.decode_error =
                Some("could not scope brokered capability event: schema unavailable".into());
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
    let Some(effective_pid) =
        crate::learning_mode_windows::extractors::effective_capability_event_pid(process_id)
    else {
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
/// (or their closed outcome reason) into `acc`.
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
    if !acc.selects(parts.provider, parts.event_id) {
        return;
    }
    let event = (parts.event_id, parts.event_name.as_deref());
    let Some(category) =
        crate::learning_mode_windows::extractors::verbose_logging_provider_for_guid(parts.provider)
    else {
        return;
    };
    let Some(pid) =
        crate::learning_mode_windows::extractors::effective_event_pid(parts, header_pid)
    else {
        if acc.event_in_scope(header_pid, filetime) && acc.begin_event() {
            acc.record_outcome(
                category,
                event,
                VerboseLoggingOutcomeReason::EventPayloadMalformed,
                header_pid,
                crate::learning_mode_windows::extractors::verbose_logging_classification(parts),
                crate::learning_mode_windows::extractors::sanitize_properties(&parts.props),
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
    let capability_candidates =
        crate::learning_mode_windows::capability_dacl::extract_denials(parts, pid, filetime);
    for raw in capability_candidates.iter().cloned() {
        acc.add_raw_denial(raw, event.1);
    }

    match primary {
        Ok(raw) => acc.add_raw_denial(raw, event.1),
        Err(reason) => {
            let recovered_by_dacl = reason == VerboseLoggingOutcomeReason::UnresolvedCapability
                && !capability_candidates.is_empty();
            if !recovered_by_dacl {
                acc.record_outcome(
                    category,
                    event,
                    reason,
                    pid,
                    crate::learning_mode_windows::extractors::verbose_logging_classification(parts),
                    crate::learning_mode_windows::extractors::sanitize_properties(&parts.props),
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
    use crate::learning_mode_core::{AccessType, ResourceType};

    const SCOPED_PID: u32 = 42;
    const SCOPED_START_FILETIME: u64 = 100;
    const SCOPED_END_FILETIME: u64 = 200;
    const SCOPED_EVENT_FILETIME: u64 = 150;

    #[test]
    fn network_decision_is_retained_only_in_unscoped_native_analysis() {
        let provider = windows::core::GUID::from_u128(0x71237669_21c3_4101_bd2f_ff38945d725a);
        assert!(is_learning_mode_event(provider, 1));
        for event_id in [0, 2, 14, 28] {
            assert!(!is_learning_mode_event(provider, event_id));
        }
        assert!(!is_learning_mode_event(
            crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
            1
        ));
        let event = event_with_provider(
            provider,
            1,
            SCOPED_PID,
            SCOPED_EVENT_FILETIME,
            &[
                ("SchemaVersion", "1"),
                ("Reason", "100"),
                ("ProcessId", "42"),
                ("ApplicationId", r"C:\Users\private\app.exe"),
                ("RemoteAddress", "203.0.113.10"),
            ],
        );
        let native = resources_from_events(std::slice::from_ref(&event));
        assert!(native.denials.is_empty());
        let signature = &native.verbose_logging.signatures[0].signature;
        assert_eq!(
            signature.provider,
            VerboseLoggingProvider::LearningModeNetworkDecision
        );
        assert_eq!(
            signature.provider_guid,
            "{71237669-21C3-4101-BD2F-FF38945D725A}"
        );
        assert_eq!(signature.pid, 0);
        assert_eq!(
            signature.reason,
            VerboseLoggingOutcomeReason::UnsupportedEventSchema
        );
        assert_eq!(property(signature, "Reason"), "100");
        assert_eq!(property(signature, "ApplicationId"), "<REDACTED>");
        assert_eq!(property(signature, "RemoteAddress"), "203.0.113.10");

        let lifetimes = [ProcessLifetime {
            pid: SCOPED_PID,
            start_filetime: SCOPED_START_FILETIME,
            end_filetime: SCOPED_END_FILETIME,
        }];
        let scoped = resources_from_events_for_process_lifetimes(&[event], Some(&lifetimes));
        assert!(scoped.verbose_logging.is_empty());

        for mut accumulator in [
            Accumulator::analyze(),
            Accumulator::analyze_for_process_lifetimes(&lifetimes),
            Accumulator::select_for_relogging(&lifetimes),
        ] {
            let native = accumulator.process_lifetimes.is_none();
            let mut record = EVENT_RECORD::default();
            record.EventHeader.ProviderId = provider;
            record.EventHeader.EventDescriptor.Id = 1;
            record.EventHeader.ProcessId = SCOPED_PID;
            record.EventHeader.TimeStamp = SCOPED_EVENT_FILETIME as i64;
            let payload = 100u32.to_le_bytes();
            record.UserData = payload.as_ptr().cast_mut().cast();
            record.UserDataLength = payload.len() as u16;
            if native {
                accumulator
                    .schema_cache
                    .insert_test_schema(&record, &["Reason"]);
            }
            unsafe { process_event_record(&mut record, &mut accumulator) };
            assert_eq!(accumulator.schema_cache.schema_loads, 0);
            assert_eq!(
                accumulator.verbose_logging.total_occurrences,
                u64::from(native)
            );
            if native {
                assert_eq!(accumulator.verbose_logging.signatures[0].signature.pid, 0);
            }
            assert!(accumulator.relog_selected_event_indices.is_empty());
            assert!(!accumulator.truncated);
        }
    }

    #[test]
    fn network_decode_failure_does_not_attribute_the_broker_pid() {
        let mut accumulator = Accumulator::analyze();
        accumulator.record_event_decode_error(
            windows::core::GUID::from_u128(0x71237669_21c3_4101_bd2f_ff38945d725a),
            1,
            SCOPED_PID,
            tdh_decode::DecodeError::event(
                tdh_decode::EventDecodeKind::PayloadMalformed,
                "malformed network event".into(),
                Some("NetworkDecisionV1".into()),
            ),
        );
        let group = &accumulator.verbose_logging.signatures[0];
        assert_eq!(group.signature.pid, 0);
        assert_eq!(
            group.signature.event_name.as_deref(),
            Some("NetworkDecisionV1")
        );
        assert_eq!(
            group.signature.reason,
            VerboseLoggingOutcomeReason::EventPayloadMalformed
        );
    }

    #[test]
    fn callback_selects_only_learning_mode_events_before_decoding() {
        let kernel = crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER;
        let privacy = crate::learning_mode_windows::extractors::PRIVACY_LEARNING_MODE_PROVIDER;
        for (provider, event_id, retained) in [
            (kernel, 14, true),
            (kernel, 27, true),
            (kernel, 28, true),
            (privacy, 14, true),
            (privacy, 27, true),
            (privacy, 4907, true),
            (kernel, 4907, false),
            (privacy, 28, false),
            (kernel, 999, false),
            (windows::core::GUID::from_u128(1), 14, false),
            (
                windows::core::GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c),
                0,
                false,
            ),
        ] {
            let lifetime = ProcessLifetime {
                pid: SCOPED_PID,
                start_filetime: SCOPED_START_FILETIME,
                end_filetime: SCOPED_END_FILETIME,
            };
            for mut accumulator in [
                Accumulator::analyze(),
                Accumulator::analyze_for_process_lifetimes(&[lifetime]),
            ] {
                let mut record = EVENT_RECORD::default();
                record.EventHeader.ProviderId = provider;
                record.EventHeader.EventDescriptor.Id = event_id;
                record.EventHeader.ProcessId = SCOPED_PID;
                record.EventHeader.TimeStamp = SCOPED_EVENT_FILETIME as i64;
                let payload = SCOPED_PID.to_le_bytes();
                record.UserData = payload.as_ptr().cast_mut().cast();
                record.UserDataLength = payload.len() as u16;
                if retained {
                    accumulator
                        .schema_cache
                        .insert_test_schema(&record, &["ProcessId"]);
                }
                unsafe { process_event_record(&mut record, &mut accumulator) };
                assert_eq!(
                    accumulator.schema_cache.schema_loads, 0,
                    "{provider:?} {event_id}"
                );
                assert_eq!(accumulator.processed_event_count, usize::from(retained));
                let analysis = accumulator.into_analysis().unwrap();
                assert_eq!(
                    analysis.verbose_logging.total_occurrences,
                    u64::from(retained)
                );
                assert!(!analysis.denied_resources_truncated);
            }
        }
    }

    #[test]
    fn raw_visitor_preserves_runtime_metadata() {
        let mut visitor = |_: &DecodedEventParts| Ok(());
        let mut accumulator = Accumulator::raw(&mut visitor);
        let mut record = EVENT_RECORD::default();
        record.EventHeader.ProviderId =
            windows::core::GUID::from_u128(0x2cb15d1d_5fc1_11d2_abe1_00a0c911f518);
        accumulator
            .schema_cache
            .insert_test_schema(&record, &["FutureValue"]);

        unsafe { process_event_record(&mut record, &mut accumulator) };

        assert_eq!(accumulator.raw_event_count, 1);
        assert!(accumulator.decode_error.is_none());
    }

    #[test]
    fn selected_access_checks_do_not_filter_object_types() {
        for (provider, event_id) in [
            (
                crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
                14,
            ),
            (
                crate::learning_mode_windows::extractors::PRIVACY_LEARNING_MODE_PROVIDER,
                4907,
            ),
        ] {
            for object_type in ["Dll", "Thread", "Process", "FutureObject"] {
                let event = event_with_provider(
                    provider,
                    event_id,
                    SCOPED_PID,
                    SCOPED_EVENT_FILETIME,
                    &[
                        ("ObjectType", object_type),
                        ("ObjectName", "retained-identifier"),
                    ],
                );
                let analysis = resources_from_events(&[event]);
                assert!(analysis.denials.is_empty());
                let signature = &find_signature(&analysis.verbose_logging, event_id).signature;
                assert_eq!(
                    signature.reason,
                    VerboseLoggingOutcomeReason::UnsupportedObjectType
                );
                assert_eq!(property(signature, "ObjectType"), object_type);
                assert_eq!(property(signature, "ObjectName"), "retained-identifier");
            }
        }
    }

    #[test]
    fn callback_keeps_unknown_resources_and_deduplicates_decode_failures() {
        let mut accumulator = Accumulator::analyze();
        let payload = 42u32.to_le_bytes();
        for (provider, event_id, names) in [
            (
                crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
                14,
                Some(vec!["ObjectType"]),
            ),
            (
                crate::learning_mode_windows::extractors::PRIVACY_LEARNING_MODE_PROVIDER,
                4907,
                Some(vec!["ObjectType"]),
            ),
            (
                crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
                27,
                Some(vec!["First", "Missing"]),
            ),
            (
                crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
                28,
                None,
            ),
        ] {
            for time in [100, 200] {
                let mut record = EVENT_RECORD::default();
                record.EventHeader.ProviderId = provider;
                record.EventHeader.EventDescriptor.Id = event_id;
                record.EventHeader.EventDescriptor.Version = u8::MAX;
                record.EventHeader.ProcessId = 42;
                record.EventHeader.TimeStamp = time;
                record.UserData = payload.as_ptr().cast_mut().cast();
                record.UserDataLength = payload.len() as u16;
                if let Some(names) = &names {
                    accumulator.schema_cache.insert_test_schema(&record, names);
                }
                unsafe { process_event_record(&mut record, &mut accumulator) };
            }
        }
        let analysis = accumulator.into_analysis().unwrap();
        let groups = &analysis.verbose_logging.signatures;
        assert_eq!(analysis.verbose_logging.total_occurrences, 8);
        assert_eq!(groups.len(), 4);
        assert!(groups.iter().all(|group| group.count == 2));
        let decoded = groups
            .iter()
            .filter(|group| {
                group.signature.reason == VerboseLoggingOutcomeReason::UnsupportedObjectType
            })
            .collect::<Vec<_>>();
        assert_eq!(decoded.len(), 2);
        assert!(decoded
            .iter()
            .all(|group| property(&group.signature, "ObjectType") == "42"));
        for reason in [
            VerboseLoggingOutcomeReason::EventPayloadMalformed,
            VerboseLoggingOutcomeReason::SchemaUnavailable,
        ] {
            let group = groups
                .iter()
                .find(|group| group.signature.reason == reason)
                .unwrap();
            assert!(group.signature.properties.is_empty());
            assert_eq!(
                group.signature.provider,
                VerboseLoggingProvider::KernelGeneral
            );
        }
        assert!(analysis.denials.is_empty());
    }

    #[test]
    fn unknown_resource_dedup_preserves_provider_identity_and_process_scope() {
        let properties = [
            ("ObjectType", "FutureObject"),
            ("ObjectName", "future-resource"),
            ("ProcessId", "99"),
        ];
        let first = crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER;
        let second = crate::learning_mode_windows::extractors::PRIVACY_LEARNING_MODE_PROVIDER;
        let events = [
            event_with_provider(first, 14, 42, 150, &properties),
            event_with_provider(first, 14, 42, 151, &properties),
            event_with_provider(second, 14, 42, 152, &properties),
            event_with_provider(second, 4907, 42, 153, &properties),
            event_with_provider(first, 14, 99, 150, &[("ProcessId", "42")]),
            event_with_provider(first, 14, 42, 201, &properties),
            kernel_event(
                14,
                42,
                160,
                &[
                    ("ObjectType", "File"),
                    ("ObjectName", r"C:\kept.txt"),
                    ("AccessMask", "1"),
                ],
            ),
        ];
        let analysis = resources_from_events_for_process_lifetimes(
            &events,
            Some(&[ProcessLifetime {
                pid: 42,
                start_filetime: 100,
                end_filetime: 200,
            }]),
        );
        let groups = &analysis.verbose_logging.signatures;
        assert_eq!(groups.len(), 4);
        assert_eq!(analysis.verbose_logging.total_occurrences, 5);
        let repeated = groups
            .iter()
            .find(|group| {
                group.signature.provider_guid
                    == crate::learning_mode_windows::extractors::format_guid_braced_uppercase(first)
                    && group.signature.reason == VerboseLoggingOutcomeReason::UnsupportedObjectType
            })
            .unwrap();
        assert_eq!(repeated.count, 2);
        assert_eq!(repeated.signature.pid, 42);
        let expected = vec![DeniedResource {
            resource: r"C:\kept.txt".into(),
            resource_type: ResourceType::File,
            access_type: AccessType::Read,
            pid: 42,
            filetime: 160,
        }];
        let serialize = |denials| {
            let mut bytes = Vec::new();
            crate::learning_mode_core::write_document(
                &mut bytes,
                &crate::learning_mode_core::DenialsDocument::new(
                    denials,
                    crate::learning_mode_core::DenialSummary::new(0, 1, false),
                ),
            )
            .unwrap();
            bytes
        };
        assert_eq!(serialize(analysis.denials), serialize(expected));
    }

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

        visit(
            crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
            14,
            42,
            100,
        );
        visit(windows::core::GUID::from_u128(1), 14, 42, 150);
        visit(
            crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
            27,
            42,
            201,
        );
        visit(
            crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
            999,
            42,
            200,
        );
        visit(
            crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
            14,
            43,
            150,
        );
        visit(
            windows::core::GUID::from_u128(0x2cb15d1d_5fc1_11d2_abe1_00a0c911f518),
            0,
            42,
            150,
        );
        visit(EventTraceGuid, 0, 42, 150);
        visit(
            windows::core::GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c),
            0,
            42,
            150,
        );
        visit(windows::core::GUID::from_u128(1), 18, 42, 150);
        visit(
            windows::core::GUID::from_u128(0xb675ec37_bdb6_4648_bc92_f3fdc74d3ca2),
            18,
            42,
            150,
        );
        visit(
            windows::core::GUID::from_u128(0xb675ec37_bdb6_4648_bc92_f3fdc74d3ca2),
            19,
            42,
            150,
        );

        assert_eq!(accumulator.relog_event_count, 3);
        assert_eq!(accumulator.relog_selected_event_indices, [0]);
        assert!(accumulator.decode_error.is_none());
    }

    #[test]
    fn relogged_analysis_requires_a_valid_transport_header() {
        for (provider, event_id, valid) in [
            (EventTraceGuid, 0, true),
            (
                crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
                14,
                false,
            ),
        ] {
            let mut accumulator = Accumulator::analyze_for_process_lifetimes(&[]);
            accumulator.skip_relog_header = true;
            let mut record = EVENT_RECORD::default();
            record.EventHeader.ProviderId = provider;
            record.EventHeader.EventDescriptor.Id = event_id;
            unsafe { process_event_record(&mut record, &mut accumulator) };
            assert_eq!(accumulator.into_analysis().is_ok(), valid);
        }
        let mut absent = Accumulator::analyze_for_process_lifetimes(&[]);
        absent.skip_relog_header = true;
        assert!(absent.into_analysis().is_err());
    }

    #[test]
    fn process_trace_cancellation_succeeds_only_when_requested() {
        assert!(process_trace_succeeded(0, false));
        assert!(process_trace_succeeded(1223, true));
        assert!(!process_trace_succeeded(1223, false));
        assert!(!process_trace_succeeded(5, true));
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
            provider: crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
            event_name: None,
            event_id: crate::learning_mode_windows::extractors::CAPABILITY_DENIAL_EVENT_ID,
            props: Vec::new(),
        };

        handle_decoded_event(&parts, SCOPED_PID, SCOPED_EVENT_FILETIME, &mut accumulator);
        let analysis = accumulator.into_analysis().unwrap();

        assert_eq!(
            find_signature(
                &analysis.verbose_logging,
                crate::learning_mode_windows::extractors::CAPABILITY_DENIAL_EVENT_ID
            )
            .signature
            .reason,
            VerboseLoggingOutcomeReason::EventPayloadMalformed
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
    fn brokered_schema_failure_marks_incomplete_before_pid_resolution() {
        for (provider, event_id, incomplete) in [
            (
                crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
                28,
                true,
            ),
            (
                crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
                14,
                false,
            ),
            (
                crate::learning_mode_windows::extractors::PRIVACY_LEARNING_MODE_PROVIDER,
                28,
                false,
            ),
            (windows::core::GUID::from_u128(1), 28, false),
        ] {
            let mut accumulator = Accumulator::analyze_for_process_lifetimes(&[ProcessLifetime {
                pid: 42,
                start_filetime: 100,
                end_filetime: 200,
            }]);
            let mut record = EVENT_RECORD::default();
            record.EventHeader.ProviderId = provider;
            record.EventHeader.EventDescriptor.Id = event_id;
            record.EventHeader.EventDescriptor.Version = u8::MAX;
            record.EventHeader.ProcessId = 9000;
            record.EventHeader.TimeStamp = 150;
            if incomplete {
                for id in 0..4096 {
                    let mut cached = EVENT_RECORD::default();
                    cached.EventHeader.EventDescriptor.Id = id;
                    accumulator
                        .schema_cache
                        .insert_test_schema(&cached, &["ProcessId"]);
                }
                assert!(matches!(
                    unsafe {
                        tdh_decode::decode_event_parts(&mut record, &mut accumulator.schema_cache)
                    },
                    Err(tdh_decode::DecodeError::Schema(_)
                        | tdh_decode::DecodeError::SchemaNotFound)
                ));
            }
            let schema_loads = accumulator.schema_cache.schema_loads;
            unsafe { process_event_record(&mut record, &mut accumulator) };
            assert_eq!(
                accumulator.schema_cache.schema_loads - schema_loads,
                usize::from(incomplete)
            );
            assert_eq!(accumulator.truncated, incomplete);
            assert!(accumulator.verbose_logging.is_empty());
            assert!(!accumulator.stop_requested);
            assert!(accumulator.decode_error.is_none());

            let valid = kernel_event(
                14,
                42,
                160,
                &[
                    ("ObjectType", "File"),
                    ("ObjectName", r"C:\kept.txt"),
                    ("AccessMask", "1"),
                ],
            );
            handle_decoded_event(&valid.parts, valid.pid, valid.filetime, &mut accumulator);
            let analysis = accumulator.into_analysis().unwrap();
            assert_eq!(analysis.denied_resources_truncated, incomplete);
            assert_eq!(analysis.denials.len(), 1);
            assert_eq!(analysis.denials[0].resource, r"C:\kept.txt");
            assert_eq!(analysis.verbose_logging.total_occurrences, 1);
        }
    }

    #[test]
    fn relog_selection_rejects_unattributable_capability_schema_failure() {
        let mut accumulator = Accumulator::select_for_relogging(&[ProcessLifetime {
            pid: 42,
            start_filetime: 100,
            end_filetime: 200,
        }]);
        let mut record = EVENT_RECORD::default();
        record.EventHeader.ProviderId =
            crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER;
        record.EventHeader.EventDescriptor.Id =
            crate::learning_mode_windows::extractors::CAPABILITY_DENIAL_EVENT_ID;
        record.EventHeader.EventDescriptor.Version = u8::MAX;
        record.EventHeader.ProcessId = 9000;
        record.EventHeader.TimeStamp = 150;
        unsafe { process_event_record(&mut record, &mut accumulator) };

        assert!(accumulator.relog_selected_event_indices.is_empty());
        assert!(accumulator.relog_selected_event_pids.is_empty());
        assert!(accumulator.verbose_logging.is_empty());
        assert!(accumulator.stop_requested);
        assert_eq!(
            accumulator.decode_error.as_deref(),
            Some("could not scope brokered capability event: schema unavailable")
        );
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
            event_name: None,
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
            crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
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
    fn analyze_mode_records_schema_lookup_failure_without_aborting() {
        let mut accumulator = Accumulator::analyze();
        accumulator.record_event_decode_error(
            crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
            14,
            1,
            tdh_decode::DecodeError::Schema("manifest unavailable".to_string()),
        );

        let analysis = accumulator.into_analysis().unwrap();
        let group = &analysis.verbose_logging.signatures[0];
        assert_eq!(
            group.signature.reason,
            VerboseLoggingOutcomeReason::SchemaUnavailable
        );
        assert!(group.signature.properties.is_empty());
        assert_eq!(group.count, 1);
        let mut bytes = Vec::new();
        crate::learning_mode_core::write_verbose_logging_document(
            &mut bytes,
            &crate::learning_mode_core::VerboseLoggingDocument::new(&analysis.verbose_logging),
        )
        .unwrap();
        assert!(!String::from_utf8(bytes)
            .unwrap()
            .contains("manifest unavailable"));
    }

    #[test]
    fn schema_failure_completeness_follows_the_supported_event_vocabulary() {
        let kernel = crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER;
        let privacy = crate::learning_mode_windows::extractors::PRIVACY_LEARNING_MODE_PROVIDER;
        for (provider, event_id, retained, incomplete) in [
            (kernel, 14, true, true),
            (kernel, 27, true, true),
            (kernel, 28, true, true),
            (privacy, 14, true, true),
            (privacy, 27, true, true),
            (privacy, 4907, true, true),
            (
                crate::learning_mode_windows::extractors::NETWORK_DECISION_PROVIDER,
                1,
                true,
                false,
            ),
            (kernel, 999, false, false),
            (privacy, 28, false, false),
            (windows::core::GUID::from_u128(1), 14, false, false),
        ] {
            let mut accumulator = Accumulator::analyze();
            accumulator.record_event_decode_error(
                provider,
                event_id,
                42,
                tdh_decode::DecodeError::Schema("manifest unavailable".into()),
            );
            let event = kernel_event(
                14,
                42,
                150,
                &[
                    ("ObjectType", "File"),
                    ("ObjectName", r"C:\kept.txt"),
                    ("AccessMask", "1"),
                ],
            );
            handle_decoded_event(&event.parts, event.pid, event.filetime, &mut accumulator);
            let analysis = accumulator.into_analysis().unwrap();
            assert_eq!(
                analysis.denied_resources_truncated, incomplete,
                "{provider:?} {event_id}"
            );
            assert_eq!(analysis.denials.len(), 1);
            assert_eq!(analysis.denials[0].resource, r"C:\kept.txt");
            assert_eq!(
                analysis.verbose_logging.total_occurrences,
                1 + u64::from(retained)
            );
            assert_eq!(
                analysis.verbose_logging.signatures.iter().any(|group| {
                    group.signature.reason == VerboseLoggingOutcomeReason::SchemaUnavailable
                }),
                retained
            );
            let mut bytes = Vec::new();
            let summary = crate::learning_mode_core::DenialSummary::new(
                0,
                analysis.denials.len(),
                analysis.denied_resources_truncated,
            );
            crate::learning_mode_core::write_document(
                &mut bytes,
                &crate::learning_mode_core::DenialsDocument::new(analysis.denials, summary),
            )
            .unwrap();
            assert!(String::from_utf8(bytes)
                .unwrap()
                .contains(&format!("\"deniedResourcesTruncated\": {incomplete}")));
        }
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
                crate::learning_mode_core::VerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode,
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
                group.signature.reason == VerboseLoggingOutcomeReason::UnusableResourcePath
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
            summary: &crate::learning_mode_core::VerboseLoggingSummary,
            provider: crate::learning_mode_core::VerboseLoggingProvider,
            event_id: u16,
            reason: VerboseLoggingOutcomeReason,
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

        accumulator.add_raw_denial(
            raw(
                r"C:\data\overflow.txt",
                AccessType::Read,
                ResourceType::File,
            ),
            None,
        );

        assert!(
            !accumulator.stop_requested,
            "hitting the unique-denial cap must not halt the trace early"
        );
        assert!(accumulator.truncated);
        assert!(accumulator.verbose_logging.actionable_limit_reached);
        assert_eq!(
            exclusion_count(
                &accumulator.verbose_logging,
                crate::learning_mode_core::VerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode,
                4907,
                VerboseLoggingOutcomeReason::Actionable
            ),
            1
        );

        // Processing continues past the cap: a further overflow candidate is
        // still aggregated (not silently discarded), and a duplicate of an
        // already-actionable denial retains the same actionable classification.
        accumulator.add_raw_denial(
            raw(
                r"C:\data\overflow-2.txt",
                AccessType::Read,
                ResourceType::File,
            ),
            None,
        );
        accumulator.add_raw_denial(
            raw(r"C:\data\0.txt", AccessType::Read, ResourceType::File),
            None,
        );

        assert!(!accumulator.stop_requested);
        assert_eq!(
            exclusion_count(
                &accumulator.verbose_logging,
                crate::learning_mode_core::VerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode,
                4907,
                VerboseLoggingOutcomeReason::Actionable
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
                event_name: None,
                props: kv
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            },
        }
    }

    fn kernel_event(event_id: u16, pid: u32, filetime: u64, kv: &[(&str, &str)]) -> CollectedEvent {
        event_with_provider(
            crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
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
            crate::learning_mode_windows::extractors::PRIVACY_LEARNING_MODE_PROVIDER,
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
            // A registry check without a usable access mask remains
            // verbose-only because it cannot be positively classified as a
            // read.
            kernel_event(
                14,
                6860,
                11,
                &[
                    ("Mode", "\"Normal\""),
                    ("ObjectType", "\"Key\""),
                    ("ObjectName", "\"\\REGISTRY\\USER\\.DEFAULT\\Console\""),
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
            VerboseLoggingOutcomeReason::NotActionable
        );
        assert_eq!(registry.signature.access_type, Some(AccessType::Unknown));
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
    fn com_access_checks_are_distinct_verbose_only_outcomes_in_both_modes() {
        let activation_clsid = "{A47979D2-C419-11D9-A5B4-001185AD2B89}";
        let call_iid = "{00000132-0000-0000-C000-000000000046}";
        let events = vec![
            kernel_event(
                14,
                100,
                1,
                &[
                    ("Mode", "\"Normal\""),
                    ("ObjectType", "\"ComActivationForClass\""),
                    ("ObjectName", activation_clsid),
                    ("AccessMask", "0x1"),
                ],
            ),
            permissive_event(
                14,
                101,
                2,
                &[
                    ("Mode", "\"Permissive\""),
                    ("ObjectType", "\"ComActivationForClass\""),
                    ("ObjectName", "\"{a47979d2-c419-11d9-a5b4-001185ad2b89}\""),
                    ("AccessMask", "0xffffffff"),
                ],
            ),
            permissive_event(
                4907,
                102,
                3,
                &[
                    ("Mode", "\"Permissive\""),
                    ("ObjectType", "\"ComCallOnInterface\""),
                    ("ObjectName", call_iid),
                    ("AccessMask", "0x2"),
                ],
            ),
        ];

        let analysis = resources_from_events(&events);

        assert!(analysis.denials.is_empty());
        let activation_signatures = analysis
            .verbose_logging
            .signatures
            .iter()
            .filter(|group| property(&group.signature, "ObjectType") == "ComActivationForClass")
            .collect::<Vec<_>>();
        assert_eq!(activation_signatures.len(), 2);
        assert!(activation_signatures.iter().all(|group| {
            group.signature.reason == VerboseLoggingOutcomeReason::ComActivation
                && group.signature.resource_type == Some(ResourceType::Other)
                && group.signature.access_type.is_none()
                && group.count == 1
        }));
        assert!(activation_signatures
            .iter()
            .any(|group| property(&group.signature, "ObjectName") == activation_clsid));
        assert!(activation_signatures.iter().any(|group| {
            group.signature.provider
                == VerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode
        }));

        let call = analysis
            .verbose_logging
            .signatures
            .iter()
            .find(|group| property(&group.signature, "ObjectType") == "ComCallOnInterface")
            .expect("COM interface call should remain in verbose logging");
        assert_eq!(
            call.signature.reason,
            VerboseLoggingOutcomeReason::ComInterfaceCall
        );
        assert_eq!(
            call.signature.provider,
            VerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode
        );
        assert_eq!(call.signature.event_id, 4907);
        assert_eq!(call.signature.resource_type, Some(ResourceType::Other));
        assert!(call.signature.access_type.is_none());
        assert_eq!(property(&call.signature, "ObjectName"), call_iid);
    }

    #[test]
    fn com_checks_do_not_change_actionable_output() {
        let file = || {
            kernel_event(
                14,
                100,
                2,
                &[
                    ("ObjectType", "\"File\""),
                    ("ObjectName", r"C:\kept.txt"),
                    ("AccessMask", "0x1"),
                ],
            )
        };
        let com = |filetime| {
            kernel_event(
                14,
                100,
                filetime,
                &[
                    ("ObjectType", "\"ComActivationForClass\""),
                    ("ObjectName", "{A47979D2-C419-11D9-A5B4-001185AD2B89}"),
                ],
            )
        };

        let without = resources_from_events(&[file()]);
        let with = resources_from_events(&[com(1), file(), com(3)]);

        assert_eq!(without.denials.len(), 1);
        assert_eq!(with.denials, without.denials);
        assert_eq!(
            with.verbose_logging.signatures.len(),
            without.verbose_logging.signatures.len() + 1
        );
        assert_eq!(
            with.verbose_logging.total_occurrences,
            without.verbose_logging.total_occurrences + 2
        );
    }

    #[test]
    fn malformed_com_identifier_remains_classified_verbose_diagnostic() {
        for object_name in [r"C:\Users\alice\secret.txt", "alice@example.com"] {
            let events = vec![kernel_event(
                14,
                42,
                1,
                &[
                    ("Mode", "\"Normal\""),
                    ("ObjectType", "\"ComActivationForClass\""),
                    ("ObjectName", object_name),
                    ("AccessMask", "0x1"),
                ],
            )];

            let analysis = resources_from_events(&events);

            assert!(analysis.denials.is_empty());
            assert_eq!(analysis.verbose_logging.signatures.len(), 1);
            let signature = &analysis.verbose_logging.signatures[0].signature;
            assert_eq!(
                signature.reason,
                VerboseLoggingOutcomeReason::EventPayloadMalformed
            );
            assert_eq!(signature.resource_type, Some(ResourceType::Other));
            assert!(signature.access_type.is_none());
            assert_eq!(property(signature, "ObjectType"), "ComActivationForClass");
            assert_eq!(
                property(signature, "ObjectName"),
                crate::learning_mode_windows::extractors::REDACTED_PATH
            );
        }
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
            VerboseLoggingOutcomeReason::UnresolvedCapability
        );
        assert_eq!(event_14_group.count, 1);
        let event_28_groups = groups
            .iter()
            .filter(|group| group.signature.event_id == 28)
            .collect::<Vec<_>>();
        assert_eq!(event_28_groups.len(), 2);
        assert!(event_28_groups.iter().all(|group| {
            group.signature.provider == VerboseLoggingProvider::KernelGeneral
                && group.signature.reason == VerboseLoggingOutcomeReason::UnresolvedCapability
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
        assert_eq!(analysis.verbose_logging.signatures.len(), 1);
        assert!(analysis
            .verbose_logging
            .signatures
            .iter()
            .all(|group| group.signature.pid == 42));
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
            .find(|group| group.signature.reason == VerboseLoggingOutcomeReason::Actionable)
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
            Some(VerboseLoggingOutcomeReason::UnsupportedObjectType)
        );
        assert_eq!(
            reason_for(28),
            Some(VerboseLoggingOutcomeReason::NotActionable)
        );
        assert_eq!(reason_for(9999), None);
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
            VerboseLoggingOutcomeReason::UnusableResourcePath
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
                    provider: crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
                    event_id: 14,
                    event_name: None,
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
                VerboseLoggingOutcomeReason::UnsupportedObjectType
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
                    provider: crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
                    event_id: 14,
                    event_name: None,
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
            group.signature.reason == VerboseLoggingOutcomeReason::NotActionable
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
            VerboseLoggingOutcomeReason::NotActionable
        );
        assert_eq!(timer.signature.resource_type, Some(ResourceType::Other));
        assert_eq!(timer.signature.access_type, Some(AccessType::Read));

        let ui = out
            .verbose_logging
            .signatures
            .iter()
            .find(|group| group.signature.resource_type == Some(ResourceType::Ui))
            .expect("UI denial should remain actionable");
        assert_eq!(ui.signature.reason, VerboseLoggingOutcomeReason::Actionable);
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

        assert!(out.verbose_logging.is_empty());
    }

    #[test]
    fn unknown_provider_is_ignored_even_with_a_learning_mode_event_id() {
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
        assert!(out.verbose_logging.is_empty());
    }

    #[test]
    fn actionable_candidates_and_duplicates_share_one_verbose_logging_signature() {
        let make_event = |sequence_no: u64| {
            let mut event = kernel_event(
                14,
                7,
                sequence_no,
                &[
                    ("ObjectType", "\"File\""),
                    ("ObjectName", "\"D:\\profiles\\jsmith\\dup.txt\""),
                    ("AccessMask", "0x1"),
                    ("UserName", "\"jsmith\""),
                ],
            );
            event.parts.event_name = Some("AccessCheck".into());
            event
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
            .find(|group| group.signature.reason == VerboseLoggingOutcomeReason::Actionable)
            .expect("actionable outcome recorded");
        assert_eq!(
            actionable_group.signature.provider,
            VerboseLoggingProvider::KernelGeneral
        );
        assert_eq!(actionable_group.signature.event_id, 14);
        assert_eq!(
            actionable_group.signature.event_name.as_deref(),
            Some("AccessCheck")
        );
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
        let mut events = vec![permissive_event(
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
        events[0].parts.event_name = Some("CapabilityCheck".into());

        let out = resources_from_events(&events);
        assert_eq!(out.denials.len(), 1);
        assert_eq!(out.denials[0].resource, "internetClient");
        assert_eq!(out.verbose_logging.signatures.len(), 1);
        let signature = &out.verbose_logging.signatures[0].signature;
        assert_eq!(signature.reason, VerboseLoggingOutcomeReason::Actionable);
        assert_eq!(signature.access_type, Some(AccessType::Unknown));
        assert_eq!(signature.resource_type, Some(ResourceType::Capability));
        assert_eq!(signature.event_name.as_deref(), Some("CapabilityCheck"));
    }

    fn find_signature(
        summary: &crate::learning_mode_core::VerboseLoggingSummary,
        event_id: u16,
    ) -> &crate::learning_mode_core::VerboseLoggingAggregate {
        summary
            .signatures
            .iter()
            .find(|group| group.signature.event_id == event_id)
            .unwrap_or_else(|| panic!("expected a verbose logging signature for event {event_id}"))
    }

    fn property<'a>(
        signature: &'a crate::learning_mode_core::VerboseLoggingSignature,
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
        let properties = (0..crate::learning_mode_windows::extractors::MAX_SIGNATURE_PROPERTIES)
            .map(|index| {
                (
                    format!("Property{index:02}"),
                    "x".repeat(crate::learning_mode_windows::extractors::MAX_SIGNATURE_VALUE_LEN),
                )
            })
            .collect::<Vec<_>>();
        for pid in 0..crate::learning_mode_core::MAX_VERBOSE_LOGGING_GROUPS as u32 {
            accumulator.record_outcome(
                VerboseLoggingProvider::KernelGeneral,
                (14, None),
                VerboseLoggingOutcomeReason::Actionable,
                pid,
                (None, None),
                properties.clone(),
            );
        }

        assert!(accumulator.verbose_logging.aggregate_groups_truncated);
        assert!(accumulator.verbose_logging.overflow_occurrences > 0);
        assert!(accumulator.verbose_logging_signature_bytes <= MAX_VERBOSE_LOGGING_SIGNATURE_BYTES);
    }

    #[test]
    fn unknown_resource_signature_redacts_the_entire_file_path() {
        let events = vec![kernel_event(
            14,
            7,
            1,
            &[
                ("ObjectType", "FutureObject"),
                ("ObjectName", "\"C:\\Users\\jsmith\\secret.txt\""),
            ],
        )];

        let out = resources_from_events(&events);

        let group = find_signature(&out.verbose_logging, 14);
        assert_eq!(
            group.signature.reason,
            VerboseLoggingOutcomeReason::UnsupportedObjectType
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
            VerboseLoggingOutcomeReason::UnresolvedCapability
        );
        assert_eq!(
            group.signature.provider,
            VerboseLoggingProvider::KernelGeneral
        );
        assert_eq!(
            group.signature.provider_guid,
            crate::learning_mode_windows::extractors::verbose_logging_provider_guid(
                VerboseLoggingProvider::KernelGeneral
            )
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
            kernel_event(14, 7, 10, &[("Foo", "\"bar\"")]),
            kernel_event(14, 7, 20_000_000, &[("Foo", "\"bar\"")]),
        ];

        let out = resources_from_events(&events);

        assert_eq!(
            out.verbose_logging.signatures.len(),
            1,
            "differing only by timestamp must dedupe to a single signature"
        );
        assert_eq!(find_signature(&out.verbose_logging, 14).count, 2);
    }

    #[test]
    fn timestamp_like_properties_are_excluded_from_the_signature() {
        let events = vec![kernel_event(
            14,
            7,
            1,
            &[
                ("Foo", "\"bar\""),
                ("LastWriteTime", "\"132847890123456789\""),
            ],
        )];

        let out = resources_from_events(&events);

        let group = find_signature(&out.verbose_logging, 14);
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
            crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
            14,
            9,
            tdh_decode::DecodeError::event(
                tdh_decode::EventDecodeKind::PayloadMalformed,
                "property payload is malformed".to_string(),
                Some("AccessCheck".to_string()),
            ),
        );
        accumulator.record_event_decode_error(
            crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
            27,
            10,
            tdh_decode::DecodeError::event(
                tdh_decode::EventDecodeKind::DecoderLimitReached,
                "property decode work exceeds limit 100000".to_string(),
                Some("LearningModeViolation".to_string()),
            ),
        );
        accumulator.record_event_decode_error(
            crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
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
            VerboseLoggingOutcomeReason::EventPayloadMalformed
        );
        assert_eq!(malformed.signature.pid, 9);
        assert_eq!(
            malformed.signature.event_name.as_deref(),
            Some("AccessCheck")
        );
        assert_eq!(
            find_signature(&out.verbose_logging, 27).signature.reason,
            VerboseLoggingOutcomeReason::DecoderLimitReached
        );
        assert_eq!(
            find_signature(&out.verbose_logging, 28).signature.reason,
            VerboseLoggingOutcomeReason::UnsupportedPropertyEncoding
        );
        assert_eq!(
            find_signature(&out.verbose_logging, 28)
                .signature
                .resource_type,
            Some(ResourceType::Capability)
        );
        assert!(out.verbose_logging.signatures.iter().all(|aggregate| {
            aggregate.signature.properties.is_empty() && aggregate.signature.event_name.is_some()
        }));
    }

    #[test]
    fn event_28_decode_failure_classification_requires_a_known_schema_name() {
        let analyze = |event_name: Option<&str>| {
            let mut accumulator = Accumulator::analyze();
            accumulator.record_event_decode_error(
                crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
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

    #[test]
    fn decode_failure_schema_names_are_sanitized_for_learning_mode_providers() {
        for provider in [
            crate::learning_mode_windows::extractors::KERNEL_GENERAL_PROVIDER,
            crate::learning_mode_windows::extractors::PRIVACY_LEARNING_MODE_PROVIDER,
        ] {
            let mut accumulator = Accumulator::analyze();
            accumulator.record_event_decode_error(
                provider,
                14,
                42,
                tdh_decode::DecodeError::event(
                    tdh_decode::EventDecodeKind::PayloadMalformed,
                    "private decoder message".into(),
                    Some(r"C:\Users\private\schema".into()),
                ),
            );
            let analysis = accumulator.into_analysis().unwrap();
            let group = &analysis.verbose_logging.signatures[0];
            assert_eq!(group.signature.event_name.as_deref(), Some("<REDACTED>"));
            assert!(group.signature.properties.is_empty());
            assert_eq!(group.count, 1);
        }
    }
}
