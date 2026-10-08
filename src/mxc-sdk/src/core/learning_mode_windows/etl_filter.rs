// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Process-scoped ETL rewriting for guarded WPR captures.

use std::collections::HashSet;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::learning_mode_core::{AnalyzeError, ProcessLifetime};
use windows::core::{implement, Ref, BSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::Diagnostics::Etw::{
    CLSID_TraceRelogger, ITraceEvent, ITraceEventCallback, ITraceEventCallback_Impl, ITraceRelogger,
};

use crate::learning_mode_windows::etl_decode::is_process_scoped_relog_candidate;
use crate::learning_mode_windows::etl_decode::select_learning_mode_events_for_relogging;
use crate::learning_mode_windows::process_lifetime::{
    attested_process_lifetimes, JobMembershipSnapshot,
};
use crate::learning_mode_windows::tdh_decode;

const RPC_E_CHANGED_MODE: u32 = 0x8001_0106;

struct ComApartment {
    owns_init: bool,
}

impl ComApartment {
    fn new() -> Result<Self, AnalyzeError> {
        // SAFETY: the matching CoUninitialize runs on this thread when this
        // call acquires an initialization reference.
        let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if result.is_ok() {
            Ok(Self { owns_init: true })
        } else if result.0 as u32 == RPC_E_CHANGED_MODE {
            Ok(Self { owns_init: false })
        } else {
            Err(decode_error("CoInitializeEx", result))
        }
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.owns_init {
            // SAFETY: balances the successful CoInitializeEx call on this
            // same thread.
            unsafe { CoUninitialize() };
        }
    }
}

#[implement(ITraceEventCallback)]
struct ProcessScopedTraceFilter {
    selection: RelogSelectionState,
    schema_cache: Mutex<tdh_decode::EventSchemaCache>,
}

#[derive(Clone)]
struct RelogSelectionState {
    selected_event_indices: Arc<[usize]>,
    selected_event_pids: Arc<[u32]>,
    attested_pids: Arc<HashSet<u32>>,
    event_cursor: Arc<AtomicUsize>,
    selected_event_cursor: Arc<AtomicUsize>,
}

impl RelogSelectionState {
    fn new(
        selected_event_indices: Vec<usize>,
        selected_event_pids: Vec<u32>,
        process_lifetimes: &[ProcessLifetime],
    ) -> Self {
        debug_assert_eq!(selected_event_indices.len(), selected_event_pids.len());
        Self {
            selected_event_indices: selected_event_indices.into(),
            selected_event_pids: selected_event_pids.into(),
            attested_pids: Arc::new(
                process_lifetimes
                    .iter()
                    .map(|lifetime| lifetime.pid)
                    .collect(),
            ),
            event_cursor: Arc::new(AtomicUsize::new(0)),
            selected_event_cursor: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn observe_known_provider_event(&self, pid: u32) -> bool {
        let event_index = self.event_cursor.fetch_add(1, Ordering::Relaxed);
        let selected_index = self.selected_event_cursor.load(Ordering::Relaxed);
        if self.selected_event_indices.get(selected_index) != Some(&event_index) {
            return false;
        }

        // The first ProcessTrace pass selected this ordinal using exact PID and
        // lifetime bounds. Revalidate the second pass's current PID before
        // injection so a different equal-timestamp ordering cannot substitute
        // a foreign process's event at the same ordinal. Do not advance the
        // selected-event index on mismatch: the final count reconciliation then
        // fails closed and the partial destination is deleted.
        if self.selected_event_pids.get(selected_index) != Some(&pid)
            || !self.attested_pids.contains(&pid)
        {
            return false;
        }

        self.selected_event_cursor.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn consumed_event_count(&self) -> usize {
        self.event_cursor.load(Ordering::Relaxed)
    }

    fn consumed_selected_event_count(&self) -> usize {
        self.selected_event_cursor.load(Ordering::Relaxed)
    }
}

impl ITraceEventCallback_Impl for ProcessScopedTraceFilter_Impl {
    fn OnBeginProcessTrace(
        &self,
        header_event: Ref<ITraceEvent>,
        relogger: Ref<ITraceRelogger>,
    ) -> windows::core::Result<()> {
        let header_event = header_event.ok()?;
        let relogger = relogger.ok()?;
        // SAFETY: both interfaces are valid for this synchronous callback.
        // The trace header is required for a standalone output ETL.
        unsafe { relogger.Inject(header_event)? };
        Ok(())
    }

    fn OnFinalizeProcessTrace(&self, _relogger: Ref<ITraceRelogger>) -> windows::core::Result<()> {
        Ok(())
    }

    fn OnEvent(
        &self,
        event: Ref<ITraceEvent>,
        relogger: Ref<ITraceRelogger>,
    ) -> windows::core::Result<()> {
        let event = event.ok()?;
        let relogger = relogger.ok()?;
        // SAFETY: Trace Relogger owns the event and keeps its EVENT_RECORD
        // valid for the duration of this callback.
        let record = unsafe { event.GetEventRecord()? };
        let Some(record) = (unsafe { record.as_ref() }) else {
            return Err(windows::core::Error::from_hresult(
                windows::Win32::Foundation::E_POINTER,
            ));
        };
        let header = &record.EventHeader;
        if !is_process_scoped_relog_candidate(header.ProviderId, header.EventDescriptor.Id) {
            return Ok(());
        }
        let is_supported_capability_event = header.EventDescriptor.Id
            == crate::learning_mode_windows::extractors::CAPABILITY_DENIAL_EVENT_ID;
        let effective_pid = if is_supported_capability_event {
            let payload_pid = self
                .schema_cache
                .lock()
                .ok()
                .and_then(|mut cache| unsafe {
                    tdh_decode::decode_event_property(
                        std::ptr::from_ref(record).cast_mut(),
                        &mut cache,
                        "ProcessId",
                    )
                    .ok()
                    .flatten()
                })
                .and_then(|pid| {
                    crate::learning_mode_windows::extractors::effective_capability_event_pid(Some(
                        pid.as_str(),
                    ))
                });
            payload_pid.unwrap_or(header.ProcessId)
        } else {
            header.ProcessId
        };
        if self.selection.observe_known_provider_event(effective_pid) {
            // SAFETY: both interfaces are valid for this synchronous callback,
            // and Inject clones the event into the output trace.
            unsafe { relogger.Inject(event)? };
        }
        Ok(())
    }
}

trait TraceRelogger {
    fn process(
        &self,
        source: &Path,
        destination: &Path,
        selection: RelogSelectionState,
    ) -> Result<(), AnalyzeError>;
}

struct WindowsTraceRelogger;

impl TraceRelogger for WindowsTraceRelogger {
    fn process(
        &self,
        source: &Path,
        destination: &Path,
        selection: RelogSelectionState,
    ) -> Result<(), AnalyzeError> {
        let _apartment = ComApartment::new()?;
        // SAFETY: COM is initialized on this thread, the in-proc class ID is
        // fixed, and the returned interface remains apartment-local.
        let relogger: ITraceRelogger = unsafe {
            CoCreateInstance(&CLSID_TraceRelogger, None, CLSCTX_INPROC_SERVER)
                .map_err(|error| windows_error("CoCreateInstance(CLSID_TraceRelogger)", error))?
        };

        let source = path_bstr(source);
        let destination = path_bstr(destination);
        // SAFETY: the BSTRs remain valid for each synchronous COM call.
        unsafe {
            relogger
                .AddLogfileTraceStream(&source, std::ptr::null())
                .map_err(|error| windows_error("ITraceRelogger::AddLogfileTraceStream", error))?;
            relogger
                .SetOutputFilename(&destination)
                .map_err(|error| windows_error("ITraceRelogger::SetOutputFilename", error))?;
        }

        let callback: ITraceEventCallback = ProcessScopedTraceFilter {
            selection,
            schema_cache: Mutex::new(tdh_decode::EventSchemaCache::default()),
        }
        .into();
        // SAFETY: callback and relogger stay alive until ProcessTrace returns.
        unsafe {
            relogger
                .RegisterCallback(&callback)
                .map_err(|error| windows_error("ITraceRelogger::RegisterCallback", error))?;
            relogger
                .ProcessTrace()
                .map_err(|error| windows_error("ITraceRelogger::ProcessTrace", error))?;
        }
        Ok(())
    }
}

/// Rewrites a host-wide guarded WPR capture into a process-scoped Learning
/// Mode ETL. The destination is removed if relogging does not complete.
pub fn filter_trace_for_job_membership(
    source: &Path,
    destination: &Path,
    membership: &JobMembershipSnapshot,
) -> Result<(), AnalyzeError> {
    let process_lifetimes = attested_process_lifetimes(membership)?;
    filter_trace_for_process_lifetimes(source, destination, &process_lifetimes)
}

fn filter_trace_for_process_lifetimes(
    source: &Path,
    destination: &Path,
    process_lifetimes: &[ProcessLifetime],
) -> Result<(), AnalyzeError> {
    if source == destination {
        return Err(AnalyzeError::Decode(
            "filtered ETL destination must differ from its source".to_string(),
        ));
    }
    if destination
        .try_exists()
        .map_err(|error| AnalyzeError::Open {
            path: destination.display().to_string(),
            source: error,
        })?
    {
        return Err(AnalyzeError::Decode(format!(
            "filtered ETL destination '{}' already exists",
            destination.display()
        )));
    }

    let result = relog_trace(source, destination, process_lifetimes);
    if result.is_err() {
        let _ = std::fs::remove_file(destination);
    }
    result
}

fn relog_trace(
    source: &Path,
    destination: &Path,
    process_lifetimes: &[ProcessLifetime],
) -> Result<(), AnalyzeError> {
    relog_trace_with(
        source,
        destination,
        process_lifetimes,
        &WindowsTraceRelogger,
    )
}

fn relog_trace_with(
    source: &Path,
    destination: &Path,
    process_lifetimes: &[ProcessLifetime],
    relogger: &dyn TraceRelogger,
) -> Result<(), AnalyzeError> {
    let selection = select_learning_mode_events_for_relogging(source, process_lifetimes)?;
    let expected_event_count = selection.total_event_count;
    let expected_selected_event_count = selection.selected_event_indices.len();
    let selection = RelogSelectionState::new(
        selection.selected_event_indices,
        selection.selected_event_pids,
        process_lifetimes,
    );
    relogger.process(source, destination, selection.clone())?;

    let consumed_event_count = selection.consumed_event_count();
    if consumed_event_count != expected_event_count {
        return Err(AnalyzeError::Decode(format!(
            "Trace Relogger observed {consumed_event_count} known-provider Learning Mode events, but ProcessTrace selected {expected_event_count}"
        )));
    }
    let consumed_selected_event_count = selection.consumed_selected_event_count();
    if consumed_selected_event_count != expected_selected_event_count {
        return Err(AnalyzeError::Decode(format!(
            "Trace Relogger injected {consumed_selected_event_count} process-scoped Learning Mode events, but ProcessTrace selected {expected_selected_event_count}"
        )));
    }

    let metadata = std::fs::metadata(destination).map_err(|source| AnalyzeError::Open {
        path: destination.display().to_string(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(AnalyzeError::Decode(format!(
            "Trace Relogger did not produce a regular non-empty ETL at '{}'",
            destination.display()
        )));
    }
    Ok(())
}

fn path_bstr(path: &Path) -> BSTR {
    BSTR::from_wide(&path.as_os_str().encode_wide().collect::<Vec<_>>())
}

fn decode_error(operation: &str, result: windows::core::HRESULT) -> AnalyzeError {
    AnalyzeError::Decode(format!(
        "{operation} failed while filtering guarded WPR trace (HRESULT = 0x{:08X})",
        result.0 as u32
    ))
}

fn windows_error(operation: &str, error: windows::core::Error) -> AnalyzeError {
    AnalyzeError::Decode(format!(
        "{operation} failed while filtering guarded WPR trace: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_private_trace(
        path: &Path,
        provider: &tracelogging::Provider,
        guid: windows::core::GUID,
        emit: impl FnOnce() -> Vec<u32>,
    ) {
        use windows::core::PCWSTR;
        use windows::Win32::System::Diagnostics::Etw::{
            ControlTraceW, EnableTraceEx2, StartTraceW, CONTROLTRACE_HANDLE,
            EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PRIVATE_IN_PROC, EVENT_TRACE_PRIVATE_LOGGER_MODE,
            EVENT_TRACE_PROPERTIES, WNODE_FLAG_TRACED_GUID,
        };
        static PRIVATE_TRACE: Mutex<()> = Mutex::new(());
        let _guard = PRIVATE_TRACE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let name = format!("mxc-verbose-test-{}", std::process::id())
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        let path = path
            .as_os_str()
            .encode_wide()
            .chain([0])
            .collect::<Vec<_>>();
        let mut storage = vec![0u64; 512];
        let properties = storage.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
        let mut session = CONTROLTRACE_HANDLE::default();
        unsafe {
            (*properties).Wnode.BufferSize = (storage.len() * 8) as u32;
            (*properties).Wnode.Guid = guid;
            (*properties).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*properties).Wnode.ClientContext = 1;
            (*properties).BufferSize = 64;
            (*properties).LogFileMode =
                EVENT_TRACE_PRIVATE_LOGGER_MODE | EVENT_TRACE_PRIVATE_IN_PROC;
            (*properties).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            (*properties).LogFileNameOffset =
                (*properties).LoggerNameOffset + (name.len() * 2) as u32;
            assert!((*properties).LogFileNameOffset as usize + path.len() * 2 <= storage.len() * 8);
            std::ptr::copy_nonoverlapping(
                path.as_ptr(),
                storage
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add((*properties).LogFileNameOffset as usize)
                    .cast::<u16>(),
                path.len(),
            );
            assert_eq!(provider.register(), 0);
            let started = StartTraceW(&mut session, PCWSTR(name.as_ptr()), properties);
            if started.0 != 0 {
                provider.unregister();
                panic!("private StartTraceW failed: {}", started.0);
            }
            let enabled = EnableTraceEx2(session, &guid, 1, 5, u64::MAX, 0, 0, None);
            let emitted = emit();
            let stopped = ControlTraceW(
                session,
                PCWSTR(name.as_ptr()),
                properties,
                EVENT_TRACE_CONTROL_STOP,
            );
            let unregistered = provider.unregister();
            for status in [enabled.0, stopped.0, unregistered]
                .into_iter()
                .chain(emitted)
            {
                assert_eq!(status, 0);
            }
        }
    }

    #[test]
    fn private_trace_relogging_excludes_unrelated_events_but_raw_decoding_preserves_them() {
        tracelogging::define_provider!(
            TEST_PROVIDER,
            "MxcTest.Redaction",
            id("a93bc25e-f2de-485a-90e7-a2d8970b22a9")
        );

        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.etl");
        let destination = directory.path().join("scoped.etl");
        let provider = windows::core::GUID::from_u128(0xa93bc25e_f2de_485a_90e7_a2d8970b22a9);
        let mut locations = 2u16.to_le_bytes().to_vec();
        for value in [r"C:\Users\alice\secret.txt", r"D:\private.txt"] {
            locations.extend(value.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
        }
        record_private_trace(&source, &TEST_PROVIDER, provider, || {
            let emit = || {
                [
                    tracelogging::write_event!(
                        TEST_PROVIDER,
                        "CompositeProperties",
                        cstr8("CommandLine", r"cmd.exe /c type C:\Users\alice\secret.txt"),
                        raw_field_slice("FutureLocations", CStr16, &locations),
                        u32("SafeIdentifier", &42),
                        u32("C:\\Users\\alice\\secret.txt", &42),
                        cstr8("EventName", "payload-name"),
                    ),
                    tracelogging::write_event!(
                        TEST_PROVIDER,
                        "OtherCompositeProperties",
                        cstr8("CommandLine", r"cmd.exe /c type C:\Users\alice\secret.txt"),
                        raw_field_slice("FutureLocations", CStr16, &locations),
                        u32("SafeIdentifier", &42),
                        u32("C:\\Users\\alice\\secret.txt", &42),
                        cstr8("EventName", "payload-name"),
                    ),
                ]
            };
            emit().into_iter().chain(emit()).collect()
        });
        if let Some(path) = std::env::var_os("MXC_TEST_ETL_OUTPUT") {
            std::fs::copy(&source, path).expect("failed to retain the test ETL for CLI replay");
        }
        let lifetimes = [ProcessLifetime {
            pid: std::process::id(),
            start_filetime: 0,
            end_filetime: u64::MAX,
        }];
        let native = crate::learning_mode_windows::EtlDenialAnalyzer
            .analyze_for_process_lifetimes(&source, &lifetimes)
            .unwrap();
        filter_trace_for_process_lifetimes(&source, &destination, &lifetimes).unwrap();
        let guarded = crate::learning_mode_windows::EtlDenialAnalyzer
            .analyze_relogged_for_process_lifetimes(&destination, &lifetimes)
            .unwrap();
        let mut decoded = Vec::new();
        crate::learning_mode_windows::visit_raw_events(&source, &mut |parts| {
            if parts.provider == provider {
                decoded.push(parts.clone());
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(decoded.len(), 4);
        assert_eq!(
            decoded
                .iter()
                .map(|parts| parts.event_name.as_deref())
                .collect::<Vec<_>>(),
            [
                Some("CompositeProperties"),
                Some("OtherCompositeProperties"),
                Some("CompositeProperties"),
                Some("OtherCompositeProperties")
            ]
        );
        for parts in decoded {
            let properties =
                crate::learning_mode_windows::extractors::sanitize_properties(&parts.props);
            for name in ["CommandLine", "FutureLocations"] {
                assert_eq!(
                    properties.iter().find(|(key, _)| key == name),
                    Some(&(
                        name.to_string(),
                        crate::learning_mode_windows::extractors::REDACTED_PATH.to_string()
                    )),
                );
            }
            assert!(properties.contains(&("SafeIdentifier".into(), "42".into())));
            assert!(properties.contains(&("EventName".into(), "payload-name".into())));
            assert!(!properties
                .iter()
                .any(|(name, _)| name.contains(r"C:\Users")));
        }
        assert_eq!(native, guarded);
        assert!(native.verbose_logging.is_empty());
        assert!(native.denials.is_empty());
    }

    #[test]
    fn private_trace_relogging_preserves_selected_learning_mode_events() {
        tracelogging::define_provider!(
            LEARNING_MODE_PROVIDER,
            "MxcTest.LearningMode",
            id("811a1ddb-2e69-5f25-adc0-4b186170e760")
        );

        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.etl");
        let destination = directory.path().join("scoped.etl");
        record_private_trace(
            &source,
            &LEARNING_MODE_PROVIDER,
            crate::learning_mode_windows::extractors::PRIVACY_LEARNING_MODE_PROVIDER,
            || {
                let unrelated = || {
                    tracelogging::write_event!(
                        LEARNING_MODE_PROVIDER,
                        "Unrelated",
                        id_version(999, 0),
                        u32("Value", &1),
                    )
                };
                vec![
                    unrelated(),
                    tracelogging::write_event!(
                        LEARNING_MODE_PROVIDER,
                        "AccessCheck",
                        id_version(14, 0),
                        cstr8("ObjectType", "File"),
                        cstr8("ObjectName", r"C:\selected.txt"),
                        u32("AccessMask", &1),
                    ),
                    unrelated(),
                ]
            },
        );
        let pid = std::process::id();
        let lifetimes = [ProcessLifetime {
            pid,
            start_filetime: 0,
            end_filetime: u64::MAX,
        }];

        let selection = select_learning_mode_events_for_relogging(&source, &lifetimes).unwrap();
        assert_eq!(selection.total_event_count, 3);
        assert_eq!(selection.selected_event_indices, [0, 1, 2]);
        assert_eq!(selection.selected_event_pids, [pid, pid, pid]);

        let native = crate::learning_mode_windows::EtlDenialAnalyzer
            .analyze_for_process_lifetimes(&source, &lifetimes)
            .unwrap();
        filter_trace_for_process_lifetimes(&source, &destination, &lifetimes).unwrap();
        let guarded = crate::learning_mode_windows::EtlDenialAnalyzer
            .analyze_relogged_for_process_lifetimes(&destination, &lifetimes)
            .unwrap();
        assert_eq!(native.denials.len(), 1);
        assert_eq!(native.denials[0].resource, r"C:\selected.txt");
        assert_eq!(native, guarded);

        struct ScriptedRelogger(Vec<u32>);
        impl TraceRelogger for ScriptedRelogger {
            fn process(
                &self,
                _source: &Path,
                destination: &Path,
                selection: RelogSelectionState,
            ) -> Result<(), AnalyzeError> {
                for pid in &self.0 {
                    selection.observe_known_provider_event(*pid);
                }
                std::fs::write(destination, b"etl").map_err(|source| AnalyzeError::Open {
                    path: destination.display().to_string(),
                    source,
                })
            }
        }
        for (observed, reconciled) in [
            (vec![pid, pid, pid], true),
            (vec![], false),
            (vec![pid], false),
            (vec![pid, pid], false),
            (vec![pid + 1, pid + 1, pid + 1], false),
        ] {
            assert_eq!(
                relog_trace_with(
                    &source,
                    &directory.path().join("scripted.etl"),
                    &lifetimes,
                    &ScriptedRelogger(observed),
                )
                .is_ok(),
                reconciled
            );
        }
    }

    const START: u64 = 100;
    const END: u64 = 200;

    fn lifetime(pid: u32) -> ProcessLifetime {
        ProcessLifetime {
            pid,
            start_filetime: START,
            end_filetime: END,
        }
    }

    #[test]
    fn selected_ordinal_with_foreign_pid_is_not_injected() {
        let selection = RelogSelectionState::new(vec![0], vec![42], &[lifetime(42)]);

        assert!(!selection.observe_known_provider_event(99));
        assert_eq!(selection.consumed_event_count(), 1);
        assert_eq!(
            selection.consumed_selected_event_count(),
            0,
            "foreign PID must not advance the selected-event cursor"
        );
    }

    #[test]
    fn selected_ordinal_with_attested_pid_is_injected() {
        let selection = RelogSelectionState::new(vec![0], vec![42], &[lifetime(42)]);

        assert!(selection.observe_known_provider_event(42));
        assert_eq!(selection.consumed_event_count(), 1);
        assert_eq!(selection.consumed_selected_event_count(), 1);
    }

    #[test]
    fn refuses_to_overwrite_existing_destination() {
        let unique = format!(
            "mxc-etl-filter-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("source.etl");
        let destination = directory.join("filtered.etl");
        std::fs::write(&destination, b"sentinel").unwrap();

        let error =
            filter_trace_for_process_lifetimes(&source, &destination, &[lifetime(42)]).unwrap_err();

        assert!(error.to_string().contains("already exists"));
        assert_eq!(std::fs::read(&destination).unwrap(), b"sentinel");
        std::fs::remove_file(destination).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
