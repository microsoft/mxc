// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Process-scoped ETL rewriting for guarded WPR captures.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use learning_mode_core::{AnalyzeError, ProcessLifetime};
use windows::core::{implement, Ref, BSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::Diagnostics::Etw::{
    CLSID_TraceRelogger, ITraceEvent, ITraceEventCallback, ITraceEventCallback_Impl, ITraceRelogger,
};

use crate::etl_decode::select_learning_mode_events_for_relogging;
use crate::extractors::provider_category;
use crate::process_lifetime::{attested_process_lifetimes, JobMembershipSnapshot};

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
    selected_event_indices: Vec<usize>,
    event_cursor: Arc<AtomicUsize>,
    selected_event_cursor: Arc<AtomicUsize>,
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
        if provider_category(header.ProviderId).is_none() {
            return Ok(());
        }
        let event_index = self.event_cursor.fetch_add(1, Ordering::Relaxed);
        let selected_index = self.selected_event_cursor.load(Ordering::Relaxed);
        if self.selected_event_indices.get(selected_index) == Some(&event_index) {
            // SAFETY: both interfaces are valid for this synchronous callback,
            // and Inject clones the event into the output trace.
            unsafe { relogger.Inject(event)? };
            self.selected_event_cursor.fetch_add(1, Ordering::Relaxed);
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
    let selection = select_learning_mode_events_for_relogging(source, process_lifetimes)?;
    let expected_event_count = selection.total_event_count;
    let expected_selected_event_count = selection.selected_event_indices.len();
    let _apartment = ComApartment::new()?;
    // SAFETY: COM is initialized on this thread, the in-proc class ID is
    // fixed, and the returned interface remains apartment-local.
    let relogger: ITraceRelogger = unsafe {
        CoCreateInstance(&CLSID_TraceRelogger, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| windows_error("CoCreateInstance(CLSID_TraceRelogger)", error))?
    };

    let source = path_bstr(source);
    let destination_bstr = path_bstr(destination);
    // SAFETY: the BSTRs remain valid for each synchronous COM call.
    unsafe {
        relogger
            .AddLogfileTraceStream(&source, std::ptr::null())
            .map_err(|error| windows_error("ITraceRelogger::AddLogfileTraceStream", error))?;
        relogger
            .SetOutputFilename(&destination_bstr)
            .map_err(|error| windows_error("ITraceRelogger::SetOutputFilename", error))?;
    }

    let event_cursor = Arc::new(AtomicUsize::new(0));
    let selected_event_cursor = Arc::new(AtomicUsize::new(0));
    let callback: ITraceEventCallback = ProcessScopedTraceFilter {
        selected_event_indices: selection.selected_event_indices,
        event_cursor: Arc::clone(&event_cursor),
        selected_event_cursor: Arc::clone(&selected_event_cursor),
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
    let consumed_event_count = event_cursor.load(Ordering::Relaxed);
    if consumed_event_count != expected_event_count {
        return Err(AnalyzeError::Decode(format!(
            "Trace Relogger observed {consumed_event_count} supported Learning Mode events, but ProcessTrace selected {expected_event_count}"
        )));
    }
    let consumed_selected_event_count = selected_event_cursor.load(Ordering::Relaxed);
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

    const START: u64 = 100;
    const END: u64 = 200;

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

        let error = filter_trace_for_process_lifetimes(
            &source,
            &destination,
            &[ProcessLifetime {
                pid: 42,
                start_filetime: START,
                end_filetime: END,
            }],
        )
        .unwrap_err();

        assert!(error.to_string().contains("already exists"));
        assert_eq!(std::fs::read(&destination).unwrap(), b"sentinel");
        std::fs::remove_file(destination).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
