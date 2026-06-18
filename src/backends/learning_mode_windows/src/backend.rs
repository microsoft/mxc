// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Implementation of the cross-platform [`LearningModeBackend`]
//! trait for Windows.
//!
//! Wraps the existing Windows learning-mode plumbing:
//!
//! - [`session::open_via_shim`] + [`session::ScopedTraceSession::start_collector_with_stream`]
//!   for the ETW kernel-audit capture.
//! - [`child_process_observer::ChildProcessObserver`] for the
//!   Toolhelp-based descendants tracker.
//!
//! The orchestrator picks this adapter automatically on Windows via
//! [`learning_mode::orchestrator::current_backend`]. Runners that
//! want to call directly into the Windows pieces (today: the
//! AppContainer / BaseContainer runners under
//! `#[cfg(target_os = "windows")]`) may continue to use the lower-
//! level modules; this adapter is the entry point for cross-
//! platform consumers.

use std::time::Duration;

use learning_mode_core::{
    CaptureHandle, CaptureOptions, CaptureSummary, LearningModeBackend, LearningModeError,
};

use crate::child_process_observer::ChildProcessObserver;
use crate::session::{self, CollectorHandle};

/// Windows learning-mode backend (ETW kernel-audit + shim RPC).
pub struct WindowsLearningModeBackend;

impl WindowsLearningModeBackend {
    /// Construct the backend. Cheap; does not touch any OS resources.
    pub const fn new() -> Self {
        Self
    }
}

impl Default for WindowsLearningModeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LearningModeBackend for WindowsLearningModeBackend {
    fn name(&self) -> &'static str {
        "windows-etw"
    }

    fn is_available(&self) -> bool {
        // Best-effort: declared available on Windows. The shim
        // service may still be missing — that surfaces as a
        // `BackendFailure` from `begin_capture` rather than a global
        // unavailable. Runners can fall back gracefully on that
        // signal (today they log + continue without capture).
        true
    }

    fn begin_capture(
        &self,
        opts: CaptureOptions,
    ) -> Result<Box<dyn CaptureHandle>, LearningModeError> {
        let CaptureOptions {
            root_pid,
            container_name: _container_name,
            event_tx,
        } = opts;

        // 1. Ask the privileged shim service to loan us an ETW
        //    trace handle scoped to `root_pid`. `package_sid` is
        //    `None` today; a future revision can derive it from
        //    `container_name`.
        let session = session::open_via_shim(root_pid, None)
            .map_err(|e| LearningModeError::BackendFailure(format!("open_via_shim: {e}")))?;

        // 2. Start the ETW consumer. Captured events stream via
        //    `event_tx` AND are buffered inside the collector for
        //    drain-time access; the trait surface relies on the
        //    streamed copy and discards the buffered one at drain.
        let collector = session
            .start_collector_with_stream(Some(event_tx))
            .map_err(|e| {
                LearningModeError::BackendFailure(format!("start_collector_with_stream: {e}"))
            })?;

        // 3. Spawn the Toolhelp-based child-process observer so the
        //    summary can include `childProcessesObserved` (per-PID
        //    ETW filtering means we miss descendants' denials; this
        //    is the SDK's "looks like a launcher" signal).
        //    `ChildProcessObserver::spawn` returns `Option` because
        //    the Toolhelp snapshot can fail on locked-down hosts.
        let observer = ChildProcessObserver::spawn(root_pid, Duration::from_millis(500));

        Ok(Box::new(WindowsCaptureHandle {
            collector: Some(collector),
            observer,
        }))
    }
}

/// Active Windows learning-mode capture. Owns the ETW collector and
/// the child-process observer; both are torn down at drain time.
struct WindowsCaptureHandle {
    // `Option` so `Drop` can tell whether `stop_and_drain` already
    // ran and skip double-teardown.
    collector: Option<CollectorHandle>,
    observer: Option<ChildProcessObserver>,
}

impl CaptureHandle for WindowsCaptureHandle {
    fn stop_and_drain(mut self: Box<Self>) -> Result<CaptureSummary, LearningModeError> {
        let collector = self.collector.take().ok_or_else(|| {
            LearningModeError::BackendFailure("WindowsCaptureHandle drained twice".into())
        })?;

        let (events, truncated) = collector.stop_and_drain();
        let raw_event_count = events.len() as u64;

        let child_processes_observed = self
            .observer
            .take()
            .map(|o| o.take_observed_count() as u32)
            .unwrap_or(0);

        Ok(CaptureSummary {
            raw_event_count,
            truncated,
            child_processes_observed,
        })
    }
}

// `Drop` left implicit: `CollectorHandle::Drop` tears the ETW
// session down on the panic path; `ChildProcessObserver` joins its
// thread on `Drop`. Nothing to add here.
