// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Trait + shared types for the learning-mode capture feature.
//!
//! This crate exists purely to break a cargo dependency cycle: per-
//! OS backend crates (`learning_mode_windows`, `_linux`, `_macos`)
//! implement [`LearningModeBackend`], and the orchestrator crate
//! `learning_mode` depends on the backends to dispatch by
//! `cfg(target_os)`. If the trait lived in `learning_mode` itself,
//! the backends would need to depend back on `learning_mode`,
//! creating a cycle.
//!
//! Consumers should depend on `learning_mode`, not this crate;
//! `learning_mode` re-exports everything defined here.

use std::sync::mpsc::Sender;

pub use denial_channel::{AccessType, DeniedResource, ResourceType};

/// Options the runner passes when starting a learning-mode capture.
pub struct CaptureOptions {
    /// Root process whose denials should be observed. Backends are
    /// expected to follow descendants when the OS exposes a way to
    /// do so (e.g. Toolhelp on Windows).
    pub root_pid: u32,

    /// Optional backend-specific scope tag. On Windows this is the
    /// AppContainer / BaseContainer human-readable name used by the
    /// ETW filter to disambiguate concurrent sandboxes. On other
    /// platforms it is ignored.
    pub container_name: Option<String>,

    /// Channel that receives each deduplicated [`DeniedResource`] as
    /// the backend observes it. The receiver end is owned by the
    /// runner's stream-formatter thread.
    pub event_tx: Sender<DeniedResource>,
}

/// Summary returned when a capture stops cleanly.
#[derive(Debug, Clone, Default)]
pub struct CaptureSummary {
    /// Total number of raw events the backend decoded, **before**
    /// per-PID dedupe. Surfaced under `MXC_DENIAL_VERBOSE=1` for
    /// diagnostics; the SDK never relies on this for prompt UX.
    pub raw_event_count: u64,

    /// `true` when the backend hit its internal cap and stopped
    /// recording further denials. Maps onto
    /// `ScriptResponse.denied_resources_truncated`.
    pub truncated: bool,

    /// Number of *child* processes the backend observed under the
    /// root PID during the capture window. Surfaced to the SDK so
    /// callers can warn the user when a workload looks like a
    /// launcher (per-PID filtering means we don't capture
    /// descendants' denials). `0` when the backend does not
    /// implement child-process tracking.
    pub child_processes_observed: u32,
}

/// Errors a learning-mode backend can surface to the orchestrator.
#[derive(Debug, thiserror::Error)]
pub enum LearningModeError {
    /// The current platform does not implement learning-mode capture
    /// (yet). The `reason` is a short human-readable explanation the
    /// runner can fold into the `denial_capture_meta.unavailable_reason`
    /// field on `ScriptResponse`.
    #[error("learning-mode capture is not supported on this platform: {reason}")]
    NotSupported { reason: &'static str },

    /// The backend is available but failed to start / stream a
    /// capture for this invocation. The string is intended for
    /// operator diagnostics, not end-user prompts.
    #[error("learning-mode backend failure: {0}")]
    BackendFailure(String),
}

/// Per-OS learning-mode adapter. Implementations live in the
/// `learning_mode_<os>` backend crates.
pub trait LearningModeBackend: Send + Sync {
    /// Short identifier for diagnostics, e.g. `"windows-etw"`,
    /// `"linux-stub"`, `"macos-stub"`.
    fn name(&self) -> &'static str;

    /// `true` when this backend can run on the current host. Stub
    /// backends always return `false`; the Windows backend returns
    /// `false` when the shim service is missing.
    fn is_available(&self) -> bool;

    /// Begin observing denials. Backends must push each
    /// deduplicated [`DeniedResource`] into `opts.event_tx` as they
    /// see it. The returned handle owns the underlying session;
    /// dropping it without calling [`CaptureHandle::stop_and_drain`]
    /// must still tear the session down cleanly.
    fn begin_capture(
        &self,
        opts: CaptureOptions,
    ) -> Result<Box<dyn CaptureHandle>, LearningModeError>;
}

/// Active learning-mode capture handle. The runner calls
/// [`Self::stop_and_drain`] after the workload exits to obtain the
/// final [`CaptureSummary`] and release the backend resources.
pub trait CaptureHandle: Send {
    /// Stop the capture and return its final summary. Consumes the
    /// handle. Implementations should be idempotent against a prior
    /// `Drop` (i.e. tolerate the resources being half-released).
    fn stop_and_drain(self: Box<Self>) -> Result<CaptureSummary, LearningModeError>;
}
