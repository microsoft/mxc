// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `learning_mode_windows` — runtime FFI adapter for the Windows AppInfo-brokered
//! **Learning Mode trace API** exported by `processmodel.dll`.
//!
//! Supported Windows builds expose a privileged, per-client learning-mode
//! ETW trace behind three official flat C exports in `processmodel.dll`:
//!
//! ```c
//! HRESULT StartLearningModeTrace(HPROCESS_SECURITY_ENVIRONMENT environment, HLEARNINGMODE_TRACE* trace);
//! HRESULT StopLearningModeTrace(HLEARNINGMODE_TRACE trace, PCWSTR outputEtlPath);
//! void CloseLearningModeTrace(HLEARNINGMODE_TRACE trace);
//! ```
//!
//! The broker collects and filters the trace to the caller's user SID and the
//! sandbox identified by the supplied security-environment handle. `Stop` seals and
//! copies the ETL into a caller-named `outputPath` (opened under the caller's own
//! identity to avoid a confused-deputy) and may be retried; `Close` releases the
//! broker state and staged ETL. There is **no real-time event access**; denials are
//! read from the ETL after the sandboxed process exits.
//!
//! Because the exports only exist on feature-enabled OS builds, this crate resolves
//! them at runtime via `LoadLibrary`/`GetProcAddress` behind the [`is_learning_mode_api_available`]
//! capability probe. The crate compiles on every platform: the capability probe returns
//! `false` on non-Windows targets, while the loader and capture lifecycle types are
//! exported only on Windows.

use thiserror::Error;

pub mod guarded_wpr_protocol;

#[cfg(target_os = "windows")]
mod ffi;
#[cfg(target_os = "windows")]
mod lifecycle;
#[cfg(target_os = "windows")]
mod secenv;

#[cfg(target_os = "windows")]
mod capability_dacl;
#[cfg(target_os = "windows")]
mod capability_names;
#[cfg(target_os = "windows")]
mod etl_decode;
#[cfg(target_os = "windows")]
mod etl_filter;
#[cfg(target_os = "windows")]
mod extractors;
#[cfg(target_os = "windows")]
mod network_extractors;
#[cfg(target_os = "windows")]
mod path_norm;
#[cfg(target_os = "windows")]
mod process_lifetime;
#[cfg(target_os = "windows")]
mod tdh_decode;
#[cfg(target_os = "windows")]
mod ui;

#[cfg(target_os = "windows")]
pub use etl_decode::{visit_raw_events, EtlDenialAnalyzer};
#[cfg(target_os = "windows")]
pub use etl_filter::filter_trace_for_job_membership;
#[cfg(target_os = "windows")]
pub use extractors::DecodedEventParts;
#[cfg(target_os = "windows")]
pub use ffi::{is_learning_mode_api_available, LearningModeApi, LearningModeTraceHandle};
#[cfg(target_os = "windows")]
pub use lifecycle::CaptureSession;
#[cfg(target_os = "windows")]
pub use process_lifetime::{
    JobMembershipSnapshot, JobProcessMembership, MAX_JOB_PROCESS_LIFETIMES,
};
#[cfg(target_os = "windows")]
pub use secenv::{
    is_security_environment_api_available, probe_security_environment_exports,
    ProcessSecurityEnvironment, SecurityEnvironmentApi, SecurityEnvironmentExportReport,
    SecurityEnvironmentStartupInfo, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
};

/// Errors surfaced while loading or invoking the Learning Mode trace API.
///
/// `Clone` is derived so that [`crate::LearningModeApi::load`] and
/// [`crate::SecurityEnvironmentApi::load`] can memoize a failed load and hand
/// every caller an owned, typed copy of the original diagnostic. Every variant
/// already owns its data (`&'static str`, `String`, or plain integers), so the
/// clone preserves the full message and source information without erasing it
/// behind a stringified surrogate.
#[derive(Debug, Clone, Error)]
pub enum LearningModeError {
    /// The named API-set group for an API surface is not implemented by this
    /// Windows build.
    #[error("API set `{api_set}` is not implemented; this OS build lacks the required {api} API")]
    ApiSetUnavailable {
        /// The API surface guarded by the named group.
        api: &'static str,
        /// The API-set contract queried with `IsApiSetImplemented`.
        api_set: &'static str,
    },

    /// `processmodel.dll` itself could not be loaded from System32.
    #[error("failed to load processmodel.dll: {0}")]
    DllLoad(String),

    /// `processmodel.dll` loaded, but a required export is missing from the
    /// named API surface.
    #[error("export `{export}` not found in processmodel.dll ({detail}); this OS build lacks the required {api} API")]
    ExportMissing {
        /// The API surface that requires the export.
        api: &'static str,
        /// The undecorated export name that failed to resolve.
        export: &'static str,
        /// Additional diagnostic detail (e.g. the `GetLastError` code).
        detail: String,
    },

    /// An API call returned a failing HRESULT.
    #[error("{function} failed (HRESULT = 0x{code:08X})")]
    HResultCall {
        /// The name of the export that returned failure.
        function: &'static str,
        /// The raw HRESULT value.
        code: i32,
    },

    /// A Win32 API call failed and set the thread's last-error value.
    #[error("{function} failed (Win32 error = {code})")]
    ApiCall {
        /// The API operation that failed.
        function: &'static str,
        /// The raw `GetLastError` value.
        code: u32,
    },

    /// A caller-provided value cannot be represented safely for the API call.
    #[error("invalid {parameter}: {detail}")]
    InvalidInput {
        /// The invalid parameter.
        parameter: &'static str,
        /// Why the value is invalid.
        detail: String,
    },
}

/// Capability probe: `true` only when `processmodel.dll` exposes the Learning Mode
/// trace exports on this machine. Always `false` on non-Windows targets.
#[cfg(not(target_os = "windows"))]
#[must_use]
pub fn is_learning_mode_api_available() -> bool {
    false
}

#[cfg(all(test, not(target_os = "windows")))]
mod stub_tests {
    use super::*;

    #[test]
    fn probe_is_false_off_windows() {
        assert!(!is_learning_mode_api_available());
    }

    #[test]
    fn error_messages_are_actionable() {
        let e = LearningModeError::ExportMissing {
            api: "Learning Mode trace",
            export: "StartLearningModeTrace",
            detail: "GetLastError = 127".to_string(),
        };
        let msg = e.to_string();
        assert!(msg.contains("StartLearningModeTrace"));
        assert!(msg.contains("Learning Mode trace API"));
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn missing_export_identifies_the_api_surface() {
        let error = LearningModeError::ExportMissing {
            api: "process security-environment",
            export: "CreateProcessSecurityEnvironment",
            detail: "GetLastError = 127".to_string(),
        };

        let message = error.to_string();
        assert!(message.contains("process security-environment API"));
        assert!(!message.contains("lacks the Learning Mode trace API"));
    }
}
