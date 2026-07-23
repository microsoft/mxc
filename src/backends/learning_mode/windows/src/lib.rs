// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `learning_mode_windows` — runtime FFI adapter for the Windows AppInfo-brokered
//! **Learning Mode trace API** exported by `processmodel.dll`.
//!
//! Supported Windows builds expose a privileged, per-client learning-mode
//! ETW trace behind two flat C exports in `processmodel.dll` — the same system DLL
//! the BaseContainer backend already loads for `Experimental_CreateProcessInSandbox`:
//!
//! ```c
//! BOOL StartLearningModeTrace(HANDLE hProcessSecurityEnvironment, HLEARNINGMODE_TRACE* pphTrace);
//! BOOL StopLearningModeTrace (HLEARNINGMODE_TRACE* pphTrace, LPCWSTR lpOutputPath);
//! ```
//!
//! The broker collects and filters the trace to the caller's user SID and the
//! sandbox identified by the supplied security-environment handle, then — on stop —
//! writes the sealed ETL into a caller-named `outputPath` (opened under the caller's
//! own identity to avoid a confused-deputy). There is **no real-time event access**;
//! denials are read from the ETL after the sandboxed process exits.
//!
//! Because the exports only exist on feature-enabled OS builds, this crate resolves
//! them at runtime via `LoadLibrary`/`GetProcAddress` behind the [`is_learning_mode_api_available`]
//! capability probe, mirroring the existing `Experimental_CreateProcessInSandbox`
//! adapter. The crate compiles on every platform: the capability probe returns
//! `false` on non-Windows targets, while the loader and capture lifecycle types are
//! exported only on Windows.

use thiserror::Error;

#[cfg(target_os = "windows")]
mod ffi;
#[cfg(target_os = "windows")]
mod lifecycle;
#[cfg(target_os = "windows")]
mod secenv;

#[cfg(target_os = "windows")]
pub use ffi::{is_learning_mode_api_available, LearningModeApi, LearningModeTraceHandle};
#[cfg(target_os = "windows")]
pub use lifecycle::CaptureSession;
#[cfg(target_os = "windows")]
pub use secenv::{
    is_security_environment_api_available, probe_security_environment_exports,
    ProcessSecurityEnvironment, SecurityEnvironmentApi, SecurityEnvironmentExportReport,
    PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
};

/// Errors surfaced while loading or invoking the Learning Mode trace API.
#[derive(Debug, Error)]
pub enum LearningModeError {
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

    /// An API call returned `FALSE`; `code` is the captured `GetLastError` value.
    #[error("{function} failed (GetLastError = {code})")]
    ApiCall {
        /// The name of the export that returned failure.
        function: &'static str,
        /// The `GetLastError` value captured immediately after the failed call.
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

    /// A primary operation failed and the subsequent cleanup operation also failed.
    #[error("{primary}; cleanup also failed: {cleanup}")]
    CleanupFailed {
        /// The error that triggered cleanup.
        primary: Box<LearningModeError>,
        /// The error returned while attempting cleanup.
        cleanup: Box<LearningModeError>,
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
    fn cleanup_error_preserves_both_failures() {
        let error = LearningModeError::CleanupFailed {
            primary: Box::new(LearningModeError::ApiCall {
                function: "StartLearningModeTrace",
                code: 5,
            }),
            cleanup: Box::new(LearningModeError::ApiCall {
                function: "CloseProcessSecurityEnvironment",
                code: 6,
            }),
        };

        let message = error.to_string();
        assert!(message.contains("StartLearningModeTrace"));
        assert!(message.contains("CloseProcessSecurityEnvironment"));
    }

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
