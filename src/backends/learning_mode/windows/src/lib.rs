// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `learning_mode_windows` — runtime FFI adapter for the Windows AppInfo-brokered
//! **Learning Mode trace API** exported by `processmodel.dll`.
//!
//! Windows (GE_CURRENT and later) exposes a privileged, per-client learning-mode
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
//! adapter. It compiles on every platform and degrades cleanly (the probe returns
//! `false` and [`LearningModeApi::load`] returns [`LearningModeError::Unsupported`])
//! wherever the API is absent.

use thiserror::Error;

#[cfg(target_os = "windows")]
mod ffi;

#[cfg(target_os = "windows")]
pub use ffi::{is_learning_mode_api_available, LearningModeApi, LearningModeTraceHandle};

/// Errors surfaced while loading or invoking the Learning Mode trace API.
#[derive(Debug, Error)]
pub enum LearningModeError {
    /// The Learning Mode trace API is not available on this platform (non-Windows
    /// targets, where the `processmodel.dll` exports cannot exist).
    #[error("the Learning Mode trace API is not supported on this platform")]
    Unsupported,

    /// `processmodel.dll` itself could not be loaded from System32.
    #[error("failed to load processmodel.dll: {0}")]
    DllLoad(String),

    /// `processmodel.dll` loaded, but a required export is missing — the OS build
    /// predates the Learning Mode trace API (or has the feature gated off).
    #[error("export `{export}` not found in processmodel.dll ({detail}); this OS build lacks the Learning Mode trace API")]
    ExportMissing {
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
            export: "StartLearningModeTrace",
            detail: "GetLastError = 127".to_string(),
        };
        let msg = e.to_string();
        assert!(msg.contains("StartLearningModeTrace"));
        assert!(msg.contains("lacks the Learning Mode trace API"));
    }
}
