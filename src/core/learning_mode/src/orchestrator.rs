// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OS dispatcher for the learning-mode feature.
//!
//! Runners call [`current_backend`] to obtain the
//! [`LearningModeBackend`] implementation for the host OS. The
//! dispatcher is a `cfg(target_os = ...)` switch that returns:
//!
//! - The real `learning_mode_windows::WindowsLearningModeBackend`
//!   on Windows.
//! - The `learning_mode_linux::LinuxLearningModeBackend` stub on
//!   Linux (`Err(NotSupported)` for every call).
//! - The `learning_mode_macos::MacosLearningModeBackend` stub on
//!   macOS (`Err(NotSupported)` for every call).
//! - A generic [`UnsupportedBackend`] on any other target so the
//!   crate still compiles.

#[allow(unused_imports)]
use crate::{
    CaptureHandle, CaptureOptions, LearningModeBackend, LearningModeError,
};

/// Returns the [`LearningModeBackend`] for the host OS.
///
/// The returned trait object is cheap to construct (no syscalls) so
/// callers can build one per invocation.
pub fn current_backend() -> Box<dyn LearningModeBackend> {
    #[cfg(target_os = "windows")]
    {
        Box::new(learning_mode_windows::WindowsLearningModeBackend::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(learning_mode_linux::LinuxLearningModeBackend::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(learning_mode_macos::MacosLearningModeBackend::new())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Box::new(UnsupportedBackend)
    }
}

/// Fallback for unrecognised platforms. Always unavailable.
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub struct UnsupportedBackend;

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
impl LearningModeBackend for UnsupportedBackend {
    fn name(&self) -> &'static str {
        "unsupported"
    }

    fn is_available(&self) -> bool {
        false
    }

    fn begin_capture(
        &self,
        _opts: CaptureOptions,
    ) -> Result<Box<dyn CaptureHandle>, LearningModeError> {
        Err(LearningModeError::NotSupported {
            reason: "learning-mode capture is not supported on this OS",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CaptureSummary;

    #[test]
    fn current_backend_reports_expected_name() {
        let backend = current_backend();
        let name = backend.name();
        #[cfg(target_os = "windows")]
        assert_eq!(name, "windows-etw");
        #[cfg(target_os = "linux")]
        assert_eq!(name, "linux-stub");
        #[cfg(target_os = "macos")]
        assert_eq!(name, "macos-stub");
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        assert_eq!(name, "unsupported");
    }

    #[test]
    fn windows_backend_is_available() {
        let backend = current_backend();
        #[cfg(target_os = "windows")]
        assert!(backend.is_available());
        #[cfg(not(target_os = "windows"))]
        assert!(!backend.is_available());
    }

    #[test]
    fn stub_summary_default_matches_zeroed_capture() {
        let summary = CaptureSummary::default();
        assert_eq!(summary.raw_event_count, 0);
        assert!(!summary.truncated);
        assert_eq!(summary.child_processes_observed, 0);
    }
}
