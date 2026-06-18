// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Linux stub for the learning-mode capture feature.
//!
//! Always reports unavailable; every call returns
//! [`LearningModeError::NotSupported`]. Exists so the cross-platform
//! [`learning_mode::orchestrator::current_backend`] dispatcher can
//! return a typed backend on Linux today.
//!
//! The real Linux implementation will likely combine `fanotify`
//! (for filesystem accesses) with the kernel audit subsystem (for
//! security-relevant denials). Tracked as future work.

use learning_mode_api::{
    CaptureHandle, CaptureOptions, LearningModeBackend, LearningModeError,
};

/// Linux stub backend.
pub struct LinuxLearningModeBackend;

impl LinuxLearningModeBackend {
    /// Construct the stub backend. Const so callers can use it in
    /// static contexts when the dispatcher eventually wires it in.
    pub const fn new() -> Self {
        Self
    }
}

impl Default for LinuxLearningModeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LearningModeBackend for LinuxLearningModeBackend {
    fn name(&self) -> &'static str {
        "linux-stub"
    }

    fn is_available(&self) -> bool {
        false
    }

    fn begin_capture(
        &self,
        _opts: CaptureOptions,
    ) -> Result<Box<dyn CaptureHandle>, LearningModeError> {
        Err(LearningModeError::NotSupported {
            reason: "learning-mode capture is not yet implemented on Linux (planned: fanotify + audit)",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn stub_reports_unavailable() {
        let backend = LinuxLearningModeBackend::new();
        assert!(!backend.is_available());
        assert_eq!(backend.name(), "linux-stub");
    }

    #[test]
    fn stub_begin_capture_returns_not_supported() {
        let backend = LinuxLearningModeBackend::new();
        let (tx, _rx) = mpsc::channel();
        let result = backend.begin_capture(CaptureOptions {
            root_pid: 0,
            container_name: None,
            event_tx: tx,
        });
        assert!(matches!(
            result,
            Err(LearningModeError::NotSupported { .. })
        ));
    }
}
