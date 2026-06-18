// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! macOS stub for the learning-mode capture feature.
//!
//! Always reports unavailable; every call returns
//! [`LearningModeError::NotSupported`]. Exists so the cross-platform
//! [`learning_mode::orchestrator::current_backend`] dispatcher can
//! return a typed backend on macOS today.
//!
//! The real macOS implementation will likely use the EndpointSecurity
//! framework, scoped to the workload's PID via the existing seatbelt
//! sandbox harness. Tracked as future work.

use learning_mode_core::{
    CaptureHandle, CaptureOptions, LearningModeBackend, LearningModeError,
};

/// macOS stub backend.
pub struct MacosLearningModeBackend;

impl MacosLearningModeBackend {
    /// Construct the stub backend.
    pub const fn new() -> Self {
        Self
    }
}

impl Default for MacosLearningModeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LearningModeBackend for MacosLearningModeBackend {
    fn name(&self) -> &'static str {
        "macos-stub"
    }

    fn is_available(&self) -> bool {
        false
    }

    fn begin_capture(
        &self,
        _opts: CaptureOptions,
    ) -> Result<Box<dyn CaptureHandle>, LearningModeError> {
        Err(LearningModeError::NotSupported {
            reason: "learning-mode capture is not yet implemented on macOS (planned: EndpointSecurity framework)",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn stub_reports_unavailable() {
        let backend = MacosLearningModeBackend::new();
        assert!(!backend.is_available());
        assert_eq!(backend.name(), "macos-stub");
    }

    #[test]
    fn stub_begin_capture_returns_not_supported() {
        let backend = MacosLearningModeBackend::new();
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
