// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The decode abstraction: turn a platform-native capture source into the
//! cross-platform [`DeniedResource`] model.
//!
//! Each backend implements [`DenialAnalyzer`] over its own capture format.
//! The Windows backend (`learning_mode_windows`) implements it over a
//! sealed ETW trace (`.etl`); a future Linux backend would implement it
//! over its own source. Keeping the trait in this cross-platform crate
//! lets the runner and tests depend on the abstraction rather than any
//! one OS decoder, and lets tests substitute a fake.

use std::path::Path;

use thiserror::Error;

use crate::model::DeniedResource;

/// Result of decoding a capture source into bounded, de-duplicated denials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisResult {
    /// Unique denials retained by the analyzer in first-seen order.
    pub denials: Vec<DeniedResource>,
    /// Whether additional unique denials were observed after the result bound
    /// was reached.
    pub denied_resources_truncated: bool,
}

impl AnalysisResult {
    /// Creates a complete, non-truncated result.
    #[must_use]
    pub fn complete(denials: Vec<DeniedResource>) -> Self {
        Self {
            denials,
            denied_resources_truncated: false,
        }
    }
}

/// Failure modes when analysing a capture source into denials.
#[derive(Debug, Error)]
pub enum AnalyzeError {
    /// The capture source could not be opened (missing file, permissions).
    #[error("failed to open capture source '{path}': {source}")]
    Open {
        /// The source path that could not be opened.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The source was opened but could not be decoded into denials.
    #[error("failed to decode capture source: {0}")]
    Decode(String),

    /// Analysis is not available on this platform / build (e.g. the
    /// decoder is Windows-only and this is a non-Windows target).
    #[error("capture analysis is not supported on this platform")]
    Unsupported,
}

/// Decodes a platform-native capture source into de-duplicated denials.
///
/// Implementors return bounded unique `(path, accessType)` observations and
/// whether additional unique records were truncated; the caller wraps them with a
/// [`crate::summary::DenialSummary`] and emits an NDJSON stream via
/// [`crate::emit`].
pub trait DenialAnalyzer {
    /// Analyses the capture at `source_path`, returning its bounded denial
    /// result.
    ///
    /// # Errors
    ///
    /// Returns [`AnalyzeError`] if the source cannot be opened, cannot be
    /// decoded, or analysis is unsupported on this platform.
    fn analyze(&self, source_path: &Path) -> Result<AnalysisResult, AnalyzeError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AccessType, ResourceType};

    /// A trivial analyzer returning a fixed set, proving the trait is
    /// object-safe and usable behind a `dyn` reference.
    struct FakeAnalyzer(Vec<DeniedResource>);

    impl DenialAnalyzer for FakeAnalyzer {
        fn analyze(&self, _source_path: &Path) -> Result<AnalysisResult, AnalyzeError> {
            Ok(AnalysisResult::complete(self.0.clone()))
        }
    }

    #[test]
    fn analyzer_is_object_safe_and_returns_denials() {
        let denials = vec![DeniedResource {
            path: r"C:\a".to_string(),
            resource_type: ResourceType::File,
            access_type: AccessType::Read,
            pid: 1,
            filetime: 2,
        }];
        let analyzer: Box<dyn DenialAnalyzer> = Box::new(FakeAnalyzer(denials.clone()));
        let got = analyzer.analyze(Path::new("ignored.etl")).unwrap();
        assert_eq!(got.denials, denials);
        assert!(!got.denied_resources_truncated);
    }

    #[test]
    fn analyze_error_messages_are_meaningful() {
        let err = AnalyzeError::Open {
            path: "x.etl".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "nope"),
        };
        assert!(err.to_string().contains("x.etl"));
        assert!(AnalyzeError::Unsupported
            .to_string()
            .contains("not supported"));
    }
}
