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
/// Implementors return the unique `(resource, accessType)` observations found
/// in `source_path`; the caller wraps them with a
/// [`crate::summary::DenialSummary`] and writes the JSON output document via
/// [`crate::emit`].
pub trait DenialAnalyzer {
    /// Analyses the capture at `source_path`, returning the denials it
    /// contains.
    ///
    /// # Errors
    ///
    /// Returns [`AnalyzeError`] if the source cannot be opened, cannot be
    /// decoded, or analysis is unsupported on this platform.
    fn analyze(&self, source_path: &Path) -> Result<Vec<DeniedResource>, AnalyzeError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AccessType, ResourceType};

    /// A trivial analyzer returning a fixed set, proving the trait is
    /// object-safe and usable behind a `dyn` reference.
    struct FakeAnalyzer(Vec<DeniedResource>);

    impl DenialAnalyzer for FakeAnalyzer {
        fn analyze(&self, _source_path: &Path) -> Result<Vec<DeniedResource>, AnalyzeError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn analyzer_is_object_safe_and_returns_denials() {
        let denials = vec![DeniedResource {
            resource: r"C:\a".to_string(),
            resource_type: ResourceType::File,
            access_type: AccessType::Read,
            pid: 1,
            filetime: 2,
        }];
        let analyzer: Box<dyn DenialAnalyzer> = Box::new(FakeAnalyzer(denials.clone()));
        let got = analyzer.analyze(Path::new("ignored.etl")).unwrap();
        assert_eq!(got, denials);
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
