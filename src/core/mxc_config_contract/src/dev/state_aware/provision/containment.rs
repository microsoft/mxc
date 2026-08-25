// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Containment backends that support state-aware provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Containment {
    /// IsolationSession backend.
    IsolationSession,
    /// Windows Sandbox backend.
    WindowsSandbox,
    /// WSL container backend.
    Wslc,
}

impl Containment {
    /// Returns the exact registered spelling of this containment.
    pub const fn as_str(self) -> &'static str {
        match self {
            Containment::IsolationSession => "isolation_session",
            Containment::WindowsSandbox => "windows_sandbox",
            Containment::Wslc => "wslc",
        }
    }

    /// Looks up an exact registered state-aware phase.
    ///
    /// Returns `None` when `value` is not an exact supported spelling.
    pub fn parse_exact(value: &str) -> Option<Self> {
        match value {
            "isolation_session" => Some(Containment::IsolationSession),
            "windows_sandbox" => Some(Containment::WindowsSandbox),
            "wslc" => Some(Containment::Wslc),
            _ => None,
        }
    }
}

/// An error encountered while probing a configuration's state-aware phase.
#[derive(Debug, thiserror::Error)]
pub enum ContainmentProbeError {
    /// The document is malformed, repeats `containment`, or gives it a non-string
    /// value.
    #[error("Invalid containment declaration for provision phase")]
    InvalidDeclaration(#[source] serde_json::Error),
    /// The document declares a syntactically valid but unsupported containment value.
    ///
    /// The contained string is decoded user input and must be escaped before
    /// inclusion in terminal or log output.
    #[error("Unsupported containment for provision phase")]
    UnsupportedContainment(String),
}

use serde::Deserialize;
use std::borrow::Cow;

#[derive(Deserialize)]
struct ContainmentProbe<'a> {
    #[serde(borrow)]
    containment: Cow<'a, str>,
}

/// Reads the exact state-aware containment declared by a raw JSON configuration.
///
/// Fields other than `containment` are ignored. This function validates only the
/// containment declaration; it does not validate the selected contract's complete
/// structure.
///
/// # Errors
///
/// Returns [`ContainmentProbeError::InvalidDeclaration`] when the input is invalid
/// JSON, is missing `containment`, supplies `containment` more than once, or gives it a non-string value.
///
/// Returns [`ContainmentProbeError::UnsupportedContainment`] when `containment` is a valid
/// JSON string but is not an exact registered state-aware containment.
pub fn probe_containment(json: &str) -> Result<Containment, ContainmentProbeError> {
    let probe: ContainmentProbe<'_> =
        serde_json::from_str(json).map_err(ContainmentProbeError::InvalidDeclaration)?;
    Containment::parse_exact(&probe.containment).ok_or_else(|| {
        ContainmentProbeError::UnsupportedContainment(probe.containment.into_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_accepts_isolation_session() {
        let json = r#"{"containment": "isolation_session"}"#;
        assert_eq!(
            probe_containment(json).unwrap(),
            Containment::IsolationSession
        );
    }

    #[test]
    fn probe_accepts_windows_sandbox() {
        let json = r#"{"containment": "windows_sandbox"}"#;
        assert_eq!(
            probe_containment(json).unwrap(),
            Containment::WindowsSandbox
        );
    }

    #[test]
    fn probe_accepts_wslc() {
        let json = r#"{"containment": "wslc"}"#;
        assert_eq!(probe_containment(json).unwrap(), Containment::Wslc);
    }

    #[test]
    fn probe_ignores_unrelated_fields() {
        let json = r#"{
        "containment": "wslc",
        "process": {"command": "echo"}
    }"#;

        assert_eq!(probe_containment(json).unwrap(), Containment::Wslc);
    }

    #[test]
    fn probe_rejects_missing_containment() {
        let json = r#"{"version": "0.9.0-alpha"}"#;
        assert!(matches!(
            probe_containment(json),
            Err(ContainmentProbeError::InvalidDeclaration(_))
        ));
    }

    #[test]
    fn probe_rejects_multiple_fields() {
        let json = r#"{"containment": "isolation_session", "containment": "wslc"}"#;
        let result = probe_containment(json);
        assert!(matches!(
            result,
            Err(ContainmentProbeError::InvalidDeclaration(_))
        ));
    }

    #[test]
    fn probe_rejects_scalar_roots() {
        // Serde structs can also deserialize from positional arrays. Object-only
        // root enforcement is deferred.
        for json in [r#""wslc""#, "null", "42", "true"] {
            assert!(matches!(
                probe_containment(json),
                Err(ContainmentProbeError::InvalidDeclaration(_))
            ));
        }
    }

    #[test]
    fn probe_rejects_trailing_json() {
        let json = r#"{"containment":"wslc"} {}"#;

        assert!(matches!(
            probe_containment(json),
            Err(ContainmentProbeError::InvalidDeclaration(_))
        ));
    }

    #[test]
    fn probe_rejects_invalid_field_types() {
        for json in [
            r#"{"containment": 0.6}"#,                      // number
            r#"{"containment": {"major": 0, "minor": 6}}"#, // object
            r#"{"containment": ["wslc"]}"#,                 // array
            r#"{"containment": null}"#,                     // null
            r#"{"containment": true}"#,                     // boolean
        ] {
            assert!(matches!(
                probe_containment(json),
                Err(ContainmentProbeError::InvalidDeclaration(_))
            ));
        }
    }

    #[test]
    fn probe_reports_unrecognized_containment() {
        let json = r#"{"containment": "unknown"}"#;
        let result = probe_containment(json);
        assert!(matches!(
            result,
            Err(ContainmentProbeError::UnsupportedContainment(_))
        ));
    }

    #[test]
    fn probe_accepts_unicode_escaped_containment() {
        let json = r#"{"containment":"ws\u006cc"}"#;
        assert_eq!(probe_containment(json).unwrap(), Containment::Wslc);
    }

    #[test]
    fn probe_reports_decoded_unsupported_containment() {
        let json = r#"{"containment":"unkn\u006fwn"}"#;

        assert!(matches!(
            probe_containment(json),
            Err(ContainmentProbeError::UnsupportedContainment(containment))
                if containment == "unknown"
        ));
    }

    #[test]
    fn probe_rejects_invalid_json() {
        let json = r#"{"containment": "wslc""#; // Missing closing brace
        let result = probe_containment(json);
        assert!(matches!(
            result,
            Err(ContainmentProbeError::InvalidDeclaration(_))
        ));
    }
}
