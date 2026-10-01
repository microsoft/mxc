// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Lifecycle phase declared by a state-aware configuration request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Provision a new sandbox.
    Provision,
    /// Start a provisioned sandbox.
    Start,
    /// Execute a process in a started sandbox.
    Exec,
    /// Stop a started sandbox without deprovisioning it.
    Stop,
    /// Release a provisioned sandbox and its resources.
    Deprovision,
}

impl Phase {
    /// Returns the exact registered spelling of this phase.
    pub const fn as_str(self) -> &'static str {
        match self {
            Phase::Provision => "provision",
            Phase::Start => "start",
            Phase::Exec => "exec",
            Phase::Stop => "stop",
            Phase::Deprovision => "deprovision",
        }
    }

    /// Looks up an exact registered state-aware phase.
    ///
    /// Returns `None` when `value` is not an exact supported spelling.
    pub fn parse_exact(value: &str) -> Option<Self> {
        match value {
            "provision" => Some(Phase::Provision),
            "start" => Some(Phase::Start),
            "exec" => Some(Phase::Exec),
            "stop" => Some(Phase::Stop),
            "deprovision" => Some(Phase::Deprovision),
            _ => None,
        }
    }
}

/// An error encountered while probing a configuration's state-aware phase.
#[derive(Debug, thiserror::Error)]
pub enum PhaseProbeError {
    /// The document is malformed, repeats `phase`, or gives it a non-string
    /// value.
    #[error("Invalid phase declaration")]
    InvalidDeclaration(#[source] serde_json::Error),
    /// The document declares a syntactically valid but unsupported phase.
    ///
    /// The contained string is decoded user input and must be escaped before
    /// inclusion in terminal or log output.
    #[error("Unsupported phase")]
    UnsupportedPhase(String),
}

use serde::{Deserialize, Deserializer};
use std::borrow::Cow;

#[derive(Deserialize)]
struct PhaseProbe<'a> {
    #[serde(borrow, default, deserialize_with = "deserialize_present_phase")]
    phase: Option<Cow<'a, str>>,
}

fn deserialize_present_phase<'de, D>(deserializer: D) -> Result<Option<Cow<'de, str>>, D::Error>
where
    D: Deserializer<'de>,
{
    Cow::deserialize(deserializer).map(Some)
}

/// Reads the exact state-aware phase declared by a raw JSON configuration.
///
/// Fields other than `phase` are ignored. This function validates only the
/// phase declaration; it does not validate the selected contract's complete
/// structure.
///
/// # Errors
///
/// Returns [`PhaseProbeError::InvalidDeclaration`] when the input is invalid
/// JSON, supplies `phase` more than once, or gives it a non-string value.
///
/// Returns [`PhaseProbeError::UnsupportedPhase`] when `phase` is a valid
/// JSON string but is not an exact registered state-aware phase.
pub fn probe_phase(json: &str) -> Result<Option<Phase>, PhaseProbeError> {
    let probe: PhaseProbe<'_> =
        serde_json::from_str(json).map_err(PhaseProbeError::InvalidDeclaration)?;

    let Some(value) = probe.phase else {
        return Ok(None);
    };

    Phase::parse_exact(&value)
        .map(Some)
        .ok_or_else(|| PhaseProbeError::UnsupportedPhase(value.into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_accepts_provision() {
        let json = r#"{"phase": "provision"}"#;
        let phase = probe_phase(json).unwrap();
        assert_eq!(phase.unwrap().as_str(), "provision");
    }

    #[test]
    fn probe_accepts_start() {
        let json = r#"{"phase": "start"}"#;
        let phase = probe_phase(json).unwrap();
        assert_eq!(phase.unwrap().as_str(), "start");
    }

    #[test]
    fn probe_accepts_exec() {
        let json = r#"{"phase": "exec"}"#;
        let phase = probe_phase(json).unwrap();
        assert_eq!(phase.unwrap().as_str(), "exec");
    }

    #[test]
    fn probe_accepts_stop() {
        let json = r#"{"phase": "stop"}"#;
        let phase = probe_phase(json).unwrap();
        assert_eq!(phase.unwrap().as_str(), "stop");
    }

    #[test]
    fn probe_accepts_deprovision() {
        let json = r#"{"phase": "deprovision"}"#;
        let phase = probe_phase(json).unwrap();
        assert_eq!(phase.unwrap().as_str(), "deprovision");
    }

    #[test]
    fn probe_ignores_unrelated_fields() {
        let json = r#"{
        "phase": "provision",
        "process": {"command": "echo"}
    }"#;

        assert_eq!(probe_phase(json).unwrap().unwrap().as_str(), "provision");
    }

    #[test]
    fn probe_accepts_missing_field() {
        let json = r#"{"not_phase": "somevalue"}"#;
        assert_eq!(probe_phase(json).unwrap(), None);
    }

    #[test]
    fn probe_rejects_multiple_fields() {
        let json = r#"{"phase": "provision", "phase": "start"}"#;
        let result = probe_phase(json);
        assert!(matches!(
            result,
            Err(PhaseProbeError::InvalidDeclaration(_))
        ));
    }

    #[test]
    fn probe_rejects_scalar_roots() {
        // Serde structs can also deserialize from positional arrays. Object-only
        // root enforcement is deferred.
        for json in [r#""start""#, "null", "42", "true"] {
            assert!(matches!(
                probe_phase(json),
                Err(PhaseProbeError::InvalidDeclaration(_))
            ));
        }
    }

    #[test]
    fn probe_rejects_trailing_json() {
        let json = r#"{"phase":"provision"} {}"#;

        assert!(matches!(
            probe_phase(json),
            Err(PhaseProbeError::InvalidDeclaration(_))
        ));
    }

    #[test]
    fn probe_rejects_invalid_field_types() {
        for json in [
            r#"{"phase": 0.6}"#,                      // number
            r#"{"phase": {"major": 0, "minor": 6}}"#, // object
            r#"{"phase": ["provision"]}"#,            // array
            r#"{"phase": null}"#,                     // null
            r#"{"phase": true}"#,                     // boolean
        ] {
            assert!(matches!(
                probe_phase(json),
                Err(PhaseProbeError::InvalidDeclaration(_))
            ));
        }
    }

    #[test]
    fn probe_reports_unrecognized_phase() {
        let json = r#"{"phase": "preprovision"}"#;
        let result = probe_phase(json);
        assert!(matches!(result, Err(PhaseProbeError::UnsupportedPhase(_))));
    }

    #[test]
    fn probe_accepts_unicode_escaped_phase() {
        let json = r#"{"phase":"provis\u0069on"}"#;

        assert_eq!(probe_phase(json).unwrap(), Some(Phase::Provision));
    }

    #[test]
    fn probe_reports_decoded_unsupported_phase() {
        let json = r#"{"phase":"pre\u0070rovision"}"#;

        assert!(matches!(
            probe_phase(json),
            Err(PhaseProbeError::UnsupportedPhase(phase))
                if phase == "preprovision"
        ));
    }

    #[test]
    fn probe_rejects_invalid_json() {
        let json = r#"{"phase": "provision""#; // Missing closing brace
        let result = probe_phase(json);
        assert!(matches!(
            result,
            Err(PhaseProbeError::InvalidDeclaration(_))
        ));
    }
}
