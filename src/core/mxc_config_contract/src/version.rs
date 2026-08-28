// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// An exact MXC configuration contract version.
///
/// Versions are matched by their complete registered spelling. No semantic
/// version ranges or normalization are applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractVersion {
    /// The `0.6.0-alpha` contract.
    V0_6_0Alpha,
    /// The `0.7.0-alpha` contract.
    V0_7_0Alpha,
    /// The `0.8.0-alpha` contract.
    V0_8_0Alpha,
    /// The `0.9.0-alpha` development contract.
    V0_9_0Alpha,
}

impl ContractVersion {
    /// Returns the exact registered spelling of this contract version.
    pub const fn as_str(self) -> &'static str {
        match self {
            ContractVersion::V0_6_0Alpha => "0.6.0-alpha",
            ContractVersion::V0_7_0Alpha => "0.7.0-alpha",
            ContractVersion::V0_8_0Alpha => "0.8.0-alpha",
            ContractVersion::V0_9_0Alpha => "0.9.0-alpha",
        }
    }

    /// Looks up an exact registered contract version.
    ///
    /// Returns `None` when `value` is not an exact supported spelling.
    pub fn parse_exact(value: &str) -> Option<Self> {
        match value {
            "0.6.0-alpha" => Some(ContractVersion::V0_6_0Alpha),
            "0.7.0-alpha" => Some(ContractVersion::V0_7_0Alpha),
            "0.8.0-alpha" => Some(ContractVersion::V0_8_0Alpha),
            "0.9.0-alpha" => Some(ContractVersion::V0_9_0Alpha),
            _ => None,
        }
    }
}

/// An error encountered while probing a configuration's version declaration.
#[derive(Debug, thiserror::Error)]
pub enum VersionProbeError {
    /// The document is malformed or does not contain exactly one string-valued
    /// `version` field.
    #[error("Invalid version declaration")]
    InvalidDeclaration(#[source] serde_json::Error),
    /// The document declares a syntactically valid but unsupported version.
    ///
    /// The contained string is decoded user input and must be escaped before
    /// inclusion in terminal or log output.
    #[error("Unsupported version")]
    UnsupportedVersion(String),
}

use serde::Deserialize;
use std::borrow::Cow;

#[derive(Deserialize)]
struct VersionProbe<'a> {
    #[serde(borrow)]
    version: Cow<'a, str>,
}

/// Reads the exact contract version declared by a raw JSON configuration.
///
/// Fields other than `version` are ignored. This function validates only the
/// version declaration; it does not validate the selected contract's complete
/// structure.
///
/// # Errors
///
/// Returns [`VersionProbeError::InvalidDeclaration`] when the input is invalid
/// JSON, is not an object, omits `version`, supplies it more than once, or gives
/// it a non-string value.
///
/// Returns [`VersionProbeError::UnsupportedVersion`] when `version` is a valid
/// JSON string but is not an exact registered contract version.
pub fn probe_version(json: &str) -> Result<ContractVersion, VersionProbeError> {
    let probe: VersionProbe<'_> =
        serde_json::from_str(json).map_err(VersionProbeError::InvalidDeclaration)?;
    ContractVersion::parse_exact(&probe.version)
        .ok_or_else(|| VersionProbeError::UnsupportedVersion(probe.version.into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_accepts_0_6_0_alpha() {
        let json = r#"{"version": "0.6.0-alpha"}"#;
        let version = probe_version(json).unwrap();
        assert_eq!(version.as_str(), "0.6.0-alpha");
    }

    #[test]
    fn probe_accepts_0_7_0_alpha() {
        let json = r#"{"version": "0.7.0-alpha"}"#;
        let version = probe_version(json).unwrap();
        assert_eq!(version.as_str(), "0.7.0-alpha");
    }

    #[test]
    fn probe_accepts_0_8_0_alpha() {
        let json = r#"{"version": "0.8.0-alpha"}"#;
        let version = probe_version(json).unwrap();
        assert_eq!(version.as_str(), "0.8.0-alpha");
    }

    #[test]
    fn probe_accepts_0_9_0_alpha() {
        let json = r#"{"version": "0.9.0-alpha"}"#;
        let version = probe_version(json).unwrap();
        assert_eq!(version.as_str(), "0.9.0-alpha");
    }

    #[test]
    fn probe_ignores_unrelated_fields() {
        let json = r#"{
        "version": "0.6.0-alpha",
        "process": {"command": "echo"}
    }"#;

        assert_eq!(probe_version(json).unwrap(), ContractVersion::V0_6_0Alpha);
    }

    #[test]
    fn probe_rejects_missing_field() {
        let json = r#"{"not_version": "0.6.0-alpha"}"#;
        let result = probe_version(json);
        assert!(matches!(
            result,
            Err(VersionProbeError::InvalidDeclaration(_))
        ));
    }

    #[test]
    fn probe_rejects_multiple_fields() {
        let json = r#"{"version": "0.6.0-alpha", "version": "0.7.0-alpha"}"#;
        let result = probe_version(json);
        assert!(matches!(
            result,
            Err(VersionProbeError::InvalidDeclaration(_))
        ));
    }

    #[test]
    fn probe_rejects_non_object_root() {
        for json in [r#"[]"#, r#""0.6.0-alpha""#, "null", "42"] {
            assert!(matches!(
                probe_version(json),
                Err(VersionProbeError::InvalidDeclaration(_))
            ));
        }
    }

    #[test]
    fn probe_rejects_trailing_json() {
        let json = r#"{"version":"0.6.0-alpha"} {}"#;

        assert!(matches!(
            probe_version(json),
            Err(VersionProbeError::InvalidDeclaration(_))
        ));
    }

    #[test]
    fn probe_rejects_invalid_field_types() {
        for json in [
            r#"{"version": 0.6}"#,                      // number
            r#"{"version": {"major": 0, "minor": 6}}"#, // object
            r#"{"version": ["0.6.0-alpha"]}"#,          // array
            r#"{"version": null}"#,                     // null
            r#"{"version": true}"#,                     // boolean
        ] {
            assert!(matches!(
                probe_version(json),
                Err(VersionProbeError::InvalidDeclaration(_))
            ));
        }
    }

    #[test]
    fn probe_reports_unrecognized_0_6_2() {
        let json = r#"{"version": "0.6.2"}"#;
        let result = probe_version(json);
        assert!(matches!(
            result,
            Err(VersionProbeError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn probe_reports_unsupported_0_6_0_dev() {
        let json = r#"{"version": "0.6.0-dev"}"#;
        let result = probe_version(json);
        assert!(matches!(
            result,
            Err(VersionProbeError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn probe_rejects_invalid_json() {
        let json = r#"{"version": "0.6.0-alpha""#; // Missing closing brace
        let result = probe_version(json);
        assert!(matches!(
            result,
            Err(VersionProbeError::InvalidDeclaration(_))
        ));
    }

    #[test]
    fn probe_accepts_unicode_escaped_hyphen() {
        let json = r#"{"version":"0.6.0\u002dalpha"}"#;

        assert_eq!(probe_version(json).unwrap(), ContractVersion::V0_6_0Alpha);
    }

    #[test]
    fn probe_accepts_unicode_escaped_digit() {
        let json = r#"{"version":"\u0030.7.0-alpha"}"#;

        assert_eq!(probe_version(json).unwrap(), ContractVersion::V0_7_0Alpha);
    }

    #[test]
    fn probe_reports_escaped_unsupported_version() {
        let json = r#"{"version":"0.6.0-\u0062eta"}"#;

        assert!(matches!(
            probe_version(json),
            Err(VersionProbeError::UnsupportedVersion(version))
                if version == "0.6.0-beta"
        ));
    }
}
