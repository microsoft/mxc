// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Internal policy parsing shared by co-versioned language bindings.

use mxc_config_contract::ContractVersion;
use serde::de::{Error as _, IgnoredAny};
use serde::{Deserialize, Deserializer};

use crate::policy::{FilesystemSection, NetworkSection, SandboxPolicy, UiSection};
use crate::{Error, ErrorCode};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BindingPolicy {
    version: String,
    #[serde(default)]
    filesystem: Option<FilesystemSection>,
    #[serde(default)]
    network: Option<NetworkSection>,
    #[serde(default)]
    ui: Option<UiSection>,
    #[serde(default)]
    timeout_ms: Option<u32>,
    #[serde(
        default,
        rename = "captureDenials",
        deserialize_with = "reject_legacy_capture_denials"
    )]
    _capture_denials: (),
    #[serde(default)]
    telemetry: TelemetryField,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TelemetrySection {
    #[serde(default)]
    enabled: Option<bool>,
}

#[derive(Default)]
enum TelemetryField {
    #[default]
    Absent,
    Present(Option<TelemetrySection>),
}

impl<'de> Deserialize<'de> for TelemetryField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<TelemetrySection>::deserialize(deserializer).map(Self::Present)
    }
}

fn reject_legacy_capture_denials<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    IgnoredAny::deserialize(deserializer)?;
    Err(D::Error::custom(
        "policy.captureDenials is not supported; set containment.type to \
         processContainer and use containment.captureDenials",
    ))
}

fn malformed(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::MalformedRequest, message)
}

fn accepts_legacy_network_migration_fields(version: &str) -> bool {
    matches!(
        ContractVersion::parse_exact(version),
        Some(ContractVersion::V0_9_0Alpha | ContractVersion::V0_10_0Alpha)
    )
}

fn validate_telemetry_version(version: &str, telemetry: &TelemetryField) -> Result<(), Error> {
    if !matches!(telemetry, TelemetryField::Present(_)) {
        return Ok(());
    }
    if semver::Version::parse(version).is_ok_and(|version| version.major == 0 && version.minor < 9)
    {
        return Err(malformed(
            "policy.telemetry requires config schema version 0.9.0-alpha or later",
        ));
    }
    Ok(())
}

/// A policy decoded for a co-versioned language-binding adapter.
#[derive(Debug)]
pub struct ParsedPolicy {
    pub policy: SandboxPolicy,
    pub telemetry_enabled: Option<bool>,
}

/// Parse binding policy JSON through the native policy authoring model.
pub fn parse_policy_json(policy_json: &str) -> Result<ParsedPolicy, Error> {
    let mut deserializer = serde_json::Deserializer::from_str(policy_json);
    let mut ignored_paths = Vec::new();
    let policy: BindingPolicy = serde_ignored::deserialize(&mut deserializer, |path| {
        ignored_paths.push(path.to_string().replace(".?.", "."));
    })
    .map_err(|error| malformed(format!("failed to parse policy JSON: {error}")))?;
    deserializer
        .end()
        .map_err(|error| malformed(format!("failed to parse policy JSON: {error}")))?;

    let accepts_legacy_names = accepts_legacy_network_migration_fields(&policy.version);
    if let Some(path) = ignored_paths.iter().find(|path| {
        !(accepts_legacy_names
            && matches!(
                path.as_str(),
                "network.defaultPolicy" | "network.enforcementMode"
            ))
    }) {
        return Err(malformed(format!("unknown request field `policy.{path}`")));
    }

    validate_telemetry_version(&policy.version, &policy.telemetry)?;
    let telemetry_enabled = match policy.telemetry {
        TelemetryField::Absent | TelemetryField::Present(None) => None,
        TelemetryField::Present(Some(telemetry)) => telemetry.enabled,
    };
    Ok(ParsedPolicy {
        policy: SandboxPolicy {
            version: policy.version,
            filesystem: policy.filesystem,
            network: policy.network,
            ui: policy.ui,
            timeout_ms: policy.timeout_ms,
        },
        telemetry_enabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(policy: &str) -> ParsedPolicy {
        parse_policy_json(policy).unwrap_or_else(|error| panic!("{policy}: {error}"))
    }

    fn assert_malformed(policy: &str, expected: &str) {
        let error = parse_policy_json(policy).expect_err("policy must be rejected");
        assert_eq!(error.code, ErrorCode::MalformedRequest);
        assert!(
            error.message.contains(expected),
            "unexpected error for {policy}: {error}"
        );
    }

    #[test]
    fn telemetry_preserves_presence_and_optional_enabled_value() {
        for (telemetry, expected) in [
            ("", None),
            (r#","telemetry":null"#, None),
            (r#","telemetry":{}"#, None),
            (r#","telemetry":{"enabled":null}"#, None),
            (r#","telemetry":{"enabled":true}"#, Some(true)),
            (r#","telemetry":{"enabled":false}"#, Some(false)),
        ] {
            let policy = format!(r#"{{"version":"0.9.0-alpha"{telemetry}}}"#);
            assert_eq!(parse(&policy).telemetry_enabled, expected);
        }
    }

    #[test]
    fn every_present_telemetry_shape_requires_schema_09() {
        for telemetry in ["null", "{}", r#"{"enabled":null}"#, r#"{"enabled":true}"#] {
            let policy = format!(r#"{{"version":"0.8.0-alpha","telemetry":{telemetry}}}"#);
            assert_malformed(&policy, "requires config schema version 0.9.0-alpha");
        }
    }

    #[test]
    fn semver_valid_pre_09_versions_preserve_the_telemetry_diagnostic() {
        for version in ["0.8.0", "0.8.1-alpha"] {
            assert_malformed(
                &format!(r#"{{"version":"{version}","telemetry":null}}"#),
                "requires config schema version 0.9.0-alpha",
            );
        }
    }

    #[test]
    fn unsupported_post_09_versions_are_deferred_to_the_exact_policy_builder() {
        let parsed = parse(r#"{"version":"0.11.0","telemetry":{"enabled":true}}"#);
        assert_eq!(parsed.policy.version, "0.11.0");
        assert_eq!(parsed.telemetry_enabled, Some(true));
    }

    #[test]
    fn duplicate_fields_are_rejected() {
        for policy in [
            r#"{"version":"0.9.0-alpha","version":"0.9.0-alpha"}"#,
            r#"{"version":"0.9.0-alpha","telemetry":null,"telemetry":null}"#,
            r#"{"version":"0.9.0-alpha","telemetry":{"enabled":true,"enabled":false}}"#,
            r#"{"version":"0.9.0-alpha","network":{},"network":{}}"#,
        ] {
            assert_malformed(policy, "duplicate field");
        }
    }

    #[test]
    fn policy_specific_diagnostics_are_preserved() {
        assert_malformed(
            r#"{"version":"0.9.0-alpha","captureDenials":{}}"#,
            "policy.captureDenials is not supported",
        );
        assert_malformed(
            r#"{"version":"0.9.0-alpha","filesystem":{"unexpected":true}}"#,
            "policy.filesystem.unexpected",
        );
        assert_malformed(
            r#"{"version":"0.9.0-alpha","telemetry":{"unexpected":true}}"#,
            "unknown field `unexpected`",
        );
    }

    #[test]
    fn legacy_network_names_reach_registered_migration_validation() {
        for version in ["0.9.0-alpha", "0.10.0-alpha"] {
            let parsed = parse(&format!(
                r#"{{"version":"{version}","network":{{"defaultPolicy":"allow","enforcementMode":"capabilities"}}}}"#
            ));
            assert!(parsed.policy.network.is_some());
        }
        assert_malformed(
            r#"{"version":"0.8.0-alpha","network":{"defaultPolicy":"allow"}}"#,
            "policy.network.defaultPolicy",
        );
    }

    #[test]
    fn repeated_wire_only_network_names_preserve_existing_tolerance() {
        parse(
            r#"{"version":"0.9.0-alpha","network":{"defaultPolicy":"allow","defaultPolicy":"deny"}}"#,
        );
    }
}
