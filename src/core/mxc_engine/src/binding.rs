// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Internal policy parsing shared by language-binding adapters.

use crate::policy::SandboxPolicy;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TelemetrySection {
    enabled: bool,
}

#[derive(Default)]
struct OptionalTelemetrySection(Option<TelemetrySection>);

impl<'de> serde::Deserialize<'de> for OptionalTelemetrySection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <TelemetrySection as serde::Deserialize>::deserialize(deserializer)
            .map(|section| Self(Some(section)))
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyEnvelope {
    #[serde(flatten)]
    policy: SandboxPolicy,
    #[serde(default)]
    telemetry: OptionalTelemetrySection,
    #[serde(
        default,
        rename = "telemetryEnabled",
        deserialize_with = "reject_legacy_telemetry_enabled"
    )]
    _telemetry_enabled: (),
}

fn reject_legacy_telemetry_enabled<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    let _ = <serde::de::IgnoredAny as serde::Deserialize>::deserialize(deserializer)?;
    Err(serde::de::Error::custom(
        "telemetryEnabled is not supported; use telemetry.enabled",
    ))
}

fn validate_canonical_telemetry_version(envelope: &PolicyEnvelope) -> Result<(), String> {
    if envelope.telemetry.0.is_none() {
        return Ok(());
    }
    let Some(core) = envelope.policy.version.split(['-', '+']).next() else {
        return Ok(());
    };
    let mut components = core.split('.');
    let (Some(major), Some(minor), Some(patch), None) = (
        components.next(),
        components.next(),
        components.next(),
        components.next(),
    ) else {
        return Ok(());
    };
    let (Ok(major), Ok(minor), Ok(_patch)) = (
        major.parse::<u64>(),
        minor.parse::<u64>(),
        patch.parse::<u64>(),
    ) else {
        return Ok(());
    };
    if major == 0 && minor < 9 {
        return Err(
            "failed to parse policy JSON: top-level 'telemetry' requires config schema version \
             0.9.0-alpha or later"
                .to_string(),
        );
    }
    Ok(())
}

/// A policy decoded for a language-binding adapter.
#[derive(Debug)]
pub struct ParsedPolicy {
    pub policy: SandboxPolicy,
    pub telemetry_enabled: Option<bool>,
}

/// Parse SDK policy JSON through the native policy contract.
pub fn parse_policy_json(policy_json: &str) -> Result<ParsedPolicy, String> {
    let envelope: PolicyEnvelope = serde_json::from_str(policy_json)
        .map_err(|error| format!("failed to parse policy JSON: {error}"))?;
    validate_canonical_telemetry_version(&envelope)?;
    let telemetry_enabled = envelope
        .telemetry
        .0
        .as_ref()
        .map(|telemetry| telemetry.enabled);
    Ok(ParsedPolicy {
        policy: envelope.policy,
        telemetry_enabled,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn accepts_canonical_telemetry() {
        let parsed =
            super::parse_policy_json(r#"{"version":"0.9.0-alpha","telemetry":{"enabled":true}}"#)
                .expect("policy should parse");

        assert_eq!(parsed.policy.version, "0.9.0-alpha");
        assert_eq!(parsed.telemetry_enabled, Some(true));
    }

    #[test]
    fn rejects_canonical_telemetry_before_schema_09() {
        let error =
            super::parse_policy_json(r#"{"version":"0.8.0-alpha","telemetry":{"enabled":true}}"#)
                .expect_err("canonical telemetry must honor the native schema boundary");

        assert!(error.contains("requires config schema version 0.9.0-alpha"));
    }

    #[test]
    fn rejects_legacy_telemetry_alias() {
        let error =
            super::parse_policy_json(r#"{"version":"0.9.0-alpha","telemetryEnabled":true}"#)
                .expect_err("the legacy telemetry alias must be rejected");

        assert!(error.contains("telemetryEnabled"));
    }

    #[test]
    fn rejects_null_and_missing_telemetry_enabled() {
        for policy_json in [
            r#"{"version":"0.9.0-alpha","telemetry":null}"#,
            r#"{"version":"0.9.0-alpha","telemetry":{"enabled":null}}"#,
            r#"{"version":"0.9.0-alpha","telemetry":{}}"#,
        ] {
            assert!(
                super::parse_policy_json(policy_json).is_err(),
                "{policy_json} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_duplicate_fields() {
        for policy_json in [
            r#"{"version":"0.9.0-alpha","version":"0.9.0-alpha"}"#,
            r#"{"version":"0.9.0-alpha","telemetry":{"enabled":true},"telemetry":{"enabled":false}}"#,
            r#"{"version":"0.9.0-alpha","telemetry":{"enabled":true,"enabled":false}}"#,
        ] {
            assert!(
                super::parse_policy_json(policy_json).is_err(),
                "{policy_json} must be rejected"
            );
        }
    }
}
