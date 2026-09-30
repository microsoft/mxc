// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Serializable policy-negotiation data. Native evaluation and remediation belong
//! to the selected backend, not this module.

use serde::{Deserialize, Serialize};

/// How a caller handles a native creation-policy refusal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyEnforcementMode {
    #[default]
    PassThrough,
    Mutate,
}

impl<'de> Deserialize<'de> for PolicyEnforcementMode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            "pass-through" => Ok(Self::PassThrough),
            "mutate" => Ok(Self::Mutate),
            value => Err(serde::de::Error::unknown_variant(
                value,
                &["pass-through", "mutate"],
            )),
        }
    }
}

fn present_pass_through_mode<'de, D>(
    deserializer: D,
) -> Result<Option<PolicyEnforcementMode>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let mode = PolicyEnforcementMode::deserialize(deserializer)?;
    if mode != PolicyEnforcementMode::PassThrough {
        return Err(serde::de::Error::custom(
            "processContainer.policyEnforcement.mode must be pass-through",
        ));
    }
    Ok(Some(mode))
}

/// Optional settings retain presence until the backend applies execution defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyEnforcementOptions {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_pass_through_mode"
    )]
    pub mode: Option<PolicyEnforcementMode>,
}

impl PolicyEnforcementOptions {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.mode == Some(PolicyEnforcementMode::Mutate) {
            return Err("processContainer.policyEnforcement.mode must be pass-through");
        }
        Ok(())
    }
}

/// Raw native codes survive even when a newer OS supplies an unknown value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyResultCode {
    pub code: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl PolicyResultCode {
    pub fn new(code: u32, name: Option<&str>) -> Self {
        Self {
            code,
            name: name.map(str::to_owned),
        }
    }
}

/// One constraint from a bounded, non-exhaustive native policy result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePolicyDetail {
    pub failure_class: PolicyResultCode,
    pub failure_reason: PolicyResultCode,
    pub required_action: PolicyResultCode,
    pub resource_kind: PolicyResultCode,
    pub value_kind: PolicyResultCode,
    #[serde(with = "decimal_u64")]
    pub requested_value: u64,
    #[serde(with = "decimal_u64")]
    pub required_value: u64,
    pub flags: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    pub resource_offset_chars: u32,
    pub resource_chars_written: u32,
    pub resource_chars_required: u32,
}

/// An owned native result, independent of provisioning success. The returned
/// details are not an exhaustive inventory of policy conflicts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePolicyResult {
    pub version: u32,
    pub outcome: PolicyResultCode,
    pub details: Vec<NativePolicyDetail>,
    pub details_capacity: u32,
    pub details_count: u32,
    pub resource_capacity_chars: u32,
    pub resource_chars_written: u32,
    pub resource_chars_required: u32,
}

/// A change to a normalized configuration setting, not an original-source JSON patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyChange {
    pub setting: String,
    pub before: serde_json::Value,
    pub after: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyEnforcementAttempt {
    pub attempt: u8,
    pub hresult: String,
    pub result: NativePolicyResult,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<PolicyChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyEnforcementAvailability {
    Available,
    Unavailable,
    NotApplicable,
    NotEvaluated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyEnforcementTermination {
    Created,
    Ignored,
    Rejected,
    Unrepairable,
    NoProgress,
    AttemptLimit,
    EvaluationFailed,
    NativeFailure,
    InvalidResult,
}

/// Creation diagnostics retained on success and on every subsequent failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyEnforcementReport {
    #[serde(deserialize_with = "report_version")]
    pub report_version: u32,
    pub requested_mode: PolicyEnforcementMode,
    pub mode_applied: bool,
    pub availability: PolicyEnforcementAvailability,
    pub termination: PolicyEnforcementTermination,
    pub environment_created: bool,
    pub original_policy_hash: String,
    pub effective_policy_hash: String,
    pub attempts: Vec<PolicyEnforcementAttempt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl PolicyEnforcementReport {
    pub fn new(
        requested_mode: PolicyEnforcementMode,
        availability: PolicyEnforcementAvailability,
        policy_hash: String,
    ) -> Self {
        Self {
            report_version: 1,
            requested_mode,
            mode_applied: availability == PolicyEnforcementAvailability::Available,
            availability,
            termination: PolicyEnforcementTermination::Ignored,
            environment_created: false,
            original_policy_hash: policy_hash.clone(),
            effective_policy_hash: policy_hash,
            attempts: Vec::new(),
            message: None,
        }
    }
}

fn report_version<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let version = u32::deserialize(deserializer)?;
    if version != 1 {
        return Err(serde::de::Error::custom(
            "unsupported policy-enforcement report version",
        ));
    }
    Ok(version)
}

mod decimal_u64 {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(D::Error::custom(
                "expected an unsigned decimal uint64 string",
            ));
        }
        value.parse().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod policy_enforcement_tests {
    use super::*;

    #[test]
    fn optional_settings_preserve_presence_and_reject_mutation_inputs() {
        let omitted: PolicyEnforcementOptions = serde_json::from_str("{}").unwrap();
        assert_eq!(omitted.mode, None);
        assert!(omitted.validate().is_ok());
        for invalid in [
            r#"{"mode":null}"#,
            r#"{"maxAttempts":null}"#,
            r#"{"mode":"mutate"}"#,
            r#"{"maxAttempts":1}"#,
            r#"{"mode":"pass-through","maxAttempts":64}"#,
            r#"{"mode":{"mutate":null}}"#,
        ] {
            assert!(serde_json::from_str::<PolicyEnforcementOptions>(invalid).is_err());
        }
        let explicit: PolicyEnforcementOptions =
            serde_json::from_str(r#"{"mode":"pass-through"}"#).unwrap();
        assert_eq!(explicit.mode, Some(PolicyEnforcementMode::PassThrough));
        assert!(explicit.validate().is_ok());
        assert!(PolicyEnforcementOptions {
            mode: Some(PolicyEnforcementMode::Mutate),
        }
        .validate()
        .is_err());
    }

    #[test]
    fn native_values_and_unknown_codes_round_trip_losslessly() {
        let result = NativePolicyResult {
            version: 1,
            outcome: PolicyResultCode::new(999, None),
            details: vec![NativePolicyDetail {
                requested_value: u64::MAX,
                required_value: (1 << 53) + 1,
                ..Default::default()
            }],
            details_count: 1,
            ..Default::default()
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["details"][0]["requestedValue"], "18446744073709551615");
        assert_eq!(json["details"][0]["requiredValue"], "9007199254740993");
        assert_eq!(json["outcome"], serde_json::json!({ "code": 999 }));
        assert_eq!(
            serde_json::from_value::<NativePolicyResult>(json).unwrap(),
            result
        );
    }

    #[test]
    fn unavailable_is_not_a_native_no_applicable_policy_result() {
        let report = PolicyEnforcementReport::new(
            PolicyEnforcementMode::Mutate,
            PolicyEnforcementAvailability::Unavailable,
            "hash".into(),
        );
        assert!(!report.mode_applied);
        assert!(!report.environment_created);
        assert!(report.attempts.is_empty());
        assert_eq!(report.termination, PolicyEnforcementTermination::Ignored);
    }

    #[test]
    fn report_round_trips_and_requires_the_supported_version() {
        let report = PolicyEnforcementReport::new(
            PolicyEnforcementMode::PassThrough,
            PolicyEnforcementAvailability::Available,
            "hash".into(),
        );
        assert_eq!(report.report_version, 1);
        let mut value = serde_json::to_value(&report).unwrap();
        assert_eq!(
            serde_json::from_value::<PolicyEnforcementReport>(value.clone()).unwrap(),
            report
        );
        value["reportVersion"] = serde_json::json!(99);
        assert!(serde_json::from_value::<PolicyEnforcementReport>(value).is_err());
    }

    #[test]
    fn creation_report_survives_capture_metadata_merge_and_error_envelopes() {
        use crate::models::{
            CaptureDenialsErrorOutput, FailurePhase, SandboxOutputMetadata, ScriptResponse,
        };
        use crate::mxc_error::{ApiFailure, MxcError, MxcErrorCode};
        let report = PolicyEnforcementReport::new(
            PolicyEnforcementMode::Mutate,
            PolicyEnforcementAvailability::Available,
            "hash".into(),
        );
        let mut metadata = SandboxOutputMetadata::default();
        metadata.merge(SandboxOutputMetadata {
            capture_denials_error: Some(CaptureDenialsErrorOutput {
                message: "capture failed".into(),
                etl_path: "retained.etl".into(),
            }),
            ..Default::default()
        });
        assert!(metadata.capture_denials_error.is_some());
        let error = MxcError::policy_validation("blocked").with_api_failure(
            ApiFailure::new("CreateProcessSecurityEnvironment2").with_native_code("0x800704EC"),
        );
        let mut response = ScriptResponse::from_mxc_error(error, FailurePhase::Rejected)
            .with_policy_report(&report);
        response.output_metadata = Some(Box::new(metadata.into()));
        assert!(response
            .output_metadata
            .as_ref()
            .unwrap()
            .capture
            .capture_denials_error
            .is_some());
        let reconstructed = MxcError::from_envelope(*response.error.unwrap());
        assert_eq!(reconstructed.code, MxcErrorCode::PolicyValidation);
        assert_eq!(reconstructed.native_code(), Some("0x800704EC"));
        assert_eq!(
            reconstructed.details.unwrap()["policyEnforcement"],
            serde_json::json!(report)
        );
    }

    #[test]
    fn exact_development_controls_preserve_presence_and_old_contracts_reject_them() {
        use crate::config_parser::load_mxc_request_from_json;
        use crate::logger::{Logger, Mode};
        use crate::state_aware_request::MxcRequest;
        let document = |version: &str, settings: serde_json::Value| {
            serde_json::json!({
                "version": version, "containment": "processcontainer",
                "process": { "commandLine": "echo unused" },
                "processContainer": { "policyEnforcement": settings }
            })
            .to_string()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let parsed = load_mxc_request_from_json(
            &document("0.10.0-alpha", serde_json::json!({})),
            &mut logger,
        )
        .unwrap();
        let MxcRequest::OneShot(request) = parsed else {
            panic!("one-shot expected")
        };
        assert_eq!(
            request.policy.policy_enforcement,
            Some(PolicyEnforcementOptions::default())
        );
        for version in ["0.6.0-alpha", "0.7.0-alpha", "0.8.0-alpha", "0.9.0-alpha"] {
            assert!(load_mxc_request_from_json(
                &document(version, serde_json::json!({})),
                &mut logger
            )
            .is_err());
        }
        for settings in [
            serde_json::json!(null),
            serde_json::json!({"mode": null}),
            serde_json::json!({"mode": "guess"}),
            serde_json::json!({"mode": "mutate"}),
            serde_json::json!({"mode": {"mutate": null}}),
            serde_json::json!({"maxAttempts": 0}),
            serde_json::json!({"maxAttempts": 1}),
            serde_json::json!({"mode":"pass-through","maxAttempts":64}),
            serde_json::json!({"maxAttempts": 65}),
            serde_json::json!({"maxAttempts": 1.5}),
            serde_json::json!({"extra": true}),
        ] {
            assert!(
                load_mxc_request_from_json(&document("0.10.0-alpha", settings), &mut logger)
                    .is_err()
            );
        }
        for settings in [
            serde_json::json!({}),
            serde_json::json!({"mode":"pass-through"}),
        ] {
            assert!(
                load_mxc_request_from_json(&document("0.10.0-alpha", settings), &mut logger)
                    .is_ok()
            );
        }
    }
}
