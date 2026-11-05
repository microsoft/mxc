// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Owned creation-policy observations shared by the SDK adapters.

use serde::{Deserialize, Serialize};

pub(crate) const FORMAT_VERSION: u32 = 1;
pub(crate) const MAX_FEEDBACK_BYTES: usize = 4 * 1024 * 1024;
const MAX_STORED_FEEDBACK_BYTES: usize = MAX_FEEDBACK_BYTES + 512 * 1024;
pub(crate) const MAX_RESULTS: usize = 64;
pub(crate) const MAX_DETAILS: usize = 1024;
pub(crate) const MAX_RESOURCE_UNITS: usize = 262_144;

/// Cumulative Windows creation-policy failures, not a policy approval.
///
/// Pass this value through V1.Dev creation options to authorize supported
/// restrictive changes. The application owns its storage and retry policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct PolicyFailures {
    /// Version of this MXC feedback format, independently of native versions.
    pub format_version: u32,
    /// Distinct native refusal batches observed across calls.
    pub results: Vec<PolicyFailureResult>,
}

impl Default for PolicyFailures {
    fn default() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            results: Vec::new(),
        }
    }
}

/// One native policy-result batch. Its details are non-exhaustive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct PolicyFailureResult {
    /// Native PSEP contract version.
    pub version: u32,
    /// Minimum native reader version.
    pub minimum_reader_version: u32,
    /// Native outcome; compare with the `OUTCOME_*` associated constants.
    /// Unrecognized numeric values are preserved.
    pub outcome: u32,
    /// Details belonging to this native batch.
    pub details: Vec<PolicyFailureDetail>,
}

impl PolicyFailureResult {
    /// Unspecified outcome, not a policy approval.
    pub const OUTCOME_UNKNOWN: u32 = 0;
    /// Creation was blocked by policy.
    pub const OUTCOME_BLOCKED: u32 = 1;
    /// Policy evaluation failed.
    pub const OUTCOME_EVALUATION_FAILED: u32 = 2;
}

impl Default for PolicyFailureResult {
    fn default() -> Self {
        Self {
            version: 1,
            minimum_reader_version: 1,
            outcome: Self::OUTCOME_UNKNOWN,
            details: Vec::new(),
        }
    }
}

/// A native policy failure. Numeric discriminators and flags retain unknown values.
///
/// `requested_value` is an observation about the request Windows evaluated,
/// not necessarily the request supplied to a subsequent call.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct PolicyFailureDetail {
    /// Native domain; compare with the `CLASS_*` associated constants.
    pub failure_class: u32,
    /// Native cause; compare with the `REASON_*` associated constants.
    pub failure_reason: u32,
    /// Suggested change; compare with the `ACTION_*` associated constants.
    pub required_action: u32,
    /// Resource category; compare with the `RESOURCE_KIND_*` associated constants.
    pub resource_kind: u32,
    /// Value category; compare with the `VALUE_KIND_*` associated constants.
    pub value_kind: u32,
    /// Native bitmask; inspect the `FLAG_*` associated constants.
    pub flags: u32,
    /// Decimal string in JSON, so all `u64` values survive JavaScript storage.
    #[serde(with = "decimal_u64")]
    pub requested_value: u64,
    /// Decimal string in JSON, so all `u64` values survive JavaScript storage.
    #[serde(with = "decimal_u64")]
    pub required_value: u64,
    /// Native UTF-16 resource units without a terminator. Absence, empty data,
    /// and malformed UTF-16 remain distinguishable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Vec<u16>>,
}

impl PolicyFailureDetail {
    /// No policy domain specified.
    pub const CLASS_NONE: u32 = 0;
    /// Network policy.
    pub const CLASS_NETWORK: u32 = 1;
    /// Filesystem policy.
    pub const CLASS_FILESYSTEM: u32 = 2;
    /// Enforcement-mode policy.
    pub const CLASS_ENFORCEMENT_MODE: u32 = 3;

    /// No failure reason specified.
    pub const REASON_NONE: u32 = 0;
    /// A requested capability is not allowed.
    pub const REASON_CAPABILITY_NOT_ALLOWED: u32 = 1;
    /// Requested access exceeds the policy ceiling.
    pub const REASON_ACCESS_EXCEEDS_CEILING: u32 = 2;
    /// Policy requires a deny entry.
    pub const REASON_DENY_REQUIRED: u32 = 3;
    /// The request exceeds the policy path limit.
    pub const REASON_REQUEST_PATH_LIMIT: u32 = 4;

    /// No request change suggested.
    pub const ACTION_NONE: u32 = 0;
    /// Remove a requested capability.
    pub const ACTION_REMOVE_CAPABILITY: u32 = 1;
    /// Restrict requested filesystem access.
    pub const ACTION_RESTRICT_FILESYSTEM_ACCESS: u32 = 2;
    /// Reduce the requested path count.
    pub const ACTION_REDUCE_PATH_COUNT: u32 = 3;

    /// No resource category specified.
    pub const RESOURCE_KIND_NONE: u32 = 0;
    /// A filesystem path.
    pub const RESOURCE_KIND_PATH: u32 = 1;
    /// A capability name.
    pub const RESOURCE_KIND_CAPABILITY: u32 = 2;

    /// No value category specified.
    pub const VALUE_KIND_NONE: u32 = 0;
    /// Values describe access; compare with the `ACCESS_*` associated constants.
    pub const VALUE_KIND_ACCESS: u32 = 1;
    /// Values describe path counts.
    pub const VALUE_KIND_PATH_COUNT: u32 = 2;

    /// No access, when `value_kind` is [`Self::VALUE_KIND_ACCESS`].
    pub const ACCESS_NONE: u64 = 0;
    /// Read-only access, when `value_kind` is [`Self::VALUE_KIND_ACCESS`].
    pub const ACCESS_READ_ONLY: u64 = 1;
    /// Read-write access, when `value_kind` is [`Self::VALUE_KIND_ACCESS`].
    pub const ACCESS_READ_WRITE: u64 = 2;

    /// No flags set.
    pub const FLAG_NONE: u32 = 0;
    /// A typed remedy is identified, not necessarily safe or available.
    pub const FLAG_HAS_ACTIONABLE_DETAILS: u32 = 1;
    /// The resource text is complete.
    pub const FLAG_RESOURCE_COMPLETE: u32 = 2;
    /// The resource text is unavailable.
    pub const FLAG_RESOURCE_UNAVAILABLE: u32 = 4;

    /// Decode resource text without replacing malformed UTF-16.
    ///
    /// This does not establish that the resource is complete or actionable;
    /// those conditions are validated again when feedback is applied.
    pub fn resource_text(&self) -> Result<Option<String>, std::string::FromUtf16Error> {
        self.resource.as_deref().map(String::from_utf16).transpose()
    }
}

impl PolicyFailures {
    /// Policy-refusal HRESULT as represented by an SDK error's `native_code`.
    ///
    /// This is `HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY)`.
    pub const NATIVE_CODE_POLICY_BLOCKED: &str = "0x800704EC";

    pub(crate) fn validate(&self) -> Result<(), String> {
        self.validate_limits(false)
    }

    pub(crate) fn validate_storage(&self) -> Result<(), String> {
        self.validate_limits(true)
    }

    fn validate_limits(&self, terminal_result: bool) -> Result<(), String> {
        if self.format_version != FORMAT_VERSION {
            return Err("unsupported policy-failure feedback formatVersion".into());
        }
        if self.results.len() > MAX_RESULTS + usize::from(terminal_result) {
            return Err("policy-failure feedback exceeds the result limit".into());
        }
        let mut details = 0usize;
        let mut resources = 0usize;
        for result in &self.results {
            if result.details.len() > 64 {
                return Err("policy-failure feedback exceeds the per-result detail limit".into());
            }
            details = details.saturating_add(result.details.len());
            let mut result_resources = 0usize;
            for detail in &result.details {
                if let Some(resource) = &detail.resource {
                    result_resources = result_resources.saturating_add(resource.len() + 1);
                }
            }
            if result_resources > 32_768 {
                return Err("policy-failure feedback exceeds the per-result resource limit".into());
            }
            resources = resources.saturating_add(result_resources);
        }
        if details > MAX_DETAILS + if terminal_result { 64 } else { 0 }
            || resources > MAX_RESOURCE_UNITS + if terminal_result { 32_768 } else { 0 }
        {
            return Err(
                "policy-failure feedback exceeds its cumulative detail/resource limit".into(),
            );
        }
        let mut counter = SizeCounter {
            bytes: 0,
            limit: if terminal_result {
                MAX_STORED_FEEDBACK_BYTES
            } else {
                MAX_FEEDBACK_BYTES
            },
        };
        serde_json::to_writer(&mut counter, self)
            .map_err(|error| format!("invalid policy-failure feedback: {error}"))
    }

    pub(crate) fn parse(json: &str) -> Result<Self, String> {
        if json.len() > MAX_FEEDBACK_BYTES {
            return Err("policy-failure feedback exceeds its byte limit".into());
        }
        let feedback: Self = serde_json::from_str(json)
            .map_err(|_| "invalid policy-failure feedback JSON".to_owned())?;
        feedback.validate()?;
        Ok(feedback)
    }

    pub(crate) fn parse_stored(json: &str) -> Result<Self, String> {
        if json.len() > MAX_STORED_FEEDBACK_BYTES {
            return Err("stored policy-failure feedback exceeds its byte limit".into());
        }
        let feedback: Self = serde_json::from_str(json)
            .map_err(|_| "invalid policy-failure feedback JSON".to_owned())?;
        feedback.validate_storage()?;
        Ok(feedback)
    }

    /// Append without dropping native information. A caller of this internal
    /// helper must report a resulting limit violation instead of truncating it.
    #[cfg(any(target_os = "windows", test))]
    pub(crate) fn append(&mut self, result: PolicyFailureResult) {
        if !self.results.contains(&result) {
            self.results.push(result);
        }
    }
}

struct SizeCounter {
    bytes: usize,
    limit: usize,
}

impl std::io::Write for SizeCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.saturating_add(bytes.len());
        if self.bytes > self.limit {
            return Err(std::io::Error::other(
                "policy-failure feedback exceeds its byte limit",
            ));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(serde::de::Error::custom(
                "expected an unsigned decimal string",
            ));
        }
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_feedback_round_trip_preserves_large_values_unknown_codes_and_utf16() {
        let detail = PolicyFailureDetail {
            failure_class: u32::MAX,
            requested_value: u64::MAX,
            required_value: 9_007_199_254_740_993,
            resource: Some(vec![0xd800, 0]),
            ..Default::default()
        };
        assert!(detail.resource_text().is_err());
        let mut original = PolicyFailures::default();
        original.append(PolicyFailureResult {
            outcome: u32::MAX,
            details: vec![detail],
            ..Default::default()
        });
        original.append(PolicyFailureResult {
            outcome: PolicyFailureResult::OUTCOME_BLOCKED,
            details: vec![PolicyFailureDetail {
                failure_class: PolicyFailureDetail::CLASS_FILESYSTEM,
                failure_reason: PolicyFailureDetail::REASON_ACCESS_EXCEEDS_CEILING,
                required_action: PolicyFailureDetail::ACTION_RESTRICT_FILESYSTEM_ACCESS,
                resource_kind: PolicyFailureDetail::RESOURCE_KIND_PATH,
                value_kind: PolicyFailureDetail::VALUE_KIND_ACCESS,
                flags: PolicyFailureDetail::FLAG_HAS_ACTIONABLE_DETAILS
                    | PolicyFailureDetail::FLAG_RESOURCE_COMPLETE,
                requested_value: PolicyFailureDetail::ACCESS_READ_WRITE,
                required_value: PolicyFailureDetail::ACCESS_READ_ONLY,
                ..Default::default()
            }],
            ..Default::default()
        });
        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("\"18446744073709551615\""));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap()["results"][1],
            serde_json::json!({
                "version": 1, "minimumReaderVersion": 1, "outcome": 1,
                "details": [{
                    "failureClass": 2, "failureReason": 2, "requiredAction": 2,
                    "resourceKind": 1, "valueKind": 1, "flags": 3,
                    "requestedValue": "2", "requiredValue": "1"
                }]
            })
        );
        assert_eq!(PolicyFailures::parse(&json).unwrap(), original);

        let mut nullable = serde_json::to_value(&original).unwrap();
        nullable["results"][0]["details"][0]["resource"] = serde_json::Value::Null;
        let restored = PolicyFailures::parse(&nullable.to_string()).unwrap();
        let mut absent = original;
        absent.results[0].details[0].resource = None;
        assert_eq!(restored, absent);
        assert!(
            serde_json::to_value(restored).unwrap()["results"][0]["details"][0]
                .get("resource")
                .is_none()
        );
    }

    #[test]
    fn policy_feedback_rejects_bad_versions_extra_fields_and_lossy_numbers() {
        for json in [
            r#"{"formatVersion":2,"results":[]}"#,
            r#"{"formatVersion":1,"results":[],"extra":true}"#,
            r#"{"formatVersion":1,"results":[{"version":1,"minimumReaderVersion":1,"outcome":1,"details":[{"failureClass":2,"failureReason":2,"requiredAction":2,"resourceKind":1,"valueKind":1,"flags":3,"requestedValue":2,"requiredValue":"1"}]}]}"#,
        ] {
            assert!(PolicyFailures::parse(json).is_err(), "{json}");
        }
    }

    #[test]
    fn policy_feedback_cumulative_limits_are_not_silent_truncation() {
        let mut feedback = PolicyFailures::default();
        for outcome in 0..=MAX_RESULTS as u32 {
            feedback.append(PolicyFailureResult {
                outcome,
                ..Default::default()
            });
        }
        assert_eq!(feedback.results.len(), MAX_RESULTS + 1);
        assert!(feedback.validate().is_err());
    }
}
