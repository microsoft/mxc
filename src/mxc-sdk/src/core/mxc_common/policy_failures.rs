// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Owned creation-policy observations shared by the SDK adapters.

use serde::{Deserialize, Serialize};

use crate::core_modules::process_security_environment_policy_result::experimental_process_security_environment_policy_result as layout;

pub(crate) const MAX_POLICY_FAILURES_BYTES: usize = 4 * 1024 * 1024;
const MAX_STORED_POLICY_FAILURES_BYTES: usize = MAX_POLICY_FAILURES_BYTES + 512 * 1024;
pub(crate) const MAX_RESULTS: usize = 64;
pub(crate) const MAX_DETAILS: usize = 1024;
pub(crate) const MAX_RESOURCE_UNITS: usize = 262_144;
pub(crate) const MAX_DETAILS_PER_RESULT: usize = layout::PolicyResultLimit::MaxDetails.0 as usize;
/// UTF-16 units per native result, counting one terminator per resource.
pub(crate) const MAX_RESOURCE_UNITS_PER_RESULT: usize =
    layout::PolicyResultLimit::MaxResourceChars.0 as usize;

/// Creation-policy failures collected by the application, not a policy approval.
///
/// Observations are specific to the backend that reported them. Native Windows
/// ProcessContainer is currently the only backend that reports them.
/// Pass this value to V1.Dev policy preparation to propose supported
/// restrictive changes. The application owns acceptance, storage and retries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct PolicyFailures {
    /// Version of this MXC policy-failures format, independently of native versions.
    pub format_version: u32,
    /// Native refusal batches. Creation returns only the batches from that
    /// attempt; the application merges earlier ones.
    pub results: Vec<PolicyFailureResult>,
}

impl Default for PolicyFailures {
    fn default() -> Self {
        Self {
            format_version: Self::FORMAT_VERSION,
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
    /// Native policy-result version this SDK reads; the default `version`.
    pub const VERSION: u32 = layout::PolicyResultVersion::V1.0;
    /// Native minimum reader version this SDK reads; the default
    /// `minimum_reader_version`.
    pub const MINIMUM_READER_VERSION: u32 = layout::PolicyResultVersion::V1.0;

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
            version: Self::VERSION,
            minimum_reader_version: Self::MINIMUM_READER_VERSION,
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
    /// Native resource text without a terminator. An empty string differs from
    /// absence. Completeness is reported by [`Self::FLAG_RESOURCE_COMPLETE`].
    /// Invalid native UTF-16 is omitted and marked unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
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

    /// Count resource units plus one terminator for each present resource.
    fn resource_units_with_terminator(&self) -> usize {
        self.resource
            .as_ref()
            .map_or(0, |text| text.encode_utf16().count() + 1)
    }
}

impl PolicyFailures {
    /// Policy-failures format version this SDK reads and writes; the default
    /// `format_version`.
    pub const FORMAT_VERSION: u32 = 1;

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
        if self.format_version != Self::FORMAT_VERSION {
            return Err("unsupported policy failures formatVersion".into());
        }
        if self.results.len() > MAX_RESULTS + usize::from(terminal_result) {
            return Err("policy failures exceed the result limit".into());
        }
        let mut details = 0usize;
        let mut resources = 0usize;
        for result in &self.results {
            if result.details.len() > MAX_DETAILS_PER_RESULT {
                return Err("policy failures exceed the per-result detail limit".into());
            }
            details = details.saturating_add(result.details.len());
            let mut result_resources = 0usize;
            for detail in &result.details {
                result_resources =
                    result_resources.saturating_add(detail.resource_units_with_terminator());
            }
            if result_resources > MAX_RESOURCE_UNITS_PER_RESULT {
                return Err("policy failures exceed the per-result resource limit".into());
            }
            resources = resources.saturating_add(result_resources);
        }
        let (terminal_details, terminal_resources) = if terminal_result {
            (MAX_DETAILS_PER_RESULT, MAX_RESOURCE_UNITS_PER_RESULT)
        } else {
            (0, 0)
        };
        if details > MAX_DETAILS + terminal_details
            || resources > MAX_RESOURCE_UNITS + terminal_resources
        {
            return Err("policy failures exceed the total detail/resource limit".into());
        }
        let mut counter = SizeCounter {
            bytes: 0,
            limit: if terminal_result {
                MAX_STORED_POLICY_FAILURES_BYTES
            } else {
                MAX_POLICY_FAILURES_BYTES
            },
        };
        serde_json::to_writer(&mut counter, self)
            .map_err(|error| format!("invalid policy failures: {error}"))
    }

    pub(crate) fn parse(json: &str) -> Result<Self, String> {
        if json.len() > MAX_POLICY_FAILURES_BYTES {
            return Err("policy failures exceed the byte limit".into());
        }
        let failures: Self =
            serde_json::from_str(json).map_err(|_| "invalid policy failures JSON".to_owned())?;
        failures.validate()?;
        Ok(failures)
    }

    pub(crate) fn parse_stored(json: &str) -> Result<Self, String> {
        if json.len() > MAX_STORED_POLICY_FAILURES_BYTES {
            return Err("stored policy failures exceed the byte limit".into());
        }
        let failures: Self =
            serde_json::from_str(json).map_err(|_| "invalid policy failures JSON".to_owned())?;
        failures.validate_storage()?;
        Ok(failures)
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
                "policy failures exceed the byte limit",
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
    fn policy_failures_round_trip_preserves_large_values_unknown_codes_and_resources() {
        let detail = PolicyFailureDetail {
            failure_class: u32::MAX,
            requested_value: u64::MAX,
            required_value: 9_007_199_254_740_993,
            resource: Some("C:\\data\0".into()),
            ..Default::default()
        };
        let mut original = PolicyFailures::default();
        original.append(PolicyFailureResult {
            outcome: u32::MAX,
            details: vec![
                detail,
                PolicyFailureDetail {
                    resource: Some(String::new()),
                    ..Default::default()
                },
            ],
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
                resource: Some("C:\\work\\\u{1f600}".into()),
                ..Default::default()
            }],
            ..Default::default()
        });
        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("\"18446744073709551615\""));
        let value = serde_json::from_str::<serde_json::Value>(&json).unwrap();
        assert_eq!(value["results"][0]["details"][0]["resource"], "C:\\data\0");
        assert_eq!(value["results"][0]["details"][1]["resource"], "");
        assert_eq!(
            value["results"][1],
            serde_json::json!({
                "version": PolicyFailureResult::VERSION,
                "minimumReaderVersion": PolicyFailureResult::MINIMUM_READER_VERSION,
                "outcome": PolicyFailureResult::OUTCOME_BLOCKED,
                "details": [{
                    "failureClass": PolicyFailureDetail::CLASS_FILESYSTEM,
                    "failureReason": PolicyFailureDetail::REASON_ACCESS_EXCEEDS_CEILING,
                    "requiredAction": PolicyFailureDetail::ACTION_RESTRICT_FILESYSTEM_ACCESS,
                    "resourceKind": PolicyFailureDetail::RESOURCE_KIND_PATH,
                    "valueKind": PolicyFailureDetail::VALUE_KIND_ACCESS,
                    "flags": PolicyFailureDetail::FLAG_HAS_ACTIONABLE_DETAILS
                        | PolicyFailureDetail::FLAG_RESOURCE_COMPLETE,
                    "requestedValue": PolicyFailureDetail::ACCESS_READ_WRITE.to_string(),
                    "requiredValue": PolicyFailureDetail::ACCESS_READ_ONLY.to_string(),
                    "resource": "C:\\work\\\u{1f600}"
                }]
            })
        );
        assert_eq!(PolicyFailures::parse(&json).unwrap(), original);

        let mut nullable = serde_json::to_value(&original).unwrap();
        nullable["results"][0]["details"][0]["resource"] = serde_json::Value::Null;
        nullable["results"][0]["details"][1]["resource"] = serde_json::Value::Null;
        let restored = PolicyFailures::parse(&nullable.to_string()).unwrap();
        let mut absent = original;
        absent.results[0].details[0].resource = None;
        absent.results[0].details[1].resource = None;
        assert_eq!(restored, absent);
        let restored = serde_json::to_value(restored).unwrap();
        for detail in [
            &restored["results"][0]["details"][0],
            &restored["results"][0]["details"][1],
        ] {
            assert!(detail.get("resource").is_none());
        }
    }

    #[test]
    fn policy_failures_reject_non_string_and_malformed_resources() {
        let mut valid = serde_json::to_value(PolicyFailures {
            results: vec![PolicyFailureResult {
                details: vec![PolicyFailureDetail::default()],
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();
        for resource in [
            serde_json::json!([0x43, 0x3a]),
            serde_json::json!([]),
            serde_json::json!("\\ud800"),
            serde_json::json!("\\udc00"),
        ] {
            let detail = &mut valid["results"][0]["details"][0];
            detail["resource"] = resource;
            let json = valid.to_string().replace("\\\\ud", "\\ud");
            assert!(PolicyFailures::parse(&json).is_err(), "{json}");
        }
        let detail = valid["results"][0]["details"][0].as_object_mut().unwrap();
        detail.remove("resource");
        detail.insert("resourceUnits".into(), serde_json::json!([0xd800]));
        assert!(PolicyFailures::parse(&valid.to_string()).is_err());
    }

    #[test]
    fn policy_failures_reject_bad_versions_extra_fields_and_lossy_numbers() {
        let valid = serde_json::to_value(PolicyFailures {
            results: vec![PolicyFailureResult {
                outcome: PolicyFailureResult::OUTCOME_BLOCKED,
                details: vec![PolicyFailureDetail {
                    requested_value: PolicyFailureDetail::ACCESS_READ_WRITE,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();
        assert!(PolicyFailures::parse(&valid.to_string()).is_ok());

        let mut unsupported_version = valid.clone();
        unsupported_version["formatVersion"] = (PolicyFailures::FORMAT_VERSION + 1).into();
        let mut extra_field = valid.clone();
        extra_field["extra"] = true.into();
        let mut numeric_u64 = valid;
        numeric_u64["results"][0]["details"][0]["requestedValue"] =
            PolicyFailureDetail::ACCESS_READ_WRITE.into();
        for json in [unsupported_version, extra_field, numeric_u64] {
            assert!(PolicyFailures::parse(&json.to_string()).is_err(), "{json}");
        }
    }

    /// Blocked results that differ only by an index, so deduplication keeps all of them.
    fn distinct_blocked_results(count: usize) -> Vec<PolicyFailureResult> {
        (0..count as u64)
            .map(|index| PolicyFailureResult {
                outcome: PolicyFailureResult::OUTCOME_BLOCKED,
                details: vec![PolicyFailureDetail {
                    requested_value: index,
                    ..Default::default()
                }],
                ..Default::default()
            })
            .collect()
    }

    #[test]
    fn policy_failures_total_limits_are_not_silent_truncation() {
        let mut failures = PolicyFailures::default();
        for result in distinct_blocked_results(MAX_RESULTS + 1) {
            failures.append(result);
        }
        assert_eq!(failures.results.len(), MAX_RESULTS + 1);
        assert_eq!(
            failures.validate().unwrap_err(),
            "policy failures exceed the result limit"
        );
    }

    #[test]
    fn policy_failures_merge_is_owned_ordered_and_deduplicates_whole_batches() {
        let first = PolicyFailureResult {
            outcome: u32::MAX,
            details: vec![PolicyFailureDetail {
                requested_value: u64::MAX,
                resource: Some("C:\\data".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut second = first.clone();
        second.details[0].resource = Some(String::new());
        let old = PolicyFailures {
            results: vec![first.clone(), first.clone()],
            ..Default::default()
        };
        let new = PolicyFailures {
            results: vec![first.clone(), second.clone(), second.clone()],
            ..Default::default()
        };
        let old_snapshot = old.clone();
        let new_snapshot = new.clone();
        let merged = old.merged_with(&new).unwrap();
        assert_eq!(merged.results, [first, second]);
        assert_eq!(old, old_snapshot);
        assert_eq!(new, new_snapshot);
        assert_eq!(
            PolicyFailures::from_json(&merged.to_json().unwrap()).unwrap(),
            merged,
        );
        assert_eq!(merged.merged_with(&merged).unwrap(), merged);
    }

    #[test]
    fn policy_failures_merge_preserves_terminal_data_but_never_truncates_overflow() {
        let terminal = PolicyFailures {
            results: distinct_blocked_results(MAX_RESULTS + 1),
            ..Default::default()
        };
        let new = PolicyFailures {
            results: vec![PolicyFailureResult {
                outcome: u32::MAX,
                ..Default::default()
            }],
            ..Default::default()
        };
        let snapshot = terminal.clone();
        terminal.to_json().unwrap();
        assert!(terminal.validate().is_err());
        assert!(terminal.merged_with(&new).is_err());
        assert_eq!(terminal, snapshot);
        assert_eq!(new.results.len(), 1);
        assert_eq!(
            terminal.merged_with(&PolicyFailures::default()).unwrap(),
            terminal,
        );
        let invalid = PolicyFailures {
            format_version: PolicyFailures::FORMAT_VERSION + 1,
            ..Default::default()
        };
        assert!(invalid.merged_with(&new).is_err());
        assert!(new.merged_with(&invalid).is_err());
    }
}
