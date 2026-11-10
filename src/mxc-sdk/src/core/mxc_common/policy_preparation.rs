// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Owned candidate-request and change data for policy preparation.

use crate::mxc_common::mxc_error::MxcError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_RESULT_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAX_CHANGES: usize = 4096;

/// How a preparation change affects a JSON location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum PolicyChangeOperation {
    /// The location was absent and is added.
    Add,
    /// The location was present and is removed.
    Remove,
    /// A present value is replaced, including a present JSON null.
    Replace,
}

/// One change to the caller's MXC request JSON.
///
/// `path` is a JSON Pointer. Both values are present in the change JSON:
/// `before` is null for Add and `after` is null for Remove. The operation
/// distinguishes these absent locations from a replaced, present JSON null.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct PolicyChange {
    /// Addition, removal or replacement of this location.
    pub operation: PolicyChangeOperation,
    /// JSON Pointer identifying the changed location.
    pub path: String,
    /// Original value, or null for an added location.
    #[serde(deserialize_with = "required_value")]
    pub before: Value,
    /// Candidate value, or null for a removed location.
    #[serde(deserialize_with = "required_value")]
    pub after: Value,
}

// The field deserializer rejects absence instead of treating a missing Value as JSON null.
fn required_value<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
    Value::deserialize(deserializer)
}

/// A candidate request, not a created container or policy approval.
///
/// Inspect, accept, edit or reject `request_json`, then submit the chosen JSON
/// through an ordinary strict creation API. Preparation owns no live handles.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct PreparedPolicyRequest {
    /// Complete MXC request JSON in the caller's original contract.
    pub request_json: String,
    /// Structured changes from the original JSON to this candidate.
    pub changes: Vec<PolicyChange>,
}

impl PreparedPolicyRequest {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.changes.len() > MAX_CHANGES {
            return Err("policy preparation exceeds its change limit".into());
        }
        if self.request_json.len() > MAX_RESULT_BYTES {
            return Err("policy preparation exceeds its result byte limit".into());
        }
        if !serde_json::from_str::<Value>(&self.request_json)
            .map_err(|_| "prepared request is not valid JSON".to_owned())?
            .is_object()
        {
            return Err("prepared request must be a JSON object".into());
        }
        for change in &self.changes {
            if (!change.path.is_empty() && !change.path.starts_with('/'))
                || change
                    .path
                    .split('~')
                    .skip(1)
                    .any(|tail| !tail.starts_with('0') && !tail.starts_with('1'))
                || matches!(change.operation, PolicyChangeOperation::Add)
                    && !change.before.is_null()
                || matches!(change.operation, PolicyChangeOperation::Remove)
                    && !change.after.is_null()
            {
                return Err("invalid policy preparation change".into());
            }
        }
        serde_json::to_writer(&mut ResultSizeCounter::default(), self)
            .map_err(|_| "policy preparation exceeds its result byte limit".to_owned())
    }

    pub(crate) fn parse(json: &str) -> Result<Self, String> {
        if json.len() > MAX_RESULT_BYTES {
            return Err("policy preparation exceeds its result byte limit".into());
        }
        let result: Self =
            serde_json::from_str(json).map_err(|_| "invalid policy preparation JSON".to_owned())?;
        result.validate()?;
        Ok(result)
    }
}

/// Append the changes from `before` to `after` at JSON Pointer `path`.
/// Objects are compared member by member; any other differing value,
/// including an array, is one change.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn collect_changes(
    path: &str,
    before: Option<&Value>,
    after: Option<&Value>,
    changes: &mut Vec<PolicyChange>,
) -> Result<(), MxcError> {
    if before == after {
        return Ok(());
    }
    if let (Some(Value::Object(old)), Some(Value::Object(new))) = (before, after) {
        let keys: std::collections::BTreeSet<_> = old.keys().chain(new.keys()).collect();
        for key in keys {
            let pointer = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
            collect_changes(&pointer, old.get(key), new.get(key), changes)?;
        }
        return Ok(());
    }
    if changes.len() >= MAX_CHANGES {
        return Err(MxcError::policy_validation(
            "policy preparation exceeds its change limit",
        ));
    }
    changes.push(PolicyChange {
        operation: match (before, after) {
            (None, Some(_)) => PolicyChangeOperation::Add,
            (Some(_), None) => PolicyChangeOperation::Remove,
            _ => PolicyChangeOperation::Replace,
        },
        path: path.to_owned(),
        before: before.cloned().unwrap_or(Value::Null),
        after: after.cloned().unwrap_or(Value::Null),
    });
    Ok(())
}

#[derive(Default)]
struct ResultSizeCounter(usize);

impl std::io::Write for ResultSizeCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        if self.0 > MAX_RESULT_BYTES {
            return Err(std::io::Error::other(
                "policy preparation exceeds its result byte limit",
            ));
        }

        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn preparation_changes_describe_exact_json_values_and_pointer_locations() {
        let before = json!({
            "version": "1.0.0",
            "a/b": { "~field": null, "removed": null },
            "array": ["first", "second"],
            "unchanged": { "optional": null }
        });
        let after = json!({
            "version": "1.0.0",
            "a/b": { "~field": false, "added": null },
            "array": ["first"],
            "unchanged": { "optional": null }
        });
        let mut changes = Vec::new();
        collect_changes("", Some(&before), Some(&after), &mut changes).unwrap();
        assert_eq!(changes.len(), 4);
        for change in &changes {
            match change.operation {
                PolicyChangeOperation::Add => {
                    assert!(before.pointer(&change.path).is_none());
                    assert_eq!(change.before, Value::Null);
                    assert_eq!(after.pointer(&change.path), Some(&change.after));
                }
                PolicyChangeOperation::Remove => {
                    assert_eq!(before.pointer(&change.path), Some(&change.before));
                    assert!(after.pointer(&change.path).is_none());
                    assert_eq!(change.after, Value::Null);
                }
                PolicyChangeOperation::Replace => {
                    assert_eq!(before.pointer(&change.path), Some(&change.before));
                    assert_eq!(after.pointer(&change.path), Some(&change.after));
                }
            }
        }
        let null_replacement = changes
            .iter()
            .find(|change| change.path == "/a~1b/~0field")
            .unwrap();
        assert_eq!(null_replacement.operation, PolicyChangeOperation::Replace);
        assert_eq!(null_replacement.before, Value::Null);
        let array = changes
            .iter()
            .find(|change| change.path == "/array")
            .unwrap();
        assert_eq!(array.before, before["array"]);
        assert_eq!(array.after, after["array"]);
        assert!(!changes
            .iter()
            .any(|change| change.path.starts_with("/unchanged")));
    }

    #[test]
    fn preparation_changes_exceeding_the_budget_fail_instead_of_returning_partial_data() {
        let before = json!({});
        let mut after = serde_json::Map::new();
        for index in 0..MAX_CHANGES {
            after.insert(index.to_string(), Value::Bool(true));
        }
        let mut changes = Vec::new();
        collect_changes(
            "",
            Some(&before),
            Some(&Value::Object(after.clone())),
            &mut changes,
        )
        .unwrap();
        after.insert("overflow".into(), Value::Bool(true));
        let error = collect_changes(
            "",
            Some(&before),
            Some(&Value::Object(after)),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            crate::mxc_common::mxc_error::MxcErrorCode::PolicyValidation
        );
        assert_eq!(error.message, "policy preparation exceeds its change limit");
    }

    #[test]
    fn preparation_storage_requires_both_values_and_preserves_real_nulls() {
        let original = json!({
            "requestJson": "{\"a\":null}",
            "changes": [
                {"operation":"add","path":"/a~1b","before":null,"after":null},
                {"operation":"remove","path":"/removed","before":null,"after":null},
                {"operation":"replace","path":"/a","before":1,"after":null}
            ]
        });
        let stored = PreparedPolicyRequest::from_json(&original.to_string()).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&stored.to_json().unwrap()).unwrap(),
            original,
        );
        for index in 0..3 {
            for field in ["before", "after"] {
                let mut incomplete = original.clone();
                incomplete["changes"][index]
                    .as_object_mut()
                    .unwrap()
                    .remove(field);
                assert!(PreparedPolicyRequest::from_json(&incomplete.to_string()).is_err());
            }
        }
        for (path, operation, before, after) in [
            ("/a~2b", "replace", Value::Null, Value::Null),
            ("not-a-pointer", "replace", Value::Null, Value::Null),
            ("/trailing~", "replace", Value::Null, Value::Null),
            ("/a", "add", json!(1), Value::Null),
            ("/a", "remove", Value::Null, json!(1)),
            ("/a", "unknown", Value::Null, Value::Null),
        ] {
            let invalid = json!({
                "requestJson": "{}",
                "changes": [{"operation":operation,"path":path,"before":before,"after":after}],
            });
            assert!(PreparedPolicyRequest::from_json(&invalid.to_string()).is_err());
        }
        for request_json in ["[]", "1", "null", "\"{}\""] {
            let non_object = json!({"requestJson": request_json, "changes": []});
            assert!(PreparedPolicyRequest::from_json(&non_object.to_string()).is_err());
        }
    }

    #[test]
    fn preparation_storage_limits_are_whole_result_limits() {
        let mut prepared = PreparedPolicyRequest {
            request_json: "{}".into(),
            changes: (0..MAX_CHANGES)
                .map(|index| PolicyChange {
                    operation: PolicyChangeOperation::Add,
                    path: format!("/{index}"),
                    before: Value::Null,
                    after: json!(index),
                })
                .collect(),
        };
        assert_eq!(
            PreparedPolicyRequest::from_json(&prepared.to_json().unwrap()).unwrap(),
            prepared,
        );
        prepared.changes.push(prepared.changes[0].clone());
        assert!(prepared.to_json().is_err());
        prepared.changes.clear();
        prepared.request_json = json!({"data": "x".repeat(MAX_REQUEST_BYTES)}).to_string();
        prepared
            .to_json()
            .expect("candidate storage is bounded by the result limit");
        prepared.request_json = json!({"data": "x".repeat(MAX_RESULT_BYTES)}).to_string();
        assert!(prepared.to_json().is_err());
        assert!(PreparedPolicyRequest::from_json(&" ".repeat(MAX_RESULT_BYTES + 1)).is_err());
    }
}
