// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Builds the policy preparation result for ProcessContainer: restricts the
//! parsed request, projects the restriction back onto the request JSON the
//! application authored, and checks that the candidate reproduces it.

use crate::mxc_common::models::{
    CaptureDenialsMode, ExecutionRequest, LearningModeCapability, NetworkAction,
};
use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};
use crate::mxc_common::policy_failures::PolicyFailures;
use crate::mxc_common::policy_preparation::{collect_changes, PreparedPolicyRequest};
use crate::mxc_common::splice::serialize_preserving_unchanged_members;
use crate::process_container_common::base_container_runner::BaseContainerRunner;
use crate::process_container_common::working_directory::{
    try_launch_working_directory, LaunchWorkingDirectory,
};
use serde_json::Value;

/// Prepare a candidate for `request`, which was parsed from `original_json`.
/// `reparse` parses candidate JSON through the same contract and options as
/// the original request.
pub(crate) fn prepare_candidate(
    original_json: &str,
    request: &ExecutionRequest,
    failures: &PolicyFailures,
    reparse: impl FnOnce(&str) -> Option<ExecutionRequest>,
) -> Result<PreparedPolicyRequest, MxcError> {
    let restricted = BaseContainerRunner::prepare_policy_request(request, failures)
        .map_err(backend_preparation_error)?;
    let original: Value = serde_json::from_str(original_json)
        .map_err(|_| MxcError::malformed_request("invalid policy preparation request JSON"))?;
    let (candidate, original_cwd) = project_request(&original, request, &restricted)?;
    let candidate_json = match (original.as_object(), candidate.as_object()) {
        (Some(original), Some(candidate)) => {
            serialize_preserving_unchanged_members(original_json, original, candidate)
        }
        _ => None,
    }
    .ok_or_else(projection_error)?;
    let reparsed = reparse(&candidate_json).ok_or_else(projection_error)?;
    BaseContainerRunner::verify_prepared_policy(&restricted, &reparsed)
        .map_err(backend_preparation_error)?;
    if resolve_launch_directory(&reparsed)?.path != original_cwd {
        return Err(projection_error());
    }
    let mut changes = Vec::new();
    collect_changes("", Some(&original), Some(&candidate), &mut changes)?;
    Ok(PreparedPolicyRequest {
        request_json: if changes.is_empty() {
            original_json.to_owned()
        } else {
            candidate_json
        },
        changes,
    })
}

// Backend messages can quote request data; preparation reports only the category.
fn backend_preparation_error(mut error: MxcError) -> MxcError {
    error.message = match error.code {
        MxcErrorCode::BackendUnavailable => {
            "native Windows ProcessContainer cannot enforce policy preparation on this host"
        }
        _ => "policy preparation cannot safely enforce the requested policy",
    }
    .to_owned();
    error.remediation = None;
    error
}

fn projection_error() -> MxcError {
    MxcError::policy_validation(
        "the restrictive policy cannot be represented safely in the request contract",
    )
}

fn resolve_launch_directory(
    request: &ExecutionRequest,
) -> Result<LaunchWorkingDirectory, MxcError> {
    try_launch_working_directory(request).map_err(|_| {
        MxcError::policy_validation(
            "policy preparation cannot resolve the launch directory safely; check filesystem availability",
        )
    })
}

fn is_reserved_learning_capability(entry: &str) -> bool {
    LearningModeCapability::from_capability_name(entry.trim_matches([' ', '\t'])).is_some()
}

/// Returns the candidate request JSON and the launch directory of the
/// original request, which the candidate must keep.
fn project_request(
    original: &Value,
    before: &ExecutionRequest,
    after: &ExecutionRequest,
) -> Result<(Value, String), MxcError> {
    let mut json = original.clone();
    let process_container = if original.get("appContainer").is_some() {
        "appContainer"
    } else {
        "processContainer"
    };
    let action = |value| {
        Value::String(
            match value {
                NetworkAction::Allow => "allow",
                NetworkAction::Deny => "deny",
            }
            .to_owned(),
        )
    };
    for (name, old, new) in [
        (
            "readwritePaths",
            &before.policy.readwrite_paths,
            &after.policy.readwrite_paths,
        ),
        (
            "readonlyPaths",
            &before.policy.readonly_paths,
            &after.policy.readonly_paths,
        ),
        (
            "deniedPaths",
            &before.policy.denied_paths,
            &after.policy.denied_paths,
        ),
    ] {
        if old != new {
            set(
                &mut json,
                &["filesystem", name],
                Some(project_path_list(
                    original.pointer(&format!("/filesystem/{name}")),
                    old,
                    new,
                )?),
            )?;
        }
    }
    let authorable_capabilities = |entries: &[String]| {
        entries
            .iter()
            .filter(|entry| !is_reserved_learning_capability(entry))
            .cloned()
            .collect::<Vec<_>>()
    };
    let old = authorable_capabilities(&before.policy.capabilities);
    let new = authorable_capabilities(&after.policy.capabilities);
    if old != new {
        set(
            &mut json,
            &[process_container, "capabilities"],
            Some(Value::from(new)),
        )?;
    }
    if after.policy.capture_denials.is_none()
        && !after.policy.capabilities.iter().any(|entry| {
            LearningModeCapability::from_capability_name(entry.trim_matches([' ', '\t']))
                == Some(LearningModeCapability::Learning)
        })
        && original
            .get(process_container)
            .and_then(|section| section.get("learningMode"))
            == Some(&Value::Bool(true))
    {
        set(
            &mut json,
            &[process_container, "learningMode"],
            Some(Value::Bool(false)),
        )?;
    }
    if before.policy.network_egress != after.policy.network_egress {
        let old = before
            .policy
            .network_egress
            .as_ref()
            .ok_or_else(projection_error)?;
        let new = after
            .policy
            .network_egress
            .as_ref()
            .ok_or_else(projection_error)?;
        if old.default != new.default {
            set(
                &mut json,
                &["network", "egress", "default"],
                Some(action(new.default)),
            )?;
        }
        if old.allow != new.allow {
            if !new.allow.is_empty() {
                return Err(projection_error());
            }
            set(
                &mut json,
                &["network", "egress", "allow"],
                Some(Value::Array(Vec::new())),
            )?;
        }
        if old.deny != new.deny {
            return Err(projection_error());
        }
    }
    if before.policy.network_ingress != after.policy.network_ingress {
        let old = before
            .policy
            .network_ingress
            .as_ref()
            .ok_or_else(projection_error)?;
        let new = after
            .policy
            .network_ingress
            .as_ref()
            .ok_or_else(projection_error)?;
        if old.default != new.default {
            set(
                &mut json,
                &["network", "ingress", "default"],
                Some(action(new.default)),
            )?;
        }
        if old.host_loopback != new.host_loopback {
            set(
                &mut json,
                &["network", "ingress", "hostLoopback"],
                Some(action(new.host_loopback)),
            )?;
        }
    }
    if before.policy.network_proxy.is_enabled() && !after.policy.network_proxy.is_enabled() {
        set(&mut json, &["runtimeConfig", "networkProxy"], None)?;
    }
    if before.policy.allowed_proxy_peer != after.policy.allowed_proxy_peer {
        set(
            &mut json,
            &[process_container, "network", "allowedProxyPeer"],
            after.policy.allowed_proxy_peer.clone().map(Value::String),
        )?;
    }
    match (
        &before.policy.capture_denials,
        &after.policy.capture_denials,
    ) {
        (Some(_), None) => set(&mut json, &[process_container, "captureDenials"], None)?,
        (Some(old), Some(new)) if old.mode != new.mode => {
            set(
                &mut json,
                &[process_container, "captureDenials", "mode"],
                Some(Value::String(
                    match new.mode {
                        CaptureDenialsMode::Block => "block",
                        CaptureDenialsMode::Allow => "allow",
                    }
                    .to_owned(),
                )),
            )?;
        }
        (None, Some(_)) => return Err(projection_error()),
        _ => {}
    }
    let original_cwd = resolve_launch_directory(before)?;
    let candidate_cwd = resolve_launch_directory(after)?;
    if original_cwd.path != candidate_cwd.path {
        set(
            &mut json,
            &["process", "cwd"],
            Some(Value::String(original_cwd.path.clone())),
        )?;
    }
    Ok((json, original_cwd.path))
}

fn project_path_list(
    authored: Option<&Value>,
    before: &[String],
    after: &[String],
) -> Result<Value, MxcError> {
    use std::collections::HashMap;
    fn counts(paths: &[String]) -> HashMap<&str, usize> {
        let mut counts = HashMap::new();
        for path in paths {
            *counts.entry(path.as_str()).or_insert(0usize) += 1;
        }
        counts
    }
    let old_counts = counts(before);
    let new_counts = counts(after);
    let mut remaining = new_counts.clone();
    let mut projected = Vec::new();
    if let Some(value) = authored.filter(|value| !value.is_null()) {
        for value in value.as_array().ok_or_else(projection_error)? {
            let path = value.as_str().ok_or_else(projection_error)?;
            // Normalization can suppress entries already covered by more
            // restrictive lists. Preserve that unrelated authored data.
            if !old_counts.contains_key(path) {
                projected.push(value.clone());
            } else if let Some(count) = remaining.get_mut(path).filter(|count| **count > 0) {
                *count -= 1;
                projected.push(value.clone());
            }
        }
    }
    let mut seen = HashMap::new();
    for path in after {
        let count = seen.entry(path.as_str()).or_insert(0usize);
        *count += 1;
        if *count > old_counts.get(path.as_str()).copied().unwrap_or(0) {
            projected.push(Value::String(path.clone()));
        }
    }
    Ok(Value::Array(projected))
}

fn set(json: &mut Value, path: &[&str], value: Option<Value>) -> Result<(), MxcError> {
    let (last, parents) = path.split_last().ok_or_else(projection_error)?;
    let mut current = json;
    for parent in parents {
        let object = current.as_object_mut().ok_or_else(projection_error)?;
        current = object
            .entry((*parent).to_owned())
            .or_insert_with(|| Value::Object(Default::default()));
        if current.is_null() {
            *current = Value::Object(Default::default());
        }
    }
    let object = current.as_object_mut().ok_or_else(projection_error)?;
    match value {
        Some(value) => {
            object.insert((*last).to_owned(), value);
        }
        None => {
            object.remove(*last);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn projection_keeps_suppressed_authoring_when_only_runtime_paths_change() {
        let before = vec!["work".into(), "work".into()];
        let after = vec!["work".into()];
        let authored = json!(["work", "denied", "work", "enumerated", "denied"]);
        assert_eq!(
            project_path_list(Some(&authored), &before, &after).unwrap(),
            json!(["work", "denied", "enumerated", "denied"]),
        );
        let authored = json!(["read", "denied", "read"]);
        assert_eq!(
            project_path_list(
                Some(&authored),
                &["read".into(), "read".into()],
                &["read".into(), "work".into()],
            )
            .unwrap(),
            json!(["read", "denied", "work"]),
        );
        assert_eq!(
            project_path_list(Some(&Value::Null), &[], &["work".into()]).unwrap(),
            json!(["work"]),
        );
    }
}
