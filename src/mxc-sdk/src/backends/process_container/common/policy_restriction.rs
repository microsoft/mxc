// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Derive conservative request restrictions from caller-owned observations.

use std::collections::HashSet;

use crate::mxc_common::filesystem_canonical::{canonicalize_allowing_absent_tail, PathCanonical};
use crate::mxc_common::filesystem_probe::FilesystemProbe;
use crate::mxc_common::models::{
    CaptureDenialsMode, ContainerPolicy, ExecutionRequest, NetworkAction, ScriptResponse,
};
use crate::mxc_common::policy_failures::{PolicyFailureDetail as Detail, PolicyFailures};
use crate::process_container_common::base_container_helpers::{
    effective_capabilities, unrestricted_host_loopback_allowed,
};
use crate::process_container_common::network_policy_helpers::{
    capture_requests_internet_capability, ensure_capability,
};
use crate::process_container_common::secenv_policy::RestrictionHint;
use crate::process_container_common::secenv_policy::{PolicyResult, POLICY_RESULT_VERSION};

fn contradicts_earlier(hints: &[RestrictionHint], index: usize) -> bool {
    let hint = &hints[index];
    hints[..index]
        .iter()
        .any(|previous| match (previous, hint) {
            (
                RestrictionHint::RestrictPath { path: a, .. },
                RestrictionHint::RestrictPath { path: b, .. },
            ) => same_path(a, b) && previous != hint,
            (RestrictionHint::ReducePathCount { .. }, RestrictionHint::ReducePathCount { .. }) => {
                previous != hint
            }
            _ => false,
        })
}

fn restrict_request(
    original: &ExecutionRequest,
    failures: &PolicyFailures,
    capture_network_decisions: bool,
    resolve: &mut impl FnMut(&str) -> Result<PathCanonical, String>,
) -> Result<ExecutionRequest, String> {
    failures.validate()?;
    let mut merged = Vec::new();
    for result in &failures.results {
        if result.version != POLICY_RESULT_VERSION
            || result.minimum_reader_version != POLICY_RESULT_VERSION
        {
            return Err("unsupported native policy-result version".into());
        }
        let native = PolicyResult::from(result);
        let hints = native
            .restriction_hints()
            .ok_or("the observations contain an unsupported or non-actionable policy result")?;
        if (0..hints.len()).any(|index| contradicts_earlier(&hints, index)) {
            return Err("a native policy-result batch contains contradictory constraints".into());
        }
        combine_restriction_hints(&mut merged, &hints);
    }
    let mut candidate = original.clone();
    for _ in 0..=merged.len() {
        let applicable = applicable_hints(&candidate, &merged, capture_network_decisions);
        if applicable.is_empty() {
            return Ok(candidate);
        }
        candidate =
            restrict_with_hints(&candidate, &applicable, capture_network_decisions, resolve)?;
    }
    Err("the policy restrictions did not converge".into())
}

pub(super) fn prepare_request(
    original: &ExecutionRequest,
    failures: &PolicyFailures,
    capture_network_decisions: bool,
) -> Result<ExecutionRequest, ScriptResponse> {
    let mut probe = FilesystemProbe::default();
    restrict_request(original, failures, capture_network_decisions, &mut |path| {
        probe.run(path, canonicalize_allowing_absent_tail)
    })
    .map_err(|reason| {
        let message = "Policy preparation cannot apply these observations safely.";
        ScriptResponse::rejected(message).with_error(
            crate::mxc_common::mxc_error::MxcError::policy_validation(message).with_details(
                serde_json::json!({
                    "policyFailures": failures,
                    "policyFeedbackError": { "code": "unsafeReplay", "reason": reason },
                }),
            ),
        )
    })
}

fn applicable_hints(
    request: &ExecutionRequest,
    hints: &[RestrictionHint],
    capture_network_decisions: bool,
) -> Vec<RestrictionHint> {
    hints
        .iter()
        .filter_map(|hint| match hint {
            RestrictionHint::RemoveCapability(capability) => {
                has_capability(request, capability, capture_network_decisions).then(|| hint.clone())
            }
            RestrictionHint::RestrictPath { path, maximum, .. } => {
                let requested = access_at(&request.policy, path);
                (requested > *maximum).then(|| RestrictionHint::RestrictPath {
                    path: path.clone(),
                    requested,
                    maximum: *maximum,
                })
            }
            RestrictionHint::ReducePathCount { maximum, .. } => {
                let requested = native_path_count(&request.policy);
                (requested > *maximum).then_some(RestrictionHint::ReducePathCount {
                    requested,
                    maximum: *maximum,
                })
            }
        })
        .collect()
}

/// Fold `hints` into `merged`, keeping the strictest maximum for each target.
fn combine_restriction_hints(merged: &mut Vec<RestrictionHint>, hints: &[RestrictionHint]) {
    for hint in hints {
        let previous = merged.iter().position(|previous| match (previous, hint) {
            (
                RestrictionHint::RemoveCapability(first),
                RestrictionHint::RemoveCapability(second),
            ) => capability_matches(first, second),
            (
                RestrictionHint::RestrictPath { path: first, .. },
                RestrictionHint::RestrictPath { path: second, .. },
            ) => same_path(first, second),
            (RestrictionHint::ReducePathCount { .. }, RestrictionHint::ReducePathCount { .. }) => {
                true
            }
            _ => false,
        });
        match previous {
            None => merged.push(hint.clone()),
            Some(index) => match (&mut merged[index], hint) {
                (
                    RestrictionHint::RestrictPath { maximum, .. },
                    RestrictionHint::RestrictPath { maximum: next, .. },
                )
                | (
                    RestrictionHint::ReducePathCount { maximum, .. },
                    RestrictionHint::ReducePathCount { maximum: next, .. },
                ) => {
                    *maximum = (*maximum).min(*next);
                }
                _ => {}
            },
        }
    }
}

fn restrict_with_hints(
    original: &ExecutionRequest,
    hints: &[RestrictionHint],
    capture_network_decisions: bool,
    resolve: &mut impl FnMut(&str) -> Result<PathCanonical, String>,
) -> Result<ExecutionRequest, String> {
    let mut candidate = original.clone();
    for (index, hint) in hints.iter().enumerate() {
        if contradicts_earlier(hints, index) {
            return Err("the native details contain contradictory constraints".into());
        }
        match hint {
            RestrictionHint::RemoveCapability(capability) => remove_capability(
                &mut candidate,
                original,
                capability,
                capture_network_decisions,
            )?,
            RestrictionHint::RestrictPath {
                path,
                requested,
                maximum,
            } => restrict_path(
                &mut candidate.policy,
                &original.policy,
                path,
                *requested,
                *maximum,
                resolve,
            )?,
            RestrictionHint::ReducePathCount { .. } => {}
        }
    }
    for hint in hints {
        match hint {
            RestrictionHint::RemoveCapability(capability) => {
                if has_capability(&candidate, capability, capture_network_decisions) {
                    return Err("a forbidden capability still has an effective source".into());
                }
            }
            RestrictionHint::ReducePathCount { requested, maximum } => {
                if native_path_count(&original.policy) != *requested {
                    return Err("the native path count disagrees with the submitted request".into());
                }
                for paths in [
                    &mut candidate.policy.readwrite_paths,
                    &mut candidate.policy.readonly_paths,
                    &mut candidate.policy.denied_paths,
                ] {
                    let mut seen = HashSet::new();
                    paths.retain(|path| seen.insert(path.clone()));
                }
                if native_path_count(&candidate.policy) > *maximum {
                    return Err(
                        "the path limit cannot be met by exact deduplication; MXC will not \
                         discard distinct grants or exceptions"
                            .into(),
                    );
                }
            }
            RestrictionHint::RestrictPath { .. } => {}
        }
    }
    let before = effective_capabilities(original, capture_network_decisions);
    if effective_capabilities(&candidate, capture_network_decisions)
        .iter()
        .any(|capability| {
            !(before
                .iter()
                .any(|previous| capability_matches(previous, capability))
                || (capability_matches(capability, "learningModeLogging")
                    && before
                        .iter()
                        .any(|previous| capability_matches(previous, "permissiveLearningMode"))))
        })
    {
        return Err("the revised request would introduce a new effective capability".into());
    }

    Ok(candidate)
}

fn native_path_count(policy: &ContainerPolicy) -> u64 {
    (policy.readwrite_paths.len() + policy.readonly_paths.len() + policy.denied_paths.len()) as u64
}

fn capability_matches(entry: &str, capability: &str) -> bool {
    entry
        .trim_matches([' ', '\t'])
        .eq_ignore_ascii_case(capability.trim_matches([' ', '\t']))
}

fn has_capability(request: &ExecutionRequest, capability: &str, network_capture: bool) -> bool {
    (capability.eq_ignore_ascii_case("networkLoopback")
        && unrestricted_host_loopback_allowed(&request.policy))
        || effective_capabilities(request, network_capture)
            .iter()
            .any(|entry| capability_matches(entry, capability))
}

fn remove_capability(
    candidate: &mut ExecutionRequest,
    original: &ExecutionRequest,
    capability: &str,
    network_capture: bool,
) -> Result<(), String> {
    if capability.is_empty()
        || capability.contains(',')
        || capability.chars().any(char::is_control)
        || !has_capability(original, capability, network_capture)
    {
        return Err("the forbidden capability does not match the submitted request".into());
    }
    let policy = &mut candidate.policy;
    policy
        .capabilities
        .retain(|entry| !capability_matches(entry, capability));
    if capability.eq_ignore_ascii_case("internetClient") {
        if let Some(egress) = &mut policy.network_egress {
            egress.default = NetworkAction::Deny;
            egress.allow.clear();
        }
        if capture_requests_internet_capability(policy, network_capture) {
            omit_capture(policy);
        }
    } else if capability.eq_ignore_ascii_case("privateNetworkClientServer") {
        if let Some(ingress) = &mut policy.network_ingress {
            ingress.default = NetworkAction::Deny;
        }
        disable_proxy(policy, network_capture);
    } else if capability.eq_ignore_ascii_case("networkLoopback") {
        if let Some(ingress) = &mut policy.network_ingress {
            ingress.host_loopback = NetworkAction::Deny;
        }
        if policy.network_proxy.is_enabled() && policy.allowed_proxy_peer.is_none() {
            disable_proxy(policy, network_capture);
        }
    } else if capability.eq_ignore_ascii_case("permissiveLearningMode") {
        if let Some(capture) = &mut policy.capture_denials {
            capture.mode = CaptureDenialsMode::Block;
            ensure_capability(&mut policy.capabilities, "learningModeLogging");
        }
    } else if capability.eq_ignore_ascii_case("learningModeLogging") {
        omit_capture(policy);
    }
    Ok(())
}

fn omit_capture(policy: &mut ContainerPolicy) {
    policy.capture_denials = None;
    policy.capabilities.retain(|capability| {
        !capability_matches(capability, "permissiveLearningMode")
            && !capability_matches(capability, "learningModeLogging")
    });
}

fn disable_proxy(policy: &mut ContainerPolicy, network_capture: bool) {
    if !policy.network_proxy.is_enabled() {
        return;
    }
    // Proxy mode omits the direct policy tables. Do not activate allowances
    // that were ineffective in the submitted proxy form.
    if let Some(egress) = &mut policy.network_egress {
        egress.default = NetworkAction::Deny;
        egress.allow.clear();
    }
    if let Some(ingress) = &mut policy.network_ingress {
        ingress.default = NetworkAction::Deny;
        ingress.host_loopback = NetworkAction::Deny;
    }
    policy.network_proxy = Default::default();
    policy.runtime_network_proxy_specified = false;
    policy.allowed_proxy_peer = None;
    if capture_requests_internet_capability(policy, network_capture) {
        // Leaving proxy mode must not synthesize a new direct-egress capability.
        omit_capture(policy);
    }
}

fn literal_path(path: &str) -> Result<String, String> {
    let bytes = path.as_bytes();
    let drive =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    let unc = path.starts_with("\\\\") && !path.starts_with("\\\\?") && !path.starts_with("\\\\.");
    if (!drive && !unc) || path.contains(['/', '*', '?']) || path.chars().any(char::is_control) {
        return Err("filesystem restriction requires an absolute literal DOS or UNC path".into());
    }
    let normalized = path.trim_end_matches('\\');
    let normalized = if drive && normalized.len() == 2 {
        &path[..3]
    } else {
        normalized
    };
    let tail = normalized
        .get(if drive { 3.. } else { 2.. })
        .ok_or("filesystem restriction cannot reinterpret non-canonical path components")?;
    if (!tail.is_empty()
        && tail.split('\\').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.ends_with(['.', ' '])
                || part.contains(':')
        }))
        || (unc && tail.split('\\').count() < 2)
    {
        return Err(
            "filesystem restriction cannot reinterpret non-canonical path components".into(),
        );
    }
    Ok(normalized.to_owned())
}

fn contains(parent: &str, child: &str) -> bool {
    child.eq_ignore_ascii_case(parent)
        || (child
            .get(..parent.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(parent))
            && child.as_bytes().get(parent.len()) == Some(&b'\\'))
}

fn same_path(first: &str, second: &str) -> bool {
    first
        .trim_end_matches('\\')
        .eq_ignore_ascii_case(second.trim_end_matches('\\'))
}

fn access_at(policy: &ContainerPolicy, point: &str) -> u64 {
    let mut best = None;
    let mut access = Detail::ACCESS_NONE;
    for (paths, value) in [
        (&policy.readwrite_paths, Detail::ACCESS_READ_WRITE),
        (&policy.readonly_paths, Detail::ACCESS_READ_ONLY),
        (&policy.denied_paths, Detail::ACCESS_NONE),
    ] {
        for path in paths {
            let path = path.trim_end_matches('\\');
            if contains(path, point) && best.is_none_or(|length| path.len() >= length) {
                best = Some(path.len());
                access = value;
            }
        }
    }
    access
}

fn restrict_path(
    policy: &mut ContainerPolicy,
    original: &ContainerPolicy,
    path: &str,
    requested: u64,
    maximum: u64,
    resolve: &mut impl FnMut(&str) -> Result<PathCanonical, String>,
) -> Result<(), String> {
    if maximum > Detail::ACCESS_READ_ONLY
        || requested > Detail::ACCESS_READ_WRITE
        || maximum >= requested
    {
        return Err("the filesystem constraint is not a supported narrowing instruction".into());
    }
    let point = literal_path(path)?;
    if access_at(original, &point) != requested {
        return Err("the native filesystem witness disagrees with the submitted request".into());
    }
    if access_at(policy, &point) <= maximum {
        return Ok(());
    }
    let readonly_grants: Vec<_> = if maximum == Detail::ACCESS_READ_ONLY {
        policy
            .readwrite_paths
            .iter()
            .filter(|path| same_path(path, &point))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    if maximum == Detail::ACCESS_READ_ONLY && readonly_grants.is_empty() {
        return Err(
            "read-only restriction requires an existing matching read-write grant; MXC will not \
             introduce a new grant name or downgrade an unrelated ancestor"
                .into(),
        );
    }
    for path in policy
        .readwrite_paths
        .iter()
        .chain(&policy.readonly_paths)
        .chain(&policy.denied_paths)
        .map(String::as_str)
        .chain(std::iter::once(point.as_str()))
    {
        let spelling = literal_path(path)?;
        let resolved = match resolve(path)? {
            PathCanonical::Canonical(path) => literal_path(&path)?,
            _ => {
                return Err(
                    "filesystem restriction cannot resolve every relevant path safely".into(),
                )
            }
        };
        if !spelling.eq_ignore_ascii_case(&resolved) {
            return Err(
                "filesystem restriction will not guess the provenance of an aliased path".into(),
            );
        }
    }
    if original.readwrite_paths.iter().any(|path| {
        let path = path.trim_end_matches('\\');
        path.len() == 2 || (path.starts_with("\\\\") && path[2..].split('\\').count() == 2)
    }) {
        return Err(
            "volume/share-root write grants have no supported automatic restriction".into(),
        );
    }

    let before = policy.clone();
    policy
        .readwrite_paths
        .retain(|path| !same_path(path, &point));
    if maximum == Detail::ACCESS_NONE {
        policy
            .readonly_paths
            .retain(|path| !same_path(path, &point));
        if !policy
            .denied_paths
            .iter()
            .any(|path| same_path(path, &point))
        {
            policy.denied_paths.push(point.clone());
        }
    } else {
        for grant in readonly_grants {
            if !policy.readonly_paths.contains(&grant) {
                policy.readonly_paths.push(grant);
            }
        }
    }
    // Access is piecewise constant between the old/new path boundaries.
    let points = before
        .readwrite_paths
        .iter()
        .chain(&before.readonly_paths)
        .chain(&before.denied_paths)
        .map(String::as_str)
        .chain(std::iter::once(point.as_str()));
    if access_at(policy, &point) > maximum
        || points
            .into_iter()
            .any(|path| access_at(policy, path) > access_at(&before, path))
    {
        return Err("the proposed filesystem restriction could increase effective access".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "policy_restriction_tests.rs"]
mod tests;
