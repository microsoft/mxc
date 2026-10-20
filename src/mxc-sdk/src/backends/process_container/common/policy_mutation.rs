// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Restrictive repairs and private in-process reuse before workload launch.

use std::collections::HashSet;

use serde::Serialize;

use crate::mxc_common::filesystem_canonical::{canonicalize_allowing_absent_tail, PathCanonical};
use crate::mxc_common::filesystem_probe::FilesystemProbe;
use crate::mxc_common::models::{
    CaptureDenialsMode, ContainerPolicy, ExecutionRequest, FailurePhase, NetworkAction,
    ScriptResponse,
};
use crate::process_container_common::base_container_helpers::{
    effective_capabilities, unrestricted_host_loopback_allowed,
};
use crate::process_container_common::network_policy_helpers::{
    capture_requests_internet_capability, ensure_capability,
};
use crate::process_container_common::secenv::{CreationError, SecurityEnvironmentVersion};
use crate::process_container_common::secenv_policy::MutationHint;

const MAX_ATTEMPTS: usize = 8;
const MAX_CHANGE_TEXT_BYTES: usize = 1024 * 1024;

#[path = "policy_mutation_cache.rs"]
mod cache;
#[cfg(test)]
pub(super) use cache::{isolated_test_cache, TestCacheScope};

#[derive(Debug)]
pub(super) struct PreparedPolicy {
    pub specification: Vec<u8>,
    pub capture_network_decisions: bool,
    pub version: SecurityEnvironmentVersion,
}

#[derive(Debug)]
pub(super) struct NegotiatedEnvironment<T> {
    pub environment: T,
    pub request: ExecutionRequest,
    pub prepared: PreparedPolicy,
    pub warnings: Vec<String>,
}

pub(super) fn negotiate<T>(
    original: &ExecutionRequest,
    prepare: impl FnMut(&ExecutionRequest) -> Result<PreparedPolicy, ScriptResponse>,
    create: impl FnMut(&PreparedPolicy, &ContainerPolicy) -> Result<T, CreationError>,
    validate: impl FnMut(&ExecutionRequest) -> Result<(), ScriptResponse>,
) -> Result<NegotiatedEnvironment<T>, ScriptResponse> {
    cache::with_shared(|shared| {
        let mut warnings = Vec::new();
        let mut cache = cache::lock(shared, &mut warnings);
        negotiate_with_cache(original, &mut cache, warnings, prepare, create, validate)
    })
}

fn negotiate_with_cache<T>(
    original: &ExecutionRequest,
    cache: &mut cache::Cache,
    mut warnings: Vec<String>,
    mut prepare: impl FnMut(&ExecutionRequest) -> Result<PreparedPolicy, ScriptResponse>,
    mut create: impl FnMut(&PreparedPolicy, &ContainerPolicy) -> Result<T, CreationError>,
    mut validate: impl FnMut(&ExecutionRequest) -> Result<(), ScriptResponse>,
) -> Result<NegotiatedEnvironment<T>, ScriptResponse> {
    let key = match cache::key() {
        Ok(key) => Some(key),
        Err(error) => {
            warnings.push(format!(
                "Policy mutation cache unavailable: {error}; this creation uses fresh negotiation."
            ));
            None
        }
    };
    let mut effective = original.clone();
    let mut remembered_hints = Vec::new();
    let mut learned_new_restrictions = false;
    let prepared_original = prepare(original).map_err(|error| {
        if warnings.is_empty() {
            error
        } else {
            stopped(error, &warnings, "the current policy cannot be prepared")
        }
    })?;
    let capture_network_decisions = prepared_original.capture_network_decisions;
    let mut initial_prepared = Some(prepared_original);
    let mut probe = FilesystemProbe::default();
    let mut resolve = |path: &str| probe.run(path, canonicalize_allowing_absent_tail);
    if let Some(key) = key {
        for previous in cache.candidates(key) {
            let hints = reusable_hints(original, &previous.hints, capture_network_decisions);
            if hints.is_empty() {
                continue;
            }
            let Ok((candidate, _)) =
                repair(original, &hints, capture_network_decisions, &mut resolve)
            else {
                continue;
            };
            if let Err(error) = validate(&candidate) {
                return Err(stopped(
                    error,
                    &warnings,
                    "the remembered restrictions cannot be enforced by the selected native tier",
                ));
            }
            effective = candidate;
            merge_hints(&mut remembered_hints, &hints);
            initial_prepared = None;
            break;
        }
    }
    let mut specifications = HashSet::new();
    let mut refusals = HashSet::new();
    let mut previous_failure = None;
    let mut attempts = 0;
    loop {
        let prepared = match initial_prepared
            .take()
            .map(Ok)
            .unwrap_or_else(|| prepare(&effective))
        {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(match previous_failure {
                    Some(response) => stopped(
                        response,
                        &warnings,
                        &format!(
                            "the revised policy cannot be prepared: {:?}",
                            error.error_message
                        ),
                    ),
                    None if !warnings.is_empty() => {
                        stopped(error, &warnings, "the effective policy cannot be prepared")
                    }
                    None => error,
                });
            }
        };
        if !specifications.insert(prepared.specification.clone()) {
            return Err(stopped(
                previous_failure.unwrap_or_else(|| {
                    ScriptResponse::error("policy mutation repeated the initial specification")
                }),
                &warnings,
                "the native specification did not change",
            ));
        }
        attempts += 1;
        let error = match create(&prepared, &effective.policy) {
            Ok(environment) => {
                if learned_new_restrictions {
                    if let Some(key) = key {
                        if let Err(error) = cache.remember(key, &remembered_hints) {
                            warnings.push(format!("Policy mutation cache not updated: {error}."));
                        }
                    }
                }
                return Ok(NegotiatedEnvironment {
                    environment,
                    request: effective,
                    prepared,
                    warnings,
                });
            }

            Err(error) => error,
        };
        let response = creation_failure(&error, effective.policy.capture_denials.is_some());
        if attempts == MAX_ATTEMPTS {
            return Err(stopped(
                response,
                &warnings,
                "the eight-attempt limit was reached",
            ));
        }
        let Some(hints) = error.mutation_hints() else {
            return Err(stopped(
                response,
                &warnings,
                "no complete, recognized, actionable blocked-policy details are available",
            ));
        };
        if !refusals.insert(hints.to_vec()) {
            return Err(stopped(response, &warnings, "the native refusal repeated"));
        }
        let (candidate, changes) = match repair(
            &effective,
            hints,
            prepared.capture_network_decisions,
            &mut resolve,
        ) {
            Ok(repair) => repair,
            Err(reason) => return Err(stopped(response, &warnings, &reason)),
        };
        if let Err(error) = validate(&candidate) {
            return Err(stopped(
                response,
                &warnings,
                &format!(
                    "the revised policy is unsupported: {:?}",
                    error.error_message
                ),
            ));
        }
        merge_hints(&mut remembered_hints, hints);
        let changes: Vec<_> = changes
            .into_iter()
            .map(|change| format!("Sandbox configuration updated due to IT policy: {change}"))
            .collect();
        if warnings
            .iter()
            .chain(&changes)
            .map(String::len)
            .sum::<usize>()
            > MAX_CHANGE_TEXT_BYTES
        {
            return Err(stopped(
                response,
                &warnings,
                "the mutation-text limit was reached",
            ));
        }
        warnings.extend(changes);
        learned_new_restrictions = true;
        effective = candidate;
        previous_failure = Some(response);
    }
}

fn reusable_hints(
    request: &ExecutionRequest,
    hints: &[MutationHint],
    capture_network_decisions: bool,
) -> Vec<MutationHint> {
    hints
        .iter()
        .filter_map(|hint| match hint {
            MutationHint::RemoveCapability(capability) => {
                has_capability(request, capability, capture_network_decisions).then(|| hint.clone())
            }
            MutationHint::RestrictPath { path, maximum, .. } => {
                let requested = access_at(&request.policy, path);
                (requested > *maximum).then(|| MutationHint::RestrictPath {
                    path: path.clone(),
                    requested,
                    maximum: *maximum,
                })
            }
            MutationHint::ReducePathCount { maximum, .. } => {
                let requested = native_path_count(&request.policy);
                (requested > *maximum).then_some(MutationHint::ReducePathCount {
                    requested,
                    maximum: *maximum,
                })
            }
        })
        .collect()
}

fn merge_hints(remembered: &mut Vec<MutationHint>, hints: &[MutationHint]) {
    for hint in hints {
        let previous = remembered
            .iter()
            .position(|previous| match (previous, hint) {
                (MutationHint::RemoveCapability(first), MutationHint::RemoveCapability(second)) => {
                    capability_matches(first, second)
                }
                (
                    MutationHint::RestrictPath { path: first, .. },
                    MutationHint::RestrictPath { path: second, .. },
                ) => same_path(first, second),
                (MutationHint::ReducePathCount { .. }, MutationHint::ReducePathCount { .. }) => {
                    true
                }
                _ => false,
            });
        match previous {
            None => remembered.push(hint.clone()),
            Some(index) => match (&mut remembered[index], hint) {
                (
                    MutationHint::RestrictPath { maximum, .. },
                    MutationHint::RestrictPath { maximum: next, .. },
                )
                | (
                    MutationHint::ReducePathCount { maximum, .. },
                    MutationHint::ReducePathCount { maximum: next, .. },
                ) => {
                    *maximum = (*maximum).min(*next);
                }
                _ => {}
            },
        }
    }
}

fn creation_failure(error: &CreationError, capture: bool) -> ScriptResponse {
    let message = error.message(capture);
    ScriptResponse::failed(
        if error.is_api_unavailable() {
            FailurePhase::BackendUnavailable
        } else {
            FailurePhase::LaunchFailed
        },
        &message,
    )
}

fn stopped(mut response: ScriptResponse, warnings: &[String], reason: &str) -> ScriptResponse {
    let suffix = format!("\nPolicy mutation stopped: {reason}.");
    response.error_message.push_str(&suffix);
    append_attempted_changes(&mut response, warnings);
    response
}

pub(super) fn append_attempted_changes(response: &mut ScriptResponse, warnings: &[String]) {
    if !warnings.is_empty() {
        let text = format!(
            "\nAttempted creation-policy changes (the workload was not retried):\n{}",
            warnings.join("\n"),
        );
        response.error_message.push_str(&text);
    }
}

fn repair(
    original: &ExecutionRequest,
    hints: &[MutationHint],
    capture_network_decisions: bool,
    resolve: &mut impl FnMut(&str) -> Result<PathCanonical, String>,
) -> Result<(ExecutionRequest, Vec<String>), String> {
    let mut candidate = original.clone();
    for (index, hint) in hints.iter().enumerate() {
        if hints[..index]
            .iter()
            .any(|previous| match (previous, hint) {
                (
                    MutationHint::RestrictPath { path: first, .. },
                    MutationHint::RestrictPath { path: second, .. },
                ) => same_path(first, second) && previous != hint,
                (MutationHint::ReducePathCount { .. }, MutationHint::ReducePathCount { .. }) => {
                    previous != hint
                }
                _ => false,
            })
        {
            return Err("the native details contain contradictory constraints".into());
        }
        match hint {
            MutationHint::RemoveCapability(capability) => remove_capability(
                &mut candidate,
                original,
                capability,
                capture_network_decisions,
            )?,
            MutationHint::RestrictPath {
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
            MutationHint::ReducePathCount { .. } => {}
        }
    }
    for hint in hints {
        match hint {
            MutationHint::RemoveCapability(capability) => {
                if has_capability(&candidate, capability, capture_network_decisions) {
                    return Err("a forbidden capability still has an effective source".into());
                }
            }
            MutationHint::ReducePathCount { requested, maximum } => {
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
            MutationHint::RestrictPath { .. } => {}
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

    let mut changes = Vec::new();
    macro_rules! record {
        ($field:ident, $name:literal) => {
            record_change(
                $name,
                &original.policy.$field,
                &candidate.policy.$field,
                &mut changes,
            )?;
        };
    }
    record!(
        capabilities,
        "processContainer.capabilities (effective request)"
    );
    record!(readwrite_paths, "filesystem.readwritePaths");
    record!(readonly_paths, "filesystem.readonlyPaths");
    record!(denied_paths, "filesystem.deniedPaths");
    record!(network_egress, "network.egress");
    record!(network_ingress, "network.ingress");
    record_change(
        "runtimeConfig.networkProxy enabled",
        &original.policy.network_proxy.is_enabled(),
        &candidate.policy.network_proxy.is_enabled(),
        &mut changes,
    )?;
    record!(
        allowed_proxy_peer,
        "processContainer.network.allowedProxyPeer"
    );
    record!(capture_denials, "processContainer.captureDenials");
    if changes.is_empty() {
        return Err("the returned constraints produced no supported policy change".into());
    }
    Ok((candidate, changes))
}

fn record_change(
    field: &str,
    before: &impl Serialize,
    after: &impl Serialize,
    changes: &mut Vec<String>,
) -> Result<(), String> {
    let before = serde_json::to_string(before)
        .map_err(|error| format!("cannot describe the prior policy: {error}"))?;
    let after = serde_json::to_string(after)
        .map_err(|error| format!("cannot describe the revised policy: {error}"))?;
    if before != after {
        let text = format!("{field}: {before} -> {after}");
        if text.len() + changes.iter().map(String::len).sum::<usize>() > MAX_CHANGE_TEXT_BYTES {
            return Err("the mutation-text limit was reached".into());
        }
        changes.push(text);
    }
    Ok(())
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
        return Err("filesystem mutation requires an absolute literal DOS or UNC path".into());
    }
    let normalized = path.trim_end_matches('\\');
    let normalized = if drive && normalized.len() == 2 {
        &path[..3]
    } else {
        normalized
    };
    let tail = normalized
        .get(if drive { 3.. } else { 2.. })
        .ok_or("filesystem mutation cannot reinterpret non-canonical path components")?;
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
        return Err("filesystem mutation cannot reinterpret non-canonical path components".into());
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
    let mut access = 0;
    for (paths, value) in [
        (&policy.readwrite_paths, 2),
        (&policy.readonly_paths, 1),
        (&policy.denied_paths, 0),
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
    if maximum > 1 || requested > 2 || maximum >= requested {
        return Err("the filesystem constraint is not a supported narrowing instruction".into());
    }
    let point = literal_path(path)?;
    if access_at(original, &point) != requested {
        return Err("the native filesystem witness disagrees with the submitted request".into());
    }
    if access_at(policy, &point) <= maximum {
        return Ok(());
    }
    let readonly_grants: Vec<_> = if maximum == 1 {
        policy
            .readwrite_paths
            .iter()
            .filter(|path| same_path(path, &point))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    if maximum == 1 && readonly_grants.is_empty() {
        return Err(
            "read-only mutation requires an existing matching read-write grant; MXC will not \
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
                return Err("filesystem mutation cannot resolve every relevant path safely".into())
            }
        };
        if !spelling.eq_ignore_ascii_case(&resolved) {
            return Err(
                "filesystem mutation will not guess the provenance of an aliased path".into(),
            );
        }
    }
    if original.readwrite_paths.iter().any(|path| {
        let path = path.trim_end_matches('\\');
        path.len() == 2 || (path.starts_with("\\\\") && path[2..].split('\\').count() == 2)
    }) {
        return Err("volume/share-root write grants have no supported automatic mutation".into());
    }

    let before = policy.clone();
    policy
        .readwrite_paths
        .retain(|path| !same_path(path, &point));
    if maximum == 0 {
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
        return Err("the proposed filesystem mutation could increase effective access".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "policy_mutation_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "policy_mutation_retry_tests.rs"]
mod retry_tests;
