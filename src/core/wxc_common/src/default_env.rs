// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared `process.env` resolution.
//!
//! [`EnvResolution`] names the state the caller asked for; every backend
//! answers to the same one. [`resolve_env`] then builds the entries for a
//! backend whose default block MXC can enumerate — only the block itself is
//! backend-specific, so the state dispatch and the overlay merge live here and
//! cannot drift apart. A backend whose default MXC cannot enumerate, such as a
//! container image's own environment, matches on [`EnvResolution`] directly.

use std::collections::HashMap;

use crate::models::ExecutionRequest;

/// What the caller asked for with `process.env` and `process.inheritDefaultEnv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvResolution {
    /// The backend's default; the caller supplied no environment.
    Default,
    /// The caller's entries and nothing else.
    Replace,
    /// The caller's entries layered over the backend's default.
    Overlay,
    /// The caller's entries, with no default block and an omitted environment
    /// indistinguishable from an empty one.
    Legacy,
}

impl EnvResolution {
    /// The state `request` selects.
    ///
    /// A request whose contract predates the distinct four states resolves to
    /// [`EnvResolution::Legacy`].
    pub fn of(request: &ExecutionRequest) -> Self {
        if !request.supplies_default_env() {
            return Self::Legacy;
        }

        match (&request.env, request.inherit_default_env) {
            (None, _) => Self::Default,
            (Some(_), false) => Self::Replace,
            (Some(_), true) => Self::Overlay,
        }
    }
}

/// The entries the child should get, as `KEY=VALUE` strings.
///
/// `defaults` builds the backend's default block, in the order the child should
/// receive it. It is only called when the request actually needs it.
///
/// A caller entry replaces the same-named default in place rather than being
/// appended, so a consumer that applies entries in order cannot end up setting
/// one name twice; a caller entry naming no default is appended in the order
/// supplied.
pub fn resolve_env(
    request: &ExecutionRequest,
    defaults: impl FnOnce() -> Vec<(String, String)>,
) -> Vec<String> {
    let supplied = request.env_entries();

    let entries = match EnvResolution::of(request) {
        EnvResolution::Legacy | EnvResolution::Replace => return supplied.to_vec(),
        EnvResolution::Default => defaults(),
        EnvResolution::Overlay => overlay(defaults(), supplied),
    };

    entries
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

/// Layer `supplied` over `defaults`, last value winning for a repeated name.
fn overlay(mut entries: Vec<(String, String)>, supplied: &[String]) -> Vec<(String, String)> {
    let mut index: HashMap<String, usize> = entries
        .iter()
        .enumerate()
        .map(|(at, (key, _))| (key.clone(), at))
        .collect();

    for (key, value) in env_pairs(supplied) {
        match index.get(key) {
            Some(&at) => entries[at].1 = value.to_string(),
            None => {
                index.insert(key.to_string(), entries.len());
                entries.push((key.to_string(), value.to_string()));
            }
        }
    }

    entries
}

/// Split resolved entries into the `(key, value)` pairs a consumer applies.
/// An entry with no `=` names no variable, so it is dropped.
pub fn env_pairs(entries: &[String]) -> Vec<(&str, &str)> {
    entries.iter().filter_map(|kv| kv.split_once('=')).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DefaultEnvCompatibility;

    fn defaults() -> Vec<(String, String)> {
        vec![
            ("PATH".to_string(), "/default/bin".to_string()),
            ("TERM".to_string(), "xterm-256color".to_string()),
        ]
    }

    fn request(compatibility: DefaultEnvCompatibility) -> ExecutionRequest {
        ExecutionRequest {
            default_env_compatibility: compatibility,
            ..Default::default()
        }
    }

    fn resolved(request: &ExecutionRequest) -> Vec<String> {
        resolve_env(request, defaults)
    }

    #[test]
    fn an_omitted_env_takes_the_default_block() {
        let r = request(DefaultEnvCompatibility::DefaultBlock);
        assert_eq!(resolved(&r), ["PATH=/default/bin", "TERM=xterm-256color"]);
    }

    #[test]
    fn an_explicitly_empty_env_stays_empty() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = Some(Vec::new());
        assert!(resolved(&r).is_empty());
    }

    #[test]
    fn a_supplied_env_is_used_verbatim() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = Some(vec!["FOO=bar".to_string()]);
        assert_eq!(resolved(&r), ["FOO=bar"]);
    }

    #[test]
    fn an_overlay_replaces_in_place_and_appends_in_order() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = Some(vec![
            "TERM=vt100".to_string(),
            "FOO=bar".to_string(),
            "BAZ=qux".to_string(),
        ]);
        r.inherit_default_env = true;

        assert_eq!(
            resolved(&r),
            ["PATH=/default/bin", "TERM=vt100", "FOO=bar", "BAZ=qux"]
        );
    }

    #[test]
    fn a_repeated_caller_key_collapses_to_the_last_value() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = Some(vec![
            "FOO=first".to_string(),
            "FOO=second".to_string(),
            "PATH=/a".to_string(),
            "PATH=/b".to_string(),
        ]);
        r.inherit_default_env = true;

        assert_eq!(
            resolved(&r),
            ["PATH=/b", "TERM=xterm-256color", "FOO=second"]
        );
    }

    #[test]
    fn an_empty_caller_value_still_replaces_the_default() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = Some(vec!["PATH=".to_string()]);
        r.inherit_default_env = true;

        assert_eq!(resolved(&r), ["PATH=", "TERM=xterm-256color"]);
    }

    #[test]
    fn a_caller_entry_without_a_value_is_dropped_by_the_overlay() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = Some(vec!["FEATURE_FLAG".to_string(), "FOO=bar".to_string()]);
        r.inherit_default_env = true;

        let entries = resolved(&r);
        assert!(!entries.iter().any(|kv| kv.starts_with("FEATURE_FLAG")));
        assert!(entries.contains(&"FOO=bar".to_string()));
    }

    #[test]
    fn below_0_9_the_callers_entries_pass_through_untouched() {
        let mut r = request(DefaultEnvCompatibility::LegacyCompatible);
        r.env = Some(vec!["FEATURE_FLAG".to_string(), "FOO=bar".to_string()]);
        r.inherit_default_env = true;

        assert_eq!(resolved(&r), ["FEATURE_FLAG", "FOO=bar"]);

        r.env = None;
        assert!(resolved(&r).is_empty());
    }

    #[test]
    fn each_state_of_process_env_resolves_to_its_own_outcome() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);

        r.env = None;
        assert_eq!(EnvResolution::of(&r), EnvResolution::Default);

        r.inherit_default_env = true;
        assert_eq!(EnvResolution::of(&r), EnvResolution::Default);

        r.env = Some(Vec::new());
        assert_eq!(EnvResolution::of(&r), EnvResolution::Overlay);

        r.inherit_default_env = false;
        assert_eq!(EnvResolution::of(&r), EnvResolution::Replace);

        r.env = Some(vec!["FOO=bar".to_string()]);
        assert_eq!(EnvResolution::of(&r), EnvResolution::Replace);

        r.inherit_default_env = true;
        assert_eq!(EnvResolution::of(&r), EnvResolution::Overlay);
    }

    #[test]
    fn below_0_9_every_state_resolves_to_legacy() {
        let mut r = request(DefaultEnvCompatibility::LegacyCompatible);

        for env in [None, Some(Vec::new()), Some(vec!["FOO=bar".to_string()])] {
            for inherit in [false, true] {
                r.env = env.clone();
                r.inherit_default_env = inherit;
                assert_eq!(EnvResolution::of(&r), EnvResolution::Legacy);
            }
        }
    }

    #[test]
    fn env_pairs_drops_an_entry_without_a_value() {
        let entries = vec![
            "FOO=bar".to_string(),
            "FEATURE_FLAG".to_string(),
            "EMPTY=".to_string(),
        ];
        assert_eq!(env_pairs(&entries), [("FOO", "bar"), ("EMPTY", "")]);
    }
}
