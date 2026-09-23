// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Default `process.env` block for the Seatbelt backend, introduced by schema
//! 0.9.
//!
//! Kept out of [`crate::seatbelt_runner`], which is `target_os = "macos"`, so
//! the resolution rules are compiled and tested on every host.

use wxc_common::models::ExecutionRequest;

/// Baseline `PATH` for the sandboxed child. We always start from a cleared
/// environment (so the host process's env — cloud creds, API tokens — never
/// leaks into untrusted sandboxed code), which means we must supply a default
/// `PATH` for the `/bin/sh` wrapper and common tools to resolve.
pub const DEFAULT_SANDBOX_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// `TERM` for the sandboxed child. Curses-based tools error out when it is
/// unset; it does not make a tool believe it has a terminal, which is `isatty`.
pub const DEFAULT_TERM: &str = "xterm-256color";

/// The default environment, from schema 0.9: `PATH`, `TERM`, and — when the
/// runner resolved one — `HOME`.
///
/// `HOME` is left unset with no resolved directory: the profile is deny-default
/// and grants `/private/tmp` only under `guiAccess`, so a `/tmp` fallback would
/// be either unwritable or a shared preplant target.
fn default_env(working_directory: Option<&str>) -> Vec<(String, String)> {
    let mut entries = vec![("PATH".to_string(), DEFAULT_SANDBOX_PATH.to_string())];

    if let Some(home) = working_directory {
        entries.push(("HOME".to_string(), home.to_string()));
    }

    entries.push(("TERM".to_string(), DEFAULT_TERM.to_string()));
    entries
}

/// The entries the child should get, as `KEY=VALUE` strings.
///
/// `working_directory` is the directory the runner will start the child in, as
/// described on [`default_env`].
///
/// From schema 0.9 the four states of `process.env` stay distinct: omitted
/// takes the default, `[]` is empty, a supplied environment is used verbatim,
/// and `inheritDefaultEnv` layers a supplied environment over the default.
/// Below 0.9 the caller's entries are passed through untouched and the runner
/// supplies the baseline `PATH` as it always did.
pub fn resolved_env(request: &ExecutionRequest, working_directory: Option<&str>) -> Vec<String> {
    if !request.supplies_default_env() {
        return request.env_entries().to_vec();
    }

    let entries = match (&request.env, request.inherit_default_env) {
        (None, _) => default_env(working_directory),
        (Some(supplied), false) => return supplied.clone(),
        (Some(supplied), true) => {
            let mut entries = default_env(working_directory);
            // A caller entry replaces the same-named default rather than being
            // appended, so the later `Command::env` call cannot shadow it.
            for (key, value) in supplied.iter().filter_map(|kv| kv.split_once('=')) {
                match entries.iter_mut().find(|(name, _)| name == key) {
                    Some(slot) => *slot = (key.to_string(), value.to_string()),
                    None => entries.push((key.to_string(), value.to_string())),
                }
            }
            entries
        }
    };

    entries
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

/// Split resolved entries into the `(key, value)` pairs the runner applies.
/// An entry with no `=` names no variable, so it is dropped.
pub fn env_pairs(entries: &[String]) -> Vec<(&str, &str)> {
    entries.iter().filter_map(|kv| kv.split_once('=')).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::DefaultEnvCompatibility;

    fn request(compatibility: DefaultEnvCompatibility) -> ExecutionRequest {
        ExecutionRequest {
            default_env_compatibility: compatibility,
            ..Default::default()
        }
    }

    fn value<'a>(entries: &'a [String], key: &str) -> Option<&'a str> {
        entries
            .iter()
            .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
    }

    #[test]
    fn below_0_9_the_caller_env_passes_through_untouched() {
        // Pre-0.9 the baseline PATH comes from the runner, not from here, so a
        // supplied env still gets one.
        let mut r = request(DefaultEnvCompatibility::LegacyCompatible);
        r.env = None;
        assert!(resolved_env(&r, None).is_empty());

        r.env = Some(vec!["FOO=bar".into()]);
        assert_eq!(resolved_env(&r, None), vec!["FOO=bar".to_string()]);
    }

    /// A direct typed SDK request that named no contract takes the current
    /// behavior.
    #[test]
    fn a_direct_sdk_request_gets_the_default_block() {
        let r = ExecutionRequest::default();
        assert_eq!(
            value(&resolved_env(&r, None), "PATH"),
            Some(DEFAULT_SANDBOX_PATH)
        );
    }

    #[test]
    fn an_omitted_env_gets_the_default_block() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = None;
        let entries = resolved_env(&r, Some("/workspace"));
        assert_eq!(value(&entries, "PATH"), Some(DEFAULT_SANDBOX_PATH));
        assert_eq!(value(&entries, "HOME"), Some("/workspace"));
        assert_eq!(value(&entries, "TERM"), Some(DEFAULT_TERM));
    }

    #[test]
    fn an_explicitly_empty_env_stays_empty() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = Some(vec![]);
        assert!(resolved_env(&r, None).is_empty());
    }

    #[test]
    fn a_supplied_env_is_used_verbatim() {
        // The 0.9 behavior change: no implicit PATH under a supplied env.
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = Some(vec!["FOO=bar".into()]);
        assert_eq!(resolved_env(&r, None), vec!["FOO=bar".to_string()]);
    }

    #[test]
    fn inherit_default_env_layers_over_the_default_block() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = Some(vec!["FOO=bar".into(), "PATH=/only/mine".into()]);
        r.inherit_default_env = true;
        let entries = resolved_env(&r, None);

        assert_eq!(value(&entries, "FOO"), Some("bar"));
        assert_eq!(value(&entries, "TERM"), Some(DEFAULT_TERM));
        assert_eq!(value(&entries, "PATH"), Some("/only/mine"));
        assert_eq!(
            entries.iter().filter(|kv| kv.starts_with("PATH=")).count(),
            1
        );
    }

    /// `HOME` names the directory the runner will start the child in, which the
    /// runner resolves (including `~` expansion) and passes in — this module
    /// deliberately does not re-derive it from the request.
    #[test]
    fn home_follows_the_directory_the_child_starts_in() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = None;
        assert_eq!(
            value(&resolved_env(&r, Some("/workspace")), "HOME"),
            Some("/workspace")
        );
    }

    #[test]
    fn an_unresolved_working_directory_leaves_home_unset() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = None;
        // Set on the request but never resolved by the runner: only what the
        // runner passes in counts.
        r.working_directory = "/workspace".into();
        let entries = resolved_env(&r, None);

        assert_eq!(value(&entries, "HOME"), None);
        assert!(!entries.iter().any(|kv| kv.starts_with("HOME=")));
        assert_eq!(value(&entries, "PATH"), Some(DEFAULT_SANDBOX_PATH));
        assert_eq!(value(&entries, "TERM"), Some(DEFAULT_TERM));
    }

    #[test]
    fn a_repeated_caller_key_collapses_to_the_last_value() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = Some(vec!["FOO=first".into(), "FOO=second".into()]);
        r.inherit_default_env = true;
        let entries = resolved_env(&r, None);

        assert_eq!(value(&entries, "FOO"), Some("second"));
        assert_eq!(
            entries.iter().filter(|kv| kv.starts_with("FOO=")).count(),
            1
        );
    }

    #[test]
    fn an_empty_caller_value_still_replaces_the_default() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = Some(vec!["PATH=".into()]);
        r.inherit_default_env = true;
        let entries = resolved_env(&r, None);

        assert_eq!(value(&entries, "PATH"), Some(""));
        assert_eq!(
            entries.iter().filter(|kv| kv.starts_with("PATH=")).count(),
            1
        );
    }

    #[test]
    fn a_caller_entry_without_a_value_is_dropped_by_both_modes() {
        let mut r = request(DefaultEnvCompatibility::DefaultBlock);
        r.env = Some(vec!["FEATURE_FLAG".into(), "FOO=bar".into()]);

        let verbatim = resolved_env(&r, None);
        assert!(verbatim.contains(&"FEATURE_FLAG".to_string()));
        assert_eq!(env_pairs(&verbatim), vec![("FOO", "bar")]);

        r.inherit_default_env = true;
        let inherited = resolved_env(&r, None);
        assert!(!inherited.iter().any(|kv| kv.starts_with("FEATURE_FLAG")));
        assert_eq!(value(&inherited, "FOO"), Some("bar"));
        assert!(!env_pairs(&inherited)
            .iter()
            .any(|(key, _)| *key == "FEATURE_FLAG"));
    }
}
