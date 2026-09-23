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
/// described on [`default_env`]. The state dispatch and overlay merge are
/// shared; see [`wxc_common::default_env::resolve_env`].
pub fn resolved_env(request: &ExecutionRequest, working_directory: Option<&str>) -> Vec<String> {
    wxc_common::default_env::resolve_env(request, || default_env(working_directory))
}

pub use wxc_common::default_env::env_pairs;

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
