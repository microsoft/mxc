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

/// `HOME` when the request resolves no working directory.
pub const FALLBACK_HOME: &str = "/tmp";

/// `TERM` for the sandboxed child. Curses-based tools error out when it is
/// unset; it does not make a tool believe it has a terminal, which is `isatty`.
pub const DEFAULT_TERM: &str = "xterm-256color";

/// The default environment, from schema 0.9: `PATH`, `HOME`, and `TERM`.
///
/// `PATH` is the same value Seatbelt has always supplied; 0.9 adds the other
/// two and makes all three suppressible by an explicitly empty `process.env`.
///
/// `HOME` names the directory the child actually runs in, so the caller passes
/// the directory it will `chdir` into rather than letting this re-derive one —
/// re-deriving it would miss the runner's `~` expansion and could name a
/// directory the child never entered. `None` means the runner has no directory
/// to start it in, which takes [`FALLBACK_HOME`].
fn default_env(working_directory: Option<&str>) -> Vec<(String, String)> {
    let home = working_directory.unwrap_or(FALLBACK_HOME).to_string();

    vec![
        ("PATH".to_string(), DEFAULT_SANDBOX_PATH.to_string()),
        ("HOME".to_string(), home),
        ("TERM".to_string(), DEFAULT_TERM.to_string()),
    ]
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

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::ContractVersion;

    fn request(version: Option<ContractVersion>) -> ExecutionRequest {
        ExecutionRequest {
            source_contract: version,
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
        for version in [
            ContractVersion::V0_6_0Alpha,
            ContractVersion::V0_7_0Alpha,
            ContractVersion::V0_8_0Alpha,
        ] {
            let mut r = request(Some(version));
            r.env = None;
            assert!(resolved_env(&r, None).is_empty(), "{version:?}");

            r.env = Some(vec!["FOO=bar".into()]);
            assert_eq!(
                resolved_env(&r, None),
                vec!["FOO=bar".to_string()],
                "{version:?}"
            );
        }
    }

    /// A direct typed SDK request has no external contract attribution and
    /// takes the current behavior.
    #[test]
    fn a_direct_sdk_request_gets_the_default_block() {
        let mut r = request(None);
        r.env = None;
        assert_eq!(
            value(&resolved_env(&r, None), "PATH"),
            Some(DEFAULT_SANDBOX_PATH)
        );
    }

    #[test]
    fn an_omitted_env_gets_the_default_block() {
        let mut r = request(Some(ContractVersion::V0_9_0Alpha));
        r.env = None;
        let entries = resolved_env(&r, None);
        assert_eq!(value(&entries, "PATH"), Some(DEFAULT_SANDBOX_PATH));
        assert_eq!(value(&entries, "HOME"), Some(FALLBACK_HOME));
        assert_eq!(value(&entries, "TERM"), Some(DEFAULT_TERM));
    }

    #[test]
    fn an_explicitly_empty_env_stays_empty() {
        let mut r = request(Some(ContractVersion::V0_9_0Alpha));
        r.env = Some(vec![]);
        assert!(resolved_env(&r, None).is_empty());
    }

    #[test]
    fn a_supplied_env_is_used_verbatim() {
        // The 0.9 behavior change: no implicit PATH under a supplied env.
        let mut r = request(Some(ContractVersion::V0_9_0Alpha));
        r.env = Some(vec!["FOO=bar".into()]);
        assert_eq!(resolved_env(&r, None), vec!["FOO=bar".to_string()]);
    }

    #[test]
    fn inherit_default_env_layers_over_the_default_block() {
        let mut r = request(Some(ContractVersion::V0_9_0Alpha));
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
        let mut r = request(Some(ContractVersion::V0_9_0Alpha));
        r.env = None;
        assert_eq!(
            value(&resolved_env(&r, Some("/workspace")), "HOME"),
            Some("/workspace")
        );
    }

    /// A working directory the runner could not resolve leaves `HOME` on the
    /// writable fallback rather than following the child to `/`.
    #[test]
    fn an_unresolved_working_directory_falls_back() {
        let mut r = request(Some(ContractVersion::V0_9_0Alpha));
        r.env = None;
        // Set on the request but never resolved by the runner: only what the
        // runner passes in counts.
        r.working_directory = "/workspace".into();
        assert_eq!(value(&resolved_env(&r, None), "HOME"), Some(FALLBACK_HOME));
    }
}
