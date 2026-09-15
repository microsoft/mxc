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

/// Whether this schema version supplies a default environment.
pub fn supports_default_env(version: &str) -> bool {
    semver::Version::parse(version).is_ok_and(|v| v.major > 0 || v.minor >= 9)
}

/// The default environment, from schema 0.9: `PATH`, `HOME`, and `TERM`.
///
/// `PATH` is the same value Seatbelt has always supplied; 0.9 adds the other
/// two and makes all three suppressible by an explicitly empty `process.env`.
///
/// `HOME` names the directory the child actually runs in, so it is a path the
/// sandbox profile allows rather than the launching user's real home, which
/// would almost certainly be denied.
fn default_env(request: &ExecutionRequest) -> Vec<(String, String)> {
    let home = request
        .resolved_working_directory()
        .map(|dir| dir.path.to_string())
        .unwrap_or_else(|| FALLBACK_HOME.to_string());

    vec![
        ("PATH".to_string(), DEFAULT_SANDBOX_PATH.to_string()),
        ("HOME".to_string(), home),
        ("TERM".to_string(), DEFAULT_TERM.to_string()),
    ]
}

/// The entries the child should get, as `KEY=VALUE` strings.
///
/// From schema 0.9 the four states of `process.env` stay distinct: omitted
/// takes the default, `[]` is empty, a supplied environment is used verbatim,
/// and `inheritDefaultEnv` layers a supplied environment over the default.
/// Below 0.9 the caller's entries are passed through untouched and the runner
/// supplies the baseline `PATH` as it always did.
pub fn resolved_env(request: &ExecutionRequest) -> Vec<String> {
    if !supports_default_env(&request.schema_version) {
        return request.env_entries().to_vec();
    }

    let entries = match (&request.env, request.inherit_default_env) {
        (None, _) => default_env(request),
        (Some(supplied), false) => return supplied.clone(),
        (Some(supplied), true) => {
            let mut entries = default_env(request);
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

    fn request(version: &str) -> ExecutionRequest {
        ExecutionRequest {
            schema_version: version.into(),
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
        for version in ["0.7.0-alpha", "0.8.0-alpha", "bogus"] {
            let mut r = request(version);
            r.env = None;
            assert!(resolved_env(&r).is_empty(), "{version}");

            r.env = Some(vec!["FOO=bar".into()]);
            assert_eq!(resolved_env(&r), vec!["FOO=bar".to_string()], "{version}");
        }
    }

    #[test]
    fn an_omitted_env_gets_the_default_block() {
        let mut r = request("0.9.0-alpha");
        r.env = None;
        let entries = resolved_env(&r);
        assert_eq!(value(&entries, "PATH"), Some(DEFAULT_SANDBOX_PATH));
        assert_eq!(value(&entries, "HOME"), Some(FALLBACK_HOME));
        assert_eq!(value(&entries, "TERM"), Some(DEFAULT_TERM));
    }

    #[test]
    fn an_explicitly_empty_env_stays_empty() {
        let mut r = request("0.9.0-alpha");
        r.env = Some(vec![]);
        assert!(resolved_env(&r).is_empty());
    }

    #[test]
    fn a_supplied_env_is_used_verbatim() {
        // The 0.9 behavior change: no implicit PATH under a supplied env.
        let mut r = request("0.9.0-alpha");
        r.env = Some(vec!["FOO=bar".into()]);
        assert_eq!(resolved_env(&r), vec!["FOO=bar".to_string()]);
    }

    #[test]
    fn inherit_default_env_layers_over_the_default_block() {
        let mut r = request("0.9.0-alpha");
        r.env = Some(vec!["FOO=bar".into(), "PATH=/only/mine".into()]);
        r.inherit_default_env = true;
        let entries = resolved_env(&r);

        assert_eq!(value(&entries, "FOO"), Some("bar"));
        assert_eq!(value(&entries, "TERM"), Some(DEFAULT_TERM));
        assert_eq!(value(&entries, "PATH"), Some("/only/mine"));
        assert_eq!(
            entries.iter().filter(|kv| kv.starts_with("PATH=")).count(),
            1
        );
    }

    #[test]
    fn home_follows_the_resolved_working_directory() {
        let mut r = request("0.9.0-alpha");
        r.env = None;
        r.working_directory = "/workspace".into();
        assert_eq!(value(&resolved_env(&r), "HOME"), Some("/workspace"));
    }
}
