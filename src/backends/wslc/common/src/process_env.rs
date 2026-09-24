// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `process.env` resolution for the WSLc backend.
//!
//! `WslcSetProcessSettingsEnvVariables` layers its entries over the image's
//! baked-in `ENV` and the SDK exposes no call that clears it, so it alone
//! cannot produce the empty and verbatim environments schema 0.9 requires.
//! Those two states launch the workload through `env -i` instead, which wipes
//! what the SDK handed the process before the shell starts.

use serde::{Deserialize, Serialize};

use wxc_common::models::ExecutionRequest;

const SHELL: &str = "/bin/sh";

/// An image that does not provide this path cannot run [`EnvScope::Replace`].
const ENV: &str = "/usr/bin/env";

/// How `process.env` combines with the container image's own environment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvScope {
    /// Layer the entries over the image's environment.
    #[default]
    Merge,
    /// Give the child the entries and nothing else.
    Replace,
}

impl EnvScope {
    /// The scope the request selects, which below schema 0.9 is always
    /// [`EnvScope::Merge`] because the four states of `process.env` are not
    /// distinct there.
    pub fn of(request: &ExecutionRequest) -> Self {
        match (&request.env, request.inherit_default_env) {
            (Some(_), false) if request.supplies_default_env() => Self::Replace,
            _ => Self::Merge,
        }
    }
}

/// The container process's argv, running `script_code` under the shell.
pub fn argv_words(scope: EnvScope, entries: &[String], script_code: &str) -> Vec<String> {
    let mut argv = Vec::new();

    if scope == EnvScope::Replace {
        argv.push(ENV.to_string());
        argv.push("-i".to_string());

        // Without this, `env` reads an entry that starts with `-` as one of its
        // own options.
        argv.push("--".to_string());

        // An entry naming no variable would be taken as the command to run.
        argv.extend(entries.iter().filter(|e| e.contains('=')).cloned());
    }

    argv.push(SHELL.to_string());
    argv.push("-c".to_string());
    argv.push(script_code.to_string());
    argv
}

/// The entries to hand the SDK's environment setter, empty under
/// [`EnvScope::Replace`] because `env -i` would clear whatever it applied.
pub fn sdk_entries(scope: EnvScope, entries: &[String]) -> &[String] {
    match scope {
        EnvScope::Merge => entries,
        EnvScope::Replace => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::DefaultEnvCompatibility;

    fn request(env: Option<Vec<&str>>, inherit_default_env: bool) -> ExecutionRequest {
        ExecutionRequest {
            default_env_compatibility: DefaultEnvCompatibility::DefaultBlock,
            env: env.map(|e| e.into_iter().map(String::from).collect()),
            inherit_default_env,
            ..Default::default()
        }
    }

    fn entries(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    /// Resolve a request the way both execution paths do: scope from the
    /// request, entries from `env_entries`, then argv and the SDK's entries.
    fn resolve(request: &ExecutionRequest) -> (Vec<String>, Vec<String>) {
        let scope = EnvScope::of(request);
        let supplied = request.env_entries();
        (
            argv_words(scope, supplied, "run"),
            sdk_entries(scope, supplied).to_vec(),
        )
    }

    #[test]
    fn the_0_9_contract_holds_for_every_state_of_process_env() {
        struct Case {
            label: &'static str,
            env: Option<Vec<&'static str>>,
            inherit_default_env: bool,
            argv: &'static [&'static str],
            sdk: &'static [&'static str],
        }

        // The child's environment is the image's `ENV` plus whatever reaches
        // the SDK, except under `env -i`, where it is only what argv carries.
        let cases = [
            Case {
                label: "omitted takes the image environment",
                env: None,
                inherit_default_env: false,
                argv: &["/bin/sh", "-c", "run"],
                sdk: &[],
            },
            Case {
                label: "omitted ignores inheritDefaultEnv",
                env: None,
                inherit_default_env: true,
                argv: &["/bin/sh", "-c", "run"],
                sdk: &[],
            },
            Case {
                label: "explicitly empty leaves the child nothing",
                env: Some(vec![]),
                inherit_default_env: false,
                argv: &["/usr/bin/env", "-i", "--", "/bin/sh", "-c", "run"],
                sdk: &[],
            },
            Case {
                label: "explicitly empty plus inheritDefaultEnv takes the image environment",
                env: Some(vec![]),
                inherit_default_env: true,
                argv: &["/bin/sh", "-c", "run"],
                sdk: &[],
            },
            Case {
                label: "supplied is used verbatim",
                env: Some(vec!["FOO=bar"]),
                inherit_default_env: false,
                argv: &[
                    "/usr/bin/env",
                    "-i",
                    "--",
                    "FOO=bar",
                    "/bin/sh",
                    "-c",
                    "run",
                ],
                sdk: &[],
            },
            Case {
                label: "supplied plus inheritDefaultEnv layers over the image environment",
                env: Some(vec!["FOO=bar"]),
                inherit_default_env: true,
                argv: &["/bin/sh", "-c", "run"],
                sdk: &["FOO=bar"],
            },
        ];

        for case in cases {
            let (argv, sdk) = resolve(&request(case.env, case.inherit_default_env));
            assert_eq!(argv, case.argv, "argv for {}", case.label);
            assert_eq!(sdk, case.sdk, "SDK entries for {}", case.label);
        }
    }

    #[test]
    fn an_omitted_and_an_explicitly_empty_env_stay_distinct() {
        // Both carry no entries, so only the scope separates "the image's
        // environment" from "nothing".
        let omitted = resolve(&request(None, false));
        let empty = resolve(&request(Some(vec![]), false));

        assert_ne!(omitted.0, empty.0);
    }

    #[test]
    fn below_0_9_every_state_keeps_the_image_environment() {
        for (env, inherit) in [
            (None, false),
            (Some(vec![]), false),
            (Some(vec!["FOO=bar"]), false),
            (Some(vec!["FOO=bar"]), true),
        ] {
            let mut r = request(env, inherit);
            r.default_env_compatibility = DefaultEnvCompatibility::LegacyCompatible;
            assert_eq!(EnvScope::of(&r), EnvScope::Merge);
        }
    }

    #[test]
    fn a_merged_environment_runs_the_shell_directly() {
        assert_eq!(
            argv_words(EnvScope::Merge, &entries(&["FOO=bar"]), "echo hi"),
            ["/bin/sh", "-c", "echo hi"]
        );
    }

    #[test]
    fn a_replaced_environment_runs_the_shell_through_env() {
        assert_eq!(
            argv_words(EnvScope::Replace, &entries(&["FOO=bar"]), "echo hi"),
            [
                "/usr/bin/env",
                "-i",
                "--",
                "FOO=bar",
                "/bin/sh",
                "-c",
                "echo hi"
            ]
        );
    }

    #[test]
    fn a_replaced_empty_environment_leaves_the_child_nothing() {
        assert_eq!(
            argv_words(EnvScope::Replace, &[], "echo hi"),
            ["/usr/bin/env", "-i", "--", "/bin/sh", "-c", "echo hi"]
        );
    }

    #[test]
    fn a_replaced_entry_naming_no_variable_is_dropped() {
        assert_eq!(
            argv_words(
                EnvScope::Replace,
                &entries(&["FEATURE_FLAG", "FOO=bar"]),
                "echo hi"
            ),
            [
                "/usr/bin/env",
                "-i",
                "--",
                "FOO=bar",
                "/bin/sh",
                "-c",
                "echo hi"
            ]
        );
    }

    #[test]
    fn a_replaced_entry_keeps_every_character_of_its_value() {
        let supplied = entries(&["FOO=a b", "BAR==x=", "EMPTY="]);
        let argv = argv_words(EnvScope::Replace, &supplied, "echo hi");

        assert_eq!(argv[3..6], supplied[..]);
    }

    #[test]
    fn a_repeated_replaced_key_reaches_the_child_in_order() {
        // `env` applies its assignments left to right, so the last one wins.
        let argv = argv_words(
            EnvScope::Replace,
            &entries(&["FOO=first", "FOO=second"]),
            "echo hi",
        );

        assert_eq!(
            argv[3..5],
            ["FOO=first".to_string(), "FOO=second".to_string()]
        );
    }

    #[test]
    fn only_a_merged_environment_reaches_the_sdk() {
        let supplied = entries(&["FOO=bar"]);

        assert_eq!(sdk_entries(EnvScope::Merge, &supplied), supplied.as_slice());
        assert!(sdk_entries(EnvScope::Replace, &supplied).is_empty());
    }
}
