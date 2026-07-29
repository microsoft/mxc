// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared `--telemetry-consent-{status,grant,revoke}` CLI handling.
//!
//! All three executors (`wxc-exec`, `lxc-exec`, `mxc-exec-mac`) expose an
//! identical consent CLI surface for parity — a host application driving any
//! of them from any platform sees the same flags and the same JSON status
//! contract — but only `wxc-exec` actually persists anything; the others
//! resolve through [`super::consent`]'s non-Windows stub, which always
//! reports [`super::ConsentState::NotApplicable`] and refuses writes. This
//! module is the **single** implementation of that shared behavior so the
//! three executors' `main.rs` files delegate instead of each re-implementing
//! (and risking drifting) the same fast path. See
//! `docs/telemetry/telemetry-consent-design.md`.

use serde::Serialize;

use super::{consent, policy};

/// The subset of the executor's parsed CLI flags relevant to telemetry
/// consent administration. Deliberately primitive (not a `clap`-derived
/// type) so this module has no dependency on any one executor's `Cli` struct.
#[derive(Debug, Clone, Copy)]
pub struct ConsentCliFlags<'a> {
    /// `--telemetry-consent-status`
    pub status: bool,
    /// `--telemetry-consent-grant`
    pub grant: bool,
    /// `--telemetry-consent-revoke`
    pub revoke: bool,
    /// `--telemetry-consent-source`; defaults to `"cli"` when absent.
    pub source: Option<&'a str>,
}

/// Wire shape for the one-line JSON status the CLI prints, e.g.
/// `{"consent":"granted","needsPrompt":false,"policy":"unrestricted"}`. Kept
/// as a real (de)serializable type — rather than hand-built string
/// interpolation — so the JSON is always well-formed and any future additive
/// field goes through `serde`.
///
/// `needsPrompt` is carried explicitly, rather than left for each SDK to
/// derive from `consent`, so that the "should the host ask the user?" policy
/// has exactly one implementation ([`consent::needs_consent_prompt`]) across
/// every language binding.
///
/// `policy` reports the administrative ceiling ([`policy::PolicyState`]) so a
/// host can distinguish "the user hasn't opted in" from "an administrator has
/// disabled this" and explain the difference, rather than rendering an inert
/// toggle. It is reported independently of `consent` because the two are
/// genuinely independent: a user's recorded grant is preserved verbatim even
/// while policy suppresses collection, so relaxing the policy later restores
/// the user's actual choice instead of silently re-prompting.
#[derive(Serialize)]
struct ConsentStatusResponse {
    consent: &'static str,
    #[serde(rename = "needsPrompt")]
    needs_prompt: bool,
    policy: &'static str,
}

/// What the caller should do after [`handle_consent_flags`] handled one of
/// the consent flags: print these lines and terminate with `exit_code`.
///
/// Returned as data rather than acted on here so `wxc_common` — the
/// cross-platform foundation crate — never owns process lifetime; the thin
/// executor binaries do the exiting, exactly as they do for every other CLI
/// fast path. It also makes every branch below assertable in a unit test
/// instead of terminating the test runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentCliOutcome {
    /// Line to print to stdout, if any (the JSON status contract).
    pub stdout: Option<String>,
    /// Line to print to stderr, if any.
    pub stderr: Option<String>,
    /// Process exit code: `0` on success, `64` (`EX_USAGE`) for mutually
    /// exclusive flags, `1` for a failed write or serialization.
    pub exit_code: i32,
}

impl ConsentCliOutcome {
    /// Prints the outcome's stdout/stderr lines and returns the exit code the
    /// caller should terminate with.
    pub fn emit(&self) -> i32 {
        if let Some(out) = &self.stdout {
            println!("{out}");
        }
        if let Some(err) = &self.stderr {
            eprintln!("{err}");
        }
        self.exit_code
    }

    fn failure(message: String, exit_code: i32) -> Self {
        Self {
            stdout: None,
            stderr: Some(message),
            exit_code,
        }
    }
}

/// Handles the `--telemetry-consent-{status,grant,revoke}` fast path shared
/// by all three executors.
///
/// Returns `Some(outcome)` if one of the flags was set — the caller should
/// [`ConsentCliOutcome::emit`] it and exit immediately without spawning a
/// sandbox or touching config parsing — or `None` if none were passed and
/// normal execution should proceed.
///
/// Windows-only in effect: [`super::consent`] compiles a non-Windows stub
/// that always reports `NotApplicable` and refuses to persist a decision, so
/// `--telemetry-consent-grant`/`-revoke` fail with a clear error on `lxc-exec`
/// / `mxc-exec-mac` rather than silently pretending to accept consent MXC
/// can never act on.
pub fn handle_consent_flags(flags: &ConsentCliFlags<'_>) -> Option<ConsentCliOutcome> {
    if !(flags.status || flags.grant || flags.revoke) {
        return None;
    }

    if flags.grant && flags.revoke {
        return Some(ConsentCliOutcome::failure(
            "Error: --telemetry-consent-grant and --telemetry-consent-revoke are mutually exclusive"
                .to_string(),
            // EX_USAGE, matching the convention for a malformed command line.
            64,
        ));
    }

    if flags.grant || flags.revoke {
        let source = flags.source.unwrap_or("cli");
        if let Err(e) = consent::set_consent(flags.grant, source) {
            return Some(ConsentCliOutcome::failure(format!("Error: {e}"), 1));
        }
    }

    // --telemetry-consent-status (or the post-grant/-revoke confirmation)
    // always prints the resulting state so callers get a single, uniform
    // JSON contract regardless of which flag was passed.
    //
    // Each underlying state is read exactly once and `needs_prompt` is derived
    // from those same two values, rather than calling
    // `consent::needs_consent_prompt()` (which would re-read both). Consumers
    // treat this response as one snapshot, so a concurrent grant/revoke or
    // policy change must not be able to produce a self-contradictory payload
    // such as `policy:"blocked"` together with `needsPrompt:true`.
    let consent_state = consent::get_consent();
    let policy_state = policy::get_policy();
    let response = ConsentStatusResponse {
        consent: consent_state.as_str(),
        needs_prompt: policy_state.allows_collection() && consent_state.needs_prompt(),
        policy: policy_state.as_str(),
    };
    match serde_json::to_string(&response) {
        Ok(json) => Some(ConsentCliOutcome {
            stdout: Some(json),
            stderr: None,
            exit_code: 0,
        }),
        Err(e) => Some(ConsentCliOutcome::failure(
            // Serialization of two static strings cannot realistically fail,
            // but fail loudly rather than silently print nothing if it does.
            format!("Error: failed to serialize telemetry consent status: {e}"),
            1,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(status: bool, grant: bool, revoke: bool) -> ConsentCliFlags<'static> {
        ConsentCliFlags {
            status,
            grant,
            revoke,
            source: None,
        }
    }

    #[test]
    fn no_flags_is_a_noop() {
        assert!(handle_consent_flags(&flags(false, false, false)).is_none());
    }

    #[test]
    fn status_response_serializes_as_expected_json() {
        let response = ConsentStatusResponse {
            consent: "granted",
            needs_prompt: false,
            policy: "unrestricted",
        };
        assert_eq!(
            serde_json::to_string(&response).unwrap(),
            r#"{"consent":"granted","needsPrompt":false,"policy":"unrestricted"}"#
        );
    }

    #[test]
    fn status_response_field_order_is_stable() {
        // The SDKs parse this by field name, but the PowerShell smoke test
        // compares the whole string, so pin the emitted order.
        let response = ConsentStatusResponse {
            consent: "undetermined",
            needs_prompt: true,
            policy: "unrestricted",
        };
        assert_eq!(
            serde_json::to_string(&response).unwrap(),
            r#"{"consent":"undetermined","needsPrompt":true,"policy":"unrestricted"}"#
        );
    }

    /// An administrative denial must be reported alongside the user's own
    /// (unchanged) decision, and must suppress the prompt — a host that asked
    /// for consent MXC would then ignore would be a dark pattern.
    #[test]
    fn blocked_policy_serializes_with_prompt_suppressed() {
        let response = ConsentStatusResponse {
            consent: "granted",
            needs_prompt: false,
            policy: "blocked",
        };
        assert_eq!(
            serde_json::to_string(&response).unwrap(),
            r#"{"consent":"granted","needsPrompt":false,"policy":"blocked"}"#
        );
    }

    /// Previously unreachable in-process: this branch called
    /// `std::process::exit(64)` and would have killed the test runner.
    #[test]
    fn grant_and_revoke_together_is_a_usage_error() {
        let outcome = handle_consent_flags(&flags(false, true, true)).expect("handled");
        assert_eq!(outcome.exit_code, 64);
        assert_eq!(outcome.stdout, None);
        assert!(outcome
            .stderr
            .as_deref()
            .unwrap()
            .contains("mutually exclusive"));
    }

    /// The non-Windows contract every executor must honor: status is a
    /// successful `not-applicable` report, and grant/revoke are refused
    /// rather than silently accepted. MXC must never offer — or appear to
    /// record — consent on a platform where it cannot collect telemetry.
    ///
    /// Gated to non-Windows (rather than merged into the Windows tests)
    /// because it asserts the *stub* behavior; without it, Linux/macOS CI
    /// would run no test at all over this shared handler.
    #[cfg(not(target_os = "windows"))]
    mod non_windows_tests {
        use super::*;

        #[test]
        fn status_reports_not_applicable_and_succeeds() {
            let outcome = handle_consent_flags(&flags(true, false, false)).expect("handled");
            assert_eq!(outcome.exit_code, 0);
            assert_eq!(
                outcome.stdout.as_deref(),
                Some(
                    r#"{"consent":"not-applicable","needsPrompt":false,"policy":"not-applicable"}"#
                )
            );
            assert_eq!(outcome.stderr, None);
        }

        #[test]
        fn grant_is_refused() {
            let outcome = handle_consent_flags(&flags(false, true, false)).expect("handled");
            assert_eq!(outcome.exit_code, 1);
            assert_eq!(outcome.stdout, None);
            assert!(outcome.stderr.as_deref().unwrap().contains("Windows-only"));
        }

        #[test]
        fn revoke_is_refused() {
            let outcome = handle_consent_flags(&flags(false, false, true)).expect("handled");
            assert_eq!(outcome.exit_code, 1);
            assert_eq!(outcome.stdout, None);
            assert!(outcome.stderr.as_deref().unwrap().contains("Windows-only"));
        }
    }

    /// End-to-end coverage of the `handle_consent_flags` paths (grant,
    /// revoke, status, and a forced write failure) against an isolated
    /// consent store — this is the same fast path all three executors
    /// (`wxc-exec`, `lxc-exec`, `mxc-exec-mac`) delegate to, so exercising it
    /// here covers all three, not just `wxc-exec` (which previously had the
    /// only CLI-level smoke test).
    #[cfg(target_os = "windows")]
    mod windows_tests {
        use super::*;
        use crate::telemetry::test_support::TelemetryTestEnv;

        /// Isolates both process-global test hooks: the policy key (so a real
        /// machine policy on the dev box cannot change the expected output)
        /// and the consent store. See [`TelemetryTestEnv`] for why acquiring
        /// them together, in one place, is what keeps the pair deadlock-free.
        fn isolate(tmp: &std::path::Path) -> TelemetryTestEnv {
            TelemetryTestEnv::new(tmp)
        }

        #[test]
        fn grant_flag_persists_and_reports_granted() {
            let tmp = tempfile::tempdir().unwrap();
            let _guards = isolate(tmp.path());

            let outcome = handle_consent_flags(&ConsentCliFlags {
                status: false,
                grant: true,
                revoke: false,
                source: Some("prompt"),
            })
            .expect("handled");
            assert_eq!(outcome.exit_code, 0);
            assert_eq!(
                outcome.stdout.as_deref(),
                Some(r#"{"consent":"granted","needsPrompt":false,"policy":"unrestricted"}"#)
            );
            assert_eq!(consent::get_consent().as_str(), "granted");
        }

        #[test]
        fn revoke_flag_persists_and_reports_denied() {
            let tmp = tempfile::tempdir().unwrap();
            let _guards = isolate(tmp.path());

            let outcome = handle_consent_flags(&ConsentCliFlags {
                status: false,
                grant: false,
                revoke: true,
                source: Some("settings-toggle"),
            })
            .expect("handled");
            assert_eq!(outcome.exit_code, 0);
            assert_eq!(
                outcome.stdout.as_deref(),
                Some(r#"{"consent":"denied","needsPrompt":false,"policy":"unrestricted"}"#)
            );
            assert_eq!(consent::get_consent().as_str(), "denied");
        }

        #[test]
        fn status_flag_reports_current_state_without_mutating_it() {
            let tmp = tempfile::tempdir().unwrap();
            let _guards = isolate(tmp.path());

            let outcome = handle_consent_flags(&flags(true, false, false)).expect("handled");
            assert_eq!(outcome.exit_code, 0);
            assert_eq!(
                outcome.stdout.as_deref(),
                Some(r#"{"consent":"undetermined","needsPrompt":true,"policy":"unrestricted"}"#)
            );
            assert_eq!(consent::get_consent().as_str(), "undetermined");
        }

        /// Under an administrative denial the status must still report the
        /// user's own recorded decision truthfully — the grant is preserved,
        /// not erased — while advertising the block and suppressing the
        /// prompt.
        #[test]
        fn blocked_policy_is_reported_and_suppresses_the_prompt() {
            let tmp = tempfile::tempdir().unwrap();
            let env = isolate(tmp.path());
            env.set_policy_value(0);

            let outcome = handle_consent_flags(&flags(true, false, false)).expect("handled");
            assert_eq!(outcome.exit_code, 0);
            assert_eq!(
                outcome.stdout.as_deref(),
                Some(r#"{"consent":"undetermined","needsPrompt":false,"policy":"blocked"}"#)
            );
        }

        /// A user may still record a decision while policy blocks collection;
        /// it is honoured if the administrator later relaxes the policy. What
        /// must not happen is the grant being treated as collectable.
        #[test]
        fn grant_is_still_recorded_under_a_blocking_policy() {
            let tmp = tempfile::tempdir().unwrap();
            let env = isolate(tmp.path());
            env.set_policy_value(0);

            let outcome = handle_consent_flags(&ConsentCliFlags {
                status: false,
                grant: true,
                revoke: false,
                source: Some("cli"),
            })
            .expect("handled");
            assert_eq!(outcome.exit_code, 0);
            assert_eq!(
                outcome.stdout.as_deref(),
                Some(r#"{"consent":"granted","needsPrompt":false,"policy":"blocked"}"#)
            );
            assert!(!crate::telemetry::is_enabled(
                &crate::models::TelemetryConfig::default()
            ));
        }

        /// Previously unreachable in-process: this branch called
        /// `std::process::exit(1)`. A regular *file* named `mxc` where the
        /// store's parent directory belongs makes `create_dir_all` fail, so
        /// the write path errors out deterministically without needing
        /// permissions games.
        #[test]
        fn write_failure_reports_error_and_nonzero_exit() {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("mxc"), b"not a directory").unwrap();
            let _guards = isolate(tmp.path());

            let outcome = handle_consent_flags(&ConsentCliFlags {
                status: false,
                grant: true,
                revoke: false,
                source: Some("cli"),
            })
            .expect("handled");
            assert_eq!(outcome.exit_code, 1);
            assert_eq!(outcome.stdout, None);
            assert!(outcome.stderr.as_deref().unwrap().starts_with("Error: "));
        }
    }
}
