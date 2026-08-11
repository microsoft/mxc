// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared telemetry-consent maintenance handling for executor binaries.
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

use serde::Deserialize;
use std::io::{IsTerminal, Write};

use super::{consent, consent_prompt, policy};
use crate::wire;

const PRESENTER_PROTOCOL_ENV: &str = "MXC_TELEMETRY_CONSENT_PRESENTER_PROTOCOL";

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

    fn json(response: &wire::TelemetryConsentMaintenanceResponse) -> Self {
        match serde_json::to_string(response) {
            Ok(json) => Self {
                stdout: Some(json),
                stderr: None,
                exit_code: 0,
            },
            Err(error) => Self::failure(
                format!("Error: failed to serialize telemetry consent response: {error}"),
                1,
            ),
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
    if !(flags.status || flags.grant || flags.revoke || flags.source.is_some()) {
        return None;
    }

    if flags.grant || flags.revoke || flags.source.is_some() {
        return Some(ConsentCliOutcome::failure(
            "Error: --telemetry-consent-grant, --telemetry-consent-revoke, and \
             --telemetry-consent-source no longer change consent. Use the typed \
             telemetry-consent JSON maintenance envelope instead."
                .to_string(),
            64,
        ));
    }

    Some(ConsentCliOutcome::json(&maintenance_response(
        wire::TelemetryConsentAction::Status,
        wire::TelemetryConsentResult::Status,
        None,
        None,
        None,
    )))
}

#[derive(Deserialize)]
struct MaintenanceDiscriminator {
    command: Option<String>,
}

/// Handle a typed telemetry-consent maintenance envelope supplied through the
/// executor's existing file/base64 JSON input path.
///
/// Returns `None` for ordinary execution JSON so the caller can continue into
/// the existing execution parser.
pub fn handle_maintenance_input(input: &str, is_base64: bool) -> Option<ConsentCliOutcome> {
    let json = match crate::config_parser::decode_request_input(input, is_base64) {
        Ok(json) => json,
        Err(_) => return None,
    };
    let discriminator: MaintenanceDiscriminator = match serde_json::from_str(&json) {
        Ok(value) => value,
        Err(_) => return None,
    };
    if discriminator.command.as_deref() != Some("telemetryConsent") {
        return None;
    }

    let request: wire::TelemetryConsentMaintenanceRequest =
        match crate::config_deserialize::from_str(&json) {
            Ok(request) => request,
            Err(error) => {
                return Some(ConsentCliOutcome::failure(
                    format!("Error: invalid telemetry consent maintenance request: {error}"),
                    64,
                ));
            }
        };

    Some(handle_maintenance_request(request))
}

fn handle_maintenance_request(
    request: wire::TelemetryConsentMaintenanceRequest,
) -> ConsentCliOutcome {
    match request.action {
        wire::TelemetryConsentAction::Status => ConsentCliOutcome::json(&maintenance_response(
            request.action,
            wire::TelemetryConsentResult::Status,
            None,
            None,
            None,
        )),
        wire::TelemetryConsentAction::Withdraw => match consent::withdraw_consent() {
            Ok(outcome) => ConsentCliOutcome::json(&maintenance_response(
                request.action,
                action_result_to_wire(outcome.result),
                None,
                None,
                None,
            )),
            Err(error) => ConsentCliOutcome::failure(format!("Error: {error}"), 1),
        },
        wire::TelemetryConsentAction::Request => {
            let protocol =
                std::env::var_os(PRESENTER_PROTOCOL_ENV).is_some_and(|value| value == "1");
            let result = consent::request_consent(request.locale.as_deref(), |prompt| {
                if protocol {
                    present_over_stdio_protocol(request.action, prompt)
                } else {
                    present_on_terminal(prompt)
                }
            });
            match result {
                Ok(outcome) => ConsentCliOutcome::json(&maintenance_response(
                    request.action,
                    action_result_to_wire(outcome.result),
                    None,
                    None,
                    None,
                )),
                Err(consent::ConsentActionError::Presenter(error)) => {
                    let response = maintenance_response(
                        request.action,
                        wire::TelemetryConsentResult::PresentationUnavailable,
                        Some(wire::TelemetryConsentStatusReason::PresentationUnavailable),
                        None,
                        None,
                    );
                    let mut outcome = ConsentCliOutcome::json(&response);
                    outcome.stderr = Some(format!("Error: {error}"));
                    outcome.exit_code = 1;
                    outcome
                }
                Err(error) => ConsentCliOutcome::failure(format!("Error: {error}"), 1),
            }
        }
    }
}

fn present_on_terminal(
    prompt: &consent_prompt::ConsentPrompt,
) -> Result<consent::ConsentDecision, String> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err("interactive telemetry consent presentation is unavailable".to_string());
    }

    eprintln!("{}", prompt.title.text);
    eprintln!();
    eprintln!("{}", prompt.body.text);
    eprintln!();
    eprintln!(
        "{}: {}",
        prompt.learn_more_label.text, prompt.learn_more_url
    );
    eprintln!();
    eprintln!("[Y] {}", prompt.affirmative_label.text);
    eprintln!("[N] {}", prompt.negative_label.text);
    eprint!("Enter Y or N: ");
    std::io::stderr()
        .flush()
        .map_err(|error| format!("failed to display telemetry consent prompt: {error}"))?;

    let mut input = String::new();
    let read = std::io::stdin()
        .read_line(&mut input)
        .map_err(|error| format!("failed to read telemetry consent response: {error}"))?;
    if read == 0 {
        return Ok(consent::ConsentDecision::Dismissed);
    }
    match input.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(consent::ConsentDecision::Yes),
        "n" | "no" => Ok(consent::ConsentDecision::No),
        _ => Ok(consent::ConsentDecision::Dismissed),
    }
}

fn present_over_stdio_protocol(
    action: wire::TelemetryConsentAction,
    prompt: &consent_prompt::ConsentPrompt,
) -> Result<consent::ConsentDecision, String> {
    let challenge = random_challenge()?;
    let presentation = maintenance_response(
        action,
        wire::TelemetryConsentResult::PresentationRequired,
        None,
        Some(prompt_to_wire(prompt)),
        Some(challenge.clone()),
    );
    let json = serde_json::to_string(&presentation)
        .map_err(|error| format!("failed to serialize consent presentation: {error}"))?;
    println!("{json}");
    std::io::stdout()
        .flush()
        .map_err(|error| format!("failed to flush consent presentation: {error}"))?;

    let mut input = String::new();
    let read = std::io::stdin()
        .read_line(&mut input)
        .map_err(|error| format!("failed to read consent presenter response: {error}"))?;
    if read == 0 {
        return Ok(consent::ConsentDecision::Dismissed);
    }
    let response: wire::TelemetryConsentPresenterResponse = serde_json::from_str(&input)
        .map_err(|error| format!("invalid consent presenter response for this request: {error}"))?;
    validate_presenter_response(response, &challenge, prompt.resource_version)
}

fn validate_presenter_response(
    response: wire::TelemetryConsentPresenterResponse,
    expected_challenge: &str,
    expected_resource_version: u32,
) -> Result<consent::ConsentDecision, String> {
    if response.challenge != expected_challenge {
        return Err("consent presenter challenge did not match this request".to_string());
    }
    if response.resource_version != expected_resource_version {
        return Err("consent presenter prompt version did not match this request".to_string());
    }
    Ok(match response.decision {
        wire::TelemetryConsentDecision::Yes => consent::ConsentDecision::Yes,
        wire::TelemetryConsentDecision::No => consent::ConsentDecision::No,
        wire::TelemetryConsentDecision::Dismissed => consent::ConsentDecision::Dismissed,
    })
}

fn random_challenge() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| format!("failed to create consent presenter challenge: {error}"))?;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")
            .map_err(|error| format!("failed to encode consent presenter challenge: {error}"))?;
    }
    Ok(encoded)
}

fn maintenance_response(
    action: wire::TelemetryConsentAction,
    result: wire::TelemetryConsentResult,
    reason: Option<wire::TelemetryConsentStatusReason>,
    prompt: Option<wire::TelemetryConsentPrompt>,
    challenge: Option<String>,
) -> wire::TelemetryConsentMaintenanceResponse {
    let status = consent::get_status();
    let policy_state = policy::get_policy();
    wire::TelemetryConsentMaintenanceResponse {
        action,
        result,
        stored_state: consent_state_to_wire(status.stored_state),
        effective_state: consent_state_to_wire(status.effective_state),
        reason: reason.or_else(|| status.reason.map(status_reason_to_wire)),
        policy: policy_state_to_wire(policy_state),
        needs_prompt: policy_state.allows_collection() && status.needs_prompt(),
        prompt,
        challenge,
    }
}

fn prompt_to_wire(prompt: &consent_prompt::ConsentPrompt) -> wire::TelemetryConsentPrompt {
    fn message(value: consent_prompt::ConsentMessage) -> wire::TelemetryConsentMessage {
        wire::TelemetryConsentMessage {
            id: value.id.to_string(),
            text: value.text.to_string(),
        }
    }

    wire::TelemetryConsentPrompt {
        resource_version: prompt.resource_version,
        locale: prompt.locale.to_string(),
        title: message(prompt.title),
        body: message(prompt.body),
        affirmative_label: message(prompt.affirmative_label),
        negative_label: message(prompt.negative_label),
        learn_more_label: message(prompt.learn_more_label),
        learn_more_url: prompt.learn_more_url.to_string(),
    }
}

fn consent_state_to_wire(state: consent::ConsentState) -> wire::TelemetryConsentState {
    match state {
        consent::ConsentState::Granted => wire::TelemetryConsentState::Granted,
        consent::ConsentState::Denied => wire::TelemetryConsentState::Denied,
        consent::ConsentState::Undetermined => wire::TelemetryConsentState::Undetermined,
        consent::ConsentState::NotApplicable => wire::TelemetryConsentState::NotApplicable,
    }
}

fn status_reason_to_wire(
    reason: consent::ConsentStatusReason,
) -> wire::TelemetryConsentStatusReason {
    match reason {
        consent::ConsentStatusReason::NoRecord => wire::TelemetryConsentStatusReason::NoRecord,
        consent::ConsentStatusReason::StoreUnreadable => {
            wire::TelemetryConsentStatusReason::StoreUnreadable
        }
        consent::ConsentStatusReason::StoreMalformed => {
            wire::TelemetryConsentStatusReason::StoreMalformed
        }
        consent::ConsentStatusReason::ConsentSchemaUnsupported => {
            wire::TelemetryConsentStatusReason::ConsentSchemaUnsupported
        }
        consent::ConsentStatusReason::PromptVersionMissing => {
            wire::TelemetryConsentStatusReason::PromptVersionMissing
        }
        consent::ConsentStatusReason::PromptVersionUnsupported => {
            wire::TelemetryConsentStatusReason::PromptVersionUnsupported
        }
        consent::ConsentStatusReason::NotApplicable => {
            wire::TelemetryConsentStatusReason::NotApplicable
        }
    }
}

fn policy_state_to_wire(state: policy::PolicyState) -> wire::TelemetryConsentPolicyState {
    match state {
        policy::PolicyState::Unrestricted => wire::TelemetryConsentPolicyState::Unrestricted,
        policy::PolicyState::Allowed => wire::TelemetryConsentPolicyState::Allowed,
        policy::PolicyState::Blocked => wire::TelemetryConsentPolicyState::Blocked,
        policy::PolicyState::NotApplicable => wire::TelemetryConsentPolicyState::NotApplicable,
    }
}

fn action_result_to_wire(result: consent::ConsentActionResult) -> wire::TelemetryConsentResult {
    match result {
        consent::ConsentActionResult::Granted => wire::TelemetryConsentResult::Granted,
        consent::ConsentActionResult::Denied => wire::TelemetryConsentResult::Denied,
        consent::ConsentActionResult::Dismissed => wire::TelemetryConsentResult::Dismissed,
        consent::ConsentActionResult::Withdrawn => wire::TelemetryConsentResult::Withdrawn,
        consent::ConsentActionResult::AlreadyGranted => {
            wire::TelemetryConsentResult::AlreadyGranted
        }
        consent::ConsentActionResult::PolicyBlocked => wire::TelemetryConsentResult::PolicyBlocked,
        consent::ConsentActionResult::NotApplicable => wire::TelemetryConsentResult::NotApplicable,
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

    fn assert_status_json(
        outcome: &ConsentCliOutcome,
        stored: &str,
        effective: &str,
        policy: &str,
        needs_prompt: bool,
    ) {
        let value: serde_json::Value =
            serde_json::from_str(outcome.stdout.as_deref().expect("status JSON")).unwrap();
        assert_eq!(value["action"], "status");
        assert_eq!(value["result"], "status");
        assert_eq!(value["storedState"], stored);
        assert_eq!(value["effectiveState"], effective);
        assert_eq!(value["policy"], policy);
        assert_eq!(value["needsPrompt"], needs_prompt);
    }

    /// Previously unreachable in-process: this branch called
    /// `std::process::exit(64)` and would have killed the test runner.
    #[test]
    fn legacy_state_changing_flags_return_a_migration_error() {
        let outcome = handle_consent_flags(&flags(false, true, true)).expect("handled");
        assert_eq!(outcome.exit_code, 64);
        assert_eq!(outcome.stdout, None);
        assert!(outcome
            .stderr
            .as_deref()
            .unwrap()
            .contains("JSON maintenance envelope"));
    }

    #[test]
    fn presenter_response_is_bound_to_challenge_and_prompt_version() {
        let valid = wire::TelemetryConsentPresenterResponse {
            challenge: "request-a".to_string(),
            resource_version: 1,
            decision: wire::TelemetryConsentDecision::Yes,
        };
        assert_eq!(
            validate_presenter_response(valid, "request-a", 1).unwrap(),
            consent::ConsentDecision::Yes
        );

        let replay = wire::TelemetryConsentPresenterResponse {
            challenge: "request-a".to_string(),
            resource_version: 1,
            decision: wire::TelemetryConsentDecision::Yes,
        };
        assert!(validate_presenter_response(replay, "request-b", 1)
            .unwrap_err()
            .contains("challenge"));

        let stale_prompt = wire::TelemetryConsentPresenterResponse {
            challenge: "request-a".to_string(),
            resource_version: 0,
            decision: wire::TelemetryConsentDecision::Yes,
        };
        assert!(validate_presenter_response(stale_prompt, "request-a", 1)
            .unwrap_err()
            .contains("version"));
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
            assert_status_json(
                &outcome,
                "not-applicable",
                "not-applicable",
                "not-applicable",
                false,
            );
            assert_eq!(outcome.stderr, None);
        }

        #[test]
        fn grant_is_refused() {
            let outcome = handle_consent_flags(&flags(false, true, false)).expect("handled");
            assert_eq!(outcome.exit_code, 64);
            assert_eq!(outcome.stdout, None);
            assert!(outcome
                .stderr
                .as_deref()
                .unwrap()
                .contains("JSON maintenance envelope"));
        }

        #[test]
        fn revoke_is_refused() {
            let outcome = handle_consent_flags(&flags(false, false, true)).expect("handled");
            assert_eq!(outcome.exit_code, 64);
            assert_eq!(outcome.stdout, None);
            assert!(outcome
                .stderr
                .as_deref()
                .unwrap()
                .contains("JSON maintenance envelope"));
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
        fn grant_flag_is_a_non_mutating_migration_tombstone() {
            let tmp = tempfile::tempdir().unwrap();
            let _guards = isolate(tmp.path());

            let outcome = handle_consent_flags(&ConsentCliFlags {
                status: false,
                grant: true,
                revoke: false,
                source: Some("prompt"),
            })
            .expect("handled");
            assert_eq!(outcome.exit_code, 64);
            assert_eq!(outcome.stdout, None);
            assert_eq!(consent::get_consent().as_str(), "undetermined");
        }

        #[test]
        fn revoke_flag_is_a_non_mutating_migration_tombstone() {
            let tmp = tempfile::tempdir().unwrap();
            let _guards = isolate(tmp.path());

            let outcome = handle_consent_flags(&ConsentCliFlags {
                status: false,
                grant: false,
                revoke: true,
                source: Some("settings-toggle"),
            })
            .expect("handled");
            assert_eq!(outcome.exit_code, 64);
            assert_eq!(outcome.stdout, None);
            assert_eq!(consent::get_consent().as_str(), "undetermined");
        }

        #[test]
        fn status_flag_reports_current_state_without_mutating_it() {
            let tmp = tempfile::tempdir().unwrap();
            let _guards = isolate(tmp.path());

            let outcome = handle_consent_flags(&flags(true, false, false)).expect("handled");
            assert_eq!(outcome.exit_code, 0);
            assert_status_json(
                &outcome,
                "undetermined",
                "undetermined",
                "unrestricted",
                true,
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
            assert_status_json(&outcome, "undetermined", "undetermined", "blocked", false);
        }

        /// A user may still record a decision while policy blocks collection;
        /// it is honoured if the administrator later relaxes the policy. What
        /// must not happen is the grant being treated as collectable.
        #[test]
        fn grant_tombstone_does_not_record_under_a_blocking_policy() {
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
            assert_eq!(outcome.exit_code, 64);
            assert_eq!(consent::get_consent(), consent::ConsentState::Undetermined);
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
        fn withdrawal_write_failure_reports_error_and_nonzero_exit() {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("mxc"), b"not a directory").unwrap();
            let _guards = isolate(tmp.path());

            let outcome = handle_maintenance_request(wire::TelemetryConsentMaintenanceRequest {
                schema: None,
                command: wire::TelemetryConsentCommand::TelemetryConsent,
                action: wire::TelemetryConsentAction::Withdraw,
                locale: None,
            });
            assert_eq!(outcome.exit_code, 1);
            assert_eq!(outcome.stdout, None);
            assert!(outcome.stderr.as_deref().unwrap().starts_with("Error: "));
        }
    }
}
