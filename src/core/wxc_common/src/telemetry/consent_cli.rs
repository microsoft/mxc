// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared telemetry-consent maintenance handling for executor binaries.
//!
//! The executor binaries share this CLI surface; persistence remains
//! platform-dependent in [`super::consent`].

use std::io::{IsTerminal, Write};

use super::{consent, consent_prompt, policy};
use crate::wire;

const PRESENTER_PROTOCOL_ENV: &str = "MXC_TELEMETRY_CONSENT_PRESENTER_PROTOCOL";

/// Telemetry-consent CLI flags.
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

/// Output and exit code for a handled consent command.
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

/// Handle legacy consent flags. Returns `None` when no flag was supplied.
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

/// Handle a typed consent-maintenance envelope, if present.
///
/// Convenience wrapper that decodes `input` (either a file path or a base64
/// blob) into JSON and delegates to [`handle_maintenance_input_json`]. Callers
/// that already hold the decoded JSON string — typically executor binaries
/// that decode the request once and thread the JSON through to both the
/// maintenance probe and the normal request loader — should call
/// [`handle_maintenance_input_json`] directly to avoid re-reading the input
/// source. Re-reading matters for regular files (duplicate I/O + parsing) and
/// is a correctness issue for named pipes, `/dev/stdin`, and process-
/// substitution paths, which are drained by the first read and fail on the
/// second.
pub fn handle_maintenance_input(input: &str, is_base64: bool) -> Option<ConsentCliOutcome> {
    let json = match crate::config_parser::decode_request_input(input, is_base64) {
        Ok(json) => json,
        Err(_) => return None,
    };
    handle_maintenance_input_json(&json)
}

/// Handle a typed consent-maintenance envelope, given an already-decoded JSON
/// string.
///
/// The single-source-of-truth path shared with [`handle_maintenance_input`].
/// Returns `None` when the JSON does not carry the `telemetryConsent`
/// discriminator; executor binaries treat that as "not a maintenance request"
/// and continue to the normal request loader with the same JSON.
///
/// This function is deliberately `pub` (not `pub(crate)`) because the sibling
/// executor crates `wxc`, `lxc`, and `mxc_darwin` all call it from their
/// respective `main.rs` entry points. Threading the pre-decoded JSON through
/// this entry point avoids re-reading named pipes, `/dev/stdin`, and
/// process-substitution inputs, which are drained by the first read.
pub fn handle_maintenance_input_json(json: &str) -> Option<ConsentCliOutcome> {
    let Ok(hint) = crate::config_parser::parse_request_hint_from_json(json) else {
        return None;
    };
    if hint.kind() != crate::config_parser::RequestKind::TelemetryConsent {
        return None;
    }

    let request: wire::TelemetryConsentMaintenanceRequest =
        match crate::config_deserialize::from_str(json) {
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
    let mut transport = StdioPresenterTransport;
    present_over_transport(action, prompt, &mut transport)
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

trait PresenterTransport {
    fn next_challenge(&mut self) -> Result<String, String>;
    fn write_presentation(&mut self, json: &str) -> Result<(), String>;
    fn flush_presentation(&mut self) -> Result<(), String>;
    fn read_response_line(&mut self, input: &mut String) -> Result<usize, String>;
}

struct StdioPresenterTransport;

impl PresenterTransport for StdioPresenterTransport {
    fn next_challenge(&mut self) -> Result<String, String> {
        random_challenge()
    }

    fn write_presentation(&mut self, json: &str) -> Result<(), String> {
        // Write the presentation envelope via `writeln!` on a locked stdout
        // handle so a BrokenPipe (host closed the pipe before we emitted)
        // becomes a clean transport error rather than a panic. `println!`
        // panics on any write failure, which turns a routine IPC disconnect
        // into an uncontrolled crash during executor setup.
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        writeln!(handle, "{json}").map_err(|error| {
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                "consent presenter pipe closed before presentation envelope was delivered"
                    .to_string()
            } else {
                format!("failed to write consent presentation: {error}")
            }
        })
    }

    fn flush_presentation(&mut self) -> Result<(), String> {
        std::io::stdout().flush().map_err(|error| {
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                "consent presenter pipe closed before presentation envelope was flushed".to_string()
            } else {
                format!("failed to flush consent presentation: {error}")
            }
        })
    }

    fn read_response_line(&mut self, input: &mut String) -> Result<usize, String> {
        std::io::stdin()
            .read_line(input)
            .map_err(|error| format!("failed to read consent presenter response: {error}"))
    }
}

fn present_over_transport(
    action: wire::TelemetryConsentAction,
    prompt: &consent_prompt::ConsentPrompt,
    transport: &mut dyn PresenterTransport,
) -> Result<consent::ConsentDecision, String> {
    let challenge = transport.next_challenge()?;
    let presentation = maintenance_response(
        action,
        wire::TelemetryConsentResult::PresentationRequired,
        None,
        Some(prompt_to_wire(prompt)),
        Some(challenge.clone()),
    );
    let json = serde_json::to_string(&presentation)
        .map_err(|error| format!("failed to serialize consent presentation: {error}"))?;
    transport.write_presentation(&json)?;
    transport.flush_presentation()?;

    let mut input = String::new();
    let read = transport.read_response_line(&mut input)?;
    if read == 0 {
        return Ok(consent::ConsentDecision::Dismissed);
    }
    let response: wire::TelemetryConsentPresenterResponse = serde_json::from_str(&input)
        .map_err(|error| format!("invalid consent presenter response for this request: {error}"))?;
    validate_presenter_response(response, &challenge, prompt.resource_version)
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
    use crate::telemetry::consent_prompt::{ConsentPrompt, EN_US_CONSENT_PROMPT};

    fn flags(status: bool, grant: bool, revoke: bool) -> ConsentCliFlags<'static> {
        ConsentCliFlags {
            status,
            grant,
            revoke,
            source: None,
        }
    }

    fn prompt() -> ConsentPrompt {
        EN_US_CONSENT_PROMPT
    }

    struct FakeTransport {
        challenge: Result<String, String>,
        write_result: Result<(), String>,
        flush_result: Result<(), String>,
        read_result: Result<usize, String>,
        response_line: String,
        writes: Vec<String>,
    }

    impl FakeTransport {
        fn with_response(response_line: String) -> Self {
            Self {
                challenge: Ok("request-a".to_string()),
                write_result: Ok(()),
                flush_result: Ok(()),
                read_result: Ok(response_line.len()),
                response_line,
                writes: Vec::new(),
            }
        }
    }

    impl PresenterTransport for FakeTransport {
        fn next_challenge(&mut self) -> Result<String, String> {
            self.challenge.clone()
        }

        fn write_presentation(&mut self, json: &str) -> Result<(), String> {
            self.writes.push(json.to_string());
            self.write_result.clone()
        }

        fn flush_presentation(&mut self) -> Result<(), String> {
            self.flush_result.clone()
        }

        fn read_response_line(&mut self, input: &mut String) -> Result<usize, String> {
            input.push_str(&self.response_line);
            self.read_result.clone()
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

    #[test]
    fn presenter_transport_reports_broken_write_without_touching_stdio() {
        let mut transport = FakeTransport {
            challenge: Ok("request-a".to_string()),
            write_result: Err("consent presenter pipe closed".to_string()),
            flush_result: Ok(()),
            read_result: Ok(0),
            response_line: String::new(),
            writes: Vec::new(),
        };
        let error = present_over_transport(
            wire::TelemetryConsentAction::Request,
            &prompt(),
            &mut transport,
        )
        .unwrap_err();
        assert!(error.contains("pipe closed"));
        assert_eq!(transport.writes.len(), 1);
    }

    #[test]
    fn presenter_transport_treats_eof_as_dismissed() {
        let mut transport = FakeTransport {
            challenge: Ok("request-a".to_string()),
            write_result: Ok(()),
            flush_result: Ok(()),
            read_result: Ok(0),
            response_line: String::new(),
            writes: Vec::new(),
        };
        let decision = present_over_transport(
            wire::TelemetryConsentAction::Request,
            &prompt(),
            &mut transport,
        )
        .unwrap();
        assert_eq!(decision, consent::ConsentDecision::Dismissed);
    }

    #[test]
    fn presenter_transport_rejects_malformed_json() {
        let mut transport = FakeTransport::with_response("not json".to_string());
        let error = present_over_transport(
            wire::TelemetryConsentAction::Request,
            &prompt(),
            &mut transport,
        )
        .unwrap_err();
        assert!(error.contains("invalid consent presenter response"));
    }

    #[test]
    fn presenter_transport_rejects_mismatched_response() {
        let response = serde_json::to_string(&wire::TelemetryConsentPresenterResponse {
            challenge: "wrong-request".to_string(),
            resource_version: 1,
            decision: wire::TelemetryConsentDecision::Yes,
        })
        .unwrap();
        let mut transport = FakeTransport::with_response(response);
        let error = present_over_transport(
            wire::TelemetryConsentAction::Request,
            &prompt(),
            &mut transport,
        )
        .unwrap_err();
        assert!(error.contains("challenge"));
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
    /// here covers the shared behavior for all three executors.
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
