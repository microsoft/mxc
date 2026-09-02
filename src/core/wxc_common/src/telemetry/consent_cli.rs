// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared telemetry-consent maintenance handling for executor binaries.
//!
//! The executor binaries share this CLI surface; persistence remains
//! platform-dependent in [`super::consent`].

use std::ffi::OsStr;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::{consent, consent_prompt, consent_protocol as protocol, policy};

const MAX_DECISION_BYTES: u64 = 64 * 1024;

/// Consent operation selected by `--telemetry-consent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConsentAction {
    /// Read consent and policy status without mutation.
    Status,
    /// Idempotently persist denied consent.
    Withdraw,
    /// Request consent through the native terminal or SDK presenter.
    Request,
}

impl FromStr for ConsentAction {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "status" => Ok(Self::Status),
            "withdraw" => Ok(Self::Withdraw),
            "request" => Ok(Self::Request),
            _ => Err(format!(
                "invalid telemetry consent action '{value}'; expected status, withdraw, or request"
            )),
        }
    }
}

/// Optional private presenter protocol selected by SDK hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentProtocol {
    /// Newline-delimited JSON over the executor's standard streams.
    StdioV1,
}

impl FromStr for ConsentProtocol {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "stdio-v1" => Ok(Self::StdioV1),
            _ => Err(format!(
                "invalid telemetry consent protocol '{value}'; expected stdio-v1"
            )),
        }
    }
}

/// Whether an argv sequence invokes the dedicated consent command surface.
///
/// Executor binaries use this to map clap failures involving consent options
/// to the consent API's invalid-input exit code without changing unrelated CLI
/// error behavior.
pub fn invocation_uses_consent_options<I, S>(arguments: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    arguments
        .into_iter()
        .take_while(|argument| argument.as_ref() != OsStr::new("--"))
        .any(|argument| {
            let argument = argument.as_ref().to_string_lossy();
            argument == "--telemetry-consent"
                || argument.starts_with("--telemetry-consent=")
                || argument == "--telemetry-consent-locale"
                || argument.starts_with("--telemetry-consent-locale=")
                || argument == "--telemetry-consent-protocol"
                || argument.starts_with("--telemetry-consent-protocol=")
        })
}

/// Output and exit code for a handled consent command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentCliOutcome {
    /// Line to print to stdout, if any (the JSON status contract).
    pub stdout: Option<String>,
    /// Line to print to stderr, if any.
    pub stderr: Option<String>,
    /// Process exit code: `0` for domain outcomes, `64` for invalid input, and
    /// `1` for operational failures.
    pub exit_code: i32,
}

impl ConsentCliOutcome {
    /// Prints the outcome's stdout/stderr lines and returns the exit code the
    /// caller should terminate with.
    pub fn emit(&self) -> i32 {
        if let Some(out) = &self.stdout {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            if let Err(error) = writeln!(handle, "{out}") {
                eprintln!("Error: failed to write telemetry consent response: {error}");
                return 1;
            }
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

    fn json(response: &protocol::ConsentResponse) -> Self {
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

/// Execute one dedicated telemetry-consent command.
pub fn handle_consent_command(
    action: ConsentAction,
    locale: Option<&str>,
    selected_protocol: Option<ConsentProtocol>,
) -> ConsentCliOutcome {
    if action != ConsentAction::Request && locale.is_some() {
        return ConsentCliOutcome::failure(
            "Error: --telemetry-consent-locale is valid only with \
             --telemetry-consent request"
                .to_string(),
            64,
        );
    }
    if action != ConsentAction::Request && selected_protocol.is_some() {
        return ConsentCliOutcome::failure(
            "Error: --telemetry-consent-protocol is valid only with \
             --telemetry-consent request"
                .to_string(),
            64,
        );
    }

    match action {
        ConsentAction::Status => ConsentCliOutcome::json(&consent_response(
            action,
            protocol::ConsentResult::Status,
            None,
            None,
            None,
        )),
        ConsentAction::Withdraw => match consent::withdraw_consent() {
            Ok(outcome) => ConsentCliOutcome::json(&consent_response(
                action,
                action_result_to_protocol(outcome.result),
                None,
                None,
                None,
            )),
            Err(error) => ConsentCliOutcome::failure(format!("Error: {error}"), 1),
        },
        ConsentAction::Request => {
            let mut presenter_failure_kind = None;
            let result = consent::request_consent(locale, |prompt| {
                let presented = match selected_protocol {
                    Some(ConsentProtocol::StdioV1) => present_over_stdio_protocol(action, prompt),
                    None => present_on_terminal(prompt).map_err(ProtocolFailure::operational),
                };
                presented.map_err(|failure| {
                    presenter_failure_kind = Some(failure.kind);
                    failure.message
                })
            });
            match result {
                Ok(outcome) => ConsentCliOutcome::json(&consent_response(
                    action,
                    action_result_to_protocol(outcome.result),
                    None,
                    None,
                    None,
                )),
                Err(consent::ConsentActionError::Presenter(error)) => {
                    if presenter_failure_kind == Some(ProtocolFailureKind::InvalidInput) {
                        return ConsentCliOutcome::failure(format!("Error: {error}"), 64);
                    }
                    let response = consent_response(
                        action,
                        protocol::ConsentResult::PresentationUnavailable,
                        Some(protocol::StatusReason::PresentationUnavailable),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtocolFailureKind {
    InvalidInput,
    Operational,
}

#[derive(Debug, Clone)]
struct ProtocolFailure {
    kind: ProtocolFailureKind,
    message: String,
}

impl ProtocolFailure {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: ProtocolFailureKind::InvalidInput,
            message: message.into(),
        }
    }

    fn operational(message: impl Into<String>) -> Self {
        Self {
            kind: ProtocolFailureKind::Operational,
            message: message.into(),
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
    Ok(parse_terminal_decision(&input))
}

fn parse_terminal_decision(input: &str) -> consent::ConsentDecision {
    match input.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => consent::ConsentDecision::Yes,
        "n" | "no" => consent::ConsentDecision::No,
        _ => consent::ConsentDecision::Dismissed,
    }
}

fn present_over_stdio_protocol(
    action: ConsentAction,
    prompt: &consent_prompt::ConsentPrompt,
) -> Result<consent::ConsentDecision, ProtocolFailure> {
    let mut transport = StdioPresenterTransport;
    present_over_transport(action, prompt, &mut transport)
}

fn validate_presenter_response(
    response: protocol::PresenterResponse,
    expected_challenge: &str,
    expected_resource_version: u32,
) -> Result<consent::ConsentDecision, ProtocolFailure> {
    if response.challenge != expected_challenge {
        return Err(ProtocolFailure::invalid(
            "consent presenter challenge did not match this request",
        ));
    }
    if response.resource_version != expected_resource_version {
        return Err(ProtocolFailure::invalid(
            "consent presenter prompt version did not match this request",
        ));
    }
    Ok(match response.decision {
        protocol::ConsentDecision::Yes => consent::ConsentDecision::Yes,
        protocol::ConsentDecision::No => consent::ConsentDecision::No,
        protocol::ConsentDecision::Dismissed => consent::ConsentDecision::Dismissed,
    })
}

fn random_challenge() -> Result<String, ProtocolFailure> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        ProtocolFailure::operational(format!(
            "failed to create consent presenter challenge: {error}"
        ))
    })?;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|error| {
            ProtocolFailure::operational(format!(
                "failed to encode consent presenter challenge: {error}"
            ))
        })?;
    }
    Ok(encoded)
}

trait PresenterTransport {
    fn next_challenge(&mut self) -> Result<String, ProtocolFailure>;
    fn write_presentation(&mut self, json: &str) -> Result<(), ProtocolFailure>;
    fn flush_presentation(&mut self) -> Result<(), ProtocolFailure>;
    fn read_response(&mut self) -> Result<String, ProtocolFailure>;
}

struct StdioPresenterTransport;

impl PresenterTransport for StdioPresenterTransport {
    fn next_challenge(&mut self) -> Result<String, ProtocolFailure> {
        random_challenge()
    }

    fn write_presentation(&mut self, json: &str) -> Result<(), ProtocolFailure> {
        // Write the presentation envelope via `writeln!` on a locked stdout
        // handle so a BrokenPipe (host closed the pipe before we emitted)
        // becomes a clean transport error rather than a panic. `println!`
        // panics on any write failure, which turns a routine IPC disconnect
        // into an uncontrolled crash during executor setup.
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        writeln!(handle, "{json}").map_err(|error| {
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                ProtocolFailure::operational(
                    "consent presenter pipe closed before presentation envelope was delivered",
                )
            } else {
                ProtocolFailure::operational(format!(
                    "failed to write consent presentation: {error}"
                ))
            }
        })
    }

    fn flush_presentation(&mut self) -> Result<(), ProtocolFailure> {
        std::io::stdout().flush().map_err(|error| {
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                ProtocolFailure::operational(
                    "consent presenter pipe closed before presentation envelope was flushed",
                )
            } else {
                ProtocolFailure::operational(format!(
                    "failed to flush consent presentation: {error}"
                ))
            }
        })
    }

    fn read_response(&mut self) -> Result<String, ProtocolFailure> {
        let stdin = std::io::stdin();
        let mut reader = BufReader::new(stdin.lock().take(MAX_DECISION_BYTES + 1));
        let mut input = String::new();
        let read = reader.read_line(&mut input).map_err(|error| {
            if error.kind() == std::io::ErrorKind::InvalidData {
                ProtocolFailure::invalid("consent presenter response was not valid UTF-8")
            } else {
                ProtocolFailure::operational(format!(
                    "failed to read consent presenter response: {error}"
                ))
            }
        })?;
        if read == 0 {
            return Err(ProtocolFailure::operational(
                "consent presenter closed without returning a decision",
            ));
        }
        if read as u64 > MAX_DECISION_BYTES {
            return Err(ProtocolFailure::invalid(format!(
                "consent presenter response exceeded the {MAX_DECISION_BYTES}-byte limit"
            )));
        }
        if !reader.buffer().is_empty() {
            return Err(ProtocolFailure::invalid(
                "consent presenter returned more than one decision line",
            ));
        }
        Ok(input)
    }
}

fn present_over_transport(
    action: ConsentAction,
    prompt: &consent_prompt::ConsentPrompt,
    transport: &mut dyn PresenterTransport,
) -> Result<consent::ConsentDecision, ProtocolFailure> {
    let challenge = transport.next_challenge()?;
    let presentation = consent_response(
        action,
        protocol::ConsentResult::PresentationRequired,
        None,
        Some(prompt_to_protocol(prompt)),
        Some(challenge.clone()),
    );
    let json = serde_json::to_string(&presentation).map_err(|error| {
        ProtocolFailure::operational(format!("failed to serialize consent presentation: {error}"))
    })?;
    transport.write_presentation(&json)?;
    transport.flush_presentation()?;

    let input = transport.read_response()?;
    parse_presenter_response(&input, &challenge, prompt.resource_version)
}

fn parse_presenter_response(
    input: &str,
    expected_challenge: &str,
    expected_resource_version: u32,
) -> Result<consent::ConsentDecision, ProtocolFailure> {
    if input.len() > MAX_DECISION_BYTES as usize {
        return Err(ProtocolFailure::invalid(format!(
            "consent presenter response exceeded the {MAX_DECISION_BYTES}-byte limit"
        )));
    }
    let Some(line) = input.strip_suffix('\n') else {
        return Err(ProtocolFailure::invalid(
            "consent presenter decision must end with a newline",
        ));
    };
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.is_empty() || line.contains(['\r', '\n']) {
        return Err(ProtocolFailure::invalid(
            "consent presenter must return exactly one JSON decision line",
        ));
    }
    let response: protocol::PresenterResponse = serde_json::from_str(line).map_err(|error| {
        ProtocolFailure::invalid(format!(
            "invalid consent presenter response for this request: {error}"
        ))
    })?;
    validate_presenter_response(response, expected_challenge, expected_resource_version)
}

fn consent_response(
    action: ConsentAction,
    result: protocol::ConsentResult,
    reason: Option<protocol::StatusReason>,
    prompt: Option<protocol::ConsentPrompt>,
    challenge: Option<String>,
) -> protocol::ConsentResponse {
    let status = consent::get_status();
    let policy_state = policy::get_policy();
    protocol::ConsentResponse {
        action,
        result,
        stored_state: consent_state_to_protocol(status.stored_state),
        effective_state: consent_state_to_protocol(status.effective_state),
        reason: reason.or_else(|| status.reason.map(status_reason_to_protocol)),
        policy: policy_state_to_protocol(policy_state),
        needs_prompt: policy_state.allows_collection() && status.needs_prompt(),
        prompt,
        challenge,
    }
}

fn prompt_to_protocol(prompt: &consent_prompt::ConsentPrompt) -> protocol::ConsentPrompt {
    fn message(value: consent_prompt::ConsentMessage) -> protocol::ConsentMessage {
        protocol::ConsentMessage {
            id: value.id.to_string(),
            text: value.text.to_string(),
        }
    }

    protocol::ConsentPrompt {
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

fn consent_state_to_protocol(state: consent::ConsentState) -> protocol::ConsentState {
    match state {
        consent::ConsentState::Granted => protocol::ConsentState::Granted,
        consent::ConsentState::Denied => protocol::ConsentState::Denied,
        consent::ConsentState::Undetermined => protocol::ConsentState::Undetermined,
        consent::ConsentState::NotApplicable => protocol::ConsentState::NotApplicable,
    }
}

fn status_reason_to_protocol(reason: consent::ConsentStatusReason) -> protocol::StatusReason {
    match reason {
        consent::ConsentStatusReason::NoRecord => protocol::StatusReason::NoRecord,
        consent::ConsentStatusReason::StoreUnreadable => protocol::StatusReason::StoreUnreadable,
        consent::ConsentStatusReason::StoreMalformed => protocol::StatusReason::StoreMalformed,
        consent::ConsentStatusReason::ConsentSchemaUnsupported => {
            protocol::StatusReason::ConsentSchemaUnsupported
        }
        consent::ConsentStatusReason::PromptVersionMissing => {
            protocol::StatusReason::PromptVersionMissing
        }
        consent::ConsentStatusReason::PromptVersionUnsupported => {
            protocol::StatusReason::PromptVersionUnsupported
        }
        consent::ConsentStatusReason::NotApplicable => protocol::StatusReason::NotApplicable,
    }
}

fn policy_state_to_protocol(state: policy::PolicyState) -> protocol::PolicyState {
    match state {
        policy::PolicyState::Unrestricted => protocol::PolicyState::Unrestricted,
        policy::PolicyState::Allowed => protocol::PolicyState::Allowed,
        policy::PolicyState::Blocked => protocol::PolicyState::Blocked,
        policy::PolicyState::NotApplicable => protocol::PolicyState::NotApplicable,
    }
}

fn action_result_to_protocol(result: consent::ConsentActionResult) -> protocol::ConsentResult {
    match result {
        consent::ConsentActionResult::Granted => protocol::ConsentResult::Granted,
        consent::ConsentActionResult::Denied => protocol::ConsentResult::Denied,
        consent::ConsentActionResult::Dismissed => protocol::ConsentResult::Dismissed,
        consent::ConsentActionResult::Withdrawn => protocol::ConsentResult::Withdrawn,
        consent::ConsentActionResult::AlreadyGranted => protocol::ConsentResult::AlreadyGranted,
        consent::ConsentActionResult::PolicyBlocked => protocol::ConsentResult::PolicyBlocked,
        consent::ConsentActionResult::NotApplicable => protocol::ConsentResult::NotApplicable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::consent_prompt::{ConsentPrompt, EN_US_CONSENT_PROMPT};

    fn prompt() -> ConsentPrompt {
        EN_US_CONSENT_PROMPT
    }

    fn present_for_test(
        transport: &mut dyn PresenterTransport,
    ) -> Result<consent::ConsentDecision, ProtocolFailure> {
        #[cfg(target_os = "windows")]
        {
            let tmp = tempfile::tempdir().unwrap();
            let _environment = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            present_over_transport(ConsentAction::Request, &prompt(), transport)
        }
        #[cfg(not(target_os = "windows"))]
        {
            present_over_transport(ConsentAction::Request, &prompt(), transport)
        }
    }

    struct FakeTransport {
        challenge: Result<String, ProtocolFailure>,
        write_result: Result<(), ProtocolFailure>,
        flush_result: Result<(), ProtocolFailure>,
        read_result: Result<String, ProtocolFailure>,
        writes: Vec<String>,
    }

    impl FakeTransport {
        fn with_response(response_line: String) -> Self {
            Self {
                challenge: Ok("request-a".to_string()),
                write_result: Ok(()),
                flush_result: Ok(()),
                read_result: Ok(format!("{response_line}\n")),
                writes: Vec::new(),
            }
        }
    }

    impl PresenterTransport for FakeTransport {
        fn next_challenge(&mut self) -> Result<String, ProtocolFailure> {
            self.challenge.clone()
        }

        fn write_presentation(&mut self, json: &str) -> Result<(), ProtocolFailure> {
            self.writes.push(json.to_string());
            self.write_result.clone()
        }

        fn flush_presentation(&mut self) -> Result<(), ProtocolFailure> {
            self.flush_result.clone()
        }

        fn read_response(&mut self) -> Result<String, ProtocolFailure> {
            self.read_result.clone()
        }
    }

    #[test]
    fn locale_is_rejected_for_non_request_actions() {
        let outcome = handle_consent_command(ConsentAction::Status, Some("en-US"), None);
        assert_eq!(outcome.exit_code, 64);
        assert!(outcome.stderr.as_deref().unwrap().contains("valid only"));
    }

    #[test]
    fn consent_option_detection_is_testable_without_process_arguments() {
        assert!(invocation_uses_consent_options([
            "wxc-exec",
            "--telemetry-consent=request"
        ]));
        assert!(invocation_uses_consent_options([
            "wxc-exec",
            "--telemetry-consent-locale",
            "en-US"
        ]));
        assert!(!invocation_uses_consent_options([
            "wxc-exec",
            "--config",
            "policy.json"
        ]));
        assert!(!invocation_uses_consent_options([
            "wxc-exec",
            "--telemetry-consent-status"
        ]));
        assert!(!invocation_uses_consent_options([
            "wxc-exec",
            "--unknown-flag",
            "--",
            "--telemetry-consent=request"
        ]));
        assert!(invocation_uses_consent_options([
            "wxc-exec",
            "--telemetry-consent=request",
            "--",
            "--telemetry-consent=withdraw"
        ]));
    }

    #[test]
    fn terminal_decisions_are_parsed_without_live_stdio() {
        for affirmative in ["y", "Y", "yes", " YES "] {
            assert_eq!(
                parse_terminal_decision(affirmative),
                consent::ConsentDecision::Yes
            );
        }
        for negative in ["n", "N", "no", " NO "] {
            assert_eq!(
                parse_terminal_decision(negative),
                consent::ConsentDecision::No
            );
        }
        for dismissed in ["", " ", "later", "cancel"] {
            assert_eq!(
                parse_terminal_decision(dismissed),
                consent::ConsentDecision::Dismissed
            );
        }
    }

    #[test]
    fn protocol_is_rejected_for_non_request_actions() {
        let outcome = handle_consent_command(
            ConsentAction::Withdraw,
            None,
            Some(ConsentProtocol::StdioV1),
        );
        assert_eq!(outcome.exit_code, 64);
        assert!(outcome.stderr.as_deref().unwrap().contains("valid only"));
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

    #[test]
    fn presenter_response_is_bound_to_challenge_and_prompt_version() {
        let valid = protocol::PresenterResponse {
            challenge: "request-a".to_string(),
            resource_version: 1,
            decision: protocol::ConsentDecision::Yes,
        };
        assert_eq!(
            validate_presenter_response(valid, "request-a", 1).unwrap(),
            consent::ConsentDecision::Yes
        );

        let replay = protocol::PresenterResponse {
            challenge: "request-a".to_string(),
            resource_version: 1,
            decision: protocol::ConsentDecision::Yes,
        };
        assert!(validate_presenter_response(replay, "request-b", 1)
            .unwrap_err()
            .message
            .contains("challenge"));

        let stale_prompt = protocol::PresenterResponse {
            challenge: "request-a".to_string(),
            resource_version: 0,
            decision: protocol::ConsentDecision::Yes,
        };
        assert!(validate_presenter_response(stale_prompt, "request-a", 1)
            .unwrap_err()
            .message
            .contains("version"));
    }

    #[test]
    fn presenter_transport_reports_broken_write_without_touching_stdio() {
        let mut transport = FakeTransport {
            challenge: Ok("request-a".to_string()),
            write_result: Err(ProtocolFailure::operational(
                "consent presenter pipe closed",
            )),
            flush_result: Ok(()),
            read_result: Ok(String::new()),
            writes: Vec::new(),
        };
        let error = present_for_test(&mut transport).unwrap_err();
        assert!(error.message.contains("pipe closed"));
        assert_eq!(transport.writes.len(), 1);
    }

    #[test]
    fn presenter_transport_treats_eof_as_operational_failure() {
        let mut transport = FakeTransport {
            challenge: Ok("request-a".to_string()),
            write_result: Ok(()),
            flush_result: Ok(()),
            read_result: Err(ProtocolFailure::operational(
                "consent presenter closed without returning a decision",
            )),
            writes: Vec::new(),
        };
        let error = present_for_test(&mut transport).unwrap_err();
        assert_eq!(error.kind, ProtocolFailureKind::Operational);
    }

    #[test]
    fn presenter_transport_rejects_malformed_json() {
        let mut transport = FakeTransport::with_response("not json".to_string());
        let error = present_for_test(&mut transport).unwrap_err();
        assert_eq!(error.kind, ProtocolFailureKind::InvalidInput);
        assert!(error.message.contains("invalid consent presenter response"));
    }

    #[test]
    fn presenter_transport_rejects_mismatched_response() {
        let response = serde_json::to_string(&protocol::PresenterResponse {
            challenge: "wrong-request".to_string(),
            resource_version: 1,
            decision: protocol::ConsentDecision::Yes,
        })
        .unwrap();
        let mut transport = FakeTransport::with_response(response);
        let error = present_for_test(&mut transport).unwrap_err();
        assert_eq!(error.kind, ProtocolFailureKind::InvalidInput);
        assert!(error.message.contains("challenge"));
    }

    #[test]
    fn presenter_transport_rejects_extra_decision_lines() {
        let response = serde_json::to_string(&protocol::PresenterResponse {
            challenge: "request-a".to_string(),
            resource_version: 1,
            decision: protocol::ConsentDecision::Yes,
        })
        .unwrap();
        let mut transport = FakeTransport::with_response(format!("{response}\n{response}"));
        let error = present_for_test(&mut transport).unwrap_err();
        assert_eq!(error.kind, ProtocolFailureKind::InvalidInput);
        assert!(error.message.contains("exactly one"));
    }

    #[test]
    fn presenter_transport_requires_newline_terminated_decision() {
        let response = serde_json::to_string(&protocol::PresenterResponse {
            challenge: "request-a".to_string(),
            resource_version: 1,
            decision: protocol::ConsentDecision::Yes,
        })
        .unwrap();
        let error = parse_presenter_response(&response, "request-a", 1).unwrap_err();
        assert_eq!(error.kind, ProtocolFailureKind::InvalidInput);
        assert!(error.message.contains("end with a newline"));
    }

    #[test]
    fn presenter_transport_rejects_oversized_decision() {
        let input = format!("{}\n", "x".repeat(MAX_DECISION_BYTES as usize));
        let error = parse_presenter_response(&input, "request-a", 1).unwrap_err();
        assert_eq!(error.kind, ProtocolFailureKind::InvalidInput);
        assert!(error.message.contains("byte limit"));
    }

    #[test]
    fn shared_decision_fixtures_match_the_private_protocol() {
        let fixtures = [
            (
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../../tests/fixtures/telemetry-consent/stdio-v1-decision-yes.json"
                )),
                consent::ConsentDecision::Yes,
            ),
            (
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../../tests/fixtures/telemetry-consent/stdio-v1-decision-no.json"
                )),
                consent::ConsentDecision::No,
            ),
            (
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../../tests/fixtures/telemetry-consent/stdio-v1-decision-dismissed.json"
                )),
                consent::ConsentDecision::Dismissed,
            ),
        ];

        for (fixture, expected) in fixtures {
            assert_eq!(
                parse_presenter_response(fixture, "request-a", 1).unwrap(),
                expected
            );
        }
        let invalid = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/fixtures/telemetry-consent/stdio-v1-decision-unknown-field.json"
        ));
        assert_eq!(
            parse_presenter_response(invalid, "request-a", 1)
                .unwrap_err()
                .kind,
            ProtocolFailureKind::InvalidInput
        );
    }

    /// The non-Windows contract every executor must honor: status is a
    /// successful `not-applicable` report. MXC must never offer — or appear
    /// to record — consent on a platform where it cannot collect telemetry.
    ///
    /// Gated to non-Windows (rather than merged into the Windows tests)
    /// because it asserts the *stub* behavior; without it, Linux/macOS CI
    /// would run no test at all over this shared handler.
    #[cfg(not(target_os = "windows"))]
    mod non_windows_tests {
        use super::*;

        #[test]
        fn status_reports_not_applicable_and_succeeds() {
            let outcome = handle_consent_command(ConsentAction::Status, None, None);
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
    }

    /// End-to-end coverage of the status path against an isolated consent
    /// store. This is the same fast path all three executors delegate to.
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
        fn status_flag_reports_current_state_without_mutating_it() {
            let tmp = tempfile::tempdir().unwrap();
            let _guards = isolate(tmp.path());

            let outcome = handle_consent_command(ConsentAction::Status, None, None);
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

            let outcome = handle_consent_command(ConsentAction::Status, None, None);
            assert_eq!(outcome.exit_code, 0);
            assert_status_json(&outcome, "undetermined", "undetermined", "blocked", false);
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

            let outcome = handle_consent_command(ConsentAction::Withdraw, None, None);
            assert_eq!(outcome.exit_code, 1);
            assert_eq!(outcome.stdout, None);
            assert!(outcome.stderr.as_deref().unwrap().starts_with("Error: "));
        }
    }
}
