// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Telemetry consent administration.
//!
//! MXC only ever collects telemetry on Windows, and only when the user has
//! explicitly granted consent. Consent is persisted by MXC itself, per Windows
//! user, and is never derived from or synchronized with any Windows-level
//! diagnostics setting. See `docs/telemetry/telemetry-consent-design.md`.
//!
//! [`ConsentState`] and [`PolicyState`] are crate-owned facades over the
//! internal `wxc_common` types, so the public API never exposes the foundation
//! crate — the same approach taken for [`crate::ErrorCode`].
//!
//! The *decision logic* is not duplicated here: every function and predicate
//! below delegates to the single implementation in `wxc_common::telemetry` —
//! the same code the `wxc-exec` `--telemetry-consent-*` flags, the C ABI
//! (`mxc_ffi`), the C# SDK, and the Node SDK all resolve to. There is no
//! Rust-SDK-specific consent logic to drift.
//!
//! The SDK ships no consent UI. A host optionally calls [`request_consent`] or
//! [`request_consent_async`]; MXC supplies the mandatory canonical resource to
//! the host presenter and persists only the typed decision returned from that
//! invocation. [`withdraw_consent`] remains available independently.
//!
//! ```no_run
//! use mxc_sdk::telemetry::{self, ConsentDecision, ConsentState};
//!
//! let outcome = telemetry::request_consent(Some("en-US"), |prompt| {
//!     // Render every prompt field verbatim in the host's UI.
//!     assert_eq!(prompt.locale, "en-US");
//!     Ok(ConsentDecision::Yes)
//! })?;
//!
//! // Anywhere later, e.g. a settings toggle:
//! match telemetry::get_consent() {
//!     ConsentState::Granted => println!("telemetry on"),
//!     ConsentState::Denied | ConsentState::Undetermined => println!("telemetry off"),
//!     // Never offer a toggle here — MXC collects nothing off Windows.
//!     ConsentState::NotApplicable => {}
//! }
//! # let _ = outcome;
//! # Ok::<(), telemetry::ConsentError>(())
//! ```
//!
//! Off Windows, [`get_consent`] always returns
//! [`ConsentState::NotApplicable`] without touching disk,
//! [`needs_consent_prompt`] is always `false`, and consent requests return
//! [`ConsentActionResult::NotApplicable`].
//!
//! # Administrative policy
//!
//! An administrator may disable MXC telemetry machine-wide via MDM (Intune) or
//! Group Policy. [`get_policy`] reports that state so a host can explain *why*
//! telemetry is unavailable instead of rendering an inert toggle:
//!
//! ```no_run
//! use mxc_sdk::telemetry::{get_policy, PolicyState};
//!
//! if get_policy() == PolicyState::Blocked {
//!     println!("Telemetry has been disabled by your administrator.");
//! }
//! ```
//!
//! The policy is a ceiling, never a grant: an administrator who permits
//! telemetry has not consented on the user's behalf, so an explicit user grant
//! is still required. A blocking policy also makes [`needs_consent_prompt`]
//! return `false`, so a host following the pattern above will not ask the user
//! to decide something MXC would then ignore.

use std::fmt;

use wxc_common::telemetry::consent as inner_consent;
use wxc_common::telemetry::policy as inner_policy;

/// The user's recorded telemetry consent decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsentState {
    /// The user has explicitly agreed to telemetry collection.
    Granted,
    /// The user has explicitly declined telemetry collection.
    Denied,
    /// No decision has been recorded yet (fresh install, or a corrupt or
    /// unreadable store). Treated identically to [`ConsentState::Denied`] for
    /// gating purposes — it differs only in that a host should still prompt.
    Undetermined,
    /// Not a Windows host. MXC collects no telemetry on other platforms, so
    /// there is nothing to consent to.
    NotApplicable,
}

impl ConsentState {
    /// The stable wire string for this state, identical across every SDK.
    pub fn as_str(&self) -> &'static str {
        Self::to_inner(*self).as_str()
    }

    /// Whether this state alone permits collection. Never sufficient on its
    /// own — collection additionally requires a permitting policy.
    pub fn allows_collection(&self) -> bool {
        Self::to_inner(*self).allows_collection()
    }

    /// Whether a host should show the first-run consent prompt for this state,
    /// ignoring administrative policy. Prefer [`needs_consent_prompt`], which
    /// also accounts for a blocking policy.
    pub fn needs_prompt(&self) -> bool {
        Self::to_inner(*self).needs_prompt()
    }

    fn to_inner(self) -> inner_consent::ConsentState {
        match self {
            Self::Granted => inner_consent::ConsentState::Granted,
            Self::Denied => inner_consent::ConsentState::Denied,
            Self::Undetermined => inner_consent::ConsentState::Undetermined,
            Self::NotApplicable => inner_consent::ConsentState::NotApplicable,
        }
    }
}

impl From<inner_consent::ConsentState> for ConsentState {
    fn from(value: inner_consent::ConsentState) -> Self {
        match value {
            inner_consent::ConsentState::Granted => Self::Granted,
            inner_consent::ConsentState::Denied => Self::Denied,
            inner_consent::ConsentState::Undetermined => Self::Undetermined,
            inner_consent::ConsentState::NotApplicable => Self::NotApplicable,
        }
    }
}

/// One independently localizable canonical consent message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentMessage {
    pub id: &'static str,
    pub text: &'static str,
}

/// Canonical consent resource supplied to a host presenter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentPrompt {
    pub resource_version: u32,
    pub locale: &'static str,
    pub title: ConsentMessage,
    pub body: ConsentMessage,
    pub affirmative_label: ConsentMessage,
    pub negative_label: ConsentMessage,
    pub learn_more_label: ConsentMessage,
    pub learn_more_url: &'static str,
}

impl From<&wxc_common::telemetry::consent_prompt::ConsentPrompt> for ConsentPrompt {
    fn from(value: &wxc_common::telemetry::consent_prompt::ConsentPrompt) -> Self {
        fn message(value: wxc_common::telemetry::consent_prompt::ConsentMessage) -> ConsentMessage {
            ConsentMessage {
                id: value.id,
                text: value.text,
            }
        }

        Self {
            resource_version: value.resource_version,
            locale: value.locale,
            title: message(value.title),
            body: message(value.body),
            affirmative_label: message(value.affirmative_label),
            negative_label: message(value.negative_label),
            learn_more_label: message(value.learn_more_label),
            learn_more_url: value.learn_more_url,
        }
    }
}

/// Explicit result returned by a host consent presenter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecision {
    Yes,
    No,
    Dismissed,
}

impl ConsentDecision {
    fn to_inner(self) -> inner_consent::ConsentDecision {
        match self {
            Self::Yes => inner_consent::ConsentDecision::Yes,
            Self::No => inner_consent::ConsentDecision::No,
            Self::Dismissed => inner_consent::ConsentDecision::Dismissed,
        }
    }
}

/// Why stored consent is not currently effective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentStatusReason {
    NoRecord,
    StoreUnreadable,
    StoreMalformed,
    ConsentSchemaUnsupported,
    PromptVersionMissing,
    PromptVersionUnsupported,
    NotApplicable,
}

impl ConsentStatusReason {
    /// Stable wire string used by the maintenance and binding contracts.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoRecord => "no-record",
            Self::StoreUnreadable => "store-unreadable",
            Self::StoreMalformed => "store-malformed",
            Self::ConsentSchemaUnsupported => "consent-schema-unsupported",
            Self::PromptVersionMissing => "prompt-version-missing",
            Self::PromptVersionUnsupported => "prompt-version-unsupported",
            Self::NotApplicable => "not-applicable",
        }
    }
}

impl From<inner_consent::ConsentStatusReason> for ConsentStatusReason {
    fn from(value: inner_consent::ConsentStatusReason) -> Self {
        match value {
            inner_consent::ConsentStatusReason::NoRecord => Self::NoRecord,
            inner_consent::ConsentStatusReason::StoreUnreadable => Self::StoreUnreadable,
            inner_consent::ConsentStatusReason::StoreMalformed => Self::StoreMalformed,
            inner_consent::ConsentStatusReason::ConsentSchemaUnsupported => {
                Self::ConsentSchemaUnsupported
            }
            inner_consent::ConsentStatusReason::PromptVersionMissing => Self::PromptVersionMissing,
            inner_consent::ConsentStatusReason::PromptVersionUnsupported => {
                Self::PromptVersionUnsupported
            }
            inner_consent::ConsentStatusReason::NotApplicable => Self::NotApplicable,
        }
    }
}

/// Stored and effective consent returned by read-only status APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentStatus {
    pub stored_state: ConsentState,
    pub effective_state: ConsentState,
    pub reason: Option<ConsentStatusReason>,
}

impl From<inner_consent::ConsentStatus> for ConsentStatus {
    fn from(value: inner_consent::ConsentStatus) -> Self {
        Self {
            stored_state: value.stored_state.into(),
            effective_state: value.effective_state.into(),
            reason: value.reason.map(Into::into),
        }
    }
}

/// Result of a presenter request or withdrawal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentActionResult {
    Granted,
    Denied,
    Dismissed,
    Withdrawn,
    AlreadyGranted,
    PolicyBlocked,
    NotApplicable,
}

impl ConsentActionResult {
    /// Stable wire string used by the maintenance and binding contracts.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Denied => "denied",
            Self::Dismissed => "dismissed",
            Self::Withdrawn => "withdrawn",
            Self::AlreadyGranted => "already-granted",
            Self::PolicyBlocked => "policy-blocked",
            Self::NotApplicable => "not-applicable",
        }
    }
}

impl From<inner_consent::ConsentActionResult> for ConsentActionResult {
    fn from(value: inner_consent::ConsentActionResult) -> Self {
        match value {
            inner_consent::ConsentActionResult::Granted => Self::Granted,
            inner_consent::ConsentActionResult::Denied => Self::Denied,
            inner_consent::ConsentActionResult::Dismissed => Self::Dismissed,
            inner_consent::ConsentActionResult::Withdrawn => Self::Withdrawn,
            inner_consent::ConsentActionResult::AlreadyGranted => Self::AlreadyGranted,
            inner_consent::ConsentActionResult::PolicyBlocked => Self::PolicyBlocked,
            inner_consent::ConsentActionResult::NotApplicable => Self::NotApplicable,
        }
    }
}

/// Consent action result with resulting status and policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentActionOutcome {
    pub result: ConsentActionResult,
    pub status: ConsentStatus,
    pub policy: PolicyState,
}

impl From<inner_consent::ConsentActionOutcome> for ConsentActionOutcome {
    fn from(value: inner_consent::ConsentActionOutcome) -> Self {
        Self {
            result: value.result.into(),
            status: value.status.into(),
            policy: value.policy.into(),
        }
    }
}

/// Failure to present or persist telemetry consent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentError {
    Presenter(String),
    Persist(String),
}

impl fmt::Display for ConsentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Presenter(message) => write!(formatter, "consent presenter failed: {message}"),
            Self::Persist(message) => write!(formatter, "failed to persist consent: {message}"),
        }
    }
}

impl std::error::Error for ConsentError {}

impl From<inner_consent::ConsentActionError> for ConsentError {
    fn from(value: inner_consent::ConsentActionError) -> Self {
        match value {
            inner_consent::ConsentActionError::Presenter(message) => Self::Presenter(message),
            inner_consent::ConsentActionError::Persist(message) => Self::Persist(message),
        }
    }
}

/// The administrative (MDM / Group Policy) telemetry ceiling for this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyState {
    /// No policy is configured — an unmanaged machine. Collection is governed
    /// by the user's consent alone.
    Unrestricted,
    /// A policy is configured and permits collection. This is a ceiling, not a
    /// grant: an explicit user consent is still required.
    Allowed,
    /// A policy blocks collection, or the configured policy could not be read
    /// or understood (fail closed).
    Blocked,
    /// Not a Windows host, where there is no telemetry to govern.
    NotApplicable,
}

impl PolicyState {
    /// The stable wire string for this state, identical across every SDK.
    pub fn as_str(&self) -> &'static str {
        Self::to_inner(*self).as_str()
    }

    /// Whether this policy permits collection. Never sufficient on its own —
    /// a policy can restrict, but can never consent on the user's behalf.
    pub fn allows_collection(&self) -> bool {
        Self::to_inner(*self).allows_collection()
    }

    fn to_inner(self) -> inner_policy::PolicyState {
        match self {
            Self::Unrestricted => inner_policy::PolicyState::Unrestricted,
            Self::Allowed => inner_policy::PolicyState::Allowed,
            Self::Blocked => inner_policy::PolicyState::Blocked,
            Self::NotApplicable => inner_policy::PolicyState::NotApplicable,
        }
    }
}

impl From<inner_policy::PolicyState> for PolicyState {
    fn from(value: inner_policy::PolicyState) -> Self {
        match value {
            inner_policy::PolicyState::Unrestricted => Self::Unrestricted,
            inner_policy::PolicyState::Allowed => Self::Allowed,
            inner_policy::PolicyState::Blocked => Self::Blocked,
            inner_policy::PolicyState::NotApplicable => Self::NotApplicable,
        }
    }
}

/// The user's currently recorded consent decision. Never panics; an unreadable
/// store reports [`ConsentState::Undetermined`].
pub fn get_consent() -> ConsentState {
    inner_consent::get_consent().into()
}

/// Read stored and effective consent with a typed fail-closed reason.
pub fn get_consent_status() -> ConsentStatus {
    inner_consent::get_status().into()
}

/// Invoke a host presenter with the canonical resource and persist its typed
/// decision.
pub fn request_consent<F>(
    locale: Option<&str>,
    presenter: F,
) -> Result<ConsentActionOutcome, ConsentError>
where
    F: FnOnce(&ConsentPrompt) -> Result<ConsentDecision, String>,
{
    inner_consent::request_consent(locale, |prompt| {
        presenter(&ConsentPrompt::from(prompt)).map(ConsentDecision::to_inner)
    })
    .map(Into::into)
    .map_err(Into::into)
}

/// Asynchronous counterpart to [`request_consent`].
pub async fn request_consent_async<F, Fut>(
    locale: Option<&str>,
    presenter: F,
) -> Result<ConsentActionOutcome, ConsentError>
where
    F: FnOnce(ConsentPrompt) -> Fut,
    Fut: std::future::Future<Output = Result<ConsentDecision, String>>,
{
    inner_consent::request_consent_async(locale, |prompt| {
        let prompt = ConsentPrompt::from(prompt);
        async move { presenter(prompt).await.map(ConsentDecision::to_inner) }
    })
    .await
    .map(Into::into)
    .map_err(Into::into)
}

/// Idempotently withdraw telemetry consent.
pub fn withdraw_consent() -> Result<ConsentActionOutcome, ConsentError> {
    inner_consent::withdraw_consent()
        .map(Into::into)
        .map_err(Into::into)
}

/// Whether a host should show the first-run consent prompt. `false` when a
/// policy blocks collection, so a host never asks the user to decide something
/// MXC would then ignore. Never panics.
pub fn needs_consent_prompt() -> bool {
    inner_consent::needs_consent_prompt()
}

/// The administrative telemetry ceiling for this machine. Never panics; an
/// unreadable or unrecognised policy reports [`PolicyState::Blocked`].
pub fn get_policy() -> PolicyState {
    inner_policy::get_policy().into()
}

/// Whether an administrator has blocked telemetry on this machine.
pub fn is_blocked_by_policy() -> bool {
    inner_policy::is_blocked_by_policy()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The facade must map every variant, and must agree with the shared
    /// implementation on the wire string — a host or a sibling SDK comparing
    /// these strings would otherwise silently diverge.
    #[test]
    fn consent_states_round_trip_and_keep_their_wire_strings() {
        for (facade, inner) in [
            (ConsentState::Granted, inner_consent::ConsentState::Granted),
            (ConsentState::Denied, inner_consent::ConsentState::Denied),
            (
                ConsentState::Undetermined,
                inner_consent::ConsentState::Undetermined,
            ),
            (
                ConsentState::NotApplicable,
                inner_consent::ConsentState::NotApplicable,
            ),
        ] {
            assert_eq!(ConsentState::from(inner), facade);
            assert_eq!(facade.as_str(), inner.as_str());
            assert_eq!(facade.allows_collection(), inner.allows_collection());
            assert_eq!(facade.needs_prompt(), inner.needs_prompt());
        }
    }

    #[test]
    fn policy_states_round_trip_and_keep_their_wire_strings() {
        for (facade, inner) in [
            (
                PolicyState::Unrestricted,
                inner_policy::PolicyState::Unrestricted,
            ),
            (PolicyState::Allowed, inner_policy::PolicyState::Allowed),
            (PolicyState::Blocked, inner_policy::PolicyState::Blocked),
            (
                PolicyState::NotApplicable,
                inner_policy::PolicyState::NotApplicable,
            ),
        ] {
            assert_eq!(PolicyState::from(inner), facade);
            assert_eq!(facade.as_str(), inner.as_str());
            assert_eq!(facade.allows_collection(), inner.allows_collection());
        }
    }

    /// Only an explicit grant may permit collection. Locks in that the facade
    /// did not accidentally widen the shared rule.
    #[test]
    fn only_granted_consent_and_a_permitting_policy_allow_collection() {
        assert!(ConsentState::Granted.allows_collection());
        for denied in [
            ConsentState::Denied,
            ConsentState::Undetermined,
            ConsentState::NotApplicable,
        ] {
            assert!(!denied.allows_collection(), "{denied:?} must not permit");
        }

        // Only an explicit block denies on the policy side. `NotApplicable`
        // (off Windows) deliberately does *not* deny: the consent gate above
        // already reports `NotApplicable`, and denying here too would wrongly
        // imply an administrator had acted.
        assert!(!PolicyState::Blocked.allows_collection());
        for permitted in [
            PolicyState::Unrestricted,
            PolicyState::Allowed,
            PolicyState::NotApplicable,
        ] {
            assert!(permitted.allows_collection(), "{permitted:?} must permit");
        }
    }

    #[test]
    fn canonical_prompt_facade_preserves_every_rust_owned_field() {
        let inner = wxc_common::telemetry::consent_prompt::prompt_for_locale(Some("en-US"));
        let facade = ConsentPrompt::from(inner);

        assert_eq!(facade.resource_version, inner.resource_version);
        assert_eq!(facade.locale, inner.locale);
        assert_eq!(facade.title.id, inner.title.id);
        assert_eq!(facade.title.text, inner.title.text);
        assert_eq!(facade.body.id, inner.body.id);
        assert_eq!(facade.body.text, inner.body.text);
        assert_eq!(facade.affirmative_label.text, inner.affirmative_label.text);
        assert_eq!(facade.negative_label.text, inner.negative_label.text);
        assert_eq!(facade.learn_more_label.text, inner.learn_more_label.text);
        assert_eq!(facade.learn_more_url, inner.learn_more_url);
    }

    #[test]
    fn consent_result_wire_strings_are_closed_and_stable() {
        assert_eq!(ConsentActionResult::Granted.as_str(), "granted");
        assert_eq!(
            ConsentActionResult::AlreadyGranted.as_str(),
            "already-granted"
        );
        assert_eq!(
            ConsentActionResult::PolicyBlocked.as_str(),
            "policy-blocked"
        );
        assert_eq!(
            ConsentStatusReason::PromptVersionUnsupported.as_str(),
            "prompt-version-unsupported"
        );
    }
}
