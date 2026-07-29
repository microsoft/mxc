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
//! The SDK ships no consent UI. A host calls [`needs_consent_prompt`] once
//! (e.g. before its first sandbox run), shows its own prompt if that returns
//! `true`, and records the answer with [`set_consent`]. A settings surface can
//! call [`set_consent`] again at any later time to let the user change their
//! mind.
//!
//! ```no_run
//! use mxc_sdk::telemetry::{needs_consent_prompt, set_consent, get_consent, ConsentState};
//!
//! if needs_consent_prompt() {
//!     // Show your own consent UI, then record the user's choice.
//!     let opted_in = true;
//!     set_consent(opted_in, "prompt").expect("Windows host");
//! }
//!
//! // Anywhere later, e.g. a settings toggle:
//! match get_consent() {
//!     ConsentState::Granted => println!("telemetry on"),
//!     ConsentState::Denied | ConsentState::Undetermined => println!("telemetry off"),
//!     // Never offer a toggle here — MXC collects nothing off Windows.
//!     ConsentState::NotApplicable => {}
//! }
//! ```
//!
//! Off Windows, [`get_consent`] always returns
//! [`ConsentState::NotApplicable`] without touching disk,
//! [`needs_consent_prompt`] is always `false`, and [`set_consent`] always
//! returns `Err` — MXC must not pretend to accept consent it can never act on.
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

/// Record the user's decision. Returns `Err` on a non-Windows host, and on
/// Windows if the decision could not be persisted — a caller must not treat a
/// failed write as consent.
pub fn set_consent(granted: bool, source: &str) -> Result<(), String> {
    inner_consent::set_consent(granted, source)
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
}
