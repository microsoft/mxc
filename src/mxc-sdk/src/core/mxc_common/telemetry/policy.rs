// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Telemetry policy state.
//!
//! MXC has no administrative telemetry policy. User consent
//! ([`super::consent`]) alone governs whether telemetry is collected, and
//! nothing is read from the registry or any other policy source.
//!
//! [`PolicyState`] and [`get_policy`] remain part of the V1 SDK and FFI
//! surface. [`get_policy`] reports [`PolicyState::Unrestricted`] on Windows and
//! [`PolicyState::NotApplicable`] elsewhere. [`PolicyState::Allowed`] and
//! [`PolicyState::Blocked`] are retained for compatibility and are not
//! currently reported.

/// The telemetry policy state for this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyState {
    /// No policy applies. Telemetry is governed solely by the user's consent
    /// decision. This is *not* a grant.
    Unrestricted,
    /// Retained for compatibility; not currently reported. Still requires user
    /// consent before anything is collected.
    Allowed,
    /// Retained for compatibility; not currently reported. Nothing would be
    /// collected regardless of user consent.
    Blocked,
    /// Not a Windows host. MXC collects no telemetry here.
    NotApplicable,
}

impl PolicyState {
    /// Stable, lowercase wire representation used by the CLI flags, the FFI
    /// boundary, and the SDKs. Kept separate from `Debug` so the on-the-wire
    /// strings never drift if the Rust variant names change.
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyState::Unrestricted => "unrestricted",
            PolicyState::Allowed => "allowed",
            PolicyState::Blocked => "blocked",
            PolicyState::NotApplicable => "not-applicable",
        }
    }

    /// Whether this state permits telemetry collection.
    ///
    /// True for every state except [`Blocked`](PolicyState::Blocked). This
    /// never means "collect": it is one conjunct of [`super::is_enabled`],
    /// which also requires user consent.
    pub fn allows_collection(&self) -> bool {
        !matches!(self, PolicyState::Blocked)
    }
}

/// Returns the current telemetry policy state.
///
/// Always [`PolicyState::Unrestricted`] on Windows and
/// [`PolicyState::NotApplicable`] on other platforms.
pub fn get_policy() -> PolicyState {
    if cfg!(target_os = "windows") {
        PolicyState::Unrestricted
    } else {
        PolicyState::NotApplicable
    }
}

/// Whether telemetry is blocked by policy. Convenience over [`get_policy`];
/// the inverse of [`PolicyState::allows_collection`].
pub fn is_blocked_by_policy() -> bool {
    !get_policy().allows_collection()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_strings_are_stable() {
        assert_eq!(PolicyState::Unrestricted.as_str(), "unrestricted");
        assert_eq!(PolicyState::Allowed.as_str(), "allowed");
        assert_eq!(PolicyState::Blocked.as_str(), "blocked");
        assert_eq!(PolicyState::NotApplicable.as_str(), "not-applicable");
    }

    #[test]
    fn only_blocked_denies_collection() {
        assert!(PolicyState::Unrestricted.allows_collection());
        assert!(PolicyState::Allowed.allows_collection());
        assert!(PolicyState::NotApplicable.allows_collection());
        assert!(!PolicyState::Blocked.allows_collection());
    }

    #[test]
    fn get_policy_reports_the_platform_state() {
        if cfg!(target_os = "windows") {
            assert_eq!(get_policy(), PolicyState::Unrestricted);
        } else {
            assert_eq!(get_policy(), PolicyState::NotApplicable);
        }
        assert!(!is_blocked_by_policy());
    }
}
