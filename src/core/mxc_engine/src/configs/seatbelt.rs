// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Seatbelt-specific configuration types.

/// macOS Seatbelt settings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Seatbelt {
    /// Replace the generated sandbox profile entirely.
    pub profile_override: Option<String>,
    /// Allow GUI applications to reach WindowServer and related services.
    pub gui_access: bool,
    /// Allow the contained process to allocate nested pseudo-terminals.
    pub nested_pty: bool,
    /// Allow access to the macOS Keychain.
    pub keychain_access: bool,
    /// Additional Mach service global names the process may resolve.
    pub extra_mach_lookups: Vec<String>,
}

impl Default for Seatbelt {
    fn default() -> Self {
        Self {
            profile_override: None,
            gui_access: false,
            nested_pty: true,
            keychain_access: false,
            extra_mach_lookups: Vec::new(),
        }
    }
}
