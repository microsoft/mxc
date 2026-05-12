// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! UI policy bitmask helpers.
//!
//! Maps cross-platform [`UiPolicy`] and BaseProcessContainer-specific
//! [`BaseProcessUiConfig`] values onto the Windows `JOB_OBJECT_UILIMIT_*`
//! flag set. The mapping follows `docs/UIPolicy_Schema.md`.
//!
//! This module is platform-agnostic: the values are pure `u64` bitmasks
//! computed from the policy structs in [`crate::models`]. The actual
//! application of the bitmask to a Job Object is performed by Windows-only
//! runners (BaseContainer in Phase 1a; AppContainer in Phase 1c).

use crate::models::{BaseProcessUiConfig, ClipboardPolicy, UiPolicy};

/// JOB_OBJECT_UILIMIT_* flag constants (from UIPolicy_Schema.md).
pub const UILIMIT_HANDLES: u64 = 0x0001;
pub const UILIMIT_READCLIPBOARD: u64 = 0x0002;
pub const UILIMIT_WRITECLIPBOARD: u64 = 0x0004;
pub const UILIMIT_SYSTEMPARAMETERS: u64 = 0x0008;
pub const UILIMIT_DISPLAYSETTINGS: u64 = 0x0010;
pub const UILIMIT_GLOBALATOMS: u64 = 0x0020;
pub const UILIMIT_DESKTOP: u64 = 0x0040;
pub const UILIMIT_EXITWINDOWS: u64 = 0x0080;
pub const UILIMIT_IME: u64 = 0x0100;
pub const UILIMIT_INJECTION: u64 = 0x0200;

/// Build the JOB_OBJECT_UILIMIT_* bitmask from the cross-platform UI policy
/// and the BaseProcessContainer-specific UI config.
/// Mapping follows docs/UIPolicy_Schema.md.
pub fn ui_restrictions_bitmask(ui: &UiPolicy, base_proc_ui: &BaseProcessUiConfig) -> u64 {
    // When UI is fully disabled: DisallowWin32kSystemCalls handles everything
    // except atoms (NT executive syscalls, not Win32k). Only set GLOBALATOMS.
    if ui.disable {
        return UILIMIT_GLOBALATOMS;
    }

    let mut mask: u64 = 0;

    // Cross-platform: clipboard (default: "none" = block both)
    match ui.clipboard {
        ClipboardPolicy::All => {}
        ClipboardPolicy::Read => {
            mask |= UILIMIT_WRITECLIPBOARD;
        }
        ClipboardPolicy::Write => {
            mask |= UILIMIT_READCLIPBOARD;
        }
        // "none" or unrecognized → default-deny: block both
        _ => {
            mask |= UILIMIT_READCLIPBOARD | UILIMIT_WRITECLIPBOARD;
        }
    }

    // Cross-platform: input injection
    if !ui.injection {
        mask |= UILIMIT_INJECTION;
    }

    // Backend-specific: isolation level (default: "container" = HANDLES + GLOBALATOMS)
    match base_proc_ui.isolation.as_str() {
        "desktop" => {
            // No isolation flags
        }
        "handles" => {
            mask |= UILIMIT_HANDLES;
        }
        "atoms" => {
            mask |= UILIMIT_GLOBALATOMS;
        }
        // "container" or unrecognized → default-deny: full isolation
        _ => {
            mask |= UILIMIT_HANDLES | UILIMIT_GLOBALATOMS;
        }
    }

    // Backend-specific: desktop system control
    if !base_proc_ui.desktop_system_control {
        mask |= UILIMIT_DESKTOP | UILIMIT_EXITWINDOWS;
    }

    // Backend-specific: system settings (default: "none" = block all)
    match base_proc_ui.system_settings.as_str() {
        "all" => {}
        "parameters" => {
            mask |= UILIMIT_DISPLAYSETTINGS;
        }
        "display" => {
            mask |= UILIMIT_SYSTEMPARAMETERS;
        }
        // "none" or unrecognized → default-deny: block all
        _ => {
            mask |= UILIMIT_SYSTEMPARAMETERS | UILIMIT_DISPLAYSETTINGS;
        }
    }

    // Backend-specific: IME
    if !base_proc_ui.ime {
        mask |= UILIMIT_IME;
    }

    mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BaseProcessUiConfig, ClipboardPolicy, UiPolicy};

    #[test]
    fn ui_bitmask_disabled() {
        let ui = UiPolicy {
            disable: true,
            ..Default::default()
        };
        let bp = BaseProcessUiConfig::default();
        // disable=true → only GLOBALATOMS
        assert_eq!(ui_restrictions_bitmask(&ui, &bp), UILIMIT_GLOBALATOMS);
    }

    #[test]
    fn ui_bitmask_default_deny() {
        // UiPolicy default: disable=true → only GLOBALATOMS
        assert_eq!(
            ui_restrictions_bitmask(&UiPolicy::default(), &BaseProcessUiConfig::default()),
            UILIMIT_GLOBALATOMS
        );
    }

    #[test]
    fn ui_bitmask_clipboard_read_with_default_backend() {
        let ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::Read,
            injection: true,
        };
        let bp = BaseProcessUiConfig::default(); // isolation=container, desktopSystemControl=false, systemSettings=none, ime=false
        let expected = UILIMIT_WRITECLIPBOARD
            | UILIMIT_HANDLES
            | UILIMIT_GLOBALATOMS
            | UILIMIT_DESKTOP
            | UILIMIT_EXITWINDOWS
            | UILIMIT_SYSTEMPARAMETERS
            | UILIMIT_DISPLAYSETTINGS
            | UILIMIT_IME;
        assert_eq!(ui_restrictions_bitmask(&ui, &bp), expected);
    }

    #[test]
    fn ui_bitmask_no_backend_restrictions() {
        let ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::All,
            injection: true,
        };
        let bp = BaseProcessUiConfig {
            isolation: "desktop".to_string(),
            desktop_system_control: true,
            system_settings: "all".to_string(),
            ime: true,
        };
        // No cross-platform restrictions + no backend restrictions = 0
        assert_eq!(ui_restrictions_bitmask(&ui, &bp), 0);
    }
}
