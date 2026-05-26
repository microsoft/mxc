// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! UI policy resolution.
//!
//! Reads the user-facing [`UiPolicy`] and [`BaseProcessUiConfig`] structs
//! from [`crate::models`] and produces an [`EffectiveUiRestrictions`] —
//! a normalized, platform-agnostic record of which UI capabilities are
//! to be blocked. The mapping follows `docs/UIPolicy_Schema.md`.
//!
//! Encoding the result into a platform-specific shape (Windows
//! `JOB_OBJECT_UILIMIT_*` bitmask, or future macOS/Linux equivalents) is
//! done in platform-specific modules — for Windows, see
//! `crate::job_object::to_job_object_uilimit_mask`.

use crate::models::{BaseProcessUiConfig, ClipboardPolicy, UiPolicy};

/// Resolved UI restrictions ready for platform-specific encoding.
///
/// Each field names a single capability the child must be denied; `true`
/// means "block this." This layer carries intent only — there is no
/// Windows (or other OS) coupling here.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveUiRestrictions {
    // Clipboard
    pub block_clipboard_read: bool,
    pub block_clipboard_write: bool,

    // Input
    pub block_input_injection: bool,
    pub block_input_method_changes: bool,

    // UI-object isolation
    pub block_external_ui_objects: bool,
    pub block_global_ui_namespace: bool,
    pub block_desktop_switching: bool,
    pub block_logoff_or_shutdown: bool,

    // System-wide settings
    pub block_system_parameter_changes: bool,
    pub block_display_settings_changes: bool,
}

/// Resolve user policy into the set of UI capabilities to block.
///
/// Mapping follows `docs/UIPolicy_Schema.md`.
pub fn resolve_ui_restrictions(
    ui: &UiPolicy,
    base_proc_ui: &BaseProcessUiConfig,
) -> EffectiveUiRestrictions {
    let mut r = EffectiveUiRestrictions::default();

    if ui.disable {
        // When UI is fully disabled: DisallowWin32kSystemCalls blocks most
        // Win32k functionality, but we still set all restriction flags so the
        // sandbox spec accurately reflects the desired policy to the OS service.
        r.block_clipboard_read = true;
        r.block_clipboard_write = true;
        r.block_input_injection = true;
        r.block_external_ui_objects = true;
        r.block_global_ui_namespace = true;
        r.block_desktop_switching = true;
        r.block_logoff_or_shutdown = true;
        r.block_system_parameter_changes = true;
        r.block_display_settings_changes = true;
    } else {
        // Clipboard (default: "none" = block both)
        match ui.clipboard {
            ClipboardPolicy::All => {}
            ClipboardPolicy::Read => {
                r.block_clipboard_write = true;
            }
            ClipboardPolicy::Write => {
                r.block_clipboard_read = true;
            }
            // "none" or unrecognized → default-deny: block both
            _ => {
                r.block_clipboard_read = true;
                r.block_clipboard_write = true;
            }
        }

        // Input injection
        if !ui.injection {
            r.block_input_injection = true;
        }

        // UI-object isolation level (default: "container" = external objects + global namespace)
        match base_proc_ui.isolation.as_str() {
            "desktop" => {
                // No isolation restrictions
            }
            "handles" => {
                r.block_external_ui_objects = true;
            }
            "atoms" => {
                r.block_global_ui_namespace = true;
            }
            // "container" or unrecognized → default-deny: full isolation
            _ => {
                r.block_external_ui_objects = true;
                r.block_global_ui_namespace = true;
            }
        }

        // Desktop system control: blocks switching desktops and ending the session
        if !base_proc_ui.desktop_system_control {
            r.block_desktop_switching = true;
            r.block_logoff_or_shutdown = true;
        }

        // System settings (default: "none" = block all)
        match base_proc_ui.system_settings.as_str() {
            "all" => {}
            "parameters" => {
                r.block_display_settings_changes = true;
            }
            "display" => {
                r.block_system_parameter_changes = true;
            }
            // "none" or unrecognized → default-deny: block all
            _ => {
                r.block_system_parameter_changes = true;
                r.block_display_settings_changes = true;
            }
        }
    }

    // IME is always evaluated independently since the OS service enforces
    // it separately from DisallowWin32kSystemCalls.
    if !base_proc_ui.ime {
        r.block_input_method_changes = true;
    }

    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BaseProcessUiConfig, ClipboardPolicy, UiPolicy};

    #[test]
    fn disabled_blocks_all_restrictions() {
        let ui = UiPolicy {
            disable: true,
            ..Default::default()
        };
        let bp = BaseProcessUiConfig::default();
        let r = resolve_ui_restrictions(&ui, &bp);
        // disable=true sets all non-IME restrictions; ime=false (default) adds IME
        assert_eq!(
            r,
            EffectiveUiRestrictions {
                block_clipboard_read: true,
                block_clipboard_write: true,
                block_input_injection: true,
                block_input_method_changes: true,
                block_external_ui_objects: true,
                block_global_ui_namespace: true,
                block_desktop_switching: true,
                block_logoff_or_shutdown: true,
                block_system_parameter_changes: true,
                block_display_settings_changes: true,
            }
        );
    }

    #[test]
    fn default_policy_blocks_all_restrictions() {
        // UiPolicy::default has disable=true + ime=false → all restrictions set
        let r = resolve_ui_restrictions(&UiPolicy::default(), &BaseProcessUiConfig::default());
        assert_eq!(
            r,
            EffectiveUiRestrictions {
                block_clipboard_read: true,
                block_clipboard_write: true,
                block_input_injection: true,
                block_input_method_changes: true,
                block_external_ui_objects: true,
                block_global_ui_namespace: true,
                block_desktop_switching: true,
                block_logoff_or_shutdown: true,
                block_system_parameter_changes: true,
                block_display_settings_changes: true,
            }
        );
    }

    #[test]
    fn clipboard_read_with_default_backend() {
        let ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::Read,
            injection: true,
        };
        let bp = BaseProcessUiConfig::default();
        let r = resolve_ui_restrictions(&ui, &bp);
        assert_eq!(
            r,
            EffectiveUiRestrictions {
                block_clipboard_write: true,
                block_external_ui_objects: true,
                block_global_ui_namespace: true,
                block_desktop_switching: true,
                block_logoff_or_shutdown: true,
                block_system_parameter_changes: true,
                block_display_settings_changes: true,
                block_input_method_changes: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn no_restrictions_when_everything_allowed() {
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
        assert_eq!(
            resolve_ui_restrictions(&ui, &bp),
            EffectiveUiRestrictions::default()
        );
    }
}
