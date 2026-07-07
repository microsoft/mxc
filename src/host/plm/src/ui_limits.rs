//! Cross-platform constants for `JOB_OBJECT_UILIMIT_*` flags, the
//! learning-mode violation categories, and the parsed `UiEvent`
//! shape. Pure data — no Win32 deps — so `config` and tests can
//! reason about UI relaxations without pulling in the Windows-only
//! event-parsing code.

// ---------------------------------------------------------------------------
// Learning-mode violation categories (EventID=27 `Category` field).
// ---------------------------------------------------------------------------

/// The process attempted an operation that requires the Win32k GUI subsystem
/// while running with `DisallowWin32kSystemCalls` enabled. To relax the
/// policy the corresponding config flips `ui.disable` from the default
/// `true` to `false`.
pub const CONVERT_TO_GUI: u32 = 1;

/// The process attempted a UI operation that was blocked by a Job UI Limit
/// (`JOB_OBJECT_UILIMIT_*`). The `Detail` field carries the specific
/// `JOB_OBJECT_UILIMIT_*` bit that fired.
pub const UI_OPERATION: u32 = 2;

// ---------------------------------------------------------------------------
// Job Object UI Limit flags. Values match the Win32 `JOB_OBJECT_UILIMIT_*`
// constants from <winnt.h>.
// ---------------------------------------------------------------------------

pub const JOB_OBJECT_UILIMIT_HANDLES: u32 = 0x0001;
pub const JOB_OBJECT_UILIMIT_READCLIPBOARD: u32 = 0x0002;
pub const JOB_OBJECT_UILIMIT_WRITECLIPBOARD: u32 = 0x0004;
pub const JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS: u32 = 0x0008;
pub const JOB_OBJECT_UILIMIT_DISPLAYSETTINGS: u32 = 0x0010;
pub const JOB_OBJECT_UILIMIT_GLOBALATOMS: u32 = 0x0020;
pub const JOB_OBJECT_UILIMIT_DESKTOP: u32 = 0x0040;
pub const JOB_OBJECT_UILIMIT_EXITWINDOWS: u32 = 0x0080;
pub const JOB_OBJECT_UILIMIT_IME: u32 = 0x0100;
pub const JOB_OBJECT_UILIMIT_INJECTION: u32 = 0x0200;

/// Human-readable name for a `JOB_OBJECT_UILIMIT_*` bit. Used for
/// diagnostic output; returns `None` if the bit is not recognised.
pub fn ui_limit_name(bit: u32) -> Option<&'static str> {
    Some(match bit {
        JOB_OBJECT_UILIMIT_HANDLES => "HANDLES",
        JOB_OBJECT_UILIMIT_READCLIPBOARD => "READCLIPBOARD",
        JOB_OBJECT_UILIMIT_WRITECLIPBOARD => "WRITECLIPBOARD",
        JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS => "SYSTEMPARAMETERS",
        JOB_OBJECT_UILIMIT_DISPLAYSETTINGS => "DISPLAYSETTINGS",
        JOB_OBJECT_UILIMIT_GLOBALATOMS => "GLOBALATOMS",
        JOB_OBJECT_UILIMIT_DESKTOP => "DESKTOP",
        JOB_OBJECT_UILIMIT_EXITWINDOWS => "EXITWINDOWS",
        JOB_OBJECT_UILIMIT_IME => "IME",
        JOB_OBJECT_UILIMIT_INJECTION => "INJECTION",
        _ => return None,
    })
}

/// Parsed payload of a UI-injection (EventID=27) event.
///
/// Pure data so it can live in a portable module. The decoding paths
/// (`parse_ui_event_payload`, `parse_ui_event_from_named`) live in the
/// Windows-only `event_parser` module because they share a hex-decoding
/// helper with the ACE walker.
#[derive(Debug, Clone)]
pub struct UiEvent {
    pub process_name: String,
    pub process_id: u64,
    pub sequence_number: u64,
    pub category: u32,
    pub detail: u32,
    pub denied: Option<bool>,
}
