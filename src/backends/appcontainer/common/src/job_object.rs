// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RAII wrapper around a Windows Job Object used to apply UI restrictions
//! (`JOB_OBJECT_UILIMIT_*`) to a child process and any descendants it creates,
//! plus the Windows-specific encoder that maps a platform-agnostic
//! [`wxc_common::ui_policy::EffectiveUiRestrictions`] to the corresponding bitmask.
//!
//! The wrapper owns the underlying job HANDLE and closes it on drop. Once a
//! process has been assigned to a job, the kernel keeps the restrictions
//! attached for the process lifetime regardless of whether the job HANDLE is
//! still open in the creator, so dropping a `UiJobObject` after assignment is
//! safe and does not relax the restrictions on the running process.

use core::ffi::c_void;
use std::mem::size_of;
use std::sync::OnceLock;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicUIRestrictions,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JOB_OBJECT_UILIMIT, JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
    JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
    JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
    JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};
use windows::Win32::System::SystemServices::JOB_OBJECT_UILIMIT_IME;
use windows_core::PCWSTR;

use wxc_common::error::WxcError;
use wxc_common::ui_policy::EffectiveUiRestrictions;

/// Helper for loading `RtlGetVersion` from `ntdll.dll` to get the true
/// (unshimmed) OS version. `GetVersionExW` lies on post-8.1 builds due
/// to the compatibility shim.
mod version_detect {
    use std::mem::size_of;

    use windows::Win32::Foundation::NTSTATUS;
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;

    type RtlGetVersionFn = unsafe extern "system" fn(version_info: *mut OSVERSIONINFOW) -> NTSTATUS;

    /// Returns the real OS build number by calling `RtlGetVersion` from
    /// `ntdll.dll`. Falls back to `u32::MAX` if the symbol cannot be
    /// resolved or the call fails. `u32::MAX` is deliberately treated as
    /// "modern" by capability gating so an indeterminate probe fails secure
    /// (the more restrictive flag is kept rather than silently dropped).
    pub(super) fn get_os_build_number() -> u32 {
        // SAFETY: ntdll.dll is always loaded in every Windows process.
        // `GetModuleHandleW` with "ntdll.dll" returns the existing module
        // handle without incrementing a reference count.
        unsafe {
            let module = windows::Win32::System::LibraryLoader::GetModuleHandleW(
                windows::core::w!("ntdll.dll"),
            );
            let module = match module {
                Ok(h) => h,
                Err(_) => return u32::MAX,
            };
            let proc = windows::Win32::System::LibraryLoader::GetProcAddress(
                module,
                windows::core::s!("RtlGetVersion"),
            );
            let proc = match proc {
                Some(p) => p,
                None => return u32::MAX,
            };
            let rtl_get_version: RtlGetVersionFn = std::mem::transmute(proc);
            let mut info = OSVERSIONINFOW {
                dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
                ..Default::default()
            };
            let status = rtl_get_version(&mut info);
            if status.is_ok() {
                info.dwBuildNumber
            } else {
                u32::MAX
            }
        }
    }
}

/// `JOB_OBJECT_UILIMIT_INJECTION` from `winnt.h`. The `windows` crate
/// does not emit this constant; if a future release adds it, the local
/// definition can be removed and the import above extended.
const JOB_OBJECT_UILIMIT_INJECTION: u32 = 0x0000_0200;

/// Every `JOB_OBJECT_UILIMIT_*` bit this module's encoder
/// ([`to_job_object_uilimit_mask`]) can emit. Acts as the universe for the
/// capability intersection performed by [`supported_ui_limit_mask`]. Must
/// stay in sync with the encoder — the `encoder_known_bit_positions` test
/// pins the all-restrictions mask to this value.
const ALL_DEFINED_UI_LIMITS: u32 = 0x0000_03FF;

/// Minimum OS build that supports `JOB_OBJECT_UILIMIT_IME` (0x100).
/// This flag is empirically accepted on Windows 11 22H2 (22621) and later
/// — confirmed on 22631 (23H2) — but rejected with `ERROR_INVALID_PARAMETER`
/// on Windows Server 2022 (20348). Its exact introduction build between 20348
/// and 22631 is unconfirmed, so it is gated at the 22H2 boundary: builds below
/// it conservatively omit the flag (UI-limit support is monotonic — once a
/// build accepts the flag, every later build does too — so this never hands
/// the kernel a flag it would reject).
const MIN_BUILD_FOR_IME_LIMIT: u32 = 22621;

/// Minimum OS build that supports `JOB_OBJECT_UILIMIT_INJECTION` (0x200).
/// Windows 11 26100 (24H2) introduced this flag; earlier builds reject it
/// with `ERROR_INVALID_PARAMETER`, so it is excluded from the supported
/// UI-limit set on those builds.
const MIN_BUILD_FOR_INJECTION_LIMIT: u32 = 26100;

/// Cached OS build number (queried once via `RtlGetVersion`).
static OS_BUILD_NUMBER: OnceLock<u32> = OnceLock::new();

/// Returns the current OS build number, caching the result for the process
/// lifetime. Returns `u32::MAX` when the build cannot be determined, which
/// capability gating treats as "modern" so detection failures fail secure.
pub fn os_build_number() -> u32 {
    *OS_BUILD_NUMBER.get_or_init(version_detect::get_os_build_number)
}

/// Returns `true` when the current OS build can enforce
/// `JOB_OBJECT_UILIMIT_INJECTION` (input-injection blocking). Introduced in
/// build 26100; an unknown build is reported as supported (fail secure).
pub fn input_injection_blocking_supported() -> bool {
    os_build_number() >= MIN_BUILD_FOR_INJECTION_LIMIT
}

/// Pure capability map: given an OS build number, returns the subset of
/// encoder-defined `JOB_OBJECT_UILIMIT_*` flags the kernel can enforce on
/// that build. `JOB_OBJECT_UILIMIT_IME` and `JOB_OBJECT_UILIMIT_INJECTION`
/// are build-gated; all other flags are universally supported.
fn supported_ui_limit_mask_for_build(build: u32) -> u32 {
    let mut supported = ALL_DEFINED_UI_LIMITS;
    if build < MIN_BUILD_FOR_IME_LIMIT {
        supported &= !JOB_OBJECT_UILIMIT_IME;
    }
    if build < MIN_BUILD_FOR_INJECTION_LIMIT {
        supported &= !JOB_OBJECT_UILIMIT_INJECTION;
    }
    supported
}

#[inline(always)]
fn has_ui_limit(mask: u32, flag: u32) -> bool {
    (mask & flag) == flag
}

fn supported_ui_restrictions_for_build(build: u32) -> EffectiveUiRestrictions {
    let supported = supported_ui_limit_mask_for_build(build);
    EffectiveUiRestrictions {
        block_clipboard_read: has_ui_limit(supported, JOB_OBJECT_UILIMIT_READCLIPBOARD.0),
        block_clipboard_write: has_ui_limit(supported, JOB_OBJECT_UILIMIT_WRITECLIPBOARD.0),
        block_input_injection: has_ui_limit(supported, JOB_OBJECT_UILIMIT_INJECTION),
        block_input_method_changes: has_ui_limit(supported, JOB_OBJECT_UILIMIT_IME),
        block_external_ui_objects: has_ui_limit(supported, JOB_OBJECT_UILIMIT_HANDLES.0),
        block_global_ui_namespace: has_ui_limit(supported, JOB_OBJECT_UILIMIT_GLOBALATOMS.0),
        block_desktop_switching: has_ui_limit(supported, JOB_OBJECT_UILIMIT_DESKTOP.0),
        block_logoff_or_shutdown: has_ui_limit(supported, JOB_OBJECT_UILIMIT_EXITWINDOWS.0),
        block_system_parameter_changes: has_ui_limit(
            supported,
            JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS.0,
        ),
        block_display_settings_changes: has_ui_limit(
            supported,
            JOB_OBJECT_UILIMIT_DISPLAYSETTINGS.0,
        ),
    }
}

/// Returns the subset of encoder-defined `JOB_OBJECT_UILIMIT_*` flags the
/// current OS build can enforce. The effective restriction mask applied to a
/// job is always `requested & supported`, so the kernel is never handed a
/// flag it would reject.
pub fn supported_ui_limit_mask() -> u32 {
    supported_ui_limit_mask_for_build(os_build_number())
}

/// Returns the platform-agnostic UI restrictions the current OS build can
/// enforce. Reported to callers via `wxc-exec --probe`.
pub fn supported_ui_restrictions() -> EffectiveUiRestrictions {
    supported_ui_restrictions_for_build(os_build_number())
}

/// Encode platform-agnostic UI restrictions as the `JOB_OBJECT_UILIMIT_*`
/// bitmask consumed by `SetInformationJobObject(JobObjectBasicUIRestrictions)`
/// and by the BaseContainer SandboxSpec `ui_restrictions` field.
pub fn to_job_object_uilimit_mask(r: &EffectiveUiRestrictions) -> u32 {
    let mut mask: u32 = 0;
    if r.block_external_ui_objects {
        mask |= JOB_OBJECT_UILIMIT_HANDLES.0;
    }
    if r.block_clipboard_read {
        mask |= JOB_OBJECT_UILIMIT_READCLIPBOARD.0;
    }
    if r.block_clipboard_write {
        mask |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD.0;
    }
    if r.block_system_parameter_changes {
        mask |= JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS.0;
    }
    if r.block_display_settings_changes {
        mask |= JOB_OBJECT_UILIMIT_DISPLAYSETTINGS.0;
    }
    if r.block_global_ui_namespace {
        mask |= JOB_OBJECT_UILIMIT_GLOBALATOMS.0;
    }
    if r.block_desktop_switching {
        mask |= JOB_OBJECT_UILIMIT_DESKTOP.0;
    }
    if r.block_logoff_or_shutdown {
        mask |= JOB_OBJECT_UILIMIT_EXITWINDOWS.0;
    }
    if r.block_input_method_changes {
        mask |= JOB_OBJECT_UILIMIT_IME;
    }
    if r.block_input_injection {
        mask |= JOB_OBJECT_UILIMIT_INJECTION;
    }
    mask
}

/// RAII wrapper for an unnamed Windows Job Object configured for UI
/// restrictions. The job HANDLE is closed when this value is dropped.
pub struct UiJobObject {
    handle: HANDLE,
}

impl UiJobObject {
    /// Creates an unnamed Job Object owned by the current process.
    pub fn new() -> Result<Self, WxcError> {
        // SAFETY: CreateJobObjectW with NULL security attributes and NULL name
        // is documented to either return a valid HANDLE or an error.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|e| WxcError::Process(format!("CreateJobObjectW: {e}")))?;
        Ok(Self { handle })
    }

    /// Applies the given UI restrictions via `JobObjectBasicUIRestrictions`.
    /// Passing `EffectiveUiRestrictions::default()` clears all UI restrictions
    /// and is a valid no-op call.
    ///
    /// The mask actually applied is `requested & supported_ui_limit_mask()`:
    /// flags the current OS build cannot enforce (e.g.
    /// `JOB_OBJECT_UILIMIT_INJECTION` on builds older than 26100) are dropped
    /// so the call never fails with `ERROR_INVALID_PARAMETER`. Which flags a
    /// host can enforce is reported by `wxc-exec --probe`.
    pub fn set_ui_limits(&self, restrictions: &EffectiveUiRestrictions) -> Result<(), WxcError> {
        let mask = to_job_object_uilimit_mask(restrictions) & supported_ui_limit_mask();

        let info = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT(mask),
        };
        // SAFETY: `info` is a valid, fully-initialized struct living on the
        // stack for the duration of the call. The size matches the struct
        // type that JobObjectBasicUIRestrictions expects.
        unsafe {
            SetInformationJobObject(
                self.handle,
                JobObjectBasicUIRestrictions,
                &info as *const _ as *const c_void,
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
        }
        .map_err(|e| WxcError::Process(format!("SetInformationJobObject(UI): {e}")))
    }

    /// Assigns the given process handle to this job. The process and any
    /// future descendants will inherit the job's UI restrictions.
    pub fn assign_process(&self, process_handle: HANDLE) -> Result<(), WxcError> {
        // SAFETY: Both handles must be valid for the duration of the call;
        // this is the caller's responsibility for `process_handle`.
        unsafe { AssignProcessToJobObject(self.handle, process_handle) }
            .map_err(|e| WxcError::Process(format!("AssignProcessToJobObject: {e}")))
    }

    /// Terminate every process currently assigned to this job (the sandboxed
    /// child and all of its descendants) with the given exit code. Used to
    /// tree-kill a running sandbox. Best-effort: errors are ignored since the
    /// processes may already have exited.
    pub fn terminate(&self, exit_code: u32) {
        // SAFETY: `self.handle` is a valid job handle owned by this struct.
        unsafe {
            let _ = TerminateJobObject(self.handle, exit_code);
        }
    }
}

impl Drop for UiJobObject {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: `self.handle` was produced by CreateJobObjectW and has
            // not been closed elsewhere — `UiJobObject` owns it.
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_set_limits_drop() {
        let job = UiJobObject::new().expect("create");
        // Empty restrictions: should still succeed.
        job.set_ui_limits(&EffectiveUiRestrictions::default())
            .expect("set zero limits");
        // Apply a real restriction.
        job.set_ui_limits(&EffectiveUiRestrictions {
            block_global_ui_namespace: true,
            ..Default::default()
        })
        .expect("set global-namespace block");
        drop(job);
    }

    #[test]
    fn encoder_known_bit_positions() {
        // Sanity-check that the encoder produces the documented winnt.h
        // bit positions. If the `windows` crate ever changes its
        // representation, this catches it.
        let r = EffectiveUiRestrictions {
            block_external_ui_objects: true,
            block_clipboard_read: true,
            block_clipboard_write: true,
            block_system_parameter_changes: true,
            block_display_settings_changes: true,
            block_global_ui_namespace: true,
            block_desktop_switching: true,
            block_logoff_or_shutdown: true,
            block_input_method_changes: true,
            block_input_injection: true,
        };
        assert_eq!(to_job_object_uilimit_mask(&r), 0x03FF);
    }

    #[test]
    fn encoder_empty() {
        assert_eq!(
            to_job_object_uilimit_mask(&EffectiveUiRestrictions::default()),
            0
        );
    }

    #[test]
    fn encoder_individual_flags() {
        assert_eq!(
            to_job_object_uilimit_mask(&EffectiveUiRestrictions {
                block_external_ui_objects: true,
                ..Default::default()
            }),
            0x0001
        );
        assert_eq!(
            to_job_object_uilimit_mask(&EffectiveUiRestrictions {
                block_input_injection: true,
                ..Default::default()
            }),
            0x0200
        );
        assert_eq!(
            to_job_object_uilimit_mask(&EffectiveUiRestrictions {
                block_input_method_changes: true,
                ..Default::default()
            }),
            0x0100
        );
    }

    #[test]
    fn set_ui_limits_with_injection_succeeds_on_any_build() {
        // Regardless of OS build, set_ui_limits must never fail due to the
        // injection flag — the capability intersection drops it on downlevel.
        let job = UiJobObject::new().expect("create");
        job.set_ui_limits(&EffectiveUiRestrictions {
            block_input_injection: true,
            ..Default::default()
        })
        .expect("should succeed on any build");
    }

    #[test]
    fn set_ui_limits_all_flags_succeeds_on_any_build() {
        // The full ui.disable=true mask must succeed on any OS build.
        let job = UiJobObject::new().expect("create");
        let restrictions = EffectiveUiRestrictions {
            block_external_ui_objects: true,
            block_clipboard_read: true,
            block_clipboard_write: true,
            block_system_parameter_changes: true,
            block_display_settings_changes: true,
            block_global_ui_namespace: true,
            block_desktop_switching: true,
            block_logoff_or_shutdown: true,
            block_input_method_changes: true,
            block_input_injection: true,
        };
        job.set_ui_limits(&restrictions).expect("should succeed");
    }

    #[test]
    fn supported_mask_strips_injection_on_downlevel() {
        // Pre-26100 builds cannot enforce input-injection blocking, so it is
        // excluded from the supported set; all other flags remain.
        let mask = supported_ui_limit_mask_for_build(22631);
        assert_eq!(mask & JOB_OBJECT_UILIMIT_INJECTION, 0);
        assert_eq!(mask, ALL_DEFINED_UI_LIMITS & !JOB_OBJECT_UILIMIT_INJECTION);
        assert_eq!(mask, 0x01FF);
    }

    #[test]
    fn supported_mask_strips_ime_on_pre_22h2() {
        // Builds older than 22621 (e.g. Server 2022 = 20348) reject the IME
        // flag, so it is excluded along with injection; the classic
        // JOB_OBJECT_UILIMIT_ALL (0xFF) set remains.
        let mask = supported_ui_limit_mask_for_build(20348);
        assert_eq!(mask & JOB_OBJECT_UILIMIT_IME, 0);
        assert_eq!(mask & JOB_OBJECT_UILIMIT_INJECTION, 0);
        assert_eq!(
            mask,
            ALL_DEFINED_UI_LIMITS & !JOB_OBJECT_UILIMIT_IME & !JOB_OBJECT_UILIMIT_INJECTION
        );
        assert_eq!(mask, 0x00FF);
    }

    #[test]
    fn supported_restrictions_match_downlevel_mask() {
        let restrictions = supported_ui_restrictions_for_build(20348);
        assert!(restrictions.block_clipboard_read);
        assert!(restrictions.block_clipboard_write);
        assert!(restrictions.block_external_ui_objects);
        assert!(restrictions.block_display_settings_changes);
        assert!(!restrictions.block_input_injection);
        assert!(!restrictions.block_input_method_changes);
    }

    #[test]
    fn supported_mask_keeps_ime_on_22h2() {
        // Build 22621 (22H2) and later support the IME flag.
        let mask = supported_ui_limit_mask_for_build(22621);
        assert_eq!(mask & JOB_OBJECT_UILIMIT_IME, JOB_OBJECT_UILIMIT_IME);
    }

    #[test]
    fn supported_mask_keeps_injection_on_uplevel() {
        // Build 26100 (24H2) and later support the injection flag.
        let mask = supported_ui_limit_mask_for_build(26100);
        assert_eq!(
            mask & JOB_OBJECT_UILIMIT_INJECTION,
            JOB_OBJECT_UILIMIT_INJECTION
        );
        assert_eq!(mask, ALL_DEFINED_UI_LIMITS);
        assert_eq!(mask, 0x03FF);
    }

    #[test]
    fn supported_mask_fails_secure_on_unknown_build() {
        // An undetermined build (u32::MAX sentinel) keeps the more restrictive
        // flag rather than silently dropping it.
        let mask = supported_ui_limit_mask_for_build(u32::MAX);
        assert_eq!(
            mask & JOB_OBJECT_UILIMIT_INJECTION,
            JOB_OBJECT_UILIMIT_INJECTION
        );
        assert!(
            input_injection_blocking_supported()
                || os_build_number() < MIN_BUILD_FOR_INJECTION_LIMIT
        );
    }

    #[test]
    fn os_build_number_is_reasonable() {
        let build = os_build_number();
        // Any Windows 10+ build number should be >= 10240.
        assert!(build >= 10240, "unexpected build number: {build}");
    }
}
