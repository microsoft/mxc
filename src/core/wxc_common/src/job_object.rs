// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RAII wrapper around a Windows Job Object used to apply UI restrictions
//! (`JOB_OBJECT_UILIMIT_*`) to a child process and any descendants it creates,
//! plus the Windows-specific encoder that maps a platform-agnostic
//! [`crate::ui_policy::EffectiveUiRestrictions`] to the corresponding bitmask.
//!
//! The wrapper owns the underlying job HANDLE and closes it on drop. Once a
//! process has been assigned to a job, the kernel keeps the restrictions
//! attached for the process lifetime regardless of whether the job HANDLE is
//! still open in the creator, so dropping a `UiJobObject` after assignment is
//! safe and does not relax the restrictions on the running process.

use core::ffi::c_void;
use std::mem::size_of;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicUIRestrictions,
    SetInformationJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS, JOB_OBJECT_UILIMIT,
    JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};
use windows::Win32::System::SystemServices::JOB_OBJECT_UILIMIT_IME;
use windows_core::PCWSTR;

use crate::error::WxcError;
use crate::ui_policy::EffectiveUiRestrictions;

/// `JOB_OBJECT_UILIMIT_INJECTION` from `winnt.h`. The `windows` crate
/// does not emit this constant; if a future release adds it, the local
/// definition can be removed and the import above extended.
const JOB_OBJECT_UILIMIT_INJECTION: u32 = 0x0000_0200;

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
    pub fn set_ui_limits(&self, restrictions: &EffectiveUiRestrictions) -> Result<(), WxcError> {
        let info = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT(to_job_object_uilimit_mask(restrictions)),
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
}
