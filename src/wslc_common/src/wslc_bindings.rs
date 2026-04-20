// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rust FFI bindings for the WSLC SDK C API (`wslcsdk.h`).
//!
//! This module contains **only** the subset of the WSLC SDK required for the
//! MXC end-to-end flow: Session → Container → Process → I/O → Cleanup.
//! Additional bindings can be added from `external/wslc-sdk/include/wslcsdk.h`
//! as new features are needed.
//!
//! Provides:
//! - Opaque settings structs and handle types
//! - Enums for networking, flags, signals, I/O handles
//! - `WslcContainerVolume` and `WslcImageInfo` data structs
//! - Extern function declarations (29 of 54 total SDK functions)
//! - RAII guard types that call release functions on Drop

#![allow(
    non_camel_case_types,
    non_snake_case,
    dead_code,
    non_upper_case_globals
)]

use std::ffi::c_void;
use std::os::raw::c_char;

// Re-export for convenience in downstream crates.
pub type HRESULT = i32;
pub type BOOL = i32;
pub type HANDLE = *mut c_void;
pub type PCSTR = *const c_char;
pub type PCWSTR = *const u16;
pub type PWSTR = *mut u16;
pub type BYTE = u8;

pub const S_OK: HRESULT = 0;

// ---------------------------------------------------------------------------
// Opaque settings structs (must match C alignment and size)
// ---------------------------------------------------------------------------

pub const WSLC_SESSION_OPTIONS_SIZE: usize = 80;
pub const WSLC_SESSION_OPTIONS_ALIGNMENT: usize = 8;

#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub struct WslcSessionSettings {
    pub _opaque: [BYTE; WSLC_SESSION_OPTIONS_SIZE],
}

pub const WSLC_CONTAINER_OPTIONS_SIZE: usize = 96;

#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub struct WslcContainerSettings {
    pub _opaque: [BYTE; WSLC_CONTAINER_OPTIONS_SIZE],
}

pub const WSLC_CONTAINER_PROCESS_OPTIONS_SIZE: usize = 72;

#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub struct WslcProcessSettings {
    pub _opaque: [BYTE; WSLC_CONTAINER_PROCESS_OPTIONS_SIZE],
}

// ---------------------------------------------------------------------------
// Handle types (opaque pointers, same as DECLARE_HANDLE)
// ---------------------------------------------------------------------------

pub type WslcSession = *mut c_void;
pub type WslcContainer = *mut c_void;
pub type WslcProcess = *mut c_void;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WslcContainerNetworkingMode {
    None = 0,
    Bridged = 1,
}

// ---------------------------------------------------------------------------
// Bitflag types (C header uses DEFINE_ENUM_FLAG_OPERATORS for these)
//
// Modeled as #[repr(transparent)] newtypes so callers can combine flags
// with `|`, e.g. `WslcContainerFlags::AutoRemove | WslcContainerFlags::EnableGpu`.
// ---------------------------------------------------------------------------

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WslcSessionFeatureFlags(pub u32);

#[allow(non_upper_case_globals)]
impl WslcSessionFeatureFlags {
    pub const None: Self = Self(0x00000000);
    pub const EnableGpu: Self = Self(0x00000004);
}

impl core::ops::BitOr for WslcSessionFeatureFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WslcContainerFlags(pub u32);

#[allow(non_upper_case_globals)]
impl WslcContainerFlags {
    pub const None: Self = Self(0x00000000);
    pub const AutoRemove: Self = Self(0x00000001);
    pub const EnableGpu: Self = Self(0x00000002);
    pub const Privileged: Self = Self(0x00000004);
}

impl core::ops::BitOr for WslcContainerFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WslcContainerStartFlags(pub u32);

#[allow(non_upper_case_globals)]
impl WslcContainerStartFlags {
    pub const None: Self = Self(0x00000000);
    pub const Attach: Self = Self(0x00000001);
}

impl core::ops::BitOr for WslcContainerStartFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WslcSignal {
    None = 0,
    SigHup = 1,
    SigInt = 2,
    SigQuit = 3,
    SigKill = 9,
    SigTerm = 15,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WslcDeleteContainerFlags {
    None = 0,
    Force = 0x01,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WslcProcessIOHandle {
    Stdin = 0,
    Stdout = 1,
    Stderr = 2,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WslcComponentFlags {
    None = 0,
    VirtualMachinePlatform = 1,
    WslPackage = 2,
}

// ---------------------------------------------------------------------------
// Data structs
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct WslcContainerVolume {
    pub windows_path: PCWSTR,
    pub container_path: PCSTR,
    pub read_only: BOOL,
}

pub const WSLC_IMAGE_NAME_LENGTH: usize = 256;

#[repr(C)]
pub struct WslcImageInfo {
    pub name: [c_char; WSLC_IMAGE_NAME_LENGTH],
    pub sha256: [u8; 32],
    pub size_bytes: u64,
    pub created_timestamp: u64,
}

/// Options for pulling a container image via `WslcPullSessionImage`.
#[repr(C)]
pub struct WslcPullImageOptions {
    pub uri: PCSTR,
    pub progress_callback: Option<WslcContainerImageProgressCallback>,
    pub progress_callback_context: *mut c_void,
    pub auth_info: *const c_void, // WslcRegistryAuthenticationInformation*
}

pub type WslcContainerImageProgressCallback = unsafe extern "system" fn(
    progress: *const c_void, // WslcImageProgressMessage*
    context: *mut c_void,
) -> HRESULT;

/// Options for importing a container image via `WslcImportSessionImageFromFile`.
#[repr(C)]
pub struct WslcImportImageOptions {
    pub progress_callback: Option<WslcContainerImageProgressCallback>,
    pub progress_callback_context: *mut c_void,
}

/// Options for loading a Docker image archive via `WslcLoadSessionImageFromFile`.
///
/// Used for `docker save` format tars (multi-layer archives with `manifest.json`).
/// The image name is extracted from the archive metadata automatically.
#[repr(C)]
pub struct WslcLoadImageOptions {
    pub progress_callback: Option<WslcContainerImageProgressCallback>,
    pub progress_callback_context: *mut c_void,
}

// ---------------------------------------------------------------------------
// Callback types for process I/O
// ---------------------------------------------------------------------------

/// Callback invoked when stdout or stderr data is available.
pub type WslcStdIOCallback = unsafe extern "system" fn(
    io_handle: WslcProcessIOHandle,
    data: *const BYTE,
    data_size: u32,
    context: *mut c_void,
);

/// Callback invoked when a process exits and all I/O has been flushed.
pub type WslcProcessExitCallback = unsafe extern "system" fn(exit_code: i32, context: *mut c_void);

/// Callbacks for process I/O and exit notification.
#[repr(C)]
pub struct WslcProcessCallbacks {
    pub on_stdout: Option<WslcStdIOCallback>,
    pub on_stderr: Option<WslcStdIOCallback>,
    pub on_exit: Option<WslcProcessExitCallback>,
}

// ---------------------------------------------------------------------------
// Extern function declarations — MVP subset for the runner lifecycle
//
// Memory ownership: several functions return heap-allocated strings via
// `error_message: *mut PWSTR` out-parameters. These are allocated with
// `CoTaskMemAlloc` by the SDK. The caller owns the returned memory and
// must free it with `CoTaskMemFree` when no longer needed. A safe wrapper
// should be provided in the runner layer to avoid leaks.
// ---------------------------------------------------------------------------

extern "system" {
    // -- Prerequisites --
    pub fn WslcCanRun(can_run: *mut BOOL, missing_components: *mut WslcComponentFlags) -> HRESULT;

    // -- Session management --
    pub fn WslcInitSessionSettings(
        name: PCWSTR,
        storage_path: PCWSTR,
        session_settings: *mut WslcSessionSettings,
    ) -> HRESULT;

    pub fn WslcSetSessionSettingsCpuCount(
        session_settings: *mut WslcSessionSettings,
        cpu_count: u32,
    ) -> HRESULT;

    pub fn WslcSetSessionSettingsMemory(
        session_settings: *mut WslcSessionSettings,
        memory_mb: u32,
    ) -> HRESULT;

    pub fn WslcSetSessionSettingsTimeout(
        session_settings: *mut WslcSessionSettings,
        timeout_ms: u32,
    ) -> HRESULT;

    pub fn WslcSetSessionSettingsFeatureFlags(
        session_settings: *mut WslcSessionSettings,
        flags: WslcSessionFeatureFlags,
    ) -> HRESULT;

    pub fn WslcCreateSession(
        session_settings: *mut WslcSessionSettings,
        session: *mut WslcSession,
        error_message: *mut PWSTR,
    ) -> HRESULT;

    pub fn WslcTerminateSession(session: WslcSession) -> HRESULT;
    pub fn WslcReleaseSession(session: WslcSession) -> HRESULT;

    // -- Image management --

    /// List images available in the session's image store.
    ///
    /// On success, `images` is set to a CoTaskMem-allocated array of
    /// `WslcImageInfo` structs and `count` to the number of elements.
    /// The caller must free the array with `CoTaskMemFree` when done.
    pub fn WslcListSessionImages(
        session: WslcSession,
        images: *mut *mut WslcImageInfo,
        count: *mut u32,
    ) -> HRESULT;

    pub fn WslcPullSessionImage(
        session: WslcSession,
        options: *const WslcPullImageOptions,
        error_message: *mut PWSTR,
    ) -> HRESULT;

    pub fn WslcImportSessionImageFromFile(
        session: WslcSession,
        image_name: PCSTR,
        path: PCWSTR,
        options: *const WslcImportImageOptions,
        error_message: *mut PWSTR,
    ) -> HRESULT;

    /// Load a Docker image archive (`docker save` format) from a local file.
    ///
    /// Unlike `WslcImportSessionImageFromFile` (which takes a rootfs tar and a
    /// caller-supplied image name), this function reads the multi-layer Docker
    /// image archive and extracts the image name from the archive metadata.
    pub fn WslcLoadSessionImageFromFile(
        session: WslcSession,
        path: PCWSTR,
        options: *const WslcLoadImageOptions,
        error_message: *mut PWSTR,
    ) -> HRESULT;

    // -- Container management --
    pub fn WslcInitContainerSettings(
        image_name: PCSTR,
        container_settings: *mut WslcContainerSettings,
    ) -> HRESULT;

    pub fn WslcSetContainerSettingsNetworkingMode(
        container_settings: *mut WslcContainerSettings,
        networking_mode: WslcContainerNetworkingMode,
    ) -> HRESULT;

    pub fn WslcSetContainerSettingsFlags(
        container_settings: *mut WslcContainerSettings,
        flags: WslcContainerFlags,
    ) -> HRESULT;

    pub fn WslcSetContainerSettingsVolumes(
        container_settings: *mut WslcContainerSettings,
        volumes: *const WslcContainerVolume,
        volume_count: u32,
    ) -> HRESULT;

    pub fn WslcSetContainerSettingsInitProcess(
        container_settings: *mut WslcContainerSettings,
        init_process: *mut WslcProcessSettings,
    ) -> HRESULT;

    pub fn WslcCreateContainer(
        session: WslcSession,
        container_settings: *const WslcContainerSettings,
        container: *mut WslcContainer,
        error_message: *mut PWSTR,
    ) -> HRESULT;

    pub fn WslcStartContainer(
        container: WslcContainer,
        flags: WslcContainerStartFlags,
        error_message: *mut PWSTR,
    ) -> HRESULT;

    pub fn WslcStopContainer(
        container: WslcContainer,
        signal: WslcSignal,
        timeout_seconds: u32,
        error_message: *mut PWSTR,
    ) -> HRESULT;

    pub fn WslcDeleteContainer(
        container: WslcContainer,
        flags: WslcDeleteContainerFlags,
        error_message: *mut PWSTR,
    ) -> HRESULT;

    pub fn WslcGetContainerInitProcess(
        container: WslcContainer,
        init_process: *mut WslcProcess,
    ) -> HRESULT;

    pub fn WslcReleaseContainer(container: WslcContainer) -> HRESULT;

    // -- Process management --
    /// Create a new process in a running container (used for post-start exec,
    /// e.g., iptables rules before the user script).
    pub fn WslcCreateContainerProcess(
        container: WslcContainer,
        new_process_settings: *mut WslcProcessSettings,
        new_process: *mut WslcProcess,
        error_message: *mut PWSTR,
    ) -> HRESULT;

    pub fn WslcInitProcessSettings(process_settings: *mut WslcProcessSettings) -> HRESULT;

    pub fn WslcSetProcessSettingsCmdLine(
        process_settings: *mut WslcProcessSettings,
        argv: *const PCSTR,
        argc: usize,
    ) -> HRESULT;

    pub fn WslcSetProcessSettingsEnvVariables(
        process_settings: *mut WslcProcessSettings,
        key_value: *const PCSTR,
        argc: usize,
    ) -> HRESULT;

    pub fn WslcSetProcessSettingsCurrentDirectory(
        process_settings: *mut WslcProcessSettings,
        current_directory: PCSTR,
    ) -> HRESULT;

    pub fn WslcSetProcessSettingsCallbacks(
        process_settings: *mut WslcProcessSettings,
        callbacks: *const WslcProcessCallbacks,
        context: *mut c_void,
    ) -> HRESULT;

    pub fn WslcGetProcessExitEvent(process: WslcProcess, exit_event: *mut HANDLE) -> HRESULT;

    pub fn WslcGetProcessExitCode(process: WslcProcess, exit_code: *mut i32) -> HRESULT;

    pub fn WslcReleaseProcess(process: WslcProcess) -> HRESULT;
}

// ---------------------------------------------------------------------------
// RAII Guard types
// ---------------------------------------------------------------------------

/// RAII guard for a WSLC session handle. Calls `WslcReleaseSession` on drop.
pub struct WslcSessionGuard {
    handle: WslcSession,
}

impl WslcSessionGuard {
    /// Create a guard from a raw session handle. The caller transfers ownership.
    ///
    /// # Safety
    /// The handle must be a valid, non-null session returned by `WslcCreateSession`.
    pub unsafe fn from_raw(handle: WslcSession) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    /// Get the raw handle for passing to SDK functions.
    pub fn as_raw(&self) -> WslcSession {
        self.handle
    }
}

impl Drop for WslcSessionGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                eprintln!("[WSLC][debug] WslcSessionGuard dropped -- releasing session");
                WslcReleaseSession(self.handle);
            }
        }
    }
}

/// RAII guard for a WSLC container handle. Calls `WslcReleaseContainer` on drop.
pub struct WslcContainerGuard {
    handle: WslcContainer,
}

impl WslcContainerGuard {
    /// Create a guard from a raw container handle. The caller transfers ownership.
    ///
    /// # Safety
    /// The handle must be a valid, non-null container returned by `WslcCreateContainer`.
    pub unsafe fn from_raw(handle: WslcContainer) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    /// Get the raw handle for passing to SDK functions.
    pub fn as_raw(&self) -> WslcContainer {
        self.handle
    }
}

impl Drop for WslcContainerGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                eprintln!("[WSLC][debug] WslcContainerGuard dropped -- releasing container");
                WslcReleaseContainer(self.handle);
            }
        }
    }
}

/// RAII guard for a WSLC process handle. Calls `WslcReleaseProcess` on drop.
pub struct WslcProcessGuard {
    handle: WslcProcess,
}

impl WslcProcessGuard {
    /// Create a guard from a raw process handle. The caller transfers ownership.
    ///
    /// # Safety
    /// The handle must be a valid, non-null process returned by `WslcGetContainerInitProcess`.
    pub unsafe fn from_raw(handle: WslcProcess) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    /// Get the raw handle for passing to SDK functions.
    pub fn as_raw(&self) -> WslcProcess {
        self.handle
    }
}

impl Drop for WslcProcessGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                eprintln!("[WSLC][debug] WslcProcessGuard dropped -- releasing process");
                WslcReleaseProcess(self.handle);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: check HRESULT
// ---------------------------------------------------------------------------

/// Convert an HRESULT into a `Result`. Returns `Ok(())` for `S_OK`,
/// or `Err(hr)` for any failure code.
///
/// Note: standard COM convention treats any `hr >= 0` as success (including
/// `S_FALSE`). We intentionally check `== S_OK` here because the WSLC SDK
/// documents `S_OK` as the only success return — any other value (including
/// `S_FALSE`) would indicate unexpected behavior worth investigating.
#[inline]
pub fn check_hresult(hr: HRESULT) -> Result<(), HRESULT> {
    if hr == S_OK {
        Ok(())
    } else {
        Err(hr)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn settings_struct_sizes_match_c_header() {
        assert_eq!(
            mem::size_of::<WslcSessionSettings>(),
            WSLC_SESSION_OPTIONS_SIZE
        );
        assert_eq!(
            mem::size_of::<WslcContainerSettings>(),
            WSLC_CONTAINER_OPTIONS_SIZE
        );
        assert_eq!(
            mem::size_of::<WslcProcessSettings>(),
            WSLC_CONTAINER_PROCESS_OPTIONS_SIZE
        );
    }

    #[test]
    fn settings_struct_alignments_match_c_header() {
        assert_eq!(
            mem::align_of::<WslcSessionSettings>(),
            WSLC_SESSION_OPTIONS_ALIGNMENT
        );
        assert_eq!(mem::align_of::<WslcContainerSettings>(), 8);
        assert_eq!(mem::align_of::<WslcProcessSettings>(), 8);
    }

    #[test]
    fn enum_discriminant_values() {
        assert_eq!(WslcContainerNetworkingMode::None as i32, 0);
        assert_eq!(WslcContainerNetworkingMode::Bridged as i32, 1);
        assert_eq!(WslcSessionFeatureFlags::EnableGpu.0, 0x4);
        assert_eq!(WslcSignal::SigKill as i32, 9);
        assert_eq!(WslcSignal::SigTerm as i32, 15);
        assert_eq!(WslcContainerFlags::AutoRemove.0, 1);
        assert_eq!(WslcContainerFlags::EnableGpu.0, 2);
        assert_eq!(WslcContainerFlags::Privileged.0, 4);
    }

    #[test]
    fn bitflags_can_be_combined() {
        let flags = WslcContainerFlags::AutoRemove | WslcContainerFlags::EnableGpu;
        assert_eq!(flags.0, 0x03);

        let session_flags = WslcSessionFeatureFlags::None | WslcSessionFeatureFlags::EnableGpu;
        assert_eq!(session_flags.0, 0x04);
    }

    #[test]
    fn check_hresult_ok_and_err() {
        assert!(check_hresult(S_OK).is_ok());
        assert!(check_hresult(-2147467259).is_err()); // E_FAIL
    }
}
