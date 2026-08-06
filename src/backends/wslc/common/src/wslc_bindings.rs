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

pub const WSLC_SESSION_OPTIONS_SIZE: usize = 72;
pub const WSLC_SESSION_OPTIONS_ALIGNMENT: usize = 8;

#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub struct WslcSessionSettings {
    pub _opaque: [BYTE; WSLC_SESSION_OPTIONS_SIZE],
}

pub const WSLC_CONTAINER_OPTIONS_SIZE: usize = 104;

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

/// Bitmask of missing WSLC runtime components returned by
/// `WslcGetMissingComponents` (an out-parameter).
///
/// Modeled as a `#[repr(transparent)]` newtype over `u32` rather than an enum
/// because the SDK may OR several bits together (e.g.
/// `VIRTUAL_MACHINE_PLATFORM | WSL_PACKAGE == 3` when both are missing).
/// Materializing such a combined value into a `#[repr(u32)]` enum with no
/// matching discriminant would be undefined behavior, so this stays a plain
/// integer newtype and callers test individual bits.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WslcComponentFlags(pub u32);

impl WslcComponentFlags {
    pub const NONE: Self = Self(0);
    pub const VIRTUAL_MACHINE_PLATFORM: Self = Self(1);
    pub const WSL_PACKAGE: Self = Self(2);
    pub const SDK_NEEDS_UPDATE: Self = Self(4);

    /// True if any missing-component bit is set.
    pub fn any_missing(self) -> bool {
        self.0 != 0
    }
}

impl core::fmt::Debug for WslcComponentFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0 == 0 {
            return write!(f, "None");
        }
        let mut names = Vec::new();
        if self.0 & Self::VIRTUAL_MACHINE_PLATFORM.0 != 0 {
            names.push("VirtualMachinePlatform");
        }
        if self.0 & Self::WSL_PACKAGE.0 != 0 {
            names.push("WslPackage");
        }
        if self.0 & Self::SDK_NEEDS_UPDATE.0 != 0 {
            names.push("SdkNeedsUpdate");
        }
        if names.is_empty() {
            write!(f, "Unknown(0x{:x})", self.0)
        } else {
            write!(f, "{} (0x{:x})", names.join(" | "), self.0)
        }
    }
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

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WslcPortProtocol {
    Tcp = 0,
    Udp = 1,
}

/// Host↔container port mapping passed to
/// `WslcSetContainerSettingsPortMappings`.
///
/// Matches `WslcContainerPortMapping` in `wslcsdk.h`. The trailing
/// `windows_address` field is an optional override for the host bind address;
/// MXC always passes `null`, which lets the SDK select the default address.
///
/// Note: although the C header declares `WSLC_PORT_PROTOCOL_UDP = 1`, the
/// shipped SDK runtime returns `E_NOTIMPL` when UDP is actually requested. The
/// parser rejects `"udp"` up front; this enum keeps the discriminant so it
/// stays in sync with the C ABI if a future SDK ships UDP support.
#[repr(C)]
pub struct WslcContainerPortMapping {
    pub windows_port: u16,
    pub container_port: u16,
    pub protocol: WslcPortProtocol,
    pub windows_address: *const c_void,
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
    pub registry_auth: PCSTR,
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
// Runtime-loaded SDK function table
//
// Instead of static `extern "system"` declarations (which require wslcsdk.dll
// at process startup), we load the DLL at runtime via `libloading`. This
// makes wslcsdk.dll a runtime dependency — the binary starts without it
// and only fails when the WSLC backend is actually used.
// ---------------------------------------------------------------------------

/// Function pointer type aliases for all WSLC SDK functions used by MXC.
mod ffi_types {
    use super::*;

    pub type WslcGetMissingComponentsFn =
        unsafe extern "system" fn(*mut WslcComponentFlags) -> HRESULT;
    pub type WslcInitSessionSettingsFn =
        unsafe extern "system" fn(PCWSTR, PCWSTR, *mut WslcSessionSettings) -> HRESULT;
    pub type WslcSetSessionSettingsCpuCountFn =
        unsafe extern "system" fn(*mut WslcSessionSettings, u32) -> HRESULT;
    pub type WslcSetSessionSettingsMemoryFn =
        unsafe extern "system" fn(*mut WslcSessionSettings, u32) -> HRESULT;
    pub type WslcSetSessionSettingsTimeoutFn =
        unsafe extern "system" fn(*mut WslcSessionSettings, u32) -> HRESULT;
    pub type WslcSetSessionSettingsFeatureFlagsFn =
        unsafe extern "system" fn(*mut WslcSessionSettings, WslcSessionFeatureFlags) -> HRESULT;
    pub type WslcCreateSessionFn = unsafe extern "system" fn(
        *mut WslcSessionSettings,
        *mut WslcSession,
        *mut PWSTR,
    ) -> HRESULT;
    pub type WslcTerminateSessionFn = unsafe extern "system" fn(WslcSession) -> HRESULT;
    pub type WslcReleaseSessionFn = unsafe extern "system" fn(WslcSession) -> HRESULT;
    pub type WslcListSessionImagesFn =
        unsafe extern "system" fn(WslcSession, *mut *mut WslcImageInfo, *mut u32) -> HRESULT;
    pub type WslcPullSessionImageFn =
        unsafe extern "system" fn(WslcSession, *const WslcPullImageOptions, *mut PWSTR) -> HRESULT;
    pub type WslcImportSessionImageFromFileFn = unsafe extern "system" fn(
        WslcSession,
        PCSTR,
        PCWSTR,
        *const WslcImportImageOptions,
        *mut PWSTR,
    ) -> HRESULT;
    pub type WslcLoadSessionImageFromFileFn = unsafe extern "system" fn(
        WslcSession,
        PCWSTR,
        *const WslcLoadImageOptions,
        *mut PWSTR,
    ) -> HRESULT;
    pub type WslcInitContainerSettingsFn =
        unsafe extern "system" fn(PCSTR, *mut WslcContainerSettings) -> HRESULT;
    pub type WslcSetContainerSettingsNetworkingModeFn = unsafe extern "system" fn(
        *mut WslcContainerSettings,
        WslcContainerNetworkingMode,
    ) -> HRESULT;
    pub type WslcSetContainerSettingsFlagsFn =
        unsafe extern "system" fn(*mut WslcContainerSettings, WslcContainerFlags) -> HRESULT;
    pub type WslcSetContainerSettingsVolumesFn = unsafe extern "system" fn(
        *mut WslcContainerSettings,
        *const WslcContainerVolume,
        u32,
    ) -> HRESULT;
    pub type WslcSetContainerSettingsPortMappingsFn = unsafe extern "system" fn(
        *mut WslcContainerSettings,
        *const WslcContainerPortMapping,
        u32,
    ) -> HRESULT;
    pub type WslcSetContainerSettingsInitProcessFn =
        unsafe extern "system" fn(*mut WslcContainerSettings, *mut WslcProcessSettings) -> HRESULT;
    pub type WslcCreateContainerFn = unsafe extern "system" fn(
        WslcSession,
        *const WslcContainerSettings,
        *mut WslcContainer,
        *mut PWSTR,
    ) -> HRESULT;
    pub type WslcStartContainerFn =
        unsafe extern "system" fn(WslcContainer, WslcContainerStartFlags, *mut PWSTR) -> HRESULT;
    pub type WslcStopContainerFn =
        unsafe extern "system" fn(WslcContainer, WslcSignal, u32, *mut PWSTR) -> HRESULT;
    pub type WslcDeleteContainerFn =
        unsafe extern "system" fn(WslcContainer, WslcDeleteContainerFlags, *mut PWSTR) -> HRESULT;
    pub type WslcGetContainerInitProcessFn =
        unsafe extern "system" fn(WslcContainer, *mut WslcProcess) -> HRESULT;
    pub type WslcReleaseContainerFn = unsafe extern "system" fn(WslcContainer) -> HRESULT;
    pub type WslcCreateContainerProcessFn = unsafe extern "system" fn(
        WslcContainer,
        *mut WslcProcessSettings,
        *mut WslcProcess,
        *mut PWSTR,
    ) -> HRESULT;
    pub type WslcInitProcessSettingsFn =
        unsafe extern "system" fn(*mut WslcProcessSettings) -> HRESULT;
    pub type WslcSetProcessSettingsCmdLineFn =
        unsafe extern "system" fn(*mut WslcProcessSettings, *const PCSTR, usize) -> HRESULT;
    pub type WslcSetProcessSettingsEnvVariablesFn =
        unsafe extern "system" fn(*mut WslcProcessSettings, *const PCSTR, usize) -> HRESULT;
    pub type WslcSetProcessSettingsWorkingDirectoryFn =
        unsafe extern "system" fn(*mut WslcProcessSettings, PCSTR) -> HRESULT;
    pub type WslcSetProcessSettingsCallbacksFn = unsafe extern "system" fn(
        *mut WslcProcessSettings,
        *const WslcProcessCallbacks,
        *mut c_void,
    ) -> HRESULT;
    pub type WslcGetProcessExitEventFn =
        unsafe extern "system" fn(WslcProcess, *mut HANDLE) -> HRESULT;
    pub type WslcGetProcessExitCodeFn = unsafe extern "system" fn(WslcProcess, *mut i32) -> HRESULT;
    pub type WslcReleaseProcessFn = unsafe extern "system" fn(WslcProcess) -> HRESULT;
}

/// Runtime-loaded WSLC SDK. Holds the loaded library and resolved function pointers.
///
/// Created via `WslcSdk::load()`. The library remains loaded for the lifetime
/// of this struct. All function pointers are valid as long as `WslcSdk` is alive.
pub struct WslcSdk {
    // Keep the library alive — function pointers are only valid while it's loaded.
    _lib: libloading::Library,

    pub WslcGetMissingComponents: ffi_types::WslcGetMissingComponentsFn,
    pub WslcInitSessionSettings: ffi_types::WslcInitSessionSettingsFn,
    pub WslcSetSessionSettingsCpuCount: ffi_types::WslcSetSessionSettingsCpuCountFn,
    pub WslcSetSessionSettingsMemory: ffi_types::WslcSetSessionSettingsMemoryFn,
    pub WslcSetSessionSettingsTimeout: ffi_types::WslcSetSessionSettingsTimeoutFn,
    pub WslcSetSessionSettingsFeatureFlags: ffi_types::WslcSetSessionSettingsFeatureFlagsFn,
    pub WslcCreateSession: ffi_types::WslcCreateSessionFn,
    pub WslcTerminateSession: ffi_types::WslcTerminateSessionFn,
    pub WslcReleaseSession: ffi_types::WslcReleaseSessionFn,
    pub WslcListSessionImages: ffi_types::WslcListSessionImagesFn,
    pub WslcPullSessionImage: ffi_types::WslcPullSessionImageFn,
    pub WslcImportSessionImageFromFile: ffi_types::WslcImportSessionImageFromFileFn,
    pub WslcLoadSessionImageFromFile: ffi_types::WslcLoadSessionImageFromFileFn,
    pub WslcInitContainerSettings: ffi_types::WslcInitContainerSettingsFn,
    pub WslcSetContainerSettingsNetworkingMode: ffi_types::WslcSetContainerSettingsNetworkingModeFn,
    pub WslcSetContainerSettingsFlags: ffi_types::WslcSetContainerSettingsFlagsFn,
    pub WslcSetContainerSettingsVolumes: ffi_types::WslcSetContainerSettingsVolumesFn,
    pub WslcSetContainerSettingsPortMappings: ffi_types::WslcSetContainerSettingsPortMappingsFn,
    pub WslcSetContainerSettingsInitProcess: ffi_types::WslcSetContainerSettingsInitProcessFn,
    pub WslcCreateContainer: ffi_types::WslcCreateContainerFn,
    pub WslcStartContainer: ffi_types::WslcStartContainerFn,
    pub WslcStopContainer: ffi_types::WslcStopContainerFn,
    pub WslcDeleteContainer: ffi_types::WslcDeleteContainerFn,
    pub WslcGetContainerInitProcess: ffi_types::WslcGetContainerInitProcessFn,
    pub WslcReleaseContainer: ffi_types::WslcReleaseContainerFn,
    pub WslcCreateContainerProcess: ffi_types::WslcCreateContainerProcessFn,
    pub WslcInitProcessSettings: ffi_types::WslcInitProcessSettingsFn,
    pub WslcSetProcessSettingsCmdLine: ffi_types::WslcSetProcessSettingsCmdLineFn,
    pub WslcSetProcessSettingsEnvVariables: ffi_types::WslcSetProcessSettingsEnvVariablesFn,
    pub WslcSetProcessSettingsWorkingDirectory: ffi_types::WslcSetProcessSettingsWorkingDirectoryFn,
    pub WslcSetProcessSettingsCallbacks: ffi_types::WslcSetProcessSettingsCallbacksFn,
    pub WslcGetProcessExitEvent: ffi_types::WslcGetProcessExitEventFn,
    pub WslcGetProcessExitCode: ffi_types::WslcGetProcessExitCodeFn,
    pub WslcReleaseProcess: ffi_types::WslcReleaseProcessFn,
}

// `WslcSdk` intentionally does not implement `Send` or `Sync`.
// Cross-thread use of the runtime-loaded SDK may require additional
// guarantees (such as per-thread COM initialization) that are not enforced
// by this type.

impl WslcSdk {
    /// Load `wslcsdk.dll` at runtime and resolve all required function pointers.
    ///
    /// Loads from the same directory as the running executable to avoid DLL
    /// search-order hijacking. Returns an error if the DLL is not found or
    /// any function cannot be resolved.
    pub fn load() -> Result<Self, String> {
        unsafe {
            let dll_path = std::env::current_exe()
                .map_err(|e| format!("Failed to determine current executable path: {}", e))?
                .parent()
                .ok_or_else(|| "Failed to determine current executable directory".to_string())?
                .join("wslcsdk.dll");

            let lib = libloading::Library::new(&dll_path).map_err(|e| {
                format!(
                    "Failed to load wslcsdk.dll from {}: {}. \
                     Ensure the WSLC SDK runtime is installed or the DLL is \
                     in the same directory as the running executable.",
                    dll_path.display(),
                    e
                )
            })?;

            macro_rules! load_fn {
                ($lib:expr, $name:literal) => {{
                    let sym: libloading::Symbol<_> = $lib.get($name).map_err(|e| {
                        format!(
                            "Failed to resolve {} from wslcsdk.dll: {}",
                            stringify!($name),
                            e
                        )
                    })?;
                    *sym
                }};
            }

            Ok(Self {
                WslcGetMissingComponents: load_fn!(lib, b"WslcGetMissingComponents\0"),
                WslcInitSessionSettings: load_fn!(lib, b"WslcInitSessionSettings\0"),
                WslcSetSessionSettingsCpuCount: load_fn!(lib, b"WslcSetSessionSettingsCpuCount\0"),
                WslcSetSessionSettingsMemory: load_fn!(lib, b"WslcSetSessionSettingsMemory\0"),
                WslcSetSessionSettingsTimeout: load_fn!(lib, b"WslcSetSessionSettingsTimeout\0"),
                WslcSetSessionSettingsFeatureFlags: load_fn!(
                    lib,
                    b"WslcSetSessionSettingsFeatureFlags\0"
                ),
                WslcCreateSession: load_fn!(lib, b"WslcCreateSession\0"),
                WslcTerminateSession: load_fn!(lib, b"WslcTerminateSession\0"),
                WslcReleaseSession: load_fn!(lib, b"WslcReleaseSession\0"),
                WslcListSessionImages: load_fn!(lib, b"WslcListSessionImages\0"),
                WslcPullSessionImage: load_fn!(lib, b"WslcPullSessionImage\0"),
                WslcImportSessionImageFromFile: load_fn!(lib, b"WslcImportSessionImageFromFile\0"),
                WslcLoadSessionImageFromFile: load_fn!(lib, b"WslcLoadSessionImageFromFile\0"),
                WslcInitContainerSettings: load_fn!(lib, b"WslcInitContainerSettings\0"),
                WslcSetContainerSettingsNetworkingMode: load_fn!(
                    lib,
                    b"WslcSetContainerSettingsNetworkingMode\0"
                ),
                WslcSetContainerSettingsFlags: load_fn!(lib, b"WslcSetContainerSettingsFlags\0"),
                WslcSetContainerSettingsVolumes: load_fn!(
                    lib,
                    b"WslcSetContainerSettingsVolumes\0"
                ),
                WslcSetContainerSettingsPortMappings: load_fn!(
                    lib,
                    b"WslcSetContainerSettingsPortMappings\0"
                ),
                WslcSetContainerSettingsInitProcess: load_fn!(
                    lib,
                    b"WslcSetContainerSettingsInitProcess\0"
                ),
                WslcCreateContainer: load_fn!(lib, b"WslcCreateContainer\0"),
                WslcStartContainer: load_fn!(lib, b"WslcStartContainer\0"),
                WslcStopContainer: load_fn!(lib, b"WslcStopContainer\0"),
                WslcDeleteContainer: load_fn!(lib, b"WslcDeleteContainer\0"),
                WslcGetContainerInitProcess: load_fn!(lib, b"WslcGetContainerInitProcess\0"),
                WslcReleaseContainer: load_fn!(lib, b"WslcReleaseContainer\0"),
                WslcCreateContainerProcess: load_fn!(lib, b"WslcCreateContainerProcess\0"),
                WslcInitProcessSettings: load_fn!(lib, b"WslcInitProcessSettings\0"),
                WslcSetProcessSettingsCmdLine: load_fn!(lib, b"WslcSetProcessSettingsCmdLine\0"),
                WslcSetProcessSettingsEnvVariables: load_fn!(
                    lib,
                    b"WslcSetProcessSettingsEnvVariables\0"
                ),
                WslcSetProcessSettingsWorkingDirectory: load_fn!(
                    lib,
                    b"WslcSetProcessSettingsWorkingDirectory\0"
                ),
                WslcSetProcessSettingsCallbacks: load_fn!(
                    lib,
                    b"WslcSetProcessSettingsCallbacks\0"
                ),
                WslcGetProcessExitEvent: load_fn!(lib, b"WslcGetProcessExitEvent\0"),
                WslcGetProcessExitCode: load_fn!(lib, b"WslcGetProcessExitCode\0"),
                WslcReleaseProcess: load_fn!(lib, b"WslcReleaseProcess\0"),
                _lib: lib,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// RAII Guard types
// ---------------------------------------------------------------------------

/// RAII guard for a WSLC session handle. Terminates and releases the session on drop.
pub struct WslcSessionGuard {
    handle: WslcSession,
    terminate_fn: ffi_types::WslcTerminateSessionFn,
    release_fn: ffi_types::WslcReleaseSessionFn,
}

impl WslcSessionGuard {
    /// Create a guard from a raw session handle. The caller transfers ownership.
    ///
    /// # Safety
    /// The handle must be a valid, non-null session returned by `WslcCreateSession`.
    pub unsafe fn from_raw(
        handle: WslcSession,
        terminate_fn: ffi_types::WslcTerminateSessionFn,
        release_fn: ffi_types::WslcReleaseSessionFn,
    ) -> Self {
        debug_assert!(!handle.is_null());
        Self {
            handle,
            terminate_fn,
            release_fn,
        }
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
                eprintln!(
                    "[WSLC][debug] WslcSessionGuard dropped -- terminating and releasing session"
                );
                let _ = (self.terminate_fn)(self.handle);
                (self.release_fn)(self.handle);
            }
        }
    }
}

/// RAII guard for a WSLC container handle. Calls the release function on drop.
pub struct WslcContainerGuard {
    handle: WslcContainer,
    release_fn: ffi_types::WslcReleaseContainerFn,
}

impl WslcContainerGuard {
    /// Create a guard from a raw container handle. The caller transfers ownership.
    ///
    /// # Safety
    /// The handle must be a valid, non-null container returned by `WslcCreateContainer`.
    pub unsafe fn from_raw(
        handle: WslcContainer,
        release_fn: ffi_types::WslcReleaseContainerFn,
    ) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle, release_fn }
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
                (self.release_fn)(self.handle);
            }
        }
    }
}

/// RAII guard for a WSLC process handle. Calls the release function on drop.
pub struct WslcProcessGuard {
    handle: WslcProcess,
    release_fn: ffi_types::WslcReleaseProcessFn,
}

impl WslcProcessGuard {
    /// Create a guard from a raw process handle. The caller transfers ownership.
    ///
    /// # Safety
    /// The handle must be a valid, non-null process returned by `WslcGetContainerInitProcess`.
    pub unsafe fn from_raw(
        handle: WslcProcess,
        release_fn: ffi_types::WslcReleaseProcessFn,
    ) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle, release_fn }
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
                (self.release_fn)(self.handle);
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
    fn port_mapping_struct_layout_matches_c_header() {
        // WslcContainerPortMapping in wslcsdk.h:
        //   uint16_t windowsPort;                      // offset 0
        //   uint16_t containerPort;                    // offset 2
        //   WslcPortProtocol protocol;                 // offset 4 (u32 enum)
        //   struct sockaddr_storage* windowsAddress;   // offset 8 (pointer, 8-byte aligned)
        // Total: 16 bytes on 64-bit, 8-byte aligned because of the pointer.
        assert_eq!(mem::size_of::<WslcContainerPortMapping>(), 16);
        assert_eq!(mem::align_of::<WslcContainerPortMapping>(), 8);
        assert_eq!(WslcPortProtocol::Tcp as u32, 0);
        assert_eq!(WslcPortProtocol::Udp as u32, 1);
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
