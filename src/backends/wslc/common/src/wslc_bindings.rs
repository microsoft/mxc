// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Ergonomic façade over the bindgen-generated WSLC SDK bindings.
//!
//! All ABI-defining items — opaque settings structs and their sizes, handle
//! types, enums, data structs, callback signatures, and the runtime-loaded
//! `WslcSdk` function table — are **generated** from `wslcsdk.h` by
//! [`crate::wslcsdk_sys`] (see `scripts/generate-wslc-bindings.ps1`). Struct
//! layout and function signatures are therefore derived directly from the C
//! header, so any ABI drift becomes a compile error instead of silent UB.
//!
//! This module re-exports the generated surface and adds the few things bindgen
//! cannot generate:
//! - [`WslcSdk::load`] — loads `wslcsdk.dll` from the executable's own directory
//!   (anti-hijack) on top of the generated `WslcSdk::new(path)`.
//! - RAII guard types ([`WslcSessionGuard`], [`WslcContainerGuard`],
//!   [`WslcProcessGuard`]) that release their handle on drop.
//! - [`check_hresult`] and the [`S_OK`] sentinel.

pub use crate::wslcsdk_sys::*;

/// COM success sentinel. Not declared in `wslcsdk.h`, so defined here.
pub const S_OK: HRESULT = 0;
// ---------------------------------------------------------------------------
// Raw function-pointer types used by the RAII guards.
//
// These mirror the corresponding generated `WslcSdk` fields; if the header ever
// changes a release/terminate signature, extracting the generated pointer into
// these aliases fails to compile — the drift is caught, not silently ignored.
// ---------------------------------------------------------------------------

/// `WslcTerminateSession` / `WslcReleaseSession` function-pointer type.
pub type SessionReleaseFn = unsafe extern "C" fn(WslcSession) -> HRESULT;
/// `WslcReleaseContainer` function-pointer type.
pub type ContainerReleaseFn = unsafe extern "C" fn(WslcContainer) -> HRESULT;
/// `WslcReleaseProcess` function-pointer type.
pub type ProcessReleaseFn = unsafe extern "C" fn(WslcProcess) -> HRESULT;

impl WslcComponentFlags {
    /// True if any missing-component bit is set.
    pub fn any_missing(self) -> bool {
        self.0 != 0
    }
}

// bindgen derives `Debug` for the generated newtype, which prints the raw
// tuple (e.g. `WslcComponentFlags(2)`). That is not actionable in a
// user-facing error, so the façade adds a `Display` impl (which bindgen does
// not generate) that decodes the set bits into named components. The
// `WslcGetMissingComponents` error path formats the value with `{}`.
impl core::fmt::Display for WslcComponentFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0 == 0 {
            return write!(f, "None");
        }
        let mut names = Vec::new();
        if self.0 & Self::WSLC_COMPONENT_FLAG_VIRTUAL_MACHINE_PLATFORM.0 != 0 {
            names.push("VirtualMachinePlatform");
        }
        if self.0 & Self::WSLC_COMPONENT_FLAG_WSL_PACKAGE.0 != 0 {
            names.push("WslPackage");
        }
        if self.0 & Self::WSLC_COMPONENT_FLAG_SDK_NEEDS_UPDATE.0 != 0 {
            names.push("SdkNeedsUpdate");
        }
        if names.is_empty() {
            write!(f, "Unknown(0x{:x})", self.0)
        } else {
            write!(f, "{} (0x{:x})", names.join(" | "), self.0)
        }
    }
}

impl WslcSdk {
    /// Load `wslcsdk.dll` at runtime and resolve all required function pointers.
    ///
    /// Loads from the same directory as the running executable to avoid DLL
    /// search-order hijacking. Returns an error if the DLL is not found, or if
    /// any function this crate depends on cannot be resolved.
    ///
    /// The generated `WslcSdk::new` (bindgen `--dynamic-loading`) succeeds as
    /// long as the DLL itself opens, storing each unresolved symbol as an `Err`
    /// that would otherwise only surface as a panic on first use. To fail fast
    /// against an incompatible SDK runtime (version skew), `load` additionally
    /// validates that every function actually called by this crate resolved,
    /// via [`ensure_required_symbols`](Self::ensure_required_symbols).
    pub fn load() -> Result<Self, String> {
        let dll_path = std::env::current_exe()
            .map_err(|e| format!("Failed to determine current executable path: {e}"))?
            .parent()
            .ok_or_else(|| "Failed to determine current executable directory".to_string())?
            .join("wslcsdk.dll");

        // SAFETY: loading a DLL and resolving symbols is inherently unsafe.
        let sdk = unsafe {
            Self::new(&dll_path).map_err(|e| {
                format!(
                    "Failed to load wslcsdk.dll from {}: {e}. \
                     Ensure the WSLC SDK runtime is installed or the DLL is \
                     in the same directory as the running executable.",
                    dll_path.display()
                )
            })?
        };
        sdk.ensure_required_symbols(&dll_path)?;
        Ok(sdk)
    }

    /// Verify that every SDK export this crate calls resolved during `new`.
    ///
    /// bindgen's `--dynamic-loading` defers per-symbol resolution failures to
    /// first use (a panic). This restores the old eager fail-fast behavior:
    /// if the loaded `wslcsdk.dll` is missing any function we depend on (an
    /// incompatible/older SDK runtime), return a descriptive error naming the
    /// missing exports instead of panicking later at the call site.
    ///
    /// The list below must mirror the SDK functions invoked by
    /// `wsl_container_runner.rs` and the RAII guards. Intentionally excludes
    /// header-declared functions this crate never calls, since SDK headers may
    /// declare exports ahead of what the shipping runtime implements.
    fn ensure_required_symbols(&self, dll_path: &std::path::Path) -> Result<(), String> {
        let mut missing: Vec<&'static str> = Vec::new();
        macro_rules! require {
            ($($f:ident),* $(,)?) => {
                $( if self.$f.is_err() { missing.push(stringify!($f)); } )*
            };
        }
        require!(
            WslcInitSessionSettings,
            WslcCreateSession,
            WslcSetSessionSettingsCpuCount,
            WslcSetSessionSettingsMemory,
            WslcSetSessionSettingsTimeout,
            WslcSetSessionSettingsFeatureFlags,
            WslcTerminateSession,
            WslcReleaseSession,
            WslcInitContainerSettings,
            WslcCreateContainer,
            WslcStartContainer,
            WslcSetContainerSettingsInitProcess,
            WslcSetContainerSettingsNetworkingMode,
            WslcSetContainerSettingsFlags,
            WslcSetContainerSettingsPortMappings,
            WslcSetContainerSettingsVolumes,
            WslcCreateContainerProcess,
            WslcReleaseContainer,
            WslcGetContainerInitProcess,
            WslcStopContainer,
            WslcDeleteContainer,
            WslcInitProcessSettings,
            WslcSetProcessSettingsWorkingDirectory,
            WslcSetProcessSettingsCmdLine,
            WslcSetProcessSettingsEnvVariables,
            WslcSetProcessSettingsCallbacks,
            WslcGetProcessExitEvent,
            WslcGetProcessExitCode,
            WslcReleaseProcess,
            WslcPullSessionImage,
            WslcImportSessionImageFromFile,
            WslcLoadSessionImageFromFile,
            WslcListSessionImages,
            WslcGetMissingComponents,
        );
        if missing.is_empty() {
            return Ok(());
        }
        Err(format!(
            "wslcsdk.dll at {} is missing {} required export(s): {}. \
             The installed WSLC SDK runtime is incompatible with this build \
             (expected a newer version). Update the WSL/WSLC runtime.",
            dll_path.display(),
            missing.len(),
            missing.join(", ")
        ))
    }

    /// Raw `WslcTerminateSession` pointer, for the session RAII guard.
    pub fn terminate_session_fn(&self) -> SessionReleaseFn {
        *self
            .WslcTerminateSession
            .as_ref()
            .expect("WslcTerminateSession not loaded")
    }

    /// Raw `WslcReleaseSession` pointer, for the session RAII guard.
    pub fn release_session_fn(&self) -> SessionReleaseFn {
        *self
            .WslcReleaseSession
            .as_ref()
            .expect("WslcReleaseSession not loaded")
    }

    /// Raw `WslcReleaseContainer` pointer, for the container RAII guard.
    pub fn release_container_fn(&self) -> ContainerReleaseFn {
        *self
            .WslcReleaseContainer
            .as_ref()
            .expect("WslcReleaseContainer not loaded")
    }

    /// Raw `WslcReleaseProcess` pointer, for the process RAII guard.
    pub fn release_process_fn(&self) -> ProcessReleaseFn {
        *self
            .WslcReleaseProcess
            .as_ref()
            .expect("WslcReleaseProcess not loaded")
    }
}

// ---------------------------------------------------------------------------
// RAII Guard types
// ---------------------------------------------------------------------------

/// RAII guard for a WSLC session handle. Terminates and releases the session on drop.
pub struct WslcSessionGuard {
    handle: WslcSession,
    terminate_fn: SessionReleaseFn,
    release_fn: SessionReleaseFn,
}

impl WslcSessionGuard {
    /// Create a guard from a raw session handle. The caller transfers ownership.
    ///
    /// # Safety
    /// The handle must be a valid, non-null session returned by `WslcCreateSession`.
    pub unsafe fn from_raw(
        handle: WslcSession,
        terminate_fn: SessionReleaseFn,
        release_fn: SessionReleaseFn,
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
    release_fn: ContainerReleaseFn,
}

impl WslcContainerGuard {
    /// Create a guard from a raw container handle. The caller transfers ownership.
    ///
    /// # Safety
    /// The handle must be a valid, non-null container returned by `WslcCreateContainer`.
    pub unsafe fn from_raw(handle: WslcContainer, release_fn: ContainerReleaseFn) -> Self {
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
    release_fn: ProcessReleaseFn,
}

impl WslcProcessGuard {
    /// Create a guard from a raw process handle. The caller transfers ownership.
    ///
    /// # Safety
    /// The handle must be a valid, non-null process returned by `WslcGetContainerInitProcess`.
    pub unsafe fn from_raw(handle: WslcProcess, release_fn: ProcessReleaseFn) -> Self {
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
        // These also have compile-time asserts baked into the generated
        // bindings; this is a redundant runtime sanity check.
        assert_eq!(
            mem::size_of::<WslcSessionSettings>(),
            WSLC_SESSION_OPTIONS_SIZE as usize
        );
        assert_eq!(
            mem::size_of::<WslcContainerSettings>(),
            WSLC_CONTAINER_OPTIONS_SIZE as usize
        );
        assert_eq!(
            mem::size_of::<WslcProcessSettings>(),
            WSLC_CONTAINER_PROCESS_OPTIONS_SIZE as usize
        );
    }

    #[test]
    fn enum_and_flag_values_match_c_header() {
        assert_eq!(
            WslcContainerNetworkingMode::WSLC_CONTAINER_NETWORKING_MODE_NONE.0,
            0
        );
        assert_eq!(
            WslcContainerNetworkingMode::WSLC_CONTAINER_NETWORKING_MODE_BRIDGED.0,
            1
        );
        assert_eq!(WslcPortProtocol::WSLC_PORT_PROTOCOL_TCP.0, 0);
        assert_eq!(WslcPortProtocol::WSLC_PORT_PROTOCOL_UDP.0, 1);
        assert_eq!(WslcSignal::WSLC_SIGNAL_SIGKILL.0, 9);
        assert_eq!(WslcSignal::WSLC_SIGNAL_SIGTERM.0, 15);
        assert_eq!(WslcContainerFlags::WSLC_CONTAINER_FLAG_AUTO_REMOVE.0, 1);
        assert_eq!(WslcContainerFlags::WSLC_CONTAINER_FLAG_ENABLE_GPU.0, 2);
        assert_eq!(WslcContainerFlags::WSLC_CONTAINER_FLAG_PRIVILEGED.0, 4);
        assert_eq!(
            WslcSessionFeatureFlags::WSLC_SESSION_FEATURE_FLAG_ENABLE_GPU.0,
            4
        );
    }

    #[test]
    fn bitflags_can_be_combined() {
        let flags = WslcContainerFlags::WSLC_CONTAINER_FLAG_AUTO_REMOVE
            | WslcContainerFlags::WSLC_CONTAINER_FLAG_ENABLE_GPU;
        assert_eq!(flags.0, 0x03);
    }

    #[test]
    fn component_flags_any_missing() {
        assert!(!WslcComponentFlags::WSLC_COMPONENT_FLAG_NONE.any_missing());
        assert!(WslcComponentFlags::WSLC_COMPONENT_FLAG_WSL_PACKAGE.any_missing());
    }

    #[test]
    fn component_flags_display_names_bits() {
        assert_eq!(
            WslcComponentFlags::WSLC_COMPONENT_FLAG_NONE.to_string(),
            "None"
        );
        assert_eq!(
            WslcComponentFlags::WSLC_COMPONENT_FLAG_WSL_PACKAGE.to_string(),
            "WslPackage (0x2)"
        );
        let both = WslcComponentFlags::WSLC_COMPONENT_FLAG_VIRTUAL_MACHINE_PLATFORM
            | WslcComponentFlags::WSLC_COMPONENT_FLAG_WSL_PACKAGE;
        assert_eq!(
            both.to_string(),
            "VirtualMachinePlatform | WslPackage (0x3)"
        );
        // A bit outside the known set falls back to a hex mask.
        assert_eq!(WslcComponentFlags(0x8).to_string(), "Unknown(0x8)");
    }

    #[test]
    fn check_hresult_ok_and_err() {
        assert!(check_hresult(S_OK).is_ok());
        assert!(check_hresult(-2147467259).is_err()); // E_FAIL
    }
}
