// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Detect whether `Client-ProjFS` is usable on this host.
//!
//! Promoted from `wxc_projfs_probe::feature_detect` in Phase D-1.
//! Used by [`crate::fallback_detector::detect`] to decide whether
//! the `AppContainerOverlay` tier is selectable.
//!
//! `Client-ProjFS` is an *optional* Windows feature, off by default
//! on most SKUs. Enabling it is an admin one-time step:
//!
//! ```text
//!   Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS
//! ```
//!
//! The probe runs as a normal user, so we can't query the
//! optional-feature API directly without elevation. We instead
//! answer the *usable* question the way the runtime path will:
//! `LoadLibraryExW` (with `LOAD_LIBRARY_SEARCH_SYSTEM32` for DLL
//! planting hardening) the user-mode library and `GetProcAddress`
//! each required entry. If both succeed we treat the feature as
//! usable; if either fails we report the Win32 error.

use std::ffi::CString;

use serde::Serialize;

use windows::core::PCSTR;
use windows::Win32::Foundation::{FreeLibrary, GetLastError, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

const PROJFS_DLL: &str = "ProjectedFSLib.dll";
const REQUIRED_EXPORTS: &[&str] = &[
    "PrjStartVirtualizing",
    "PrjStopVirtualizing",
    "PrjMarkDirectoryAsPlaceholder",
    "PrjWritePlaceholderInfo",
    "PrjWriteFileData",
    "PrjFillDirEntryBuffer",
];

/// Outcome of the feature-detect step.
#[derive(Debug, Clone, Serialize)]
pub struct FeatureDetect {
    /// True if `ProjectedFSLib.dll` loaded *and* every required
    /// export resolved.
    pub usable: bool,
    /// True if the DLL loaded at all. May be true while `usable` is
    /// false on truly broken installs.
    pub dll_loaded: bool,
    /// Win32 last-error from `LoadLibraryExW`, if the load failed.
    pub load_error: Option<u32>,
    /// Per-export resolution.
    pub exports: Vec<ExportResolution>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportResolution {
    pub name: String,
    pub resolved: bool,
}

impl FeatureDetect {
    /// Quick yes/no probe for `fallback_detector` consumption.
    pub fn is_usable(&self) -> bool {
        self.usable
    }

    /// Human-readable summary suitable for the
    /// `Overlay tier rejected:` diagnostic in the detector's
    /// warnings list.
    pub fn summary(&self) -> String {
        if self.usable {
            "Client-ProjFS appears usable (all required exports resolved)".to_string()
        } else if self.dll_loaded {
            let missing: Vec<&str> = self
                .exports
                .iter()
                .filter(|e| !e.resolved)
                .map(|e| e.name.as_str())
                .collect();
            format!(
                "ProjectedFSLib.dll loaded but exports missing: {}",
                missing.join(", ")
            )
        } else {
            format!(
                "ProjectedFSLib.dll did not load (Win32 error {})",
                self.load_error.unwrap_or(0)
            )
        }
    }
}

/// Probe `ProjectedFSLib.dll`. Stateless; safe to call from any
/// thread; safe to call repeatedly (each call reloads + releases).
pub fn detect() -> FeatureDetect {
    // Load via LOAD_LIBRARY_SEARCH_SYSTEM32 so we cannot be tricked
    // into picking up a planted DLL in CWD or PATH.
    let wide: Vec<u16> = PROJFS_DLL
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let pcwstr = windows::core::PCWSTR(wide.as_ptr());

    let module: HMODULE =
        match unsafe { LoadLibraryExW(pcwstr, None, LOAD_LIBRARY_SEARCH_SYSTEM32) } {
            Ok(m) => m,
            Err(_) => {
                let code = unsafe { GetLastError().0 };
                return FeatureDetect {
                    usable: false,
                    dll_loaded: false,
                    load_error: Some(code),
                    exports: vec![],
                };
            }
        };

    let mut exports = Vec::with_capacity(REQUIRED_EXPORTS.len());
    let mut all_resolved = true;
    for name in REQUIRED_EXPORTS {
        let cname = CString::new(*name).expect("static ASCII");
        let proc = unsafe { GetProcAddress(module, PCSTR(cname.as_ptr() as *const u8)) };
        let resolved = proc.is_some();
        if !resolved {
            all_resolved = false;
        }
        exports.push(ExportResolution {
            name: (*name).to_string(),
            resolved,
        });
    }

    // Release the reference — actual usage will reload the symbols
    // via the `windows` crate's import-lib path at runtime. The OS
    // keeps the DLL mapped while there are any references.
    let _ = unsafe { FreeLibrary(module) };

    FeatureDetect {
        usable: all_resolved,
        dll_loaded: true,
        load_error: None,
        exports,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_usable_or_explains() {
        let r = detect();
        if r.usable {
            assert!(r.dll_loaded);
            assert!(r.exports.iter().all(|e| e.resolved));
        } else {
            // Either the DLL didn't load, or one or more required
            // exports is missing. Both are possible on older
            // cohorts; either way, `summary()` must be non-empty.
            assert!(!r.summary().is_empty());
        }
    }
}
