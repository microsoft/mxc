// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Step 1a — detect whether `Client-ProjFS` is usable on this host.
//!
//! `Client-ProjFS` is an *optional* Windows feature, off by default on most
//! SKUs. Enabling it is an admin one-time step:
//!
//!   Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS
//!
//! The probe runs as a normal user, so we can't query the optional-feature
//! API directly without elevation. We instead answer the *usable* question
//! the same way our future runtime code will: `LoadLibraryW` the user-mode
//! library and `GetProcAddress` the entry point we'd actually call. If both
//! succeed we treat the feature as usable; if either fails we report the
//! Win32 error and bail out of later steps.
//!
//! This is also robust against the case where someone has the DLL on disk
//! but the kernel minifilter is not running — `PrjStartVirtualizing` itself
//! will surface that later as `PRJ_ERR_VIRTUALIZATION_UNAVAILABLE`, which
//! step 1c reports separately.

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

/// Outcome of the feature-detect step. Serialized into the JSON report.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct FeatureDetect {
    /// True if `ProjectedFSLib.dll` loaded *and* every required export resolved.
    pub usable: bool,
    /// True if the DLL loaded at all (i.e. the optional feature has placed
    /// the binary in System32). May be true while `usable` is false on
    /// truly broken installs.
    pub dll_loaded: bool,
    /// Win32 last-error from `LoadLibraryExW`, if the load failed.
    pub load_error: Option<u32>,
    /// Per-export resolution: name -> resolved? Empty if the DLL did not load.
    pub exports: Vec<ExportResolution>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ExportResolution {
    pub name: String,
    pub resolved: bool,
}

impl FeatureDetect {
    pub fn is_usable(&self) -> bool {
        self.usable
    }

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

pub(crate) fn detect() -> FeatureDetect {
    // Load via LOAD_LIBRARY_SEARCH_SYSTEM32 so we cannot be tricked into
    // picking up a planted DLL in CWD or PATH.
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

    // Release the reference — actual usage will reload the symbols via the
    // `windows` crate's import library at runtime. The OS will keep the DLL
    // mapped if needed.
    let _ = unsafe { FreeLibrary(module) };

    FeatureDetect {
        usable: all_resolved,
        dll_loaded: true,
        load_error: None,
        exports,
    }
}
