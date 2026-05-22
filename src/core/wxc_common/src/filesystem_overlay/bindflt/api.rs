// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BindFlt direct-API FFI surface.
//!
//! Wraps the user-mode exports from `bindfltapi.dll` (the user-mode
//! companion to `bindflt.sys`, the BindFilter kernel filter driver).
//! See `D:\os\src\onecore\base\fs\wci\inc\bindlink.h` for the public
//! API and `bindflt_pub.h` for the internal `Bf*` API.
//!
//! Phase B-1 wires the public `CreateBindLink` / `RemoveBindLink`
//! surface — sufficient for `BindFltRoOverlay` and `BindFltRwOverlay`
//! mapping primitives. The internal `Bf*` family (per-job, per-SID,
//! batched) is reserved for a follow-on if production needs the extra
//! control surface.
//!
//! # Loading discipline
//!
//! We use `LoadLibraryExW` with `LOAD_LIBRARY_SEARCH_SYSTEM32` so that:
//!
//! - On cohorts where `bindfltapi.dll` is absent (older Win10 builds
//!   before the Bind Filter shipped), `LoadLibrary` fails cleanly and
//!   we surface `PrimitiveUnavailable`.
//! - We never accidentally load a same-named DLL planted in the
//!   working directory or `PATH` — that's the "DLL planting" attack
//!   surface.
//!
//! # Concurrency
//!
//! The DLL handle and resolved entry points live in a process-wide
//! [`OnceLock`]. First call to [`BindFltApi::get`] loads + resolves;
//! subsequent calls hand out a borrowed reference. No `FreeLibrary`
//! ever fires (the handle outlives the process).

use std::sync::OnceLock;

use windows::core::{HRESULT, PCWSTR};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

use crate::filesystem_overlay::error::OverlayError;

/// `CREATE_BIND_LINK_FLAGS` from `bindlink.h`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum CreateBindLinkFlags {
    None = 0x0000_0000,
    ReadOnly = 0x0000_0001,
    Merged = 0x0000_0002,
}

/// Resolved entry points from `bindfltapi.dll`.
///
/// Function-pointer types are the C signatures from `bindlink.h`:
///
/// ```c
/// STDAPI CreateBindLink(
///     PCWSTR virtualPath,
///     PCWSTR backingPath,
///     CREATE_BIND_LINK_FLAGS flags,
///     UINT32 exceptionCount,
///     PCWSTR* exceptionPaths);
///
/// STDAPI RemoveBindLink(PCWSTR virtualPath);
/// ```
pub(crate) struct BindFltApi {
    /// Module handle for `bindfltapi.dll`. Held to keep the
    /// resolved function pointers live for the rest of the process.
    _module: HMODULE,
    pub(crate) create_bind_link: unsafe extern "system" fn(
        virtual_path: PCWSTR,
        backing_path: PCWSTR,
        flags: u32,
        exception_count: u32,
        exception_paths: *const PCWSTR,
    ) -> HRESULT,
    pub(crate) remove_bind_link: unsafe extern "system" fn(virtual_path: PCWSTR) -> HRESULT,
}

// SAFETY: `BindFltApi` is initialised once at process load and is
// then immutable. `HMODULE` is an opaque handle the kernel owns;
// shared reads from multiple threads are safe. Function pointers
// are inherently thread-safe to share.
unsafe impl Send for BindFltApi {}
unsafe impl Sync for BindFltApi {}

impl BindFltApi {
    /// Get the resolved API, loading + resolving on first call.
    /// Returns [`OverlayError::PrimitiveUnavailable`] when the DLL
    /// or any required entry point is absent.
    pub(crate) fn get() -> Result<&'static BindFltApi, OverlayError> {
        static API: OnceLock<Result<BindFltApi, String>> = OnceLock::new();
        let entry = API.get_or_init(BindFltApi::load);
        match entry {
            Ok(api) => Ok(api),
            Err(reason) => Err(OverlayError::PrimitiveUnavailable {
                primitive: "bindflt",
                reason: reason.clone(),
            }),
        }
    }

    fn load() -> Result<BindFltApi, String> {
        // SAFETY: `LoadLibraryExW` is the documented dynamic-load
        // entry point. The PCWSTR we pass is a static, NUL-terminated
        // UTF-16 string literal.
        let module = unsafe {
            // `bindfltapi.dll` as a UTF-16 NUL-terminated literal.
            let name: &[u16] = &[
                b'b' as u16,
                b'i' as u16,
                b'n' as u16,
                b'd' as u16,
                b'f' as u16,
                b'l' as u16,
                b't' as u16,
                b'a' as u16,
                b'p' as u16,
                b'i' as u16,
                b'.' as u16,
                b'd' as u16,
                b'l' as u16,
                b'l' as u16,
                0,
            ];
            LoadLibraryExW(PCWSTR(name.as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32)
                .map_err(|e| format!("LoadLibraryExW(bindfltapi.dll): {e}"))?
        };

        let create_bind_link_addr =
            resolve(module, b"CreateBindLink\0").ok_or("CreateBindLink not exported")?;
        let remove_bind_link_addr =
            resolve(module, b"RemoveBindLink\0").ok_or("RemoveBindLink not exported")?;

        // SAFETY: GetProcAddress returns either NULL or a valid
        // function pointer of the documented signature. The lifetime
        // of these pointers is tied to `module`, which we keep in
        // the returned struct (and which is in turn stored in a
        // process-static `OnceLock`).
        let create_bind_link: unsafe extern "system" fn(
            PCWSTR,
            PCWSTR,
            u32,
            u32,
            *const PCWSTR,
        ) -> HRESULT = unsafe { std::mem::transmute(create_bind_link_addr) };
        let remove_bind_link: unsafe extern "system" fn(PCWSTR) -> HRESULT =
            unsafe { std::mem::transmute(remove_bind_link_addr) };

        Ok(BindFltApi {
            _module: module,
            create_bind_link,
            remove_bind_link,
        })
    }
}

/// Resolve an exported function. `name` must be NUL-terminated ASCII.
fn resolve(module: HMODULE, name: &[u8]) -> Option<unsafe extern "system" fn() -> isize> {
    debug_assert_eq!(
        *name.last().expect("non-empty"),
        0,
        "name must be NUL-terminated"
    );
    let pcstr = windows::core::PCSTR(name.as_ptr());
    unsafe { GetProcAddress(module, pcstr) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On a host with `bindfltapi.dll` available, `BindFltApi::get`
    /// resolves cleanly. On hosts without it (older Win10), the call
    /// surfaces `PrimitiveUnavailable`. Either outcome is acceptable;
    /// the assertion is just that the call doesn't panic or hang.
    #[test]
    fn get_either_succeeds_or_reports_unavailable() {
        match BindFltApi::get() {
            Ok(api) => {
                // Function pointers are non-null on success.
                assert!(api.create_bind_link as usize != 0);
                assert!(api.remove_bind_link as usize != 0);
            }
            Err(OverlayError::PrimitiveUnavailable { primitive, reason }) => {
                assert_eq!(primitive, "bindflt");
                assert!(!reason.is_empty());
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    /// Subsequent calls return the same cached pointer (no
    /// re-loading). Mostly a smoke test for the `OnceLock` use.
    #[test]
    fn get_is_idempotent() {
        let a = BindFltApi::get();
        let b = BindFltApi::get();
        match (a, b) {
            (Ok(x), Ok(y)) => {
                assert_eq!(x.create_bind_link as usize, y.create_bind_link as usize);
            }
            (Err(_), Err(_)) => {
                // Both attempts fail consistently — acceptable.
            }
            _ => panic!("inconsistent BindFltApi::get results"),
        }
    }
}
