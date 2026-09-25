// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows API-set contract helpers.

use windows::Win32::System::WindowsProgramming::IsApiSetImplemented;
use windows_core::PCSTR;

/// Whether Windows implements the named API-set contract.
#[must_use]
pub fn is_api_set_implemented(name: &core::ffi::CStr) -> bool {
    // SAFETY: `CStr` guarantees that `name` is null-terminated.
    unsafe { IsApiSetImplemented(PCSTR(name.as_ptr().cast())).as_bool() }
}
