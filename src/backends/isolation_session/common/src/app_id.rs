// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! App-id resolution for the isolation session backend.
//!
//! The OS Preview `AddUserAsync2` takes an app-scoped registration id
//! ("appId"). When the caller supplies one it is used verbatim; otherwise we
//! detect the Package Family Name of wxc-exec's *immediate parent* process —
//! the app that invoked MXC — and pass "PFN:<pfn>". This mirrors the OS-side
//! `ResolveRegistrationId` format so the resulting registration is identical
//! whether formed here or in the OS client DLL. An unpackaged parent (or any
//! detection failure) yields an empty appId, which lets the OS fall back to
//! its default registration.
//!
//! Note: the OS `ResolveRegistrationId` runs in-proc inside wxc-exec, so an
//! empty appId there would resolve to *wxc-exec's* own PFN — not the invoking
//! app's. Detecting the parent here, and passing a non-empty "PFN:<pfn>" that
//! the OS then uses verbatim, is what scopes the registration to the caller.

use wxc_common::process_util::OwnedHandle;

use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::Storage::Packaging::Appx::GetPackageFamilyName;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_core::PWSTR;

/// The prefix the OS uses for package-family-scoped registration ids.
const PFN_PREFIX: &str = "PFN:";

/// Resolves the appId to pass to `AddUserAsync2`.
///
/// - Non-empty `explicit` -> returned unchanged (caller opted in).
/// - Empty `explicit` -> detect the immediate parent process's Package Family
///   Name and return "PFN:<pfn>".
/// - Detection failure (unpackaged parent, PID lookup miss, OS error) ->
///   empty string (OS default registration).
pub(super) fn resolve_app_id(explicit: &str) -> String {
    if !explicit.is_empty() {
        return explicit.to_string();
    }
    match detect_parent_pfn() {
        Some(pfn) => format!("{PFN_PREFIX}{pfn}"),
        None => String::new(),
    }
}

/// Returns the Package Family Name of wxc-exec's immediate parent process, or
/// `None` if the parent is unpackaged or cannot be inspected.
fn detect_parent_pfn() -> Option<String> {
    let parent_pid = parent_process_id()?;
    // PROCESS_QUERY_LIMITED_INFORMATION is sufficient for GetPackageFamilyName
    // and is grantable across integrity levels.
    let handle =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, parent_pid) }.ok()?;
    let owned = OwnedHandle::new(handle);
    package_family_name(owned.get())
}

/// Walks a ToolHelp process snapshot to find the current process's
/// `th32ParentProcessID`. Best-effort: PID reuse can race, but this is only an
/// identity hint for registration scoping.
fn parent_process_id() -> Option<u32> {
    let current = unsafe { GetCurrentProcessId() };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.ok()?;
    let owned = OwnedHandle::new(snapshot);

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    if unsafe { Process32FirstW(owned.get(), &mut entry) }.is_err() {
        return None;
    }
    loop {
        if entry.th32ProcessID == current {
            return Some(entry.th32ParentProcessID);
        }
        if unsafe { Process32NextW(owned.get(), &mut entry) }.is_err() {
            return None;
        }
    }
}

/// Queries the Package Family Name for a process handle. `None` when the
/// process is unpackaged (`APPMODEL_ERROR_NO_PACKAGE`) or on any error.
fn package_family_name(process: HANDLE) -> Option<String> {
    // First call with a null buffer to obtain the required length. A packaged
    // process returns ERROR_INSUFFICIENT_BUFFER with `length` set; an
    // unpackaged one returns APPMODEL_ERROR_NO_PACKAGE and leaves length 0.
    let mut length: u32 = 0;
    let _ = unsafe { GetPackageFamilyName(process, &mut length, None) };
    if length == 0 {
        return None;
    }

    let mut buffer = vec![0u16; length as usize];
    let rc =
        unsafe { GetPackageFamilyName(process, &mut length, Some(PWSTR(buffer.as_mut_ptr()))) };
    if rc != ERROR_SUCCESS {
        return None;
    }

    // `length` includes the terminating null; trim at the first null.
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_app_id_is_passed_through_unchanged() {
        assert_eq!(
            resolve_app_id("PFN:Contoso.App_8wekyb3d8bbwe"),
            "PFN:Contoso.App_8wekyb3d8bbwe"
        );
        assert_eq!(resolve_app_id("my-literal-id"), "my-literal-id");
    }

    #[test]
    fn empty_explicit_resolves_via_parent_detection() {
        // Environment-dependent: the test runner's parent is typically an
        // unpackaged shell/cargo process, so this yields "". When the parent
        // *is* packaged, the value must carry the "PFN:" prefix. Either way it
        // must never panic and must be a valid (possibly empty) appId.
        let resolved = resolve_app_id("");
        if !resolved.is_empty() {
            assert!(
                resolved.starts_with(PFN_PREFIX),
                "detected appId must be PFN-prefixed, got {resolved:?}"
            );
        }
    }
}
