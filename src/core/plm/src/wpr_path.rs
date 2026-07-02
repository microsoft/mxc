// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Locate `wpr.exe` by absolute path.
//!
//! `Command::new("wpr")` is unsafe: on Windows it resolves via
//! `CreateProcessW`'s implicit DLL/EXE search order — and that order
//! starts with the **current working directory**. Because PLM runs as
//! administrator (required to start the NT Kernel Logger), an
//! unprivileged user who can drop a `wpr.exe` into a directory an
//! admin later runs PLM from would gain code execution as that admin.
//!
//! Reading `%SystemRoot%` from the process environment block is also
//! unsafe: UAC inherits the unelevated parent's env verbatim. A
//! standard user can `setx
//! SystemRoot=C:\\Users\\Public\\evil`, plant
//! `evil\\System32\\wpr.exe`, and the next admin-elevated
//! `wxc-exec --audit` (or any cleanup-path `wpr -cancel`) launches the
//! attacker binary as administrator — strictly worse than the
//! original CWD plant because env travels with elevation.
//!
//! This module resolves the System directory via `GetSystemDirectoryW`
//! (kernel-published, not env-spoofable) once at first call and caches
//! the result. All PLM call sites must go through `wpr_command()`
//! instead of `Command::new("wpr")` directly.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Cached absolute path to `wpr.exe`, resolved on first use.
static WPR_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Cached result of the Authenticode signature verification for
/// `WPR_PATH`. `Ok(())` means WinVerifyTrust returned success; `Err`
/// carries the human-readable reason. Cached so we pay the cert-chain
/// walk once per process (`plm log` + `plm stop` back-to-back would
/// otherwise verify twice).
#[cfg(target_os = "windows")]
static WPR_TRUST: OnceLock<Result<(), String>> = OnceLock::new();

/// Resolve `<System32>\wpr.exe` via `GetSystemDirectoryW`. The kernel
/// publishes this value at process creation and the env block cannot
/// override it, so this is safe even when the parent (unelevated)
/// process set `SystemRoot` to an attacker-controlled directory.
///
/// Falls back to `C:\\Windows\\System32\\wpr.exe` only if the API call
/// itself fails (which on a real Windows install does not happen).
#[cfg(target_os = "windows")]
fn resolve_wpr_path() -> PathBuf {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = vec![0u16; 260];
    // SAFETY: buf is initialized; we pass a valid length and own the
    // memory for the duration of the call.
    let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
    if n == 0 || (n as usize) > buf.len() {
        // API failed or buffer somehow too small: use a hardcoded
        // fallback rather than reading the env block.
        return PathBuf::from("C:\\Windows\\System32\\wpr.exe");
    }
    let dir = wxc_common::string_util::from_wide(&buf[..n as usize]);
    let mut p = PathBuf::from(dir);
    p.push("wpr.exe");
    p
}

/// Verify `path` (must be an absolute path to a signed binary) via
/// WinVerifyTrust with the generic policy. Returns `Ok(())` if the
/// binary carries a valid Authenticode signature that chains to a
/// trusted root; returns `Err(reason)` otherwise. Does NOT pin to a
/// specific publisher — callers wanting a `Microsoft`-only gate must
/// layer that on top (e.g. by cracking `WinTrust`'s signer state).
///
/// The verification opens the file with `WTD_STATEACTION_VERIFY`,
/// captures the return status, then closes with
/// `WTD_STATEACTION_CLOSE` to release the state handle regardless of
/// the outcome — required per the WinTrust docs.
#[cfg(target_os = "windows")]
fn verify_authenticode(path: &Path) -> Result<(), String> {
    use windows::core::{HSTRING, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{GetLastError, HWND};
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
        WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
        WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    let wide_path = HSTRING::from(path.as_os_str());

    let file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR::from_raw(wide_path.as_ptr()),
        hFile: Default::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &file_info as *const _ as *mut _,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: Default::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0),
        dwUIContext: WINTRUST_DATA_UICONTEXT(0),
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: WINTRUST_DATA is fully initialized; hwnd=NULL is valid
    // for headless verification (WTD_UI_NONE). File info outlives the
    // VERIFY + CLOSE calls.
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut trust_data as *mut _ as *mut _,
        )
    };

    // Always close the state handle, even on failure — required.
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _close = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut trust_data as *mut _ as *mut _,
        )
    };

    if status == 0 {
        Ok(())
    } else {
        // WinVerifyTrust returns a signed 32-bit status; render both
        // decimal + hex so an operator can look it up in the docs.
        let last = unsafe { GetLastError().0 };
        Err(format!(
            "WinVerifyTrust rejected {}: status=0x{:08x} last_error=0x{:08x}",
            path.display(),
            status as u32,
            last
        ))
    }
}

/// Verify the resolved wpr.exe carries a valid Authenticode signature.
/// Result is cached so callers can invoke this from every command
/// entry point without paying the cert-chain cost more than once.
#[cfg(target_os = "windows")]
pub fn verify_wpr_signed() -> Result<(), String> {
    let path = WPR_PATH.get_or_init(resolve_wpr_path);
    WPR_TRUST.get_or_init(|| verify_authenticode(path)).clone()
}

/// Non-Windows stub — PLM is Windows-only, but the crate builds
/// cross-platform for CI parity, so this always succeeds.
#[cfg(not(target_os = "windows"))]
pub fn verify_wpr_signed() -> Result<(), String> {
    Ok(())
}

/// Return a `Command` rooted at the absolute `wpr.exe` path. Callers
/// should still build their own `.args(...)` chain on top.
pub fn wpr_command() -> Command {
    let p = WPR_PATH.get_or_init(resolve_wpr_path);
    Command::new(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_absolute_system_directory_wpr() {
        let p = resolve_wpr_path();
        assert!(
            p.is_absolute(),
            "wpr path must be absolute: {}",
            p.display()
        );
        assert!(
            p.ends_with("wpr.exe"),
            "wpr path must end with wpr.exe: {}",
            p.display()
        );
        // The result must be under a `System32` (or `Sysnative` /
        // `SysWOW64`) directory — never under user-writable paths.
        let s = p.to_string_lossy().to_ascii_lowercase();
        assert!(
            s.contains("\\system32\\") || s.contains("\\sysnative\\") || s.contains("\\syswow64\\"),
            "wpr path must be under a system directory; got: {}",
            p.display()
        );
    }

    /// setting `SystemRoot` in the
    /// process env MUST NOT change which `wpr.exe` we resolve, because
    /// the kernel-published system directory is the source of truth.
    #[test]
    fn ignores_system_root_env_var() {
        let original = std::env::var_os("SystemRoot");
        std::env::set_var("SystemRoot", "C:\\Users\\Public\\evil");
        let p = resolve_wpr_path();
        let s = p.to_string_lossy().to_ascii_lowercase();
        assert!(
            !s.contains("public") && !s.contains("evil"),
            "resolve_wpr_path honored attacker-controlled SystemRoot: {}",
            p.display()
        );
        match original {
            Some(v) => std::env::set_var("SystemRoot", v),
            None => std::env::remove_var("SystemRoot"),
        }
    }
}
