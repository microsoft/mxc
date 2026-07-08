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
//!
//! We do **not** call `WinVerifyTrust` on the resolved `wpr.exe`.
//! System binaries under `%SystemDirectory%` are typically
//! catalog-signed (`.cat` files in `CatRoot\`) rather than
//! embedded-signed, so `WinVerifyTrust` with the generic file policy
//! returns `TRUST_E_NOSIGNATURE` (0x800B0100) on stock Windows
//! installs. Correctly verifying a catalog-signed binary requires the
//! `CryptCATAdmin*` fallback dance, and even then the trust boundary
//! it would enforce is "the file under `System32\\wpr.exe` was placed
//! there by an entity Windows trusts". Because we resolve that path
//! via `GetSystemDirectoryW` (not an attacker-controllable env var),
//! and any write to `%SystemDirectory%` requires `TrustedInstaller`
//! (or SYSTEM) — a strictly higher privilege than the admin
//! elevation PLM already runs at — the path resolution itself is our
//! security boundary. We keep `verify_wpr_present` as a thin sanity
//! check that the binary actually exists at the resolved path.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// Cached absolute path to `wpr.exe`, resolved on first use.
static WPR_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Resolve `<System32>\wpr.exe` via `GetSystemDirectoryW`. The kernel
/// publishes this value at process creation and the env block cannot
/// override it, so this is safe even when the parent (unelevated)
/// process set `SystemRoot` to an attacker-controlled directory.
///
/// If `GetSystemDirectoryW` reports the initial 260-wide buffer is
/// insufficient (return value `>= buf.len()`, per Win32 semantics),
/// we retry once with the required size. Only if the API returns 0
/// (a Win32 failure, which does not happen on a real Windows install)
/// do we surface `None` to the caller.
#[cfg(target_os = "windows")]
fn resolve_wpr_path() -> Option<PathBuf> {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buf = vec![0u16; 260];
    // SAFETY: buf is initialized; we pass a valid length and own the
    // memory for the duration of the call.
    let mut n = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
    if n == 0 {
        return None;
    }
    // Per docs: on success `n` is the length WITHOUT the terminating
    // NUL and is strictly less than the buffer size. If `n` is >=
    // buffer size, the buffer was too small and `n` is the required
    // size INCLUDING the NUL — grow and retry once.
    if (n as usize) >= buf.len() {
        buf = vec![0u16; n as usize];
        n = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
        if n == 0 || (n as usize) >= buf.len() {
            return None;
        }
    }
    let dir = wxc_common::string_util::from_wide(&buf[..n as usize]);
    let mut p = PathBuf::from(dir);
    p.push("wpr.exe");
    Some(p)
}

/// Sanity-check that the resolved `wpr.exe` actually exists on disk.
///
/// The real security guarantee comes from `resolve_wpr_path`
/// (`GetSystemDirectoryW`, not env-spoofable) plus the OS
/// `TrustedInstaller`-only ACL on `%SystemDirectory%\\wpr.exe` — an
/// attacker who can plant a binary there has already escalated past
/// the admin token PLM runs under, so an in-process signature check
/// would be defence against a strictly higher privilege than the one
/// we hold. See the module doc for the full rationale.
///
/// Returns `Err` if `GetSystemDirectoryW` failed outright, or if the
/// resolved path doesn't exist on disk — both indicate a
/// broken/stripped Windows install (WPT not present or `System32`
/// unreadable), which the caller must surface with a clear message
/// rather than let `CreateProcess` fail cryptically later.
#[cfg(target_os = "windows")]
pub fn verify_wpr_present() -> Result<(), String> {
    let slot = WPR_PATH.get_or_init(resolve_wpr_path);
    let path = slot
        .as_ref()
        .ok_or_else(|| "GetSystemDirectoryW failed; cannot locate wpr.exe".to_string())?;
    if !path.is_file() {
        return Err(format!(
            "wpr.exe not found at {} — install the Windows Performance Toolkit \
             (part of the Windows ADK) and retry",
            path.display()
        ));
    }
    Ok(())
}

/// Non-Windows stub — PLM is Windows-only, but the crate builds
/// cross-platform for CI parity, so this always succeeds.
#[cfg(not(target_os = "windows"))]
pub fn verify_wpr_present() -> Result<(), String> {
    Ok(())
}

/// Return a `Command` rooted at the absolute `wpr.exe` path. Callers
/// should still build their own `.args(...)` chain on top.
///
/// Assumes `verify_wpr_present` has already been called and succeeded
/// (which cached the resolved path). If `GetSystemDirectoryW` failed
/// at first-call time, we fall back to a bare `wpr.exe` argument so
/// `CreateProcess` produces a clear "not found" error — the caller
/// should have surfaced the `verify_wpr_present` failure before
/// getting here.
pub fn wpr_command() -> Command {
    let slot = WPR_PATH.get_or_init(resolve_wpr_path);
    let mut cmd = match slot {
        Some(p) => Command::new(p),
        None => Command::new("wpr.exe"),
    };
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_absolute_system_directory_wpr() {
        let p = resolve_wpr_path().expect("GetSystemDirectoryW should succeed on Windows CI");
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
        let p = resolve_wpr_path().expect("GetSystemDirectoryW should succeed on Windows CI");
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
