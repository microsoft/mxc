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

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// Cached absolute path to `wpr.exe`, resolved on first use.
static WPR_PATH: OnceLock<PathBuf> = OnceLock::new();

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
