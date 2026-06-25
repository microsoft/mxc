//! Locate `wpr.exe` by absolute path.
//!
//! Round-4 security finding #1: every PLM caller of `wpr` previously
//! used `Command::new("wpr")`, which on Windows resolves via
//! `CreateProcessW`'s implicit DLL/EXE search order — and that order
//! starts with the **current working directory**. Because PLM runs as
//! administrator (required to start the NT Kernel Logger), an
//! unprivileged user who can drop a `wpr.exe` into a directory an
//! admin later runs PLM from would gain code execution as that admin.
//!
//! This module resolves `%SystemRoot%\System32\wpr.exe` once at first
//! call and caches the result. All PLM call sites must go through
//! `wpr_command()` instead of `Command::new("wpr")` directly.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// Cached absolute path to `wpr.exe`, resolved on first use.
static WPR_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Resolve `%SystemRoot%\System32\wpr.exe`. Falls back to plain
/// `"wpr.exe"` only when `%SystemRoot%` is unset or empty (which
/// shouldn't happen on a real Windows install) — that fallback exists
/// solely so unit tests that mock the env don't panic.
fn resolve_wpr_path() -> PathBuf {
    let system_root = std::env::var_os("SystemRoot")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| std::ffi::OsString::from("C:\\Windows"));
    let mut p = PathBuf::from(system_root);
    p.push("System32");
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
    fn resolves_under_system_root_when_set() {
        std::env::set_var("SystemRoot", "C:\\Windows");
        let p = resolve_wpr_path();
        assert!(
            p.is_absolute(),
            "wpr path must be absolute: {}",
            p.display()
        );
        assert!(
            p.ends_with("System32\\wpr.exe") || p.ends_with("System32/wpr.exe"),
            "unexpected wpr path: {}",
            p.display()
        );
    }

    #[test]
    fn falls_back_to_default_system_root_when_env_missing() {
        std::env::remove_var("SystemRoot");
        let p = resolve_wpr_path();
        assert!(p.is_absolute());
        // Default fallback is C:\Windows; just assert it starts with
        // a drive root rather than a relative path.
        let s = p.to_string_lossy();
        assert!(s.contains(":\\") || s.contains(":/"), "got: {s}");
    }
}
