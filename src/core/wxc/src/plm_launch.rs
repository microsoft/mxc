// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Elevated spawn of `plm.exe` from unelevated `wxc-exec --audit`.
//!
//! `plm.exe` carries a `requireAdministrator` application manifest
//! (see `src/host/plm/build.rs`). A standard `std::process::Command`
//! spawn from an unelevated parent fails with
//! `ERROR_ELEVATION_REQUIRED` (740) — the OS refuses to load such a
//! binary except via a UAC-mediated launch. This module wraps that
//! launch using `ShellExecuteExW` with the `runas` verb, waits for
//! the elevated child to exit, and surfaces its exit code + any
//! diagnostic output the child wrote to file-capture paths passed via
//! env.
//!
//! Windows-only.

use std::env;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, HANDLE, WAIT_FAILED};
use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

/// `SW_SHOWNORMAL` from `Win32_UI_WindowsAndMessaging`. Copied as a
/// literal to avoid pulling in that whole feature for one constant.
const SW_SHOWNORMAL: i32 = 1;

/// Result of an elevated `plm.exe` invocation.
pub struct ElevatedRun {
    /// Exit code of the elevated child.
    pub exit_code: i32,
    /// Captured stdout, empty if the caller didn't request capture.
    pub stdout: Vec<u8>,
    /// Captured stderr, empty if the caller didn't request capture.
    pub stderr: Vec<u8>,
}

fn to_wide<S: AsRef<std::ffi::OsStr>>(s: S) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// Quote a single argument using CommandLineToArgvW rules.
fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"', '\n']) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let chars: Vec<char> = arg.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let mut backslashes = 0;
        while i < chars.len() && chars[i] == '\\' {
            backslashes += 1;
            i += 1;
        }
        if i == chars.len() {
            for _ in 0..(backslashes * 2) {
                out.push('\\');
            }
        } else if chars[i] == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            i += 1;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            out.push(chars[i]);
            i += 1;
        }
    }
    out.push('"');
    out
}

/// Invoke `plm_path <args...>` elevated via `ShellExecuteExW` + `runas`,
/// wait for it to exit, and return its exit code + captured stdio.
///
/// Because `ShellExecuteExW` cannot inherit stdio pipes across the
/// elevation boundary, the elevated child is asked to redirect its own
/// stdout/stderr to two temp files via `MXC_PLM_STDOUT_FILE` /
/// `MXC_PLM_STDERR_FILE`. We create the files, publish the env vars on
/// *this* process (elevated child inherits our env by default), launch,
/// read the files back, and clean up.
///
/// Any additional env vars in `extra_env` are set on *this* process
/// before the launch (and unset after) so the elevated child inherits
/// them too. This is how the `SINGLETON_HELD_BY_PARENT_ENV` bypass
/// flag gets to the child under UAC.
pub fn run_plm_elevated(
    plm_path: &Path,
    args: &[&std::ffi::OsStr],
    extra_env: &[(&str, &str)],
) -> Result<ElevatedRun, String> {
    // Build a temp directory for the two capture files. Using a
    // per-invocation directory + fixed filenames keeps cleanup simple
    // and avoids two `TempPath`s.
    let tmp_dir = env::temp_dir().join(format!("mxc-plm-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let stdout_path = tmp_dir.join("stdout.log");
    let stderr_path = tmp_dir.join("stderr.log");
    // Truncate any pre-existing content.
    let _ = std::fs::write(&stdout_path, b"");
    let _ = std::fs::write(&stderr_path, b"");

    // Publish env vars on the current process for inheritance. We save
    // any prior values and restore them via `EnvGuard::drop` so a
    // concurrent thread reading the env can't observe a permanent
    // change (and so nested / repeat calls don't accumulate leftovers).
    let mut guards: Vec<EnvGuard> = Vec::with_capacity(2 + extra_env.len());
    guards.push(EnvGuard::set(
        "MXC_PLM_STDOUT_FILE",
        stdout_path.as_os_str(),
    ));
    guards.push(EnvGuard::set(
        "MXC_PLM_STDERR_FILE",
        stderr_path.as_os_str(),
    ));
    for (k, v) in extra_env {
        guards.push(EnvGuard::set(k, v.as_ref()));
    }

    // Build the parameter string ShellExecuteExW expects.
    let params_str: String = args
        .iter()
        .map(|a| quote_arg(&a.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ");

    let verb_w = to_wide("runas");
    let file_w = to_wide(plm_path.as_os_str());
    let params_w = to_wide(&params_str);
    let cwd_w = to_wide(
        env::current_dir()
            .map(PathBuf::into_os_string)
            .unwrap_or_default(),
    );

    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb_w.as_ptr()),
        lpFile: PCWSTR(file_w.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        lpDirectory: PCWSTR(cwd_w.as_ptr()),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };

    let result = unsafe { ShellExecuteExW(&mut sei) };
    // Drop guards early so the env change window is minimized. The
    // elevated child has already inherited its snapshot.
    drop(guards);

    if let Err(e) = result {
        let raw = (e.code().0 as u32) & 0xFFFF;
        if raw == ERROR_CANCELLED.0 {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err("UAC prompt was cancelled".to_string());
        }
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(format!("ShellExecuteExW failed: {e}"));
    }

    let proc_handle: HANDLE = sei.hProcess;
    if proc_handle.is_invalid() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err("ShellExecuteExW returned no process handle".to_string());
    }

    let wait = unsafe { WaitForSingleObject(proc_handle, INFINITE) };
    if wait == WAIT_FAILED {
        unsafe {
            let _ = CloseHandle(proc_handle);
        }
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err("WaitForSingleObject failed on elevated plm child".to_string());
    }
    let mut exit_code: u32 = 0;
    let rc = unsafe { GetExitCodeProcess(proc_handle, &mut exit_code) };
    unsafe {
        let _ = CloseHandle(proc_handle);
    }
    if rc.is_err() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err("GetExitCodeProcess failed on elevated plm child".to_string());
    }

    let stdout = std::fs::read(&stdout_path).unwrap_or_default();
    let stderr = std::fs::read(&stderr_path).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&tmp_dir);

    Ok(ElevatedRun {
        exit_code: exit_code as i32,
        stdout,
        stderr,
    })
}

/// RAII scope-guard for setting a process env var and restoring the
/// prior value on drop. Prevents env vars from leaking past the
/// ShellExecute call so nested / repeat invocations don't accumulate
/// state and concurrent env readers don't observe permanent changes.
struct EnvGuard {
    key: String,
    prior: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(key: &str, value: &std::ffi::OsStr) -> Self {
        let prior = env::var_os(key);
        env::set_var(key, value);
        EnvGuard {
            key: key.to_string(),
            prior,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prior {
            Some(v) => env::set_var(&self.key, v),
            None => env::remove_var(&self.key),
        }
    }
}
