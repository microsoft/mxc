// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Elevated spawn of `plm.exe` from unelevated `wxc-exec --audit`.
//!
//! **Invariant: `wxc-exec.exe` itself never runs elevated.** It ships
//! without a `requireAdministrator` manifest and is expected to be
//! launched by an unelevated (medium-integrity) user. Any operation
//! that legitimately needs admin — currently only the PLM audit-trace
//! WPR/ETW session — is delegated to a dedicated admin-manifested
//! helper binary (`plm.exe`), which we spawn via UAC and wait on.
//! This matches the pattern used by `wxc-host-prep.exe` for the
//! system-drive / null-device ACL work.
//!
//! `plm.exe` carries a `requireAdministrator` application manifest
//! (see `src/host/plm/build.rs`). A standard `std::process::Command`
//! spawn from an unelevated parent fails with
//! `ERROR_ELEVATION_REQUIRED` (740) — the OS refuses to load such a
//! binary except via a UAC-mediated launch. This module wraps that
//! launch using `ShellExecuteExW` with the `runas` verb, waits for
//! the elevated child to exit, and surfaces its exit code + any
//! diagnostic output the child captured to files in a random-suffix
//! temp directory whose path is passed on the command line (the
//! elevation broker does not propagate env vars or stdio handles
//! across the elevation boundary, so both signals must ride on
//! `lpParameters`).
//!
//! Windows-only.

use std::env;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, HANDLE, WAIT_FAILED, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

/// `SW_SHOWNORMAL` from `Win32_UI_WindowsAndMessaging`. Copied as a
/// literal to avoid pulling in that whole feature for one constant.
const SW_SHOWNORMAL: i32 = 1;

/// Maximum time to wait for an elevated `plm.exe` child to exit
/// before giving up and returning an error. Chosen to be well beyond
/// the wall-clock cost of `plm start` / `plm stop` (which are
/// dominated by `wpr.exe` invocations that complete in a few seconds)
/// while still avoiding an unbounded hang if the child wedges (e.g.
/// waiting on a stuck WPR kernel session).
///
/// Note: 30 s may be too short if `plm stop` has to merge a
/// multi-GB ETL. PLM is intended to be run against a single
/// end-to-end flow or unit test at a time, so traces should stay
/// well under that bound in the supported usage. If a real-world
/// workload trips this timeout, revisit the bound (or switch to a
/// Ctrl-C-driven cancel) rather than raising it blindly.
const PLM_ELEVATED_WAIT_MS: u32 = 30_000;

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
/// The elevation broker (AppInfo service) creates the elevated child
/// with a fresh environment block and no inheritable stdio handles,
/// so we cannot use env vars to hand off the capture-file paths or
/// the singleton-held bypass. Both signals travel as hidden CLI
/// arguments the child parses out (see `redirect_stdio_from_argv`
/// and the `--wxc-singleton-held-by-parent` handling in plm's
/// `main`).
///
/// `singleton_held_by_parent = true` tells the elevated child that
/// the caller already holds the `Global\Mxc_Plm_Audit` mutex and it
/// should skip acquisition; without this the child bails with
/// "another PLM trace is already in progress".
pub fn run_plm_elevated(
    plm_path: &Path,
    args: &[&std::ffi::OsStr],
    singleton_held_by_parent: bool,
) -> Result<ElevatedRun, String> {
    // Build a temp directory for the two capture files. Uses a
    // random-suffix `tempfile::Builder::tempdir` (not a
    // deterministic `%TEMP%\mxc-plm-<pid>`) so a same-user medium-IL
    // attacker cannot pre-squat the directory or its contents before
    // the elevated child (running under the admin token) opens files
    // inside it. `tempdir` fails if the directory already exists —
    // treat that failure as fatal rather than silently reusing an
    // attacker-controlled path.
    //
    // We deliberately do NOT wrap this in a `TempDir` RAII guard:
    // the elevated child writes into the dir long after this
    // function's stack frame is gone, and we need the paths to
    // survive across the `WaitForSingleObject`. We clean up
    // explicitly on every exit path via `remove_dir_all(&tmp_dir)`.
    let tmp_dir = match tempfile::Builder::new()
        .prefix("mxc-plm-")
        .rand_bytes(16)
        .tempdir()
    {
        Ok(td) => td.keep(),
        Err(e) => return Err(format!("failed to create plm capture temp dir: {e}")),
    };
    let stdout_path = tmp_dir.join("stdout.log");
    let stderr_path = tmp_dir.join("stderr.log");
    // No pre-truncation: the elevated child creates the files
    // itself with `create_new(true).append(true)`, which fails with
    // `ERROR_FILE_EXISTS` if anything (regular file, symlink,
    // junction) already occupies the path. Any parent-side
    // pre-write here would defeat that check by materialising the
    // target as a plain file first — either turning a legitimate
    // capture into `ERROR_FILE_EXISTS`, or (worse) having the
    // unelevated parent follow an attacker-planted symlink before
    // the elevated child ever runs.

    // Build the parameter string ShellExecuteExW expects. Prepend the
    // internal handshake flags before the subcommand args so clap
    // parses them as top-level Cli options. `--wxc-capture-dir` and
    // `--wxc-singleton-held-by-parent` are hidden `#[arg]`s on Cli.
    let mut param_parts: Vec<String> = Vec::with_capacity(args.len() + 3);
    param_parts.push("--wxc-capture-dir".to_string());
    param_parts.push(quote_arg(&tmp_dir.to_string_lossy()));
    if singleton_held_by_parent {
        param_parts.push("--wxc-singleton-held-by-parent".to_string());
    }
    for a in args {
        param_parts.push(quote_arg(&a.to_string_lossy()));
    }
    let params_str = param_parts.join(" ");

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

    let wait = unsafe { WaitForSingleObject(proc_handle, PLM_ELEVATED_WAIT_MS) };
    if wait == WAIT_FAILED {
        unsafe {
            let _ = CloseHandle(proc_handle);
        }
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err("WaitForSingleObject failed on elevated plm child".to_string());
    }
    if wait == WAIT_TIMEOUT {
        // Kill the orphaned elevated child so it can't finish
        // `wpr -start` (or -stop) behind our back and leave the WPR
        // kernel logger session alive with nothing tracking it.
        // `TerminateProcess` is best-effort; the handle carries
        // PROCESS_TERMINATE from `ShellExecuteExW`, but we ignore
        // the result either way so cleanup continues.
        unsafe {
            let _ = TerminateProcess(proc_handle, 1);
            let _ = CloseHandle(proc_handle);
        }
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(format!(
            "elevated plm child did not exit within {}s",
            PLM_ELEVATED_WAIT_MS / 1000
        ));
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
