// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SeatbeltScriptRunner` — executes scripts inside Apple's Seatbelt
//! sandbox via `/usr/bin/sandbox-exec`.
//!
//! This is the Phase A "exec mode" implementation. It generates a
//! TinyScheme profile from the [`CodexRequest`] using
//! [`crate::profile_builder::build_profile`], writes it to a tempfile in
//! `TMPDIR`, then spawns `sandbox-exec -f <profile> /bin/sh -c <script>`
//! with the request's env and working directory.
//!
//! Compiled only on macOS — the rest of the workspace continues to build
//! on Windows / Linux unchanged.

use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wxc_common::logger::Logger;
use wxc_common::models::{CodexRequest, ScriptResponse};
use wxc_common::script_runner::ScriptRunner;

use crate::profile_builder::build_profile;

/// Path to the system-provided sandbox launcher. Present on every macOS
/// release (deprecated in headers since 10.7 but still shipped through
/// current versions).
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Default shell used to execute `script_code`. `/bin/sh` is guaranteed
/// to exist and is on the SIP-protected path so it's always reachable
/// from inside the sandbox.
const DEFAULT_SHELL: &str = "/bin/sh";

pub struct SeatbeltScriptRunner;

impl SeatbeltScriptRunner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SeatbeltScriptRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptRunner for SeatbeltScriptRunner {
    fn execute(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        // 1. Build the Seatbelt profile from the policy.
        let profile = build_profile(request);

        // 2. Persist it to a tempfile so sandbox-exec can read it via -f.
        //    We use `tempfile::NamedTempFile` so the file is removed on drop
        //    even on panic.
        let mut tmp = match tempfile::Builder::new()
            .prefix("mxc-seatbelt-")
            .suffix(".sb")
            .tempfile()
        {
            Ok(t) => t,
            Err(e) => return error_response(format!("failed to create profile tempfile: {e}")),
        };

        if let Err(e) = tmp.write_all(profile.as_bytes()) {
            return error_response(format!("failed to write profile: {e}"));
        }
        if let Err(e) = tmp.flush() {
            return error_response(format!("failed to flush profile: {e}"));
        }

        let profile_path = tmp.path().to_path_buf();
        let _ = writeln!(
            logger,
            "Seatbelt: profile written to {}",
            profile_path.display()
        );

        // 3. Spawn `sandbox-exec -f <profile> /bin/sh -c <script>`.
        let mut cmd = Command::new(SANDBOX_EXEC);
        cmd.arg("-f")
            .arg(&profile_path)
            .arg(DEFAULT_SHELL)
            .arg("-c")
            .arg(&request.script_code);

        // Apply env if any was specified — otherwise inherit the parent
        // environment (matches LXC behaviour for empty env vectors).
        if !request.env.is_empty() {
            cmd.env_clear();
            for kv in &request.env {
                if let Some((k, v)) = kv.split_once('=') {
                    cmd.env(k, v);
                }
            }
        }

        if !request.working_directory.is_empty() {
            cmd.current_dir(&request.working_directory);
        }

        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return error_response(format!(
                    "failed to spawn {SANDBOX_EXEC}: {e}; ensure sandbox-exec exists"
                ))
            }
        };

        // 4. Drain stdout/stderr in background threads to avoid deadlock
        //    if the child fills the OS pipe buffer (~64KB on macOS).
        let stdout_handle = child.stdout.take().map(|r| {
            std::thread::spawn(move || read_to_string(r))
        });
        let stderr_handle = child.stderr.take().map(|r| {
            std::thread::spawn(move || read_to_string(r))
        });

        // 5. Wait with timeout. `script_timeout == 0` means infinite.
        let timeout = if request.script_timeout == 0 {
            None
        } else {
            Some(Duration::from_millis(u64::from(request.script_timeout)))
        };

        let exit_status = match wait_with_timeout(&mut child, timeout) {
            Ok(status) => status,
            Err(WaitError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                return ScriptResponse {
                    exit_code: -1,
                    standard_out: stdout_handle
                        .and_then(|h| h.join().ok())
                        .unwrap_or_default(),
                    standard_err: stderr_handle
                        .and_then(|h| h.join().ok())
                        .unwrap_or_default(),
                    error_message: format!(
                        "Seatbelt: script timed out after {}ms",
                        request.script_timeout
                    ),
                };
            }
            Err(WaitError::Io(e)) => return error_response(format!("wait failed: {e}")),
        };

        let stdout = stdout_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_default();
        let stderr = stderr_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_default();

        ScriptResponse {
            exit_code: exit_status.code().unwrap_or(-1),
            standard_out: stdout,
            standard_err: stderr,
            error_message: String::new(),
        }
    }
}

fn error_response(msg: String) -> ScriptResponse {
    ScriptResponse {
        exit_code: -1,
        standard_out: String::new(),
        standard_err: String::new(),
        error_message: msg,
    }
}

fn read_to_string<R: std::io::Read>(mut r: R) -> String {
    let mut buf = String::new();
    let _ = r.read_to_string(&mut buf);
    buf
}

enum WaitError {
    Timeout,
    Io(std::io::Error),
}

/// Wait for `child` to exit, polling at 50ms intervals if a timeout is set.
/// We avoid pulling in `tokio` here — the runner is otherwise synchronous.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Option<Duration>,
) -> Result<std::process::ExitStatus, WaitError> {
    let Some(deadline) = timeout.map(|t| Instant::now() + t) else {
        return child.wait().map_err(WaitError::Io);
    };

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return Err(WaitError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(WaitError::Io(e)),
        }
    }
}
