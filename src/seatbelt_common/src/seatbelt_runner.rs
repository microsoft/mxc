// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SeatbeltScriptRunner` — executes scripts inside Apple's Seatbelt
//! sandbox.
//!
//! The sandbox is applied via `sandbox_init()` inside `Command::pre_exec`,
//! then `/bin/sh` is exec'd directly. The child inherits the parent's
//! Mach bootstrap namespace so both CLI commands and GUI applications
//! (when `guiAccess = true`) work correctly.
//!
//! For apps that require LaunchServices (`launchMethod: "open"`), the runner
//! writes a sandbox helper script and launches the target app via `open -n -W`,
//! applying the sandbox to the command running inside the app.
//!
//! Compiled only on macOS — the rest of the workspace continues to build
//! on Windows / Linux unchanged.

use std::ffi::{CStr, CString};
use std::fmt::Write as FmtWrite;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wxc_common::logger::Logger;
use wxc_common::models::{CodexRequest, LaunchMethod, ScriptResponse};
use wxc_common::script_runner::ScriptRunner;

use crate::profile_builder::build_profile;

// ---------------------------------------------------------------------------
// FFI declarations for Apple's sandbox API (libsandbox.dylib).
//
// `sandbox_init` is declared in <sandbox.h> and marked deprecated since
// macOS 10.8, but is still shipped and used by first-party apps through
// macOS 15+.
// ---------------------------------------------------------------------------

#[link(name = "sandbox")]
extern "C" {
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        errorbuf: *mut *mut libc::c_char,
    ) -> libc::c_int;

    fn sandbox_free_error(errorbuf: *mut libc::c_char);
}

/// Default shell used to execute `script_code`. `/bin/sh` is guaranteed
/// to exist and is on the SIP-protected path so it's always reachable
/// from inside the sandbox.
const DEFAULT_SHELL: &str = "/bin/sh";

#[derive(Default)]
pub struct SeatbeltScriptRunner;

impl SeatbeltScriptRunner {
    pub fn new() -> Self {
        Self
    }
}

const POLL_INTERVAL_MS: u64 = 500;

impl ScriptRunner for SeatbeltScriptRunner {
    fn validate_runner(&self, request: &CodexRequest) -> Result<(), ScriptResponse> {
        // Seatbelt cannot filter network by hostname — reject blockedHosts
        // rather than silently allowing traffic the user expects to be denied.
        if !request.policy.blocked_hosts.is_empty() {
            return Err(error_response(
                "macOS Seatbelt does not support per-host network filtering. \
                 'blockedHosts' cannot be enforced; remove it or use \
                 defaultPolicy: \"block\" to deny all network."
                    .to_string(),
            ));
        }

        // Reject timeouts that are too small for our polling interval to
        // enforce accurately.
        if request.script_timeout > 0 && u64::from(request.script_timeout) < POLL_INTERVAL_MS {
            return Err(error_response(format!(
                "scriptTimeout {}ms is below the minimum of {}ms",
                request.script_timeout, POLL_INTERVAL_MS
            )));
        }

        Ok(())
    }

    fn execute(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        // 1. Build the Seatbelt profile from the policy.
        let profile = build_profile(request);

        // Determine launch method from seatbelt config.
        let launch_method = request
            .experimental
            .seatbelt
            .as_ref()
            .map(|s| s.launch_method.clone())
            .unwrap_or_default();

        let gui_access = request
            .experimental
            .seatbelt
            .as_ref()
            .map(|s| s.gui_access)
            .unwrap_or(false);

        match launch_method {
            LaunchMethod::Exec => self.execute_exec(&profile, request, gui_access, logger),
            LaunchMethod::Open => self.execute_open(&profile, request, logger),
        }
    }
}

impl SeatbeltScriptRunner {
    /// Standard execution path: fork → sandbox_init → exec.
    /// When `gui_access` is true, stdio is inherited for GUI app compatibility.
    fn execute_exec(
        &self,
        profile: &str,
        request: &CodexRequest,
        gui_access: bool,
        logger: &mut Logger,
    ) -> ScriptResponse {
        let mut command = match build_sandbox_command(profile, &request.script_code, logger) {
            Ok(cmd) => cmd,
            Err(resp) => return resp,
        };

        // Environment setup.
        if !request.env.is_empty() {
            command.env_clear();
            for kv in &request.env {
                if let Some((key, value)) = kv.split_once('=') {
                    command.env(key, value);
                }
            }
        }

        if !request.working_directory.is_empty() {
            command.current_dir(&request.working_directory);
        }

        if gui_access {
            // GUI apps need inherited stdio for PTY/window interaction.
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        } else {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }

        // Spawn.
        let mut child = match command.spawn() {
            Ok(process) => process,
            Err(error) => {
                return error_response(format!("failed to spawn sandboxed process: {error}"))
            }
        };

        if gui_access {
            // GUI mode: no output capture, just wait for exit.
            let timeout = if request.script_timeout == 0 {
                None
            } else {
                Some(Duration::from_millis(u64::from(request.script_timeout)))
            };

            match wait_with_timeout(&mut child, timeout) {
                Ok(status) => ScriptResponse {
                    exit_code: status.code().unwrap_or(-1),
                    standard_out: String::new(),
                    standard_err: String::new(),
                    error_message: String::new(),
                },
                Err(WaitError::Timeout) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    ScriptResponse {
                        exit_code: -1,
                        standard_out: String::new(),
                        standard_err: String::new(),
                        error_message: format!(
                            "Seatbelt: process timed out after {}ms",
                            request.script_timeout
                        ),
                    }
                }
                Err(WaitError::Io(error)) => error_response(format!("wait failed: {error}")),
            }
        } else {
            // CLI mode: capture stdout/stderr.
            let stdout_handle = child
                .stdout
                .take()
                .map(|reader| std::thread::spawn(move || read_to_string(reader)));
            let stderr_handle = child
                .stderr
                .take()
                .map(|reader| std::thread::spawn(move || read_to_string(reader)));

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
                        standard_out: join_reader("stdout", stdout_handle),
                        standard_err: join_reader("stderr", stderr_handle),
                        error_message: format!(
                            "Seatbelt: script timed out after {}ms",
                            request.script_timeout
                        ),
                    };
                }
                Err(WaitError::Io(error)) => {
                    return error_response(format!("wait failed: {error}"))
                }
            };

            let stdout = join_reader("stdout", stdout_handle);
            let stderr = join_reader("stderr", stderr_handle);

            ScriptResponse {
                exit_code: exit_status.code().unwrap_or(-1),
                standard_out: stdout,
                standard_err: stderr,
                error_message: String::new(),
            }
        }
    }

    /// LaunchServices execution path: write a sandbox helper, launch via
    /// `open -n -W`. Required for Apple system apps with Launch Constraints
    /// (e.g. Terminal.app).
    fn execute_open(
        &self,
        profile: &str,
        request: &CodexRequest,
        logger: &mut Logger,
    ) -> ScriptResponse {
        let _ = writeln!(
            logger,
            "Seatbelt: using LaunchServices (open) launch method"
        );

        // 1. Write the profile to a secure temp file.
        let profile_path = match write_secure_temp_file("mxc_sb_profile_", profile, 0o600) {
            Ok(p) => p,
            Err(e) => return error_response(format!("failed to write profile: {e}")),
        };

        // 2. Build environment exports for the helper script.
        let mut env_exports = String::new();
        for kv in &request.env {
            if let Some((key, value)) = kv.split_once('=') {
                // Shell-escape the value.
                let escaped = value.replace('\'', "'\\''");
                let _ = writeln!(env_exports, "export {key}='{escaped}'");
            }
        }

        // 3. Create the sandbox helper script.
        // This script is executed inside the terminal app. It:
        //   a) Calls sandbox-exec with the profile file to sandbox the shell
        //   b) Execs the user's command inside the sandbox
        let script_code = &request.script_code;
        let helper_content = format!(
            "#!/bin/sh\n\
             # MXC Seatbelt sandbox helper — auto-generated, do not edit.\n\
             {env_exports}\
             exec sandbox-exec -f '{profile_path}' /bin/sh -c 'clear; {script_escaped}'\n",
            profile_path = profile_path,
            script_escaped = script_code.replace('\'', "'\\''"),
        );

        let helper_path = match write_secure_temp_file("mxc_sb_helper_", &helper_content, 0o700) {
            Ok(p) => p,
            Err(e) => {
                let _ = fs::remove_file(&profile_path);
                return error_response(format!("failed to write helper script: {e}"));
            }
        };

        // 4. Create the .command file that Terminal will execute.
        let command_content = format!("#!/bin/sh\nexec '{}'\n", helper_path);
        let command_path = match write_secure_temp_file("mxc_sb_launch_", &command_content, 0o700) {
            Ok(mut p) => {
                // Rename to .command extension so Terminal recognizes it.
                let new_path = format!("{p}.command");
                if fs::rename(&p, &new_path).is_ok() {
                    p = new_path;
                }
                p
            }
            Err(e) => {
                let _ = fs::remove_file(&profile_path);
                let _ = fs::remove_file(&helper_path);
                return error_response(format!("failed to write .command file: {e}"));
            }
        };

        let _ = writeln!(logger, "Seatbelt: launching via: open -n -W {command_path}");

        // 5. Launch via `open -n -W`.
        let mut child = match Command::new("open")
            .args(["-n", "-W", "-a", "Terminal", &command_path])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                cleanup_files(&[&profile_path, &helper_path, &command_path]);
                return error_response(format!("failed to launch via open: {e}"));
            }
        };

        // 6. Wait for the terminal to close.
        let timeout = if request.script_timeout == 0 {
            None
        } else {
            Some(Duration::from_millis(u64::from(request.script_timeout)))
        };

        let result = match wait_with_timeout(&mut child, timeout) {
            Ok(status) => ScriptResponse {
                exit_code: status.code().unwrap_or(-1),
                standard_out: String::new(),
                standard_err: String::new(),
                error_message: String::new(),
            },
            Err(WaitError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                ScriptResponse {
                    exit_code: -1,
                    standard_out: String::new(),
                    standard_err: String::new(),
                    error_message: format!(
                        "Seatbelt: terminal timed out after {}ms",
                        request.script_timeout
                    ),
                }
            }
            Err(WaitError::Io(error)) => error_response(format!("wait failed: {error}")),
        };

        // 7. Cleanup temp files.
        cleanup_files(&[&profile_path, &helper_path, &command_path]);

        result
    }
}

/// Build a `Command` that applies the sandbox via `sandbox_init()` in
/// `pre_exec`, then execs `/bin/sh -c <script>`. The child inherits the
/// parent's Mach bootstrap namespace, so both CLI and GUI applications
/// work correctly under the sandbox.
///
/// # Safety
///
/// `pre_exec` runs between `fork()` and `exec()`. We limit operations
/// inside it to a single FFI call (`sandbox_init`) with pre-allocated
/// arguments. `sandbox_init` is not formally async-signal-safe but is
/// used in this pattern by Chromium and other production macOS sandboxes.
fn build_sandbox_command(
    profile: &str,
    script_code: &str,
    logger: &mut Logger,
) -> Result<Command, ScriptResponse> {
    let profile_cstr = CString::new(profile)
        .map_err(|e| error_response(format!("seatbelt profile contains embedded NUL byte: {e}")))?;

    let _ = writeln!(logger, "Seatbelt: applying sandbox via sandbox_init");

    let mut command = Command::new(DEFAULT_SHELL);
    command.arg("-c").arg(script_code);

    // SAFETY: The closure runs after fork(), before exec(). We only call
    // sandbox_init with a pre-allocated CString — no Rust allocations
    // happen inside the closure. sandbox_init is used in this fork+exec
    // pattern by Chromium and other production macOS software.
    unsafe {
        command.pre_exec(move || {
            let mut errorbuf: *mut libc::c_char = std::ptr::null_mut();
            let rc = sandbox_init(profile_cstr.as_ptr(), 0, &mut errorbuf);
            if rc != 0 {
                // Extract error message using only libc calls (no allocation).
                if !errorbuf.is_null() {
                    let msg = CStr::from_ptr(errorbuf);
                    let bytes = msg.to_bytes();
                    // Write directly to stderr fd — no Rust allocation.
                    let prefix = b"Seatbelt: sandbox_init failed: ";
                    libc::write(2, prefix.as_ptr().cast(), prefix.len());
                    libc::write(2, bytes.as_ptr().cast(), bytes.len());
                    libc::write(2, b"\n".as_ptr().cast(), 1);
                    sandbox_free_error(errorbuf);
                }
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        });
    }

    Ok(command)
}

fn error_response(message: String) -> ScriptResponse {
    ScriptResponse {
        exit_code: -1,
        standard_out: String::new(),
        standard_err: String::new(),
        error_message: message,
    }
}

/// Reads all bytes from `r` into a String. Returns whatever was captured
/// even if the read fails partway (e.g. broken pipe from a killed child).
fn read_to_string<R: std::io::Read>(mut reader: R) -> (String, Option<std::io::Error>) {
    let mut buffer = String::new();
    match reader.read_to_string(&mut buffer) {
        Ok(_) => (buffer, None),
        Err(error) => (buffer, Some(error)),
    }
}

fn join_reader(
    name: &str,
    handle: Option<std::thread::JoinHandle<(String, Option<std::io::Error>)>>,
) -> String {
    match handle {
        Some(h) => match h.join() {
            Ok((output, None)) => output,
            Ok((output, Some(error))) => {
                eprintln!(
                    "Seatbelt: warning: failed to read child {}: {}",
                    name, error
                );
                output
            }
            Err(_) => {
                eprintln!("Seatbelt: warning: child {} reader thread panicked", name);
                String::new()
            }
        },
        None => String::new(),
    }
}

enum WaitError {
    Timeout,
    Io(std::io::Error),
}

/// Wait for `child` to exit, polling at `POLL_INTERVAL_MS` intervals if a
/// timeout is set. We poll manually rather than adding an async runtime
/// dependency since the runner is otherwise synchronous.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Option<Duration>,
) -> Result<std::process::ExitStatus, WaitError> {
    let Some(deadline) = timeout.map(|duration| Instant::now() + duration) else {
        return child.wait().map_err(WaitError::Io);
    };

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return Err(WaitError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
            }
            Err(error) => return Err(WaitError::Io(error)),
        }
    }
}

/// Write `content` to a temp file with randomized name and the given
/// permissions mode. Returns the absolute path on success.
fn write_secure_temp_file(
    prefix: &str,
    content: &str,
    mode: u32,
) -> Result<String, std::io::Error> {
    use std::io::Write;

    let dir = std::env::temp_dir();
    let random: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64
        ^ std::process::id() as u64;
    let path = dir.join(format!("{prefix}{random:016x}"));
    let path_str = path.to_string_lossy().to_string();

    let mut file = fs::File::create(&path)?;
    file.write_all(content.as_bytes())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;

    Ok(path_str)
}

/// Remove a list of temp files, ignoring errors.
fn cleanup_files(paths: &[&str]) {
    for path in paths {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{CodexRequest, SeatbeltConfig};

    fn base_request() -> CodexRequest {
        let mut request = CodexRequest::default();
        request.experimental_enabled = true;
        request.experimental.seatbelt = Some(SeatbeltConfig::default());
        request
    }

    #[test]
    fn rejects_blocked_hosts() {
        let mut request = base_request();
        request.policy.blocked_hosts = vec!["evil.example.com".into()];
        let runner = SeatbeltScriptRunner::new();
        let response = runner.validate_runner(&request).unwrap_err();
        assert_eq!(response.exit_code, -1);
        assert!(response.error_message.contains("blockedHosts"));
        assert!(response.error_message.contains("cannot be enforced"));
    }
}
