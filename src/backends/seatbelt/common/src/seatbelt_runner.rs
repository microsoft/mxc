// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SeatbeltScriptRunner` — executes scripts inside Apple's Seatbelt
//! sandbox.
//!
//! The sandbox is applied via `sandbox_init()` inside `Command::pre_exec`,
//! then `/bin/sh` is exec'd directly. The child inherits the parent's
//! Mach bootstrap namespace so both CLI commands and GUI applications
//! (when `guiAccess = true`) work correctly. The exec path uses
//! [`mxc_pty::run_with_pty`] so the inner shell sees a real TTY and the
//! host can stream its output as it arrives.
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
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use mxc_pty::{run_with_pty, PtyOptions, PtyOutcome};
use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, FailurePhase, LaunchMethod, ScriptResponse};
use wxc_common::sandbox_process::{SandboxProcess, StreamingRunner};
use wxc_common::script_runner::ScriptRunner;
use wxc_common::validator::validate_common;

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
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
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

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        // 1. Build the Seatbelt profile from the policy.
        let profile = match build_profile(request) {
            Ok(p) => p,
            Err(e) => {
                return ScriptResponse {
                    exit_code: -1,
                    standard_out: String::new(),
                    standard_err: String::new(),
                    error_message: e,
                    ..Default::default()
                }
            }
        };

        // Determine launch method from seatbelt config.
        let launch_method = request
            .seatbelt
            .as_ref()
            .map(|s| s.launch_method.clone())
            .unwrap_or_default();

        let gui_access = request
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
        request: &ExecutionRequest,
        gui_access: bool,
        logger: &mut Logger,
    ) -> ScriptResponse {
        let mut command = match build_sandbox_command(profile, &request.script_code, false, logger)
        {
            Ok(cmd) => cmd,
            Err(resp) => return resp,
        };

        // Environment setup. Always start from a cleared environment so
        // untrusted sandboxed code never inherits the host's env.
        apply_clean_environment(&mut command, request);

        // Working directory. Also export `PWD` to match so the child's
        // `getcwd()` uses its fast `$PWD` path (a single stat) instead of
        // walking parent directories the sandbox may not let it read — which
        // otherwise leaks "getcwd: ... Operation not permitted" to stderr.
        let cwd = resolve_working_directory(request);
        command.current_dir(&cwd);
        command.env("PWD", &cwd);

        if gui_access {
            // GUI apps need inherited stdio for window interaction.
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());

            // Spawn manually — run_with_pty is not appropriate for GUI mode.
            let mut child = match command.spawn() {
                Ok(process) => process,
                Err(error) => return error_response(spawn_error(&error)),
            };

            let timeout = if request.script_timeout == 0 {
                None
            } else {
                Some(Duration::from_millis(u64::from(request.script_timeout)))
            };

            match wait_with_timeout(&mut child, timeout) {
                Ok(status) => {
                    exit_response(status.code().unwrap_or(-1), String::new(), String::new())
                }
                Err(WaitError::Timeout) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    timeout_response(format!(
                        "Seatbelt: process timed out after {}ms",
                        request.script_timeout
                    ))
                }
                Err(WaitError::Io(error)) => error_response(format!("wait failed: {error}")),
            }
        } else if request.capture_output {
            // Library / no-pty mode: capture stdout/stderr into the response
            // instead of streaming through a pty. Mirrors the bubblewrap
            // runner's piped-capture model. Used by the `mxc` library crate.
            //
            // Rebuild as a session leader so a timeout can group-kill the whole
            // tree: otherwise a surviving descendant holding the stdout/stderr
            // pipe write-end would keep the capture drain from ever seeing EOF,
            // hanging the call despite the timeout.
            let mut command =
                match build_sandbox_command(profile, &request.script_code, true, logger) {
                    Ok(cmd) => cmd,
                    Err(resp) => return resp,
                };
            apply_clean_environment(&mut command, request);
            command.current_dir(&cwd);
            command.env("PWD", &cwd);
            self.execute_captured(command, request)
        } else {
            // CLI mode: hand off to the shared PTY bridge so the inner shell
            // sees a real TTY and the host can stream output as it arrives.
            let timeout = if request.script_timeout == 0 {
                None
            } else {
                Some(Duration::from_millis(u64::from(request.script_timeout)))
            };

            let options = PtyOptions {
                timeout,
                ..PtyOptions::default()
            };

            match run_with_pty(command, options) {
                Ok(PtyOutcome::Exited(status)) => {
                    exit_response(status.code().unwrap_or(-1), String::new(), String::new())
                }
                Ok(PtyOutcome::TimedOut) => {
                    let msg = format!(
                        "Seatbelt: script timed out after {}ms",
                        request.script_timeout
                    );
                    let _ = writeln!(logger, "{msg}");
                    timeout_response(msg)
                }
                Err(error) => error_response(format!("Seatbelt: {error}")),
            }
        }
    }

    /// No-pty captured execution path. Spawns the sandboxed `/bin/sh -c`
    /// with piped stdout/stderr, drains both on background threads to avoid
    /// pipe-buffer deadlock, and returns the captured output in the
    /// [`ScriptResponse`]. Used when `request.capture_output` is set (the
    /// `mxc` library path); the interactive CLI path keeps the pty bridge.
    fn execute_captured(&self, mut command: Command, request: &ExecutionRequest) -> ScriptResponse {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match command.spawn() {
            Ok(process) => process,
            Err(error) => return error_response(spawn_error(&error)),
        };

        let stdout_handle = child
            .stdout
            .take()
            .map(|r| std::thread::spawn(move || read_to_string(r)));
        let stderr_handle = child
            .stderr
            .take()
            .map(|r| std::thread::spawn(move || read_to_string(r)));

        let timeout = if request.script_timeout == 0 {
            None
        } else {
            Some(Duration::from_millis(u64::from(request.script_timeout)))
        };

        match wait_with_timeout(&mut child, timeout) {
            Ok(status) => exit_response(
                status.code().unwrap_or(-1),
                join_reader(stdout_handle),
                join_reader(stderr_handle),
            ),
            Err(WaitError::Timeout) => {
                // Group-kill (the child is a session leader) so a surviving
                // descendant can't hold the pipe open and block the drains.
                let _ = group_kill_child(&mut child);
                let _ = child.wait();
                ScriptResponse {
                    exit_code: -1,
                    standard_out: join_reader(stdout_handle),
                    standard_err: join_reader(stderr_handle),
                    error_message: format!(
                        "Seatbelt: script timed out after {}ms",
                        request.script_timeout
                    ),
                    failure_phase: FailurePhase::Timeout,
                    ..Default::default()
                }
            }
            Err(WaitError::Io(error)) => error_response(format!("wait failed: {error}")),
        }
    }

    /// LaunchServices execution path: write a sandbox helper, launch via
    /// `open -n -W`. Required for Apple system apps with Launch Constraints
    /// (e.g. Terminal.app).
    fn execute_open(
        &self,
        profile: &str,
        request: &ExecutionRequest,
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
                // Validate key is a safe shell identifier to prevent injection.
                if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    || key.is_empty()
                    || key.starts_with(|c: char| c.is_ascii_digit())
                {
                    continue; // Skip invalid env var names
                }
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
             exec /usr/bin/sandbox-exec -f '{profile_path}' /bin/sh -c 'clear; {script_escaped}'\n",
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
            Ok(p) => {
                // Rename to .command extension so Terminal recognizes it.
                let new_path = format!("{p}.command");
                if let Err(e) = fs::rename(&p, &new_path) {
                    let _ = fs::remove_file(&p);
                    let _ = fs::remove_file(&profile_path);
                    let _ = fs::remove_file(&helper_path);
                    return error_response(format!("failed to rename to .command: {e}"));
                }
                new_path
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
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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
            Ok(status) => exit_response(status.code().unwrap_or(-1), String::new(), String::new()),
            Err(WaitError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                timeout_response(format!(
                    "Seatbelt: terminal timed out after {}ms",
                    request.script_timeout
                ))
            }
            Err(WaitError::Io(error)) => error_response(format!("wait failed: {error}")),
        };

        // 7. Cleanup temp files.
        cleanup_files(&[&profile_path, &helper_path, &command_path]);

        result
    }
}

impl StreamingRunner for SeatbeltScriptRunner {
    fn spawn_streaming(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        // Mirror the validation `ScriptRunner::run` performs before executing.
        validate_common(request)?;
        self.validate_runner(request)?;

        // Streaming requires the standard exec path: the LaunchServices
        // (`open`) and GUI-stdio modes do not expose the child's pipes.
        let launch_method = request
            .seatbelt
            .as_ref()
            .map(|s| s.launch_method.clone())
            .unwrap_or_default();
        if launch_method != LaunchMethod::Exec {
            return Err(error_response(
                "Seatbelt streaming requires launchMethod 'exec'".to_string(),
            ));
        }
        if request
            .seatbelt
            .as_ref()
            .map(|s| s.gui_access)
            .unwrap_or(false)
        {
            return Err(error_response(
                "Seatbelt streaming is not supported with guiAccess".to_string(),
            ));
        }

        let profile = match build_profile(request) {
            Ok(p) => p,
            Err(e) => return Err(error_response(e)),
        };

        let mut command = build_sandbox_command(&profile, &request.script_code, true, logger)?;

        apply_clean_environment(&mut command, request);
        let cwd = resolve_working_directory(request);
        command.current_dir(&cwd);
        command.env("PWD", &cwd);

        // Bidirectional stdio over ordinary pipes (no pty).
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match command.spawn() {
            Ok(process) => process,
            Err(error) => return Err(error_response(spawn_error(&error))),
        };

        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let timeout = if request.script_timeout == 0 {
            None
        } else {
            Some(Duration::from_millis(u64::from(request.script_timeout)))
        };

        Ok(Box::new(SeatbeltSandboxProcess {
            child,
            stdin,
            stdout,
            stderr,
            timeout,
        }))
    }
}

/// Grace period between `SIGTERM` and `SIGKILL` in [`SandboxProcess::kill`].
const KILL_GRACE: Duration = Duration::from_secs(2);

/// Process-tree kill for a child spawned as a session leader (`setsid()`, so
/// its pgid equals its pid): graceful `SIGTERM` to the whole process group,
/// then a `SIGKILL` sweep of the group after [`KILL_GRACE`]. Signalling the
/// negative pid targets only that group — never the host's — and is a no-op if
/// the child has already exited. Shared by the streaming handle's `kill()` and
/// the no-pty capture path's timeout branch.
///
/// The final `SIGKILL` is sent unconditionally, even once the leader has
/// exited: it sweeps any descendant that was forked around the `SIGTERM` (so it
/// never received it) and would otherwise survive — leaving a later `wait()` to
/// block for that descendant's full runtime. While such a descendant exists it
/// keeps the group alive, so the pgid is still valid and unambiguous; if none
/// remains the sweep is a harmless `ESRCH`.
fn group_kill_child(child: &mut std::process::Child) -> std::io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    let pgid = child.id() as libc::pid_t;
    unsafe {
        libc::kill(-pgid, libc::SIGTERM);
    }
    let deadline = Instant::now() + KILL_GRACE;
    loop {
        if child.try_wait()?.is_some() || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    Ok(())
}

/// A running Seatbelt-sandboxed process (exec mode), exposing its pipes,
/// kill, and wait. See [`SandboxProcess`] for the streaming contract.
struct SeatbeltSandboxProcess {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
    timeout: Option<Duration>,
}

impl SandboxProcess for SeatbeltSandboxProcess {
    fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
        self.stdin
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Write + Send>)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        self.stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        self.stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        Ok(self
            .child
            .try_wait()?
            .map(|status| status.code().unwrap_or(-1)))
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        group_kill_child(&mut self.child)
    }

    fn wait(&mut self) -> ScriptResponse {
        // Close our copy of any not-taken stdin so the child sees EOF and is
        // not blocked waiting for input the caller never intends to send.
        self.stdin.take();

        // Drain any not-taken stdout/stderr concurrently (taken streams are
        // the caller's responsibility and are reported empty here).
        let stdout_handle = self
            .stdout
            .take()
            .map(|r| std::thread::spawn(move || read_to_string(r)));
        let stderr_handle = self
            .stderr
            .take()
            .map(|r| std::thread::spawn(move || read_to_string(r)));

        match wait_with_timeout(&mut self.child, self.timeout) {
            Ok(status) => exit_response(
                status.code().unwrap_or(-1),
                join_reader(stdout_handle),
                join_reader(stderr_handle),
            ),
            Err(WaitError::Timeout) => {
                // Group-kill (SIGTERM→SIGKILL) so sandboxed descendants are
                // reaped too — `self.child.kill()` would orphan them; then
                // wait to clear the zombie.
                let _ = self.kill();
                let _ = self.child.wait();
                ScriptResponse {
                    exit_code: -1,
                    standard_out: join_reader(stdout_handle),
                    standard_err: join_reader(stderr_handle),
                    error_message: "Seatbelt: process timed out".to_string(),
                    failure_phase: FailurePhase::Timeout,
                    ..Default::default()
                }
            }
            Err(WaitError::Io(error)) => {
                // The child may still be running: kill+reap it (don't orphan
                // the sandbox) and join the drains before returning.
                let _ = self.kill();
                let _ = self.child.wait();
                let _ = join_reader(stdout_handle);
                let _ = join_reader(stderr_handle);
                error_response(format!("wait failed: {error}"))
            }
        }
    }
}

impl Drop for SeatbeltSandboxProcess {
    fn drop(&mut self) {
        // Don't leak a running sandboxed process (and its group) or a zombie if
        // the handle is dropped without `wait()`. `kill()` is idempotent (its
        // `try_wait` guard no-ops once the child has exited), and the group
        // signal reaps descendants too.
        let _ = self.kill();
        let _ = self.child.wait();
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
    new_session: bool,
    logger: &mut Logger,
) -> Result<Command, ScriptResponse> {
    let profile_cstr = CString::new(profile)
        .map_err(|e| error_response(format!("seatbelt profile contains embedded NUL byte: {e}")))?;

    let _ = writeln!(logger, "Seatbelt: applying sandbox via sandbox_init");

    let mut command = Command::new(DEFAULT_SHELL);
    command.arg("-c").arg(script_code);

    // When requested (streaming path), put the child in its own session /
    // process group via `setsid()` so a caller can tree-kill it with a single
    // `killpg` without touching the host's process group. This runs before
    // `sandbox_init` so the detach happens regardless of the profile.
    //
    // SAFETY: `setsid` is async-signal-safe and runs after fork(), before
    // exec(); the child is not a process-group leader at this point, so it
    // succeeds. Failure is non-fatal (the caller's negative-pid kill simply
    // targets a group that does not exist).
    if new_session {
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

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
        error_message: message,
        ..Default::default()
    }
}

/// A `ScriptResponse` for a timed-out run with no captured output (the GUI,
/// CLI/pty, and LaunchServices paths). Paths that capture stdout/stderr build
/// the response inline so they can attach it.
fn timeout_response(message: String) -> ScriptResponse {
    ScriptResponse {
        exit_code: -1,
        error_message: message,
        failure_phase: FailurePhase::Timeout,
        ..Default::default()
    }
}

/// Message for a `Command::spawn` failure, calling out the likely cause
/// (`sandbox_init` rejecting the profile) when the OS reports a permission
/// error.
fn spawn_error(error: &std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        format!(
            "failed to spawn sandboxed process (sandbox_init likely rejected \
             the profile — check stderr for details): {error}"
        )
    } else {
        format!("failed to spawn sandboxed process: {error}")
    }
}

/// Build a `ScriptResponse` for a process that actually ran, tagging
/// [`FailurePhase::ProcessExited`] on a non-zero exit (and
/// [`FailurePhase::None`] on success) so callers can distinguish a launch
/// failure from a process that ran and failed.
fn exit_response(exit_code: i32, standard_out: String, standard_err: String) -> ScriptResponse {
    ScriptResponse {
        exit_code,
        standard_out,
        standard_err,
        failure_phase: if exit_code == 0 {
            FailurePhase::None
        } else {
            FailurePhase::ProcessExited
        },
        ..Default::default()
    }
}

/// Resolve the working directory for the sandboxed child.
///
/// An explicit `working_directory` always wins. Otherwise — rather than
/// inheriting the host process's cwd, which under the deny-by-default Seatbelt
/// profile may be inaccessible and make `getcwd()` fail (leaking a
/// "getcwd: ... Operation not permitted" line on the child's stderr) — we pick
/// a directory the profile is guaranteed to allow: the first readwrite path,
/// else the first readonly path, else `/` (always readable per the baseline).
fn resolve_working_directory(request: &ExecutionRequest) -> String {
    if !request.working_directory.is_empty() {
        return request.working_directory.clone();
    }
    request
        .policy
        .readwrite_paths
        .first()
        .or_else(|| request.policy.readonly_paths.first())
        .cloned()
        .unwrap_or_else(|| "/".to_string())
}

/// Read a child pipe to a `String`, capped and UTF-8-lossy (shared bounded
/// drain). Keeps reading past the cap so the child never blocks, and replaces
/// invalid UTF-8 rather than discarding the stream.
fn read_to_string<R: std::io::Read>(reader: R) -> String {
    wxc_common::capture_io::read_capped_lossy(reader)
}

/// Baseline `PATH` for the sandboxed child. We always start from a cleared
/// environment (so the host process's env — cloud creds, API tokens — never
/// leaks into untrusted sandboxed code), which means we must supply a default
/// `PATH` for the `/bin/sh` wrapper and common tools to resolve.
const DEFAULT_SANDBOX_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Populate `command`'s environment from a cleared baseline: never inherit the
/// host environment (matching the bubblewrap `--clearenv` and AppContainer
/// clean-block behaviour). Sets a default `PATH`, then the request's vars
/// (which may override `PATH`). `PWD` is set separately alongside the cwd.
fn apply_clean_environment(command: &mut Command, request: &ExecutionRequest) {
    command.env_clear();
    command.env("PATH", DEFAULT_SANDBOX_PATH);
    for kv in &request.env {
        if let Some((key, value)) = kv.split_once('=') {
            command.env(key, value);
        }
    }
}

/// Join a drain thread, returning its captured output (empty on join failure
/// or when no pipe was present).
fn join_reader(handle: Option<std::thread::JoinHandle<String>>) -> String {
    match handle {
        Some(h) => h.join().unwrap_or_default(),
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

/// Write `content` to a temp file with a cryptographically random name and the
/// given permissions mode. Uses `O_CREAT | O_EXCL` (create_new) to avoid
/// symlink-following and collisions, and sets permissions immediately after
/// creation on the open file descriptor to close the TOCTOU window.
fn write_secure_temp_file(
    prefix: &str,
    content: &str,
    mode: u32,
) -> Result<String, std::io::Error> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = std::env::temp_dir();

    // Retry loop in case of (unlikely) collision with create_new.
    for _ in 0..8 {
        let random: u64 = {
            // Use /dev/urandom for unpredictable temp names.
            let mut buf = [0u8; 8];
            let mut f = fs::File::open("/dev/urandom")?;
            std::io::Read::read_exact(&mut f, &mut buf)?;
            u64::from_ne_bytes(buf)
        };
        let path = dir.join(format!("{prefix}{random:016x}"));

        match fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL: fail if exists, no symlink follow
            .mode(mode) // Set permissions atomically at creation
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(content.as_bytes())?;
                return Ok(path.to_string_lossy().to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "failed to create unique temp file after 8 attempts",
    ))
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
    use wxc_common::models::{ExecutionRequest, SeatbeltConfig};

    #[allow(clippy::field_reassign_with_default)]
    fn base_request() -> ExecutionRequest {
        let mut request = ExecutionRequest::default();
        request.experimental_enabled = true;
        request.seatbelt = Some(SeatbeltConfig::default());
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

    #[test]
    fn write_secure_temp_file_sets_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = write_secure_temp_file("mxc_test_", "hello", 0o700).unwrap();
        let meta = fs::metadata(&path).unwrap();
        // Verify permissions (mask with 0o777 to ignore setuid/sticky bits)
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        // Verify content
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn write_secure_temp_file_no_collisions() {
        let mut paths = Vec::new();
        for _ in 0..10 {
            let path = write_secure_temp_file("mxc_collision_test_", "data", 0o600).unwrap();
            assert!(!paths.contains(&path), "collision detected: {path}");
            paths.push(path);
        }
        for p in &paths {
            let _ = fs::remove_file(p);
        }
    }
}
