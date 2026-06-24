// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SeatbeltScriptRunner` — executes scripts inside Apple's Seatbelt
//! sandbox.
//!
//! The sandbox is applied via `sandbox_init()` inside `Command::pre_exec`,
//! then `/bin/sh` is exec'd directly. The child inherits the parent's
//! Mach bootstrap namespace so both CLI commands and GUI applications
//! (when `guiAccess = true`) work correctly. The exec path returns a
//! `SandboxProcess` whose stdio follows the requested `StdioMode`:
//! `Inherit` gives the child the host's own stdio (a real TTY when the
//! binary runs under a pty), while `Pipes` exposes stdout/stderr/stdin
//! handles the caller can stream.
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
use std::time::Duration;

use wxc_common::interruptible_reader::{wrap_pipe, InterruptibleReader, ReadCanceller};
use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, LaunchMethod, ScriptResponse};
use wxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, group_kill, spawn_discard, take_boxed_read,
    take_boxed_write, wait_with_timeout, SandboxBackend, SandboxProcess, StdioMode, StreamCloser,
    WaitError,
};
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

impl SandboxBackend for SeatbeltScriptRunner {
    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
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

        Ok(())
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        validate_common(request)?;
        self.validate(request)?;

        // Build the Seatbelt profile from the policy.
        let profile = build_profile(request).map_err(error_response)?;

        // Determine launch method + GUI access from the seatbelt config.
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
            LaunchMethod::Exec => spawn_exec(&profile, request, gui_access, stdio, logger),
            LaunchMethod::Open => spawn_open(&profile, request, stdio, logger),
        }
    }
}

/// Exec launch path: fork → sandbox_init → exec `/bin/sh -c <script>`. With
/// [`StdioMode::Pipes`] the child gets pipes and leads its own session (so the
/// caller can tree-terminate via the process group); with
/// [`StdioMode::Inherit`] it inherits the process's stdio (a TTY when the
/// binary has one) and stays in the binary's session. `gui_access` apps require
/// inherited stdio and cannot stream.
fn spawn_exec(
    profile: &str,
    request: &ExecutionRequest,
    gui_access: bool,
    stdio: StdioMode,
    logger: &mut Logger,
) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
    if gui_access && stdio == StdioMode::Pipes {
        return Err(error_response(
            "Seatbelt guiAccess requires inherited stdio and cannot stream over pipes".to_string(),
        ));
    }

    // Pipes → own session (setsid) so a process-group tree-kill never touches
    // the host. Inherit/GUI → keep the binary's session and controlling
    // terminal so the child sees a TTY exactly when the binary does.
    let new_session = stdio == StdioMode::Pipes;
    // Inherit mode with a finite timeout: put the child in its own process group
    // (same session, so it keeps the controlling terminal) so the timeout branch
    // can tree-kill its descendants instead of only the direct `/bin/sh`. A
    // backgrounded group reading the inherited TTY can be SIGTTIN-stopped, so
    // this is limited to timeout-bounded runs, which are inherently
    // non-interactive.
    let new_group = stdio == StdioMode::Inherit && timeout_from(request).is_some();
    let mut command = build_sandbox_command(
        profile,
        &request.script_code,
        new_session,
        new_group,
        logger,
    )?;

    // Always start from a cleared environment so untrusted sandboxed code never
    // inherits the host's env.
    apply_clean_environment(&mut command, request);

    // Working directory. Also export `PWD` so the child's `getcwd()` uses its
    // fast `$PWD` path (a single stat) instead of walking parent directories
    // the sandbox may not let it read — which otherwise leaks
    // "getcwd: ... Operation not permitted" to stderr.
    let cwd = resolve_working_directory(request);
    command.current_dir(&cwd);
    command.env("PWD", &cwd);

    match stdio {
        StdioMode::Pipes => {
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }
        StdioMode::Inherit => {
            // The child inherits the binary's stdio directly (a TTY when the
            // binary has one) — no separate pty bridge.
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        }
    }

    let mut child = command
        .spawn()
        .map_err(|error| error_response(spawn_error(&error)))?;

    let (stdin, stdout, stderr) = match stdio {
        StdioMode::Pipes => (child.stdin.take(), child.stdout.take(), child.stderr.take()),
        StdioMode::Inherit => (None, None, None),
    };

    // Wrap the pipe reads so the caller can abandon a stream a backgrounded
    // descendant is holding open (see `SandboxProcess::stdout_closer`), without
    // killing the child. On failure, don't orphan the already-spawned sandboxed
    // process — kill and reap it before returning the error.
    let (stdout, stdout_canceller, stderr, stderr_canceller) =
        match (wrap_pipe(stdout), wrap_pipe(stderr)) {
            (Ok((out, out_canceller)), Ok((err, err_canceller))) => {
                (out, out_canceller, err, err_canceller)
            }
            (out_result, err_result) => {
                let _ = child.kill();
                let _ = child.wait();
                let error = out_result.err().or(err_result.err());
                return Err(error_response(format!(
                    "Seatbelt: failed to wrap stdio pipes: {}",
                    error.map_or_else(|| "unknown error".to_string(), |e| e.to_string()),
                )));
            }
        };

    Ok(Box::new(SeatbeltSandboxProcess {
        child,
        stdin,
        stdout,
        stderr,
        stdout_canceller,
        stderr_canceller,
        timeout: timeout_from(request),
        group: new_session || new_group,
        cleanup: Vec::new(),
    }))
}

/// LaunchServices launch path: write a sandbox helper + `.command` file and run
/// it in Terminal.app via `open -n -W`. Required for Apple system apps with
/// Launch Constraints (e.g. Terminal.app). The sandboxed shell runs inside
/// Terminal, not as our child, so there are no pipes to stream — only the
/// `open -W` waiter — and [`StdioMode::Pipes`] is rejected.
fn spawn_open(
    profile: &str,
    request: &ExecutionRequest,
    stdio: StdioMode,
    logger: &mut Logger,
) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
    if stdio == StdioMode::Pipes {
        return Err(error_response(
            "Seatbelt launchMethod 'open' launches Terminal.app and cannot stream over pipes"
                .to_string(),
        ));
    }

    let _ = writeln!(
        logger,
        "Seatbelt: using LaunchServices (open) launch method"
    );

    // 1. Write the profile to a secure temp file.
    let profile_path = match write_secure_temp_file("mxc_sb_profile_", profile, 0o600) {
        Ok(p) => p,
        Err(e) => return Err(error_response(format!("failed to write profile: {e}"))),
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
            return Err(error_response(format!(
                "failed to write helper script: {e}"
            )));
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
                return Err(error_response(format!("failed to rename to .command: {e}")));
            }
            new_path
        }
        Err(e) => {
            let _ = fs::remove_file(&profile_path);
            let _ = fs::remove_file(&helper_path);
            return Err(error_response(format!(
                "failed to write .command file: {e}"
            )));
        }
    };

    let _ = writeln!(logger, "Seatbelt: launching via: open -n -W {command_path}");

    // 5. Launch via `open -n -W`.
    let child = match Command::new("open")
        .args(["-n", "-W", "-a", "Terminal", &command_path])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            cleanup_files(&[&profile_path, &helper_path, &command_path]);
            return Err(error_response(format!("failed to launch via open: {e}")));
        }
    };

    // The `open -W` process is the thing to wait on; the sandboxed shell runs
    // inside Terminal. No streamable stdio; the temp files are removed once the
    // handle's `wait()` (or drop) runs.
    Ok(Box::new(SeatbeltSandboxProcess {
        child,
        stdin: None,
        stdout: None,
        stderr: None,
        stdout_canceller: None,
        stderr_canceller: None,
        timeout: timeout_from(request),
        group: false,
        cleanup: vec![profile_path, helper_path, command_path],
    }))
}

/// A running Seatbelt-sandboxed process: the child plus, for the pipes path,
/// its parent-side pipe ends. See [`SandboxProcess`] for the contract.
struct SeatbeltSandboxProcess {
    child: std::process::Child,
    /// Pipe ends — `Some` only for [`StdioMode::Pipes`]; `None` for inherited
    /// stdio / Open mode (the streams are the binary's own, or detached). The
    /// reads are wrapped so they can be cancelled out-of-band (see the
    /// `*_canceller` fields).
    stdin: Option<std::process::ChildStdin>,
    stdout: Option<InterruptibleReader>,
    stderr: Option<InterruptibleReader>,
    /// Cancellers for the stdout/stderr reads (`Some` alongside the pipe ends),
    /// kept so [`stdout_closer`](SandboxProcess::stdout_closer) /
    /// [`stderr_closer`](SandboxProcess::stderr_closer) can mint closers even
    /// after the stream has been taken.
    stdout_canceller: Option<ReadCanceller>,
    stderr_canceller: Option<ReadCanceller>,
    timeout: Option<Duration>,
    /// The child leads its own process group (`setsid`), so termination signals
    /// the whole group; `false` for inherited / Open mode (a single process).
    group: bool,
    /// Temp files to remove once the child exits (Open mode); empty otherwise.
    cleanup: Vec<String>,
}

impl SeatbeltSandboxProcess {
    /// Remove the Open-mode temp files (profile / helper / `.command`) once the
    /// child has exited. Idempotent — drains `cleanup` — so it is safe to call
    /// from both `wait()` and `drop`.
    fn run_cleanup(&mut self) {
        if self.cleanup.is_empty() {
            return;
        }
        let files = std::mem::take(&mut self.cleanup);
        let refs: Vec<&str> = files.iter().map(String::as_str).collect();
        cleanup_files(&refs);
    }
}

impl SandboxProcess for SeatbeltSandboxProcess {
    fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
        take_boxed_write(&mut self.stdin)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        take_boxed_read(&mut self.stdout)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        take_boxed_read(&mut self.stderr)
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stdout_canceller)
    }

    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stderr_canceller)
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
        // No-op once the child has exited and been reaped: its pid/pgid can be
        // recycled, so signaling it could hit an unrelated process (group). A
        // reaped `Child` returns its cached status here without a syscall.
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }
        if self.group {
            // The child leads its own process group — signal the whole group so
            // sandboxed descendants are terminated too.
            group_kill(&mut self.child)
        } else {
            // Inherited / Open mode: a single process sharing the binary's
            // process group, so signal just it (a group-kill would hit the
            // binary itself).
            self.child.kill()
        }
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        // Close our copy of any not-taken stdin so the child sees EOF and is
        // not blocked waiting for input the caller never intends to send.
        self.stdin.take();

        // Drain (and discard) any not-taken stdout/stderr concurrently so the
        // child can't block on a full pipe (taken streams are the caller's
        // responsibility).
        let stdout_thread = spawn_discard(self.stdout.take());
        let stderr_thread = spawn_discard(self.stderr.take());

        let result = match wait_with_timeout(&mut self.child, self.timeout) {
            Ok(status) => Ok(status.code().unwrap_or(-1)),
            Err(WaitError::Timeout) => {
                // Timed out — terminate now (`kill()` SIGKILLs the group or the
                // lone child) and reap the zombie.
                let _ = self.kill();
                let _ = self.child.wait();
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Seatbelt: process timed out",
                ))
            }
            Err(WaitError::Io(error)) => {
                // The child may still be running: kill+reap it (don't orphan
                // the sandbox) before returning.
                let _ = self.kill();
                let _ = self.child.wait();
                Err(std::io::Error::other(format!("wait failed: {error}")))
            }
        };

        cancel_and_join_discard(stdout_thread, &self.stdout_canceller);
        cancel_and_join_discard(stderr_thread, &self.stderr_canceller);
        self.run_cleanup();
        result
    }
}

impl Drop for SeatbeltSandboxProcess {
    fn drop(&mut self) {
        // Don't leak a running sandboxed process (and its group) or a zombie if
        // the handle is dropped without `wait()`, and remove any temp files.
        // `kill()` is idempotent (its `try_wait` guard no-ops once the child has
        // exited).
        let _ = self.kill();
        let _ = self.child.wait();
        self.run_cleanup();
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
    new_group: bool,
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
    } else if new_group {
        // Inherit-with-timeout: a new process group within the *existing*
        // session, so the child keeps the controlling terminal yet can be
        // tree-killed via `killpg(-pgid)` on timeout.
        //
        // SAFETY: `setpgid` is async-signal-safe and runs after fork(), before
        // exec(); the child is not yet a group leader, so it succeeds. Failure
        // is non-fatal (the timeout kill then targets the direct child only).
        unsafe {
            command.pre_exec(|| {
                libc::setpgid(0, 0);
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

/// The optional run timeout — `None` when `scriptTimeout` is 0 (wait forever).
fn timeout_from(request: &ExecutionRequest) -> Option<Duration> {
    if request.script_timeout == 0 {
        None
    } else {
        Some(Duration::from_millis(u64::from(request.script_timeout)))
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
    let default = request
        .policy
        .readwrite_paths
        .first()
        .or_else(|| request.policy.readonly_paths.first())
        .cloned()
        .unwrap_or_else(|| "/".to_string());
    // The default may be a `~`/`~/…` policy path; expand it exactly as the
    // sandbox profile does so `Command::current_dir` never gets a literal `~`
    // (which would fail). Fall back to the unexpanded value if `HOME` is unset.
    crate::profile_builder::expand_tilde(&default).unwrap_or(default)
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
        let response = runner.validate(&request).unwrap_err();
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
