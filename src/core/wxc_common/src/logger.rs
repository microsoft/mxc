// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::cell::RefCell;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write as IoWrite;
use std::path::Path;
use std::time::SystemTime;

#[allow(unused_imports)]
use serde_json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Console,
    Buffer,
}

/// Multi-sink logger.
///
/// Always operates in one of two primary modes (Console or Buffer), and
/// optionally writes to a diagnostic log file and/or the shared diagnostic
/// console (via named pipe) when enabled via [`Logger::enable_diagnostics`].
///
/// Diagnostic sinks accumulate `fmt::Write` fragments in an internal buffer
/// and flush complete lines, so that a single `writeln!` produces exactly one
/// message on the pipe / one timestamped line in the file.
pub struct Logger {
    mode: Mode,
    buffer: String,
    /// Security warnings emitted during the run, retained for library callers.
    warnings: Vec<String>,
    /// Optional CLI-driven log file sink (`--log-file`).
    file: Option<File>,
    /// Named pipe handle for the shared diagnostic console.
    #[cfg(target_os = "windows")]
    diag_pipe: Option<std::fs::File>,
    /// Accumulates fragments from `fmt::Write::write_str` so that diagnostic
    /// sinks receive whole lines instead of per-argument fragments.
    diag_line_buf: String,
}

thread_local! {
    /// Per-thread parking slot for a `Logger` clone whose diagnostic sinks
    /// (`--log-file` + Windows diagnostic pipe) should be inherited by any
    /// downstream call that constructs its own logger. See
    /// [`Logger::install_thread_diagnostic_sink`] for the rationale.
    static THREAD_DIAG_SINK: RefCell<Option<Logger>> = const { RefCell::new(None) };
}

/// RAII guard returned by [`Logger::install_thread_diagnostic_sink`]. Clears
/// the thread-local slot on drop — including when a panic unwinds through
/// the installing scope — so an installed sink can never outlive the scope
/// that published it, regardless of how that scope is exited.
pub struct ThreadDiagnosticSinkGuard {
    _private: (),
}

impl Drop for ThreadDiagnosticSinkGuard {
    fn drop(&mut self) {
        Logger::clear_thread_diagnostic_sink();
    }
}

impl fmt::Debug for Logger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Logger")
            .field("mode", &self.mode)
            .field("buffer_len", &self.buffer.len())
            .finish()
    }
}

impl Logger {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            buffer: String::new(),
            warnings: Vec::new(),
            file: None,
            #[cfg(target_os = "windows")]
            diag_pipe: None,
            diag_line_buf: String::new(),
        }
    }

    /// Enable writing to a log file in addition to console/buffer output.
    pub fn enable_file_sink(&mut self, path: &Path) -> std::io::Result<()> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        self.file = Some(file);
        Ok(())
    }

    /// Enable diagnostic sinks based on the provided configuration.
    ///
    /// If file logging is enabled, creates a per-run log file. If console mode
    /// If enabled, connects to the shared diagnostic console via named pipe.
    ///
    /// Errors during setup are printed to stderr but do not prevent execution.
    #[cfg(target_os = "windows")]
    pub fn enable_diagnostics(&mut self, config: &crate::diagnostic::DiagnosticConfig) {
        if config.console_enabled {
            self.connect_diagnostic_pipe();
        }
    }

    /// Try to connect to the shared diagnostic console named pipe.
    /// Best-effort: prints a warning and continues if the console is not running.
    /// After connecting, verifies the pipe server is running at High integrity
    /// level or above to prevent a rogue process from intercepting diagnostic data.
    #[cfg(target_os = "windows")]
    fn connect_diagnostic_pipe(&mut self) {
        if crate::diagnostic::diagnostic_pipe_token().is_none() {
            eprintln!(
                "[MXC Diagnostics] Refusing an unauthenticated diagnostic pipe; \
                 set MXC_DIAG_PIPE_TOKEN to a high-entropy token."
            );
            return;
        }
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Storage::FileSystem::FILE_FLAG_WRITE_THROUGH;
        use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
        use windows::Win32::System::Threading::{
            OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        // `READ_CONTROL` (a generic access right, distinct from the SQOS
        // flags below despite sharing a numeric value) lets us read the
        // pipe's security descriptor if ever needed for diagnostics; it is
        // not defined as a `FILE_ACCESS_RIGHTS` constant in the `windows`
        // crate's `FileSystem` module, so it is named here explicitly rather
        // than left as an unexplained magic number in `access_mode`.
        const READ_CONTROL: u32 = 0x0002_0000;
        // Security Quality of Service flags for `CreateFile`, passed via
        // `custom_flags` (`dwFlagsAndAttributes`). Without
        // `SECURITY_SQOS_PRESENT`, Windows defaults an outbound pipe
        // connection to `SECURITY_IMPERSONATION`, letting the pipe server
        // impersonate this process's security context. Since the server is
        // only identity-checked *after* connecting (see
        // `verify_server_integrity` below), request the minimum
        // `SECURITY_IDENTIFICATION` level up front so a connection to an
        // unexpected or compromised server can never use our token to act as
        // us, even for the brief window before that check runs.
        const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
        const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

        let pipe_path = crate::diagnostic::diagnostic_pipe_name();

        match std::fs::OpenOptions::new()
            .write(true)
            .access_mode(
                windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE.0
                    | READ_CONTROL
                    | windows::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES.0,
            )
            .custom_flags(
                FILE_FLAG_WRITE_THROUGH.0 | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            )
            .open(&pipe_path)
        {
            Ok(file) => {
                // Verify the pipe server is running at High IL or above.
                match verify_server_integrity(&file) {
                    Ok(()) => {
                        self.diag_pipe = Some(file);
                    }
                    Err(reason) => {
                        // Send an error to the console before dropping the handle.
                        use std::io::Write;
                        let msg = format!(
                            "[MXC Diagnostics] SECURITY: Refusing to connect -- \
                             server integrity check failed: {reason}\n"
                        );
                        let mut pipe = file;
                        let _ = pipe.write_all(msg.as_bytes());
                        let _ = pipe.flush();
                        eprintln!("{}", msg.trim());
                        // pipe handle dropped here.
                    }
                }
            }
            Err(_) => {
                // Diagnostic console is not running -- this is fine; continue silently.
                // The user asked for console output (MXC_DIAG_CONSOLE=1) but the
                // console process hasn't been started yet.
            }
        }

        /// Verify the pipe belongs to the current user and its server runs at
        /// High integrity level or above.
        fn verify_server_integrity(pipe_file: &std::fs::File) -> Result<(), String> {
            use windows::Win32::Foundation::{CloseHandle, HANDLE};
            use windows::Win32::Security::{
                GetTokenInformation, TokenIntegrityLevel, TokenUser, TOKEN_MANDATORY_LABEL,
                TOKEN_QUERY, TOKEN_USER,
            };
            use windows::Win32::System::SystemServices::SECURITY_MANDATORY_HIGH_RID;

            let pipe_handle = HANDLE(pipe_file.as_raw_handle());

            // Get the server PID from the pipe handle.
            let mut server_pid: u32 = 0;
            // SAFETY: pipe_handle is valid (from an open File); server_pid is a valid out pointer.
            unsafe { GetNamedPipeServerProcessId(pipe_handle, &mut server_pid) }
                .map_err(|e| format!("GetNamedPipeServerProcessId failed: {e}"))?;

            // 2. Open the server process.
            // SAFETY: server_pid was returned by the OS above; flags request limited info only.
            let process =
                unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, server_pid) }
                    .map_err(|e| format!("OpenProcess({server_pid}) failed: {e}"))?;

            // 3. Open the process token.
            let mut token = HANDLE::default();
            // SAFETY: `process` is a valid handle from OpenProcess above; token is a valid out ptr.
            unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.map_err(|e| {
                let _ = unsafe { CloseHandle(process) };
                format!("OpenProcessToken failed: {e}")
            })?;

            // Validate the server identity from its token rather than the
            // pipe object's default owner, which may differ for elevated
            // processes.
            let expected_sid = match crate::diagnostic::current_user_sid() {
                Some(sid) => sid,
                None => {
                    let _ = unsafe { CloseHandle(token) };
                    let _ = unsafe { CloseHandle(process) };
                    return Err("current user SID could not be determined".to_string());
                }
            };
            let mut user_buf = vec![0u8; 256];
            let mut user_returned: u32 = 0;
            unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    Some(user_buf.as_mut_ptr().cast()),
                    user_buf.len() as u32,
                    &mut user_returned,
                )
            }
            .map_err(|e| {
                let _ = unsafe { CloseHandle(token) };
                let _ = unsafe { CloseHandle(process) };
                format!("GetTokenInformation(TokenUser) failed: {e}")
            })?;
            let server_user = unsafe { &*(user_buf.as_ptr() as *const TOKEN_USER) };
            let server_sid = unsafe { crate::string_util::sid_to_string(server_user.User.Sid.0) };
            if server_sid.as_deref() != Some(expected_sid.as_str()) {
                let _ = unsafe { CloseHandle(token) };
                let _ = unsafe { CloseHandle(process) };
                return Err("server token user does not match current user".to_string());
            }

            // 4. Query TokenIntegrityLevel.
            let mut buf = vec![0u8; 256];
            let mut returned: u32 = 0;
            // SAFETY: `token` is a valid handle; buf is large enough for TOKEN_MANDATORY_LABEL.
            unsafe {
                GetTokenInformation(
                    token,
                    TokenIntegrityLevel,
                    Some(buf.as_mut_ptr().cast()),
                    buf.len() as u32,
                    &mut returned,
                )
            }
            .map_err(|e| {
                let _ = unsafe { CloseHandle(token) };
                let _ = unsafe { CloseHandle(process) };
                format!("GetTokenInformation failed: {e}")
            })?;

            // 5. Extract the integrity level RID from the SID.
            // SAFETY: GetTokenInformation succeeded, so buf contains a valid TOKEN_MANDATORY_LABEL.
            let label = unsafe { &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
            let sid = label.Label.Sid;

            // The integrity level is the last sub-authority of the SID.
            // SAFETY: sid is valid (from the token information query above).
            let sub_authority_count =
                unsafe { *windows::Win32::Security::GetSidSubAuthorityCount(sid) };
            if sub_authority_count == 0 {
                let _ = unsafe { CloseHandle(token) };
                let _ = unsafe { CloseHandle(process) };
                return Err("SID has no sub-authorities".to_string());
            }
            // SAFETY: sid is valid and sub_authority_count > 0, so (count - 1) is a valid index.
            let integrity_rid = unsafe {
                *windows::Win32::Security::GetSidSubAuthority(sid, (sub_authority_count - 1) as u32)
            };

            let _ = unsafe { CloseHandle(token) };
            let _ = unsafe { CloseHandle(process) };

            let high_rid = SECURITY_MANDATORY_HIGH_RID as u32;
            if integrity_rid >= high_rid {
                Ok(())
            } else {
                Err(format!(
                    "server PID {server_pid} integrity level 0x{integrity_rid:04X} \
                     is below High (0x{high_rid:04X})"
                ))
            }
        }
    }

    pub fn log(&mut self, msg: &str) {
        match self.mode {
            Mode::Console => print!("{}", msg),
            Mode::Buffer => self.buffer.push_str(msg),
        }
        if let Some(ref mut f) = self.file {
            Self::write_timestamped_file(f, msg, false);
        }
        self.diag_accumulate(msg);
    }

    pub fn log_line(&mut self, msg: &str) {
        match self.mode {
            Mode::Console => println!("{}", msg),
            Mode::Buffer => {
                self.buffer.push_str(msg);
                self.buffer.push('\n');
            }
        }
        self.log_diagnostic_line(msg);
    }

    /// Write a complete line only to configured auxiliary diagnostic sinks,
    /// without duplicating it in the primary console/buffer output.
    pub fn log_diagnostic_line(&mut self, msg: &str) {
        if let Some(ref mut f) = self.file {
            Self::write_timestamped_file(f, msg, true);
        }
        // log_line is a complete line -- flush any prior fragments, then this line.
        self.diag_accumulate(msg);
        self.diag_accumulate("\n");
    }

    /// Renders `msg` (possibly multi-line) into timestamped lines and issues a
    /// **single** `write_all` for the whole assembled buffer.
    ///
    /// Two clones of the same `Logger` (or two processes) can append to the
    /// same file concurrently. `File::write_all` on most platforms does not
    /// guarantee a single syscall's data lands atomically relative to a
    /// concurrent writer once split across multiple `write`/`write_all` calls,
    /// so building the complete line(s) first and writing them in one call
    /// keeps the on-disk format's one-record-per-line invariant even under
    /// concurrent appenders.
    fn write_timestamped_file(file: &mut File, msg: &str, terminate: bool) {
        use std::fmt::Write as _;
        let secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let lines: Vec<&str> = msg.split('\n').collect();
        let mut out = String::with_capacity(msg.len() + lines.len() * 16);
        for (index, line) in lines.iter().enumerate() {
            let is_trailing_empty_line = index + 1 == lines.len() && line.is_empty();
            if is_trailing_empty_line && msg.ends_with('\n') {
                break;
            }
            let _ = write!(out, "[{}] {}", secs, line.trim_end_matches('\r'));
            if index + 1 < lines.len() || terminate {
                out.push('\n');
            }
        }
        let _ = file.write_all(out.as_bytes());
    }

    /// Emit a structured [`AuditEvent`](crate::audit::AuditEvent) as a single
    /// JSON line on the auxiliary diagnostic sinks only.
    ///
    /// Audit records are *internal diagnostics*, not user-facing output, so this
    /// writes to the diagnostic sinks directly and deliberately never
    /// touches the primary console/buffer sink — that channel is the SDK
    /// caller's captured stdout / debug buffer, and adding to it would change
    /// the observable output of every existing consumer.
    ///
    /// These are **local log lines, not ETW events**: there is no consent gate,
    /// no administrative policy ceiling, and no config kill-switch. The record is
    /// written when (and only when) a diagnostic sink is attached — a `--log-file`
    /// path or the `MXC_DIAG_CONSOLE` named pipe — and is otherwise a cheap
    /// no-op.
    pub fn log_audit_event(&mut self, event: &crate::audit::AuditEvent) {
        // Every emission site must carry the fields the OpenShell requirements
        // mandate for its record. Asserting here rather than at each site means
        // any existing test that drives a site also enforces the contract.
        // Debug-only: a field omission must never take down a production run
        // that is merely trying to log.
        debug_assert!(
            event.missing_required_fields().is_empty(),
            "audit record {} is missing required field(s) {:?}",
            event.name(),
            event.missing_required_fields(),
        );
        // Skip the render entirely when nothing would consume it.
        if !self.has_diagnostic_sink() {
            return;
        }
        let line = event.to_json_line();
        if let Some(ref mut f) = self.file {
            Self::write_timestamped_file(f, &line, true);
        }
        self.diag_flush_audit(&line);
    }

    /// Whether any auxiliary diagnostic sink is attached, i.e. whether
    /// [`Logger::log_diagnostic_line`] would reach a consumer.
    ///
    /// Public so a caller can skip *building* an expensive record — the policy
    /// hash serialises and digests the whole effective request — rather than
    /// building it and having [`Logger::log_audit_event`] discard it.
    pub fn has_diagnostic_sink(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            self.file.is_some() || self.diag_pipe.is_some()
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.file.is_some()
        }
    }

    /// Produce a detached logger that shares this logger's **diagnostic sinks
    /// only** (the `--log-file` handle and, on Windows, the diagnostic-console
    /// pipe), with an empty primary buffer.
    ///
    /// This exists for owners that must emit diagnostics from a context with no
    /// caller-supplied logger — most importantly `Drop`, whose signature takes
    /// no arguments, and the teardown paths reachable from it. Such call sites
    /// currently build a throwaway `Logger::new(Mode::Buffer)` whose output is
    /// discarded; holding a clone of the real sinks is what makes their records
    /// observable.
    ///
    /// The handles are duplicated with [`std::fs::File::try_clone`], so the
    /// clone writes to the same file / pipe as the original:
    ///
    /// * the log file is opened in append mode, so duplicated handles always
    ///   write at the end regardless of the shared file pointer;
    /// * the diagnostic pipe is a `PIPE_TYPE_MESSAGE` pipe, so each
    ///   `write_all` is a discrete message that cannot interleave with another
    ///   handle's message.
    ///
    /// If a handle cannot be duplicated the corresponding sink is simply absent
    /// from the clone — a failed duplication must never take down a run.
    pub fn clone_diagnostic_sink(&self) -> Logger {
        Logger {
            mode: Mode::Buffer,
            buffer: String::new(),
            warnings: Vec::new(),
            file: self.file.as_ref().and_then(|f| f.try_clone().ok()),
            #[cfg(target_os = "windows")]
            diag_pipe: self.diag_pipe.as_ref().and_then(|p| p.try_clone().ok()),
            diag_line_buf: String::new(),
        }
    }

    /// Publish this logger's diagnostic sinks (`--log-file` handle and, on
    /// Windows, the diagnostic-console pipe) on the **current thread** so a
    /// downstream Rust API call whose signature has no `Logger` parameter can
    /// still route its records to the driver's sinks instead of a discarded
    /// throwaway buffer.
    ///
    /// The concrete need this exists for: `wxc-exec` opens a `--log-file` on
    /// its main `Logger`, then calls `mxc_engine::run_state_aware`, which
    /// consumes the parsed request and internally dispatches to a backend's
    /// `StatefulSandboxBackend::exec` — a trait method that has no `Logger`
    /// argument. Without this hook, the backend would build a fresh
    /// `Logger::new(Mode::Buffer)`, wire it to the diagnostic-console pipe
    /// from the environment, and drop every record into a buffer the caller
    /// never reads — the `--log-file` sink is silently missing.
    ///
    /// The hook stores a `clone_diagnostic_sink` of this logger — the file
    /// handle is `try_clone`-duplicated (append mode, so a shared file pointer
    /// is safe) and, on Windows, the diagnostic pipe is duplicated the same
    /// way (`PIPE_TYPE_MESSAGE`, so each `write_all` remains a discrete
    /// message that cannot interleave). Publication is per-thread, so
    /// concurrent runs on different threads never share sinks by accident.
    ///
    /// Returns a [`ThreadDiagnosticSinkGuard`] that clears the installed sink
    /// on drop, including when a panic unwinds through the caller's scope or
    /// an early return skips an explicit clear — a bare
    /// `install`/`clear_thread_diagnostic_sink` pair left it up to the caller
    /// to remember to call the latter on every exit path, which a panic or a
    /// future early return could silently skip, leaving stale ambient state
    /// installed for whatever runs next on this thread. Dropping the guard at
    /// process exit without ever running is equally harmless (the sinks close
    /// with the process).
    #[must_use = "the diagnostic sink is cleared when this guard drops; \
                  binding it to `_` clears it immediately"]
    pub fn install_thread_diagnostic_sink(&self) -> ThreadDiagnosticSinkGuard {
        let clone = self.clone_diagnostic_sink();
        THREAD_DIAG_SINK.with(|slot| {
            *slot.borrow_mut() = Some(clone);
        });
        ThreadDiagnosticSinkGuard { _private: () }
    }

    /// Clear any diagnostic sink installed on the current thread by
    /// [`Logger::install_thread_diagnostic_sink`].
    ///
    /// Normally unnecessary to call directly: the [`ThreadDiagnosticSinkGuard`]
    /// returned by `install_thread_diagnostic_sink` does this on drop. Kept
    /// available for a caller that needs to clear ahead of the guard's scope
    /// ending.
    pub fn clear_thread_diagnostic_sink() {
        THREAD_DIAG_SINK.with(|slot| {
            slot.borrow_mut().take();
        });
    }

    /// Return a fresh `Buffer`-mode logger that inherits the current thread's
    /// installed diagnostic sinks. If no sink is installed the returned
    /// logger has no diagnostic sinks — the same result as
    /// `Logger::new(Mode::Buffer)`.
    ///
    /// This is what a Rust API path with no `Logger` parameter should use
    /// **instead of** `Logger::new(Mode::Buffer)`: identical in the
    /// no-sink case, but preserves the driver's `--log-file` (and pipe)
    /// when the driver installed one.
    pub fn inherit_thread_diagnostic_sink() -> Logger {
        THREAD_DIAG_SINK.with(|slot| match slot.borrow().as_ref() {
            Some(sink) => sink.clone_diagnostic_sink(),
            None => Logger::new(Mode::Buffer),
        })
    }

    /// Retain a warning for in-process callers and configured diagnostic sinks.
    pub fn warning_line(&mut self, msg: &str) {
        self.warnings.push(msg.to_string());
        self.log_diagnostic_line(msg);
    }

    /// Warnings emitted during the run.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Take all retained security warnings, leaving the logger empty.
    pub fn take_warnings(&mut self) -> Vec<String> {
        std::mem::take(&mut self.warnings)
    }

    pub fn get_buffer(&self) -> &str {
        &self.buffer
    }

    // -----------------------------------------------------------------------
    // Diagnostic sink internals
    // -----------------------------------------------------------------------

    /// Accumulate text into the diagnostic line buffer. Whenever a newline is
    /// encountered, flush the completed line(s) to the pipe sink.
    fn diag_accumulate(&mut self, text: &str) {
        #[cfg(target_os = "windows")]
        if self.diag_pipe.is_some() {
            self.diag_line_buf.push_str(text);

            // Flush each complete line.
            while let Some(newline_pos) = self.diag_line_buf.find('\n') {
                let line = self.diag_line_buf[..newline_pos].to_string();
                self.diag_line_buf.drain(..=newline_pos);
                self.diag_flush_line(&line);
            }
        }
        // Non-Windows: diagnostic pipe sink isn't implemented; accept & discard.
        #[cfg(not(target_os = "windows"))]
        let _ = text;
    }

    /// Send one complete line to the pipe sink.
    fn diag_flush_line(&mut self, line: &str) {
        #[cfg(target_os = "windows")]
        if self.diag_pipe.is_some() {
            let envelope = format!(
                "{{\"msg\":{}}}",
                serde_json::to_string(line).unwrap_or_default()
            );
            if let Some(ref mut pipe) = self.diag_pipe {
                if pipe.write_all(envelope.as_bytes()).is_err() {
                    self.diag_pipe = None;
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        let _ = line;
    }

    /// Send a structured audit record with an envelope that cannot be
    /// produced by the plain diagnostic-line path.
    fn diag_flush_audit(&mut self, record: &str) {
        #[cfg(target_os = "windows")]
        if self.diag_pipe.is_some() {
            if !self.diag_line_buf.is_empty() {
                let pending = std::mem::take(&mut self.diag_line_buf);
                self.diag_flush_line(&pending);
            }
            let envelope = format!("{{\"kind\":\"audit\",\"record\":{record}}}");
            if let Some(ref mut pipe) = self.diag_pipe {
                if pipe.write_all(envelope.as_bytes()).is_err() {
                    self.diag_pipe = None;
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        let _ = record;
    }

    /// Flush and close diagnostic sinks.
    pub fn close_diagnostics(&mut self) {
        // Flush any remaining buffered text as a final line.
        if !self.diag_line_buf.is_empty() {
            let remaining = std::mem::take(&mut self.diag_line_buf);
            self.diag_flush_line(&remaining);
        }

        // Close the pipe (server will detect disconnect).
        #[cfg(target_os = "windows")]
        {
            self.diag_pipe = None;
        }
    }
}

impl fmt::Write for Logger {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.log(s);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEvent, AuditEventName};

    #[test]
    fn security_warnings_are_retained_outside_the_debug_buffer() {
        let mut logger = Logger::new(Mode::Buffer);

        logger.warning_line("security warning");

        assert_eq!(logger.warnings(), ["security warning"]);
        assert!(logger.get_buffer().is_empty());
        assert_eq!(logger.take_warnings(), ["security warning"]);
        assert!(logger.warnings().is_empty());
    }

    #[test]
    fn audit_events_reach_the_file_sink_but_not_the_buffer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.log");
        let mut logger = Logger::new(Mode::Buffer);
        logger.enable_file_sink(&path).expect("file sink");

        logger.log_audit_event(
            &AuditEvent::new(AuditEventName::ProcessExited)
                .str("backend", "processcontainer")
                .str("identity", "CLI")
                .u64("pid", 1234)
                .i64("exit_code", 3),
        );
        // Drop the logger so the file handle is flushed/closed before reading.
        drop(logger);

        let contents = std::fs::read_to_string(&path).expect("read log");
        let records: Vec<serde_json::Value> = contents
            .lines()
            .map(|line| {
                let json = line
                    .split_once("] ")
                    .expect("audit record must have a timestamp prefix")
                    .1;
                serde_json::from_str(json).expect("audit record must be JSON")
            })
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["event"], "mxc.ProcessExited");
        assert_eq!(records[0]["exit_code"], 3);
        // One record, one line.
        assert_eq!(contents.lines().count(), 1, "got: {contents}");
    }

    #[test]
    fn multiline_diagnostic_lines_are_individually_prefixed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("diagnostic.log");
        let mut logger = Logger::new(Mode::Buffer);
        logger.enable_file_sink(&path).expect("file sink");

        logger.log_diagnostic_line("first\n{\"event\":\"spoof\"}");
        drop(logger);

        let contents = std::fs::read_to_string(&path).expect("read log");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|line| line.starts_with('[')));
    }

    #[test]
    fn audit_events_are_a_no_op_without_a_diagnostic_sink() {
        let mut logger = Logger::new(Mode::Buffer);

        logger.log_audit_event(
            &AuditEvent::new(AuditEventName::SandboxIdentity).str("identity", "CLI"),
        );

        assert!(logger.get_buffer().is_empty());
        assert!(logger.warnings().is_empty());
    }

    #[test]
    fn cloned_diagnostic_sink_shares_the_file_but_not_the_buffer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.log");
        let mut logger = Logger::new(Mode::Buffer);
        logger.enable_file_sink(&path).expect("file sink");
        logger.log_line("primary line");

        let mut detached = logger.clone_diagnostic_sink();
        detached.log_audit_event(
            &AuditEvent::new(AuditEventName::SandboxTornDown)
                .str("identity", "CLI")
                .str("status", "success"),
        );
        drop(detached);
        drop(logger);

        let contents = std::fs::read_to_string(&path).expect("read log");
        assert!(contents.contains("primary line"), "got: {contents}");
        assert!(
            contents
                .contains(r#"{"event":"mxc.SandboxTornDown","identity":"CLI","status":"success"}"#),
            "got: {contents}"
        );
    }

    #[test]
    fn cloned_diagnostic_sink_without_sinks_is_inert() {
        let logger = Logger::new(Mode::Buffer);
        let mut detached = logger.clone_diagnostic_sink();

        detached.log_audit_event(
            &AuditEvent::new(AuditEventName::ProcessExited)
                .str("identity", "CLI")
                .u64("pid", 1234)
                .i64("exit_code", 0),
        );

        assert!(detached.get_buffer().is_empty());
    }
}
