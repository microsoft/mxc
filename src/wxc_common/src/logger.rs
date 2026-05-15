// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
    /// Optional CLI-driven log file sink (`--log-file`).
    file: Option<File>,
    /// Named pipe handle for the shared diagnostic console.
    #[cfg(target_os = "windows")]
    diag_pipe: Option<std::fs::File>,
    /// Accumulates fragments from `fmt::Write::write_str` so that diagnostic
    /// sinks receive whole lines instead of per-argument fragments.
    diag_line_buf: String,
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
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, TokenIntegrityLevel, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
        };
        use windows::Win32::Storage::FileSystem::FILE_FLAG_WRITE_THROUGH;
        use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
        use windows::Win32::System::Threading::{
            OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let pipe_path = crate::diagnostic::diagnostic_pipe_name();

        match std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_WRITE_THROUGH.0)
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

        /// Verify the pipe server process is running at High integrity level or above.
        fn verify_server_integrity(pipe_file: &std::fs::File) -> Result<(), String> {
            // 1. Get the server PID from the pipe handle.
            let pipe_handle = HANDLE(pipe_file.as_raw_handle());
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

            use windows::Win32::System::SystemServices::SECURITY_MANDATORY_HIGH_RID;
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
            let secs = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let _ = write!(f, "[{}] {}", secs, msg);
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
        if let Some(ref mut f) = self.file {
            let secs = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let _ = writeln!(f, "[{}] {}", secs, msg);
        }
        // log_line is a complete line -- flush any prior fragments, then this line.
        self.diag_accumulate(msg);
        self.diag_accumulate("\n");
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
                if pipe.write_all(envelope.as_bytes()).is_err() || pipe.flush().is_err() {
                    self.diag_pipe = None;
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        let _ = line;
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
