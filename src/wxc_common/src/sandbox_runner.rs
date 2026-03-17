//! `SandboxScriptRunner` — executes scripts via the Windows Sandbox daemon.
//!
//! When `wxc-exec` is configured with `"containment": "sandbox"`, this runner
//! connects to the sandbox daemon's IPC server, sends an EXEC request, and
//! returns the exit code.  If the daemon isn't running it is auto-launched.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use crate::logger::Logger;
use crate::models::{CodexRequest, SandboxConfig, ScriptResponse};
use crate::script_runner::ScriptRunner;

/// Script runner that delegates execution to the Windows Sandbox daemon.
pub struct SandboxScriptRunner {
    config: SandboxConfig,
}

impl SandboxScriptRunner {
    pub fn new(config: &SandboxConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Deterministic port derived from the pipe name (matches daemon logic).
    fn pipe_name_to_port(name: &str) -> u16 {
        let hash: u32 = name
            .bytes()
            .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
        let range = 65535u32 - 49152;
        (49152 + (hash % range)) as u16
    }

    /// Try to connect to the daemon's IPC server.
    fn connect_to_daemon(&self) -> Result<TcpStream, String> {
        let port = Self::pipe_name_to_port(&self.config.daemon_pipe_name);
        let addr = format!("127.0.0.1:{}", port);

        TcpStream::connect_timeout(
            &addr.parse().map_err(|e| format!("bad addr: {}", e))?,
            Duration::from_secs(5),
        )
        .map_err(|e| format!("connect to daemon at {}: {}", addr, e))
    }

    /// Locate the daemon executable next to wxc-exec.
    fn daemon_exe_path() -> Result<PathBuf, String> {
        let exe = std::env::current_exe().map_err(|e| format!("current_exe: {}", e))?;
        let dir = exe.parent().ok_or("exe has no parent dir")?;
        let daemon = dir.join("wxc-sandbox-daemon.exe");
        if daemon.exists() {
            Ok(daemon)
        } else {
            Err(format!("daemon binary not found at {:?}", daemon))
        }
    }

    /// Launch the daemon process if it's not already running.
    fn ensure_daemon_running(&self, logger: &mut Logger) -> Result<(), String> {
        // First, try to connect — if it works, daemon is already running.
        if self.connect_to_daemon().is_ok() {
            return Ok(());
        }

        logger.log_line("Sandbox daemon not running, launching...");

        let daemon_path = Self::daemon_exe_path()?;
        let idle_timeout = self.config.idle_timeout_ms.to_string();

        // Launch daemon as a detached background process.
        std::process::Command::new(&daemon_path)
            .arg(&self.config.daemon_pipe_name)
            .arg(&idle_timeout)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn daemon: {}", e))?;

        // Poll until the daemon's IPC port is reachable.
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        loop {
            if std::time::Instant::now() >= deadline {
                return Err("timed out waiting for daemon to start".to_string());
            }
            std::thread::sleep(Duration::from_millis(500));
            if self.connect_to_daemon().is_ok() {
                logger.log_line("Sandbox daemon is now running");
                return Ok(());
            }
        }
    }

    /// Send an execution request to the daemon and read the result.
    fn execute_via_daemon(&self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        // Ensure daemon is up.
        if let Err(e) = self.ensure_daemon_running(logger) {
            return ScriptResponse::error(&e);
        }

        // Connect.
        let mut stream = match self.connect_to_daemon() {
            Ok(s) => s,
            Err(e) => return ScriptResponse::error(&e),
        };

        // Send EXEC request as a single line: "EXEC <json>\n"
        let payload = IpcExecRequest {
            script_code: request.script_code.clone(),
            working_directory: request.working_directory.clone(),
            timeout_ms: request.script_timeout,
        };
        let json = match serde_json::to_string(&payload) {
            Ok(j) => j,
            Err(e) => return ScriptResponse::error(&format!("serialize request: {}", e)),
        };

        let msg = format!("EXEC {}\n", json);
        if let Err(e) = stream.write_all(msg.as_bytes()) {
            return ScriptResponse::error(&format!("send to daemon: {}", e));
        }

        // Read the "RESULT <exit-code> <error-message>" response line.
        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        if let Err(e) = reader.read_line(&mut response_line) {
            return ScriptResponse::error(&format!("read daemon response: {}", e));
        }

        let response_line = response_line.trim();
        if let Some(rest) = response_line.strip_prefix("RESULT ") {
            // First token is exit code, rest is error message.
            let (code_str, error_msg) = match rest.find(' ') {
                Some(pos) => (&rest[..pos], rest[pos + 1..].to_string()),
                None => (rest, String::new()),
            };
            let exit_code = code_str.parse::<i32>().unwrap_or(-1);

            if error_msg.is_empty() {
                ScriptResponse {
                    exit_code,
                    standard_out: String::new(),
                    standard_err: String::new(),
                    error_message: String::new(),
                }
            } else {
                ScriptResponse {
                    exit_code,
                    standard_out: String::new(),
                    standard_err: error_msg.clone(),
                    error_message: error_msg,
                }
            }
        } else if let Some(stripped) = response_line.strip_prefix("ERROR ") {
            ScriptResponse::error(stripped)
        } else {
            ScriptResponse::error(&format!("unexpected daemon response: {}", response_line))
        }
    }
}

impl ScriptRunner for SandboxScriptRunner {
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        self.execute_via_daemon(request, logger)
    }
}

/// JSON payload sent to the daemon over the IPC channel.
#[derive(serde::Serialize)]
struct IpcExecRequest {
    script_code: String,
    working_directory: String,
    timeout_ms: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_to_port_deterministic() {
        let p1 = SandboxScriptRunner::pipe_name_to_port("wxc-sandbox");
        let p2 = SandboxScriptRunner::pipe_name_to_port("wxc-sandbox");
        assert_eq!(p1, p2);
        assert!(p1 >= 49152);
    }

    #[test]
    fn pipe_name_to_port_matches_daemon() {
        // Must produce the same port as the daemon's pipe_name_to_port.
        fn daemon_pipe_name_to_port(name: &str) -> u16 {
            let hash: u32 = name
                .bytes()
                .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
            let range = 65535u32 - 49152;
            (49152 + (hash % range)) as u16
        }
        assert_eq!(
            SandboxScriptRunner::pipe_name_to_port("wxc-sandbox"),
            daemon_pipe_name_to_port("wxc-sandbox")
        );
        assert_eq!(
            SandboxScriptRunner::pipe_name_to_port("custom-pipe"),
            daemon_pipe_name_to_port("custom-pipe")
        );
    }
}
