//! `WindowsSandboxScriptRunner` — executes scripts via the Windows Sandbox daemon.
//!
//! When `wxc-exec` is configured with `"containment": "windows_sandbox"`, this runner
//! connects to the sandbox daemon's IPC server, sends an EXEC request, and
//! returns the exit code.  If the daemon isn't running it is auto-launched.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::logger::Logger;
use crate::models::{CodexRequest, ScriptResponse, WindowsSandboxConfig};
use crate::process_util::resolve_sibling_binary;
use crate::sandbox_protocol::DaemonResult;
use crate::script_runner::ScriptRunner;

/// Script runner that delegates execution to the Windows Sandbox daemon.
pub struct WindowsSandboxScriptRunner {
    config: WindowsSandboxConfig,
}

impl WindowsSandboxScriptRunner {
    pub fn new(config: &WindowsSandboxConfig) -> Self {
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
    fn daemon_exe_path() -> Result<std::path::PathBuf, String> {
        resolve_sibling_binary("wxc-windows-sandbox-daemon.exe").map_err(|e| e.to_string())
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

    /// Check if Windows Sandbox is available on this system.
    fn check_sandbox_available() -> Result<(), String> {
        let output = std::process::Command::new("dism")
            .args([
                "/online",
                "/get-featureinfo",
                "/featurename:Containers-DisposableClientVM",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .map_err(|err| format!("failed to run dism: {}", err))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("State : Enabled") {
            Ok(())
        } else {
            Err(
                "Windows Sandbox is not enabled. \
                 Run 'dism /online /enable-feature /featurename:Containers-DisposableClientVM /all' \
                 and reboot."
                    .to_string(),
            )
        }
    }

    /// Send an execution request to the daemon and read the result.
    fn execute_via_daemon(&self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        // Pre-flight: verify Windows Sandbox is available.
        if let Err(err) = Self::check_sandbox_available() {
            return ScriptResponse::error(&err);
        }

        // Ensure daemon is up.
        if let Err(err) = self.ensure_daemon_running(logger) {
            return ScriptResponse::error(&err);
        }

        // Connect.
        let mut stream = match self.connect_to_daemon() {
            Ok(stream) => stream,
            Err(err) => return ScriptResponse::error(&err),
        };

        // Send EXEC request as a single line: "EXEC <json>\n"
        let payload = IpcExecRequest {
            script_code: request.script_code.clone(),
            working_directory: request.working_directory.clone(),
            timeout_ms: request.script_timeout,
        };
        let json = match serde_json::to_string(&payload) {
            Ok(json) => json,
            Err(err) => return ScriptResponse::error(&format!("serialize request: {}", err)),
        };

        let msg = format!("EXEC {}\n", json);
        if let Err(err) = stream.write_all(msg.as_bytes()) {
            return ScriptResponse::error(&format!("send to daemon: {}", err));
        }

        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        if let Err(err) = reader.read_line(&mut response_line) {
            return ScriptResponse::error(&format!("read daemon response: {}", err));
        }

        Self::parse_daemon_response(response_line.trim())
    }

    /// Parse the daemon's response line into a `ScriptResponse`.
    fn parse_daemon_response(response_line: &str) -> ScriptResponse {
        if response_line.starts_with("RESULT ") {
            match DaemonResult::parse(response_line) {
                Ok(result) => {
                    let stdout_text = String::from_utf8(result.stdout).unwrap_or_default();
                    let stderr_text = String::from_utf8(result.stderr).unwrap_or_default();
                    ScriptResponse {
                        exit_code: result.exit_code,
                        standard_out: stdout_text,
                        standard_err: stderr_text.clone(),
                        error_message: if result.error_message.is_empty() {
                            stderr_text
                        } else {
                            result.error_message
                        },
                        ..Default::default()
                    }
                }
                Err(err) => ScriptResponse::error(&err),
            }
        } else if let Some(stripped) = response_line.strip_prefix("ERROR ") {
            ScriptResponse::error(stripped)
        } else {
            ScriptResponse::error(&format!("unexpected daemon response: {}", response_line))
        }
    }
}

impl ScriptRunner for WindowsSandboxScriptRunner {
    fn execute(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
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
        let p1 = WindowsSandboxScriptRunner::pipe_name_to_port("wxc-windows-sandbox");
        let p2 = WindowsSandboxScriptRunner::pipe_name_to_port("wxc-windows-sandbox");
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
            WindowsSandboxScriptRunner::pipe_name_to_port("wxc-windows-sandbox"),
            daemon_pipe_name_to_port("wxc-windows-sandbox")
        );
        assert_eq!(
            WindowsSandboxScriptRunner::pipe_name_to_port("custom-pipe"),
            daemon_pipe_name_to_port("custom-pipe")
        );
    }
}
