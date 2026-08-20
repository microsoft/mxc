// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::availability::APPLE_CONTAINER_CLI_PATH;

/// Default timeout for read-only Apple Container management commands.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum combined stdout/stderr retained from a management command.
pub const DEFAULT_COMMAND_OUTPUT_LIMIT: usize = 64 * 1024;

/// One Apple Container CLI argument and its diagnostic sensitivity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliArgument {
    value: OsString,
    sensitive: bool,
}

impl CliArgument {
    /// Construct a normal argument that may be rendered in diagnostics.
    pub fn literal(value: impl Into<OsString>) -> Self {
        Self {
            value: value.into(),
            sensitive: false,
        }
    }

    /// Construct an argument whose value must be redacted in diagnostics.
    pub fn sensitive(value: impl Into<OsString>) -> Self {
        Self {
            value: value.into(),
            sensitive: true,
        }
    }

    /// The exact argument supplied to the child process.
    pub fn value(&self) -> &OsStr {
        &self.value
    }

    fn diagnostic_value(&self) -> String {
        if self.sensitive {
            "<redacted>".to_string()
        } else {
            self.value.to_string_lossy().into_owned()
        }
    }
}

/// A bounded invocation of the fixed Apple Container CLI executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliCommand {
    arguments: Vec<CliArgument>,
    timeout: Duration,
    output_limit: usize,
}

impl CliCommand {
    /// Construct a command with the management defaults.
    pub fn new(arguments: impl IntoIterator<Item = CliArgument>) -> Self {
        Self {
            arguments: arguments.into_iter().collect(),
            timeout: DEFAULT_COMMAND_TIMEOUT,
            output_limit: DEFAULT_COMMAND_OUTPUT_LIMIT,
        }
    }

    /// Override the command timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the combined stdout/stderr retention limit.
    pub fn with_output_limit(mut self, output_limit: usize) -> Self {
        self.output_limit = output_limit;
        self
    }

    /// The fixed external executable path.
    pub fn program(&self) -> &'static OsStr {
        OsStr::new(APPLE_CONTAINER_CLI_PATH)
    }

    /// Exact child-process arguments, preserving argument boundaries.
    pub fn arguments(&self) -> impl Iterator<Item = &OsStr> {
        self.arguments.iter().map(CliArgument::value)
    }

    /// Maximum runtime for this helper command.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Maximum combined stdout/stderr retained by the runner.
    pub fn output_limit(&self) -> usize {
        self.output_limit
    }

    /// Shell-free, redacted diagnostic rendering.
    pub fn diagnostic(&self) -> String {
        std::iter::once(APPLE_CONTAINER_CLI_PATH.to_string())
            .chain(self.arguments.iter().map(CliArgument::diagnostic_value))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Captured output from a bounded CLI invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Process exit code, or `None` when terminated by a signal.
    pub exit_code: Option<i32>,
    /// Captured stdout bytes.
    pub stdout: Vec<u8>,
    /// Captured stderr bytes.
    pub stderr: Vec<u8>,
}

impl CommandOutput {
    /// Whether the CLI exited successfully.
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Category of command-runner failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandErrorKind {
    Spawn,
    Timeout,
    OutputLimit,
    Wait,
}

/// Failure before a usable CLI result was obtained.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct CommandError {
    /// Stable failure category.
    pub kind: CommandErrorKind,
    /// Redacted diagnostic message.
    pub message: String,
}

impl CommandError {
    /// Construct a command error whose message contains no secret arguments.
    pub fn new(kind: CommandErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// Injectable boundary around external Apple Container CLI execution.
pub trait CommandRunner: Send + Sync {
    /// Execute one bounded command without a host shell.
    fn run(&self, command: &CliCommand) -> Result<CommandOutput, CommandError>;
}

/// Production runner for bounded Apple Container management commands.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, command: &CliCommand) -> Result<CommandOutput, CommandError> {
        run_program(command.program(), command)
    }
}

fn run_program(program: &OsStr, command: &CliCommand) -> Result<CommandOutput, CommandError> {
    let diagnostic = command.diagnostic();
    let mut child = Command::new(program)
        .args(command.arguments())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            CommandError::new(
                CommandErrorKind::Spawn,
                format!("failed to start {diagnostic}: {error}"),
            )
        })?;

    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child);
        return Err(CommandError::new(
            CommandErrorKind::Spawn,
            format!("{diagnostic} did not provide a stdout pipe"),
        ));
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_and_reap(&mut child);
        return Err(CommandError::new(
            CommandErrorKind::Spawn,
            format!("{diagnostic} did not provide a stderr pipe"),
        ));
    };

    let (sender, receiver) = mpsc::channel();
    read_stream(stdout, StreamKind::Stdout, sender.clone());
    read_stream(stderr, StreamKind::Stderr, sender);

    let deadline = Instant::now() + command.timeout();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut readers_open = 2;
    let exit_code = loop {
        drain_available(
            &receiver,
            &mut stdout,
            &mut stderr,
            &mut readers_open,
            command.output_limit(),
            &diagnostic,
            &mut child,
        )?;

        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {}
            Err(error) => {
                terminate_and_reap(&mut child);
                return Err(CommandError::new(
                    CommandErrorKind::Wait,
                    format!("failed while waiting for {diagnostic}: {error}"),
                ));
            }
        }

        if Instant::now() >= deadline {
            terminate_and_reap(&mut child);
            return Err(CommandError::new(
                CommandErrorKind::Timeout,
                format!("{diagnostic} exceeded its {:?} timeout", command.timeout()),
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    };

    let drain_deadline = Instant::now() + Duration::from_secs(1);
    while readers_open > 0 {
        if Instant::now() >= drain_deadline {
            return Err(CommandError::new(
                CommandErrorKind::Wait,
                format!("{diagnostic} output pipes did not close after process exit"),
            ));
        }
        match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(message) => append_message(
                message,
                &mut stdout,
                &mut stderr,
                &mut readers_open,
                command.output_limit(),
                &diagnostic,
            )?,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => readers_open = 0,
        }
    }

    Ok(CommandOutput {
        exit_code,
        stdout,
        stderr,
    })
}

#[derive(Debug, Clone, Copy)]
enum StreamKind {
    Stdout,
    Stderr,
}

enum StreamMessage {
    Data(StreamKind, Vec<u8>),
    Closed,
    Failed(StreamKind, std::io::Error),
}

fn read_stream(
    mut stream: impl Read + Send + 'static,
    kind: StreamKind,
    sender: mpsc::Sender<StreamMessage>,
) {
    std::thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    let _ = sender.send(StreamMessage::Closed);
                    return;
                }
                Ok(count) => {
                    if sender
                        .send(StreamMessage::Data(kind, buffer[..count].to_vec()))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) => {
                    let _ = sender.send(StreamMessage::Failed(kind, error));
                    return;
                }
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn drain_available(
    receiver: &mpsc::Receiver<StreamMessage>,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    readers_open: &mut usize,
    output_limit: usize,
    diagnostic: &str,
    child: &mut std::process::Child,
) -> Result<(), CommandError> {
    while let Ok(message) = receiver.try_recv() {
        if let Err(error) = append_message(
            message,
            stdout,
            stderr,
            readers_open,
            output_limit,
            diagnostic,
        ) {
            terminate_and_reap(child);
            return Err(error);
        }
    }
    Ok(())
}

fn append_message(
    message: StreamMessage,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    readers_open: &mut usize,
    output_limit: usize,
    diagnostic: &str,
) -> Result<(), CommandError> {
    match message {
        StreamMessage::Data(kind, bytes) => {
            if stdout
                .len()
                .saturating_add(stderr.len())
                .saturating_add(bytes.len())
                > output_limit
            {
                return Err(CommandError::new(
                    CommandErrorKind::OutputLimit,
                    format!("{diagnostic} output exceeded the {output_limit}-byte limit"),
                ));
            }
            match kind {
                StreamKind::Stdout => stdout.extend_from_slice(&bytes),
                StreamKind::Stderr => stderr.extend_from_slice(&bytes),
            }
        }
        StreamMessage::Closed => *readers_open = readers_open.saturating_sub(1),
        StreamMessage::Failed(kind, error) => {
            return Err(CommandError::new(
                CommandErrorKind::Wait,
                format!("{diagnostic} failed reading {kind:?}: {error}"),
            ));
        }
    }
    Ok(())
}

fn terminate_and_reap(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_preserves_arguments_and_redacts_sensitive_values() {
        let command = CliCommand::new([
            CliArgument::literal("run"),
            CliArgument::literal("--env-file"),
            CliArgument::sensitive("/private/tmp/mxc-secret-env"),
        ]);

        let arguments = command
            .arguments()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            arguments,
            ["run", "--env-file", "/private/tmp/mxc-secret-env"]
        );
        assert_eq!(
            command.diagnostic(),
            "/usr/local/bin/container run --env-file <redacted>"
        );
        assert_eq!(command.timeout(), DEFAULT_COMMAND_TIMEOUT);
        assert_eq!(command.output_limit(), DEFAULT_COMMAND_OUTPUT_LIMIT);
    }

    #[cfg(unix)]
    #[test]
    fn system_runner_enforces_timeout() {
        let command =
            CliCommand::new([CliArgument::literal("5")]).with_timeout(Duration::from_millis(25));
        let error = run_program(OsStr::new("/bin/sleep"), &command).unwrap_err();
        assert_eq!(error.kind, CommandErrorKind::Timeout);
    }

    #[cfg(unix)]
    #[test]
    fn system_runner_enforces_combined_output_limit() {
        let command = CliCommand::new([CliArgument::literal("x")]).with_output_limit(128);
        let error = run_program(OsStr::new("/usr/bin/yes"), &command).unwrap_err();
        assert_eq!(error.kind, CommandErrorKind::OutputLimit);
    }
}
