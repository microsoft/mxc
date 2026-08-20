// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::{OsStr, OsString};
use std::time::Duration;

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
}
