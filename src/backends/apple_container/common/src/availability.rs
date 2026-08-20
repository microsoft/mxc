// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::Path;

use serde::Deserialize;
use thiserror::Error;
use wxc_common::mxc_error::MxcError;

use crate::command::{CliArgument, CliCommand, CommandOutput, CommandRunner, SystemCommandRunner};

/// Fixed path where Apple's installer places the Container CLI.
pub const APPLE_CONTAINER_CLI_PATH: &str = "/usr/local/bin/container";

/// Official Apple Container release downloads.
pub const APPLE_CONTAINER_RELEASES_URL: &str = "https://github.com/apple/container/releases";

/// Exact CLI and API server version qualified by this prototype.
pub const QUALIFIED_APPLE_CONTAINER_VERSION: AppleContainerVersion =
    AppleContainerVersion::new(1, 2, 2);

/// Parsed Apple Container semantic version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppleContainerVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl AppleContainerVersion {
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl std::fmt::Display for AppleContainerVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Host facts needed by the Apple Container availability gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInfo {
    pub operating_system: String,
    pub architecture: String,
    pub macos_major_version: Option<u32>,
    pub cli_present: bool,
}

impl HostInfo {
    /// Capture compile-time OS/architecture and caller-supplied macOS version.
    pub fn current(macos_major_version: Option<u32>) -> Self {
        Self {
            operating_system: std::env::consts::OS.to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            macos_major_version,
            cli_present: Path::new(APPLE_CONTAINER_CLI_PATH).is_file(),
        }
    }
}

/// Documented JSON returned by `container system status --format json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemStatus {
    pub api_server_app_name: String,
    pub api_server_build: String,
    pub api_server_commit: String,
    pub api_server_version: String,
    pub app_root: String,
    pub install_root: String,
    pub status: String,
}

/// Successful Apple Container availability details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleContainerAvailability {
    pub cli_version: AppleContainerVersion,
    pub api_server_version: AppleContainerVersion,
    pub api_server_commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AvailabilityError {
    #[error("Apple Container is available only on Apple silicon macOS 26 or newer")]
    UnsupportedHost,
    #[error(
        "Apple Container CLI was not found at /usr/local/bin/container. Install Apple Container from https://github.com/apple/container/releases"
    )]
    CliMissing,
    #[error("Apple Container availability command failed: {0}")]
    CommandFailed(String),
    #[error("Apple Container returned malformed availability data: {0}")]
    MalformedOutput(String),
    #[error(
        "Apple Container version {actual} is not qualified; MXC currently requires version {required}"
    )]
    UnsupportedVersion {
        actual: AppleContainerVersion,
        required: AppleContainerVersion,
    },
    #[error("Apple Container service is not running (reported status: {0})")]
    ServiceNotRunning(String),
    #[error("Apple Container CLI version {cli} does not match API server version {api_server}")]
    VersionMismatch {
        cli: AppleContainerVersion,
        api_server: AppleContainerVersion,
    },
}

impl AvailabilityError {
    /// Map availability failures to the public typed backend error.
    pub fn into_mxc_error(self) -> MxcError {
        MxcError::backend_unavailable(self.to_string())
    }
}

/// Check only the fixed CLI installation path without invoking the executable.
pub fn check_cli_installed() -> Result<(), AvailabilityError> {
    check_cli_presence(Path::new(APPLE_CONTAINER_CLI_PATH).is_file())
}

/// Probe the current host using the production bounded command runner.
pub fn probe() -> Result<AppleContainerAvailability, AvailabilityError> {
    probe_with(&SystemCommandRunner, &current_host_info())
}

/// Whether the current host passes the full read-only availability probe.
pub fn is_available() -> bool {
    probe().is_ok()
}

fn current_host_info() -> HostInfo {
    HostInfo::current(current_macos_major_version())
}

#[cfg(target_os = "macos")]
fn current_macos_major_version() -> Option<u32> {
    let mut name = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: `uname` initializes the supplied `utsname` on success.
    if unsafe { libc::uname(name.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: `uname` succeeded, so every field is initialized and the release
    // field is a NUL-terminated C string.
    let name = unsafe { name.assume_init() };
    let release = unsafe { std::ffi::CStr::from_ptr(name.release.as_ptr()) };
    let darwin_major = release
        .to_str()
        .ok()?
        .split('.')
        .next()?
        .parse::<u32>()
        .ok()?;
    darwin_major.checked_add(1)
}

#[cfg(not(target_os = "macos"))]
fn current_macos_major_version() -> Option<u32> {
    None
}

fn check_cli_presence(present: bool) -> Result<(), AvailabilityError> {
    if present {
        Ok(())
    } else {
        Err(AvailabilityError::CliMissing)
    }
}

/// Probe Apple Container using an injected command runner.
pub fn probe_with(
    runner: &dyn CommandRunner,
    host: &HostInfo,
) -> Result<AppleContainerAvailability, AvailabilityError> {
    validate_host(host)?;
    check_cli_presence(host.cli_present)?;

    let version_output =
        run_probe_command(runner, CliCommand::new([CliArgument::literal("--version")]))?;
    let cli_version = parse_version_output(&version_output)?;
    require_qualified_version(cli_version)?;

    let status_output = run_probe_command(
        runner,
        CliCommand::new([
            CliArgument::literal("system"),
            CliArgument::literal("status"),
            CliArgument::literal("--format"),
            CliArgument::literal("json"),
        ]),
    )?;
    let status: SystemStatus = serde_json::from_slice(&status_output.stdout)
        .map_err(|error| AvailabilityError::MalformedOutput(error.to_string()))?;
    if status.status != "running" {
        return Err(AvailabilityError::ServiceNotRunning(status.status));
    }
    if status.api_server_app_name != "container-apiserver" {
        return Err(AvailabilityError::MalformedOutput(format!(
            "unexpected API server identity {:?}",
            status.api_server_app_name
        )));
    }
    let api_server_version = parse_version_text(&status.api_server_version)?;
    if cli_version != api_server_version {
        return Err(AvailabilityError::VersionMismatch {
            cli: cli_version,
            api_server: api_server_version,
        });
    }
    require_qualified_version(api_server_version)?;

    Ok(AppleContainerAvailability {
        cli_version,
        api_server_version,
        api_server_commit: status.api_server_commit,
    })
}

fn validate_host(host: &HostInfo) -> Result<(), AvailabilityError> {
    if host.operating_system != "macos"
        || host.architecture != "aarch64"
        || host.macos_major_version.is_none_or(|major| major < 26)
    {
        return Err(AvailabilityError::UnsupportedHost);
    }
    Ok(())
}

fn run_probe_command(
    runner: &dyn CommandRunner,
    command: CliCommand,
) -> Result<CommandOutput, AvailabilityError> {
    let diagnostic = command.diagnostic();
    let output_limit = command.output_limit();
    let output = runner
        .run(&command)
        .map_err(|error| AvailabilityError::CommandFailed(error.to_string()))?;
    if output.stdout.len().saturating_add(output.stderr.len()) > output_limit {
        return Err(AvailabilityError::MalformedOutput(format!(
            "{diagnostic} output exceeded the {output_limit}-byte limit"
        )));
    }
    if !output.success() {
        return Err(AvailabilityError::CommandFailed(format!(
            "{diagnostic} exited with status {:?}: {}",
            output.exit_code,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output)
}

fn parse_version_output(
    output: &CommandOutput,
) -> Result<AppleContainerVersion, AvailabilityError> {
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|error| AvailabilityError::MalformedOutput(error.to_string()))?;
    parse_version_text(text)
}

fn parse_version_text(text: &str) -> Result<AppleContainerVersion, AvailabilityError> {
    let token = text
        .split_whitespace()
        .skip_while(|token| *token != "version")
        .nth(1)
        .ok_or_else(|| {
            AvailabilityError::MalformedOutput(
                "version output did not contain a 'version X.Y.Z' marker".to_string(),
            )
        })?;
    let components = token
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            AvailabilityError::MalformedOutput(format!(
                "invalid Apple Container version token {token:?}"
            ))
        })?;
    match components.as_slice() {
        [major, minor, patch] => Ok(AppleContainerVersion::new(*major, *minor, *patch)),
        _ => Err(AvailabilityError::MalformedOutput(format!(
            "invalid Apple Container version token {token:?}"
        ))),
    }
}

fn require_qualified_version(version: AppleContainerVersion) -> Result<(), AvailabilityError> {
    if version == QUALIFIED_APPLE_CONTAINER_VERSION {
        Ok(())
    } else {
        Err(AvailabilityError::UnsupportedVersion {
            actual: version,
            required: QUALIFIED_APPLE_CONTAINER_VERSION,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use crate::command::{CommandError, CommandErrorKind};

    struct FakeRunner {
        results: Mutex<VecDeque<Result<CommandOutput, CommandError>>>,
        diagnostics: Mutex<Vec<String>>,
    }

    impl FakeRunner {
        fn new(results: impl IntoIterator<Item = Result<CommandOutput, CommandError>>) -> Self {
            Self {
                results: Mutex::new(results.into_iter().collect()),
                diagnostics: Mutex::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, command: &CliCommand) -> Result<CommandOutput, CommandError> {
            self.diagnostics.lock().unwrap().push(command.diagnostic());
            self.results
                .lock()
                .unwrap()
                .pop_front()
                .expect("fake command result")
        }
    }

    fn supported_host() -> HostInfo {
        HostInfo {
            operating_system: "macos".to_string(),
            architecture: "aarch64".to_string(),
            macos_major_version: Some(26),
            cli_present: true,
        }
    }

    fn success(stdout: &str) -> Result<CommandOutput, CommandError> {
        Ok(CommandOutput {
            exit_code: Some(0),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        })
    }

    fn running_status() -> &'static str {
        r#"{"apiServerAppName":"container-apiserver","apiServerBuild":"release","apiServerCommit":"0190097d06df0b9065f4c2d2c7873c649d81d493","apiServerVersion":"container-apiserver version 1.2.2 (build: release, commit: 0190097)","appRoot":"/tmp/apple-container","installRoot":"/usr/local/","status":"running"}"#
    }

    #[test]
    fn probe_accepts_qualified_running_service() {
        let runner = FakeRunner::new([
            success("container CLI version 1.2.2 (build: release, commit: 0190097)"),
            success(running_status()),
        ]);

        let availability = probe_with(&runner, &supported_host()).unwrap();

        assert_eq!(availability.cli_version, QUALIFIED_APPLE_CONTAINER_VERSION);
        assert_eq!(
            runner.diagnostics.lock().unwrap().as_slice(),
            [
                "/usr/local/bin/container --version",
                "/usr/local/bin/container system status --format json"
            ]
        );
    }

    #[test]
    fn missing_cli_error_is_actionable_and_typed() {
        let host = HostInfo {
            cli_present: false,
            ..supported_host()
        };
        let runner = FakeRunner::new([]);

        let error = probe_with(&runner, &host).unwrap_err();
        let message = error.to_string();

        assert!(matches!(error, AvailabilityError::CliMissing));
        assert!(message.contains(APPLE_CONTAINER_CLI_PATH));
        assert!(message.contains(APPLE_CONTAINER_RELEASES_URL));
        assert_eq!(
            AvailabilityError::CliMissing.into_mxc_error().code,
            wxc_common::mxc_error::MxcErrorCode::BackendUnavailable
        );
    }

    #[test]
    fn probe_rejects_unsupported_host_before_commands() {
        let runner = FakeRunner::new([]);
        let host = HostInfo {
            architecture: "x86_64".to_string(),
            ..supported_host()
        };

        assert!(matches!(
            probe_with(&runner, &host),
            Err(AvailabilityError::UnsupportedHost)
        ));
    }

    #[test]
    fn probe_rejects_wrong_version_and_stopped_service() {
        let wrong_version = FakeRunner::new([success("container CLI version 1.3.0")]);
        assert!(matches!(
            probe_with(&wrong_version, &supported_host()),
            Err(AvailabilityError::UnsupportedVersion { .. })
        ));

        let stopped_status = running_status().replace("\"running\"", "\"stopped\"");
        let stopped = FakeRunner::new([
            success("container CLI version 1.2.2"),
            success(&stopped_status),
        ]);
        assert!(matches!(
            probe_with(&stopped, &supported_host()),
            Err(AvailabilityError::ServiceNotRunning(status)) if status == "stopped"
        ));
    }

    #[test]
    fn probe_rejects_mismatched_server_version() {
        let mismatched_status = running_status().replace("version 1.2.2", "version 1.2.1");
        let runner = FakeRunner::new([
            success("container CLI version 1.2.2"),
            success(&mismatched_status),
        ]);

        assert!(matches!(
            probe_with(&runner, &supported_host()),
            Err(AvailabilityError::VersionMismatch {
                cli: AppleContainerVersion {
                    major: 1,
                    minor: 2,
                    patch: 2
                },
                api_server: AppleContainerVersion {
                    major: 1,
                    minor: 2,
                    patch: 1
                }
            })
        ));
    }

    #[test]
    fn probe_rejects_malformed_and_oversized_output() {
        let malformed =
            FakeRunner::new([success("container CLI release without a version marker")]);
        assert!(matches!(
            probe_with(&malformed, &supported_host()),
            Err(AvailabilityError::MalformedOutput(_))
        ));

        let oversized = FakeRunner::new([success(
            &"x".repeat(crate::command::DEFAULT_COMMAND_OUTPUT_LIMIT + 1),
        )]);
        let error = probe_with(&oversized, &supported_host()).unwrap_err();
        assert!(matches!(error, AvailabilityError::MalformedOutput(_)));
        assert!(error.to_string().contains("output exceeded"));
    }

    #[test]
    fn runner_failure_is_preserved_without_invoking_later_commands() {
        let runner = FakeRunner::new([Err(CommandError::new(
            CommandErrorKind::Timeout,
            "version probe timed out",
        ))]);

        let error = probe_with(&runner, &supported_host()).unwrap_err();

        assert!(matches!(error, AvailabilityError::CommandFailed(_)));
        assert!(error.to_string().contains("timed out"));
    }
}
