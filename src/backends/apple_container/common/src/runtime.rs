// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use wxc_common::interruptible_reader::{wrap_pipe, InterruptibleReader, ReadCanceller};
use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use wxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, group_kill, spawn_discard, take_boxed_read,
    take_boxed_write, wait_with_timeout, SandboxBackend, SandboxProcess, StdioMode, StreamCloser,
    WaitError,
};
use wxc_common::validator::validate_common;

use crate::availability::probe;
use crate::cli::{
    create_network_command, delete_command, run_checked, run_command, stop_container_command,
    verify_network_block_init_image, verify_ownership, CliError,
};
use crate::command::{CommandRunner, SystemCommandRunner, DEFAULT_COMMAND_TIMEOUT};
use crate::plan::{CleanupPlan, EnvironmentFile, NetworkPlan, RunPlan};
use crate::policy::{build_run_plan, validate_policy};
use crate::recovery::{stale_recoveries, RecoveryGuard};
use crate::resource::{OwnedResource, ResourceKind};

#[derive(Default)]
pub struct AppleContainerBackend;

impl AppleContainerBackend {
    pub fn new() -> Self {
        Self
    }
}

impl SandboxBackend for AppleContainerBackend {
    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_policy(request).map_err(|error| rejected(error.to_string()))
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        _logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        validate_common(request)?;
        self.validate(request)?;
        probe().map_err(|error| backend_unavailable(error.to_string()))?;

        let runner: Arc<dyn CommandRunner> = Arc::new(SystemCommandRunner);
        recover_stale_resources(runner.as_ref())
            .map_err(|error| backend_unavailable(error.to_string()))?;

        let environment = SecureEnvironmentFile::create(&request.env).map_err(|error| {
            launch_failed(format!("failed to create environment file: {error}"))
        })?;
        let environment_plan = environment
            .as_ref()
            .map(|file| EnvironmentFile::new(file.path.clone()))
            .transpose()
            .map_err(|error| rejected(error.to_string()))?;
        let plan = build_run_plan(request, environment_plan)
            .map_err(|error| rejected(error.to_string()))?;
        if matches!(plan.network, NetworkPlan::Isolated { .. }) {
            verify_network_block_init_image(runner.as_ref())
                .map_err(|error| backend_unavailable(error.to_string()))?;
        }

        let recovery = RecoveryGuard::create(&plan, &request.container_id)
            .map_err(|error| launch_failed(error.to_string()))?;

        if let NetworkPlan::Isolated { resource } = &plan.network {
            if let Err(error) = run_checked(runner.as_ref(), &create_network_command(resource)) {
                let cleanup =
                    finish_cleanup(runner.as_ref(), &plan.cleanup_plan(), false, recovery);
                return Err(match cleanup {
                    Ok(()) => launch_failed(error.to_string()),
                    Err(cleanup_error) => {
                        launch_failed(format!("{error}; cleanup also failed: {cleanup_error}"))
                    }
                });
            }
        }

        match spawn_foreground(request, plan, environment, recovery, runner, stdio) {
            Ok(process) => Ok(Box::new(process)),
            Err((error, cleanup)) => {
                if let Err(cleanup_error) = cleanup {
                    Err(launch_failed(format!(
                        "{error}; cleanup also failed: {cleanup_error}"
                    )))
                } else {
                    Err(launch_failed(error))
                }
            }
        }
    }
}

fn spawn_foreground(
    request: &ExecutionRequest,
    plan: RunPlan,
    environment: Option<SecureEnvironmentFile>,
    recovery: RecoveryGuard,
    runner: Arc<dyn CommandRunner>,
    stdio: StdioMode,
) -> Result<AppleContainerProcess, (String, Result<(), std::io::Error>)> {
    let cwd = if request.working_directory.is_empty() {
        "/"
    } else {
        &request.working_directory
    };
    let tty = stdio == StdioMode::Inherit && stdio_is_tty();
    let cli_command = run_command(&plan, &request.script_code, cwd, tty);
    let mut command = Command::new(cli_command.program());
    command.args(cli_command.arguments()).env_clear();
    let grouped =
        stdio == StdioMode::Pipes || (stdio == StdioMode::Inherit && request.script_timeout != 0);
    if grouped {
        command.process_group(0);
    }
    match stdio {
        StdioMode::Pipes => {
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }
        StdioMode::Inherit => {
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        }
    }

    let cleanup_plan = plan.cleanup_plan();
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let cleanup = finish_cleanup(runner.as_ref(), &cleanup_plan, false, recovery);
            return Err((
                format!("failed to start {}: {error}", cli_command.diagnostic()),
                cleanup,
            ));
        }
    };
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (stdout, stdout_canceller, stderr, stderr_canceller) =
        match wrap_child_pipes(stdout, stderr) {
            Ok(pipes) => pipes,
            Err(error) => {
                if group_kill(&mut child).is_err() {
                    let _ = child.kill();
                }
                let _ = wait_with_timeout(&mut child, Some(DEFAULT_COMMAND_TIMEOUT));
                let cleanup = finish_cleanup(runner.as_ref(), &cleanup_plan, true, recovery);
                return Err((
                    format!("failed to wrap Apple Container stdio: {error}"),
                    cleanup,
                ));
            }
        };

    Ok(AppleContainerProcess {
        child,
        stdin,
        stdout,
        stderr,
        stdout_canceller,
        stderr_canceller,
        timeout: (request.script_timeout != 0)
            .then(|| Duration::from_millis(u64::from(request.script_timeout))),
        grouped,
        cleanup: Some(cleanup_plan),
        environment,
        recovery: Some(recovery),
        runner,
    })
}

type WrappedPipes = (
    Option<InterruptibleReader>,
    Option<ReadCanceller>,
    Option<InterruptibleReader>,
    Option<ReadCanceller>,
);

fn wrap_child_pipes(
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
) -> std::io::Result<WrappedPipes> {
    let (stdout, stdout_canceller) = wrap_pipe(stdout)?;
    let (stderr, stderr_canceller) = wrap_pipe(stderr)?;
    Ok((stdout, stdout_canceller, stderr, stderr_canceller))
}

struct AppleContainerProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<InterruptibleReader>,
    stderr: Option<InterruptibleReader>,
    stdout_canceller: Option<ReadCanceller>,
    stderr_canceller: Option<ReadCanceller>,
    timeout: Option<Duration>,
    grouped: bool,
    cleanup: Option<CleanupPlan>,
    environment: Option<SecureEnvironmentFile>,
    recovery: Option<RecoveryGuard>,
    runner: Arc<dyn CommandRunner>,
}

impl AppleContainerProcess {
    fn terminate_owned(&mut self) -> std::io::Result<()> {
        let child_result = match self.child.try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => self.kill_local_child(),
            Err(error) => {
                let kill_result = self.kill_local_child();
                match kill_result {
                    Ok(()) => Err(error),
                    Err(kill_error) => Err(std::io::Error::new(
                        error.kind(),
                        format!(
                            "failed to inspect Apple Container CLI child: {error}; \
                             additionally failed to terminate it: {kill_error}"
                        ),
                    )),
                }
            }
        };

        let stop_result = match &self.cleanup {
            Some(cleanup) => match verify_ownership(self.runner.as_ref(), &cleanup.container) {
                Ok(true) => run_checked(
                    self.runner.as_ref(),
                    &stop_container_command(&cleanup.container),
                )
                .map(|_| ())
                .map_err(cli_io_error),
                Ok(false) => Ok(()),
                Err(error) => Err(cli_io_error(error)),
            },
            None => Ok(()),
        };

        stop_result.and(child_result)
    }

    fn kill_local_child(&mut self) -> std::io::Result<()> {
        if self.grouped {
            if let Err(group_error) = group_kill(&mut self.child) {
                return self.child.kill().map_err(|child_error| {
                    std::io::Error::new(
                        group_error.kind(),
                        format!(
                            "failed to terminate Apple Container CLI process group: \
                             {group_error}; child termination also failed: {child_error}"
                        ),
                    )
                });
            }
        } else {
            self.child.kill()?;
        }
        Ok(())
    }

    fn reap_local_child_bounded(&mut self) {
        let _ = wait_with_timeout(&mut self.child, Some(DEFAULT_COMMAND_TIMEOUT));
    }

    fn cleanup(&mut self, stop_container: bool) -> std::io::Result<()> {
        let Some(plan) = self.cleanup.take() else {
            return Ok(());
        };
        let result =
            cleanup_resources(self.runner.as_ref(), &plan, stop_container).map_err(cli_io_error);
        let result = match (result, self.recovery.take()) {
            (Ok(()), Some(recovery)) => recovery
                .complete()
                .map_err(|error| std::io::Error::other(error.to_string())),
            (result, _) => result,
        };
        self.environment.take();
        result
    }
}

impl SandboxProcess for AppleContainerProcess {
    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        take_boxed_write(&mut self.stdin)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        take_boxed_read(&mut self.stdout)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
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
        self.terminate_owned()
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        self.stdin.take();
        let stdout_thread = spawn_discard(self.stdout.take());
        let stderr_thread = spawn_discard(self.stderr.take());

        let result = match wait_with_timeout(&mut self.child, self.timeout) {
            Ok(status) => {
                let exit_code = status.code().unwrap_or(-1);
                let ownership = self
                    .cleanup
                    .as_ref()
                    .map(|plan| verify_ownership(self.runner.as_ref(), &plan.container))
                    .transpose()
                    .map(|value| value.unwrap_or(false))
                    .map_err(cli_io_error);
                let cleanup = self.cleanup(false);
                match (ownership, cleanup) {
                    (Ok(false), Ok(())) => Err(std::io::Error::other(format!(
                        "Apple Container CLI exited with status {exit_code} before creating the owned container"
                    ))),
                    (Ok(true), Ok(())) => Ok(exit_code),
                    (Err(error), _) => Err(error),
                    (_, Err(error)) => Err(error),
                }
            }
            Err(WaitError::Timeout) => {
                let termination = self.terminate_owned();
                self.reap_local_child_bounded();
                let cleanup = self.cleanup(false);
                let message = termination.and(cleanup).err().map_or_else(
                    || "Apple Container workload timed out".to_string(),
                    |error| {
                        format!("Apple Container workload timed out and cleanup failed: {error}")
                    },
                );
                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
            }
            Err(WaitError::Io(error)) => {
                let termination = self.terminate_owned();
                self.reap_local_child_bounded();
                let cleanup = self.cleanup(false);
                let kind = error.kind();
                let message = termination.and(cleanup).err().map_or_else(
                    || format!("wait failed: {error}"),
                    |cleanup_error| {
                        format!("wait failed: {error}; cleanup failed: {cleanup_error}")
                    },
                );
                Err(std::io::Error::new(kind, message))
            }
        };

        cancel_and_join_discard(stdout_thread, &self.stdout_canceller);
        cancel_and_join_discard(stderr_thread, &self.stderr_canceller);
        result
    }
}

impl Drop for AppleContainerProcess {
    fn drop(&mut self) {
        let _ = self.terminate_owned();
        self.reap_local_child_bounded();
        let _ = self.cleanup(false);
    }
}

fn cleanup_resources(
    runner: &dyn CommandRunner,
    plan: &CleanupPlan,
    stop_container: bool,
) -> Result<(), CliError> {
    cleanup_resource(runner, &plan.container, stop_container)?;
    if let Some(network) = &plan.network {
        cleanup_resource(runner, network, false)?;
    }
    Ok(())
}

fn finish_cleanup(
    runner: &dyn CommandRunner,
    plan: &CleanupPlan,
    stop_container: bool,
    recovery: RecoveryGuard,
) -> Result<(), std::io::Error> {
    cleanup_resources(runner, plan, stop_container).map_err(cli_io_error)?;
    recovery
        .complete()
        .map_err(|error| std::io::Error::other(error.to_string()))
}

fn recover_stale_resources(runner: &dyn CommandRunner) -> Result<(), std::io::Error> {
    for stale in stale_recoveries().map_err(|error| std::io::Error::other(error.to_string()))? {
        cleanup_resources(runner, stale.cleanup_plan(), true).map_err(cli_io_error)?;
        stale
            .complete()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
    }
    Ok(())
}

fn cleanup_resource(
    runner: &dyn CommandRunner,
    resource: &OwnedResource,
    stop_container: bool,
) -> Result<(), CliError> {
    if !verify_ownership(runner, resource)? {
        return Ok(());
    }
    if stop_container && resource.name.kind() == ResourceKind::Container {
        run_checked(runner, &stop_container_command(resource))?;
        if !verify_ownership(runner, resource)? {
            return Ok(());
        }
    }
    match run_checked(runner, &delete_command(resource)) {
        Ok(_) => Ok(()),
        Err(delete_error) if resource.name.kind() == ResourceKind::Container && !stop_container => {
            // The foreground CLI can exit a few milliseconds before Apple's
            // persisted container state becomes terminal. Re-prove ownership
            // before escalating to the same bounded stop/delete path used for
            // timeout cleanup.
            match verify_ownership(runner, resource) {
                Ok(false) => return Ok(()),
                Ok(true) => {}
                Err(probe_error) => {
                    return Err(CliError::Command(format!(
                        "{delete_error}; ownership re-check failed: {probe_error}"
                    )));
                }
            }
            let stop_result = run_checked(runner, &stop_container_command(resource));
            match verify_ownership(runner, resource) {
                Ok(false) => return Ok(()),
                Ok(true) => {}
                Err(probe_error) => {
                    let stop_detail = stop_result
                        .err()
                        .map(|error| format!("; fallback stop failed: {error}"))
                        .unwrap_or_default();
                    return Err(CliError::Command(format!(
                        "{delete_error}{stop_detail}; ownership check after fallback stop failed: \
                         {probe_error}"
                    )));
                }
            }
            run_checked(runner, &delete_command(resource))
                .map(|_| ())
                .map_err(|retry_error| {
                    let stop_detail = stop_result
                        .err()
                        .map(|error| format!("; fallback stop failed: {error}"))
                        .unwrap_or_default();
                    CliError::Command(format!(
                        "{delete_error}{stop_detail}; delete after fallback stop also failed: \
                         {retry_error}"
                    ))
                })
        }
        Err(error) => Err(error),
    }
}

struct SecureEnvironmentFile {
    path: PathBuf,
}

impl SecureEnvironmentFile {
    fn create(environment: &[String]) -> std::io::Result<Option<Self>> {
        if environment.is_empty() {
            return Ok(None);
        }
        for _ in 0..8 {
            let mut random = [0u8; 8];
            getrandom::getrandom(&mut random)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let path = std::env::temp_dir().join(format!(
                "mxc-apple-container-env-{:016x}",
                u64::from_ne_bytes(random)
            ));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(mut file) => {
                    for entry in environment {
                        writeln!(file, "{entry}")?;
                    }
                    file.flush()?;
                    return Ok(Some(Self { path }));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "failed to create a unique Apple Container environment file",
        ))
    }
}

impl Drop for SecureEnvironmentFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn cli_io_error(error: CliError) -> std::io::Error {
    std::io::Error::other(format!("Apple Container cleanup failed: {error}"))
}

fn stdio_is_tty() -> bool {
    // SAFETY: `isatty` only inspects the two standard file descriptors.
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1 }
}

fn rejected(message: String) -> ScriptResponse {
    error_response(message, FailurePhase::Rejected)
}

fn backend_unavailable(message: String) -> ScriptResponse {
    error_response(message, FailurePhase::BackendUnavailable)
}

fn launch_failed(message: String) -> ScriptResponse {
    error_response(message, FailurePhase::LaunchFailed)
}

fn error_response(message: String, failure_phase: FailurePhase) -> ScriptResponse {
    ScriptResponse {
        exit_code: -1,
        standard_err: message.clone(),
        error_message: message,
        failure_phase,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{CommandError, CommandErrorKind, CommandOutput};
    use crate::resource::{OwnershipToken, ResourceNames};

    struct FailingRunner;

    impl CommandRunner for FailingRunner {
        fn run(
            &self,
            _command: &crate::command::CliCommand,
        ) -> Result<CommandOutput, CommandError> {
            Err(CommandError::new(
                CommandErrorKind::Wait,
                "simulated management failure",
            ))
        }
    }

    #[test]
    fn management_failure_still_terminates_local_cli_child() {
        let child = Command::new("/bin/sleep").arg("60").spawn().unwrap();
        let token = OwnershipToken::parse("0123456789abcdef0123456789abcdef").unwrap();
        let names = ResourceNames::new("termination-test", &token);
        let mut process = AppleContainerProcess {
            child,
            stdin: None,
            stdout: None,
            stderr: None,
            stdout_canceller: None,
            stderr_canceller: None,
            timeout: None,
            grouped: false,
            cleanup: Some(CleanupPlan {
                container: OwnedResource::container(names.container, &token),
                network: None,
            }),
            environment: None,
            recovery: None,
            runner: Arc::new(FailingRunner),
        };

        assert!(process.terminate_owned().is_err());
        assert!(wait_with_timeout(&mut process.child, Some(Duration::from_secs(1))).is_ok());
        process.cleanup = None;
    }
}
