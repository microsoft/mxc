// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::BTreeMap;
use std::ffi::OsString;

use serde::Deserialize;
use thiserror::Error;

use crate::command::{CliArgument, CliCommand, CommandOutput, CommandRunner};
use crate::plan::{MountAccess, NetworkPlan, RunPlan};
use crate::resource::{OwnedResource, ResourceKind};

/// Trusted MXC guest-init image qualified for default-deny networking.
pub const NETWORK_BLOCK_INIT_IMAGE: &str = "local/mxc-loopback-init:0.2";
pub const NETWORK_BLOCK_INIT_IMAGE_DIGEST: &str =
    "sha256:a82bc45e6fee26927b9881150ca2d8d1b29969a306ba579e8b8887345d31dc2f";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CliError {
    #[error("{0}")]
    Command(String),
    #[error("{command} failed with status {status:?}: {stderr}")]
    Exit {
        command: String,
        status: Option<i32>,
        stderr: String,
    },
    #[error("{resource} returned malformed JSON: {message}")]
    MalformedJson {
        resource: &'static str,
        message: String,
    },
    #[error("Apple Container returned {actual} {kind} records while inspecting {expected:?}")]
    UnexpectedInspectResult {
        kind: &'static str,
        expected: String,
        actual: usize,
    },
    #[error("refusing to modify Apple {kind} {name:?}: MXC ownership labels do not match")]
    OwnershipMismatch { kind: &'static str, name: String },
    #[error(
        "qualified Apple Container init image {image:?} is not installed at digest {expected_digest}"
    )]
    InitImageMismatch {
        image: &'static str,
        expected_digest: &'static str,
    },
}

#[derive(Debug, Deserialize)]
struct ContainerInspect {
    id: String,
    configuration: ContainerConfiguration,
}

#[derive(Debug, Deserialize)]
struct ContainerConfiguration {
    id: String,
    labels: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct NetworkInspect {
    id: String,
    configuration: NetworkConfiguration,
}

#[derive(Debug, Deserialize)]
struct NetworkConfiguration {
    name: String,
    labels: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ImageInspect {
    configuration: ImageConfiguration,
}

#[derive(Debug, Deserialize)]
struct ImageConfiguration {
    descriptor: ImageDescriptor,
    name: String,
}

#[derive(Debug, Deserialize)]
struct ImageDescriptor {
    digest: String,
}

/// Execute a management command and require a successful CLI exit.
pub fn run_checked(
    runner: &dyn CommandRunner,
    command: &CliCommand,
) -> Result<CommandOutput, CliError> {
    let output = runner
        .run(command)
        .map_err(|error| CliError::Command(error.to_string()))?;
    if output.success() {
        Ok(output)
    } else {
        Err(CliError::Exit {
            command: command.diagnostic(),
            status: output.exit_code,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

/// Build the isolated per-run network creation command.
pub fn create_network_command(resource: &OwnedResource) -> CliCommand {
    debug_assert_eq!(resource.name.kind(), ResourceKind::Network);
    let mut arguments = vec![
        CliArgument::literal("network"),
        CliArgument::literal("create"),
        CliArgument::literal("--internal"),
    ];
    append_labels(&mut arguments, resource, "--label");
    arguments.push(CliArgument::literal(resource.name.as_str()));
    CliCommand::new(arguments)
}

/// Require the locally installed enforcement image to match the qualified digest.
pub fn verify_network_block_init_image(runner: &dyn CommandRunner) -> Result<(), CliError> {
    let command = CliCommand::new([
        CliArgument::literal("image"),
        CliArgument::literal("inspect"),
        CliArgument::literal(NETWORK_BLOCK_INIT_IMAGE),
    ]);
    let output = run_checked(runner, &command)?;
    let records: Vec<ImageInspect> =
        serde_json::from_slice(&output.stdout).map_err(|error| CliError::MalformedJson {
            resource: "init image inspect",
            message: error.to_string(),
        })?;
    let Some(record) = records.first().filter(|_| records.len() == 1) else {
        return Err(CliError::UnexpectedInspectResult {
            kind: "init image",
            expected: NETWORK_BLOCK_INIT_IMAGE.to_string(),
            actual: records.len(),
        });
    };
    if record.configuration.name != NETWORK_BLOCK_INIT_IMAGE
        || record.configuration.descriptor.digest != NETWORK_BLOCK_INIT_IMAGE_DIGEST
    {
        return Err(CliError::InitImageMismatch {
            image: NETWORK_BLOCK_INIT_IMAGE,
            expected_digest: NETWORK_BLOCK_INIT_IMAGE_DIGEST,
        });
    }
    Ok(())
}

/// Build a foreground `container run` command with stable argument boundaries.
pub fn run_command(plan: &RunPlan, command_line: &str, cwd: &str, tty: bool) -> CliCommand {
    let mut arguments = vec![
        CliArgument::literal("run"),
        CliArgument::literal("--interactive"),
        CliArgument::literal("--progress"),
        CliArgument::literal("none"),
        CliArgument::literal("--name"),
        CliArgument::literal(plan.container.name.as_str()),
    ];
    if tty {
        arguments.push(CliArgument::literal("--tty"));
    }
    append_labels(&mut arguments, &plan.container, "--label");

    match &plan.network {
        NetworkPlan::DefaultNat => {
            arguments.push(CliArgument::literal("--network"));
            arguments.push(CliArgument::literal("default"));
        }
        NetworkPlan::Isolated { resource } => {
            arguments.push(CliArgument::literal("--network"));
            arguments.push(CliArgument::literal(resource.name.as_str()));
            arguments.push(CliArgument::literal("--init-image"));
            arguments.push(CliArgument::literal(NETWORK_BLOCK_INIT_IMAGE));
        }
    }

    if let Some(environment_file) = &plan.environment_file {
        arguments.push(CliArgument::literal("--env-file"));
        arguments.push(CliArgument::sensitive(environment_file.path.as_os_str()));
    }
    if !cwd.is_empty() {
        arguments.push(CliArgument::literal("--workdir"));
        arguments.push(CliArgument::literal(cwd));
    }
    if let Some(cpu_count) = plan.resources.cpu_count {
        arguments.push(CliArgument::literal("--cpus"));
        arguments.push(CliArgument::literal(cpu_count.to_string()));
    }
    if let Some(memory_mb) = plan.resources.memory_mb {
        arguments.push(CliArgument::literal("--memory"));
        arguments.push(CliArgument::literal(format!("{memory_mb}M")));
    }
    for mount in &plan.mounts {
        arguments.push(CliArgument::literal("--mount"));
        let mut value = OsString::from("type=bind,source=");
        value.push(&mount.host_path);
        value.push(",target=");
        value.push(&mount.guest_path);
        if mount.access == MountAccess::ReadOnly {
            value.push(",readonly");
        }
        arguments.push(CliArgument::literal(value));
    }

    arguments.extend([
        CliArgument::literal(&plan.image),
        CliArgument::literal("/bin/sh"),
        CliArgument::literal("-lc"),
        CliArgument::sensitive(command_line),
    ]);
    CliCommand::new(arguments)
}

pub fn inspect_command(resource: &OwnedResource) -> CliCommand {
    let arguments = match resource.name.kind() {
        ResourceKind::Container => vec![
            CliArgument::literal("inspect"),
            CliArgument::literal(resource.name.as_str()),
        ],
        ResourceKind::Network => vec![
            CliArgument::literal("network"),
            CliArgument::literal("inspect"),
            CliArgument::literal(resource.name.as_str()),
        ],
    };
    CliCommand::new(arguments)
}

pub fn stop_container_command(resource: &OwnedResource) -> CliCommand {
    debug_assert_eq!(resource.name.kind(), ResourceKind::Container);
    CliCommand::new([
        CliArgument::literal("stop"),
        CliArgument::literal("--signal"),
        CliArgument::literal("KILL"),
        CliArgument::literal("--time"),
        CliArgument::literal("0"),
        CliArgument::literal(resource.name.as_str()),
    ])
}

pub fn delete_command(resource: &OwnedResource) -> CliCommand {
    let arguments = match resource.name.kind() {
        ResourceKind::Container => vec![
            CliArgument::literal("delete"),
            CliArgument::literal(resource.name.as_str()),
        ],
        ResourceKind::Network => vec![
            CliArgument::literal("network"),
            CliArgument::literal("delete"),
            CliArgument::literal(resource.name.as_str()),
        ],
    };
    CliCommand::new(arguments)
}

/// Read back and verify MXC ownership before any destructive command.
pub fn verify_ownership(
    runner: &dyn CommandRunner,
    resource: &OwnedResource,
) -> Result<bool, CliError> {
    let command = inspect_command(resource);
    let output = runner
        .run(&command)
        .map_err(|error| CliError::Command(error.to_string()))?;
    if !output.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.to_ascii_lowercase().contains("not found") {
            return Ok(false);
        }
        return Err(CliError::Exit {
            command: command.diagnostic(),
            status: output.exit_code,
            stderr,
        });
    }
    let (id, labels) =
        match resource.name.kind() {
            ResourceKind::Container => {
                let records: Vec<ContainerInspect> = serde_json::from_slice(&output.stdout)
                    .map_err(|error| CliError::MalformedJson {
                        resource: "container inspect",
                        message: error.to_string(),
                    })?;
                if records.len() != 1 {
                    return Err(CliError::UnexpectedInspectResult {
                        kind: "container",
                        expected: resource.name.as_str().to_string(),
                        actual: records.len(),
                    });
                }
                let record = &records[0];
                if record.id != record.configuration.id {
                    return Err(CliError::MalformedJson {
                        resource: "container inspect",
                        message: "top-level and configuration IDs differ".to_string(),
                    });
                }
                (record.id.clone(), record.configuration.labels.clone())
            }
            ResourceKind::Network => {
                let records: Vec<NetworkInspect> =
                    serde_json::from_slice(&output.stdout).map_err(|error| {
                        CliError::MalformedJson {
                            resource: "network inspect",
                            message: error.to_string(),
                        }
                    })?;
                if records.len() != 1 {
                    return Err(CliError::UnexpectedInspectResult {
                        kind: "network",
                        expected: resource.name.as_str().to_string(),
                        actual: records.len(),
                    });
                }
                let record = &records[0];
                if record.id != record.configuration.name {
                    return Err(CliError::MalformedJson {
                        resource: "network inspect",
                        message: "top-level ID and configuration name differ".to_string(),
                    });
                }
                (record.id.clone(), record.configuration.labels.clone())
            }
        };
    if id != resource.name.as_str() || !resource.labels.matches(&labels) {
        return Err(CliError::OwnershipMismatch {
            kind: resource.name.kind().as_str(),
            name: resource.name.as_str().to_string(),
        });
    }
    Ok(true)
}

fn append_labels(arguments: &mut Vec<CliArgument>, resource: &OwnedResource, flag: &str) {
    for (key, value) in resource.labels.iter() {
        arguments.push(CliArgument::literal(flag));
        arguments.push(CliArgument::literal(format!("{key}={value}")));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use crate::command::{CommandError, CommandRunner};
    use crate::plan::{EnvironmentFile, MountPlan, ResourceLimits};
    use crate::resource::OwnershipToken;

    fn token() -> OwnershipToken {
        OwnershipToken::parse("0123456789abcdef0123456789abcdef").unwrap()
    }

    fn isolated_plan() -> RunPlan {
        RunPlan::new(
            "docker.io/library/alpine:3.22@sha256:abc",
            "build job",
            &token(),
            true,
            vec![
                MountPlan::new("/host/rw", "/host/rw", MountAccess::ReadWrite).unwrap(),
                MountPlan::new("/host/ro", "/host/ro", MountAccess::ReadOnly).unwrap(),
            ],
            Some(EnvironmentFile::new("/private/tmp/secret.env").unwrap()),
            ResourceLimits::new(Some(2), Some(512)).unwrap(),
        )
        .unwrap()
    }

    fn arguments(command: &CliCommand) -> Vec<String> {
        command
            .arguments()
            .map(|value| value.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn run_argv_preserves_unsplit_workload_and_redacts_env_path() {
        let command_line = "printf '%s\\n' \"$TOKEN\"; touch '/tmp/a b'";
        let command = run_command(&isolated_plan(), command_line, "/host/rw", false);
        let argv = arguments(&command);

        assert_eq!(
            &argv[argv.len() - 4..],
            &[
                "docker.io/library/alpine:3.22@sha256:abc",
                "/bin/sh",
                "-lc",
                command_line,
            ]
        );
        assert!(argv.contains(&NETWORK_BLOCK_INIT_IMAGE.to_string()));
        assert!(argv.contains(&"type=bind,source=/host/ro,target=/host/ro,readonly".to_string()));
        assert!(!command.diagnostic().contains("/private/tmp/secret.env"));
        assert!(!command.diagnostic().contains(command_line));
        assert!(!argv.iter().any(|argument| argument == "--rm"));
    }

    struct FakeRunner {
        output: Mutex<VecDeque<Result<CommandOutput, CommandError>>>,
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, _command: &CliCommand) -> Result<CommandOutput, CommandError> {
            self.output.lock().unwrap().pop_front().unwrap()
        }
    }

    #[test]
    fn ownership_verification_rejects_foreign_labels() {
        let plan = isolated_plan();
        let output = format!(
            r#"[{{"id":"{0}","configuration":{{"id":"{0}","labels":{{"com.microsoft.mxc.managed":"true","com.microsoft.mxc.owner-token":"foreign","com.microsoft.mxc.resource-kind":"container"}}}}}}]"#,
            plan.container.name.as_str()
        );
        let runner = FakeRunner {
            output: Mutex::new(VecDeque::from([Ok(CommandOutput {
                exit_code: Some(0),
                stdout: output.into_bytes(),
                stderr: Vec::new(),
            })])),
        };

        assert!(matches!(
            verify_ownership(&runner, &plan.container),
            Err(CliError::OwnershipMismatch { .. })
        ));
    }
}
