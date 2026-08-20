// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed management primitives for MXC's experimental Apple Container backend.
//!
//! This crate deliberately does not execute workloads. It defines the boundary
//! around Apple's external CLI, availability parsing, owned resource identity,
//! and lifecycle plans. The executor integration supplies the real command
//! runner in a later increment.

pub mod availability;
pub mod cli;
pub mod command;
pub mod plan;
pub mod policy;
#[cfg(target_os = "macos")]
pub mod recovery;
pub mod resource;
#[cfg(target_os = "macos")]
pub mod runtime;

pub use availability::{
    check_cli_installed, is_available, probe, probe_with, AppleContainerAvailability,
    AppleContainerVersion, HostInfo, SystemStatus, APPLE_CONTAINER_CLI_PATH,
    APPLE_CONTAINER_RELEASES_URL, QUALIFIED_APPLE_CONTAINER_VERSION,
};
pub use command::{
    CliArgument, CliCommand, CommandError, CommandErrorKind, CommandOutput, CommandRunner,
    SystemCommandRunner, DEFAULT_COMMAND_OUTPUT_LIMIT, DEFAULT_COMMAND_TIMEOUT,
};
pub use plan::{
    CleanupPlan, EnvironmentFile, MountAccess, MountPlan, NetworkPlan, ResourceLimits, RunPlan,
};
pub use policy::{build_run_plan, validate_policy, PolicyError};
pub use resource::{
    ContainerName, NetworkName, OwnedResource, OwnershipLabels, OwnershipToken, ResourceKind,
    ResourceName, ResourceNames,
};
#[cfg(target_os = "macos")]
pub use runtime::AppleContainerBackend;
