// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed management primitives for MXC's experimental Apple Container backend.
//!
//! This crate deliberately does not execute workloads. It defines the boundary
//! around Apple's external CLI, availability parsing, owned resource identity,
//! and lifecycle plans. The executor integration supplies the real command
//! runner in a later increment.

pub mod availability;
pub mod command;
pub mod plan;
pub mod resource;

pub use availability::{
    check_cli_installed, probe_with, AppleContainerAvailability, AppleContainerVersion, HostInfo,
    SystemStatus, APPLE_CONTAINER_CLI_PATH, APPLE_CONTAINER_RELEASES_URL,
    QUALIFIED_APPLE_CONTAINER_VERSION,
};
pub use command::{
    CliArgument, CliCommand, CommandError, CommandErrorKind, CommandOutput, CommandRunner,
    DEFAULT_COMMAND_OUTPUT_LIMIT, DEFAULT_COMMAND_TIMEOUT,
};
pub use plan::{
    CleanupPlan, EnvironmentFile, MountAccess, MountPlan, NetworkPlan, ResourceLimits, RunPlan,
};
pub use resource::{
    ContainerName, NetworkName, OwnedResource, OwnershipLabels, OwnershipToken, ResourceKind,
    ResourceName, ResourceNames,
};
