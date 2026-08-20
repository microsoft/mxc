// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::primitives::NonEmptyString;
use super::primitives::OptionalField;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

/// Placeholder feature used to exercise experimental configuration plumbing.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestFeature {
    /// The message for the test feature.
    #[serde(default)]
    pub message: OptionalField<String>,
}

/// One-shot telemetry override.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Telemetry {
    /// Whether telemetry is enabled.
    #[serde(default)]
    pub enabled: OptionalField<bool>,
}

/// Compatibility settings accepted for one-shot Windows Sandbox requests.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneShotWindowsSandbox {
    /// Idle timeout before teardown, in milliseconds.
    #[serde(default)]
    pub idle_timeout_ms: OptionalField<u32>,
    /// Legacy idle-timeout field retained for compatibility.
    #[serde(default)]
    pub idle_timeout: OptionalField<u32>,
    /// Optional daemon named-pipe override.
    #[serde(default)]
    pub daemon_pipe_name: OptionalField<String>,
}

#[rustfmt::skip]
string_enum! {
/// Transport protocol for a WSLC port mapping.
#[derive(Debug)]
pub enum TransportProtocol {
    /// TCP transport.
    Tcp => ["tcp"],
}
}

/// A host-to-container WSLC port mapping.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortMapping {
    /// Non-zero TCP port on the Windows host.
    pub windows_port: NonZeroU16,
    /// Non-zero TCP port inside the container.
    pub container_port: NonZeroU16,
    /// Optional transport protocol. Only TCP is currently supported.
    #[serde(default)]
    pub protocol: OptionalField<TransportProtocol>,
}

/// One-shot WSLC backend settings.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneShotWslc {
    /// Target operating system inside the container.
    #[serde(default)]
    pub target_os: OptionalField<String>,
    /// Container image reference.
    #[serde(default)]
    pub image: OptionalField<String>,
    /// Path to a local image tarball to import.
    #[serde(default)]
    pub image_tar_path: OptionalField<String>,
    /// Requested virtual CPU count.
    #[serde(default)]
    pub cpu_count: OptionalField<u32>,
    /// Requested memory limit in megabytes.
    #[serde(default)]
    pub memory_mb: OptionalField<u64>,
    /// Whether GPU passthrough is enabled.
    #[serde(default)]
    pub gpu: OptionalField<bool>,
    /// Optional storage path override.
    #[serde(default)]
    pub storage_path: OptionalField<String>,
    /// Optional host-to-container TCP port mappings.
    #[serde(default)]
    pub port_mappings: OptionalField<Vec<PortMapping>>,
}

/// One-shot Apple Container backend settings.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneShotAppleContainer {
    /// OCI image reference. The image must provide `/bin/sh`.
    pub image: NonEmptyString,
    /// Requested virtual CPU count.
    #[serde(default)]
    pub cpu_count: OptionalField<NonZeroU32>,
    /// Requested memory limit in megabytes.
    #[serde(default)]
    pub memory_mb: OptionalField<NonZeroU64>,
}

/// Experimental settings.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneShotExperimental {
    /// Optional placeholder test feature.
    #[serde(default)]
    pub test: OptionalField<TestFeature>,
    /// Optional one-shot Windows Sandbox compatibility settings.
    #[serde(rename = "windows_sandbox", default)]
    pub windows_sandbox: OptionalField<OneShotWindowsSandbox>,
    /// Optional one-shot WSLC backend settings.
    #[serde(default)]
    pub wslc: OptionalField<OneShotWslc>,
    /// Optional one-shot Apple Container backend settings.
    #[serde(rename = "apple_container", default)]
    pub apple_container: OptionalField<OneShotAppleContainer>,
    /// Optional telemetry override.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}
