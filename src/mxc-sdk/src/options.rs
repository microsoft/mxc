// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Compatibility preference; does not control Required telemetry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TelemetryConfig {
    /// Preserved in the request; Required collection ignores this value.
    pub enabled: Option<bool>,
}

/// Invocation controls for captured container execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunOptions {
    /// Compatibility preference; does not control Required telemetry.
    pub telemetry: Option<TelemetryConfig>,
}

/// Invocation controls for spawning a live process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpawnOptions {
    /// Compatibility preference; does not control Required telemetry.
    pub telemetry: Option<TelemetryConfig>,
}

/// Invocation controls for spawning a caller-controlled terminal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpawnWithPtyOptions {
    /// Compatibility preference; does not control Required telemetry.
    pub telemetry: Option<TelemetryConfig>,
    pub size: crate::sandbox::MxcPtySize,
}

/// Invocation controls for provisioning a container.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProvisionOptions {
    pub telemetry: Option<TelemetryConfig>,
}
/// Invocation controls for starting a container.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StartOptions {
    pub telemetry: Option<TelemetryConfig>,
}
/// Invocation controls for stopping a container.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StopOptions {
    pub telemetry: Option<TelemetryConfig>,
}
/// Invocation controls for releasing a container.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeprovisionOptions {
    pub telemetry: Option<TelemetryConfig>,
}
/// Invocation controls for live execution in an existing container.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpawnInContainerOptions {
    pub telemetry: Option<TelemetryConfig>,
}
/// Invocation controls for captured execution in an existing container.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunInContainerOptions {
    pub telemetry: Option<TelemetryConfig>,
}
/// Invocation controls for a terminal in an existing container.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpawnInContainerWithPtyOptions {
    pub telemetry: Option<TelemetryConfig>,
    pub size: crate::sandbox::MxcPtySize,
}
