// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::primitives::OptionalField;

/// Placeholder development feature used to exercise feature plumbing.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestFeature {
    /// The message for the test feature.
    #[serde(default)]
    pub message: OptionalField<String>,
}

/// Compatibility settings accepted for one-shot Windows Sandbox requests.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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

string_enum! {
    /// Guest runtime for the Hyperlight backend.
    #[derive(Debug)]
    pub enum HyperlightRuntime {
        /// CPython with the data-science stack preloaded (the default).
        Agent => ["agent"],
        /// CPython.
        Python => ["python"],
        /// CPython with a BusyBox shell.
        PythonShell => ["python-shell"],
        /// Node.js.
        Node => ["node"],
        /// Bash with BusyBox.
        Bash => ["bash"],
        /// .NET with the JIT.
        DotnetJit => ["dotnet-jit"],
    }
}

/// One-shot Hyperlight backend settings.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneShotHyperlight {
    /// Guest runtime that `process.commandLine` is source for. Defaults to
    /// `agent`.
    #[serde(default)]
    pub runtime: OptionalField<HyperlightRuntime>,
}
