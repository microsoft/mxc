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

/// Per-application tamper-protection policy for one-shot requests.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TamperProtection {
    /// Master switch (default true).
    #[serde(default)]
    pub enabled: OptionalField<bool>,
    /// Debugger-attach controls.
    #[serde(default)]
    pub debug_protection: OptionalField<DebugProtection>,
    /// Cross-compartment UI controls.
    #[serde(default)]
    pub ui_protection: OptionalField<UiProtection>,
    /// Process and cross-instance isolation controls.
    #[serde(default)]
    pub process_protection: OptionalField<ProcessProtection>,
    /// Code-signing requirements.
    #[serde(default)]
    pub require_signing: OptionalField<RequireSigning>,
}

/// Debugger-attach controls and entitlement requirements.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DebugProtection {
    #[serde(default)]
    pub allow_debugging: OptionalField<bool>,
    #[serde(default)]
    pub require_entitlement: OptionalField<bool>,
    #[serde(default)]
    pub use_specific_entitlement: OptionalField<bool>,
    #[serde(default)]
    pub entitlement: OptionalField<DebugEntitlement>,
}

/// Explicit entitlement required of a debugger.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DebugEntitlement {
    #[serde(default)]
    pub required_signing_level: OptionalField<SigningLevel>,
    #[serde(default)]
    pub required_sids: OptionalField<Vec<String>>,
}

/// Cross-compartment UI interactions.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UiProtection {
    #[serde(default)]
    pub block_ui_access: OptionalField<bool>,
    #[serde(default)]
    pub allow_external_hook: OptionalField<bool>,
    #[serde(default)]
    pub allow_handle_access: OptionalField<bool>,
    #[serde(default)]
    pub allow_window_messages: OptionalField<bool>,
    #[serde(default)]
    pub allow_synthetic_input: OptionalField<bool>,
}

/// Process isolation and cross-instance access.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessProtection {
    #[serde(default)]
    pub never_inherit_from_parent: OptionalField<bool>,
    #[serde(default)]
    pub allow_inherit_from_any_identity: OptionalField<bool>,
    #[serde(default)]
    pub share_instance_with_children: OptionalField<bool>,
    #[serde(default)]
    pub cross_instance_access: OptionalField<CrossInstanceAccess>,
}

/// Access between instances of the same application.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossInstanceAccess {
    #[serde(default)]
    pub read_virtual_memory: OptionalField<bool>,
    #[serde(default)]
    pub duplicate_handle: OptionalField<bool>,
}

/// Signing requirements for the process and its libraries.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequireSigning {
    #[serde(default)]
    pub executable: OptionalField<bool>,
    #[serde(default)]
    pub libraries: OptionalField<bool>,
    #[serde(default)]
    pub required_signing_level: OptionalField<SigningLevel>,
}

string_enum! {
    /// Minimum trust level required of a signer.
    #[derive(Debug)]
    pub enum SigningLevel {
        None => ["none"],
        Authenticode => ["authenticode"],
        Store => ["store"],
        Microsoft => ["microsoft"],
        Windows => ["windows"],
    }
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
