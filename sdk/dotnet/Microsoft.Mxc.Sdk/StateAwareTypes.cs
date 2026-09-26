// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// The containment backend a sandbox is provisioned under. Selected at
/// provision; later phases resolve it from the <see cref="SandboxId"/>.
/// </summary>
public enum StateAwareContainment
{
    /// <summary>Windows IsolationSession.</summary>
    IsolationSession,

    /// <summary>Windows Subsystem for Linux container.</summary>
    Wslc,
}

/// <summary>The default action for traffic with no matching rule.</summary>
public enum StateAwareNetworkDefault
{
    /// <summary>Deny traffic by default.</summary>
    Block,

    /// <summary>Allow traffic by default.</summary>
    Allow,
}

/// <summary>
/// Network posture sent on a state-aware lifecycle request. Omitted values are
/// resolved by the native backend using its fail-closed defaults.
/// The v1 high-level SDK exposes directional policy only.
/// </summary>
public sealed class StateAwareNetworkPolicy
{
    internal string? LegacyFieldSpecified { get; private set; }

    /// <summary>Directional outbound posture for WSLC provision.</summary>
    public NetworkEgressPolicy? Egress { get; set; }

    /// <summary>Directional inbound and host-loopback posture for WSLC provision.</summary>
    public NetworkIngressPolicy? Ingress { get; set; }

}

/// <summary>Filesystem posture sent on a state-aware lifecycle request.</summary>
public sealed class StateAwareFilesystemPolicy
{
    /// <summary>Paths the sandbox can read and write.</summary>
    public List<string> ReadwritePaths { get; set; } = new();

    /// <summary>Paths the sandbox can read but not write.</summary>
    public List<string> ReadonlyPaths { get; set; } = new();

    /// <summary>Paths explicitly denied, overriding broader allow rules.</summary>
    public List<string> DeniedPaths { get; set; } = new();
}

/// <summary>Base class for backend-specific provision options.</summary>
public abstract class StateAwareProvisionOptions
{
    internal string? Version { get; set; }

    /// <summary>
    /// Optional per-phase telemetry request. Emission is still gated by the
    /// MXC-owned user consent and administrative policy.
    /// </summary>
    public TelemetrySettings? Telemetry { get; set; }
}

/// <summary>IsolationSession provision options.</summary>
public sealed class IsolationSessionProvisionOptions : StateAwareProvisionOptions
{
    /// <summary>
    /// Creates options with the unrestricted directional network posture
    /// required by IsolationSession.
    /// </summary>
    public IsolationSessionProvisionOptions(StateAwareNetworkPolicy network)
    {
        Network = network ?? throw new ArgumentNullException(nameof(network));
    }

    /// <summary>Required directional all-allow network posture.</summary>
    public StateAwareNetworkPolicy Network { get; set; }

    /// <summary>Optional packaged-app PFN or unpackaged-app identifier.</summary>
    public string? AppId { get; set; }
}

/// <summary>WSLC provision options.</summary>
public sealed class WslcProvisionOptions : StateAwareProvisionOptions
{
    /// <summary>Host paths to mount into the container.</summary>
    public StateAwareFilesystemPolicy? Filesystem { get; set; }

    /// <summary>
    /// Container network mode. Egress default, ingress default, and host loopback
    /// must all be Deny (the omitted default), or all explicitly Allow for
    /// unrestricted bridged networking. Mixed postures and filtering rules
    /// cannot be enforced.
    /// </summary>
    public StateAwareNetworkPolicy? Network { get; set; }

    /// <summary>Container image reference, such as <c>alpine:latest</c>.</summary>
    public string? Image { get; set; }

    /// <summary>Optional local image archive to import instead of pulling.</summary>
    public string? ImageTarPath { get; set; }
}

/// <summary>
/// Compatibility options for the original IsolationSession-only API. New code
/// must use <see cref="IsolationSessionProvisionOptions"/>. This type raises a
/// schema-0.9 migration error; no network data is silently ignored.
/// </summary>
public sealed class ProvisionSandboxOptions : StateAwareProvisionOptions
{
    /// <summary>IsolationSession network acknowledgement.</summary>
    public StateAwareNetworkPolicy? Network { get; set; }

    /// <summary>
    /// Legacy filesystem field. IsolationSession rejects it because that
    /// backend cannot share host paths.
    /// </summary>
    public StateAwareFilesystemPolicy? Filesystem { get; set; }

    /// <summary>Optional packaged-app PFN or unpackaged-app identifier.</summary>
    public string? AppId { get; set; }
}

/// <summary>Options shared by start, stop, and deprovision phases.</summary>
public class StateAwarePhaseOptions
{
    internal string? Version { get; set; }

    /// <summary>
    /// Optional per-phase telemetry request. Emission is still gated by the
    /// MXC-owned user consent and administrative policy.
    /// </summary>
    public TelemetrySettings? Telemetry { get; set; }
}

/// <summary>Process and schema options for a state-aware exec phase.</summary>
public class StateAwareExecOptions : StateAwarePhaseOptions
{
    /// <summary>Working directory inside the sandbox.</summary>
    public string? WorkingDirectory { get; set; }

    /// <summary>Environment variables encoded as <c>KEY=VALUE</c> strings.</summary>
    /// <remarks>
    /// <see langword="null"/> gives the child the backend's default
    /// environment. A supplied list — including an empty one — is used
    /// verbatim unless <see cref="InheritDefaultEnvironment"/> is set.
    /// </remarks>
    public List<string>? Environment { get; set; }

    /// <summary>
    /// Layer <see cref="Environment"/> on top of the backend's default
    /// environment rather than replacing it.
    /// </summary>
    public bool? InheritDefaultEnvironment { get; set; }

    /// <summary>Wall-clock timeout in milliseconds. Zero means no timeout.</summary>
    public uint? TimeoutMs { get; set; }
}

/// <summary>WSLC exec options, including its per-exec proxy override.</summary>
public sealed class WslcExecOptions : StateAwareExecOptions
{
    /// <summary>Runtime values emitted at the envelope top level, without network posture.</summary>
    public NetworkRuntimeConfig? RuntimeConfig { get; set; }
}

/// <summary>The result of <see cref="MxcLifecycle.ProvisionSandbox"/>.</summary>
public sealed class ProvisionResult
{
    /// <summary>The freshly minted sandbox id.</summary>
    public SandboxId SandboxId { get; init; }

    /// <summary>Backend-typed provision metadata as raw JSON.</summary>
    public string? MetadataJson { get; init; }

    /// <summary>Typed IsolationSession metadata, when available.</summary>
    public IsolationSessionProvisionMetadata? IsolationSessionMetadata { get; init; }
}

/// <summary>Metadata returned by IsolationSession provision.</summary>
public sealed class IsolationSessionProvisionMetadata
{
    /// <summary>Sandbox agent account name.</summary>
    [JsonPropertyName("agentUserName")]
    public string? AgentUserName { get; init; }

    /// <summary>Sandbox agent account SID.</summary>
    [JsonPropertyName("agentUserSid")]
    public string? AgentUserSid { get; init; }

    /// <summary>Ephemeral host workspace shared with the agent.</summary>
    [JsonPropertyName("ephemeralWorkspacePath")]
    public string? EphemeralWorkspacePath { get; init; }
}
