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

    /// <summary>Windows Sandbox.</summary>
    WindowsSandbox,

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
/// </summary>
public sealed class StateAwareNetworkPolicy
{
    /// <summary>The default action for outbound traffic.</summary>
    public StateAwareNetworkDefault? DefaultPolicy { get; set; }

    /// <summary>Whether the sandbox may reach the local network.</summary>
    public bool? AllowLocalNetwork { get; set; }

    /// <summary>Host names or IP addresses the sandbox may contact.</summary>
    public List<string>? AllowedHosts { get; set; }

    /// <summary>Host names or IP addresses the sandbox may not contact.</summary>
    public List<string>? BlockedHosts { get; set; }

    /// <summary>Optional cooperative HTTP/HTTPS proxy configuration.</summary>
    public NetworkProxyPolicy? Proxy { get; set; }
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
    /// <summary>Overrides the backend's default state-aware schema version.</summary>
    public string? Version { get; set; }

    /// <summary>
    /// Optional per-phase telemetry opt-in. Emission is still gated by the
    /// MXC-owned user consent and administrative policy.
    /// </summary>
    public bool? TelemetryEnabled { get; set; }

}

/// <summary>IsolationSession provision options.</summary>
public sealed class IsolationSessionProvisionOptions : StateAwareProvisionOptions
{
    /// <summary>
    /// Creates options with the unrestricted-network acknowledgement required
    /// by IsolationSession.
    /// </summary>
    public IsolationSessionProvisionOptions(StateAwareNetworkPolicy network)
    {
        ValidateNetwork(network, nameof(network));
        Network = network;
    }

    /// <summary>
    /// Required unrestricted posture: default allow with local network access.
    /// </summary>
    public StateAwareNetworkPolicy Network { get; set; }

    /// <summary>Optional packaged-app PFN or unpackaged-app identifier.</summary>
    public string? AppId { get; set; }

    internal static void ValidateNetwork(
        StateAwareNetworkPolicy network,
        string parameterName)
    {
        ArgumentNullException.ThrowIfNull(network, parameterName);
        if (network.DefaultPolicy != StateAwareNetworkDefault.Allow
            || network.AllowLocalNetwork != true
            || network.AllowedHosts is { Count: > 0 }
            || network.BlockedHosts is { Count: > 0 }
            || network.Proxy is not null)
        {
            throw new ArgumentException(
                "IsolationSession requires default allow with local network access, "
                    + "no host rules, and no proxy.",
                parameterName);
        }
    }
}

/// <summary>Windows Sandbox provision options.</summary>
public sealed class WindowsSandboxProvisionOptions : StateAwareProvisionOptions
{
    /// <summary>Host paths to map into the sandbox.</summary>
    public StateAwareFilesystemPolicy? Filesystem { get; set; }
}

/// <summary>WSLC provision options.</summary>
public sealed class WslcProvisionOptions : StateAwareProvisionOptions
{
    /// <summary>Host paths to mount into the container.</summary>
    public StateAwareFilesystemPolicy? Filesystem { get; set; }

    /// <summary>Container network mode.</summary>
    public StateAwareNetworkPolicy? Network { get; set; }

    /// <summary>Container image reference, such as <c>alpine:latest</c>.</summary>
    public string? Image { get; set; }

    /// <summary>Optional local image archive to import instead of pulling.</summary>
    public string? ImageTarPath { get; set; }
}

/// <summary>
/// Compatibility options for the original IsolationSession-only API. New code
/// should use <see cref="IsolationSessionProvisionOptions"/>.
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
    /// <summary>Overrides the schema version inferred from the sandbox id.</summary>
    public string? Version { get; set; }

    /// <summary>
    /// Optional per-phase telemetry opt-in. Emission is still gated by the
    /// MXC-owned user consent and administrative policy.
    /// </summary>
    public bool? TelemetryEnabled { get; set; }
}

/// <summary>
/// Compatibility alias for <see cref="StateAwarePhaseOptions"/> used at start.
/// </summary>
public sealed class StartSandboxOptions : StateAwarePhaseOptions
{
}

/// <summary>
/// Compatibility alias for <see cref="StateAwareExecOptions"/> used at exec,
/// stop, and deprovision phases. Derives from <see cref="StateAwareExecOptions"/>
/// so it is directly accepted where an exec-phase options bag is expected;
/// unused exec fields simply default to null and are elided from the wire.
/// </summary>
public sealed class StateAwareOperationOptions : StateAwareExecOptions
{
}

/// <summary>Process and schema options for a state-aware exec phase.</summary>
public class StateAwareExecOptions : StateAwarePhaseOptions
{
    /// <summary>Working directory inside the sandbox.</summary>
    public string? WorkingDirectory { get; set; }

    /// <summary>Environment variables encoded as <c>KEY=VALUE</c> strings.</summary>
    public List<string>? Environment { get; set; }

    /// <summary>Wall-clock timeout in milliseconds. Zero means no timeout.</summary>
    public uint? TimeoutMs { get; set; }
}

/// <summary>WSLC exec options, including its per-exec proxy override.</summary>
public sealed class WslcExecOptions : StateAwareExecOptions
{
    /// <summary>Optional exec-time URL proxy configuration.</summary>
    public WslcExecNetworkPolicy? Network { get; set; }
}

/// <summary>
/// WSLC's exec-time network override. Network mode is immutable after
/// provision, so only a cooperative proxy may be supplied here.
/// </summary>
public sealed class WslcExecNetworkPolicy
{
    /// <summary>Optional URL proxy injected into the process environment.</summary>
    public NetworkProxyPolicy? Proxy { get; set; }
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
