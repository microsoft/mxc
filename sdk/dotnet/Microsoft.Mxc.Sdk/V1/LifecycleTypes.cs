// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>
/// The containment backend a container is provisioned under. Selected at
/// provision; later phases resolve it from the <see cref="ContainerId"/>.
/// </summary>
public enum LifecycleContainmentKind
{
    /// <summary>Windows IsolationSession.</summary>
    IsolationSession,

    /// <summary>Windows Subsystem for Linux container.</summary>
    Wslc,
}

/// <summary>Closed request for provisioning a supported containment.</summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "containment")]
[JsonDerivedType(typeof(IsolationSessionProvisionRequest), "isolation_session")]
[JsonDerivedType(typeof(WslcProvisionRequest), "wslc")]
public abstract class ProvisionRequest
{
    private protected ProvisionRequest() { }

    internal abstract LifecycleContainmentKind Containment { get; }

    internal string? Version { get; set; }

    /// <summary>
    /// Optional per-phase telemetry request. Emission is still gated by the
    /// MXC-owned user consent and administrative policy.
    /// </summary>
    public TelemetryConfig? Telemetry { get; set; }
}

/// <summary>IsolationSession provision request.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class IsolationSessionProvisionRequest : ProvisionRequest
{
    internal override LifecycleContainmentKind Containment => LifecycleContainmentKind.IsolationSession;

    /// <summary>
    /// Creates a request with the unrestricted directional network posture
    /// required by IsolationSession.
    /// </summary>
    public IsolationSessionProvisionRequest(NetworkPolicy network)
    {
        Network = network ?? throw new ArgumentNullException(nameof(network));
    }

    /// <summary>Required directional all-allow network posture.</summary>
    public NetworkPolicy Network { get; set; }

    /// <summary>Optional packaged-app PFN or unpackaged-app identifier.</summary>
    public string? AppId { get; set; }
}

/// <summary>WSLC provision request.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class WslcProvisionRequest : ProvisionRequest
{
    internal override LifecycleContainmentKind Containment => LifecycleContainmentKind.Wslc;

    /// <summary>Host paths to mount into the container.</summary>
    public FilesystemPolicy? Filesystem { get; set; }

    /// <summary>
    /// Container network mode. Egress default, ingress default, and host loopback
    /// must all be Deny (the omitted default), or all explicitly Allow for
    /// unrestricted bridged networking. Mixed postures and filtering rules
    /// cannot be enforced.
    /// </summary>
    public NetworkPolicy? Network { get; set; }

    /// <summary>Container image reference, such as <c>alpine:latest</c>.</summary>
    public string? Image { get; set; }

    /// <summary>Optional local image archive to import instead of pulling.</summary>
    public string? ImageTarPath { get; set; }
}

/// <summary>Invocation controls for provisioning a container.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class ProvisionOptions
{
    internal string? Version { get; set; }

    /// <summary>
    /// Optional per-phase telemetry request. Emission is still gated by the
    /// MXC-owned user consent and administrative policy.
    /// </summary>
    public TelemetryConfig? Telemetry { get; set; }
}

/// <summary>Invocation controls for starting a provisioned container.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class StartOptions
{
    internal string? Version { get; set; }

    /// <summary>Optional telemetry preference, subject to consent and policy.</summary>
    public TelemetryConfig? Telemetry { get; set; }
}

/// <summary>Invocation controls for stopping a running container.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class StopOptions
{
    internal string? Version { get; set; }

    /// <summary>Optional telemetry preference, subject to consent and policy.</summary>
    public TelemetryConfig? Telemetry { get; set; }
}

/// <summary>Invocation controls for releasing a provisioned container.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class DeprovisionOptions
{
    internal string? Version { get; set; }

    /// <summary>Optional telemetry preference, subject to consent and policy.</summary>
    public TelemetryConfig? Telemetry { get; set; }
}

/// <summary>A workload and its process settings for an existing container.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class ExecutionRequest
{
    internal string? Version { get; set; }

    /// <summary>Optional telemetry preference, subject to consent and policy.</summary>
    public TelemetryConfig? Telemetry { get; set; }

    /// <summary>Create an execution request for <paramref name="command"/>.</summary>
    public ExecutionRequest(string command)
    {
        ArgumentNullException.ThrowIfNull(command);
        Command = command;
    }

    /// <summary>The command line to run in the existing container.</summary>
    public string Command { get; }

    /// <summary>Working directory inside the container.</summary>
    public string? WorkingDirectory { get; set; }

    /// <summary>Environment variables supplied to the contained process.</summary>
    /// <remarks>
    /// <see langword="null"/> gives the child the backend's default
    /// environment. A supplied dictionary — including an empty one — is used
    /// verbatim unless <see cref="InheritDefaultEnvironment"/> is set.
    /// </remarks>
    public Dictionary<string, string>? Environment { get; set; }

    /// <summary>
    /// Layer <see cref="Environment"/> on top of the backend's default
    /// environment rather than replacing it.
    /// </summary>
    public bool? InheritDefaultEnvironment { get; set; }

    /// <summary>Wall-clock timeout in milliseconds. Zero means no timeout.</summary>
    public uint? TimeoutMs { get; set; }

    /// <summary>Runtime-only network settings for this execution.</summary>
    /// <remarks>
    /// Provision-time network policy is fixed on the existing container and
    /// cannot be changed by an execution request.
    /// </remarks>
    public ProcessNetworkPolicy? Network { get; set; }
}

/// <summary>Runtime network settings available to an existing-container execution.</summary>
public sealed class ProcessNetworkPolicy
{
    /// <summary>Runtime values such as the cooperative proxy URL.</summary>
    public NetworkRuntimeConfig? RuntimeConfig { get; set; }
}

/// <summary>Warnings returned by validating an operation without executing it.</summary>
public sealed class ValidationResult
{
    /// <summary>Policy and operational warnings reported by native validation.</summary>
    public string[] Warnings { get; set; } = [];
}

/// <summary>The result of <see cref="MxcLifecycle.ProvisionContainer"/>.</summary>
public sealed class ProvisionResult
{
    /// <summary>The freshly minted container identifier.</summary>
    public ContainerId ContainerId { get; init; }

    /// <summary>Backend-specific provision metadata, when available.</summary>
    public ProvisionMetadata? Metadata { get; init; }

    /// <summary>Policy and operational warnings returned by provisioning.</summary>
    public string[] Warnings { get; set; } = [];
}

/// <summary>Result of successfully starting, stopping, or deprovisioning a container.</summary>
public sealed class LifecycleResult
{
    /// <summary>Policy and operational warnings returned by the operation.</summary>
    public string[] Warnings { get; set; } = [];
}

/// <summary>Closed backend-specific metadata returned by provisioning.</summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[JsonDerivedType(typeof(IsolationSessionProvisionMetadata), "isolationSession")]
public abstract class ProvisionMetadata
{
    private protected ProvisionMetadata() { }
}

/// <summary>Metadata returned by IsolationSession provision.</summary>
public sealed class IsolationSessionProvisionMetadata : ProvisionMetadata
{
    /// <summary>Agent account name assigned to the container.</summary>
    [JsonPropertyName("agentUserName")]
    public required string AgentUserName { get; init; }

    /// <summary>Agent account SID assigned to the container.</summary>
    [JsonPropertyName("agentUserSid")]
    public required string AgentUserSid { get; init; }

    /// <summary>Ephemeral host workspace shared with the agent.</summary>
    [JsonPropertyName("ephemeralWorkspacePath")]
    public required string EphemeralWorkspacePath { get; init; }
}
