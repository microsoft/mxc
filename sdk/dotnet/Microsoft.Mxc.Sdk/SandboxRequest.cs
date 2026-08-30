// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// A complete one-shot sandbox request. This is the managed counterpart of the
/// Rust SDK's request built by <c>build_request_with_containment</c>.
/// </summary>
public sealed class SandboxRequest
{
    /// <summary>Create a request for <paramref name="command"/> under <paramref name="policy"/>.</summary>
    public SandboxRequest(SandboxPolicy policy, string command)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(command);
        Policy = policy;
        Command = command;
    }

    /// <summary>The cross-platform restrictions applied to the sandbox.</summary>
    [JsonPropertyName("policy")]
    public SandboxPolicy Policy { get; }

    /// <summary>The command line to run.</summary>
    [JsonPropertyName("command")]
    public string Command { get; }

    /// <summary>The containment backend and its backend-specific configuration.</summary>
    [JsonPropertyName("containment")]
    public SandboxContainment Containment { get; set; } = new ProcessContainment();

    /// <summary>An optional caller-selected container name.</summary>
    [JsonPropertyName("containerName")]
    public string? ContainerName { get; set; }

    /// <summary>An optional initial working directory.</summary>
    [JsonPropertyName("workingDirectory")]
    public string? WorkingDirectory { get; set; }

    /// <summary>Environment variables supplied to the sandboxed process.</summary>
    [JsonPropertyName("environment")]
    public Dictionary<string, string> Environment { get; set; } = new();

    /// <summary>Opt in to experimental containment backends and features.</summary>
    [JsonPropertyName("experimental")]
    public bool Experimental { get; set; }
}

/// <summary>A containment backend selected by a <see cref="SandboxRequest"/>.</summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(ProcessContainment), "process")]
[JsonDerivedType(typeof(ProcessContainerContainment), "processContainer")]
[JsonDerivedType(typeof(WslcContainment), "wslc")]
public abstract class SandboxContainment;

/// <summary>
/// The host's native process-isolation backend: ProcessContainer on Windows,
/// Bubblewrap on Linux, and Seatbelt on macOS.
/// </summary>
public sealed class ProcessContainment : SandboxContainment;

/// <summary>Explicit Windows ProcessContainer configuration.</summary>
public sealed class ProcessContainerContainment : SandboxContainment
{
    /// <summary>Enable least-privilege process creation.</summary>
    [JsonPropertyName("leastPrivilege")]
    public bool LeastPrivilege { get; set; }

    /// <summary>Enable deny-and-record AppContainer learning mode.</summary>
    [JsonPropertyName("learningMode")]
    public bool LearningMode { get; set; }

    /// <summary>Additional AppContainer capability names.</summary>
    [JsonPropertyName("capabilities")]
    public List<string> Capabilities { get; set; } = new();

    /// <summary>Optional denial-capture configuration.</summary>
    [JsonPropertyName("captureDenials")]
    public CaptureDenialsPolicy? CaptureDenials { get; set; }

    /// <summary>BaseProcessContainer-specific UI isolation.</summary>
    [JsonPropertyName("ui")]
    public ProcessContainerUiPolicy? Ui { get; set; } = new();

    /// <summary>ProcessContainer-specific directional network settings.</summary>
    [JsonPropertyName("network")]
    public ProcessContainerNetworkPolicy? Network { get; set; }
}

/// <summary>ProcessContainer desktop-resource isolation level.</summary>
public enum ProcessContainerUiIsolation
{
    /// <summary>Isolate the desktop.</summary>
    Desktop,

    /// <summary>Isolate desktop handles.</summary>
    Handles,

    /// <summary>Isolate desktop atoms.</summary>
    Atoms,

    /// <summary>Use the complete container UI isolation posture.</summary>
    Container,
}

/// <summary>ProcessContainer system-settings access level.</summary>
public enum ProcessContainerSystemSettings
{
    /// <summary>Allow parameter and display-setting changes.</summary>
    All,

    /// <summary>Allow parameter changes only.</summary>
    Parameters,

    /// <summary>Allow display-setting changes only.</summary>
    Display,

    /// <summary>Block parameter and display-setting changes.</summary>
    None,
}

/// <summary>BaseProcessContainer-specific UI settings.</summary>
public sealed class ProcessContainerUiPolicy
{
    /// <summary>Desktop-resource isolation level.</summary>
    [JsonPropertyName("isolation")]
    public ProcessContainerUiIsolation Isolation { get; set; } =
        ProcessContainerUiIsolation.Container;

    /// <summary>Permit desktop system control.</summary>
    [JsonPropertyName("desktopSystemControl")]
    public bool DesktopSystemControl { get; set; }

    /// <summary>System-settings access level.</summary>
    [JsonPropertyName("systemSettings")]
    public ProcessContainerSystemSettings SystemSettings { get; set; } =
        ProcessContainerSystemSettings.None;

    /// <summary>Permit Input Method Editor access.</summary>
    [JsonPropertyName("ime")]
    public bool Ime { get; set; }
}

/// <summary>ProcessContainer-specific directional network settings.</summary>
public sealed class ProcessContainerNetworkPolicy
{
    /// <summary>
    /// Package family name or AppContainer profile authorized to connect to the
    /// runtime proxy.
    /// </summary>
    [JsonPropertyName("allowedProxyPeer")]
    public string? AllowedProxyPeer { get; set; }
}

/// <summary>Experimental WSL Container backend configuration.</summary>
public sealed class WslcContainment : SandboxContainment
{
    /// <summary>Container image reference.</summary>
    [JsonPropertyName("image")]
    public string Image { get; set; } = "alpine:latest";

    /// <summary>Optional image archive imported when the image is not cached.</summary>
    [JsonPropertyName("imageTarPath")]
    public string? ImageTarPath { get; set; }

    /// <summary>Requested virtual CPU count, or null for the host default.</summary>
    [JsonPropertyName("cpuCount")]
    public uint? CpuCount { get; set; }

    /// <summary>Requested memory in MB, or null for the host default.</summary>
    [JsonPropertyName("memoryMb")]
    public ulong? MemoryMb { get; set; }

    /// <summary>Enable GPU passthrough.</summary>
    [JsonPropertyName("gpu")]
    public bool Gpu { get; set; }

    /// <summary>Optional WSLC image-store path.</summary>
    [JsonPropertyName("storagePath")]
    public string? StoragePath { get; set; }

    /// <summary>Host-to-container TCP port mappings.</summary>
    [JsonPropertyName("portMappings")]
    public List<WslcPortMapping> PortMappings { get; set; } = new();
}

/// <summary>A WSLC host-to-container TCP port mapping.</summary>
public sealed class WslcPortMapping
{
    /// <summary>Create a TCP port mapping.</summary>
    public WslcPortMapping(int windowsPort, int containerPort)
    {
        WindowsPort = ValidatePort(windowsPort, nameof(windowsPort));
        ContainerPort = ValidatePort(containerPort, nameof(containerPort));
    }

    /// <summary>The listening port on the Windows host.</summary>
    [JsonPropertyName("windowsPort")]
    public ushort WindowsPort { get; }

    /// <summary>The destination port in the container.</summary>
    [JsonPropertyName("containerPort")]
    public ushort ContainerPort { get; }

    private static ushort ValidatePort(int port, string parameterName)
    {
        if (port is < 1 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                port,
                $"Port must be between 1 and {ushort.MaxValue}.");
        }
        return (ushort)port;
    }
}
