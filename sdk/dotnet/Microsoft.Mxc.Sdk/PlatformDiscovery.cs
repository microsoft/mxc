// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk;

/// <summary>A containment backend reported by native host discovery.</summary>
public enum ContainmentBackend
{
    /// <summary>A backend introduced by a newer native library.</summary>
    Unknown,

    /// <summary>Windows ProcessContainer (BaseContainer or AppContainer).</summary>
    ProcessContainer,

    /// <summary>Windows Sandbox.</summary>
    WindowsSandbox,

    /// <summary>Linux LXC.</summary>
    Lxc,

    /// <summary>Windows WSL Container.</summary>
    Wslc,

    /// <summary>macOS Seatbelt.</summary>
    Seatbelt,

    /// <summary>Windows IsolationSession.</summary>
    IsolationSession,

    /// <summary>Linux Bubblewrap.</summary>
    Bubblewrap,

    /// <summary>Windows Hyperlight micro-VM.</summary>
    Hyperlight,
}

/// <summary>The effective Windows ProcessContainer isolation tier.</summary>
public enum IsolationTier
{
    /// <summary>An isolation tier introduced by a newer native library.</summary>
    Unknown,

    /// <summary>BaseProcessContainer, the strongest ProcessContainer tier.</summary>
    BaseContainer,

    /// <summary>AppContainer with bind-filter filesystem isolation.</summary>
    AppContainerBfs,

    /// <summary>AppContainer with DACL-based filesystem isolation.</summary>
    AppContainerDacl,
}

/// <summary>An optional feature supported by a backend on the current host.</summary>
public enum BackendCapability
{
    /// <summary>A capability introduced by a newer native library.</summary>
    Unknown,

    /// <summary>Windows ProcessContainer denial capture.</summary>
    CaptureDenials,

    /// <summary>Bubblewrap proxy-only egress in a private network namespace.</summary>
    ProxyEnforcement,
}

/// <summary>One host-available backend and its probed capabilities.</summary>
public sealed class AvailableBackend
{
    /// <summary>The containment backend.</summary>
    public required ContainmentBackend Backend { get; init; }

    /// <summary>
    /// The strongest isolation tier the host can reach for this backend, or
    /// <see langword="null"/> when the backend has no tier ladder.
    /// </summary>
    public IsolationTier? Tier { get; init; }

    /// <summary>Optional backend features usable on this host.</summary>
    public IReadOnlyList<BackendCapability> Capabilities { get; init; } =
        Array.Empty<BackendCapability>();

    /// <summary>
    /// Why an optional capability is absent from <see cref="Capabilities"/>.
    /// </summary>
    /// <remarks>
    /// On a host that cannot enforce Bubblewrap proxy-only egress this carries
    /// the probe's reason — which dependency is missing or unusable. It is the
    /// only actionable detail such a host reports, so it is surfaced rather
    /// than collapsed into the absent capability.
    /// </remarks>
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}

/// <summary>Support for the containment backends the public SDK can launch.</summary>
public sealed class PlatformSupport
{
    /// <summary>Whether the public SDK can launch a sandbox on this host.</summary>
    public bool IsSupported { get; init; }

    /// <summary>Why the host is unsupported, when <see cref="IsSupported"/> is false.</summary>
    public string? Reason { get; init; }

    /// <summary>Backends the public SDK can launch on this host.</summary>
    public IReadOnlyList<ContainmentBackend> AvailableMethods { get; init; } =
        Array.Empty<ContainmentBackend>();
}

internal sealed class NativeAvailableBackend
{
    [JsonPropertyName("backend")]
    public string Backend { get; init; } = string.Empty;

    [JsonPropertyName("tier")]
    public string? Tier { get; init; }

    [JsonPropertyName("capabilities")]
    public string[] Capabilities { get; init; } = [];

    [JsonPropertyName("warnings")]
    public string[] Warnings { get; init; } = [];
}

internal sealed class NativePlatformSupport
{
    [JsonPropertyName("isSupported")]
    public bool IsSupported { get; init; }

    [JsonPropertyName("reason")]
    public string? Reason { get; init; }

    [JsonPropertyName("availableMethods")]
    public string[] AvailableMethods { get; init; } = [];
}
