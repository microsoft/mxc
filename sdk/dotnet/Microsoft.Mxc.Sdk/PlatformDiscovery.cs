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

    /// <summary>Hyperlight micro-VM.</summary>
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
    Unknown = 0,

    /// <summary>Windows ProcessContainer denial capture.</summary>
    CaptureDenials = 1,

    /// <summary>Bubblewrap proxy-only egress in a private network namespace.</summary>
    ProxyEnforcement = 2,

    /// <summary>
    /// Native filesystem denied-path enforcement at the reported tier.
    /// </summary>
    FilesystemDeniedPaths = 3,

    /// <summary>
    /// Host-loopback allow enforcement at the reported tier.
    /// </summary>
    IngressHostLoopbackAllow = 4,

    /// <summary>
    /// Native filesystem enumeration-only access at the reported tier.
    /// </summary>
    FilesystemEnumeratePaths = 5,
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

    /// <summary>
    /// Optional backend features supported by <see cref="Tier"/>.
    /// </summary>
    public IReadOnlyList<BackendCapability> Capabilities { get; init; } =
        Array.Empty<BackendCapability>();

    /// <summary>
    /// Diagnostics for a capability this host cannot offer.
    /// </summary>
    /// <remarks>
    /// Not populated for every absent capability — only checks that produce a
    /// reason contribute. Bubblewrap's
    /// <see cref="BackendCapability.ProxyEnforcement"/> does, carrying which
    /// dependency is missing or unusable; Windows omits
    /// <see cref="BackendCapability.CaptureDenials"/> without a warning.
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

/// <summary>Result of probing which Windows ProcessContainer tier can serve a request.</summary>
public sealed class ProbeOutput
{
    public IsolationTier? Tier { get; init; }
    public bool? NeedsDaclAugmentation { get; init; }
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    public required ProbeFacts Probes { get; init; }
    public string? Error { get; init; }
}

/// <summary>Raw host facts used by request tier selection.</summary>
public sealed class ProbeFacts
{
    public bool BaseContainerApiPresent { get; init; }
    public bool NativeCaptureAvailable { get; init; }
    public bool GuardedCaptureAvailable { get; init; }
    public bool BfscfgPresent { get; init; }
    public bool BfsCompiledIn { get; init; }
    public bool BaseContainerSupportsDenyPaths { get; init; }
    public bool BaseContainerSupportsEnumeratePaths { get; init; }
    public bool BaseContainerSupportsIngressHostLoopbackAllow { get; init; }
    public bool IsolationSessionAvailable { get; init; }
    public bool HyperlightAvailable { get; init; }
    public required UiCapabilitySupport UiCapabilities { get; init; }
}

/// <summary>Host support for enforcing sandbox UI restrictions.</summary>
public sealed class UiCapabilitySupport
{
    public bool CanBlockClipboardRead { get; init; }
    public bool CanBlockClipboardWrite { get; init; }
    public bool CanBlockInputInjection { get; init; }
    public bool CanBlockInputMethodChanges { get; init; }
    public bool CanBlockExternalUiObjects { get; init; }
    public bool CanBlockGlobalUiNamespace { get; init; }
    public bool CanBlockDesktopSwitching { get; init; }
    public bool CanBlockLogoffOrShutdown { get; init; }
    public bool CanBlockSystemParameterChanges { get; init; }
    public bool CanBlockDisplaySettingsChanges { get; init; }
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

internal sealed class NativeProbeOutput
{
    private string? tier;
    private bool? needsDaclAugmentation;
    private string? error;

    internal bool HasTier { get; private set; }
    internal bool HasNeedsDaclAugmentation { get; private set; }
    internal bool HasError { get; private set; }

    [JsonPropertyName("tier")]
    public string? Tier
    {
        get => tier;
        init
        {
            tier = value;
            HasTier = true;
        }
    }

    [JsonPropertyName("needsDaclAugmentation")]
    public bool? NeedsDaclAugmentation
    {
        get => needsDaclAugmentation;
        init
        {
            needsDaclAugmentation = value;
            HasNeedsDaclAugmentation = true;
        }
    }

    [JsonRequired]
    [JsonPropertyName("warnings")]
    public string?[]? Warnings { get; init; }

    [JsonRequired]
    [JsonPropertyName("probes")]
    public NativeProbeFacts? Probes { get; init; }

    [JsonPropertyName("error")]
    public string? Error
    {
        get => error;
        init
        {
            error = value;
            HasError = true;
        }
    }
}

internal sealed class NativeProbeFacts
{
    [JsonRequired]
    [JsonPropertyName("baseContainerApiPresent")]
    public bool BaseContainerApiPresent { get; init; }

    [JsonRequired]
    [JsonPropertyName("nativeCaptureAvailable")]
    public bool NativeCaptureAvailable { get; init; }

    [JsonRequired]
    [JsonPropertyName("guardedCaptureAvailable")]
    public bool GuardedCaptureAvailable { get; init; }

    [JsonRequired]
    [JsonPropertyName("bfscfgPresent")]
    public bool BfscfgPresent { get; init; }

    [JsonRequired]
    [JsonPropertyName("bfsCompiledIn")]
    public bool BfsCompiledIn { get; init; }

    [JsonRequired]
    [JsonPropertyName("baseContainerSupportsDenyPaths")]
    public bool BaseContainerSupportsDenyPaths { get; init; }

    [JsonRequired]
    [JsonPropertyName("baseContainerSupportsEnumeratePaths")]
    public bool BaseContainerSupportsEnumeratePaths { get; init; }

    [JsonRequired]
    [JsonPropertyName("baseContainerSupportsIngressHostLoopbackAllow")]
    public bool BaseContainerSupportsIngressHostLoopbackAllow { get; init; }

    [JsonRequired]
    [JsonPropertyName("isolationSessionAvailable")]
    public bool IsolationSessionAvailable { get; init; }

    [JsonRequired]
    [JsonPropertyName("hyperlightAvailable")]
    public bool HyperlightAvailable { get; init; }

    [JsonRequired]
    [JsonPropertyName("uiCapabilities")]
    public NativeUiCapabilitySupport? UiCapabilities { get; init; }
}

internal sealed class NativeUiCapabilitySupport
{
    [JsonRequired]
    [JsonPropertyName("canBlockClipboardRead")]
    public bool CanBlockClipboardRead { get; init; }

    [JsonRequired]
    [JsonPropertyName("canBlockClipboardWrite")]
    public bool CanBlockClipboardWrite { get; init; }

    [JsonRequired]
    [JsonPropertyName("canBlockInputInjection")]
    public bool CanBlockInputInjection { get; init; }

    [JsonRequired]
    [JsonPropertyName("canBlockInputMethodChanges")]
    public bool CanBlockInputMethodChanges { get; init; }

    [JsonRequired]
    [JsonPropertyName("canBlockExternalUiObjects")]
    public bool CanBlockExternalUiObjects { get; init; }

    [JsonRequired]
    [JsonPropertyName("canBlockGlobalUiNamespace")]
    public bool CanBlockGlobalUiNamespace { get; init; }

    [JsonRequired]
    [JsonPropertyName("canBlockDesktopSwitching")]
    public bool CanBlockDesktopSwitching { get; init; }

    [JsonRequired]
    [JsonPropertyName("canBlockLogoffOrShutdown")]
    public bool CanBlockLogoffOrShutdown { get; init; }

    [JsonRequired]
    [JsonPropertyName("canBlockSystemParameterChanges")]
    public bool CanBlockSystemParameterChanges { get; init; }

    [JsonRequired]
    [JsonPropertyName("canBlockDisplaySettingsChanges")]
    public bool CanBlockDisplaySettingsChanges { get; init; }
}
