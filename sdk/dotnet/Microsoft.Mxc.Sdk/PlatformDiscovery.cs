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

/// <summary>
/// Result of probing which Windows ProcessContainer tier can serve a request.
/// </summary>
public sealed class ProbeOutput
{
    /// <summary>The selected tier, or null when detection failed.</summary>
    public IsolationTier? Tier { get; init; }

    /// <summary>Whether the selected tier needs DACL deny augmentation.</summary>
    public bool? NeedsDaclAugmentation { get; init; }

    /// <summary>Tier degradation warnings.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

    /// <summary>Raw host facts gathered by the detector.</summary>
    public required ProbeFacts Probes { get; init; }

    /// <summary>The detector failure, or null when detection succeeded.</summary>
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
    /// <summary>
    /// Whether this native SDK build includes IsolationSession and the host can activate it.
    /// </summary>
    public bool IsolationSessionAvailable { get; init; }

    /// <summary>
    /// Whether this native SDK build includes Hyperlight and its host runtime is available.
    /// </summary>
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
    [JsonPropertyName("tier")]
    public string? Tier { get; init; }

    [JsonPropertyName("needsDaclAugmentation")]
    public bool? NeedsDaclAugmentation { get; init; }

    [JsonPropertyName("warnings")]
    public string[] Warnings { get; init; } = [];

    [JsonPropertyName("probes")]
    public NativeProbeFacts? Probes { get; init; }

    [JsonPropertyName("error")]
    public string? Error { get; init; }
}

internal sealed class NativeProbeFacts
{
    [JsonPropertyName("baseContainerApiPresent")]
    public bool BaseContainerApiPresent { get; init; }

    [JsonPropertyName("nativeCaptureAvailable")]
    public bool NativeCaptureAvailable { get; init; }

    [JsonPropertyName("guardedCaptureAvailable")]
    public bool GuardedCaptureAvailable { get; init; }

    [JsonPropertyName("bfscfgPresent")]
    public bool BfscfgPresent { get; init; }

    [JsonPropertyName("bfsCompiledIn")]
    public bool BfsCompiledIn { get; init; }

    [JsonPropertyName("baseContainerSupportsDenyPaths")]
    public bool BaseContainerSupportsDenyPaths { get; init; }

    [JsonPropertyName("baseContainerSupportsEnumeratePaths")]
    public bool BaseContainerSupportsEnumeratePaths { get; init; }

    [JsonPropertyName("baseContainerSupportsIngressHostLoopbackAllow")]
    public bool BaseContainerSupportsIngressHostLoopbackAllow { get; init; }

    [JsonPropertyName("isolationSessionAvailable")]
    public bool IsolationSessionAvailable { get; init; }

    [JsonPropertyName("hyperlightAvailable")]
    public bool HyperlightAvailable { get; init; }

    [JsonPropertyName("uiCapabilities")]
    public NativeUiCapabilitySupport? UiCapabilities { get; init; }
}

internal sealed class NativeUiCapabilitySupport
{
    [JsonPropertyName("canBlockClipboardRead")]
    public bool CanBlockClipboardRead { get; init; }

    [JsonPropertyName("canBlockClipboardWrite")]
    public bool CanBlockClipboardWrite { get; init; }

    [JsonPropertyName("canBlockInputInjection")]
    public bool CanBlockInputInjection { get; init; }

    [JsonPropertyName("canBlockInputMethodChanges")]
    public bool CanBlockInputMethodChanges { get; init; }

    [JsonPropertyName("canBlockExternalUiObjects")]
    public bool CanBlockExternalUiObjects { get; init; }

    [JsonPropertyName("canBlockGlobalUiNamespace")]
    public bool CanBlockGlobalUiNamespace { get; init; }

    [JsonPropertyName("canBlockDesktopSwitching")]
    public bool CanBlockDesktopSwitching { get; init; }

    [JsonPropertyName("canBlockLogoffOrShutdown")]
    public bool CanBlockLogoffOrShutdown { get; init; }

    [JsonPropertyName("canBlockSystemParameterChanges")]
    public bool CanBlockSystemParameterChanges { get; init; }

    [JsonPropertyName("canBlockDisplaySettingsChanges")]
    public bool CanBlockDisplaySettingsChanges { get; init; }
}
