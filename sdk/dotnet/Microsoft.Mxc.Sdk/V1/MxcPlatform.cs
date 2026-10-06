// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Mxc.Sdk.Native;

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>
/// Host and native-library information for the MXC SDK.
/// </summary>
public static class MxcPlatform
{
    static MxcPlatform()
    {
        NativeLibraryResolver.Initialize();
    }

    /// <summary>
    /// The version of the native <c>mxc_ffi</c> library.
    /// </summary>
    public static string NativeVersion
    {
        get
        {
            unsafe
            {
                var p = NativeMethods.mxc_version();
                return p is null ? string.Empty : Marshal.PtrToStringUTF8((IntPtr)p) ?? string.Empty;
            }
        }
    }

    /// <summary>
    /// Probe every containment backend the current host can run.
    /// </summary>
    /// <remarks>
    /// This includes host-capability backends the V1 policy SDK cannot
    /// necessarily launch. Cross-check <see cref="GetPlatformSupport"/> before
    /// choosing a V1 one-shot containment backend.
    /// </remarks>
    public static IReadOnlyList<AvailableBackend> GetAvailableBackends()
    {
        unsafe
        {
            var json = ReadOwnedJson(
                NativeMethods.mxc_available_backends_json(),
                "probing available backends");
            return ParseAvailableBackends(json);
        }
    }

    /// <summary>
    /// Map the native backend-discovery array onto the public model.
    /// </summary>
    /// <remarks>
    /// Split from <see cref="GetAvailableBackends"/> so the projection is
    /// testable against a fixed native payload.
    /// </remarks>
    internal static IReadOnlyList<AvailableBackend> ParseAvailableBackends(string json)
    {
        var backends = MxcJson.Deserialize<NativeAvailableBackend[]>(json)
            ?? throw new JsonException("Native backend discovery returned null JSON.");
        return backends.Select(MapAvailableBackend).ToArray();
    }

    /// <summary>
    /// Probe whether the public SDK can launch sandboxes on this host and which
    /// backends it can launch.
    /// </summary>
    public static PlatformSupport GetPlatformSupport()
    {
        unsafe
        {
            var json = ReadOwnedJson(
                NativeMethods.mxc_platform_support_json(),
                "probing platform support");
            var support = MxcJson.Deserialize<NativePlatformSupport>(json)
                ?? throw new JsonException("Native platform support returned null JSON.");
            return new PlatformSupport
            {
                IsSupported = support.IsSupported,
                Reason = support.Reason,
                AvailableMethods = support.AvailableMethods.Select(ParseBackend).ToArray(),
            };
        }
    }

    internal static ContainmentBackend ParseBackend(string value) =>
        value switch
        {
            "processcontainer" => ContainmentBackend.ProcessContainer,
            "windows_sandbox" => ContainmentBackend.WindowsSandbox,
            "lxc" => ContainmentBackend.Lxc,
            "wslc" => ContainmentBackend.Wslc,
            "seatbelt" => ContainmentBackend.Seatbelt,
            "isolation_session" => ContainmentBackend.IsolationSession,
            "bubblewrap" => ContainmentBackend.Bubblewrap,
            "hyperlight" => ContainmentBackend.Hyperlight,
            _ => ContainmentBackend.Unknown,
        };

    internal static IsolationTier ParseIsolationTier(string value) =>
        value switch
        {
            "base-container" => IsolationTier.BaseContainer,
            "appcontainer-bfs" => IsolationTier.AppContainerBfs,
            "appcontainer-dacl" => IsolationTier.AppContainerDacl,
            _ => IsolationTier.Unknown,
        };

    internal static BackendCapability ParseBackendCapability(string value) =>
        value switch
        {
            "captureDenials" => BackendCapability.CaptureDenials,
            "filesystemDeniedPaths" => BackendCapability.FilesystemDeniedPaths,
            "filesystemEnumeratePaths" => BackendCapability.FilesystemEnumeratePaths,
            "ingressHostLoopbackAllow" => BackendCapability.IngressHostLoopbackAllow,
            "proxyEnforcement" => BackendCapability.ProxyEnforcement,
            _ => BackendCapability.Unknown,
        };

    private static AvailableBackend MapAvailableBackend(NativeAvailableBackend backend) =>
        new()
        {
            Backend = ParseBackend(backend.Backend),
            Tier = backend.Tier is null ? null : ParseIsolationTier(backend.Tier),
            Capabilities = backend.Capabilities.Select(ParseBackendCapability).ToArray(),
            Warnings = backend.Warnings.ToArray(),
        };

    private static unsafe string ReadOwnedJson(byte* value, string operation)
    {
        if (value is null)
        {
            throw new MxcException(ErrorCode.BackendError, $"{operation} failed");
        }

        try
        {
            return Marshal.PtrToStringUTF8((IntPtr)value)
                ?? throw new MxcException(
                    ErrorCode.BackendError,
                    $"{operation} returned invalid JSON");
        }
        finally
        {
            NativeMethods.mxc_string_free(value);
        }
    }
}
