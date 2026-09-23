// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Trimming- and NativeAOT-safe JSON configuration shared by the SDK.
/// </summary>
/// <remarks>
/// Every serialized shape is resolved through the source-generated
/// <see cref="MxcJsonContext"/>, so the SDK never falls back to reflection-based
/// metadata. Options keep their runtime naming policy, ignore condition, and
/// converters; the context supplies only the type metadata.
/// </remarks>
internal static class MxcJson
{
    /// <summary>
    /// Equivalent of <see cref="JsonSerializerOptions.Default"/> for native
    /// output documents that are read without SDK-specific settings.
    /// </summary>
    internal static readonly JsonSerializerOptions DefaultOptions = new()
    {
        TypeInfoResolver = MxcJsonContext.Default,
    };

    internal static JsonSerializerOptions CreateOptions(JsonNamingPolicy? propertyNamingPolicy)
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = propertyNamingPolicy,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            TypeInfoResolver = MxcJsonContext.Default,
        };

        // The non-generic JsonStringEnumConverter constructs its per-enum
        // converter with MakeGenericType, which NativeAOT cannot compile ahead
        // of time. Each serialized enum is therefore listed explicitly.
        options.Converters.Add(new JsonStringEnumConverter<CaptureDenialsMode>(JsonNamingPolicy.CamelCase));
        options.Converters.Add(new JsonStringEnumConverter<ClipboardPolicy>(JsonNamingPolicy.CamelCase));
        options.Converters.Add(new JsonStringEnumConverter<NetworkAction>(JsonNamingPolicy.CamelCase));
        options.Converters.Add(new JsonStringEnumConverter<NetworkProtocol>(JsonNamingPolicy.CamelCase));
        options.Converters.Add(new JsonStringEnumConverter<ProcessContainerSystemSettings>(JsonNamingPolicy.CamelCase));
        options.Converters.Add(new JsonStringEnumConverter<ProcessContainerUiIsolation>(JsonNamingPolicy.CamelCase));
        options.Converters.Add(new JsonStringEnumConverter<StateAwareNetworkDefault>(JsonNamingPolicy.CamelCase));
        options.Converters.Add(new NetworkProxyPolicyJsonConverter());
        return options;
    }

    internal static JsonTypeInfo<T> TypeInfo<T>(JsonSerializerOptions options) =>
        (JsonTypeInfo<T>)options.GetTypeInfo(typeof(T));

    /// <summary>
    /// Reads a native output-metadata document with the defaults the public
    /// model declares.
    /// </summary>
    /// <remarks>
    /// Source-generated metadata binds init-only properties like constructor
    /// parameters, so a member the native document omits would arrive as
    /// <see langword="null"/> rather than the declared <see cref="string.Empty"/>.
    /// Rebuilding the objects keeps the public non-nullable contract.
    /// </remarks>
    internal static SandboxOutputMetadata? ReadOutputMetadata(string json)
    {
        var parsed = JsonSerializer.Deserialize(json, TypeInfo<SandboxOutputMetadata>(DefaultOptions));
        if (parsed is null)
        {
            return null;
        }

        return new SandboxOutputMetadata
        {
            CaptureDenials = parsed.CaptureDenials is { } capture
                ? new CaptureDenialsOutput
                {
                    Type = capture.Type ?? string.Empty,
                    OutputPath = capture.OutputPath ?? string.Empty,
                    ExitCode = capture.ExitCode,
                    TotalDenials = capture.TotalDenials,
                    DeniedResourcesTruncated = capture.DeniedResourcesTruncated,
                    EtlPath = capture.EtlPath,
                }
                : null,
            CaptureDenialsError = parsed.CaptureDenialsError is { } error
                ? new CaptureDenialsErrorOutput
                {
                    Message = error.Message ?? string.Empty,
                    EtlPath = error.EtlPath ?? string.Empty,
                }
                : null,
        };
    }
}

[JsonSerializable(typeof(SandboxPolicy))]
[JsonSerializable(typeof(SandboxRequest))]
[JsonSerializable(typeof(SandboxContainment))]
[JsonSerializable(typeof(ProcessContainment))]
[JsonSerializable(typeof(ProcessContainerContainment))]
[JsonSerializable(typeof(SeatbeltContainment))]
[JsonSerializable(typeof(LxcContainment))]
[JsonSerializable(typeof(BubblewrapContainment))]
[JsonSerializable(typeof(WslcContainment))]
[JsonSerializable(typeof(IsolationSessionContainment))]
[JsonSerializable(typeof(NetworkPolicy))]
[JsonSerializable(typeof(NetworkProxyPolicy))]
[JsonSerializable(typeof(NetworkEgressPolicy))]
[JsonSerializable(typeof(NetworkIngressPolicy))]
[JsonSerializable(typeof(NetworkRuntimeConfig))]
[JsonSerializable(typeof(StateAwareNetworkPolicy))]
[JsonSerializable(typeof(StateAwareFilesystemPolicy))]
[JsonSerializable(typeof(StateAwareNetworkDefault?))]
[JsonSerializable(typeof(TelemetrySettings))]
[JsonSerializable(typeof(WslcExecNetworkPolicy))]
[JsonSerializable(typeof(IsolationSessionProvisionMetadata))]
[JsonSerializable(typeof(NativeAvailableBackend[]))]
[JsonSerializable(typeof(NativePlatformSupport))]
[JsonSerializable(typeof(SandboxOutputMetadata))]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(bool))]
[JsonSerializable(typeof(bool?))]
[JsonSerializable(typeof(JsonElement?))]
internal sealed partial class MxcJsonContext : JsonSerializerContext;
