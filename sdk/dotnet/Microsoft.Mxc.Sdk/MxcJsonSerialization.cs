// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Microsoft.Mxc.Sdk.V1;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// A <see cref="JsonStringEnumConverter{TEnum}"/> that renders enum members in
/// camelCase, matching the wire format the native layer expects. The generic
/// converter is Native AOT and trimming safe; the non-generic
/// <see cref="JsonStringEnumConverter"/> is not.
/// </summary>
internal sealed class CamelCaseJsonStringEnumConverter<TEnum>
    : JsonStringEnumConverter<TEnum>
    where TEnum : struct, Enum
{
    public CamelCaseJsonStringEnumConverter()
        : base(JsonNamingPolicy.CamelCase)
    {
    }
}

/// <summary>
/// Source-generated serialization metadata for every production wire/model type
/// the SDK serializes or deserializes. Using generated <see cref="JsonTypeInfo{T}"/>
/// (rather than reflection-backed <c>JsonSerializer</c> overloads) is what makes
/// the SDK Native AOT and trimming compatible.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
// Public request/policy surface.
[JsonSerializable(typeof(Generated.OneShotRequest))]
[JsonSerializable(typeof(ContainerRequest))]
[JsonSerializable(typeof(ProvisionRequest))]
[JsonSerializable(typeof(IsolationSessionProvisionRequest))]
[JsonSerializable(typeof(WslcProvisionRequest))]
[JsonSerializable(typeof(ExecutionRequest))]
[JsonSerializable(typeof(ProcessNetworkPolicy))]
[JsonSerializable(typeof(RunOptions))]
[JsonSerializable(typeof(SpawnOptions))]
[JsonSerializable(typeof(SpawnWithPtyOptions))]
[JsonSerializable(typeof(ProvisionOptions))]
[JsonSerializable(typeof(StartOptions))]
[JsonSerializable(typeof(StopOptions))]
[JsonSerializable(typeof(DeprovisionOptions))]
[JsonSerializable(typeof(SpawnInContainerOptions))]
[JsonSerializable(typeof(RunInContainerOptions))]
[JsonSerializable(typeof(SpawnInContainerWithPtyOptions))]
[JsonSerializable(typeof(MxcPtySize))]
[JsonSerializable(typeof(Containment))]
[JsonSerializable(typeof(Containment.Process), TypeInfoPropertyName = "SdkContainmentProcess")]
[JsonSerializable(typeof(Containment.ProcessContainer), TypeInfoPropertyName = "SdkContainmentProcessContainer")]
[JsonSerializable(typeof(Containment.Seatbelt), TypeInfoPropertyName = "SdkContainmentSeatbelt")]
[JsonSerializable(typeof(Containment.Lxc), TypeInfoPropertyName = "SdkContainmentLxc")]
[JsonSerializable(typeof(Containment.Bubblewrap), TypeInfoPropertyName = "SdkContainmentBubblewrap")]
[JsonSerializable(typeof(Containment.Wslc), TypeInfoPropertyName = "SdkContainmentWslc")]
[JsonSerializable(typeof(Containment.IsolationSession), TypeInfoPropertyName = "SdkContainmentIsolationSession")]
[JsonSerializable(typeof(ProcessContainerUiPolicy))]
[JsonSerializable(typeof(ProcessContainerFilesystemPolicy))]
[JsonSerializable(typeof(ProcessContainerNetworkPolicy))]
[JsonSerializable(typeof(WslcPortMapping))]
[JsonSerializable(typeof(FilesystemPolicy))]
[JsonSerializable(typeof(NetworkPolicy))]
[JsonSerializable(typeof(UiPolicy))]
[JsonSerializable(typeof(CaptureDenialsPolicy))]
[JsonSerializable(typeof(TelemetryConfig))]
// Directional network sub-objects (egress/ingress resolved through the
// non-null section converter).
[JsonSerializable(typeof(NetworkEgressPolicy))]
[JsonSerializable(typeof(NetworkIngressPolicy))]
[JsonSerializable(typeof(NetworkRuntimeConfig))]
[JsonSerializable(typeof(NetworkRulePolicy))]
[JsonSerializable(typeof(NetworkPeerPolicy))]
[JsonSerializable(typeof(NetworkPortPolicy))]
// Native discovery, output, and provision metadata.
[JsonSerializable(typeof(NativeAvailableBackend[]))]
[JsonSerializable(typeof(NativePlatformSupport))]
[JsonSerializable(typeof(NativeProbeOutput))]
[JsonSerializable(typeof(ExecutionMetadata))]
[JsonSerializable(typeof(CaptureDenialsResult))]
[JsonSerializable(typeof(CaptureDenialsError))]
[JsonSerializable(typeof(IsolationSessionProvisionMetadata))]
[JsonSerializable(typeof(ProvisionMetadata))]
[JsonSerializable(typeof(ValidationResult))]
[JsonSerializable(typeof(LifecycleResult))]
[JsonSerializable(typeof(ProvisionResult))]
[JsonSerializable(typeof(ContainerId))]
// Primitive and collection shapes resolved by the custom converters and helpers.
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(bool))]
[JsonSerializable(typeof(bool?))]
internal sealed partial class MxcJsonContext : JsonSerializerContext
{
}

/// <summary>
/// Shared, Native AOT safe JSON helpers. Every serialize/deserialize path routes
/// through a source-generated <see cref="JsonTypeInfo{T}"/> resolved from these
/// options, so nothing falls back to reflection.
/// </summary>
internal static class MxcJson
{
    /// <summary>
    /// The default options: the source-generated resolver plus camelCase naming
    /// and null-omission carried from <see cref="MxcJsonContext"/>.
    /// </summary>
    internal static readonly JsonSerializerOptions Options = CreateOptions();

    /// <summary>
    /// Options for deserializing the native request probe output. Built from the
    /// source-generated resolver (so it stays reflection-free) with strict
    /// unmapped-member handling, so an unexpected field from the native layer is
    /// rejected rather than silently ignored.
    /// </summary>
    internal static readonly JsonSerializerOptions ProbeOptions = CreateProbeOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions(MxcJsonContext.Default.Options);
        AddEnumConverters(options);
        AddNetworkSectionConverters(options);
        return options;
    }

    private static JsonSerializerOptions CreateProbeOptions()
    {
        var options = CreateOptions();
        options.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow;
        return options;
    }

    /// <summary>
    /// Registers the camelCase enum converters on <paramref name="options"/>.
    /// </summary>
    private static void AddEnumConverters(JsonSerializerOptions options)
    {
        options.Converters.Add(new CamelCaseJsonStringEnumConverter<CaptureDenialsMode>());
        options.Converters.Add(new CamelCaseJsonStringEnumConverter<NetworkAction>());
        options.Converters.Add(new CamelCaseJsonStringEnumConverter<NetworkProtocol>());
        options.Converters.Add(new CamelCaseJsonStringEnumConverter<ClipboardPolicy>());
        options.Converters.Add(new CamelCaseJsonStringEnumConverter<ProcessContainerUiIsolation>());
        options.Converters.Add(new CamelCaseJsonStringEnumConverter<ProcessContainerSystemSettings>());
    }

    /// <summary>
    /// Applies the non-null network section converter to the directional
    /// <c>egress</c>/<c>ingress</c> properties via a resolver modifier on the
    /// SDK's own options.
    /// </summary>
    private static void AddNetworkSectionConverters(JsonSerializerOptions options)
    {
        options.TypeInfoResolver = options.TypeInfoResolver!.WithAddedModifier(static typeInfo =>
        {
            foreach (var property in typeInfo.Properties)
            {
                if (property.PropertyType == typeof(NetworkEgressPolicy))
                {
                    property.CustomConverter = new NonNullNetworkSectionJsonConverter<NetworkEgressPolicy>();
                }
                else if (property.PropertyType == typeof(NetworkIngressPolicy))
                {
                    property.CustomConverter = new NonNullNetworkSectionJsonConverter<NetworkIngressPolicy>();
                }
            }
        });
    }

    /// <summary>
    /// Resolve the generated <see cref="JsonTypeInfo{T}"/> for <typeparamref name="T"/>
    /// from <paramref name="options"/>. Used by custom converters to serialize
    /// nested values without a reflection fallback.
    /// </summary>
    internal static JsonTypeInfo<T> TypeInfo<T>(JsonSerializerOptions options) =>
        (JsonTypeInfo<T>)options.GetTypeInfo(typeof(T));

    internal static string Serialize<T>(T value, JsonSerializerOptions options) =>
        JsonSerializer.Serialize(value, TypeInfo<T>(options));

    internal static JsonNode? SerializeToNode<T>(T value, JsonSerializerOptions options) =>
        JsonSerializer.SerializeToNode(value, TypeInfo<T>(options));

    internal static T? Deserialize<T>(string json, JsonSerializerOptions options) =>
        JsonSerializer.Deserialize(json, TypeInfo<T>(options));

    internal static T? Deserialize<T>(string json) => Deserialize<T>(json, Options);
}
