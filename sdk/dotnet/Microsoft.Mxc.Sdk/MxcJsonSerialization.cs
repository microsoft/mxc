// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// A <see cref="JsonStringEnumConverter{TEnum}"/> that renders enum members in
/// camelCase, matching the wire format the native layer expects. The generic
/// converter is Native AOT and trimming safe; the non-generic
/// <see cref="JsonStringEnumConverter"/> is not.
/// 
/// We need this custom converter so we don't have to specify JsonNamingPolicy
/// in [JsonConverter(typeof())] statements.
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
[JsonSerializable(typeof(SandboxRequest))]
[JsonSerializable(typeof(SandboxPolicy))]
[JsonSerializable(typeof(SandboxContainment))]
[JsonSerializable(typeof(ProcessContainment))]
[JsonSerializable(typeof(ProcessContainerContainment))]
[JsonSerializable(typeof(SeatbeltContainment))]
[JsonSerializable(typeof(LxcContainment))]
[JsonSerializable(typeof(BubblewrapContainment))]
[JsonSerializable(typeof(WslcContainment))]
[JsonSerializable(typeof(IsolationSessionContainment))]
[JsonSerializable(typeof(ProcessContainerUiPolicy))]
[JsonSerializable(typeof(ProcessContainerFilesystemPolicy))]
[JsonSerializable(typeof(ProcessContainerNetworkPolicy))]
[JsonSerializable(typeof(WslcPortMapping))]
[JsonSerializable(typeof(FilesystemPolicy))]
[JsonSerializable(typeof(NetworkPolicy))]
[JsonSerializable(typeof(UiPolicy))]
[JsonSerializable(typeof(CaptureDenialsPolicy))]
[JsonSerializable(typeof(TelemetrySettings))]
// Network sub-objects serialized through the custom network converters.
[JsonSerializable(typeof(NetworkProxyPolicy))]
[JsonSerializable(typeof(NetworkEgressPolicy))]
[JsonSerializable(typeof(NetworkIngressPolicy))]
[JsonSerializable(typeof(NetworkRuntimeConfig))]
[JsonSerializable(typeof(NetworkRulePolicy))]
[JsonSerializable(typeof(NetworkPeerPolicy))]
[JsonSerializable(typeof(NetworkPortPolicy))]
// State-aware lifecycle cross-cutting sections.
[JsonSerializable(typeof(StateAwareNetworkPolicy))]
[JsonSerializable(typeof(StateAwareFilesystemPolicy))]
// Native discovery, output, and provision metadata.
[JsonSerializable(typeof(NativeAvailableBackend[]))]
[JsonSerializable(typeof(NativePlatformSupport))]
[JsonSerializable(typeof(NativeProbeOutput))]
[JsonSerializable(typeof(SandboxOutputMetadata))]
[JsonSerializable(typeof(CaptureDenialsOutput))]
[JsonSerializable(typeof(CaptureDenialsErrorOutput))]
[JsonSerializable(typeof(IsolationSessionProvisionMetadata))]
// Primitive and collection shapes resolved by the custom converters and helpers.
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(bool))]
[JsonSerializable(typeof(bool?))]
[JsonSerializable(typeof(StateAwareNetworkDefault))]
[JsonSerializable(typeof(StateAwareNetworkDefault?))]
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
    /// and null-omission carried from <see cref="MxcJsonContext"/>. Type-level
    /// <c>[JsonConverter]</c> attributes supply the custom network converters.
    /// </summary>
    internal static readonly JsonSerializerOptions Options =
        new(MxcJsonContext.Default.Options);

    /// <summary>
    /// Options for serializing published (0.6–0.8) policies, which emit the
    /// legacy network default fields. The options-level converter overrides the
    /// type-level attribute for <see cref="NetworkPolicy"/>.
    /// </summary>
    internal static readonly JsonSerializerOptions PublishedPolicyOptions =
        CreatePublishedPolicyOptions();

    /// <summary>
    /// Options for deserializing the native request probe output. Built from the
    /// source-generated resolver (so it stays reflection-free) with strict
    /// unmapped-member handling, so an unexpected field from the native layer is
    /// rejected rather than silently ignored.
    /// </summary>
    internal static readonly JsonSerializerOptions ProbeOptions =
        new(MxcJsonContext.Default.Options)
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };

    private static JsonSerializerOptions CreatePublishedPolicyOptions()
    {
        var options = new JsonSerializerOptions(MxcJsonContext.Default.Options);
        options.Converters.Add(new NetworkPolicyJsonConverter(includeLegacyDefaults: true));
        return options;
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
