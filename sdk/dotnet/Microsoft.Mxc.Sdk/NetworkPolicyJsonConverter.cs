// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk;

internal sealed class NetworkPolicyJsonConverter : JsonConverter<NetworkPolicy>
{
    private readonly bool _includeLegacyDefaults;

    private static readonly string[] PropertyNames =
    [
        "allowOutbound", "allowLocalNetwork", "allowedHosts", "blockedHosts",
        "proxy", "egress", "ingress", "runtimeConfig", "defaultPolicy", "enforcementMode",
    ];

    public NetworkPolicyJsonConverter()
    {
    }

    internal NetworkPolicyJsonConverter(bool includeLegacyDefaults)
    {
        _includeLegacyDefaults = includeLegacyDefaults;
    }

    public override NetworkPolicy Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("network must be an object.");
        }

        var network = new NetworkPolicy();
        foreach (var property in document.RootElement.EnumerateObject())
        {
            var name = options.PropertyNameCaseInsensitive
                ? PropertyNames.FirstOrDefault(candidate =>
                    string.Equals(candidate, property.Name, StringComparison.OrdinalIgnoreCase))
                    ?? property.Name
                : property.Name;
            if (property.Value.ValueKind == JsonValueKind.Null
                && name is "allowOutbound" or "allowLocalNetwork" or "allowedHosts" or "blockedHosts")
            {
                throw new JsonException($"network.{name} cannot be null.");
            }
            switch (name)
            {
                case "allowOutbound":
                    network.AllowOutbound = property.Value.Deserialize<bool>(options);
                    break;
                case "allowLocalNetwork":
                    network.AllowLocalNetwork = property.Value.Deserialize<bool>(options);
                    break;
                case "allowedHosts":
                    network.AllowedHosts = property.Value.Deserialize<List<string>>(options)!;
                    break;
                case "blockedHosts":
                    network.BlockedHosts = property.Value.Deserialize<List<string>>(options)!;
                    break;
                case "proxy":
                    network.Proxy = property.Value.Deserialize<NetworkProxyPolicy>(options);
                    break;
                case "egress":
                    network.Egress = property.Value.Deserialize<NetworkEgressPolicy>(options);
                    break;
                case "ingress":
                    network.Ingress = property.Value.Deserialize<NetworkIngressPolicy>(options);
                    break;
                case "runtimeConfig":
                    network.RuntimeConfig = property.Value.Deserialize<NetworkRuntimeConfig>(options);
                    break;
                default:
                    if (options.UnmappedMemberHandling == JsonUnmappedMemberHandling.Disallow)
                    {
                        throw new JsonException($"Unknown network authoring field '{property.Name}'.");
                    }
                    if (name is "defaultPolicy" or "enforcementMode")
                    {
                        network.RecordLegacyWireField(name);
                    }
                    break;
            }
        }
        return network;
    }

    public override void Write(
        Utf8JsonWriter writer,
        NetworkPolicy value,
        JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        if (_includeLegacyDefaults || value.HasLegacyField("allowOutbound"))
            WriteProperty(writer, "allowOutbound",
                value.HasLegacyField("allowOutbound") ? value.AuthoredAllowOutbound : false, options);
        if (_includeLegacyDefaults || value.HasLegacyField("allowLocalNetwork"))
            WriteProperty(writer, "allowLocalNetwork",
                value.HasLegacyField("allowLocalNetwork") ? value.AuthoredAllowLocalNetwork : false, options);
        if (_includeLegacyDefaults || value.HasLegacyField("allowedHosts"))
            WriteProperty(writer, "allowedHosts", value.AllowedHosts, options);
        if (_includeLegacyDefaults || value.HasLegacyField("blockedHosts"))
            WriteProperty(writer, "blockedHosts", value.BlockedHosts, options);
        if (value.HasLegacyField("proxy") && (!_includeLegacyDefaults || value.Proxy is not null))
            WriteProperty(writer, "proxy", value.Proxy, options);
        if (value.Egress is not null)
            WriteProperty(writer, "egress", value.Egress, options);
        if (value.Ingress is not null)
            WriteProperty(writer, "ingress", value.Ingress, options);
        if (value.RuntimeConfig is not null)
            WriteProperty(writer, "runtimeConfig", value.RuntimeConfig, options);
        writer.WriteEndObject();
    }

    private static void WriteProperty<T>(
        Utf8JsonWriter writer,
        string name,
        T value,
        JsonSerializerOptions options)
    {
        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, options);
    }
}
