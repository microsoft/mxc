// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk;

internal sealed class StateAwareNetworkPolicyJsonConverter
    : JsonConverter<StateAwareNetworkPolicy>
{
    private static readonly string[] PropertyNames =
    [
        "egress",
        "ingress",
        "defaultPolicy",
        "allowLocalNetwork",
        "allowedHosts",
        "blockedHosts",
        "proxy",
    ];

    public override StateAwareNetworkPolicy Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("network must be an object.");
        }

        var network = new StateAwareNetworkPolicy();
        foreach (var property in document.RootElement.EnumerateObject())
        {
            var name = options.PropertyNameCaseInsensitive
                ? PropertyNames.FirstOrDefault(candidate =>
                    string.Equals(candidate, property.Name, StringComparison.OrdinalIgnoreCase))
                    ?? property.Name
                : property.Name;
            switch (name)
            {
                case "egress":
                    network.Egress = property.Value.Deserialize<NetworkEgressPolicy>(options);
                    break;
                case "ingress":
                    network.Ingress = property.Value.Deserialize<NetworkIngressPolicy>(options);
                    break;
                case "defaultPolicy":
                    network.DefaultPolicy =
                        property.Value.Deserialize<StateAwareNetworkDefault?>(options);
                    break;
                case "allowLocalNetwork":
                    network.AllowLocalNetwork = property.Value.Deserialize<bool?>(options);
                    break;
                case "allowedHosts":
                    network.AllowedHosts = property.Value.Deserialize<List<string>?>(options);
                    break;
                case "blockedHosts":
                    network.BlockedHosts = property.Value.Deserialize<List<string>?>(options);
                    break;
                case "proxy":
                    network.Proxy = property.Value.Deserialize<NetworkProxyPolicy?>(options);
                    break;
                default:
                    if (options.UnmappedMemberHandling == JsonUnmappedMemberHandling.Disallow)
                    {
                        throw new JsonException(
                            $"Unknown state-aware network field '{property.Name}'.");
                    }
                    break;
            }
        }
        return network;
    }

    public override void Write(
        Utf8JsonWriter writer,
        StateAwareNetworkPolicy value,
        JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        if (value.Egress is not null)
            WriteProperty(writer, "egress", value.Egress, options);
        if (value.Ingress is not null)
            WriteProperty(writer, "ingress", value.Ingress, options);
        if (value.HasLegacyField("defaultPolicy"))
            WriteProperty(writer, "defaultPolicy", value.DefaultPolicy, options);
        if (value.HasLegacyField("allowLocalNetwork"))
            WriteProperty(writer, "allowLocalNetwork", value.AllowLocalNetwork, options);
        if (value.HasLegacyField("allowedHosts"))
            WriteProperty(writer, "allowedHosts", value.AllowedHosts, options);
        if (value.HasLegacyField("blockedHosts"))
            WriteProperty(writer, "blockedHosts", value.BlockedHosts, options);
        if (value.HasLegacyField("proxy"))
            WriteProperty(writer, "proxy", value.Proxy, options);
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
