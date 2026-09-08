// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk;

internal sealed class NetworkProxyPolicyJsonConverter : JsonConverter<NetworkProxyPolicy>
{
    public NetworkProxyPolicyJsonConverter()
    {
    }

    public override NetworkProxyPolicy Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.GetRawText() == "{}")
        {
            throw new JsonException(
                "network.proxy must set exactly one of localhost or url.");
        }

        NetworkProxyPolicy? proxy = null;
        foreach (var property in root.EnumerateObject())
        {
            if (proxy is not null)
            {
                throw new JsonException(
                    "network.proxy must set exactly one of localhost or url.");
            }

            proxy = property.Name switch
            {
                "localhost" => new LocalhostNetworkProxyPolicy(property.Value.GetInt32()),
                "url" => new UrlNetworkProxyPolicy(property.Value.GetString()
                    ?? throw new JsonException("network.proxy.url must be a string.")),
                _ => throw new JsonException(
                    $"Unknown network.proxy property '{property.Name}'."),
            };
        }

        return proxy
            ?? throw new JsonException(
                "network.proxy must set exactly one of localhost or url.");
    }

    public override void Write(
        Utf8JsonWriter writer,
        NetworkProxyPolicy value,
        JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        switch (value)
        {
            case LocalhostNetworkProxyPolicy localhost:
                writer.WriteNumber("localhost", localhost.Port);
                break;
            case UrlNetworkProxyPolicy url:
                writer.WriteString("url", url.Url);
                break;
            default:
                throw new JsonException(
                    $"Unsupported network proxy policy type '{value.GetType().FullName}'.");
        }
        writer.WriteEndObject();
    }
}
