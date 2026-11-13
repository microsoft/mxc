// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk;

internal sealed class PolicyFailureValueJsonConverter : JsonConverter<ulong>
{
    public override ulong Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException("policy-failure values must be unsigned 64-bit decimal strings");
        }
        var text = reader.GetString();
        if (string.IsNullOrEmpty(text)
            || text.Any(static character => character is < '0' or > '9')
            || !ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value))
        {
            throw new JsonException("policy-failure values must be unsigned 64-bit decimal strings");
        }
        return value;
    }

    public override void Write(Utf8JsonWriter writer, ulong value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value.ToString(CultureInfo.InvariantCulture));
}
