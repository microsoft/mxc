// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk;

internal sealed class NonNullNetworkSectionJsonConverter<T> : JsonConverter<T>
    where T : class
{
    public override bool HandleNull => true;

    public override T Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
        JsonSerializer.Deserialize(ref reader, MxcJson.TypeInfo<T>(options))
            ?? throw new JsonException(
                "Network sections cannot be null. Omit the property instead.");

    public override void Write(
        Utf8JsonWriter writer,
        T value,
        JsonSerializerOptions options) =>
        JsonSerializer.Serialize(writer, value, MxcJson.TypeInfo<T>(options));
}
