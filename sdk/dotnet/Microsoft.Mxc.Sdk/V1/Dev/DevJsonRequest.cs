// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using System.Text.Json;

namespace Microsoft.Mxc.Sdk.V1.Dev;

internal static class DevJsonRequest
{
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);
    // The phase/timeout inspection must not reject nesting the native JSON parser accepts.
    private static readonly JsonDocumentOptions InspectionOptions = new() { MaxDepth = 128 };

    internal static uint? Inspect(string json, string operation, string? expectedPhase = null)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            using var document = JsonDocument.Parse(json, InspectionOptions);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new MxcException(ErrorCode.MalformedRequest,
                    $"{operation} requires a JSON object");
            }

            JsonElement phase = default;
            var phaseCount = 0;
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (property.Name != "phase")
                {
                    continue;
                }
                phase = property.Value;
                phaseCount++;
            }
            if (phaseCount > 1)
            {
                throw new MxcException(ErrorCode.MalformedRequest,
                    $"{operation} contains duplicate phase declarations");
            }
            if (expectedPhase is null && phaseCount != 0)
            {
                throw new MxcException(ErrorCode.MalformedRequest,
                    $"{operation} requires a one-shot document without phase");
            }
            if (expectedPhase is not null &&
                (phaseCount != 1 || phase.ValueKind != JsonValueKind.String ||
                    phase.GetString() != expectedPhase))
            {
                throw new MxcException(ErrorCode.MalformedRequest,
                    $"{operation} requires phase '{expectedPhase}'");
            }

            if (document.RootElement.TryGetProperty("process", out var process) &&
                process.ValueKind == JsonValueKind.Object &&
                process.TryGetProperty("timeout", out var timeout) &&
                timeout.ValueKind == JsonValueKind.Number &&
                timeout.TryGetUInt32(out var milliseconds))
            {
                return milliseconds;
            }
            return null;
        }
        catch (JsonException error)
        {
            throw new MxcException(ErrorCode.MalformedRequest,
                $"{operation} received invalid JSON: {error.Message}", error);
        }
    }

    internal static byte[] ToNullTerminatedUtf8(string json)
    {
        if (json.Contains('\0'))
        {
            throw new MxcException(ErrorCode.MalformedRequest,
                "exact JSON must not contain an embedded NUL character");
        }
        byte[] buffer;
        try
        {
            buffer = StrictUtf8.GetBytes(json);
        }
        catch (EncoderFallbackException error)
        {
            throw new MxcException(ErrorCode.MalformedRequest,
                "exact JSON contains an invalid UTF-16 sequence", error);
        }
        Array.Resize(ref buffer, buffer.Length + 1);
        return buffer;
    }
}
