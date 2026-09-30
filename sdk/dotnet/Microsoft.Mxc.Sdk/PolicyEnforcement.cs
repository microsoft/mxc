// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk;

/// <summary>How to handle an OS creation-policy refusal.</summary>
public enum PolicyEnforcementMode
{
    /// <summary>Return the first refusal without editing the request.</summary>
    PassThrough,
    /// <summary>Apply supported tightening-only repairs before retrying creation.</summary>
    Mutate,
}

/// <summary>Development-only CPSE policy handling; ignored without CPSE2 support.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class PolicyEnforcementOptions
{
    /// <summary>Defaults to pass-through. Mutation also requires experimental authorization.</summary>
    [JsonPropertyName("mode")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonConverter(typeof(PolicyEnforcementModeConverter))]
    public PolicyEnforcementMode? Mode { get; set; }

    /// <summary>CPSE2 negotiation attempts, including the first: 1-64, default 8. Initial unavailability can additionally invoke legacy creation once.</summary>
    [JsonPropertyName("maxAttempts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonConverter(typeof(PolicyEnforcementAttemptLimitConverter))]
    public byte? MaxAttempts { get; set; }
}

internal sealed class PolicyEnforcementOptionsConverter : JsonConverter<PolicyEnforcementOptions?>
{
    public override bool HandleNull => true;

    public override PolicyEnforcementOptions? Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("policyEnforcement must be an object when specified.");
        }
        return JsonSerializer.Deserialize<PolicyEnforcementOptions>(ref reader, options);
    }

    public override void Write(
        Utf8JsonWriter writer, PolicyEnforcementOptions? value, JsonSerializerOptions options)
    {
        if (value is null) writer.WriteNullValue();
        else JsonSerializer.Serialize(writer, value, options);
    }
}

internal sealed class PolicyEnforcementModeConverter : JsonConverter<PolicyEnforcementMode?>
{
    public override bool HandleNull => true;

    public override PolicyEnforcementMode? Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String) throw new JsonException("Expected a policy-enforcement mode string.");
        return reader.GetString() switch
        {
            "pass-through" => PolicyEnforcementMode.PassThrough,
            "mutate" => PolicyEnforcementMode.Mutate,
            _ => throw new JsonException("Unknown policy-enforcement mode."),
        };
    }

    public override void Write(
        Utf8JsonWriter writer, PolicyEnforcementMode? value, JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
            return;
        }
        writer.WriteStringValue(value switch
        {
            PolicyEnforcementMode.PassThrough => "pass-through",
            PolicyEnforcementMode.Mutate => "mutate",
            _ => throw new JsonException("Unknown policy-enforcement mode."),
        });
    }
}

internal sealed class PolicyEnforcementAttemptLimitConverter : JsonConverter<byte?>
{
    public override bool HandleNull => true;

    public override byte? Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.Number || !reader.TryGetByte(out byte value) ||
            value is < 1 or > 64)
        {
            throw new JsonException("Expected a policy-enforcement attempt count between 1 and 64.");
        }
        return value;
    }

    public override void Write(Utf8JsonWriter writer, byte? value, JsonSerializerOptions options)
    {
        if (value is null) writer.WriteNullValue();
        else writer.WriteNumberValue(value.Value);
    }
}

/// <summary>A raw native code and, when recognized, its symbolic name.</summary>
public sealed class PolicyResultCode
{
    [JsonPropertyName("code")]
    public uint Code { get; init; }
    [JsonPropertyName("name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Name { get; init; }
}

/// <summary>One constraint from a bounded, non-exhaustive policy result.</summary>
public sealed class NativePolicyDetail
{
    [JsonPropertyName("failureClass")]
    public PolicyResultCode FailureClass { get; init; } = new();
    [JsonPropertyName("failureReason")]
    public PolicyResultCode FailureReason { get; init; } = new();
    [JsonPropertyName("requiredAction")]
    public PolicyResultCode RequiredAction { get; init; } = new();
    [JsonPropertyName("resourceKind")]
    public PolicyResultCode ResourceKind { get; init; } = new();
    [JsonPropertyName("valueKind")]
    public PolicyResultCode ValueKind { get; init; } = new();
    [JsonPropertyName("requestedValue")]
    [JsonNumberHandling(JsonNumberHandling.AllowReadingFromString | JsonNumberHandling.WriteAsString)]
    public ulong RequestedValue { get; init; }
    [JsonPropertyName("requiredValue")]
    [JsonNumberHandling(JsonNumberHandling.AllowReadingFromString | JsonNumberHandling.WriteAsString)]
    public ulong RequiredValue { get; init; }
    [JsonPropertyName("flags")]
    public uint Flags { get; init; }
    [JsonPropertyName("resource")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Resource { get; init; }
    [JsonPropertyName("resourceOffsetChars")]
    public uint ResourceOffsetChars { get; init; }
    [JsonPropertyName("resourceCharsWritten")]
    public uint ResourceCharsWritten { get; init; }
    [JsonPropertyName("resourceCharsRequired")]
    public uint ResourceCharsRequired { get; init; }
}

/// <summary>An owned policy decision independent of the creation HRESULT.</summary>
public sealed class NativePolicyResult
{
    [JsonPropertyName("version")]
    public uint Version { get; init; }
    [JsonPropertyName("outcome")]
    public PolicyResultCode Outcome { get; init; } = new();
    [JsonPropertyName("details")]
    public IReadOnlyList<NativePolicyDetail> Details { get; init; } = [];
    [JsonPropertyName("detailsCapacity")]
    public uint DetailsCapacity { get; init; }
    [JsonPropertyName("detailsCount")]
    public uint DetailsCount { get; init; }
    [JsonPropertyName("resourceCapacityChars")]
    public uint ResourceCapacityChars { get; init; }
    [JsonPropertyName("resourceCharsWritten")]
    public uint ResourceCharsWritten { get; init; }
    [JsonPropertyName("resourceCharsRequired")]
    public uint ResourceCharsRequired { get; init; }
}

/// <summary>A normalized setting change, not a literal patch into the original JSON.</summary>
public sealed class PolicyChange
{
    [JsonPropertyName("setting")]
    public string Setting { get; init; } = string.Empty;
    [JsonPropertyName("before")]
    public JsonElement Before { get; init; }
    [JsonPropertyName("after")]
    public JsonElement After { get; init; }
}

/// <summary>One creation attempt and the changes made before its successor.</summary>
public sealed class PolicyEnforcementAttempt
{
    [JsonPropertyName("attempt")]
    public byte Attempt { get; init; }
    [JsonPropertyName("hresult")]
    public string HResult { get; init; } = string.Empty;
    [JsonPropertyName("result")]
    public NativePolicyResult Result { get; init; } = new();
    [JsonPropertyName("changes")]
    public IReadOnlyList<PolicyChange> Changes { get; init; } = [];
}

/// <summary>Policy handling, retained on success and terminal failure.</summary>
public sealed class PolicyEnforcementReport : IJsonOnDeserialized
{
    [JsonPropertyName("reportVersion")]
    public uint ReportVersion { get; init; }
    [JsonPropertyName("requestedMode")]
    public string RequestedMode { get; init; } = string.Empty;
    [JsonPropertyName("modeApplied")]
    public bool ModeApplied { get; init; }
    [JsonPropertyName("availability")]
    public string Availability { get; init; } = string.Empty;
    [JsonPropertyName("termination")]
    public string Termination { get; init; } = string.Empty;
    [JsonPropertyName("environmentCreated")]
    public bool EnvironmentCreated { get; init; }
    [JsonPropertyName("originalPolicyHash")]
    public string OriginalPolicyHash { get; init; } = string.Empty;
    [JsonPropertyName("effectivePolicyHash")]
    public string EffectivePolicyHash { get; init; } = string.Empty;
    [JsonPropertyName("attempts")]
    public IReadOnlyList<PolicyEnforcementAttempt> Attempts { get; init; } = [];
    [JsonPropertyName("message")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Message { get; init; }

    void IJsonOnDeserialized.OnDeserialized()
    {
        if (ReportVersion != 1)
        {
            throw new JsonException("Unsupported policy-enforcement report version.");
        }
    }
}
