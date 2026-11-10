// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk.V1.Dev;

/// <summary>The kind of change to a JSON value in an MXC request.</summary>
[JsonConverter(typeof(PolicyChangeOperationJsonConverter))]
public enum PolicyChangeOperation
{
    /// <summary>Add a previously absent value; Before is JSON null.</summary>
    Add,
    /// <summary>Remove a present value; After is JSON null.</summary>
    Remove,
    /// <summary>Replace a present value, which may itself be JSON null.</summary>
    Replace,
}

/// <summary>One proposed change, with owned JSON values and an RFC 6901 JSON Pointer.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class PolicyChange
{
    // .NET 8 source generation assigns Undefined before checking required fields.
    private JsonElement before;
    private JsonElement after;

    /// <summary>The operation distinguishing absent values from actual JSON null values.</summary>
    [JsonRequired]
    public PolicyChangeOperation Operation { get; init; }

    /// <summary>The changed value's RFC 6901 JSON Pointer.</summary>
    [JsonRequired]
    public string Path { get; init; } = string.Empty;

    /// <summary>The original JSON value, or JSON null for Add.</summary>
    [JsonRequired]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public JsonElement Before
    {
        get => before;
        init => before = value.ValueKind == JsonValueKind.Undefined ? value : value.Clone();
    }

    /// <summary>The prepared JSON value, or JSON null for Remove.</summary>
    [JsonRequired]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public JsonElement After
    {
        get => after;
        init => after = value.ValueKind == JsonValueKind.Undefined ? value : value.Clone();
    }

    internal void Validate()
    {
        if (Operation is not (PolicyChangeOperation.Add or PolicyChangeOperation.Remove or PolicyChangeOperation.Replace)
            || Before.ValueKind == JsonValueKind.Undefined || After.ValueKind == JsonValueKind.Undefined
            || (Operation == PolicyChangeOperation.Add && Before.ValueKind != JsonValueKind.Null)
            || (Operation == PolicyChangeOperation.Remove && After.ValueKind != JsonValueKind.Null))
        {
            throw new JsonException("invalid policy change operation or values");
        }
        if (Path is null || (Path.Length != 0 && Path[0] != '/'))
        {
            throw new JsonException("invalid policy change JSON Pointer");
        }
        _ = PolicyPreparationJson.StrictUtf8.GetByteCount(Path);
        for (var index = 0; index < Path.Length; index++)
        {
            if (Path[index] == '~' && (++index == Path.Length || Path[index] is not ('0' or '1')))
            {
                throw new JsonException("invalid policy change JSON Pointer escape");
            }
        }
    }
}

/// <summary>A prepared MXC request and proposed changes for the caller to accept or reject.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class PreparedPolicyRequest
{
    /// <summary>The complete prepared MXC request JSON; preparation does not execute it.</summary>
    [JsonRequired]
    public string RequestJson { get; init; } = string.Empty;

    /// <summary>The proposed changes in application order.</summary>
    [JsonRequired]
    public PolicyChange[] Changes { get; init; } = [];

    /// <summary>Serialize the prepared request for application-owned storage without reflection.</summary>
    /// <exception cref="JsonException">The prepared request is malformed or exceeds storage limits.</exception>
    public string ToJson()
    {
        try
        {
            ValidateStorage();
            var json = MxcJson.Serialize(this, PolicyPreparationJson.SerializerOptions);
            PolicyPreparationJson.ValidateResultSize(json);
            return json;
        }
        catch (Exception error) when (error is JsonException or EncoderFallbackException)
        {
            throw new JsonException("invalid prepared policy request");
        }
    }

    /// <summary>Read stored preparation data without approving its changes or validating backend policy.</summary>
    /// <exception cref="JsonException">The JSON is malformed or exceeds storage limits.</exception>
    public static PreparedPolicyRequest FromJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            PolicyPreparationJson.ValidateResultSize(json);
            using (var document = JsonDocument.Parse(json, PolicyPreparationJson.DocumentOptions))
            {
                MxcJson.RejectDuplicateProperties(document.RootElement);
            }
            var prepared = MxcJson.Deserialize<PreparedPolicyRequest>(
                json, PolicyPreparationJson.SerializerOptions)
                ?? throw new JsonException("prepared policy request must be an object");
            prepared.ValidateStorage();
            return prepared;
        }
        catch (Exception error) when (error is JsonException or EncoderFallbackException)
        {
            throw new JsonException("invalid prepared policy request");
        }
    }

    private void ValidateStorage()
    {
        if (RequestJson is null)
        {
            throw new JsonException("prepared policy request has null requestJson");
        }
        PolicyPreparationJson.ValidateRequestSize(RequestJson, PolicyPreparationJson.MaximumResultBytes);
        using (var document = JsonDocument.Parse(RequestJson, new JsonDocumentOptions { MaxDepth = 128 }))
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new JsonException("prepared MXC request must be an object");
            }
        }
        if (Changes is null || Changes.Length > PolicyPreparationJson.MaximumChanges)
        {
            throw new JsonException("prepared policy request has invalid changes or exceeds the change limit");
        }
        foreach (var change in Changes)
        {
            if (change is null)
            {
                throw new JsonException("prepared policy request has a null change");
            }
            change.Validate();
            MxcJson.RejectDuplicateProperties(change.Before);
            MxcJson.RejectDuplicateProperties(change.After);
        }
    }
}

internal sealed class PolicyChangeOperationJsonConverter : JsonConverter<PolicyChangeOperation>
{
    public override PolicyChangeOperation Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            if (reader.ValueTextEquals("add")) return PolicyChangeOperation.Add;
            if (reader.ValueTextEquals("remove")) return PolicyChangeOperation.Remove;
            if (reader.ValueTextEquals("replace")) return PolicyChangeOperation.Replace;
        }
        throw new JsonException("invalid policy change operation");
    }

    public override void Write(
        Utf8JsonWriter writer, PolicyChangeOperation value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value switch
        {
            PolicyChangeOperation.Add => "add",
            PolicyChangeOperation.Remove => "remove",
            PolicyChangeOperation.Replace => "replace",
            _ => throw new JsonException("invalid policy change operation"),
        });
}

internal static class PolicyPreparationJson
{
    internal const int MaximumInputBytes = 8 * 1024 * 1024;
    internal const int MaximumResultBytes = 32 * 1024 * 1024;
    internal const int MaximumChanges = 4096;
    internal static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);
    // JSON values can include the request's full nesting beneath the result envelope.
    internal static readonly JsonSerializerOptions SerializerOptions = new(MxcJson.Options)
    {
        MaxDepth = 256,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
    internal static readonly JsonDocumentOptions DocumentOptions = new() { MaxDepth = 256 };

    internal static void ValidateRequestSize(string json, int maximumBytes = MaximumInputBytes)
    {
        try
        {
            if (json.Contains('\0') || StrictUtf8.GetByteCount(json) > maximumBytes)
            {
                throw new JsonException("invalid policy preparation request or request byte limit exceeded");
            }
        }
        catch (EncoderFallbackException)
        {
            throw new JsonException("invalid policy preparation request encoding");
        }
    }

    internal static void ValidateResultSize(string json)
    {
        if (StrictUtf8.GetByteCount(json) > MaximumResultBytes)
        {
            throw new JsonException("policy preparation result byte limit exceeded");
        }
    }
}
