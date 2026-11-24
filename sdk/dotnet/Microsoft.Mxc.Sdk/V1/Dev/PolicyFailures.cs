// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Buffers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk.V1.Dev;

/// <summary>Known policy-failure status strings for MxcException.NativeCode.</summary>
public static class PolicyFailureNativeCodes
{
    /// <summary>HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY), formatted as an SDK native code.</summary>
    public const string PolicyBlocked = "0x800704EC";
}

/// <summary>Known native outcomes. Outcome properties also retain unknown uint values.</summary>
public static class PolicyFailureOutcomes
{
    /// <summary>Unspecified outcome, not a policy approval.</summary>
    public const uint Unknown = 0;
    /// <summary>Creation was blocked by policy.</summary>
    public const uint Blocked = 1;
    /// <summary>Policy evaluation failed.</summary>
    public const uint EvaluationFailed = 2;
}

/// <summary>Known native failure classes.</summary>
public static class PolicyFailureClasses
{
    /// <summary>No policy domain specified.</summary>
    public const uint None = 0;
    /// <summary>Network policy.</summary>
    public const uint Network = 1;
    /// <summary>Filesystem policy.</summary>
    public const uint Filesystem = 2;
    /// <summary>Enforcement-mode policy.</summary>
    public const uint EnforcementMode = 3;
}

/// <summary>Known native failure reasons.</summary>
public static class PolicyFailureReasons
{
    /// <summary>No failure reason specified.</summary>
    public const uint None = 0;
    /// <summary>A requested capability is not allowed.</summary>
    public const uint CapabilityNotAllowed = 1;
    /// <summary>Requested access exceeds the policy ceiling.</summary>
    public const uint AccessExceedsCeiling = 2;
    /// <summary>Policy requires a deny entry.</summary>
    public const uint DenyRequired = 3;
    /// <summary>The request exceeds the policy path limit.</summary>
    public const uint RequestPathLimit = 4;
}

/// <summary>Known suggested changes, not authorization to apply them.</summary>
public static class PolicyFailureActions
{
    /// <summary>No request change suggested.</summary>
    public const uint None = 0;
    /// <summary>Remove a requested capability.</summary>
    public const uint RemoveCapability = 1;
    /// <summary>Restrict requested filesystem access.</summary>
    public const uint RestrictFilesystemAccess = 2;
    /// <summary>Reduce the requested path count.</summary>
    public const uint ReducePathCount = 3;
}

/// <summary>Known native resource categories.</summary>
public static class PolicyFailureResourceKinds
{
    /// <summary>No resource category specified.</summary>
    public const uint None = 0;
    /// <summary>A filesystem path.</summary>
    public const uint Path = 1;
    /// <summary>A capability name.</summary>
    public const uint Capability = 2;
}

/// <summary>Known native value categories.</summary>
public static class PolicyFailureValueKinds
{
    /// <summary>No value category specified.</summary>
    public const uint None = 0;
    /// <summary>Values describe access; compare with <see cref="PolicyFailureAccessValues"/>.</summary>
    public const uint Access = 1;
    /// <summary>Values describe path counts.</summary>
    public const uint PathCount = 2;
}

/// <summary>Access values for requested/required values when ValueKind is Access.</summary>
public static class PolicyFailureAccessValues
{
    /// <summary>No access.</summary>
    public const ulong None = 0;
    /// <summary>Read-only access.</summary>
    public const ulong ReadOnly = 1;
    /// <summary>Read-write access.</summary>
    public const ulong ReadWrite = 2;
}

/// <summary>Known native flag bits. Flags properties also retain unknown bits.</summary>
public static class PolicyFailureFlags
{
    /// <summary>No flags set.</summary>
    public const uint None = 0;
    /// <summary>A typed remedy is identified, not necessarily safe or available.</summary>
    public const uint HasActionableDetails = 1;
    /// <summary>The resource text is complete.</summary>
    public const uint ResourceComplete = 2;
    /// <summary>The resource text is unavailable.</summary>
    public const uint ResourceUnavailable = 4;
}

/// <summary>Supported policy-failure format and native result versions.</summary>
public static class PolicyFailureVersions
{
    /// <summary>The supported <see cref="PolicyFailures.FormatVersion"/>.</summary>
    public const uint Format = 1;
    /// <summary>The native result version the SDK writes for <see cref="PolicyFailureResult.Version"/>.</summary>
    public const uint Result = 1;
    /// <summary>The native reader version the SDK writes for <see cref="PolicyFailureResult.MinimumReaderVersion"/>.</summary>
    public const uint MinimumReader = 1;
}

/// <summary>Caller-owned creation-policy observations, not a policy approval.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class PolicyFailures
{
    private const int MaximumInvocationBytes = 4 * 1024 * 1024;
    private const int MaximumStorageBytes = MaximumInvocationBytes + 512 * 1024;
    private const int MaximumInvocationResults = 64;
    private const int MaximumInvocationDetails = 1024;
    private const long MaximumInvocationResourceUnits = 262_144;
    private const int MaximumDetailsPerResult = 64;
    private const long MaximumResourceUnitsPerResult = 32_768;
    // A terminal report can contain one native batch beyond the invocation limits.
    private const int MaximumStorageResults = MaximumInvocationResults + 1;
    private const int MaximumStorageDetails = MaximumInvocationDetails + MaximumDetailsPerResult;
    private const long MaximumStorageResourceUnits = MaximumInvocationResourceUnits + MaximumResourceUnitsPerResult;

    /// <summary>The MXC policy-failure format version, independent of native versions.</summary>
    [JsonRequired]
    public uint FormatVersion { get; init; } = PolicyFailureVersions.Format;

    /// <summary>Native refusal batches, preserving their boundaries and order.</summary>
    [JsonRequired]
    public PolicyFailureResult[] Results { get; init; } = [];

    /// <summary>Serialize observations for application-owned storage without reflection.</summary>
    /// <exception cref="JsonException">The observations have an unsupported format or exceed storage bounds.</exception>
    public string ToJson()
    {
        ValidateStorage();
        var json = MxcJson.Serialize(this, MxcJson.Options);
        ValidateSize(json);
        return json;
    }

    /// <summary>Read stored observations without interpreting native policy requirements.</summary>
    /// <exception cref="JsonException">The JSON has an invalid shape, unsupported format, or exceeds storage bounds.</exception>
    public static PolicyFailures FromJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            ValidateSize(json);
            using (var document = JsonDocument.Parse(json))
            {
                MxcJson.RejectDuplicateProperties(document.RootElement);
            }
            var failures = MxcJson.Deserialize<PolicyFailures>(json)
                ?? throw new JsonException("policy failures must be a JSON object");
            failures.ValidateStorage();
            return failures;
        }
        catch (JsonException)
        {
            throw new JsonException("invalid stored policy failures");
        }
    }

    /// <summary>Read <c>Details.policyFailures</c>, or return null when it is absent.</summary>
    /// <exception cref="MxcException">
    /// Present observations are invalid or exceed storage bounds; <see cref="MxcException.Code"/>
    /// is <see cref="ErrorCode.BackendError"/>.
    /// </exception>
    public static PolicyFailures? FromException(MxcException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        if (exception.Details is not { ValueKind: JsonValueKind.Object } details
            || !details.TryGetProperty("policyFailures", out var failures))
        {
            return null;
        }
        try
        {
            return FromJson(failures.GetRawText());
        }
        catch (JsonException)
        {
            throw new MxcException(ErrorCode.BackendError, "native policy failures are malformed");
        }
    }

    /// <summary>Return an owned merge of distinct complete batches in first-observed order.</summary>
    /// <exception cref="JsonException">Either input or the complete merge exceeds storage bounds or is invalid.</exception>
    public PolicyFailures MergedWith(PolicyFailures other)
    {
        ArgumentNullException.ThrowIfNull(other);
        var first = FromJson(ToJson());
        var second = FromJson(other.ToJson());
        var batches = new List<PolicyFailureResult>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var result in first.Results.Concat(second.Results))
        {
            if (seen.Add(MxcJson.Serialize(result, MxcJson.Options)))
            {
                batches.Add(result);
            }
        }
        var merged = new PolicyFailures { Results = batches.ToArray() };
        _ = merged.ToJson();
        return merged;
    }

    private static void ValidateSize(string json)
    {
        if (Encoding.UTF8.GetByteCount(json) > MaximumStorageBytes)
        {
            throw new JsonException("policy failures exceed the storage byte limit");
        }
    }

    private void ValidateStorage()
    {
        if (FormatVersion != PolicyFailureVersions.Format)
        {
            throw new JsonException("unsupported policy-failure formatVersion");
        }
        if (Results is null || Results.Length > MaximumStorageResults)
        {
            throw new JsonException("policy failures exceed the storage result limit or have null results");
        }

        var details = 0;
        long resourceUnits = 0;
        foreach (var result in Results)
        {
            if (result?.Details is null || result.Details.Length > MaximumDetailsPerResult)
            {
                throw new JsonException("policy failures have an invalid result or exceed the per-result detail limit");
            }
            details += result.Details.Length;
            long resultUnits = 0;
            foreach (var detail in result.Details)
            {
                if (detail is null)
                {
                    throw new JsonException("policy failures contain a null detail");
                }
                resultUnits += detail.ResourceUnitsWithTerminator();
            }
            if (resultUnits > MaximumResourceUnitsPerResult)
            {
                throw new JsonException("policy failures exceed the per-result resource limit");
            }
            resourceUnits += resultUnits;
        }
        if (details > MaximumStorageDetails || resourceUnits > MaximumStorageResourceUnits)
        {
            throw new JsonException("policy failures exceed the total storage detail/resource limit");
        }
    }
}

/// <summary>One native creation-policy result batch.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class PolicyFailureResult
{
    /// <summary>The native policy-result contract version.</summary>
    [JsonRequired]
    public uint Version { get; init; } = PolicyFailureVersions.Result;

    /// <summary>The minimum native reader version.</summary>
    [JsonRequired]
    public uint MinimumReaderVersion { get; init; } = PolicyFailureVersions.MinimumReader;

    /// <summary>The native outcome; compare with <see cref="PolicyFailureOutcomes"/>. Unknown values are retained.</summary>
    [JsonRequired]
    public uint Outcome { get; init; }

    /// <summary>The observations belonging to this batch.</summary>
    [JsonRequired]
    public PolicyFailureDetail[] Details { get; init; } = [];
}

/// <summary>A native policy observation with lossless numeric values and optional resource text.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class PolicyFailureDetail
{
    /// <summary>The raw native failure class.</summary>
    [JsonRequired]
    public uint FailureClass { get; init; }

    /// <summary>The raw native failure reason.</summary>
    [JsonRequired]
    public uint FailureReason { get; init; }

    /// <summary>The raw native required action; the SDK does not apply it.</summary>
    [JsonRequired]
    public uint RequiredAction { get; init; }

    /// <summary>The raw native resource discriminator.</summary>
    [JsonRequired]
    public uint ResourceKind { get; init; }

    /// <summary>The raw native value discriminator.</summary>
    [JsonRequired]
    public uint ValueKind { get; init; }

    /// <summary>The raw native flags, including unknown bits.</summary>
    [JsonRequired]
    public uint Flags { get; init; }

    /// <summary>The observed requested value, stored as an unsigned decimal string in JSON.</summary>
    [JsonRequired]
    [JsonConverter(typeof(PolicyFailureValueJsonConverter))]
    public ulong RequestedValue { get; init; }

    /// <summary>The observed required value, stored as an unsigned decimal string in JSON.</summary>
    [JsonRequired]
    [JsonConverter(typeof(PolicyFailureValueJsonConverter))]
    public ulong RequiredValue { get; init; }

    /// <summary>
    /// Native resource text without a terminator. An empty string differs from null (absent).
    /// Completeness is reported by <see cref="PolicyFailureFlags.ResourceComplete"/>.
    /// Invalid native UTF-16 is omitted and marked unavailable.
    /// </summary>
    public string? Resource { get; init; }

    internal long ResourceUnitsWithTerminator()
    {
        if (Resource is { } text)
        {
            // Serialization would silently replace an unpaired surrogate.
            if (!IsValidUtf16(text))
            {
                throw new JsonException("policy failure resource must be valid UTF-16");
            }
            return text.Length + 1L;
        }
        return 0;
    }

    private static bool IsValidUtf16(ReadOnlySpan<char> text)
    {
        while (!text.IsEmpty)
        {
            if (Rune.DecodeFromUtf16(text, out _, out var consumed) != OperationStatus.Done)
            {
                return false;
            }
            text = text[consumed..];
        }
        return true;
    }
}
