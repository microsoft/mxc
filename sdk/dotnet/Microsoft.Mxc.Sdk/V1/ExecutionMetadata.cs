// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>Structured outputs produced by optional sandbox features.</summary>
public sealed class ExecutionMetadata
{
    /// <summary>Location and summary of a captureDenials output document.</summary>
    [JsonPropertyName("captureDenials")]
    public CaptureDenialsResult? CaptureDenials { get; init; }

    /// <summary>Failure details and the retained ETL path, when finalization fails.</summary>
    [JsonPropertyName("captureDenialsError")]
    public CaptureDenialsError? CaptureDenialsError { get; init; }
}

/// <summary>Structured diagnostics for a failed captureDenials finalization.</summary>
public sealed class CaptureDenialsError
{
    /// <summary>Human-readable finalization failure.</summary>
    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;

    /// <summary>
    /// Absolute path to the retained ETL trace. Delete this file after use; do not delete its
    /// parent directory unless the caller independently owns or positively recognizes it.
    /// </summary>
    [JsonPropertyName("etlPath")]
    public string EtlPath { get; init; } = string.Empty;
}

/// <summary>Location and summary of a captureDenials output document.</summary>
public sealed class CaptureDenialsResult
{
    /// <summary>Metadata discriminator; always <c>captureDenials</c>.</summary>
    [JsonPropertyName("type")]
    public string Type { get; init; } = string.Empty;

    /// <summary>Absolute path to the JSON denials output file.</summary>
    [JsonPropertyName("outputPath")]
    public string OutputPath { get; init; } = string.Empty;

    /// <summary>Exit code of the sandboxed child.</summary>
    [JsonPropertyName("exitCode")]
    public int ExitCode { get; init; }

    /// <summary>Count of unique denials written.</summary>
    [JsonPropertyName("totalDenials")]
    public ulong TotalDenials { get; init; }

    /// <summary>Whether the emitted denial set was truncated.</summary>
    [JsonPropertyName("deniedResourcesTruncated")]
    public bool DeniedResourcesTruncated { get; init; }

    /// <summary>
    /// Absolute path to the retained ETL trace, when requested. Delete this file after use; do
    /// not delete its parent directory unless the caller independently owns or positively
    /// recognizes it.
    /// </summary>
    [JsonPropertyName("etlPath")]
    public string? EtlPath { get; init; }
}
