// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk;

/// <summary>Structured outputs produced by optional sandbox features.</summary>
public sealed class SandboxOutputMetadata
{
    /// <summary>Location and summary of a captureDenials output document.</summary>
    [JsonPropertyName("captureDenials")]
    public CaptureDenialsOutput? CaptureDenials { get; init; }

    /// <summary>Failure details and the retained ETL path, when finalization fails.</summary>
    [JsonPropertyName("captureDenialsError")]
    public CaptureDenialsErrorOutput? CaptureDenialsError { get; init; }
}

/// <summary>Structured diagnostics for a failed captureDenials finalization.</summary>
public sealed class CaptureDenialsErrorOutput
{
    /// <summary>Human-readable finalization failure.</summary>
    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;

    /// <summary>Absolute path to the retained ETL trace.</summary>
    [JsonPropertyName("etlPath")]
    public string EtlPath { get; init; } = string.Empty;
}

/// <summary>Location and summary of a captureDenials output document.</summary>
public sealed class CaptureDenialsOutput
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

    /// <summary>Absolute path to the retained ETL trace, when requested.</summary>
    [JsonPropertyName("etlPath")]
    public string? EtlPath { get; init; }
}
