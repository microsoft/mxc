// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// A cross-platform sandbox policy — describes <em>what</em> to restrict.
/// Omitted sections are most-restrictive (default-deny). Serializes to the
/// camelCase JSON the native layer expects.
/// </summary>
public sealed class SandboxPolicy
{
    /// <summary>Policy/schema version (e.g. <c>"0.7.0-alpha"</c>). Required.</summary>
    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    /// <summary>Filesystem access policy.</summary>
    [JsonPropertyName("filesystem")]
    public FilesystemPolicy? Filesystem { get; set; }

    /// <summary>Network access policy.</summary>
    [JsonPropertyName("network")]
    public NetworkPolicy? Network { get; set; }

    /// <summary>UI access policy.</summary>
    [JsonPropertyName("ui")]
    public UiPolicy? Ui { get; set; }

    /// <summary>
    /// Windows ProcessContainer denial capture. Its presence enables capture;
    /// Linux and macOS backends ignore it.
    /// </summary>
    [JsonPropertyName("captureDenials")]
    public CaptureDenialsPolicy? CaptureDenials { get; set; }

    /// <summary>Execution timeout in milliseconds (<c>null</c> = no timeout).</summary>
    [JsonPropertyName("timeoutMs")]
    public uint? TimeoutMs { get; set; }
}

/// <summary>
/// How <c>captureDenials</c> handles each ungranted access check while recording it.
/// </summary>
public enum CaptureDenialsMode
{
    /// <summary>
    /// Keep the access denied and record the denial, preserving deny-by-default containment.
    /// </summary>
    Block,

    /// <summary>
    /// Allow and record the access. This relaxes containment for the run and emits a warning.
    /// <see cref="MxcSandbox.Run(SandboxPolicy, string)"/> and
    /// <see cref="MxcSandbox.RunAsync(SandboxPolicy, string, CancellationToken)"/> expose that
    /// warning; streaming processes returned by
    /// <see cref="MxcSandbox.Spawn(SandboxPolicy, string)"/> currently do not.
    /// </summary>
    Allow,
}

/// <summary>
/// Windows ProcessContainer denial-capture settings. The presence of this section enables
/// capture and reports the resulting document through <see cref="SandboxOutputMetadata"/>.
/// </summary>
public sealed class CaptureDenialsPolicy
{
    /// <summary>How ungranted access checks are handled while recording them.</summary>
    [JsonPropertyName("mode")]
    public CaptureDenialsMode Mode { get; set; } = CaptureDenialsMode.Block;

    /// <summary>
    /// Optional absolute path for the JSON denials document. The parent directory must exist.
    /// MXC inserts a per-run identifier into the file stem and reports the actual path through
    /// output metadata. When omitted, MXC uses a run-unique file in the system temporary
    /// directory.
    /// </summary>
    [JsonPropertyName("outputPath")]
    public string? OutputPath { get; set; }

    /// <summary>
    /// Preserve the sealed ETL trace and report its path through output metadata. Retained traces
    /// can contain sensitive paths and identifiers; callers must delete the reported trace after
    /// use. Do not delete its parent directory unless the caller independently owns or positively
    /// recognizes that directory.
    /// </summary>
    [JsonPropertyName("retainEtl")]
    public bool RetainEtl { get; set; }
}

/// <summary>Filesystem section of a <see cref="SandboxPolicy"/>.</summary>
public sealed class FilesystemPolicy
{
    /// <summary>Paths granted read-write access inside the sandbox.</summary>
    [JsonPropertyName("readwritePaths")]
    public List<string> ReadwritePaths { get; set; } = new();

    /// <summary>Paths granted read-only access inside the sandbox.</summary>
    [JsonPropertyName("readonlyPaths")]
    public List<string> ReadonlyPaths { get; set; } = new();

    /// <summary>Paths explicitly denied inside the sandbox.</summary>
    [JsonPropertyName("deniedPaths")]
    public List<string> DeniedPaths { get; set; } = new();

    /// <summary>Clear the filesystem policy when the shell exits (default true).</summary>
    [JsonPropertyName("clearPolicyOnExit")]
    public bool? ClearPolicyOnExit { get; set; }
}

/// <summary>Network section of a <see cref="SandboxPolicy"/>. All flags default to deny.</summary>
public sealed class NetworkPolicy
{
    /// <summary>Allow outbound network access.</summary>
    [JsonPropertyName("allowOutbound")]
    public bool AllowOutbound { get; set; }

    /// <summary>Allow access to the local network.</summary>
    [JsonPropertyName("allowLocalNetwork")]
    public bool AllowLocalNetwork { get; set; }

    /// <summary>Hosts explicitly allowed.</summary>
    [JsonPropertyName("allowedHosts")]
    public List<string> AllowedHosts { get; set; } = new();

    /// <summary>Hosts explicitly blocked.</summary>
    [JsonPropertyName("blockedHosts")]
    public List<string> BlockedHosts { get; set; } = new();
}

/// <summary>Clipboard access level. Serialized as camelCase ("none"/"read"/"write"/"all").</summary>
public enum ClipboardPolicy
{
    /// <summary>No clipboard access.</summary>
    None,

    /// <summary>Read-only clipboard access.</summary>
    Read,

    /// <summary>Write-only clipboard access.</summary>
    Write,

    /// <summary>Read and write clipboard access.</summary>
    All,
}

/// <summary>UI section of a <see cref="SandboxPolicy"/>. All flags default to denied.</summary>
public sealed class UiPolicy
{
    /// <summary>Allow the sandboxed process to create windows.</summary>
    [JsonPropertyName("allowWindows")]
    public bool AllowWindows { get; set; }

    /// <summary>Clipboard access level.</summary>
    [JsonPropertyName("clipboard")]
    public ClipboardPolicy Clipboard { get; set; } = ClipboardPolicy.None;

    /// <summary>Allow synthetic input injection.</summary>
    [JsonPropertyName("allowInputInjection")]
    public bool AllowInputInjection { get; set; }
}
