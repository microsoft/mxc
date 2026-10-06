// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>Per-invocation telemetry preference, subject to consent and policy.</summary>
public sealed class TelemetryConfig
{
    /// <summary>
    /// Opt this invocation into telemetry, subject to persisted user consent
    /// and administrative policy.
    /// </summary>
    [JsonPropertyName("enabled")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Enabled { get; set; }
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
    /// <see cref="MxcContainer.Run(ContainerRequest)"/>,
    /// <see cref="MxcContainer.RunAsync(ContainerRequest, CancellationToken)"/>, and
    /// <see cref="MxcProcess.Warnings"/> expose that warning.
    /// </summary>
    Allow,
}

/// <summary>
/// Windows ProcessContainer denial-capture settings. The presence of this section enables
/// capture and reports the resulting document through <see cref="ExecutionMetadata"/>.
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

/// <summary>Filesystem settings carried directly by a <see cref="ContainerRequest"/>.</summary>
public sealed class FilesystemPolicy
{
    /// <summary>Paths granted read-write access inside the container.</summary>
    [JsonPropertyName("readwritePaths")]
    public List<string> ReadwritePaths { get; set; } = new();

    /// <summary>Paths granted read-only access inside the container.</summary>
    [JsonPropertyName("readonlyPaths")]
    public List<string> ReadonlyPaths { get; set; } = new();

    /// <summary>Paths explicitly denied inside the container.</summary>
    [JsonPropertyName("deniedPaths")]
    public List<string> DeniedPaths { get; set; } = new();

    /// <summary>Clear the filesystem policy when the shell exits (default true).</summary>
    [JsonPropertyName("clearPolicyOnExit")]
    public bool? ClearPolicyOnExit { get; set; }
}

/// <summary>
/// Directional network authoring section for the v1 high-level SDK.
/// Omission retains native default-deny.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class NetworkPolicy
{
    /// <summary>Outbound network policy.</summary>
    [JsonPropertyName("egress")]
    public NetworkEgressPolicy? Egress { get; set; }

    /// <summary>Inbound and host-loopback policy.</summary>
    [JsonPropertyName("ingress")]
    public NetworkIngressPolicy? Ingress { get; set; }

    /// <summary>Runtime network values.</summary>
    [JsonPropertyName("runtimeConfig")]
    public NetworkRuntimeConfig? RuntimeConfig { get; set; }
}

/// <summary>Allow or deny a network action.</summary>
public enum NetworkAction
{
    /// <summary>Allow the traffic.</summary>
    Allow,

    /// <summary>Deny the traffic.</summary>
    Deny,
}

/// <summary>Transport protocol selector.</summary>
public enum NetworkProtocol
{
    /// <summary>TCP.</summary>
    Tcp,

    /// <summary>UDP.</summary>
    Udp,

    /// <summary>ICMP.</summary>
    Icmp,

    /// <summary>Any protocol.</summary>
    Any,
}

/// <summary>A CIDR network peer.</summary>
public sealed class NetworkPeerPolicy
{
    /// <summary>Create a peer matching <paramref name="cidr"/>.</summary>
    public NetworkPeerPolicy(string cidr)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cidr);
        Cidr = cidr;
    }

    /// <summary>The CIDR matched by this peer.</summary>
    [JsonPropertyName("cidr")]
    public string Cidr { get; }

    /// <summary>Optional CIDRs excluded from the peer.</summary>
    [JsonPropertyName("except")]
    public List<string>? Except { get; set; }
}

/// <summary>A protocol and destination-port selector.</summary>
public sealed class NetworkPortPolicy
{
    /// <summary>Optional transport protocol.</summary>
    [JsonPropertyName("protocol")]
    public NetworkProtocol? Protocol { get; set; }

    /// <summary>Optional first destination port.</summary>
    [JsonPropertyName("port")]
    public ushort? Port { get; set; }

    /// <summary>Optional inclusive final destination port.</summary>
    [JsonPropertyName("endPort")]
    public ushort? EndPort { get; set; }
}

/// <summary>An outbound network rule.</summary>
public sealed class NetworkRulePolicy
{
    /// <summary>Optional destination peers.</summary>
    [JsonPropertyName("to")]
    public List<NetworkPeerPolicy>? To { get; set; }

    /// <summary>Optional protocol and port selectors.</summary>
    [JsonPropertyName("ports")]
    public List<NetworkPortPolicy>? Ports { get; set; }
}

/// <summary>Directional outbound network policy.</summary>
public sealed class NetworkEgressPolicy
{
    /// <summary>Action for traffic not matched by a rule.</summary>
    [JsonPropertyName("default")]
    public NetworkAction? Default { get; set; }

    /// <summary>Explicit allow rules.</summary>
    [JsonPropertyName("allow")]
    public List<NetworkRulePolicy>? Allow { get; set; }

    /// <summary>Explicit deny rules.</summary>
    [JsonPropertyName("deny")]
    public List<NetworkRulePolicy>? Deny { get; set; }
}

/// <summary>Directional inbound and host-loopback network policy.</summary>
public sealed class NetworkIngressPolicy
{
    /// <summary>Default inbound action.</summary>
    [JsonPropertyName("default")]
    public NetworkAction? Default { get; set; }

    /// <summary>Host-loopback action.</summary>
    [JsonPropertyName("hostLoopback")]
    public NetworkAction? HostLoopback { get; set; }
}

/// <summary>Runtime network values.</summary>
public sealed class NetworkRuntimeConfig
{
    /// <summary>
    /// HTTP/S proxy URL supplied at runtime. WSLC accepts guest-routable URLs;
    /// host-loopback restrictions apply only to backends that require them.
    /// </summary>
    [JsonPropertyName("networkProxy")]
    public string? NetworkProxy { get; set; }
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

/// <summary>UI settings carried directly by a <see cref="ContainerRequest"/>.</summary>
public sealed class UiPolicy
{
    /// <summary>Disable UI for the container (the default).</summary>
    [JsonPropertyName("disable")]
    public bool Disable { get; set; } = true;

    /// <summary>Clipboard access level.</summary>
    [JsonPropertyName("clipboard")]
    public ClipboardPolicy Clipboard { get; set; } = ClipboardPolicy.None;

    /// <summary>Allow synthetic input injection.</summary>
    [JsonPropertyName("allowInputInjection")]
    public bool AllowInputInjection { get; set; }
}
