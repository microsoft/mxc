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
    /// Windows ProcessContainer denial capture used by the compatibility
    /// <see cref="MxcSandbox.Run(SandboxPolicy, string)"/> and
    /// <see cref="MxcSandbox.Spawn(SandboxPolicy, string)"/> overloads.
    /// New code should set
    /// <see cref="ProcessContainerContainment.CaptureDenials"/> explicitly.
    /// </summary>
    /// <remarks>
    /// Request-based execution migrates this value to ProcessContainer
    /// containment. It rejects incompatible containment and conflicting
    /// <see cref="ProcessContainerContainment.CaptureDenials"/> values.
    /// <para>
    /// This property stays serializable so legacy policy JSON round-trips
    /// without silently losing the value. It is stripped from the clone sent
    /// natively once it has been migrated onto the containment, so the native
    /// layer never sees the deprecated shape.
    /// </para>
    /// </remarks>
    [Obsolete(
        "Set ProcessContainerContainment.CaptureDenials instead. Removed in 1.0.",
        DiagnosticId = "MXC0001",
        UrlFormat = "https://github.com/microsoft/mxc/blob/main/sdk/dotnet/README.md#{0}")]
    [JsonPropertyName("captureDenials")]
    public CaptureDenialsPolicy? CaptureDenials { get; set; }

    /// <summary>Execution timeout in milliseconds (<c>null</c> = no timeout).</summary>
    [JsonPropertyName("timeoutMs")]
    public uint? TimeoutMs { get; set; }

    /// <summary>
    /// Stable per-invocation telemetry settings.
    /// </summary>
    [JsonPropertyName("telemetry")]
    public TelemetrySettings? Telemetry { get; set; }
}

/// <summary>Telemetry section of a <see cref="SandboxPolicy"/>.</summary>
public sealed class TelemetrySettings
{
    /// <summary>
    /// Opt this invocation into telemetry, subject to persisted user consent
    /// and administrative policy.
    /// </summary>
    [JsonPropertyName("enabled")]
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
    /// <see cref="MxcSandbox.Run(SandboxPolicy, string)"/>,
    /// <see cref="MxcSandbox.RunAsync(SandboxPolicy, string, CancellationToken)"/>, and
    /// <see cref="MxcSandboxProcess.Warnings"/> expose that warning.
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

    /// <summary>
    /// HTTP/HTTPS proxy used by the sandbox. Raw-socket clients may bypass
    /// cooperative proxy implementations on backends that cannot enforce
    /// proxy-only egress.
    /// </summary>
    [JsonPropertyName("proxy")]
    public NetworkProxyPolicy? Proxy { get; set; }

    /// <summary>Schema-0.8 outbound network policy.</summary>
    [JsonPropertyName("egress")]
    public NetworkEgressPolicy? Egress { get; set; }

    /// <summary>Schema-0.8 inbound and host-loopback policy.</summary>
    [JsonPropertyName("ingress")]
    public NetworkIngressPolicy? Ingress { get; set; }

    /// <summary>Schema-0.8 runtime network values.</summary>
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

/// <summary>Schema-0.8 outbound network policy.</summary>
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

/// <summary>Schema-0.8 inbound and host-loopback network policy.</summary>
public sealed class NetworkIngressPolicy
{
    /// <summary>Default inbound action.</summary>
    [JsonPropertyName("default")]
    public NetworkAction? Default { get; set; }

    /// <summary>Host-loopback action.</summary>
    [JsonPropertyName("hostLoopback")]
    public NetworkAction? HostLoopback { get; set; }
}

/// <summary>Schema-0.8 runtime network values.</summary>
public sealed class NetworkRuntimeConfig
{
    /// <summary>HTTP/S loopback proxy URL supplied at runtime.</summary>
    [JsonPropertyName("networkProxy")]
    public string? NetworkProxy { get; set; }
}

/// <summary>
/// Production network-proxy configuration. Use
/// <see cref="LocalhostNetworkProxyPolicy"/> for a proxy listening on the host
/// loopback interface or <see cref="UrlNetworkProxyPolicy"/> for an explicit
/// proxy URL.
/// </summary>
[JsonConverter(typeof(NetworkProxyPolicyJsonConverter))]
public abstract class NetworkProxyPolicy;

/// <summary>An HTTP/HTTPS proxy listening on a host loopback port.</summary>
public sealed class LocalhostNetworkProxyPolicy : NetworkProxyPolicy
{
    /// <summary>Create a loopback proxy configuration.</summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="port"/> is outside the TCP port range.
    /// </exception>
    public LocalhostNetworkProxyPolicy(int port)
    {
        if (port is < 1 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(port),
                port,
                $"Proxy port must be between 1 and {ushort.MaxValue}.");
        }

        Port = (ushort)port;
    }

    /// <summary>The host loopback TCP port.</summary>
    public ushort Port { get; }
}

/// <summary>An HTTP/HTTPS proxy identified by an explicit URL.</summary>
public sealed class UrlNetworkProxyPolicy : NetworkProxyPolicy
{
    /// <summary>Create an explicit proxy URL configuration.</summary>
    /// <exception cref="ArgumentException"><paramref name="url"/> is empty.</exception>
    public UrlNetworkProxyPolicy(string url)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        Url = url;
    }

    /// <summary>The proxy URL. Native policy validation determines whether it is supported.</summary>
    public string Url { get; }
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
