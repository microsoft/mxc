# .NET V1 types

> **Audience:** MXC consumers

Public entrypoint: `Microsoft.Mxc.Sdk.V1`. [Operations](api.md) | [Overview](README.md)

Declarations include public fields, variants, constructors, and members. Inherited SDK members remain defined on their base type; implementation-only helpers and external framework APIs are not expanded.

## `Microsoft.Mxc.Sdk.V1.AvailableBackend`

One host-available backend and its probed capabilities.

```csharp
public sealed class AvailableBackend
{
    public AvailableBackend();

    public required ContainmentBackend Backend { get; init; }
    public IsolationTier? Tier { get; init; }
    public IReadOnlyList<BackendCapability> Capabilities { get; init; } =
        Array.Empty<BackendCapability>();

    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}
```


## `Microsoft.Mxc.Sdk.V1.BackendCapability`

An optional feature supported by a backend on the current host.

```csharp
public enum BackendCapability
{
    Unknown = 0,
    CaptureDenials = 1,
    ProxyEnforcement = 2,
    FilesystemDeniedPaths = 3,
    IngressHostLoopbackAllow = 4,
    FilesystemEnumeratePaths = 5,
    IdentitylessLoopbackProxy = 6,
}
```


## `Microsoft.Mxc.Sdk.V1.CaptureDenialsError`

Structured diagnostics for a failed captureDenials finalization.

```csharp
public sealed class CaptureDenialsError
{
    public CaptureDenialsError();

    public string Message { get; init; } = string.Empty;
    public string EtlPath { get; init; } = string.Empty;
}
```


## `Microsoft.Mxc.Sdk.V1.CaptureDenialsMode`

How captureDenials handles each ungranted access check while recording it.

```csharp
public enum CaptureDenialsMode
{
    Block,
    Allow,
}
```


## `Microsoft.Mxc.Sdk.V1.CaptureDenialsResult`

Location and summary of a captureDenials output document.

```csharp
public sealed class CaptureDenialsResult
{
    public CaptureDenialsResult();

    public string Type { get; init; } = string.Empty;
    public string OutputPath { get; init; } = string.Empty;
    public int ExitCode { get; init; }
    public ulong TotalDenials { get; init; }
    public bool DeniedResourcesTruncated { get; init; }
    public string? EtlPath { get; init; }
}
```


## `Microsoft.Mxc.Sdk.V1.CaptureDenialsPolicy`

Windows ProcessContainer denial-capture settings.

```csharp
public sealed class CaptureDenialsPolicy
{
    public CaptureDenialsPolicy();

    public CaptureDenialsMode Mode { get; set; } = CaptureDenialsMode.Block;
    public string? OutputPath { get; set; }
    public bool RetainEtl { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.ClipboardPolicy`

Clipboard access level.

```csharp
public enum ClipboardPolicy
{
    None,
    Read,
    Write,
    All,
}
```


## `Microsoft.Mxc.Sdk.V1.ContainerId`

An opaque container identity minted by MxcLifecycle.ProvisionContainer.

```csharp
public readonly struct ContainerId : IEquatable<ContainerId>
{
    public string Value { get; }

    public ContainerId(string value);

    public bool Equals(ContainerId other);

    public override bool Equals(object? obj);

    public override int GetHashCode();

    public override string ToString();

    public static bool operator ==(ContainerId left, ContainerId right);

    public static bool operator !=(ContainerId left, ContainerId right);
}
```


## `Microsoft.Mxc.Sdk.V1.ContainerRequest`

A complete container request.

```csharp
public sealed class ContainerRequest
{
    public ContainerRequest(string command);

    public string Command { get; }
    public FilesystemPolicy? Filesystem { get; set; }
    public NetworkPolicy? Network { get; set; }
    public UiPolicy? Ui { get; set; }
    public uint? TimeoutMs { get; set; }

    public Containment Containment { get; set; } = new Containment.Process();

    public string? ContainerName { get; set; }
    public string? WorkingDirectory { get; set; }
    public Dictionary<string, string>? Environment { get; set; }
    public bool InheritDefaultEnvironment { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.Containment`

Choose one of the SDK-supported containment configurations.

```csharp
public abstract class Containment
{
}
```


## `Microsoft.Mxc.Sdk.V1.Containment.Bubblewrap`

Explicit Linux Bubblewrap configuration.

```csharp
public sealed class Bubblewrap : Containment
{
    public Bubblewrap();
}
```


## `Microsoft.Mxc.Sdk.V1.Containment.IsolationSession`

Windows IsolationSession backend, which runs the workload under an isolated agent user account.

```csharp
public sealed class IsolationSession : Containment
{
    public IsolationSession();
}
```


## `Microsoft.Mxc.Sdk.V1.Containment.Lxc`

Explicit Linux LXC configuration.

```csharp
public sealed class Lxc : Containment
{
    public Lxc();

    public string Distribution { get; set; } = "alpine";
    public string Release { get; set; } = "3.23";
}
```


## `Microsoft.Mxc.Sdk.V1.Containment.Process`

The host's native process-isolation backend: ProcessContainer on Windows, Bubblewrap on Linux, and Seatbelt on macOS.

```csharp
public sealed class Process : Containment
{
    public Process();
}
```


## `Microsoft.Mxc.Sdk.V1.Containment.ProcessContainer`

Explicit Windows ProcessContainer configuration.

```csharp
public sealed class ProcessContainer : Containment
{
    public ProcessContainer();

    public bool LearningMode { get; set; }

    public List<string> Capabilities { get; set; } = new();

    public CaptureDenialsPolicy? CaptureDenials { get; set; }

    public ProcessContainerUiPolicy? Ui { get; set; } = new();

    public ProcessContainerFilesystemPolicy? Filesystem { get; set; }
    public ProcessContainerNetworkPolicy? Network { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.Containment.Seatbelt`

Explicit macOS Seatbelt configuration.

```csharp
public sealed class Seatbelt : Containment
{
    public Seatbelt();

    public string? ProfileOverride { get; set; }
    public bool GuiAccess { get; set; }
    public bool NestedPty { get; set; } = true;
    public bool KeychainAccess { get; set; }

    public List<string> ExtraMachLookups { get; set; } = new();
}
```


## `Microsoft.Mxc.Sdk.V1.Containment.Wslc`

WSL Container backend configuration.

```csharp
public sealed class Wslc : Containment
{
    public Wslc();

    public string Image { get; set; } = "alpine:latest";
    public string? ImageTarPath { get; set; }
    public uint? CpuCount { get; set; }
    public ulong? MemoryMb { get; set; }
    public bool Gpu { get; set; }
    public string? StoragePath { get; set; }

    public List<WslcPortMapping> PortMappings { get; set; } = new();
}
```


## `Microsoft.Mxc.Sdk.V1.ContainmentBackend`

A containment backend reported by native host discovery.

```csharp
public enum ContainmentBackend
{
    Unknown,
    ProcessContainer,
    WindowsSandbox,
    Lxc,
    Wslc,
    Seatbelt,
    IsolationSession,
    Bubblewrap,
    Hyperlight,
}
```


## `Microsoft.Mxc.Sdk.V1.DeprovisionOptions`

Invocation controls for releasing a provisioned container.

```csharp
public sealed class DeprovisionOptions
{
    public DeprovisionOptions();

    public TelemetryConfig? Telemetry { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.ErrorCode`

Error codes returned across the native FFI boundary.

```csharp
public enum ErrorCode
{
    Success = 0,
    MalformedRequest = 1,
    UnsupportedContainment = 2,
    UnsupportedPhase = 3,
    BackendUnavailable = 4,
    MalformedId = 5,
    StaleId = 6,
    NotProvisioned = 7,
    NotStarted = 8,
    AlreadyStarted = 9,
    AlreadyStopped = 10,
    PolicyValidation = 11,
    BackendError = 12,
    NullArgument = 100,
    InvalidUtf8 = 101,
    Panic = 102,
    ConsentWriteFailed = 103,
}
```


## `Microsoft.Mxc.Sdk.V1.ExecutionResult`

The result of running a container to completion via MxcContainer.Run(ContainerRequest).

```csharp
public sealed class ExecutionResult
{
    public ExecutionResult();

    public int ExitCode { get; init; }
    public bool TimedOut { get; init; }
    public string Stdout { get; init; } = string.Empty;
    public string Stderr { get; init; } = string.Empty;
    public ExecutionMetadata? OutputMetadata { get; init; }

    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}
```


## `Microsoft.Mxc.Sdk.V1.FilesystemPolicy`

Filesystem settings carried directly by a ContainerRequest.

```csharp
public sealed class FilesystemPolicy
{
    public FilesystemPolicy();

    public List<string> ReadwritePaths { get; set; } = new();

    public List<string> ReadonlyPaths { get; set; } = new();

    public List<string> DeniedPaths { get; set; } = new();

    public bool? ClearPolicyOnExit { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.Policy.Filesystem`

Discovers host paths commonly needed by contained developer tools.

```csharp
public static class Filesystem
{
    public static FilesystemPolicyResult GetAvailableToolsPolicy(
        IReadOnlyDictionary<string, string?>? environment = null);

    public static FilesystemPolicyResult GetUserProfilePolicy(
        IReadOnlyDictionary<string, string?>? environment = null);

    public static FilesystemPolicyResult GetTemporaryFilesPolicy(
        IReadOnlyDictionary<string, string?>? environment = null);
}
```


## `Microsoft.Mxc.Sdk.V1.Policy.FilesystemPolicyResult`

A composable filesystem-policy fragment discovered from the host.

```csharp
public sealed class FilesystemPolicyResult
{
    public FilesystemPolicyResult();

    public IReadOnlyList<string> ReadonlyPaths { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> ReadwritePaths { get; init; } = Array.Empty<string>();
}
```


## `Microsoft.Mxc.Sdk.V1.IMxcProcess`

Injectable abstraction for a live container process.

```csharp
public interface IMxcProcess : IDisposable
{
    uint Id { get; }
    Stream? StandardInput { get; }
    Stream? StandardOutput { get; }
    Stream? StandardError { get; }
    IMxcStreamCloser? StandardOutputCloser { get; }
    IMxcStreamCloser? StandardErrorCloser { get; }
    IReadOnlyList<string> Warnings { get; }
    ExecutionMetadata? OutputMetadata { get; }
    WaitResult Wait();
    Task<WaitResult> WaitAsync(CancellationToken cancellationToken = default);
    bool TryGetExitCode(out int exitCode);
    Task<(WaitResult Result, byte[] Stdout, byte[] Stderr)> WaitForExitWithOutputAsync(
        CancellationToken cancellationToken = default);
    void Kill();
}
```


## `Microsoft.Mxc.Sdk.V1.IMxcStreamCloser`

Injectable handle that interrupts reads from one container process output stream.

```csharp
public interface IMxcStreamCloser : IDisposable
{
    void Close();
}
```


## `Microsoft.Mxc.Sdk.V1.IsolationSessionProvisionMetadata`

Metadata returned by IsolationSession provision.

```csharp
public sealed class IsolationSessionProvisionMetadata : ProvisionMetadata
{
    public IsolationSessionProvisionMetadata();

    public required string AgentUserName { get; init; }
    public required string AgentUserSid { get; init; }
    public required string EphemeralWorkspacePath { get; init; }
}
```


## `Microsoft.Mxc.Sdk.V1.IsolationSessionProvisionRequest`

IsolationSession provision request.

```csharp
public sealed class IsolationSessionProvisionRequest : ProvisionRequest
{
    public IsolationSessionProvisionRequest(NetworkPolicy network);

    public NetworkPolicy Network { get; set; }
    public string? AppId { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.IsolationTier`

The effective Windows ProcessContainer isolation tier.

```csharp
public enum IsolationTier
{
    Unknown,
    BaseContainer,
    AppContainerBfs,
    AppContainerDacl,
}
```


## `Microsoft.Mxc.Sdk.V1.LifecycleContainmentKind`

The containment backend a container is provisioned under.

```csharp
public enum LifecycleContainmentKind
{
    IsolationSession,
    Wslc,
}
```


## `Microsoft.Mxc.Sdk.V1.MxcContainer`

V1 entry point for running MXC containers from C#.

```csharp
public static class MxcContainer
{
    public static ProbeOutput Probe(ContainerRequest? request = null);

    public static ExecutionResult Run(ContainerRequest request, RunOptions? options = null);

    public static Task<ExecutionResult> RunAsync(
        ContainerRequest request,
        RunOptions? options = null,
        CancellationToken cancellationToken = default);

    public static MxcProcess Spawn(ContainerRequest request, SpawnOptions? options = null);

    public static Task<MxcProcess> SpawnAsync(
        ContainerRequest request,
        SpawnOptions? options = null,
        CancellationToken cancellationToken = default);

    public static MxcPtyProcess SpawnWithPty(
        ContainerRequest request,
        SpawnWithPtyOptions? options = null);
}
```


## `Microsoft.Mxc.Sdk.V1.MxcException`

Thrown when an MXC operation fails.

```csharp
public sealed class MxcException : Exception
{
    public ErrorCode Code { get; }
    public string? Operation { get; }
    public string? NativeCode { get; }
    public string? Remediation { get; }

    public MxcException(ErrorCode code, string message)
    : this(code, message, null, null, null);

    public override string ToString();
}
```


## `Microsoft.Mxc.Sdk.V1.MxcLifecycle`

Drives an IsolationSession or WSLC container through provision, start, execution, stop, and deprovision.

```csharp
public static class MxcLifecycle
{
    public const string SdkContractVersion = SchemaVersions.SdkContract;
    public const string IsolationSessionContainment = "isolation_session";
    public const string WslcContainment = "wslc";

    public static ProvisionResult ProvisionContainer(
        ProvisionRequest request,
        ProvisionOptions? options = null);

    public static ValidationResult ValidateProvision(
        ProvisionRequest request,
        ProvisionOptions? options = null);

    public static LifecycleResult StartContainer(ContainerId id, StartOptions? options = null);

    public static ValidationResult ValidateStart(ContainerId id, StartOptions? options = null);

    public static MxcProcess SpawnInContainer(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerOptions? options = null);

    public static Task<MxcProcess> SpawnInContainerAsync(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerOptions? options = null,
        CancellationToken cancellationToken = default);

    public static MxcPtyProcess SpawnInContainerWithPty(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerWithPtyOptions? options = null);

    public static ValidationResult ValidateProcess(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerOptions? options = null);

    public static Task<ExecutionResult> RunInContainerAsync(
        ContainerId id,
        ExecutionRequest request,
        RunInContainerOptions? options = null,
        CancellationToken cancellationToken = default);

    public static ExecutionResult RunInContainer(
        ContainerId id,
        ExecutionRequest request,
        RunInContainerOptions? options = null);

    public static LifecycleResult StopContainer(ContainerId id, StopOptions? options = null);

    public static ValidationResult ValidateStop(ContainerId id, StopOptions? options = null);

    public static LifecycleResult DeprovisionContainer(
        ContainerId id,
        DeprovisionOptions? options = null);

    public static ValidationResult ValidateDeprovision(
        ContainerId id,
        DeprovisionOptions? options = null);
}
```


## `Microsoft.Mxc.Sdk.V1.MxcPlatform`

Host and native-library information for the MXC SDK.

```csharp
public static class MxcPlatform
{
    public static string NativeVersion { get; }

    public static IReadOnlyList<AvailableBackend> GetAvailableBackends();

    public static PlatformSupport GetPlatformSupport();
}
```


## `Microsoft.Mxc.Sdk.V1.MxcProcess`

A live process spawned by MxcContainer.Spawn(ContainerRequest).

```csharp
public class MxcProcess : IMxcProcess
{
    public uint Id { get; }
    public Stream? StandardInput { get; }
    public Stream? StandardOutput { get; }
    public Stream? StandardError { get; }
    public MxcStreamCloser? StandardOutputCloser { get; }
    public MxcStreamCloser? StandardErrorCloser { get; }
    public IReadOnlyList<string> Warnings { get; }
    public ExecutionMetadata? OutputMetadata { get; }

    public WaitResult Wait();

    public Task<WaitResult> WaitAsync(CancellationToken cancellationToken = default);

    public bool TryGetExitCode(out int exitCode);

    public Task<(WaitResult Result, byte[] Stdout, byte[] Stderr)> WaitForExitWithOutputAsync(
        CancellationToken cancellationToken = default);

    public void Kill();

    public void Dispose();
}
```


## `Microsoft.Mxc.Sdk.V1.MxcPtyProcess`

A live container process attached to a caller-driven pseudo-terminal.

```csharp
public sealed class MxcPtyProcess : MxcProcess
{
    public Stream Input { get; }
    public Stream Output { get; }

    public void Resize(MxcPtySize size);
}
```


## `Microsoft.Mxc.Sdk.V1.MxcPtySize`

Dimensions of an MXC pseudo-terminal.

```csharp
public readonly record struct MxcPtySize(ushort Rows, ushort Columns)
{
    public ushort Columns { get; init; }
    public ushort Rows { get; init; }

    public static MxcPtySize Default { get; } = new(24, 80);
}
```


## `Microsoft.Mxc.Sdk.V1.MxcStreamCloser`

Independently closes a container process output reader, making a blocking read return EOF without terminating the process.

```csharp
public sealed class MxcStreamCloser : IMxcStreamCloser
{
    public void Close();

    public void Dispose();
}
```


## `Microsoft.Mxc.Sdk.V1.MxcTelemetry`

Administers MXC telemetry consent.

```csharp
public static class MxcTelemetry
{
    public static TelemetryConsentState GetConsent();

    public static bool NeedsConsentPrompt();

    public static TelemetryPolicyState GetPolicy();

    public static TelemetryConsentOutcome RequestConsent(
        Func<TelemetryConsentPrompt, TelemetryConsentDecision> presenter,
        string? locale = null);

    public static Task<TelemetryConsentOutcome> RequestConsentAsync(
        Func<TelemetryConsentPrompt, ValueTask<TelemetryConsentDecision>> presenter,
        string? locale = null,
        CancellationToken cancellationToken = default);

    public static TelemetryConsentStatus GetConsentStatus();

    public static TelemetryConsentOutcome WithdrawConsent();
}
```


## `Microsoft.Mxc.Sdk.V1.NetworkAction`

Allow or deny a network action.

```csharp
public enum NetworkAction
{
    Allow,
    Deny,
}
```


## `Microsoft.Mxc.Sdk.V1.NetworkEgressPolicy`

Supported directional outbound network policy.

```csharp
public sealed class NetworkEgressPolicy
{
    public NetworkEgressPolicy();

    public NetworkAction? Default { get; set; }
    public List<NetworkRulePolicy>? Allow { get; set; }
    public List<NetworkRulePolicy>? Deny { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.NetworkIngressPolicy`

Supported directional inbound and host-loopback network policy.

```csharp
public sealed class NetworkIngressPolicy
{
    public NetworkIngressPolicy();

    public NetworkAction? Default { get; set; }
    public NetworkAction? HostLoopback { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.NetworkPeerPolicy`

A CIDR network peer.

```csharp
public sealed class NetworkPeerPolicy
{
    public NetworkPeerPolicy(string cidr);

    public string Cidr { get; }
    public List<string>? Except { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.NetworkPolicy`

Directional network authoring section for the v1 high-level SDK.

```csharp
public sealed class NetworkPolicy
{
    public NetworkPolicy();

    public NetworkEgressPolicy? Egress { get; set; }
    public NetworkIngressPolicy? Ingress { get; set; }
    public NetworkRuntimeConfig? RuntimeConfig { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.NetworkPortPolicy`

A protocol and destination-port selector.

```csharp
public sealed class NetworkPortPolicy
{
    public NetworkPortPolicy();

    public NetworkProtocol? Protocol { get; set; }
    public ushort? Port { get; set; }
    public ushort? EndPort { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.NetworkProtocol`

Transport protocol selector.

```csharp
public enum NetworkProtocol
{
    Tcp,
    Udp,
    Icmp,
    Any,
}
```


## `Microsoft.Mxc.Sdk.V1.NetworkRulePolicy`

An outbound network rule.

```csharp
public sealed class NetworkRulePolicy
{
    public NetworkRulePolicy();

    public List<NetworkPeerPolicy>? To { get; set; }
    public List<NetworkPortPolicy>? Ports { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.NetworkRuntimeConfig`

Supported runtime network values.

```csharp
public sealed class NetworkRuntimeConfig
{
    public NetworkRuntimeConfig();

    public string? NetworkProxy { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.ExecutionMetadata`

Structured outputs produced by optional container features.

```csharp
public sealed class ExecutionMetadata
{
    public ExecutionMetadata();

    public CaptureDenialsResult? CaptureDenials { get; init; }
    public CaptureDenialsError? CaptureDenialsError { get; init; }
}
```


## `Microsoft.Mxc.Sdk.V1.PlatformSupport`

Support for the containment backends the public SDK can launch.

```csharp
public sealed class PlatformSupport
{
    public PlatformSupport();

    public bool IsSupported { get; init; }
    public string? Reason { get; init; }
    public IReadOnlyList<ContainmentBackend> AvailableMethods { get; init; } =
        Array.Empty<ContainmentBackend>();
}
```


## `Microsoft.Mxc.Sdk.V1.ProbeFacts`

Raw host facts used by request tier selection.

```csharp
public sealed class ProbeFacts
{
    public ProbeFacts();

    public bool BaseContainerApiPresent { get; init; }
    public bool NativeCaptureAvailable { get; init; }
    public bool GuardedCaptureAvailable { get; init; }
    public bool BfscfgPresent { get; init; }
    public bool BfsCompiledIn { get; init; }
    public bool BaseContainerSupportsDenyPaths { get; init; }
    public bool BaseContainerSupportsEnumeratePaths { get; init; }
    public bool BaseContainerSupportsIngressHostLoopbackAllow { get; init; }
    public bool BaseContainerSupportsIdentitylessLoopbackProxy { get; init; }
    public bool IsolationSessionAvailable { get; init; }
    public bool HyperlightAvailable { get; init; }
    public required UiCapabilitySupport UiCapabilities { get; init; }
}
```


## `Microsoft.Mxc.Sdk.V1.ProbeOutput`

Result of probing which Windows ProcessContainer tier can serve a request.

```csharp
public sealed class ProbeOutput
{
    public ProbeOutput();

    public IsolationTier? Tier { get; init; }
    public bool? NeedsDaclAugmentation { get; init; }

    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

    public required ProbeFacts Probes { get; init; }
    public string? Error { get; init; }
}
```


## `Microsoft.Mxc.Sdk.V1.ProcessContainerFilesystemPolicy`

ProcessContainer-specific filesystem settings.

```csharp
public sealed class ProcessContainerFilesystemPolicy
{
    public ProcessContainerFilesystemPolicy();

    public List<string> EnumeratePaths { get; set; } = new();
}
```


## `Microsoft.Mxc.Sdk.V1.ProcessContainerNetworkPolicy`

ProcessContainer-specific directional network settings.

```csharp
public sealed class ProcessContainerNetworkPolicy
{
    public ProcessContainerNetworkPolicy();

    public string? AllowedProxyPeer { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.ProcessContainerSystemSettings`

ProcessContainer system-settings access level.

```csharp
public enum ProcessContainerSystemSettings
{
    All,
    Parameters,
    Display,
    None,
}
```


## `Microsoft.Mxc.Sdk.V1.ProcessContainerUiIsolation`

ProcessContainer desktop-resource isolation level.

```csharp
public enum ProcessContainerUiIsolation
{
    Desktop,
    Handles,
    Atoms,
    Container,
}
```


## `Microsoft.Mxc.Sdk.V1.ProcessContainerUiPolicy`

BaseProcessContainer-specific UI settings.

```csharp
public sealed class ProcessContainerUiPolicy
{
    public ProcessContainerUiPolicy();

    public ProcessContainerUiIsolation Isolation { get; set; } =
        ProcessContainerUiIsolation.Container;
    public bool DesktopSystemControl { get; set; }
    public ProcessContainerSystemSettings SystemSettings { get; set; } =
        ProcessContainerSystemSettings.None;
    public bool Ime { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.ProcessNetworkPolicy`

Runtime network settings available to an existing-container execution.

```csharp
public sealed class ProcessNetworkPolicy
{
    public ProcessNetworkPolicy();

    public NetworkRuntimeConfig? RuntimeConfig { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.ExecutionRequest`

A workload and its process settings for an existing container.

```csharp
public sealed class ExecutionRequest
{
    public TelemetryConfig? Telemetry { get; set; }

    public ExecutionRequest(string command);

    public string Command { get; }
    public string? WorkingDirectory { get; set; }
    public Dictionary<string, string>? Environment { get; set; }
    public bool? InheritDefaultEnvironment { get; set; }
    public uint? TimeoutMs { get; set; }
    public ProcessNetworkPolicy? Network { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.ProvisionOptions`

Invocation controls for provisioning a container.

```csharp
public sealed class ProvisionOptions
{
    public ProvisionOptions();

    public TelemetryConfig? Telemetry { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.ProvisionRequest`

Closed request for provisioning a supported containment.

```csharp
public abstract class ProvisionRequest
{
    public TelemetryConfig? Telemetry { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.ProvisionMetadata`

Closed backend-specific metadata returned by provisioning.

```csharp
public abstract class ProvisionMetadata
{
    private protected ProvisionMetadata();
}
```


## `Microsoft.Mxc.Sdk.V1.ProvisionResult`

The result of MxcLifecycle.ProvisionContainer.

```csharp
public sealed class ProvisionResult
{
    public ProvisionResult();

    public ContainerId ContainerId { get; init; }
    public ProvisionMetadata? Metadata { get; init; }
    public string[] Warnings { get; set; }
}
```

## `Microsoft.Mxc.Sdk.V1.LifecycleResult`

Warnings returned by successfully starting, stopping, or deprovisioning a container.

```csharp
public sealed class LifecycleResult
{
    public LifecycleResult();
    public string[] Warnings { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.RunInContainerOptions`

Invocation controls for captured execution in an existing container.

```csharp
public sealed class RunInContainerOptions
{
    public RunInContainerOptions();

    public TelemetryConfig? Telemetry { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.RunOptions`

Invocation controls for Run and RunAsync.

```csharp
public sealed class RunOptions
{
    public RunOptions();

    public TelemetryConfig? Telemetry { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.ValidationResult`

Warnings returned by validating an operation without executing it.
Omitted native warnings become an empty array; malformed warnings fail.

```csharp
public sealed class ValidationResult
{
    public ValidationResult();

    public string[] Warnings { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.SchemaVersions`

Schema versions supported by this SDK release.

```csharp
public static class SchemaVersions
{
    public const string Minimum = "0.9.0-alpha";
    public const string MaximumSupported = "1.1.0-alpha";
    public const string LatestStable = "1.0.0";
}
```


## `Microsoft.Mxc.Sdk.V1.SpawnInContainerOptions`

Invocation controls for spawning a workload in an existing container.

```csharp
public sealed class SpawnInContainerOptions
{
    public SpawnInContainerOptions();

    public TelemetryConfig? Telemetry { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.SpawnInContainerWithPtyOptions`

Invocation controls for a terminal in an existing container.

```csharp
public sealed class SpawnInContainerWithPtyOptions
{
    public SpawnInContainerWithPtyOptions();

    public TelemetryConfig? Telemetry { get; set; }
    public MxcPtySize? Size { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.SpawnOptions`

Invocation controls for Spawn and SpawnAsync.

```csharp
public sealed class SpawnOptions
{
    public SpawnOptions();

    public TelemetryConfig? Telemetry { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.SpawnWithPtyOptions`

Invocation controls for spawning a caller-controlled terminal.

```csharp
public sealed class SpawnWithPtyOptions
{
    public SpawnWithPtyOptions();

    public TelemetryConfig? Telemetry { get; set; }
    public MxcPtySize? Size { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.StartOptions`

Invocation controls for starting a provisioned container.

```csharp
public sealed class StartOptions
{
    public StartOptions();

    public TelemetryConfig? Telemetry { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.StopOptions`

Invocation controls for stopping a running container.

```csharp
public sealed class StopOptions
{
    public StopOptions();

    public TelemetryConfig? Telemetry { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.TelemetryConsentActionResult`

Result of a consent request or withdrawal.

```csharp
public enum TelemetryConsentActionResult
{
    Unknown = 0,
    Granted = 1,
    Denied = 2,
    Dismissed = 3,
    Withdrawn = 4,
    AlreadyGranted = 5,
    PolicyBlocked = 6,
    NotApplicable = 7,
}
```


## `Microsoft.Mxc.Sdk.V1.TelemetryConsentDecision`

The explicit result returned by a host consent presenter.

```csharp
public enum TelemetryConsentDecision
{
    No,
    Yes,
    Dismissed,
}
```


## `Microsoft.Mxc.Sdk.V1.TelemetryConsentMessage`

An independently localizable canonical consent message.

```csharp
public sealed record TelemetryConsentMessage(string Id, string Text)
{
    public string Text { get; init; }
    public string Id { get; init; }
}
```


## `Microsoft.Mxc.Sdk.V1.TelemetryConsentOutcome`

Result and resulting status of a consent-changing operation.

```csharp
public sealed record TelemetryConsentOutcome(
    TelemetryConsentActionResult Result,
    TelemetryConsentState StoredState,
    TelemetryConsentState EffectiveState,
    TelemetryPolicyState Policy) {
    public TelemetryPolicyState Policy { get; init; }
    public TelemetryConsentState EffectiveState { get; init; }
    public TelemetryConsentState StoredState { get; init; }
    public TelemetryConsentActionResult Result { get; init; }
}
```


## `Microsoft.Mxc.Sdk.V1.TelemetryConsentPrompt`

The complete Rust-owned consent resource a host must render verbatim.

```csharp
public sealed record TelemetryConsentPrompt(
    uint ResourceVersion,
    string Locale,
    TelemetryConsentMessage Title,
    TelemetryConsentMessage Body,
    TelemetryConsentMessage AffirmativeLabel,
    TelemetryConsentMessage NegativeLabel,
    TelemetryConsentMessage LearnMoreLabel,
    string LearnMoreUrl) {
    public string LearnMoreUrl { get; init; }
    public TelemetryConsentMessage LearnMoreLabel { get; init; }
    public TelemetryConsentMessage NegativeLabel { get; init; }
    public TelemetryConsentMessage AffirmativeLabel { get; init; }
    public TelemetryConsentMessage Body { get; init; }
    public TelemetryConsentMessage Title { get; init; }
    public string Locale { get; init; }
    public uint ResourceVersion { get; init; }
}
```


## `Microsoft.Mxc.Sdk.V1.TelemetryConsentState`

Telemetry consent state used for both persisted and effective values.

```csharp
public enum TelemetryConsentState
{
    Undetermined = 0,
    Granted = 1,
    Denied = 2,
    NotApplicable = 3,
}
```


## `Microsoft.Mxc.Sdk.V1.TelemetryConsentStatus`

Persisted and effective consent together with the policy ceiling.

```csharp
public sealed record TelemetryConsentStatus(
    TelemetryConsentState StoredState,
    TelemetryConsentState EffectiveState,
    TelemetryPolicyState Policy) {
    public TelemetryPolicyState Policy { get; init; }
    public TelemetryConsentState EffectiveState { get; init; }
    public TelemetryConsentState StoredState { get; init; }
}
```


## `Microsoft.Mxc.Sdk.V1.TelemetryPolicyState`

The administrative (MDM / Group Policy) telemetry decision for this machine.

```csharp
public enum TelemetryPolicyState
{
    Blocked = 0,
    Unrestricted = 1,
    Allowed = 2,
    NotApplicable = 3,
}
```


## `Microsoft.Mxc.Sdk.V1.TelemetryConfig`

Per-invocation telemetry preference, subject to consent and policy.

```csharp
public sealed class TelemetryConfig
{
    public TelemetryConfig();

    public bool? Enabled { get; set; }
}
```

## `Microsoft.Mxc.Sdk.V1.UiCapabilitySupport`

Host support for enforcing container UI restrictions.

```csharp
public sealed class UiCapabilitySupport
{
    public UiCapabilitySupport();

    public bool CanBlockClipboardRead { get; init; }
    public bool CanBlockClipboardWrite { get; init; }
    public bool CanBlockInputInjection { get; init; }
    public bool CanBlockInputMethodChanges { get; init; }
    public bool CanBlockExternalUiObjects { get; init; }
    public bool CanBlockGlobalUiNamespace { get; init; }
    public bool CanBlockDesktopSwitching { get; init; }
    public bool CanBlockLogoffOrShutdown { get; init; }
    public bool CanBlockSystemParameterChanges { get; init; }
    public bool CanBlockDisplaySettingsChanges { get; init; }
}
```


## `Microsoft.Mxc.Sdk.V1.UiPolicy`

UI settings carried directly by a ContainerRequest.

```csharp
public sealed class UiPolicy
{
    public UiPolicy();

    public bool Disable { get; set; } = true;
    public ClipboardPolicy Clipboard { get; set; } = ClipboardPolicy.None;
    public bool AllowInputInjection { get; set; }
}
```


## `Microsoft.Mxc.Sdk.V1.WaitResult`

The result of waiting for a contained process to finish.

```csharp
public readonly struct WaitResult
{
    public int ExitCode { get; init; }
    public bool TimedOut { get; init; }
}
```


## `Microsoft.Mxc.Sdk.V1.WslcPortMapping`

A WSLC host-to-container TCP port mapping.

```csharp
public sealed class WslcPortMapping
{
    public WslcPortMapping(int windowsPort, int containerPort);

    public ushort WindowsPort { get; }
    public ushort ContainerPort { get; }
}
```


## `Microsoft.Mxc.Sdk.V1.WslcProvisionRequest`

WSLC provision request.

```csharp
public sealed class WslcProvisionRequest : ProvisionRequest
{
    public WslcProvisionRequest();

    public FilesystemPolicy? Filesystem { get; set; }
    public NetworkPolicy? Network { get; set; }
    public string? Image { get; set; }
    public string? ImageTarPath { get; set; }
}
```
