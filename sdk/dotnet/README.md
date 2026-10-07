# Microsoft.Mxc.Sdk

> **Audience:** MXC consumers

`Microsoft.Mxc.Sdk` provides .NET APIs for authoring and executing MXC
container requests through the in-process native `mxc_ffi` library. The
versioned public API is in `Microsoft.Mxc.Sdk.V1`. All request and policy types
in this API use the SDK-selected contract version; callers do not select
that version. See the [consumer glossary](https://github.com/microsoft/mxc/blob/main/docs/glossary.md) for terminology.

## ProcessContainer policy errors

On capable Windows BaseContainer hosts, policy-denied creation (`0x800704EC`)
automatically retrieves the calling thread's cached refusal and includes
available outcome/action details in `MxcException.Message`. Use ordinary V1
`MxcContainer.Run`, `RunAsync`, `Spawn`, or `SpawnAsync` errors.
No new request option, report DTO, or additional experimental authorization
is required. Successful outputs and existing exception codes are unchanged.

The message includes the native operation and HRESULT; the optional
`Operation` and `NativeCode` properties can still be null. Always preserve the
message, not only optional metadata. Missing or failed retrieval cannot
replace the creation error; success and non-policy failures are not queried.
MXC does not mutate the request or retry a policy refusal. Returned
constraints are non-exhaustive and can be unknown or incomplete; the prose
is not a supported parsing contract. See
[detailed policy errors](../../docs/development/guides/process-container-adding-os-features.md#detailed-policy-errors).

## Run to completion

```csharp
using Microsoft.Mxc.Sdk.V1;

var request = new ContainerRequest("cmd /c echo hello")
{
    Filesystem = new FilesystemPolicy
    {
        ReadwritePaths = { @"C:\work" },
    },
    TimeoutMs = 30_000,
};

ExecutionResult output = await MxcContainer.RunAsync(request);
Console.WriteLine($"exit={output.ExitCode} stdout={output.Stdout}");
```

Use `MxcContainer.Run` / `RunAsync` for captured output.
Cancelling `RunAsync` stops awaiting the result; native execution continues
until completion or the request timeout.

## Spawn with streaming output

```csharp
using Microsoft.Mxc.Sdk.V1;

using var process = await MxcContainer.SpawnAsync(
    new ContainerRequest("cmd /c echo hello from container") { TimeoutMs = 30_000 });
Task stdout = process.StandardOutput is { } output
    ? output.CopyToAsync(Console.OpenStandardOutput()) : Task.CompletedTask;
Task stderr = process.StandardError is { } error
    ? error.CopyToAsync(Console.OpenStandardError()) : Task.CompletedTask;
WaitResult result = await process.WaitAsync();
await Task.WhenAll(stdout, stderr);
Console.WriteLine($"exit={result.ExitCode}");
```

`Spawn` / `SpawnAsync` return a live `MxcProcess` with separate stdin, stdout,
and stderr streams, plus wait, termination, and disposal operations. Shared filesystem,
network, and UI restrictions are authored directly on `ContainerRequest`,
alongside the selected backend configuration. The SDK selects the contract
version; `ContainerRequest` does not accept a caller-selected schema version.

`UiPolicy.Disable` defaults to `true`; clipboard and input-injection
permissions are authored separately.

`ContainerRequest.Containment` accepts the SDK-defined `Containment` choices. Select an
SDK-owned nested choice such as `Containment.Process` (the default),
`Containment.ProcessContainer`, or `Containment.Wslc`. Backend semantics are
validated by the native engine.

Creation methods accept their own `RunOptions`, `SpawnOptions`, or
`SpawnWithPtyOptions` after the request. Set `SpawnWithPtyOptions.Size` to
choose initial dimensions; it defaults to 24 rows by 80 columns. Async cancellation
tokens come last.

## Spawn with a caller-controlled terminal

PTY execution supports IsolationSession on Windows with the native
`isolation_session` feature enabled, Bubblewrap and LXC on Linux, and Seatbelt
direct execution on macOS. IsolationSession requires explicit unrestricted
networking because it cannot enforce network restrictions.

```csharp
using System.Text;
using Microsoft.Mxc.Sdk.V1;

using var terminal = MxcContainer.SpawnWithPty(
    new ContainerRequest("cmd.exe")
    {
        Containment = new Containment.IsolationSession(),
        Network = new NetworkPolicy
        {
            Egress = new NetworkEgressPolicy { Default = NetworkAction.Allow },
            Ingress = new NetworkIngressPolicy
            {
                Default = NetworkAction.Allow,
                HostLoopback = NetworkAction.Allow,
            },
        },
        TimeoutMs = 30_000,
    },
    new SpawnWithPtyOptions { Size = new MxcPtySize(24, 80) });
Task output = terminal.Output.CopyToAsync(Console.OpenStandardOutput());
await terminal.Input.WriteAsync(
    Encoding.UTF8.GetBytes("echo hello from terminal\r\nexit\r\n"));
terminal.Input.Dispose();
WaitResult result = await terminal.WaitAsync();
await output;
Console.WriteLine($"exit={result.ExitCode}");
```

`SpawnWithPty` returns an `MxcPtyProcess` with merged terminal output and
resizing support. Initial dimensions default to 24 rows by 80 columns.
PTY stderr is merged into `Output`. Closing `Input` requests terminal EOF in
canonical mode; raw-mode applications must use their own completion protocol.
Seatbelt rejects PTY mode with `guiAccess` or legacy `launchMethod: "open"`.
Unsupported combinations are rejected before sandbox creation.

## Lifecycle API

`ProvisionResult.Metadata` is an optional `ProvisionMetadata` value. For
IsolationSession, pattern-match `IsolationSessionProvisionMetadata` to read the
agent account and workspace details. WSLC returns no provision metadata. Native
metadata is converted to these SDK-defined types; callers do not parse native result JSON.

`MxcLifecycle` provides typed provision, start, exec, stop, and deprovision
operations. The provision result contains an opaque `ContainerId`; pass it to
subsequent operations rather than parsing it.

```csharp
using Microsoft.Mxc.Sdk.V1;

var provisioned = MxcLifecycle.ProvisionContainer(
    new IsolationSessionProvisionRequest(new NetworkPolicy
    {
        Egress = new NetworkEgressPolicy { Default = NetworkAction.Allow },
        Ingress = new NetworkIngressPolicy
        {
            Default = NetworkAction.Allow,
            HostLoopback = NetworkAction.Allow,
        },
    }));
ContainerId id = provisioned.ContainerId;

try
{
    MxcLifecycle.StartContainer(id);
    try
    {
        ExecutionResult output = await MxcLifecycle.RunInContainerAsync(
            id, new ExecutionRequest("echo hello from lifecycle") { TimeoutMs = 30_000 });
        Console.WriteLine(output.Stdout);
    }
    finally
    {
        MxcLifecycle.StopContainer(id);
    }
}
finally
{
    MxcLifecycle.DeprovisionContainer(id);
}
```

Use `SpawnInContainer` or `SpawnInContainerAsync` for live piped execution. The
asynchronous methods are convenience wrappers over native operations and
support cancellation. Backend and phase-specific policy requirements are
described in the
[IsolationSession](https://github.com/microsoft/mxc/blob/main/docs/development/architecture/backends/isolation-session/state-aware-rust.md) and
[WSLC](https://github.com/microsoft/mxc/blob/main/docs/backends/wslc/wslc-state-aware.md) guides.
`MxcLifecycle.SpawnInContainerWithPty(id, request, options?)` starts an
IsolationSession exec with a caller-controlled terminal and returns an
`MxcPtyProcess`. Set `SpawnInContainerWithPtyOptions.Size` to choose initial
dimensions; it defaults to 24 rows by 80 columns.

`ExecutionRequest` supplies the command, working directory, environment, timeout,
telemetry, and runtime-only network settings to both `RunInContainer` and
`SpawnInContainer`. Existing-container network settings cannot change provision
policy:

```csharp
var request = new ExecutionRequest("echo hello")
{
    Network = new ProcessNetworkPolicy
    {
        RuntimeConfig = new NetworkRuntimeConfig
        {
            NetworkProxy = "http://proxy.example:8080",
        },
    },
};
```

Provisioning uses the same `FilesystemPolicy` and `NetworkPolicy` authoring
types as container creation; the selected backend determines what it enforces.

Provisioning takes an SDK-owned `ProvisionRequest` followed by optional
`ProvisionOptions`. Start, stop, and deprovision use `StartOptions`,
`StopOptions`, and `DeprovisionOptions`. Existing-container execution takes
the identity, `ExecutionRequest`, and its own `SpawnInContainerOptions`,
`RunInContainerOptions`, or `SpawnInContainerWithPtyOptions`; PTY initial
dimensions are on that options object. Invocation
telemetry overrides request telemetry when supplied.

`ValidateProvision`, `ValidateStart`, `ValidateStop`, `ValidateDeprovision`,
and `ValidateProcess` perform native dry-run validation and return
`ValidationResult` with policy and operational `Warnings`, not an execution
result. They accept the corresponding operation options.
Backend/platform discovery, errors, telemetry, and helpers are also in
`Microsoft.Mxc.Sdk.V1`; no public SDK types remain outside it.

## Public V1 types

| Purpose | .NET type |
| --- | --- |
| Creation workload and cross-backend restrictions | `ContainerRequest` |
| Persistent container identity | `ContainerId` |
| Persistent container provision input | `ProvisionRequest` |
| Existing-container workload | `ExecutionRequest` |
| Live process with standard pipes | `MxcProcess` |
| Live process with a terminal | `MxcPtyProcess` |
| Terminal dimensions | `MxcPtySize` |
| Captured execution | `ExecutionResult` |
| Terminal process outcome | `WaitResult` |

All types above are in `Microsoft.Mxc.Sdk.V1`. See the
[networking guide](https://github.com/microsoft/mxc/blob/main/docs/schema.md#directional-networking-supported-contracts);
for policy behavior and the
[SDK API reference](https://github.com/microsoft/mxc/blob/main/docs/api-reference/README.md)
for complete signatures and types.

## Errors, warnings, and discovery

Native failures are surfaced as `MxcException`; inspect `Code`, `Operation`,
`NativeCode`, and `Remediation` when available. Security and operational
warnings are available on `ExecutionResult.Warnings` and `MxcProcess.Warnings`.
Provision returns identity, optional typed metadata, and `ProvisionResult.Warnings`.
Start, stop, and deprovision return `LifecycleResult.Warnings`. Omitted native
warnings become an empty array; malformed warnings fail explicitly. When
IsolationSession provision metadata is present, `AgentUserName`, `AgentUserSid`,
and `EphemeralWorkspacePath` are required non-null strings.

`MxcPlatform.GetPlatformSupport()` reports whether the SDK can launch a
sandbox on the current host. `MxcPlatform.GetAvailableBackends()` reports
host backend capabilities; availability is advisory and launch-time
validation still applies.

Creation telemetry is supplied through `Telemetry` on `RunOptions`,
`SpawnOptions`, or `SpawnWithPtyOptions`, not on `ContainerRequest`. Omission
leaves telemetry disabled; `new TelemetryConfig { Enabled = false }`
explicitly disables it. Opt-in is still gated by MXC's persisted user consent
and administrative policy.

Filesystem discovery helpers are on `Microsoft.Mxc.Sdk.V1.Policy.Filesystem`
and return `FilesystemPolicyResult` from the same namespace. They take an
optional `environment` dictionary; `null` snapshots the process environment
and an empty dictionary remains empty. `GetAvailableToolsPolicy` discovers
existing tool directories and excludes system-critical paths; it does not
inspect ACLs. `GetUserProfilePolicy` uses the supplied environment,
and `GetTemporaryFilesPolicy` returns existing temporary storage without creating
directories.

## Package and native library

The package includes the native runtime assets for supported platforms.
Applications do not need to launch an MXC executor process. The governed build
pipeline produces the publishable NuGet package; `build.bat` creates local
architecture-specific packages under `output\packages`.

For API details, see the
[SDK API reference](https://github.com/microsoft/mxc/blob/main/docs/api-reference/README.md).
Build and validation commands are in the
[pull request guide](https://github.com/microsoft/mxc/blob/main/docs/development/build-and-test/pull-requests.md).
