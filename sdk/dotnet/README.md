# Microsoft.Mxc.Sdk

`Microsoft.Mxc.Sdk` provides .NET APIs for authoring and executing MXC
container requests through the in-process native `mxc_ffi` library. The
versioned public API is in `Microsoft.Mxc.Sdk.V1`. All request and policy types
in this API use the owned V1 contract rather than exposing a wire-version
selector.

## One-shot execution

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

ExecutionOutput output = await MxcContainer.RunAsync(request);
Console.WriteLine($"exit={output.ExitCode} stdout={output.Stdout}");
```

Use `MxcContainer.Run` / `RunAsync` for captured output or `Spawn` for a live
`MxcProcess` with separate stdin, stdout, and stderr streams. `MxcProcess`
provides wait, termination, and disposal operations. Shared filesystem,
network, and UI restrictions are authored directly on `ContainerRequest`,
alongside the selected backend configuration. The SDK owns the exact wire
contract; requests do not accept a caller-selected schema version.

`MxcContainer.SpawnWithPty(request, size?)` starts a one-shot request with a
caller-controlled terminal and returns an `MxcPtyProcess`. PTY support is
currently available for IsolationSession requests.

## Existing containers

`MxcLifecycle` provides typed provision, start, exec, stop, and deprovision
operations. The provision result contains an opaque `ContainerId`; pass it to
subsequent operations rather than parsing it.

```csharp
using Microsoft.Mxc.Sdk.V1;

var provisioned = MxcLifecycle.ProvisionSandbox(
    LifecycleBackend.Wslc,
    new WslcProvisionOptions { Image = "alpine:latest" });
ContainerId id = provisioned.ContainerId;

MxcLifecycle.StartSandbox(id);
ExecutionOutput output = await MxcLifecycle.ExecInSandboxAsync(
    id,
    new ExecRequest("echo hello"));
Console.WriteLine(output.Stdout);
MxcLifecycle.StopSandbox(id);
MxcLifecycle.DeprovisionSandbox(id);
```

Use `ExecInSandbox` or `SpawnInContainer` for live piped execution. The
asynchronous methods are convenience wrappers over native operations and
support cancellation. Backend and phase-specific policy requirements are
described in the
[IsolationSession](../../docs/isolation-session/state-aware-rust.md) and
[WSLC](../../docs/wsl/wslc-state-aware.md) guides.
`MxcLifecycle.SpawnInContainerWithPty(id, request, size?)` starts an
IsolationSession exec with a caller-controlled terminal and returns an
`MxcPtyProcess`.

## Public V1 types

| Purpose | .NET type |
| --- | --- |
| One-shot workload and cross-backend restrictions | `ContainerRequest` |
| Persistent container identity | `ContainerId` |
| Existing-container workload | `ExecRequest` |
| Live process with standard pipes | `MxcProcess` |
| Live process with a terminal | `MxcPtyProcess` |
| Terminal dimensions | `MxcPtySize` |
| Captured execution | `ExecutionOutput` |
| Terminal process outcome | `WaitOutcome` |

All types above are in `Microsoft.Mxc.Sdk.V1`. See the
[networking guide](../../docs/sandbox-policy/0.8.0/networking/networking.md)
and [schema reference](../../docs/schema.md) for policy behavior.

## Errors, warnings, and discovery

Native failures are surfaced as `MxcException`; inspect `Code`, `Operation`,
`NativeCode`, and `Remediation` when available. Security and operational
warnings are available on `ExecutionOutput.Warnings` and `MxcProcess.Warnings`.

`MxcPlatform.GetPlatformSupport()` reports whether the SDK can launch a
sandbox on the current host. `MxcPlatform.GetAvailableBackends()` reports
host backend capabilities; availability is advisory and launch-time
validation still applies.

Telemetry is disabled unless requested for an operation and is still gated by
MXC's persisted user consent and administrative policy.

## Package and native library

The package includes the native runtime assets for supported platforms.
Applications do not need to launch an MXC executor process. The governed build
pipeline produces the publishable NuGet package; `build.bat` creates local
architecture-specific packages under `output\packages`.

For examples, AOT requirements, and development commands, see the
[SDK project](Microsoft.Mxc.Sdk/README.md) and the repository's backend guides.
