# Microsoft.Mxc.Sdk

`Microsoft.Mxc.Sdk` provides .NET APIs for authoring and executing MXC
container requests through the in-process native `mxc_ffi` library. The
versioned public API is in `Microsoft.Mxc.Sdk.V1`. All request and policy types
in this API use the owned V1 contract rather than exposing a wire-version
selector.

## One-shot execution

```csharp
using Microsoft.Mxc.Sdk.V1;

var request = new ContainerRequest(
    new ContainerPolicy
    {
        Filesystem = new FilesystemPolicy
        {
            ReadwritePaths = { @"C:\work" },
        },
        TimeoutMs = 30_000,
    },
    "cmd /c echo hello");

Output output = await MxcSandbox.RunAsync(request);
Console.WriteLine($"exit={output.ExitCode} stdout={output.Stdout}");
```

Use `MxcSandbox.Run` / `RunAsync` for captured output or `Spawn` for a live
`MxcProcess` with separate stdin, stdout, and stderr streams. `MxcProcess`
provides wait, termination, and disposal operations. One-shot requests are
built from `ContainerPolicy` and `ContainerRequest`; they do not accept a
caller-selected schema version.

## Existing containers

`MxcLifecycle` provides typed provision, start, exec, stop, and deprovision
operations. The provision result contains an opaque `ContainerId`; pass it to
subsequent operations rather than parsing it.

```csharp
using Microsoft.Mxc.Sdk.V1;

var provisioned = MxcLifecycle.ProvisionSandbox(
    StateAwareContainment.Wslc,
    new WslcProvisionOptions { Image = "alpine:latest" });
ContainerId id = provisioned.ContainerId;

MxcLifecycle.StartSandbox(id);
Output output = await MxcLifecycle.ExecInSandboxAsync(
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

## Public V1 types

| Purpose | .NET type |
| --- | --- |
| Container restrictions | `ContainerPolicy` |
| One-shot workload | `ContainerRequest` |
| Persistent container identity | `ContainerId` |
| Existing-container workload | `ExecRequest` |
| Live process with standard pipes | `MxcProcess` |
| Captured execution | `Output` |
| Terminal process outcome | `WaitOutcome` |

All types above are in `Microsoft.Mxc.Sdk.V1`. PTY operations are not part of
this V1 API. See the
[networking guide](../../docs/sandbox-policy/0.8.0/networking/networking.md)
and [schema reference](../../docs/schema.md) for policy behavior.

## Errors, warnings, and discovery

Native failures are surfaced as `MxcException`; inspect `Code`, `Operation`,
`NativeCode`, and `Remediation` when available. Security and operational
warnings are available on `Output.Warnings` and `MxcProcess.Warnings`.

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
