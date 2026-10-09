# NVX .NET examples

> [!NOTE]
> These examples describe the proposed completed NVX-backed MicroVM SDK
> surface. The MicroVM types are not available in the current NuGet package.

For architecture, packaging, policy limits, and implementation details, see
[NVX integration in MXC](./nvx-integration.md).

For npm examples, see
[NVX npm examples](./nvx-npm-examples.md).

## Install the packages

Reference matching SDK and runtime package versions:

```xml
<PackageReference Include="Microsoft.Mxc.Sdk" Version="..." />
<PackageReference Include="Microsoft.Mxc.Sdk.Nvx.Runtime" Version="..." />
```

## Check MicroVM availability

```csharp
using Microsoft.Mxc.Sdk.V1;

PlatformSupport support = MxcPlatform.GetPlatformSupport();
if (!support.AvailableMethods.Contains(ContainmentBackend.Microvm))
{
    string reason = support.UnavailableReasons.TryGetValue(
        ContainmentBackend.Microvm,
        out string? unavailable)
        ? unavailable
        : "MicroVM is unavailable";

    throw new InvalidOperationException(reason);
}
```

## Run and capture output

```csharp
using Microsoft.Mxc.Sdk.V1;

var request = new ContainerRequest(
    "python -c \"print('hello from NVX')\"")
{
    TimeoutMs = 30_000,
    Containment = new Containment.Microvm
    {
        Image = "python:3.12-alpine",
        MemoryMb = 256,
    },
};

ExecutionResult result = await MxcContainer.RunAsync(request);
Console.Write(result.Stdout);
Console.Error.Write(result.Stderr);
Console.WriteLine($"exit={result.ExitCode} timedOut={result.TimedOut}");
```

Cancelling the `RunAsync` await does not necessarily stop native execution.
Use a request timeout or a live process handle when the application must stop
the workload.

## Spawn with live output

```csharp
using Microsoft.Mxc.Sdk.V1;

var request = new ContainerRequest(
    "python -u -c \"import sys,time; print('out'); "
    + "print('err', file=sys.stderr); time.sleep(1)\"")
{
    TimeoutMs = 30_000,
    Containment = new Containment.Microvm
    {
        Image = "python:3.12-alpine",
        MemoryMb = 256,
    },
};

using var process = await MxcContainer.SpawnAsync(request);
Task stdout = process.StandardOutput is { } output
    ? output.CopyToAsync(Console.OpenStandardOutput())
    : Task.CompletedTask;
Task stderr = process.StandardError is { } error
    ? error.CopyToAsync(Console.OpenStandardError())
    : Task.CompletedTask;

try
{
    WaitResult result = await process.WaitAsync();
    await Task.WhenAll(stdout, stderr);
    Console.WriteLine($"exit={result.ExitCode} timedOut={result.TimedOut}");
}
catch
{
    process.Kill();
    throw;
}
```

Consume stdout and stderr concurrently. Call `Kill()` when the application
must stop the workload.

## Reuse an NVX instance

The state-aware lifecycle is:

```text
provision → start → repeated execution → stop → deprovision
```

```csharp
using Microsoft.Mxc.Sdk.V1;

var provisioned = MxcLifecycle.ProvisionContainer(
    new MicrovmProvisionRequest
    {
        Image = "python:3.12-alpine",
        MemoryMb = 256,
    });
ContainerId id = provisioned.ContainerId;

Exception? primaryError = null;
var cleanupErrors = new List<Exception>();
bool startAttempted = false;

try
{
    startAttempted = true;
    MxcLifecycle.StartContainer(id);

    foreach (string value in new[] { "first", "second" })
    {
        ExecutionResult result = await MxcLifecycle.RunInContainerAsync(
            id,
            new ExecutionRequest($"echo {value}"));
        Console.WriteLine(result.Stdout);
    }
}
catch (Exception error)
{
    primaryError = error;
}
finally
{
    if (startAttempted)
    {
        try
        {
            MxcLifecycle.StopContainer(id);
        }
        catch (Exception error)
        {
            cleanupErrors.Add(error);
        }
    }

    try
    {
        MxcLifecycle.DeprovisionContainer(id);
    }
    catch (Exception error)
    {
        cleanupErrors.Add(error);
    }
}

if (primaryError is not null || cleanupErrors.Count != 0)
{
    var errors = new List<Exception>(cleanupErrors);
    if (primaryError is not null)
    {
        errors.Insert(0, primaryError);
    }
    throw new AggregateException($"NVX lifecycle failed for {id}", errors);
}
```

Keep `ContainerId` unchanged. If cleanup fails, keep the ID in application
logs so an operator can retry cleanup.

## Filesystem and network policy

```json
{
  "filesystem": {
    "readonlyPaths": ["C:\\nvx-work\\input"],
    "readwritePaths": ["C:\\nvx-work\\output"],
    "deniedPaths": ["C:\\nvx-work\\input\\private"]
  },
  "network": {
    "egress": {
      "default": "deny",
      "allow": [{
        "to": [{ "cidr": "203.0.113.0/24" }],
        "ports": [{ "protocol": "tcp", "port": 443 }]
      }]
    },
    "ingress": {
      "default": "deny",
      "hostLoopback": "deny"
    }
  }
}
```

Set `Filesystem` and `Network` on the one-shot request or the provision
request. Host paths must exist before launch.

Inside the Linux workload:

```text
C:\nvx-work\input  → /mnt/c/nvx-work/input
C:\nvx-work\output → /mnt/c/nvx-work/output
```

Use Linux guest paths in commands and `WorkingDirectory`. Read-write mappings
modify host files immediately.

## PTY and live stdin

PTY support is not available initially. `MxcContainer.SpawnWithPty` and
`MxcLifecycle.SpawnInContainerWithPty` reject MicroVM requests.

Use `MxcContainer.Spawn` or `MxcLifecycle.SpawnInContainer` for
non-interactive workloads. These operations provide stdout and stderr pipes.
They do not provide a terminal. Live stdin is not available initially, and
the workload receives EOF.

## Errors

| Result | Meaning |
| --- | --- |
| `BackendUnavailable` | The NVX runtime, WHP, runtime files, architecture, or runtime version is unavailable |
| Policy validation error | The request uses a policy form or value that NVX cannot enforce |
| Nonzero workload exit | The workload ran and returned a nonzero status |

