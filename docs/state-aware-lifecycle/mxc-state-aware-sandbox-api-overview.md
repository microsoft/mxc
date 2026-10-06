# MXC State-Aware Sandbox API - Overview

Companion to [mxc-state-aware-sandbox-api.md](./mxc-state-aware-sandbox-api.md).

MXC separates container creation from persistent lifecycle operations.
Creation runs a `ContainerRequest`; persistent execution provisions a
container, starts it, runs `ExecutionRequest` workloads, then stops and
deprovisions it. The public SDK surface is versioned independently of the
native wire contract.

## Public SDK surface

All public types, operations, probes, backend/platform discovery, telemetry,
and helpers live under `mxc_sdk::v1`, `Microsoft.Mxc.Sdk.V1`, or
`@microsoft/mxc-sdk/v1`. The Node package root exports no APIs.

| Capability | Rust | .NET | Node |
|---|---|---|---|
| Creation input | `ContainerRequest` | `ContainerRequest` | `ContainerRequest` |
| Captured creation | `run` | `MxcContainer.Run` / `RunAsync` | `run` |
| Live standard pipes | `spawn` | `MxcContainer.Spawn` / `SpawnAsync` | `spawn` |
| Provision | `container::provision_container` | `MxcLifecycle.ProvisionContainer` | `provisionContainer` |
| Start | `container::start_container` | `MxcLifecycle.StartContainer` | `startContainer` |
| Existing-container capture | `container::run_in_container` | `RunInContainer` / `RunInContainerAsync` | `runInContainer` |
| Existing-container streaming | `container::spawn_in_container` | `SpawnInContainer` / `SpawnInContainerAsync` | `spawnInContainer` |
| Stop | `container::stop_container` | `MxcLifecycle.StopContainer` | `stopContainer` |
| Deprovision | `container::deprovision_container` | `MxcLifecycle.DeprovisionContainer` | `deprovisionContainer` |

- Creation takes a request followed by its operation-specific options.
- Provision takes `ProvisionRequest` followed by `ProvisionOptions`.
- Start, stop, and deprovision take `ContainerId` followed by their own options.
- Existing-container execution takes `ContainerId`, `ExecutionRequest`, and
  its execution-specific options. Initial PTY size is a field of those options.
- .NET asynchronous cancellation tokens are last. Rust remains synchronous.

Common process settings are command, working directory, environment,
inherit-default-environment, and timeout. SDKs use properties or setters
according to their language conventions. Containment choices are closed:
Rust enum variants, SDK-owned .NET subclasses, and Node discriminated unions.
Creation defaults to generic `Process` intent.

Explicit PTY APIs return SDK-owned terminal process handles with interactive
input, resize, wait, termination, and disposal. Use these for interactive
workloads instead of attaching a workload to the host application's console.
See the launch-choice tables for [Rust](../reference/rust/v1/api.md#choosing-a-launch-operation),
[.NET](../reference/dotnet/v1/api.md#choosing-a-launch-operation), and
[Node](../reference/node/v1/api.md#choosing-a-launch-operation).

Explicit validation APIs perform native dry-run validation and return no
execution result. Backend policy and feature support remain native-engine
responsibilities. Invocation telemetry cannot grant persisted consent or
override restrictive administrative policy.

## Lifecycle

| Phase | Valid from state | Resulting state | Output |
|---|---|---|---|
| `provision` | Not provisioned | Provisioned | Opaque identity and optional metadata |
| `start` | Provisioned | Running | Optional metadata |
| `exec` | Running | Running | Live streams or captured execution output |
| `stop` | Running | Provisioned | Optional metadata |
| `deprovision` | Provisioned | Not provisioned | Optional metadata |

Provision returns an opaque `ContainerId`. Keep that value and pass it unchanged
to start, execution, stop, and deprovision. Do not parse or construct it from
the optional, caller-selected label on a creation request.

Backend-specific policy, idempotence, concurrency, cleanup, and error mapping
are documented in the backend guides. SDKs surface structured errors and
warnings rather than converting failures into successful-looking output.

## Contributor and native integration details

The [full design](./mxc-state-aware-sandbox-api.md) documents engine dispatch,
backend interfaces, and native JSON contracts for contributors and direct
executor/FFI integrations. These implementation details are not required to
author typed SDK requests.

## References

- [Full lifecycle and wire contract](./mxc-state-aware-sandbox-api.md)
- [Rust SDK](../../src/core/mxc-sdk/README.md)
- [.NET SDK](../../sdk/dotnet/README.md)
- [Node SDK](../../sdk/node/README.md)
- [IsolationSession TypeScript guide](../isolation-session/state-aware-typescript.md)
- [WSLC lifecycle guide](../wsl/wslc-state-aware.md)
