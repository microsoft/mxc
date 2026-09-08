# Node and .NET SDK generation

## Proposal

Generate both foreign binding layers from the UniFFI metadata in `mxc_ffi`. Keep thin public facades for stable,
idiomatic APIs; the generated surface remains internal.

## Generated and handwritten surfaces

| Surface | Generated | Handwritten |
|---|---:|---|
| Rust public SDK | No | `mxc-sdk` behavior and safe API |
| Rust projection | No | Thin UniFFI exports and safe value conversion in `mxc_ffi` |
| Node internal binding | Yes | None per generated callable operation |
| .NET internal binding | Yes | None per generated callable operation |
| Node public SDK | No | Names, re-exports, and stream adapters |
| .NET public SDK | No | Names, re-exports, and .NET-specific adapters |
| Node/.NET policy models | No change | Existing typed models and JSON serialization |

Adding a public callable operation therefore changes Rust behavior, one Rust UniFFI export, and normally one
forwarding method in each public foreign facade. UniFFI generates the foreign calls, records, object plumbing, and
async bridge.

## Node

```mermaid
flowchart LR
    A[Node application] --> P[Node public facade]
    P --> T[Generated internal TypeScript]
    T --> R["@ubjs/node"]
    R --> F[libffi]
    F --> L[mxc_ffi library]
```

[`uniffi-bindgen-react-native` Node support][node] generates TypeScript that describes the UniFFI symbols and value
conversions. The generic `@ubjs/node` N-API addon opens `mxc_ffi` and calls it through libffi.

[node]: https://jhugman.github.io/uniffi-bindgen-react-native/reference/nodejs.html

The generated TypeScript is bundled because upstream currently emits extensionless internal imports while MXC targets
ESM. This is packaging, not a callable operation adapter.

## .NET

```mermaid
flowchart LR
    A[.NET application] --> F[.NET public facade]
    F --> C[Generated internal C# objects]
    C --> P[Generated P/Invoke]
    P --> L[mxc_ffi library]
```

[`uniffi-bindgen-cs`](https://github.com/NordSecurity/uniffi-bindgen-cs) generates records, owned objects, async Task
plumbing, disposal, checksums, and P/Invoke from the same library metadata.

The public facade exposes `Run` and `RunAsync`, matching the generated callable operation names.

## Projected surface

| Family | Generated internal surface |
|---|---|
| Discovery | Version and platform-support functions and records |
| Run to completion | Sync/async callable operations, result record, and structured error |
| Live process | Sandbox object, take-once streams, poll, wait, and process termination |
| State-aware lifecycle | Provision, start, exec, stop, and deprovision callable operations |

The public Node and .NET facades rename these internal generated types where needed but do not reimplement their
behavior.

## Public type policy

The public facades do not wrap every generated type. Use the smallest boundary that keeps generator details out of the
public API:

| Type category | Public treatment | Binding treatment |
|---|---|---|
| Stable results and errors | Public product-named type | Generated record/error mapped by the facade |
| Plain Node records with an identical shape | Public interface or type alias | Reused structurally; no runtime copy |
| .NET records returned by generated code | Public record or class | Mapped to keep generated namespaces internal |
| Sandboxes, streams, and other owned objects | Public wrapper | Delegates to generated object and controls disposal |
| Policy, request, and config inputs | Typed models plus a raw config/JSON overload | Serialized to JSON before the UniFFI call |

The JSON boundary is for evolving request/config data, not for every API value. Results, errors, discovery records,
wait results, and owned process/stream handles remain typed across the binding. Raw config allows a caller to use a new
schema field before a convenience model adds it; typed policy APIs remain the normal entry point.

## API alignment

| Concept | Node public | .NET public | Rust API |
|---|---|---|---|
| Version | `version()` | `Version()` | package version |
| Discovery | `discover()` | `Discover()` | discovery functions |
| Run sync | `run()` | `Run()` | `run()` |
| Run async | `runAsync()` | `RunAsync()` | worker calling `run()` |
| Spawn sync | `spawn()` | `Spawn()` | `spawn_sandbox()` |
| Spawn async | `spawnAsync()` | `SpawnAsync()` | worker calling `spawn_sandbox()` |
| Poll | `tryWait()` | `TryWait()` | `Sandbox::try_wait()` |
| Wait sync | `wait()` | `Wait()` | `Sandbox::wait()` |
| Wait async | `waitAsync()` | `WaitAsync()` | worker calling `Sandbox::wait()` |
| Terminate sync | `terminate()` | `Terminate()` | `Sandbox::terminate()` |
| Terminate async | `terminateAsync()` | `TerminateAsync()` | worker calling `Sandbox::terminate()` |

State-aware envelope execution, streaming exec, and attached exec follow the same base-name/`Async` convention.

## Namespaces

| Surface | Public namespace | Internal generated code |
|---|---|---|
| Rust | `mxc_sdk` | `mxc_ffi` is not a Rust consumer API |
| Node | `@microsoft/mxc-sdk` | Package-private `internal/generated` modules |
| .NET | `Microsoft.Mxc.Sdk` | `Microsoft.Mxc.Sdk.Interop`, not publicly documented |

UniFFI and generator names such as `BindingSandbox`, `MxcNative`, and `uniffiDestroy` must not appear in the public
SDK. Public types use product terms such as `MxcSandbox`, `SandboxProcess`, `RunResult`, and `MxcError`.

## API compatibility

The generated projection is internal and ships with the matching `mxc_ffi` library. Mixing generated bindings and a
native library from different package versions is unsupported; UniFFI contract checks must reject a mismatch.

A generated-code change is not a public breaking change when the public facade preserves its existing names, types,
and behavior. Regeneration and any required facade adaptation happen in the same change. If the public facade must
break, prefer a compatibility overload or deprecation period. An unavoidable break requires:

1. the next synchronized SemVer breaking release in Rust, Node, and .NET (minor while 0.x, major after 1.0)
2. matching entries in each affected SDK changelog
3. migration instructions and updated public API snapshots
4. one coordinated release so all SDKs describe the same Rust behavior

CI snapshots the public facades separately from the internal generated/native contract. Generated diffs remain
reviewable, but internal generator names are not treated as supported public API.

## Node runtime ownership

| Component | Produced by | MXC-specific handwritten code |
|---|---|---:|
| Function/type converters and symbol metadata | UniFFI Node generator | None |
| N-API addon and libffi dispatch | Third-party `@ubjs/node` package | None |
| Native library staging and package wiring | MXC | Generation script and Node package manifest |
| Public facade and Node stream adapters | MXC | TypeScript facade and stream adapters |

## True async behavior

```mermaid
sequenceDiagram
    participant A as Node or .NET caller
    participant F as Generated future bridge
    participant W as Rust worker thread
    participant S as mxc-sdk
    A->>F: runAsync(...)
    F->>W: Start blocking callable operation
    W->>S: mxc_sdk::run
    F-->>A: Promise or Task remains pending
    S-->>W: Result
    W-->>F: Complete Rust future
    F-->>A: Resolve generated value
```

## Ownership

| Value | Ownership rule |
|---|---|
| Sandbox | Generated object owns an `Arc` to a synchronized Rust `Sandbox` |
| stdin | May be taken once; dropping or disposing closes the writer |
| stdout/stderr | Each may be taken once; reads return owned byte buffers |
| Error | Generated thrown object owns an `Arc<BindingError>` |
| Result records | Copied into language-native values |

Generated finalizers prevent leaks after abandoned objects. Callers should still dispose objects deterministically.

## Behavior covered by tests

Node and .NET tests run against the real library and verify:

1. version and host discovery
2. structured malformed-request errors
3. synchronous and asynchronous run-to-completion
4. state-aware and attached-exec error paths
5. live process ownership
6. take-once stdin, stdout, and stderr
7. stream read, write, and flush
8. `terminate` stops the process while `waitAsync` is pending, plus defined behavior for conflicting stream calls

## Before switching Node and .NET to the generated bindings

- Run generated SDK scenarios on Windows, Linux, and macOS where supported.
- Repeatedly create, use, cancel, and dispose async calls, streams, and processes without leaks or deadlocks.
- Make CI identify changes to public facades and the generated/native contract.
- Package one native library per target without changing generated callable operation code.
- Confirm generated calls return the same results, errors, streams, and process behavior as the Rust SDK.
- Remove the previous interop generation path.
