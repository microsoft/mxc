# Node and .NET SDK generation

## Decision

Generate both foreign binding layers from the UniFFI metadata in `mxc_ffi`. Keep thin public facades for stable,
idiomatic APIs; the generated surface remains internal.

## Node

```mermaid
flowchart LR
    A[Node application] --> T[Generated TypeScript]
    T --> R["@ubjs/node"]
    R --> F[libffi]
    F --> L[mxc_ffi library]
```

[`uniffi-bindgen-react-native` Node support][node] generates TypeScript that describes the UniFFI symbols and value
conversions. The generic `@ubjs/node` N-API addon opens `mxc_ffi` and calls it through libffi.

There is no MXC-specific addon, C++, subprocess, daemon, RPC path, or WebAssembly module.

[node]: https://jhugman.github.io/uniffi-bindgen-react-native/reference/nodejs.html

The generated TypeScript is bundled because upstream currently emits extensionless internal imports while MXC targets
ESM. This is packaging, not an operation-specific adapter.

## .NET

```mermaid
flowchart LR
    A[.NET application] --> C[Generated C# objects]
    C --> P[Generated P/Invoke]
    P --> L[mxc_ffi library]
```

[`uniffi-bindgen-cs`](https://github.com/NordSecurity/uniffi-bindgen-cs) generates records, owned objects, async Task
plumbing, disposal, checksums, and P/Invoke from the same library metadata.

The public facade exposes `Run` and `RunAsync`, matching the generated operation names.

## Projected surface

| Family | Generated internal surface |
|---|---|
| Discovery | Version and platform-support functions and records |
| Run to completion | Sync/async operations, result record, and structured error |
| Live process | Sandbox object, take-once streams, poll, wait, and kill |
| State-aware lifecycle | Provision, start, exec, stop, and deprovision operations |

The public Node and .NET facades rename these internal generated types where needed but do not reimplement their
behavior.

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
| Kill sync | `kill()` | `Kill()` | `Sandbox::kill()` |
| Kill async | `killAsync()` | `KillAsync()` | worker calling `Sandbox::kill()` |

State-aware envelope execution, streaming exec, and attached exec follow the same base-name/`Async` convention.

## Namespaces

| Surface | Public namespace | Internal generated code |
|---|---|---|
| Rust | `mxc_sdk` | `mxc_ffi` is not a Rust consumer API |
| Node | `@microsoft/mxc-sdk` | Package-private `internal/generated` modules |
| .NET | `Microsoft.Mxc.Sdk` | `Microsoft.Mxc.Sdk.Interop`, not publicly documented |

UniFFI and generator names such as `BindingSandbox`, `MxcNative`, and `uniffiDestroy` must not appear in the public
SDK. Public types use product terms such as `MxcSandbox`, `SandboxProcess`, `RunResult`, and `MxcError`.

## Node runtime ownership

| Component | Produced by | MXC-specific handwritten code |
|---|---|---:|
| Function/type converters and symbol metadata | UniFFI Node generator | None |
| N-API addon and libffi dispatch | Third-party `@ubjs/node` package | None |
| Native library staging and package wiring | MXC | One shared packaging path |
| Public facade and Node stream adapters | MXC | Thin handwritten layer |

`@ubjs/node` itself is an upstream handwritten generic runtime, not generated per MXC API. MXC writes no N-API C++,
libffi dispatch, ABI symbol registry, or operation-specific native addon code. MXC's Node-specific infrastructure is
package configuration, native-library staging, public stream adapters, and tests.

## True async behavior

```mermaid
sequenceDiagram
    participant A as Node or .NET caller
    participant F as Generated future bridge
    participant W as Rust worker thread
    participant S as mxc-sdk
    A->>F: runAsync(...)
    F->>W: Start blocking operation
    W->>S: mxc_sdk::run
    F-->>A: Promise or Task remains pending
    S-->>W: Result
    W-->>F: Complete Rust future
    F-->>A: Resolve generated value
```

UniFFI's TypeScript `forceAsync` option is not used. It changes a signature but does not make blocking Rust work async.

## Ownership

| Value | Ownership rule |
|---|---|
| Sandbox | Generated object owns an `Arc` to a synchronized Rust `Sandbox` |
| stdin | May be taken once; dropping or disposing closes the writer |
| stdout/stderr | Each may be taken once; reads return owned byte buffers |
| Error | Generated thrown object owns an `Arc<BindingError>` |
| Result records | Copied into language-native values |

Generated finalizers prevent leaks after abandoned objects. Callers should still dispose objects deterministically.

## Cancellation

Generated async calls can cancel future polling, but cancellation cannot safely imply process termination. MXC should
only advertise kill-on-cancel after `mxc-sdk` provides cancellation independent of the lock held by `wait`.

## Behavior covered by tests

Node and .NET tests run against the real library and verify:

1. version and host discovery
2. structured malformed-request errors
3. synchronous and asynchronous run-to-completion
4. state-aware and attached-exec error paths
5. live process ownership
6. take-once stdin, stdout, and stderr
7. stream read, write, and flush
8. prompt busy errors during concurrent handle use

## Before switching Node and .NET to the generated bindings

- Run generated SDK scenarios on Windows, Linux, and macOS where supported.
- Repeatedly create, use, cancel, and dispose async calls, streams, and processes without leaks or deadlocks.
- Make CI identify changes to generated public APIs and native entry points.
- Package one native library per target without changing generated operation code.
- Confirm generated calls return the same results, errors, streams, and process behavior as the Rust SDK.
- Remove the previous interop generation path.
