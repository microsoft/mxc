# MXC Node-API unification prototype

This disposable package demonstrates the Node half of the SDK-unification
design without changing the Rust workspace or the current `@microsoft/mxc-sdk`
surface. It dynamically loads `src/target/debug/mxc_ffi.dll` and calls the
generated Diplomat C ABI; it never links to or invokes `mxc-sdk` directly.

## Generated boundary

`scripts/generate-operations.mjs` consumes the generated Diplomat C headers
under `src/target/diplomat-bindings/c`. It has no separate `operations.json`,
but its internal `description.operations` still hand-maintains Node-specific
public names and argument/result mappings. The generator derives and
exhaustively validates the current
`MxcDiplomat` entry points and opaque-handle members, plus the required
`DiplomatWrite` helpers and error enum; adding, removing, or renaming a bridge
operation or member fails generation. Running `npm run generate` produces all
operation-specific code:

| Generated file | Responsibility |
| --- | --- |
| `src/generated/api.ts` | Public TypeScript sync/async names, request serialization, result validation, and typed error conversion |
| `native/generated/operations.{h,cc}` | Node-API callbacks, C ABI symbol selection, opaque result/error conversion, and async operation descriptors |
| `native/generated/ffi-symbols.inc` and `ffi-library.h` | The C ABI symbol list and library basename consumed by the handwritten dynamic loader |

Handwritten files are restricted to addon discovery (`src/runtime.ts`), public
handle wrappers (`src/handles.ts`), native dynamic-library loading, generic
`napi_async_work` scheduling (`native/runtime.{h,cc}`), and generated opaque
pointer ownership (`native/handles.cc`). The runtime does not contain a list
of value-returning SDK operations or their parameter, result, or error
mappings.

`runSandboxSync` invokes the C ABI on the calling thread. `runSandbox` invokes
that same generated C ABI function through `napi_async_work`, so the blocking
run never occupies the JavaScript thread. Version and discovery APIs remain
synchronous because their native calls are expected to be immediate.

## Commands

Run from `sdk/node/prototype`:

```powershell
npm run check:generated
npm run build
npm test
```

`npm test` builds the addon against
`src/target/diplomat-bindings/c` and runs focused Node/TypeScript smoke tests
against `src/target/debug/mxc_ffi.dll`. The addon dynamically loads its library
from `MXC_FFI_LIBRARY`; set that variable to an absolute path to select a
different MXC build. `MXC_NODE_ADDON` optionally overrides discovery of the
compiled `.node` module.

The default `node-gyp` include path is the generated Diplomat output. To use a
different generated binding directory:

```powershell
node ../node_modules/node-gyp/bin/node-gyp.js rebuild --release -- -Dmxc_ffi_include_dir=C:\path\to\generated\include
```

This is a **temporary header-driven Diplomat backend**, not a true Diplomat
codegen backend: it parses the emitted C headers rather than consuming
Diplomat's HIR directly. Productization requires a shared Rust/HIR manifest
consumed by both Node and .NET, replacing the remaining handwritten
Node-specific operation mapping while preserving the same generated outputs.
The generated bridge targets the complete prototype surface: discovery,
run-to-completion, live spawn, state-aware phases, streaming exec, attached
exec, sandbox control, and stream I/O. It owns every generated opaque handle
through its corresponding generated destructor and collects variable text
through `DiplomatWrite` buffers before returning to JavaScript.

## State-aware and live-process surfaces

The generated static phase also exposes synchronous and Promise APIs for
`provisionSandbox`, `startSandbox`, `stopSandbox`, `deprovisionSandbox`, and
`execAttachedSandbox`. State-aware operations serialize their request before
calling the same synchronous Diplomat export; async variants use the shared
`napi_async_work` scheduler. This uses libuv's shared worker pool, so a
long-running sandbox can delay unrelated Node native work; it is
prototype-only, and production requires dedicated execution scheduling.
Provision/start/stop/deprovision return the
generated response envelope JSON, while ExecAttached returns the generated
`{ timedOut, exitCode }` value.

`spawnSandboxSync` / `spawnSandbox` and `execSandboxSync` / `execSandbox`
return a live `Sandbox`. Its stdin, stdout, and stderr are take-once
`SandboxInput` and `SandboxOutput` handles. Each JavaScript handle owns a
shared native control block with an explicit `dispose()` and a finalizer.
Async work retains that control block until completion, so disposal cannot
free a pointer while native work is active; the generated destructor runs
once after the final owner releases it.

Stream operations are serialized per stream. Concurrent sandbox state
transitions use the Rust bridge's nonblocking ownership check: if `wait`
currently owns the handle, `kill` and `tryWait` fail promptly with a typed
`backend_error` instead of deadlocking. Supporting kill-during-wait requires
an interruptible `mxc-sdk` wait primitive or a dedicated sandbox-owning actor;
the prototype deliberately does not imply that capability.
