# Rust SDK architecture

## Decision

Keep [`mxc-sdk`](../../../src/core/mxc-sdk/src/lib.rs) as the only safe callable layer above
[`mxc_engine`](../../../src/core/mxc_engine/src/lib.rs).

```mermaid
flowchart LR
    R[Rust application] --> S[mxc-sdk]
    U[mxc_ffi UniFFI exports] --> S
    S --> E[mxc_engine]
```

Rust callers never route through an FFI layer. Foreign bindings immediately delegate to `mxc-sdk`. Adoption replaces
the unshipped legacy C projection; it does not preserve two API surfaces.

## Responsibilities

| `mxc-sdk` owns | `mxc_engine` owns |
|---|---|
| Public run, spawn, and state-aware functions | Backend selection |
| Safe request, result, and error types | Backend construction |
| `Sandbox`, live streams, wait, poll, and kill | Platform execution |
| Stable SDK errors | Backend-specific errors and probes |
| Request JSON conversion used by foreign bindings | Containment implementation |

## Operation families

```mermaid
flowchart TD
    S[mxc-sdk]
    S --> D[Discovery]
    S --> R[Run to completion]
    S --> P[Live process]
    S --> A[State-aware lifecycle]
    D --> D1[available_backends]
    D --> D2[platform_support]
    R --> R1[run]
    P --> P1[spawn_sandbox]
    P1 --> P2[take stdin, stdout, stderr]
    P1 --> P3[try_wait, wait, kill]
    A --> A1[run_state_aware_json]
    A --> A2[exec_sandbox]
    A --> A3[exec_attached]
```

## Request parsing

The co-versioned binding request parser lives in `mxc-sdk`, not in either FFI crate:

```mermaid
sequenceDiagram
    participant F as FFI projection
    participant S as mxc-sdk
    participant E as mxc_engine
    F->>S: build_request_from_json
    S->>S: Deserialize binding request
    S->>E: build_request
    E-->>S: SandboxRequest or Error
    S-->>F: Stable SDK value
```

This keeps request construction in the Rust SDK rather than the projection. It does not redesign the public schema.

## Projection rule

The UniFFI module in `mxc_ffi` may:

- map safe SDK values to UniFFI records and objects
- retain `Sandbox` and stream ownership behind synchronized objects
- move blocking SDK calls to dedicated worker threads for exported async functions
- convert `mxc_sdk::Error` to a structured projected error
- contain panics before they cross the generated ABI

It may not validate policy, select a backend, reinterpret results, or maintain another operation implementation.

## Synchronous and asynchronous behavior

`mxc-sdk` remains synchronous where the engine is synchronous. `mxc_ffi` exports an internal UniFFI pair:

```text
run(request) -> RunResult
async run_async(request) -> RunResult
```

The async function starts work on a dedicated Rust thread and resolves a Rust future. It does not merely relabel a
blocking call as async, and it does not depend on the embedding runtime's thread pool.

## Live object behavior

- A `Sandbox` owns one native process handle.
- stdin, stdout, and stderr are take-once owned objects.
- operations use `try_lock`, so concurrent access returns a typed busy error instead of blocking a runtime thread.
- `kill` cannot interrupt a concurrent `wait` until `mxc-sdk` exposes independent cancellation.
- generated object finalizers are a safety net; deterministic disposal remains recommended.

## Exit criteria

- Every projected operation immediately delegates to `mxc-sdk`.
- Rust behavior tests define the expected result.
- Adoption removes the legacy C exports and csbindgen projection.
- Rust callers retain direct typed APIs.
- No backend dependency is introduced into `mxc_ffi`.
