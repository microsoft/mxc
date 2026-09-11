# JSON-first one-shot sandbox APIs

> **Status:** Proposal

This proposal updates only the dataflow for one-shot sandbox run and spawn.

## Decision

- Make the versioned MXC config JSON the configuration currency.
- Add one-shot run and spawn JSON entry points to `mxc-sdk` and `mxc_ffi`.
- Make C# and Node thin wrappers over the C ABI, with Koffi providing Node's
  asynchronous foreign-function integration.
- Keep the parser, engine, backends, and existing APIs.

## Problem

Today MXC maintains multiple representations of the same request.

```mermaid
flowchart TB
    subgraph CS["C# SDK"]
        C[C# SandboxPolicy] -->|serialize| B[RequestSpec JSON string]
    end
    subgraph ABI["C ABI"]
        B -->|deserialize| F[mxc_ffi::RequestSpec]
    end
    subgraph RP["Rust API — mxc_engine types re-exported by mxc-sdk"]
        R[Rust caller] -->|constructs| P[SandboxPolicy + Containment]
        F -->|map RequestSpec| P
        P -->|build| V[serde_json::Value]
    end
    subgraph NS["Node SDK"]
        N[TypeScript SandboxPolicy] -->|map| T[ContainerConfig]
        T -->|JSON.stringify| J[Schema JSON string]
    end
    subgraph CLI["Executor process"]
        J --> X[Decoded JSON string]
    end
    subgraph CP["wxc_common config parser"]
        V --> Q[Parser]
        X --> Q
        Q -->|deserialize| W[wire::MxcConfig]
        W -->|parse semantics + normalize| E[ExecutionRequest]
    end
    subgraph EN["mxc_engine"]
        E --> M[Backend dispatch]
    end
```

- C# converts `SandboxPolicy` through the binding-only `RequestSpec`.
- Rust builds JSON values only to parse them back in the same process.
- Node converts `SandboxPolicy` to `ContainerConfig` and starts an executor.
- These parallel models and mappings can drift as the schema changes.

## Proposed flow

```mermaid
flowchart TB
    subgraph API["Public APIs — new"]
        RR[Rust: JSON &str + typed options]
        CC[C#: JSON string + typed options]
        NN[Node: JSON string + typed options]
    end
    subgraph AD["Native adapters — new entry paths"]
        KF[Node Koffi adapter]
        FF[mxc_ffi: pass UTF-8; do not parse]
    end
    subgraph SDK["mxc-sdk — new JSON entry points"]
        JJ[Forward JSON unchanged]
    end
    subgraph CP["wxc_common config parser"]
        Q[Parser]
        WM[wire::MxcConfig]
        ER[ExecutionRequest]
    end
    subgraph ENG["mxc_engine"]
        DD[Backend dispatch]
    end

    CC -->|UTF-8 unchanged| FF --> JJ
    NN -->|UTF-8 unchanged| KF --> FF
    RR -->|borrow unchanged| JJ
    JJ -->|versioned MXC config JSON| Q
    Q -->|deserialize| WM
    WM -->|parse semantics + normalize| ER
    ER --> DD
    DD --> OO[Strongly typed output or handle]
    classDef new fill:#0f5132,color:#fff
    classDef same fill:#343a40,color:#fff
    class RR,CC,NN,KF,FF,JJ new
    class Q,WM,ER,DD,OO same
```
The existing parser remains: version-specific `mxc_config_contract` types and
adapters produce `wire::MxcConfig`, then semantic parsing produces
`ExecutionRequest`. This proposal does not change that pipeline.

## Proposed API

The JSON contains the complete versioned one-shot request. `RunOptions` holds
`experimental` and `dryRun`; `SpawnOptions` holds only `experimental`.
Options are reserved for host-controlled execution flags and must not duplicate
versioned config fields. C option structs include `size` for future extension.

**Rust (`mxc-sdk`)**

```rust
pub fn run_config(json: &str, options: RunOptions) -> Result<Output, Error>;
pub fn spawn_config(json: &str, options: SpawnOptions) -> Result<Sandbox, Error>;
```

**C ABI (`mxc_ffi`)**

```c
int32_t mxc_run_config(const char* json, const MxcRunOptions*, MxcRunResult*);
int32_t mxc_spawn_config(const char* json, const MxcSpawnOptions*, MxcSandbox**, MxcErrorDetail*);
```

**C# (`Microsoft.Mxc.Sdk`)**

```csharp
RunResult RunConfig(string json, RunOptions? options = null);
Task<RunResult> RunConfigAsync(string json, RunOptions? options = null);
MxcSandboxProcess SpawnConfig(string json, SpawnOptions? options = null);
```

**TypeScript (`@microsoft/mxc-sdk`)**

```typescript
runConfigAsync(json: string, options?: RunOptions): Promise<RunResult>;
spawnConfig(json: string, options?: SpawnOptions): SandboxProcess;
```

### Node Koffi adapter

Node uses Koffi as a thin adapter over the shared `mxc_ffi` C ABI rather than
maintaining a separate native binding. Koffi declares the C functions, structs,
and opaque handles and runs blocking calls off the JavaScript event-loop
thread. TypeScript only adapts results and handles to promises and Node streams
while enforcing the C ABI's ownership and concurrency rules.

Before migration, validate run, streaming, cancellation, cleanup, and worker
capacity on Windows, Linux, and macOS. The built-in `node:ffi` module was
introduced in Node.js 26 and remains experimental; it may replace Koffi later
without changing the JSON-first API or C ABI.

## Scope

| Scope | Decision |
| --- | --- |
| Add | One-shot run and spawn JSON APIs, C# wrappers, and a thin Node Koffi adapter over the C ABI. |
| Keep | Published schemas, version adapters, `wire::MxcConfig`, the parser, `ExecutionRequest`, engine validation, backends, and existing typed APIs. |
| Avoid on the new path | `RequestSpec`, binding-only JSON, policy-builder round trips, and the Node executor process. |
| Follow-up (separate proposals) | Redesign state-aware lifecycle APIs; define API-shape guidelines for discovery, policy helpers, telemetry, and future SDK APIs. |

## Migration

1. Add JSON-first run and spawn entry points to `mxc-sdk` and `mxc_ffi`.
2. Validate Koffi run, streaming, cancellation, cleanup, and worker capacity on
   Windows, Linux, and macOS.
3. Bind C# directly and Node through a thin Koffi adapter to the `mxc_ffi` C
   ABI.
4. Keep existing paths through parity. Deprecation comes later.

## Success criteria

- The same config behaves the same through CLI, Rust, C#, and Node.
- New paths require no binding-specific config model or extra JSON round trip.
- Validation errors retain the same category and path in every language.
- Existing callers continue to work during migration.
