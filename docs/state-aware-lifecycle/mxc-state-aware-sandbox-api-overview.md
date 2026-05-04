# MXC State-Aware Sandbox API — Overview

*Companion to [mxc-state-aware-sandbox-api.md](./mxc-state-aware-sandbox-api.md).*
*Compiled 2026-04-28.*

A state-aware sandbox API for MXC, surfaced alongside the existing one-shot
`spawnSandbox*` family. Five lifecycle phases; opaque caller-owned `SandboxId`; typed
per-phase backend config; cross-cutting `SandboxPolicy` shared with one-shot. Backends
opt in by implementing a new `StatefulSandboxBackend` Rust trait. MXC retains no state
between calls.

`spawnSandbox` is the composition of the five phases run end-to-end. State-aware exposes
each phase individually.

## Existing MXC types referenced

The proposal reuses several existing MXC types unchanged. They appear in interfaces and
function signatures throughout. One-line summaries; full definitions live in
`sdk/src/types.ts`, `sdk/src/policy.ts`, and `docs/config-schema.md`.

| Type | Where | Role |
|---|---|---|
| `SandboxPolicy` | `sdk/src/types.ts` | Cross-platform restriction policy: filesystem, network, UI, timeout. Reused as the cross-cutting policy on state-aware. |
| `SandboxingMethod` | `sdk/src/types.ts` | String union of MXC backend names (`'appcontainer' \| 'windows_sandbox' \| 'lxc' \| 'wslc' \| 'vm' \| 'microvm' \| 'isolation_session'`). |
| `ProcessConfig` | `sdk/src/types.ts` | Per-process settings: `commandLine`, `cwd`, `env`, `timeout`. Reused for state-aware exec. |
| `FilesystemConfig`, `NetworkConfig`, `UiConfig` | `sdk/src/types.ts` | Wire-format restriction blocks. The `SandboxPolicy` → wire mapping is the existing `createConfigFromPolicy` logic. |
| `pty.IPty` | `node-pty` package | Interactive PTY handle. Used as the streaming-exec return type, matching existing `spawnSandbox`. |
| `getAvailableToolsPolicy`, `getUserProfilePolicy`, `getTemporaryFilesPolicy` | `sdk/src/policy.ts` | Filesystem-policy discovery helpers. Compose unchanged with state-aware via `SandboxPolicy`. |
| `ContainmentBackend` (Rust) | `wxc_common::models` | Rust dispatch enum (one variant per backend). State-aware adds `IsolationSession` and future variants. |
| ProcessContainer | MXC's existing AppContainer-based one-shot backend | Relevant context: ProcessContainer streams stdout/stderr live via PTY; state-aware exec preserves that streaming model. |

**Disambiguation: `sandboxId` vs `containerId`.** The state-aware wire envelope's
`sandboxId` (system-generated, opaque, returned by `provisionSandbox`) is distinct from
the existing one-shot wire envelope's `containerId` (caller-supplied human-readable
label, used as e.g. an AppContainer profile name). Different fields, different purposes;
state-aware non-provision calls carry `sandboxId` on the request, provision returns it
on the response, and neither shape carries `containerId`.

## What's new / What's unchanged

| MXC layer | What's new | What's unchanged |
|---|---|---|
| TypeScript SDK (reference §6) | Five new functions: `provisionSandbox`, `startSandbox`, `execInSandbox` / `execInSandboxAsync`, `stopSandbox`, `deprovisionSandbox`. Branded `SandboxId<C>` type tagging ids by backend (`containment` named once at provision, inferred from the id thereafter). Per-phase typed `*Config` types per backend. Per-phase typed `*Result` types per backend. `AbortSignal` cancellation. Typed exception classes. | `spawnSandbox` family preserved. `SandboxPolicy` reused as cross-cutting policy. `SandboxingMethod` extension reused. `*Config` naming convention reused. |
| JSON wire format (reference §7) | Top-level `phase` discriminator. Top-level `sandboxId`. `containment` carried on provision only; non-provision phases route via the `sandboxId` prefix. Per-phase nesting under `experimental.<backend>.<phase>`. Named envelope types as a TypeScript discriminated union. | One-shot configs (no `phase`) work unchanged. Cross-cutting `filesystem` / `network` / `ui` at top level for state-aware too — backends declare per-phase honor. |
| Rust executor (reference §9) | Dispatch arm for state-aware. New `StatefulSandboxBackend` trait. Rust mirror of the wire envelope (private `Raw*` parser pattern). | `ScriptRunner` trait. Existing one-shot dispatch path. Existing backends unchanged. |
| Error model (reference §8) | Closed enum of 12 codes. `MxcError` base + per-code subclasses. `details` open object. | Existing one-shot error paths preserved. |
| Plug-in surface (reference §11) | Implement `StatefulSandboxBackend`. Define typed per-phase `*Config` interfaces. Register a backend-specific id prefix. Document the cross-cutting honor matrix. | Ephemeral-only backends require no changes. |

## Lifecycle

| Phase | Valid from state | Resulting state | Output |
|---|---|---|---|
| `provision` | (not provisioned) | provisioned | `sandboxId`, optional metadata |
| `start` | provisioned | running | optional metadata |
| `exec` | running | running | stdout, stderr, exit code |
| `stop` | running | provisioned | optional metadata |
| `deprovision` | provisioned | (not provisioned) | optional metadata |

Phases without native equivalents fall through to the trait's default no-op bodies; only
`exec` is required. Reference §4 has the per-phase rule.

## TypeScript SDK

Types used in the function signatures below. Per-phase `<Phase>SandboxOptions<C>` and
`<Phase>Result<C>` are typed-generic over the chosen backend; full definitions are in
[reference §6.1](./mxc-state-aware-sandbox-api.md#6-typescript-sdk).

```typescript
type Phase = 'provision' | 'start' | 'exec' | 'stop' | 'deprovision';
type SandboxId<C extends StateAwareSandboxingMethod> =
  string & { readonly __mxcBrand: 'SandboxId'; readonly __mxcBackend: C };
type StateAwareSandboxingMethod = Extract<SandboxingMethod, 'isolation_session'>;
// extended as state-aware-capable backends are added

interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}
```

```typescript
function provisionSandbox<C extends StateAwareSandboxingMethod>(
  containment: C,
  options?: ProvisionSandboxOptions<C>,
): Promise<ProvisionResult<C>>;

function startSandbox<C extends StateAwareSandboxingMethod>(
  sandboxId: SandboxId<C>,
  options?: StartSandboxOptions<C>,
): Promise<StartResult<C>>;

function execInSandbox<C extends StateAwareSandboxingMethod>(
  sandboxId: SandboxId<C>,
  process: ProcessConfig,
  options?: ExecInSandboxOptions<C>,
): pty.IPty;

function execInSandboxAsync<C extends StateAwareSandboxingMethod>(
  sandboxId: SandboxId<C>,
  process: ProcessConfig,
  options?: ExecInSandboxOptions<C>,
): Promise<ExecResult>;

function stopSandbox<C extends StateAwareSandboxingMethod>(
  sandboxId: SandboxId<C>,
  options?: StopSandboxOptions<C>,
): Promise<StopResult<C>>;

function deprovisionSandbox<C extends StateAwareSandboxingMethod>(
  sandboxId: SandboxId<C>,
  options?: DeprovisionSandboxOptions<C>,
): Promise<DeprovisionResult<C>>;
```

Each phase's options carry `policy?: SandboxPolicy` (cross-cutting restrictions, shared
with one-shot), `config?: <Phase>ConfigFor<C>` (per-phase backend config, typed), and
`signal?: AbortSignal` (cancellation). `containment` is named once at `provisionSandbox`
and inferred from the branded `SandboxId<C>` on every subsequent call. Each non-exec
phase returns a typed `<Phase>Result<C>`: provision carries `sandboxId` plus optional
metadata; start, stop, and deprovision carry optional metadata only. `execInSandbox`
returns an `IPty` for live streaming; `execInSandboxAsync` is a buffered convenience
that resolves on exit. Existing policy-discovery helpers (`getAvailableToolsPolicy`,
etc.) compose into `SandboxPolicy` unchanged.

## Wire contract

The wire envelope is a TypeScript discriminated union over `phase`, JSON-serialised.
The Rust executor parses the same shape via private `Raw*` intermediate structs
(reference §9.1). The only `Record<string, unknown>` in the contract is
`ErrorEnvelope.details` — the escape hatch for backend-specific structured failure
information.

```typescript
interface OneShotRequest {
  phase?: never;
  containment: SandboxingMethod;
  process: ProcessConfig;
  filesystem?: FilesystemConfig;
  network?: NetworkConfig;
  ui?: UiConfig;
  experimental?: ExperimentalOneShotConfigs;  // existing one-shot shape per docs/config-schema.md
  // ...other one-shot fields per docs/config-schema.md
}

interface ProvisionStateAwareRequest {
  phase: 'provision';
  containment: StateAwareSandboxingMethod;
  filesystem?: FilesystemConfig;      // backend declares per-phase honor
  network?: NetworkConfig;
  ui?: UiConfig;
  experimental?: ExperimentalStateAwareConfigs;
}

interface NonProvisionStateAwareRequest {
  phase: 'start' | 'exec' | 'stop' | 'deprovision';
  sandboxId: SandboxId<StateAwareSandboxingMethod>;  // backend resolved from prefix
  process?: ProcessConfig;            // exec only
  filesystem?: FilesystemConfig;
  network?: NetworkConfig;
  ui?: UiConfig;
  experimental?: ExperimentalStateAwareConfigs;
}

type StateAwareRequest = ProvisionStateAwareRequest | NonProvisionStateAwareRequest;

interface ExperimentalStateAwareConfigs {
  isolation_session?: IsolationSessionStateAwareConfigs;
  // future state-aware-capable backends add typed entries here
}

interface IsolationSessionStateAwareConfigs {
  start?: IsolationSessionStartConfig;
  // provision, exec, stop, deprovision omitted — IsolationSession has no config there
}

interface IsolationSessionStartConfig {
  configurationId?: 'small' | 'medium' | 'large' | 'commandLine';
}

type MxcRequest = OneShotRequest | StateAwareRequest;
```

The two shapes do not coexist in a single call — `phase` fully discriminates.

**Response convention** is phase-aware. `stdout` is reserved for the structured
response: a single JSON envelope (`{result}` or `{error}`) for non-exec phases, the
script's raw stream for exec succeeded, or one `{error}` envelope for exec
dispatch-failure. `stderr` carries MXC diagnostic output (when `--debug` is passed) and,
in exec, the script's stderr. See main doc §7.3 for the full stream-usage table and
SDK parsing rules.

## Rust trait

```rust
pub trait StatefulSandboxBackend {
    const ID_PREFIX: &'static str;

    type ProvisionConfig: serde::de::DeserializeOwned;
    type StartConfig: serde::de::DeserializeOwned;
    type ExecConfig: serde::de::DeserializeOwned;
    type StopConfig: serde::de::DeserializeOwned;
    type DeprovisionConfig: serde::de::DeserializeOwned;
    type ProvisionMetadata: serde::Serialize;
    type StartMetadata: serde::Serialize;
    type StopMetadata: serde::Serialize;
    type DeprovisionMetadata: serde::Serialize;

    // Default body mints `<ID_PREFIX>:<random-token>`; override for native provision.
    fn provision(
        &mut self,
        request: &CodexRequest,
        config: Option<Self::ProvisionConfig>,
    ) -> Result<ProvisionResult<Self::ProvisionMetadata>, MxcError> { /* ... */ }

    // Default body returns Ok with no metadata.
    fn start(
        &mut self,
        sandbox_id: &str,
        request: &CodexRequest,
        config: Option<Self::StartConfig>,
    ) -> Result<StartResult<Self::StartMetadata>, MxcError> { /* ... */ }

    // Required.
    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &CodexRequest,
        config: Option<Self::ExecConfig>,
    ) -> Result<ExecHandle, MxcError>;

    fn stop(
        &mut self,
        sandbox_id: &str,
        request: &CodexRequest,
        config: Option<Self::StopConfig>,
    ) -> Result<StopResult<Self::StopMetadata>, MxcError> { /* ... */ }

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        request: &CodexRequest,
        config: Option<Self::DeprovisionConfig>,
    ) -> Result<DeprovisionResult<Self::DeprovisionMetadata>, MxcError> { /* ... */ }

    // Per-phase validate_<phase> hooks (default Ok). See main doc §9.2.
}
```

Backends declare a const id prefix, per-phase config and metadata as associated types
(use `()` for phases that don't need either), and override only the methods they care
about — `exec` is the only required method. Trait methods take `&CodexRequest` (the
existing one-shot domain model from `wxc_common::models`) plus `sandbox_id` for
non-provision phases and an optional backend-specific typed config; cross-cutting
policy fields flow through `request.policy` (a `ContainerPolicy`) and per-exec process
info flows through `request.script_code` / `request.working_directory` /
`request.script_timeout` / `request.env`. There is no unified Rust "policy" type and
no Rust `ProcessConfig` / `FilesystemConfig` / `NetworkConfig` / `UiConfig` wrapper
struct — those names exist as TypeScript SDK interfaces only. See "Why the trait
reuses `CodexRequest`" in main doc §9.2 for the rationale.

A backend's participation mode (ephemeral-only, state-aware-only, both) is declared by
which traits it implements. State-aware backends additionally register an id prefix
alongside their `ContainmentBackend` variant; the dispatcher reads the prefix from
`sandboxId` to route non-provision calls. Reference §4 describes the modes; reference
§5 covers id prefixes; reference §9 describes the Rust mirror struct and dispatch.

## Worked example: IsolationSession

Provision and exec — the two most distinctive shapes. Reference §7.4 has all five phases
(provision, start, exec, stop, deprovision) end-to-end.

#### Provision

```typescript
const policy: SandboxPolicy = {
  version: '0.5.0-alpha',
  filesystem: { readwritePaths: ['C:\\workspace'] },
  network: { allowOutbound: true, allowedHosts: ['api.anthropic.com'] },
};
const { sandboxId } = await provisionSandbox('isolation_session', { policy });
// sandboxId = "iso:reg-abc:prov-123"
```

```json
{
  "containment": "isolation_session",
  "phase": "provision",
  "filesystem": { "readwritePaths": ["C:\\workspace"] },
  "network": { "defaultPolicy": "allow", "allowedHosts": ["api.anthropic.com"] }
}
```

```rust
// Parser deserializes the JSON above into a CodexRequest with
//   request.policy.readwrite_paths = ["C:\\workspace"]
//   request.policy.default_network_policy = NetworkPolicy::Allow
//   request.policy.allowed_hosts = ["api.anthropic.com"]
// (the same one-shot path the parser already uses). The dispatcher then calls:
backend.provision(&request, /* config */ None)
// returns Ok(ProvisionResult {
//     sandbox_id: "iso:reg-abc:prov-123".into(),
//     metadata: Some(IsolationSessionProvisionMetadata {
//         agent_user_name: "_iso_abc_123".into(),
//     }),
// })
```

```json
{ "result": { "sandboxId": "iso:reg-abc:prov-123", "metadata": { "agentUserName": "_iso_abc_123" } } }
```

#### Exec (buffered)

```typescript
// sandboxId from the provision example above.
const r = await execInSandboxAsync(sandboxId, {
  commandLine: 'echo hello',
});
// r = { stdout: "hello\n", stderr: "", exitCode: 0 }
```

```json
{
  "phase": "exec",
  "sandboxId": "iso:reg-abc:prov-123",
  "process": { "commandLine": "echo hello" }
}
```

```rust
// Parser populates request.script_code = "echo hello" from the wire-format `process`
// block (same path as one-shot). The dispatcher then calls:
backend.exec("iso:reg-abc:prov-123", &request, /* config */ None)
// returns Ok(ExecHandle { stdout, stderr, stdin, waiter, terminator })
```

Wire response (raw streaming, no JSON envelope on success):
- stdout: `hello\n`
- stderr: (empty)
- exit code: `0`

The SDK constructs `{ stdout: "hello\n", stderr: "", exitCode: 0 }` from PTY events.

The SDK auto-wraps backend-specific config under `experimental.<backend>.<phase>`.
Cross-backend exec fields flow through top-level `process`. `SandboxPolicy` fields map to
top-level `filesystem` / `network` / `ui` for state-aware (backend declares per-phase
honor per reference §10.3).

## Error codes

Closed enum at the MXC layer; backend-specific failures use `backend_error` with
structured `details`. Reference §8 has the full list and the typed exception class
mapping.

| Group | Codes |
|---|---|
| Envelope problems | `malformed_request`, `unsupported_containment`, `unsupported_phase` |
| Runtime dependency | `backend_unavailable` |
| Id problems | `malformed_id`, `stale_id` |
| State-machine violations | `not_provisioned`, `not_started`, `already_started`, `already_stopped` |
| Config / policy | `policy_validation` |
| Catch-all | `backend_error` (with structured `details`) |

Process-runtime kill conditions (timeouts, backend-initiated termination) surface as
sentinel exit codes from the exec process, not as typed wire-format errors. Each code
maps to a typed TS exception class (`MxcError` base + per-code subclasses).

## Plug-in steps for new backends

Reference §11 has the full guide. Operational checklist:

1. Pick a participation mode (ephemeral-only, state-aware-only, both).
2. Implement the trait. Define associated types for each phase's config and metadata;
   use `()` for any phase that doesn't need them.
3. Define typed `*Config` interfaces in `@microsoft/mxc-sdk` and slot into
   `ExperimentalStateAwareConfigs`. If newly SDK-exposed, extend `SandboxingMethod` and
   `StateAwareSandboxingMethod`.
4. Register a variant in the `ContainmentBackend` enum, declare the backend's id prefix
   alongside the variant (it serves as the dispatcher's routing key for non-provision
   calls), and add a dispatch arm.
5. Add `Raw*` intermediate structs in `config_parser.rs` for the backend's wire-format
   block.
6. Document policy-honor matrix, idempotence, concurrency, and error mapping in
   `docs/<backend-or-feature>/<plan-name>.md` (e.g.,
   `docs/isolation-session/state-aware-plan.md`).
7. Add a feature-unavailable test (CI-runnable) and an integration test.
8. Update `.github/copilot-instructions.md`.

## Graduation and scope

- **Graduation rule.** Per-stage config stays under `experimental.<backend>.<phase>`
  while either the API or that backend's state-aware participation is experimental.
  When both are stable, migrates to top-level `<backend>.<phase>`. The same `phase`
  discrimination rule applies post-graduation. Reference §13.
- **Out of scope for v1.** Detached / OS-level fire-and-forget execs (JS-async
  fire-and-forget IS supported via don't-await on existing functions); additional
  lifecycle stages; cross-machine `SandboxId` portability; MXC-enforced container-wide
  timeouts; per-backend metadata for `exec` (live-streaming response makes this
  structurally hard, deferred until a concrete backend need arises). Reference §14.
