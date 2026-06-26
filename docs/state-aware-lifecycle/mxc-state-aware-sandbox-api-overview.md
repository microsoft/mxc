# MXC State-Aware Sandbox API — Overview

*Companion to [mxc-state-aware-sandbox-api.md](./mxc-state-aware-sandbox-api.md).*
*Compiled 2026-04-28.*

A state-aware sandbox API for MXC, surfaced alongside the existing one-shot
`spawnSandbox*` family. Five lifecycle phases; opaque caller-owned `SandboxId`;
per-(backend, phase) typed Config interfaces that absorb cross-cutting fields directly
(no separate `SandboxPolicy` parameter). Backends opt in by implementing a new
`StatefulSandboxBackend` Rust trait. MXC retains no state between calls.

`spawnSandbox` is the composition of the five phases run end-to-end. State-aware exposes
each phase individually.

## Existing MXC types referenced

The proposal reuses several existing MXC types unchanged. They appear in interfaces and
function signatures throughout. One-line summaries; full definitions live in
`sdk/src/types.ts`, `sdk/src/policy.ts`, and `docs/config-schema.md`.

| Type | Where | Role |
|---|---|---|
| `ContainmentType` / `ContainmentBackend` | `sdk/src/types.ts` | Two-tier containment names: `ContainmentType` for abstract intents (`'process' \| 'vm' \| 'microvm'` today); `ContainmentBackend` for concrete runners (`'processcontainer' \| 'windows_sandbox' \| 'lxc' \| 'wslc' \| 'microvm' \| 'seatbelt' \| 'isolation_session'`). Wire `containment` accepts either. The deprecated alias `SandboxingMethod = ContainmentType \| ContainmentBackend` is retained for back-compat. |
| `ProcessConfig` | `sdk/src/types.ts` | Per-process settings: `commandLine`, `cwd`, `env`, `timeout`. Reused inside state-aware exec Configs. |
| `FilesystemConfig`, `NetworkConfig`, `UiConfig` | `sdk/src/types.ts` | Wire-format-aligned cross-cutting interfaces. Reused inline as field types inside the per-(backend, phase) state-aware Configs. |
| `SandboxSpawnOptions` | `sdk/src/sandbox.ts` | Existing options bag (debug, dryRun, logDir, executablePath, ptyOptions, usePty, experimental). State-aware reuses it as the third positional arg, extended with `signal?: AbortSignal` for cancellation. |
| `pty.IPty` | `node-pty` package | Interactive PTY handle. Used as the streaming-exec return type, matching existing `spawnSandbox`. |
| `getAvailableToolsPolicy`, `getUserProfilePolicy`, `getTemporaryFilesPolicy` | `sdk/src/policy.ts` | Filesystem-policy discovery helpers. Produce `FilesystemPolicyResult` fragments that compose into a state-aware Config's `filesystem` field. |
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
| TypeScript SDK (reference §6) | Five new functions: `provisionSandbox`, `startSandbox`, `execInSandbox` / `execInSandboxAsync`, `stopSandbox`, `deprovisionSandbox`. Branded `SandboxId<C>` type tagging ids by backend (`containment` named once at provision, inferred from the id thereafter). Per-(backend, phase) typed `*Config` interfaces (e.g. `IsolationSessionProvisionConfig`) that absorb cross-cutting fields directly — no separate policy parameter. Per-phase typed `*Result` types per backend. `AbortSignal` cancellation via the existing `SandboxSpawnOptions`. Typed `MxcError` class carrying a closed-enum `code`. | `spawnSandbox` family preserved. `ContainmentBackend` extension reused. The wire-format-aligned `Process` / `Filesystem` / `Network` / `UiConfig` interfaces from `sdk/src/types.ts` are reused as field types inside state-aware Configs. `SandboxSpawnOptions` reused as the third-arg options bag (gains `signal?: AbortSignal`). `*Config` naming convention reused. |
| JSON wire format (reference §7) | Top-level `phase` discriminator. Top-level `sandboxId`. `containment` carried on provision only; non-provision phases route via the `sandboxId` prefix. Per-phase nesting under `experimental.<backend>.<phase>`. Named envelope types as a TypeScript discriminated union. | One-shot configs (no `phase`) work unchanged. Cross-cutting `filesystem` / `network` / `ui` at top level for state-aware too — backends declare per-phase honor. |
| Rust executor (reference §9) | Dispatch arm for state-aware. New `StatefulSandboxBackend` trait. Rust mirror of the wire envelope (the `wire::MxcConfig` parse target). | `ScriptRunner` trait. Existing one-shot dispatch path. Existing backends unchanged. |
| Error model (reference §8) | Closed enum of 12 codes. `MxcError` class with `code: ErrorCode`. `details` open object. | Existing one-shot error paths preserved. |
| Plug-in surface (reference §11) | Implement `StatefulSandboxBackend`. Define typed per-(backend, phase) `*Config` interfaces. Declare the trait's `ID_PREFIX` and `BACKEND_KEY` consts. Document the cross-cutting honor matrix. | Ephemeral-only backends require no changes. |

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

Each phase takes a per-(backend, phase) Config — a single named interface that absorbs
both the cross-cutting fields the backend honors at that phase and any backend-specific
per-phase fields. `SandboxPolicy` does not appear in the state-aware surface. Full
definitions and worked types are in
[reference §6.1](./mxc-state-aware-sandbox-api.md#6-typescript-sdk).

```typescript
type Phase = 'provision' | 'start' | 'exec' | 'stop' | 'deprovision';
type SandboxId<C extends StateAwareContainmentBackend> =
  string & { readonly __mxcBrand: 'SandboxId'; readonly __mxcBackend: C };
type StateAwareContainmentBackend = Extract<ContainmentBackend, 'isolation_session'>;
// extended as state-aware-capable backends are added

interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}
```

```typescript
function provisionSandbox<C extends StateAwareContainmentBackend>(
  containment: C,
  config?: ProvisionConfigFor<C>,
  options?: SandboxSpawnOptions,
): Promise<ProvisionResult<C>>;

function startSandbox<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config?: StartConfigFor<C>,
  options?: SandboxSpawnOptions,
): Promise<StartResult<C>>;

function execInSandbox<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config: ExecConfigFor<C>,
  options?: SandboxSpawnOptions,
): pty.IPty;

function execInSandboxAsync<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config: ExecConfigFor<C>,
  options?: SandboxSpawnOptions,
): Promise<ExecResult>;

function stopSandbox<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config?: StopConfigFor<C>,
  options?: SandboxSpawnOptions,
): Promise<StopResult<C>>;

function deprovisionSandbox<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config?: DeprovisionConfigFor<C>,
  options?: SandboxSpawnOptions,
): Promise<DeprovisionResult<C>>;
```

`<Phase>ConfigFor<C>` resolves to a per-(backend, phase) named interface (e.g.,
`IsolationSessionProvisionConfig`) that declares only the fields valid for that
backend at that phase. Cross-cutting fields appear inline at the Config root in the
phases where the backend honors them (e.g., `IsolationSessionProvisionConfig` carries
`filesystem` / `network` / `ui`); phases without backend-specific or cross-cutting
fields declare a Config carrying only `version?`. `containment` is named once at
`provisionSandbox` and inferred from the branded `SandboxId<C>` on every subsequent
call. Each non-exec phase returns a typed `<Phase>Result<C>`: provision carries
`sandboxId` plus optional metadata; start, stop, and deprovision carry optional
metadata only. `execInSandbox` returns an `IPty` for live streaming;
`execInSandboxAsync` is a buffered convenience that resolves on exit. The third
positional argument is the existing `SandboxSpawnOptions` (extended with
`signal?: AbortSignal` for cancellation), the same options bag one-shot uses.
`experimental: true` is required when the targeted backend is itself experimental
(IsolationSession is today); state-awareness as a feature is not gated by an
experimental flag. Existing policy-discovery helpers (`getAvailableToolsPolicy` and
friends) produce `FilesystemPolicyResult` fragments that compose directly into a
state-aware Config's `filesystem` field — no change to the helpers.

## Wire contract

The wire envelope is a TypeScript discriminated union over `phase`, JSON-serialised.
The Rust executor parses the same shape into the typed wire model
(`wire::MxcConfig`, reference §9.1). The only `Record<string, unknown>` in the contract is
`ErrorEnvelope.details` — the escape hatch for backend-specific structured failure
information.

```typescript
interface OneShotRequest {
  phase?: never;
  containment: ContainmentType | ContainmentBackend;
  process: ProcessConfig;
  filesystem?: FilesystemConfig;
  network?: NetworkConfig;
  ui?: UiConfig;
  experimental?: ExperimentalOneShotConfigs;  // existing one-shot shape per docs/config-schema.md
  // ...other one-shot fields per docs/config-schema.md
}

interface ProvisionStateAwareRequest {
  phase: 'provision';
  containment: StateAwareContainmentBackend;
  filesystem?: FilesystemConfig;      // backend declares per-phase honor
  network?: NetworkConfig;
  ui?: UiConfig;
  experimental?: ExperimentalStateAwareConfigs;
}

interface NonProvisionStateAwareRequest {
  phase: 'start' | 'exec' | 'stop' | 'deprovision';
  sandboxId: SandboxId<StateAwareContainmentBackend>;  // backend resolved from prefix
  process?: ProcessConfig;            // exec only
  filesystem?: FilesystemConfig;
  network?: NetworkConfig;
  ui?: UiConfig;
  experimental?: ExperimentalStateAwareConfigs;
}

type StateAwareRequest = ProvisionStateAwareRequest | NonProvisionStateAwareRequest;

// Wire-format shape of the `experimental` block on state-aware requests. The SDK
// builds this from per-(backend, phase) Configs (see TypeScript SDK section above).
interface ExperimentalStateAwareConfigs {
  isolation_session?: {
    start?: { configurationId?: 'small' | 'medium' | 'large' | 'composable' };
    // provision, exec, stop, deprovision omitted — IsolationSession has no
    // backend-specific config for those phases.
  };
  // future state-aware-capable backends add typed entries here
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
    const BACKEND_KEY: &'static str;

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
        request: &ExecutionRequest,
        config: Option<Self::ProvisionConfig>,
    ) -> Result<ProvisionResult<Self::ProvisionMetadata>, MxcError> { /* ... */ }

    // Default body returns Ok with no metadata.
    fn start(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        config: Option<Self::StartConfig>,
    ) -> Result<StartResult<Self::StartMetadata>, MxcError> { /* ... */ }

    // Required.
    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        config: Option<Self::ExecConfig>,
    ) -> Result<ExecHandle, MxcError>;

    fn stop(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        config: Option<Self::StopConfig>,
    ) -> Result<StopResult<Self::StopMetadata>, MxcError> { /* ... */ }

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        config: Option<Self::DeprovisionConfig>,
    ) -> Result<DeprovisionResult<Self::DeprovisionMetadata>, MxcError> { /* ... */ }

    // Per-phase validate_<phase> hooks (default Ok). See main doc §9.2.
}
```

Backends declare two consts (`ID_PREFIX` for sandbox-id routing, `BACKEND_KEY` for the
wire-format `containment` value and `experimental.<BACKEND_KEY>.<phase>` deserialisation
— see reference §5), per-phase config and metadata as associated types (use `()` for
phases that don't need either), and override only the methods they care about — `exec`
is the only required method. Trait methods take `&ExecutionRequest` (the existing one-shot
domain model from `wxc_common::models`) plus `sandbox_id` for non-provision phases and
an optional backend-specific typed config; cross-cutting policy fields flow through
`request.policy` (a `ContainerPolicy`) and per-exec process info flows through
`request.script_code` / `request.working_directory` / `request.script_timeout` /
`request.env`. There is no Rust `ProcessConfig` / `FilesystemConfig` / `NetworkConfig`
/ `UiConfig` wrapper struct — those names exist as TypeScript SDK interfaces only. See
"Why the trait reuses `ExecutionRequest`" in main doc §9.2 for the rationale.

A backend's participation mode (ephemeral-only, state-aware-only, both) is declared by
which traits it implements. State-aware backends additionally register their
`ID_PREFIX` and `BACKEND_KEY` on the trait impl alongside their `ContainmentBackend`
variant; the dispatcher reads the prefix from `sandboxId` to route non-provision calls
and the backend key for provision-phase routing and experimental-block deserialisation.
Reference §4 describes the modes; reference §5 covers identifiers; reference §9
describes the Rust mirror struct and dispatch.

## Worked example: IsolationSession

Provision and exec — the two most distinctive shapes. Reference §7.4 has all five phases
(provision, start, exec, stop, deprovision) end-to-end.

#### Provision

```typescript
const config: IsolationSessionProvisionConfig = {
  filesystem: { readwritePaths: ['C:\\workspace'] },
  network: { defaultPolicy: 'allow', allowedHosts: ['api.anthropic.com'] },
};
const { sandboxId } = await provisionSandbox(
  'isolation_session',
  config,
  { experimental: true },
);
// sandboxId = "iso:reg-abc:prov-123"
```

```json
{
  "version": "0.6.0-alpha",
  "containment": "isolation_session",
  "phase": "provision",
  "filesystem": { "readwritePaths": ["C:\\workspace"] },
  "network": { "defaultPolicy": "allow", "allowedHosts": ["api.anthropic.com"] }
}
```

```rust
// Parser deserializes the JSON above into an ExecutionRequest with
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
const r = await execInSandboxAsync(
  sandboxId,
  { process: { commandLine: 'echo hello' } },
  { experimental: true },
);
// r = { stdout: "hello\n", stderr: "", exitCode: 0 }
```

```json
{
  "version": "0.6.0-alpha",
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
Cross-backend exec fields flow through top-level `process`. Cross-cutting fields
(`filesystem` / `network` / `ui`) on the per-(backend, phase) Config map directly to
top-level wire fields (backend declares per-phase honor per reference §10.3). The
SDK Config exposes only the cross-cutting fields the runtime currently honors —
for IsolationSession at provision today that's `filesystem`; `network` and `ui` are
added when the runtime honors them.

## Error codes

Closed enum at the MXC layer; backend-specific failures use `backend_error` with
structured `details`. Reference §8 has the full list and the `MxcError` mapping.

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
maps to an `MxcError` with the corresponding `code` field.

## Plug-in steps for new backends

Reference §11 has the full guide. Operational checklist:

1. Pick a participation mode (ephemeral-only, state-aware-only, both).
2. Implement the trait. Define associated types for each phase's config and metadata;
   use `()` for any phase that doesn't need them.
3. Define typed per-(backend, phase) `*Config` interfaces in `@microsoft/mxc-sdk` and
   add an arm to `ConfigsForBackend<C>` mapping the backend to its five phase Configs.
   If newly SDK-exposed, extend `ContainmentBackend` and `StateAwareContainmentBackend`.
4. Register a variant in the `ContainmentBackend` enum and declare two consts on the
   trait impl: `ID_PREFIX` (the sandbox-id tag, dispatcher's routing key for
   non-provision calls — pick a short distinct tag and treat it as permanent) and
   `BACKEND_KEY` (the wire-format `containment` value, used for provision-phase
   routing and `experimental.<BACKEND_KEY>.<phase>` deserialisation). Add a dispatch
   arm for the new variant.
5. Add typed fields to the `experimental` block of the wire model (`wire.rs`) for the
   backend's wire-format block, then regenerate the schema.
6. Document policy-honor matrix, idempotence, concurrency, and error mapping in
   `docs/<backend-or-feature>/<plan-name>.md` (e.g.,
   `docs/isolation-session/state-aware-plan.md`).
7. Add a feature-unavailable test (CI-runnable) and an integration test.
8. Update `.github/copilot-instructions.md`.

## Graduation and scope

- **Graduation rule.** The state-aware API surface ships stable from `0.6.0`.
  Per-stage config for a backend stays under `experimental.<backend>.<phase>` while
  that backend's state-aware participation is experimental, and migrates to top-level
  `<backend>.<phase>` when the backend's state-aware participation graduates. The
  `phase` discrimination rule applies post-graduation. Reference §13.
- **Out of scope for v1.** Detached / OS-level fire-and-forget execs (JS-async
  fire-and-forget IS supported via don't-await on existing functions); additional
  lifecycle stages; cross-machine `SandboxId` portability; MXC-enforced container-wide
  timeouts; per-backend metadata for `exec` (live-streaming response makes this
  structurally hard, deferred until a concrete backend need arises). Reference §14.
