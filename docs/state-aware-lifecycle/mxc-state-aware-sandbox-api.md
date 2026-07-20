# MXC State-Aware Sandbox API

*Detailed design proposal. Compiled 2026-04-28.*

## Contents

**Part I — Motivation and principles**

1. [Summary](#1-summary)
2. [Context and motivation](#2-context-and-motivation)
3. [Design philosophy](#3-design-philosophy)

**Part II — Consumer-facing surface**

4. [Lifecycle model](#4-lifecycle-model)
5. [Identifiers](#5-identifiers)
6. [TypeScript SDK](#6-typescript-sdk)
7. [Wire contract](#7-wire-contract)
8. [Error model](#8-error-model)

**Part III — Backend-author surface**

9. [Rust layer architecture](#9-rust-layer-architecture)
10. [Per-stage configs and validation](#10-per-stage-configs-and-validation)
11. [Plug-in guide for new backends](#11-plug-in-guide-for-new-backends)

**Part IV — Operational concerns**

12. [Failure semantics](#12-failure-semantics)
13. [Graduation path](#13-graduation-path)

**Part V — Bounds**

14. [Out of scope for v1](#14-out-of-scope-for-v1)

## 1. Summary

This document proposes a state-aware sandbox API for MXC, surfaced alongside the existing
one-shot `spawnSandbox*` family. Five lifecycle phases are exposed at the SDK level:
provision, start, exec, stop, deprovision. Each is a discrete call. Provision returns an
opaque `SandboxId` string the caller persists and forwards to subsequent calls. The API
surface ships stable from `0.6.0` — state-awareness is not itself gated by an
`--experimental` flag. Per-stage configuration is typed per-backend per-phase under
`experimental.<backend>.<phase>` while a backend's state-aware participation is
experimental, and migrates to top-level `<backend>.<phase>` when that backend's
state-aware participation graduates (§13). Backends opt in by implementing a new
`StatefulSandboxBackend` Rust trait. The existing `ScriptRunner` trait is unchanged. A
backend's participation mode (state-aware, ephemeral, or both) is declared by which
trait or traits it implements.

The mental model: `spawnSandbox` is the composition of the five phases into one call.
State-aware exposes them individually so callers can hold a sandbox between calls, run
multiple workloads inside it, and tear it down explicitly.

Sandbox state is owned by the backend's underlying service. The `SandboxId` is the only
handle the caller gets; persisting it between calls is the caller's responsibility. MXC
retains no state between calls and does not become a sandbox orchestrator. Backends with
no meaningful state continue to expose only the one-shot surface; state-aware
participation is fully opt-in.

The proposal adds artefacts at five layers of MXC. Each row points into the section that
elaborates.

| MXC layer | What's new | What's unchanged |
|---|---|---|
| TypeScript SDK (§6) | Five new functions: `provisionSandbox`, `startSandbox`, `execInSandbox` / `execInSandboxAsync`, `stopSandbox`, `deprovisionSandbox`. Branded `SandboxId<C>` type tagging ids by backend (`containment` named once at provision, inferred from the id thereafter). Per-(backend, phase) typed `*Config` interfaces (e.g. `IsolationSessionProvisionConfig`) that absorb cross-cutting fields directly — no separate policy parameter. Per-phase typed `*Result` types per backend. `AbortSignal` cancellation via the existing `SandboxSpawnOptions`. Typed `MxcError` class carrying a closed-enum `code`. | `spawnSandbox` family preserved. `ContainmentBackend` extension mechanism reused. The existing wire-format-aligned `ProcessConfig` / `FilesystemConfig` / `NetworkConfig` / `UiConfig` interfaces from `sdk/node/src/types.ts` are reused as field types inside the new state-aware Configs. `SandboxSpawnOptions` reused as the third-arg options bag (gains `signal?: AbortSignal`). Existing typed `*Config` naming convention reused. |
| JSON wire format (§7) | Top-level `phase` discriminator. Top-level `sandboxId`. `containment` carried on provision only; non-provision phases route via the `sandboxId` prefix. Per-phase nesting under `experimental.<backend>.<phase>`. Named envelope types as a TypeScript discriminated union over `phase`. | One-shot configs (no `phase`) work unchanged. Cross-cutting `filesystem` / `network` / `ui` fields at top level for state-aware too — backends declare per-phase honor. |
| Rust executor (§9) | Dispatch arm for state-aware. New `StatefulSandboxBackend` trait. Rust mirror of the wire envelope (the `wire::MxcConfig` parse target). | `ScriptRunner` trait. Existing one-shot dispatch path. Existing backends function without modification. |
| Error model (§8) | Closed enum of 12 error codes. `MxcError` class with `code: ErrorCode`. `details` open object as escape hatch for backend-specific structured information. | Existing one-shot error paths preserved. |
| Plug-in surface (§11) | Implement `StatefulSandboxBackend` (in addition to or instead of `ScriptRunner`). Define typed per-(backend, phase) `*Config` interfaces. Declare the backend's `ID_PREFIX` and `BACKEND_KEY` consts on the trait impl. Document the cross-cutting policy honor matrix. | Ephemeral-only backends require no changes. The `ContainmentBackend` Rust enum is extended, not replaced. |

## 2. Context and motivation

MXC's existing containment surface runs each invocation as a self-contained lifecycle: set
up the sandbox, execute the workload, tear it down. This shape fits backends whose
sandboxes carry no meaningful state between invocations.

It does not fit backends whose sandboxes are inherently persistent. A provisioned isolation
session has a long-lived user profile holding installed tools, configuration, and
credentials. A WSL distribution is a long-lived Linux environment with its own filesystem
and package set. A Hyper-V virtual machine is a running OS instance. A Docker container
can host a service that lives across many client interactions. For all of these, sandbox
state is not a side-effect of the workload; it is part of what the workload depends on. A
one-shot API forces these backends to fold the full provision/start/exec/stop/deprovision
sequence into every call, discarding any state the workload accumulated.

This proposal introduces a state-aware lifecycle surface alongside the existing one-shot
API, so backends with meaningful persistent state can expose that state to callers as a
first-class concept. IsolationSession is the first such backend.

The design holds three constraints throughout:

- MXC does not take on responsibility for any persistent storage. The durable identifier
  of a stateful sandbox belongs to the backend's underlying service; persisting it
  across calls is the caller's responsibility.
- The contract supports easy plug-in by backend developers. Per-phase configuration is
  typed per-backend in a way that backends with different native lifecycle models can map
  cleanly.
- MXC's charter stays scoped to managing and executing within sandboxes, ephemeral or
  persistent. MXC is the conduit into sandbox APIs, not a state manager itself.

## 3. Design philosophy

Three principles shape decisions throughout the rest of the document.

**Backends declare semantics.** Concurrency, idempotence, security guarantees, sequencing rules,
allowed phase transitions, cross-cutting policy honor, and error mapping are per-backend. MXC
standardises the envelope that conveys backend responses (success result or typed error)
but does not impose universal semantics on top. For example, a double-stop call returns
whatever the backend reports, and MXC surfaces that response unchanged.

**Layered validation.** The SDK validates the envelope (recognised containment, required
fields, branded `SandboxId<C>` type, typed `*Config` shape). The MXC dispatch layer
re-validates the envelope and adds capability checks. The backend implementation validates
per-stage config field values and cross-cutting policy semantics. Each layer validates
what it cheaply can, so obvious errors surface without an unnecessary subprocess
round-trip.

**Honest opt-in surface.** State-aware participation is declared explicitly by the backend
implementor. A backend that does not declare state-aware support continues to expose only
the one-shot surface, and state-aware methods called against it return a typed error. The
API surface reflects what each backend actually supports rather than papering over
capability gaps with no-op stubs.

## 4. Lifecycle model

The state-aware API exposes five lifecycle phases. Each is a discrete call. Together they
compose into the full sandbox lifecycle that one-shot `spawnSandbox` runs end-to-end.

| Phase | Valid from state | Resulting state | Output | Purpose |
|---|---|---|---|---|
| `provision` | (not provisioned) | provisioned | `sandboxId`, optional metadata | Allocate the sandbox resource |
| `start` | provisioned | running | optional metadata | Bring the sandbox to a state where it can host workloads |
| `exec` | running | running | stdout, stderr, exit code | Run a workload; may be called any number of times |
| `stop` | running | provisioned | optional metadata | Take the sandbox out of running; the provisioned resource remains |
| `deprovision` | provisioned | (not provisioned) | optional metadata | Release the provisioned resource; the `SandboxId` becomes invalid |

The five phases form a small state machine over three states: not-provisioned,
provisioned, and running. The `SandboxId` is valid from provision through deprovision;
once deprovision returns, the id is assumed to no longer route to any backend resource.

A backend whose underlying API has no meaningful equivalent for `provision`, `start`,
`stop`, or `deprovision` can omit the implementation entirely; the trait provides
default no-op bodies for those four (§9.2). The default `provision` mints a synthetic
`sandbox_id` of the form `<ID_PREFIX>:<random-token>` that subsequent calls echo back.
`exec` is always required — every state-aware backend must execute the workload to be
useful. The backend's documentation states which phases are no-ops. The MXC dispatch
layer treats substantive and no-op implementations identically; SDK signatures do not
differentiate them.

Each backend declares one of three participation modes:

- **Ephemeral-only**: implements only the existing one-shot `ScriptRunner` trait.
  State-aware calls against this backend return `error.code: "unsupported_phase"` (§8).
- **State-aware-only**: implements only the new `StatefulSandboxBackend` trait. One-shot
  calls return `unsupported_phase`.
- **Both**: implements both traits. The relationship between the two code paths (whether
  the one-shot path internally invokes the stateful lifecycle or runs as a separate
  implementation) is the implementor's choice.

Stages beyond these five (snapshot, suspend, attach, restore, etc.) are deferred (§14). A
backend with native support can expose them privately under
`experimental.<backend>.<custom-stage>` until they are universalised.

## 5. Identifiers

The `SandboxId` returned by `provision` is the only identifier the caller uses to refer to
the provisioned sandbox in later calls. It is an opaque string at every observable layer
(TS SDK, JSON wire format, CLI output).

The backend generates the `SandboxId` during `provision`. A backend whose underlying API
requires caller-supplied identifiers (e.g., one that uses registration and provisioning
IDs) mints them inside the backend implementation and encodes them into the id string.
A backend whose underlying API generates identifiers itself (Docker, future Hyper-V)
captures the generated value and encodes it. The first segment is a
backend-specific prefix (e.g., `iso:`, `docker:`); past the prefix, the encoding is
opaque to MXC.

The prefix is required: backend authors register their tag alongside the backend's
`ContainmentBackend` variant, and the dispatcher uses it to route non-provision calls
without a separate `containment` field on the wire (§7.1).

The wire spec and the SDK observably disagree on *which* error fires for an
unrecognised prefix, and this is by design:

| Source                  | Behaviour for an unrecognised `sandboxId` prefix |
| ----------------------- | ------------------------------------------------ |
| SDK (TypeScript)        | Throws `MxcError { code: 'malformed_id' }` **before** the request reaches `wxc-exec`. The SDK matches the prefix against the closed `StateAwareContainmentBackend` union it was compiled with; an unknown prefix is treated as a malformed id (not as a runtime dispatch failure). See `sdk/node/src/state-aware-helper.ts`. |
| Wire (`wxc-exec` directly) | Returns `MxcError { code: 'unsupported_containment' }`. The Rust dispatcher parses the prefix successfully but the prefix-to-backend lookup table has no entry for it. See `src/core/wxc_common/src/state_aware_dispatch.rs`. |

A recognised prefix with a malformed body is `malformed_id` from both sources
(§8). The same prefix is exposed on the `StatefulSandboxBackend` trait as
`const ID_PREFIX: &'static str` (§9.2) so the default `provision` body can mint
synthetic ids with the right prefix; the trait const and the dispatcher's routing table
read from the same source, eliminating drift within Rust.

A second const, `const BACKEND_KEY: &'static str`, lives alongside `ID_PREFIX` on the
trait (§9.2). It carries the wire-format `containment` value for the backend (e.g.,
`"isolation_session"`) and matches the SDK's `StateAwareContainmentBackend` member name.
The dispatcher uses it to navigate `experimental.<BACKEND_KEY>.<phase>` for typed-config
deserialisation and to resolve `provision`-phase requests whose wire `containment`
string maps to this backend. `ID_PREFIX` and `BACKEND_KEY` are deliberately distinct
strings: `ID_PREFIX` is a compact tag chosen for sandbox-id brevity (e.g. `"iso"`)
while `BACKEND_KEY` is the full backend name shared with the SDK type system (e.g.
`"isolation_session"`). Backends that pick a long `BACKEND_KEY` for SDK readability
are not forced to repeat that length in every persisted sandbox id.

The SDK exposes the id as a branded TypeScript string parameterised by backend:

```typescript
type SandboxId<C extends StateAwareContainmentBackend> =
  string & { readonly __mxcBrand: 'SandboxId'; readonly __mxcBackend: C };
```

The runtime value is a plain string; the brand exists at compile time only. The
`__mxcBackend` phantom field carries the backend identity through the type system so
non-provision SDK calls can infer their backend from the id without the caller restating
it. The brand also prevents callers from accidentally passing other strings (a
`containerId`, a path, a literal) where a `SandboxId` is expected.

Persisting the id between calls is the caller's responsibility. The caller chooses the
storage mechanism. MXC neither tracks the id after `provision` returns nor verifies its
validity until the caller passes it back. If an id refers to a resource that no longer
exists, the next call returns `error.code: "stale_id"` (§8); the caller decides whether
to re-provision or treat the failure terminally.

MXC detects `stale_id` by translating the backend's native lookup-failure error —
returned when the underlying service no longer recognises the resource — into the typed
MXC error code. MXC itself retains no caller-side state and performs no validity check
before the call reaches the backend. Each backend's plan doc (§11.6) documents which
native errors map to `stale_id`.

**Disambiguation: `sandboxId` vs `containerId`.** Two different identifiers exist on the
wire format and have different roles:

| Field | Where it appears | Source | Purpose |
|---|---|---|---|
| `sandboxId` | State-aware wire envelope (§7); SDK return value from `provisionSandbox` | System-generated by the backend | Opaque routing identifier; must be passed to subsequent state-aware calls |
| `containerId` | One-shot wire envelope (per `docs/schema.md`) | Caller-supplied (or auto-generated random hex) | Human-readable label, used as e.g. AppContainer profile name |

State-aware non-provision calls carry `sandboxId` on the request; provision returns it
on the response. Neither shape carries `containerId`. One-shot calls carry `containerId`
(when present); they do not carry `sandboxId`.

## 6. TypeScript SDK

The SDK adds five new functions, exported from `@microsoft/mxc-sdk` alongside the existing
one-shot entry points. Each function corresponds to a lifecycle phase from §4. The
state-aware surface does not use `SandboxPolicy` — its cross-cutting fields live
directly on the per-(backend, phase) Configs introduced below.

### 6.1 Type definitions

```typescript
type SandboxId<C extends StateAwareContainmentBackend> =
  string & { readonly __mxcBrand: 'SandboxId'; readonly __mxcBackend: C };

type Phase = 'provision' | 'start' | 'exec' | 'stop' | 'deprovision';

type StateAwareContainmentBackend = Extract<ContainmentBackend, 'isolation_session' | 'windows_sandbox'>;
// extended as state-aware-capable backends are added

// Per-(backend, phase) Configs. Each declares only the fields valid for that backend
// at that phase. Cross-cutting fields (`filesystem`, `network`, `ui`) appear inline
// at the Config root, only in phases where the backend honors them per its policy
// honor matrix (§10.3). Phases with no backend-specific or cross-cutting fields
// declare a Config carrying only `version?`.

interface IsolationSessionProvisionConfig {
  version?: string;
  filesystem?: FilesystemConfig;
  network?: NetworkConfig;
  ui?: UiConfig;
}

interface IsolationSessionStartConfig {
  version?: string;
  configurationId?: 'small' | 'medium' | 'large' | 'composable';
}

interface IsolationSessionExecConfig {
  version?: string;
  process: ProcessConfig;
}

interface IsolationSessionStopConfig {
  version?: string;
}

interface IsolationSessionDeprovisionConfig {
  version?: string;
}

interface IsolationSessionProvisionMetadata {
  agentUserName: string;
}

// WindowsSandbox holds a single active sandbox behind a persistent host-side
// daemon. It has no Entra/user bundle. Filesystem policy is honored at
// provision and is immutable thereafter (see §10.3).

interface WindowsSandboxProvisionConfig {
  version?: string;
  filesystem?: FilesystemConfig;
}

interface WindowsSandboxStartConfig {
  version?: string;
}

interface WindowsSandboxExecConfig {
  version?: string;
  process: ProcessConfig;
}

interface WindowsSandboxStopConfig {
  version?: string;
}

interface WindowsSandboxDeprovisionConfig {
  version?: string;
}

// WindowsSandbox returns no metadata for any phase.

// Backend Config bundle — outer keys are state-aware-capable backends; inner per-phase
// entries carry the typed per-(backend, phase) Config. Used by the generic per-phase
// helpers below.
type ConfigsForBackend<C extends StateAwareContainmentBackend> =
  C extends 'isolation_session' ? {
    provision: IsolationSessionProvisionConfig;
    start: IsolationSessionStartConfig;
    exec: IsolationSessionExecConfig;
    stop: IsolationSessionStopConfig;
    deprovision: IsolationSessionDeprovisionConfig;
  } : C extends 'windows_sandbox' ? {
    provision: WindowsSandboxProvisionConfig;
    start: WindowsSandboxStartConfig;
    exec: WindowsSandboxExecConfig;
    stop: WindowsSandboxStopConfig;
    deprovision: WindowsSandboxDeprovisionConfig;
  } : never;

type ProvisionConfigFor<C extends StateAwareContainmentBackend> =
  ConfigsForBackend<C>['provision'];
type StartConfigFor<C extends StateAwareContainmentBackend> =
  ConfigsForBackend<C>['start'];
type ExecConfigFor<C extends StateAwareContainmentBackend> =
  ConfigsForBackend<C>['exec'];
type StopConfigFor<C extends StateAwareContainmentBackend> =
  ConfigsForBackend<C>['stop'];
type DeprovisionConfigFor<C extends StateAwareContainmentBackend> =
  ConfigsForBackend<C>['deprovision'];

// Per-backend metadata bundle. Backends omit phases that return no metadata.
interface StateAwareMetadata {
  isolation_session?: {
    provision?: IsolationSessionProvisionMetadata;
    // IsolationSession returns no metadata for start, stop, deprovision
  };
  windows_sandbox?: Record<never, never>;
  // WindowsSandbox returns no metadata for any phase (keyof never -> undefined).
  // Future state-aware-capable backends add typed entries here.
}

type ProvisionMetadataFor<C extends StateAwareContainmentBackend> =
  'provision' extends keyof NonNullable<StateAwareMetadata[C]>
    ? NonNullable<StateAwareMetadata[C]>['provision']
    : undefined;
type StartMetadataFor<C extends StateAwareContainmentBackend> =
  'start' extends keyof NonNullable<StateAwareMetadata[C]>
    ? NonNullable<StateAwareMetadata[C]>['start']
    : undefined;
type StopMetadataFor<C extends StateAwareContainmentBackend> =
  'stop' extends keyof NonNullable<StateAwareMetadata[C]>
    ? NonNullable<StateAwareMetadata[C]>['stop']
    : undefined;
type DeprovisionMetadataFor<C extends StateAwareContainmentBackend> =
  'deprovision' extends keyof NonNullable<StateAwareMetadata[C]>
    ? NonNullable<StateAwareMetadata[C]>['deprovision']
    : undefined;

interface ProvisionResult<C extends StateAwareContainmentBackend> {
  sandboxId: SandboxId<C>;
  metadata?: ProvisionMetadataFor<C>;
  correlationVector?: string; // MS-CV to relay onto later phases (telemetry)
}

interface StartResult<C extends StateAwareContainmentBackend> {
  metadata?: StartMetadataFor<C>;
}

interface StopResult<C extends StateAwareContainmentBackend> {
  metadata?: StopMetadataFor<C>;
}

interface DeprovisionResult<C extends StateAwareContainmentBackend> {
  metadata?: DeprovisionMetadataFor<C>;
}

interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}
```

`FilesystemConfig`, `NetworkConfig`, `UiConfig`, `ProcessConfig` are the existing
wire-format-aligned interfaces from `sdk/node/src/types.ts`, reused unchanged as field
types inside the per-(backend, phase) Configs. State-aware deliberately does not use
`SandboxPolicy`; consumers spell out wire-format-aligned values directly (e.g.,
`network: { defaultPolicy: 'block' }` instead of `network: { allowOutbound: false }`).

A backend's per-(backend, phase) Config declares each cross-cutting field exactly once,
and only in the phase where the backend's policy honor matrix (§10.3) marks it as
`applied`. For IsolationSession, that means `IsolationSessionProvisionConfig` carries
`filesystem` / `network` / `ui` and the other four phase Configs do not — the type
system rejects callers passing those fields to start, exec, stop, or deprovision (§10.3
explains how the matrix lands at compile time on the SDK and at runtime in Rust).
Phases with no backend-specific or cross-cutting fields declare a Config carrying only
`version?` — explicit and minimal. Adding a future state-aware backend is a localised
change: extend `StateAwareContainmentBackend`, define five new `*Config` interfaces, and
add an arm to `ConfigsForBackend`.

Each Config carries an optional `version?: string`. When omitted, the SDK fills in its
own `SUPPORTED_VERSION`; an explicit value is range-validated against the SDK's
`MIN_VERSION` and `SUPPORTED_VERSION` (same convention as today's
`validatePolicyVersion`). The override exists so consumers can target a specific wire
version when debugging or testing version negotiation.

### 6.2 Method signatures

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

`execInSandbox` returns an `IPty` for live streaming (caller subscribes to `onData` /
`onExit`); `execInSandboxAsync` is a buffered convenience that accumulates output and
resolves on exit. This mirrors the existing `spawnSandbox` (returns `IPty`) /
`spawnSandboxAsync` (returns Promise) split.

`provisionSandbox` takes `containment` as its first argument, binding the backend choice
into the returned `SandboxId<C>`. Subsequent calls (`startSandbox`, `execInSandbox` /
`execInSandboxAsync`, `stopSandbox`, `deprovisionSandbox`) infer the backend from the
branded id and do not restate it. The wire envelope mirrors this: provision carries
`containment`; non-provision phases route via the prefix on `sandboxId` (§5, §7.1).

The third positional argument is the existing `SandboxSpawnOptions` from
`sdk/node/src/sandbox.ts`, extended with `signal?: AbortSignal` for cancellation.
State-aware reuses the same options bag as one-shot — single mental model, single place
to learn the cross-cutting flags. Phase-specific fields on `SandboxSpawnOptions`
(`ptyOptions`, `usePty`) are honored by `execInSandbox` / `execInSandboxAsync` and
silently ignored on the other phases. State-awareness is not itself experimental —
`experimental: true` must be set when the targeted backend is itself experimental, just
as it is today for one-shot calls against `microvm` and `wslc`. IsolationSession is
experimental at the time of writing; that status is independent of the state-aware API
surface (§13).

### 6.3 Example

```typescript
import {
  provisionSandbox,
  startSandbox,
  execInSandbox,
  execInSandboxAsync,
  stopSandbox,
  deprovisionSandbox,
  getAvailableToolsPolicy,
  IsolationSessionProvisionConfig,
  SandboxSpawnOptions,
} from '@microsoft/mxc-sdk';

const tools = getAvailableToolsPolicy();
const provisionConfig: IsolationSessionProvisionConfig = {
  filesystem: {
    readwritePaths: ['C:\\workspace', ...tools.readwritePaths],
    readonlyPaths: tools.readonlyPaths,
  },
  network: { defaultPolicy: 'allow', allowedHosts: ['api.anthropic.com'] },
};

// IsolationSession is experimental, so every call carries `experimental: true`.
const opts: SandboxSpawnOptions = { experimental: true };

// Provision — cross-cutting fields apply at this phase per the IS honor matrix (§10.3).
const { sandboxId } = await provisionSandbox('isolation_session', provisionConfig, opts);

// Start — backend-specific config picks the session size.
await startSandbox(sandboxId, { configurationId: 'small' }, opts);

// Exec — buffered convenience for short workloads.
const result = await execInSandboxAsync(
  sandboxId,
  { process: { commandLine: 'echo hello', timeout: 5000 } },
  opts,
);
console.log(result.stdout);  // "hello\n"

// Exec — streaming for long-running workloads. Returns IPty.
const session = execInSandbox(
  sandboxId,
  { process: { commandLine: 'C:\\workspace\\agent.exe --watch' } },
  opts,
);
session.onData((chunk) => process.stdout.write(chunk));
session.onExit(({ exitCode }) => console.log(`agent exit: ${exitCode}`));

// Stop and deprovision when done. Stop and deprovision Configs carry only `version?`,
// so callers typically pass `{}` (or omit when no options are needed).
await stopSandbox(sandboxId, {}, opts);
await deprovisionSandbox(sandboxId, {}, opts);
```

### 6.4 Composition with the one-shot surface

`spawnSandbox` is the composition of the five state-aware phases run end-to-end. The two
surfaces share `ContainmentBackend` and the wire-format-aligned interfaces in
`sdk/node/src/types.ts` (`ProcessConfig`, `FilesystemConfig`, `NetworkConfig`, `UiConfig`).
They differ in granularity and in how those interfaces are surfaced: one-shot bundles
them inside `ContainerConfig` (which is itself produced from a `SandboxPolicy` by
`createConfigFromPolicy`); state-aware uses them as field types inside the
per-(backend, phase) Configs and does not involve `SandboxPolicy` at all. A backend
that participates in both modes can be invoked through either surface; a backend that
participates in only one returns `unsupported_phase` from the other (§8).

State-aware-capable backends extend `ContainmentBackend` and `StateAwareContainmentBackend`
the same way ephemeral backends extend `ContainmentBackend`. Cancellation via
`AbortSignal` is supported on all state-aware methods (via `signal?: AbortSignal` on
`SandboxSpawnOptions`). Detached / fire-and-forget exec (process outliving the SDK
call) is deferred to v2 (§14).

### 6.5 Policy discovery

The existing policy-discovery helpers (`getAvailableToolsPolicy`,
`getUserProfilePolicy`, `getTemporaryFilesPolicy`) compose with state-aware Configs
unchanged. They produce `FilesystemPolicyResult` fragments — `{ readonlyPaths,
readwritePaths }` — whose shape matches `FilesystemConfig`'s readonly / readwrite path
arrays. Consumers merge the fragments directly into a state-aware Config's `filesystem`
field, as in the §6.3 example.

## 7. Wire contract

The wire contract is a typed envelope, JSON-serialised, that flows from the SDK to the
executor (`wxc-exec` on Windows, `lxc-exec` on Linux) via the existing `--config-base64`
CLI argument. Both ends agree on the same shape: the SDK serialises a TypeScript value,
the executor parses the same value into a Rust struct (§9.1). The only open content in
the envelope is at the leaves of `ErrorEnvelope.details`.

### 7.1 Request envelope

The envelope is a TypeScript discriminated union over a top-level `phase` field. When
`phase` is absent, the request targets the existing one-shot surface. When `phase` is
present, the request targets the state-aware surface. The two shapes do not coexist in a
single call — `phase` fully discriminates which interpretation applies.

```typescript
interface OneShotRequest {
  phase?: never;                                  // discriminator: absent
  version?: string;
  containment: ContainmentType | ContainmentBackend;
  containerId?: string;
  process: ProcessConfig;
  filesystem?: FilesystemConfig;
  network?: NetworkConfig;
  ui?: UiConfig;
  lifecycle?: LifecycleConfig;
  processContainer?: ProcessContainerConfig;
  lxc?: LxcConfig;
  experimental?: ExperimentalOneShotConfigs;     // existing one-shot shape per docs/schema.md
}

interface ProvisionStateAwareRequest {
  phase: 'provision';                             // discriminator
  version?: string;
  containment: StateAwareContainmentBackend;
  filesystem?: FilesystemConfig;                  // backend declares per-phase honor
  network?: NetworkConfig;                        // backend declares per-phase honor
  ui?: UiConfig;                                  // backend declares per-phase honor
  experimental?: ExperimentalStateAwareConfigs;
}

interface NonProvisionStateAwareRequest {
  phase: 'start' | 'exec' | 'stop' | 'deprovision';  // discriminator
  version?: string;
  sandboxId: SandboxId<StateAwareContainmentBackend>;  // backend resolved from prefix
  process?: ProcessConfig;                            // exec only
  filesystem?: FilesystemConfig;                      // backend declares per-phase honor
  network?: NetworkConfig;                            // backend declares per-phase honor
  ui?: UiConfig;                                      // backend declares per-phase honor
  experimental?: ExperimentalStateAwareConfigs;
}

type StateAwareRequest = ProvisionStateAwareRequest | NonProvisionStateAwareRequest;

type MxcRequest = OneShotRequest | StateAwareRequest;
```

The wire format is the JSON serialisation of an `MxcRequest` value. There is no
"stringified blob" anywhere in the contract; everything except `ErrorEnvelope.details` is
statically typed.

Top-level fields shared by both branches:

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | string | No | Schema version (semver). |
| `experimental` | object | No | Backend-specific config block. Shape depends on `phase` (§7.2). |

Backend-routing fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `containment` | `ContainmentType` or `ContainmentBackend` member | One-shot: yes. State-aware: yes for `provision`, absent for `start` / `exec` / `stop` / `deprovision`. | Backend selection on calls that do not yet have a `sandboxId`. |
| `sandboxId` | branded string | State-aware non-provision: yes. Otherwise absent. | Opaque sandbox id returned by `provision`. Carries the backend prefix used to route non-provision calls (§5). |

State-aware-only fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `phase` | `Phase` member | Yes | Discriminator. Absence means a one-shot request. |
| `correlationVector` | string | No. Relayed by the client onto non-`provision` phases; absent on `provision` (seeded by the executor). Rejected as a parse error on one-shot requests. | Microsoft Correlation Vector (MS-CV) seeded at `provision` and returned in its result; the client relays it verbatim into later phases so the lifecycle shares a telemetry base prefix (emitted under `__TlgCV__`). Each non-`provision` phase validates the relayed value and *spins* a fresh child element off a mutable base (keeping repeat invocations distinct), passes an already-frozen vector through unchanged, and reseeds a new base if it is absent or malformed. Ignored unless experimental telemetry is enabled. See [telemetry docs](../telemetry/telemetry.md#correlating-a-lifecycle). |
| `process` | `ProcessConfig` | Required for `exec`; absent otherwise. | Cross-backend execution fields. |

Cross-cutting fields available to state-aware (state-aware-only at top level — backends
declare which phases honor them, see §10.3):

| Field | Type | Description |
|---|---|---|
| `filesystem` | `FilesystemConfig` | Filesystem access policy. |
| `network` | `NetworkConfig` | Network access policy. |
| `ui` | `UiConfig` | UI access policy. |

One-shot-only fields (`containerId`, `lifecycle`, `processContainer`, `lxc`) are not
enumerated here; their definitions live in `docs/schema.md`.

### 7.2 The `experimental` block

`ExperimentalStateAwareConfigs` describes the wire-format shape of the `experimental`
field on a state-aware request. It is a wire-only type — consumers do not construct
it directly. The SDK builds this shape internally from the per-(backend, phase) Configs
defined in §6.1, lifting backend-specific fields into the nested experimental block:

```typescript
interface ExperimentalStateAwareConfigs {
  isolation_session?: {
    start?: { configurationId?: 'small' | 'medium' | 'large' | 'composable' };
    // provision, exec, stop, deprovision omitted — IsolationSession has no
    // backend-specific config for those phases.
  };
  // future state-aware-capable backends add typed entries here
}
```

| Layer | Wire shape | Constraint |
|---|---|---|
| Outer key | `StateAwareContainmentBackend` member | Must be a state-aware-capable backend |
| Inner key | A subset of `Phase` per backend's needs | Backends omit phases with no backend-specific config |
| Innermost value | Backend-specific fields only (no cross-cutting, no `version`) | The SDK extracts these from the consumer's per-(backend, phase) Config |

Compile-time enforcement of valid combinations lives on the SDK's per-(backend, phase)
Configs (§6.1), not on this wire-shape type. Raw-JSON callers writing
`ExperimentalStateAwareConfigs` directly are validated by the Rust parser and
`validate_<phase>` hooks at runtime (§10.1).

For one-shot calls (phase absent), `experimental.<backend>` directly holds the backend's
one-shot config object (e.g., `experimental.wslc?: WslcConfig`), as documented in
`docs/schema.md`. The TypeScript types make this distinction structural:
`OneShotRequest.experimental` and `StateAwareRequest.experimental` have different shapes.

### 7.3 Response convention

The response convention is phase-aware and uses the executor process's stdout and
stderr streams distinctly.

**Stream usage (state-aware):**

| Phase / outcome | stdout | stderr |
|---|---|---|
| Non-exec (provision, start, stop, deprovision), success or failure | Single JSON envelope (`{result}` or `{error}`) | MXC diagnostic output (when `--debug`); empty otherwise |
| Exec, dispatch succeeded | Script's stdout (via PTY or pipe) | Script's stderr (pipe mode) or merged with stdout (PTY mode); MXC diagnostic also lands here when `--debug` is passed |
| Exec, dispatch failed | Single JSON envelope (`{error}`) | MXC diagnostic output (when `--debug`); empty otherwise |

`stdout` is authoritative: for non-exec phases it carries exactly one envelope; for exec
it carries either the script's output (success) or exactly one envelope (failure).
`stderr` is informational. MXC routes its diagnostic logger output to `stderr` in
state-aware mode so `stdout` remains parseable without sentinels. (One-shot dispatch
keeps its existing `stdout` logger behaviour — the stricter routing applies to
state-aware only.)

For exec specifically, MXC diagnostic output mixes with the script's own stderr when
`--debug` is passed. This is a small amount of pre- and post-dispatch noise; consumers
wanting clean separation should use `--log-file <path>` instead, which routes diagnostic
output to a file and leaves stderr as pure script content.

**Envelope shape:**

```typescript
interface ErrorEnvelope {
  code: ErrorCode;
  message: string;
  details?: Record<string, unknown>;
}

type NonExecResponseEnvelope<TResult> = { result: TResult } | { error: ErrorEnvelope };
```

| Phase | `TResult` shape |
|---|---|
| `provision` | `{ sandboxId: SandboxId<C>; metadata?: object; correlationVector?: string }` |
| `start` | `{ metadata?: object }` |
| `stop` | `{ metadata?: object }` |
| `deprovision` | `{ metadata?: object }` |

**Distinguishing exec dispatch-failure from script execution:**

The SDK uses exit code plus stdout content:

- `exitCode == 0`: the script ran and exited successfully. SDK constructs
  `{stdout, stderr, exitCode}` from PTY / pipe events.
- `exitCode != 0` AND stdout's entire content parses as a complete `{error: {...}}`
  envelope: dispatch failed before the script ran; SDK surfaces the typed error.
- `exitCode != 0` AND stdout does NOT parse as an envelope: the script ran and exited
  non-zero. SDK constructs `{stdout, stderr, exitCode}`.

Because MXC diagnostic output is routed to `stderr` in state-aware mode, this
stdout-based discrimination has no false positives or negatives — the content is always
either pure envelope or pure script output.

`ErrorEnvelope.details` is the only `Record<string, unknown>` in the contract. It's the
escape hatch backends use to convey structured failure information that's
per-error-code (a backend's native HRESULT, partial output captured before a timeout,
etc.). Each backend's plan doc (§11) specifies what `details` contains for which error
codes.

### 7.4 Worked example: IsolationSession end-to-end

A complete state-aware lifecycle, threading TS call → JSON the SDK serialises and passes
to the executor via `--config-base64` → Rust trait method that dispatches → response
shape, across all five phases.

#### Phase 1 — provision

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
// (and the other top-level wire fields populated as today's one-shot path
// already populates them). The dispatcher then calls:
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

#### Phase 2 — start

```typescript
await startSandbox(
  sandboxId,
  { configurationId: 'small' },
  { experimental: true },
);
```

```json
{
  "version": "0.6.0-alpha",
  "phase": "start",
  "sandboxId": "iso:reg-abc:prov-123",
  "experimental": { "isolation_session": { "start": { "configurationId": "small" } } }
}
```

```rust
// Dispatcher deserializes `experimental.isolation_session.start` into
// IsolationSessionStartConfig { configuration_id: Small }, then calls:
backend.start(
    "iso:reg-abc:prov-123",
    &request,
    Some(IsolationSessionStartConfig { configuration_id: Small }),
)
// returns Ok(StartResult { metadata: None })
```

```json
{ "result": {} }
```

#### Phase 3 — exec (buffered)

```typescript
const r = await execInSandboxAsync(
  sandboxId,
  { process: { commandLine: 'echo hello', timeout: 5000 } },
  { experimental: true },
);
// r = { stdout: "hello\n", stderr: "", exitCode: 0 }
```

```json
{
  "version": "0.6.0-alpha",
  "phase": "exec",
  "sandboxId": "iso:reg-abc:prov-123",
  "process": { "commandLine": "echo hello", "timeout": 5000 }
}
```

```rust
// Parser populates request.script_code = "echo hello", request.script_timeout =
// 5000 from the wire-format `process` block (same path as one-shot). The
// dispatcher then calls:
backend.exec("iso:reg-abc:prov-123", &request, /* config */ None)
// returns Ok(ExecHandle { ... pipe handles + waiter ... })
```

Wire response (raw streaming, no JSON envelope on success):
- stdout: `hello\n`
- stderr: (empty)
- exit code: `0`

The SDK constructs `{ stdout: "hello\n", stderr: "", exitCode: 0 }` from PTY events and
resolves the Promise.

#### Phase 4 — stop

```typescript
await stopSandbox(sandboxId, {}, { experimental: true });
```

```json
{
  "version": "0.6.0-alpha",
  "phase": "stop",
  "sandboxId": "iso:reg-abc:prov-123"
}
```

```rust
backend.stop("iso:reg-abc:prov-123", &request, /* config */ None)
// returns Ok(StopResult { metadata: None })
```

```json
{ "result": {} }
```

#### Phase 5 — deprovision

```typescript
await deprovisionSandbox(sandboxId, {}, { experimental: true });
```

```json
{
  "version": "0.6.0-alpha",
  "phase": "deprovision",
  "sandboxId": "iso:reg-abc:prov-123"
}
```

```rust
backend.deprovision("iso:reg-abc:prov-123", &request, /* config */ None)
// returns Ok(DeprovisionResult { metadata: None })
```

```json
{ "result": {} }
```

#### Mapping summary

The SDK auto-wraps backend-specific config under `experimental.<backend>.<phase>` when
serialising state-aware calls — consumers write `configurationId` directly on the
`IsolationSessionStartConfig`, the SDK builds the nested wire form. Cross-cutting
fields (`filesystem` / `network` / `ui`) on a per-(backend, phase) Config map directly
to top-level wire fields — they are already wire-format-aligned in the Config, so the
SDK passes them through unchanged. Cross-backend exec fields (`commandLine`, `cwd`,
`env`, `timeout`) flow through the top-level `process` block, not through
`experimental`. For non-exec phases the executor emits a single JSON envelope on
stdout; for exec the script's output streams raw and the SDK constructs the result
from PTY events. Responses unwrap any `result` envelope at the SDK boundary so the
caller sees a plain `ProvisionResult` / `StartResult` / `ExecResult` / `StopResult` /
`DeprovisionResult`.

## 8. Error model

Errors crossing the wire-format boundary are typed by a closed enum of error codes
defined at the MXC layer. Backends map their native errors to these codes; the SDK
throws an `MxcError` carrying the corresponding `code` field. An `MxcError` with
`code: 'stale_id'` thrown from IsolationSession behaves the same as one thrown from any
other state-aware backend, so caller error-handling code is portable across backends.

### 8.1 Error code enum

| Code | Meaning |
|---|---|
| `malformed_request` | Envelope-level error: missing required field, unknown phase, malformed JSON |
| `unsupported_containment` | The backend named by `containment` (provision) or implied by the `sandboxId` prefix (non-provision) is not a recognised backend in this build. **SDK callers**: the SDK type-checks unknown `sandboxId` prefixes against the closed `StateAwareContainmentBackend` union *before* dispatching and instead throws `malformed_id` for an unknown prefix; `unsupported_containment` is reachable from the SDK only on the provision path. See §6.4 |
| `unsupported_phase` | The backend does not support the requested call mode (state-aware call against an ephemeral-only backend, or one-shot call against a state-aware-only backend) |
| `backend_unavailable` | The backend's runtime dependency is missing or unreachable (service not running, daemon stopped) |
| `malformed_id` | The `sandboxId` does not have a recognised backend prefix, or has a recognised prefix but does not deserialise into the backend's native form. **SDK callers** also see this error code for any non-provision call whose `sandboxId` prefix is not in `StateAwareContainmentBackend` |
| `stale_id` | The `sandboxId` deserialised but refers to a resource the backend no longer recognises |
| `not_provisioned` | Phase requires a provisioned sandbox; none provided, or the id is in a pre-provision state |
| `not_started` | Phase requires a started sandbox; the id is provisioned but not started |
| `already_started` | `start` called on an already-running sandbox |
| `already_stopped` | `stop` called on an already-stopped sandbox |
| `policy_validation` | Per-stage config or cross-cutting policy contents do not satisfy the backend's expected shape or values |
| `backend_error` | Catch-all for backend-specific failures; `details` carries structured information |

```typescript
type ErrorCode =
  | 'malformed_request'
  | 'unsupported_containment'
  | 'unsupported_phase'
  | 'backend_unavailable'
  | 'malformed_id'
  | 'stale_id'
  | 'not_provisioned'
  | 'not_started'
  | 'already_started'
  | 'already_stopped'
  | 'policy_validation'
  | 'backend_error';
```

The set is closed at the MXC layer. Backend-specific failures that don't fit one of the
enumerated codes surface as `backend_error` with structured information in `details`.

Process-runtime kill conditions (a script exceeding its `timeout`, a backend forcibly
terminating a process) are not represented as typed wire-format errors. They surface as
sentinel exit codes from the exec process, matching the existing one-shot convention.

### 8.2 Details payload

`details` (introduced in §7.3) is an open `Record<string, unknown>`. Backends use it to
convey structured information that callers may inspect: a backend's native error code,
partial output captured before a timeout fired, or any other context. The shape of
`details` for each error code is documented in the relevant backend's own docs (§11).

### 8.3 TypeScript error class

The SDK throws (rejects) a single `MxcError` class. The wire-format error code lives on
the `code` field and is the discriminator callers pattern-match on:

```typescript
class MxcError extends Error {
  readonly code: ErrorCode;
  readonly details?: Record<string, unknown>;
}
```

Callers discriminate by comparing `.code` to a wire-format error code string
(`err instanceof MxcError && err.code === 'stale_id'`). The TypeScript string-literal
union on `ErrorCode` gives the same IDE completion as a per-code class hierarchy.

## 9. Rust layer architecture

The Rust layer adds a new `StatefulSandboxBackend` trait alongside the existing
`ScriptRunner` trait. Each backend implementation in the workspace is a struct that
implements one trait, the other, or both, depending on its declared participation mode
(§4).

### 9.1 Wire envelope (Rust mirror)

MXC's parser at `src/core/wxc_common/src/config_parser.rs` deserializes the
wire-format JSON directly into the typed wire model in
`src/core/wxc_common/src/wire.rs` (`wire::MxcConfig`), then maps it into the
typed domain models (`convert_wire_config` → `ExecutionRequest`, with `From`
impls beside the domain types for the trivial enum/struct conversions) before
dispatch. The state-aware path reuses this same wire model.

```rust
// In config_parser.rs — discrimination is by presence of the `phase` key in
// the decoded JSON; both shapes deserialize into the one wire::MxcConfig type,
// which declares `phase` / `sandboxId` and the per-backend `experimental` block.
let value: serde_json::Value = serde_json::from_str(&json_str)?;
if value.get("phase").is_some() {
    // state-aware: peel off the raw `experimental` block (typed per-backend at
    // dispatch), deserialize the rest into wire::MxcConfig, then map.
    convert_wire_state_aware(value, logger, allow_missing_command)
} else {
    // one-shot: deserialize wire::MxcConfig from the source text (preserving
    // serde line/column diagnostics) and map.
    let cfg: wire::MxcConfig = serde_json::from_str(&json_str)?;
    convert_wire_config(cfg, logger, true, allow_missing_command)
}
```

`wire::MxcConfig` is closed (`deny_unknown_fields`) on its stable surface, so
unknown fields are rejected at the trust boundary. `phase` maps to the
`wire::Phase` enum. The `experimental` block stays permissive and is captured as
a raw `serde_json::Value` on the state-aware path so the dispatcher can type each
backend's per-phase config from it (`experimental.<backend>.<phase>`).

Per-phase requirements (`containment` for `provision`, `sandboxId` for the
others) are enforced in the conversion step, not at the deserializer. The
one-shot path rejects `phase` / `sandboxId`, and the state-aware path rejects
one-shot-only sections (`seatbelt` / `processContainer` / `lxc` / `lifecycle`),
so each mode only accepts its valid fields.

Conversion populates the cross-cutting wire fields (`filesystem`, `network`,
`ui`) into `ExecutionRequest.policy` (a `ContainerPolicy`) exactly as the
one-shot path does, and `process` populates `ExecutionRequest`'s flat
`script_code` / `working_directory` / `script_timeout` / `env` fields. The
state-aware-only fields (`phase`, `sandboxId`, `experimental.<backend>.<phase>`)
are extracted alongside the `ExecutionRequest` and bundled into a
`ParsedStateAwareRequest` domain model — `{ request: ExecutionRequest, phase:
Phase, containment: Option<ContainmentBackend>, sandbox_id: Option<String>,
experimental_raw: Option<serde_json::Value> }` — that the dispatcher consumes
(§9.3). The bundling does not modify `ExecutionRequest`'s shape. Domain models
are exposed to the dispatch layer; the wire types are an implementation detail of
the parser and schema generation.

### 9.2 The trait

Backends implement the trait with two consts (id prefix and backend key, §5),
associated types for each phase's config and metadata, and method overrides where they
have substantive work.
Most methods have default no-op bodies; only `exec` is strictly required. Use `()` for
any associated type the backend does not need.

```rust
pub trait StatefulSandboxBackend {
    /// Backend identifier prefix. Used as the leading `<tag>:` segment of every
    /// `sandbox_id` minted by the default `provision` body, and read by the
    /// dispatcher to route non-provision calls to this backend (§5).
    const ID_PREFIX: &'static str;

    /// Wire-format `containment` value for this backend, matching the SDK's
    /// `StateAwareContainmentBackend` member name (e.g. `"isolation_session"`).
    /// The dispatcher uses it to navigate `experimental.<BACKEND_KEY>.<phase>`
    /// for typed-config deserialisation (§9.3), and to resolve `provision`-phase
    /// requests whose wire `containment` string maps to this backend.
    /// Distinct from `ID_PREFIX` — see §5 for the rationale.
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

    /// Optional. Default mints `<ID_PREFIX>:<random-token>` for a stateless-
    /// underneath backend; override when the backend has native provision work
    /// (e.g., allocating a session, registering with the underlying service).
    fn provision(
        &mut self,
        _request: &ExecutionRequest,
        _config: Option<Self::ProvisionConfig>,
    ) -> Result<ProvisionResult<Self::ProvisionMetadata>, MxcError> {
        Ok(ProvisionResult {
            sandbox_id: format!("{}:{}", Self::ID_PREFIX, mint_random_token()),
            metadata: None,
        })
    }

    /// Optional. Default returns success with no metadata. Override when the
    /// backend has substantive work to do at start.
    fn start(
        &mut self,
        _sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::StartConfig>,
    ) -> Result<StartResult<Self::StartMetadata>, MxcError> {
        Ok(StartResult { metadata: None })
    }

    /// Required. Must execute the workload and return a handle.
    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        config: Option<Self::ExecConfig>,
    ) -> Result<ExecHandle, MxcError>;

    /// Optional. Default returns success with no metadata.
    fn stop(
        &mut self,
        _sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::StopConfig>,
    ) -> Result<StopResult<Self::StopMetadata>, MxcError> {
        Ok(StopResult { metadata: None })
    }

    /// Optional. Default returns success with no metadata.
    fn deprovision(
        &mut self,
        _sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::DeprovisionConfig>,
    ) -> Result<DeprovisionResult<Self::DeprovisionMetadata>, MxcError> {
        Ok(DeprovisionResult { metadata: None })
    }

    /// Per-phase validation hooks. Called by the dispatch layer before the
    /// corresponding phase method. Default: accept all requests. Override to
    /// add backend-specific checks (config field semantics, policy honor
    /// enforcement, id format checks beyond the prefix). Failures surface as
    /// the chosen `MxcError` code.
    fn validate_provision(
        &self,
        _request: &ExecutionRequest,
        _config: Option<&Self::ProvisionConfig>,
    ) -> Result<(), MxcError> {
        Ok(())
    }

    fn validate_start(
        &self,
        _sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&Self::StartConfig>,
    ) -> Result<(), MxcError> {
        Ok(())
    }

    fn validate_exec(
        &self,
        _sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&Self::ExecConfig>,
    ) -> Result<(), MxcError> {
        Ok(())
    }

    fn validate_stop(
        &self,
        _sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&Self::StopConfig>,
    ) -> Result<(), MxcError> {
        Ok(())
    }

    fn validate_deprovision(
        &self,
        _sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&Self::DeprovisionConfig>,
    ) -> Result<(), MxcError> {
        Ok(())
    }
}

pub struct ProvisionResult<M> {
    pub sandbox_id: String,
    pub metadata: Option<M>,
}

pub struct StartResult<M> {
    pub metadata: Option<M>,
}

pub struct StopResult<M> {
    pub metadata: Option<M>,
}

pub struct DeprovisionResult<M> {
    pub metadata: Option<M>,
}

pub struct ExecHandle {
    /// Stdout pipe handle from the running process. Executor relays to its own stdout.
    pub stdout: PipeHandle,
    /// Stderr pipe handle from the running process. Executor relays to its own stderr.
    pub stderr: PipeHandle,
    /// Stdin pipe handle. Executor relays from its own stdin.
    pub stdin: PipeHandle,
    /// Function to wait for exit; returns the exit code.
    pub waiter: Box<dyn FnOnce() -> Result<i32, MxcError> + Send>,
    /// Function to terminate the process (called on AbortSignal).
    pub terminator: Box<dyn FnOnce() + Send>,
}
```

Trait methods take `&ExecutionRequest` (the existing one-shot domain model from
`wxc_common::models`, populated by the same `convert_wire_config` parser path that
serves one-shot calls), plus `sandbox_id` for non-provision phases and an optional
backend-specific typed config (`Self::<Phase>Config`). Cross-cutting policy fields
flow through `request.policy` (a `ContainerPolicy`); per-exec process info flows
through `request.script_code` / `request.working_directory` / `request.script_timeout`
/ `request.env`; backend-specific per-phase typed config is deserialised by the
dispatcher from `experimental.<backend>.<phase>` and passed as the `config` parameter
(§9.3). Per-phase result types (`ProvisionResult<M>`, `StartResult<M>`,
`StopResult<M>`, `DeprovisionResult<M>`) carry the typed metadata return value;
`ExecHandle` exposes the running process's pipe handles for relay.
`MxcError` is the typed Rust equivalent of its SDK counterpart. `PipeHandle` is a
platform-abstracted pipe-handle wrapper — a kernel `HANDLE` on Windows, a file
descriptor on Linux. The executor's outer driver reads from `ExecHandle.stdout` /
`stderr` and writes to `stdin`, awaits exit via `waiter`, and calls `terminator` on
cancellation signals.

`mint_random_token()` is a small helper in `wxc_common` that produces a short hex string
(mirroring the SDK's `randomBytes`-based id minting in `sandbox.ts`); it is used by the
default `provision` body to construct synthetic ids for stateless-underneath backends.

Methods take `&mut self`, matching the existing `ScriptRunner::run` signature. Backends
do not need to accumulate state between calls within a backend instance — within a
single call a backend may use mutability to hold open service connections, but no state
needs to survive across phase calls.

#### Why the trait reuses `ExecutionRequest`

The trait could plausibly require its own per-phase request types (e.g., an
`ExecRequest<C>` containing typed `ProcessConfig`, `FilesystemConfig`, `NetworkConfig`,
and `UiConfig` fields) instead of taking `&ExecutionRequest` directly. The design rejects
that shape and reuses `ExecutionRequest` for five concrete reasons:

1. **The field-ignore precedent is established across every existing backend.** Every
   `ScriptRunner` impl in the workspace today (`AppContainer`, `BaseContainer`,
   `NanVix`, `WindowsSandbox`, `IsolationSession`, `Lxc`, `Wslc`) takes
   `&ExecutionRequest` and reads only the fields it needs. `NanVix` and
   `IsolationSession` go further and actively reject fields they cannot honor (e.g.,
   `NanVixScriptRunner::validate_runner` rejects filesystem paths, network rules,
   network proxy, and a non-empty working directory). State-aware follows the same
   pattern, so the trait ergonomic stays consistent across one-shot and state-aware
   surfaces.

2. **Process info is already typed on `ExecutionRequest`.** The wire-format `process`
   block (`commandLine`, `cwd`, `env`, `timeout`) deserialises into `ExecutionRequest`'s
   flat fields (`script_code`, `working_directory`, `script_timeout`, `env`) via the
   existing `RawProcess` intermediate in `config_parser.rs`. Wrapping these four
   typed fields into a Rust `ProcessConfig` struct adds no type safety the compiler
   does not already provide on the flat fields. The TypeScript-side `ProcessConfig`
   in `sdk/node/src/types.ts` is unchanged regardless.

3. **Cross-cutting policy is already typed on `ExecutionRequest`.** Existing backends read
   `request.policy.readwrite_paths`, `request.policy.allowed_hosts`,
   `request.policy.network_proxy`, `request.policy.ui`, etc. directly today.
   State-aware `provision` and `validate_<phase>` hooks read the same fields.
   Splitting `ContainerPolicy` into separate `FilesystemConfig` / `NetworkConfig` /
   `UiConfig` Rust types would force a mechanical refactor across every backend
   without changing what any of them does.

4. **The existing extraction helpers already work for state-aware exec.** The
   `IsolationSessionRunner::build_process_options(&ExecutionRequest)` function in
   `isolation_session_common` extracts process info into the runner's
   internal `ProcessOptions` struct used to populate `IsoSessionProcessOptions` for
   `RunProcessWithOptionsAsync`. State-aware `exec` calls the same function with the
   same `&ExecutionRequest` argument; no new public Rust type closes a semantic gap that
   does not exist.

5. **No SDK or wire-format change is required.** The TypeScript `ProcessConfig`,
   `FilesystemConfig`, `NetworkConfig`, and `UiConfig` interfaces in
   `sdk/node/src/types.ts` are public consumer-facing types and remain unchanged. The
   wire JSON shape is unchanged. The Rust trait reading `request.script_code`,
   `request.policy.allowed_hosts`, etc. is an internal implementation choice
   invisible above the Rust layer.

What would justify deviating from `ExecutionRequest` reuse — none of which apply to the v1
surface in this proposal:

- A fundamentally new state-aware-only field that does not fit any existing
  `ExecutionRequest` shape (e.g., a snapshot id for a hypothetical `restore` phase).
- A type-system invariant only expressible via a wrapper struct (e.g., enforcing at
  compile time that exec requests always carry a non-empty command line —
  `validate_exec_common` checks this at runtime instead per §10.1).
- An SDK-API evolution that introduces a new typed shape the Rust trait must mirror
  across the SDK-Rust boundary.

If any of these emerges, the trait gains the necessary type at that point. The v1
surface introduces none, so the trait stays minimal and reuses `ExecutionRequest`.

### 9.3 Dispatch

```rust
/// Dispatch outcome. Distinguishes structured-envelope responses (non-exec phases or
/// dispatch failure) from exec success (where stdio has already streamed live through
/// the relay).
enum DispatchOutcome {
    Envelope(ResponseEnvelope),
    ExecCompleted { exit_code: i32 },
}

fn run(req: MxcRequest, dry_run: bool) -> Result<DispatchOutcome, MxcError> {
    match req {
        MxcRequest::OneShot(r) => Ok(DispatchOutcome::Envelope(run_one_shot(r))),

        MxcRequest::StateAware(parsed) => match resolve_backend(&parsed)? {
            ContainmentBackend::IsolationSession => {
                let mut backend = IsolationSessionRunner::new();
                dispatch_state_aware::<IsolationSessionRunner>(&mut backend, parsed, dry_run)
            }
            // additional state-aware backends added here
            _ => Err(MxcError::UnsupportedPhase),
        },
    }
}

fn dispatch_state_aware<B: StatefulSandboxBackend>(
    backend: &mut B,
    parsed: ParsedStateAwareRequest,
    dry_run: bool,
) -> Result<DispatchOutcome, MxcError> {
    // `parsed` carries the typed `ExecutionRequest`, the parsed `Phase`, the optional
    // `sandbox_id`, and the raw JSON value for `experimental.<backend>.<phase>` (if
    // present). The dispatcher deserialises that raw JSON into the backend's
    // `Self::<Phase>Config` associated type before calling the trait method.
    let request = &parsed.request;
    match parsed.phase {
        Phase::Provision => {
            let config = parsed.deserialize_config::<B::ProvisionConfig>(B::BACKEND_KEY, "provision")?;
            backend.validate_provision(request, config.as_ref())?;
            if dry_run { return Ok(DispatchOutcome::Envelope(empty_envelope())); }
            let result = backend.provision(request, config)?;
            Ok(DispatchOutcome::Envelope(provision_envelope(result)))
        }
        Phase::Start => {
            let sandbox_id = parsed.sandbox_id_required()?;
            let config = parsed.deserialize_config::<B::StartConfig>(B::BACKEND_KEY, "start")?;
            backend.validate_start(sandbox_id, request, config.as_ref())?;
            if dry_run { return Ok(DispatchOutcome::Envelope(empty_envelope())); }
            let result = backend.start(sandbox_id, request, config)?;
            Ok(DispatchOutcome::Envelope(start_envelope(result)))
        }
        Phase::Exec => {
            let sandbox_id = parsed.sandbox_id_required()?;
            let config = parsed.deserialize_config::<B::ExecConfig>(B::BACKEND_KEY, "exec")?;
            validate_exec_common(request)?;
            backend.validate_exec(sandbox_id, request, config.as_ref())?;
            if dry_run { return Ok(DispatchOutcome::Envelope(empty_envelope())); }
            let handle = backend.exec(sandbox_id, request, config)?;
            // relay_exec_to_stdio streams the script's pipes to the executor's
            // stdout/stderr/stdin live, awaits exit, and returns the script's exit code.
            let exit_code = relay_exec_to_stdio(handle)?;
            Ok(DispatchOutcome::ExecCompleted { exit_code })
        }
        Phase::Stop => {
            let sandbox_id = parsed.sandbox_id_required()?;
            let config = parsed.deserialize_config::<B::StopConfig>(B::BACKEND_KEY, "stop")?;
            backend.validate_stop(sandbox_id, request, config.as_ref())?;
            if dry_run { return Ok(DispatchOutcome::Envelope(empty_envelope())); }
            let result = backend.stop(sandbox_id, request, config)?;
            Ok(DispatchOutcome::Envelope(stop_envelope(result)))
        }
        Phase::Deprovision => {
            let sandbox_id = parsed.sandbox_id_required()?;
            let config = parsed.deserialize_config::<B::DeprovisionConfig>(B::BACKEND_KEY, "deprovision")?;
            backend.validate_deprovision(sandbox_id, request, config.as_ref())?;
            if dry_run { return Ok(DispatchOutcome::Envelope(empty_envelope())); }
            let result = backend.deprovision(sandbox_id, request, config)?;
            Ok(DispatchOutcome::Envelope(deprovision_envelope(result)))
        }
    }
}
```

`resolve_backend(&parsed)` reads `parsed.containment` when `phase == Provision`; for the
other phases it reads the prefix from `parsed.sandbox_id` and looks it up in the
registered prefix table. Mismatches surface as `unsupported_containment` (unrecognised
prefix) or `malformed_id` (no prefix structure) per §8.

`ParsedStateAwareRequest::deserialize_config::<C>(backend_key, phase_name)` returns
`Result<Option<C>, MxcError>`: it navigates the wire `experimental.<backend_key>.<phase_name>`
JSON value and deserialises it into `C` when present, returns `Ok(None)` when absent,
and surfaces malformed JSON as `malformed_request`. The dispatcher passes
`B::BACKEND_KEY` so each backend reads from its own slot.
`sandbox_id_required()` enforces that non-provision phases carry a `sandboxId`,
returning `&str` on success or `malformed_request` on absence. `validate_exec_common`
is a free function in `validator.rs` that checks cross-backend per-phase invariants
(e.g., `request.script_code` non-empty); other phases have no cross-backend common
checks today and skip directly to the backend's `validate_<phase>` hook.

Helper functions for handle-validation, config deserialisation, envelope wrapping, and
empty-envelope construction are mechanical and elided. The executor's outer driver
invokes `run` and handles each outcome:

- `Ok(DispatchOutcome::Envelope(env))` — write the envelope's JSON to stdout, exit 0.
- `Ok(DispatchOutcome::ExecCompleted { exit_code })` — exec already streamed live; the
  outer driver exits the executor process with this code. No JSON is emitted.
- `Err(e)` — convert `MxcError` to an `error`-envelope (§7.3), write the JSON to stdout,
  exit non-zero.

### 9.4 Capability declaration

A backend's participation mode (§4) is declared by which traits it implements. Rust's
type system enforces the declaration: dispatch arms can only invoke trait methods that
the backend actually implements. Dispatch-wiring mismatches are compile-time errors,
not runtime registry checks.

State-aware backends additionally register two consts on their trait impl alongside
their `ContainmentBackend` variant: `ID_PREFIX` (the sandbox-id tag, used by the
dispatcher to resolve non-provision calls to the right backend) and `BACKEND_KEY` (the
wire-format `containment` value, used for provision-phase routing and
`experimental.<BACKEND_KEY>.<phase>` typed-config deserialisation). Both are described
in §5.

Per-stage config contents are also typed at compile time — the backend's associated
types declare exactly what JSON shape each phase accepts, and the dispatch layer
deserialises into those types before the trait method runs. There is no
`Record<string, unknown>` shim between the wire format and the backend's typed input.

## 10. Per-stage configs and validation

Per-stage configs are typed end-to-end: TypeScript interfaces in the SDK package, Rust
types in the backend's crate. The wire format is the JSON serialisation of those typed
shapes.

### 10.1 Validation layers

| Layer | Validates | Failure surfaces as |
|---|---|---|
| SDK (TypeScript) | Recognised `containment` (provision); branded `SandboxId<C>` (other phases); required cross-backend fields (`process.commandLine` for exec); typed config shape (autocompletion + compile-time check) | Thrown at the call site, before any subprocess runs |
| MXC parser (Rust) | Envelope shape: `phase` present; `sandbox_id` present for non-provision; `process` present for exec; typed config deserialisation from JSON | `error.code: malformed_request`, `unsupported_phase`, `unsupported_containment` |
| MXC dispatch common (Rust) | Cross-backend per-phase invariants (e.g., `validate_exec_common` checks `process.commandLine` non-empty) | `error.code: malformed_request`, `policy_validation` |
| Backend `validate_<phase>` hooks (Rust) | Per-backend per-phase invariants: config field values, cross-cutting policy honor (per the matrix in §10.3), id format checks beyond prefix matching | `error.code: policy_validation`, `malformed_id`, `stale_id`, `backend_error`, `backend_unavailable` |

Each layer validates only what it cheaply can. The SDK's typed config catches structural
errors at compile time. The dispatch layer catches structural errors that escaped the
SDK (e.g., from non-TypeScript callers). The backend catches semantic errors that depend
on runtime state (e.g., "the configuration ID is recognised but not allowed for this
agent user").

### 10.2 Backend-side config typing

A typical state-aware backend defines its `*Config` types alongside the trait
implementation, in both Rust and TypeScript. The Rust types use `#[derive(Deserialize)]`
with serde renames to camelCase and represent the wire-shape sub-portion that lives
under `experimental.<BACKEND_KEY>.<phase>` — backend-specific fields only. The
TypeScript type exported from the SDK package is the consumer-facing per-(backend,
phase) Config from §6.1; it is a strict superset of the wire shape, adding
`version?` (for explicit version overrides) and the cross-cutting `filesystem` /
`network` / `ui` fields in phases where the backend's policy honor matrix marks them
as `applied` (§10.3).

```rust
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IsolationSessionStartConfig {
    pub configuration_id: IsolationSessionConfigurationId,
}
```

```typescript
interface IsolationSessionStartConfig {
  version?: string;
  configurationId?: 'small' | 'medium' | 'large' | 'composable';
}
```

The TypeScript Config carries `version` (which the SDK serialises to the top-level
wire `version` field) plus any cross-cutting fields the matrix marks `applied` for
that phase (none for IsolationSession's `start`). The Rust struct receives only what
the wire's `experimental.isolation_session.start` block carries —
`{ "configurationId": "small" }` — because that is what the dispatcher deserialises
into `Self::StartConfig` (§9.3). The SDK is responsible for splitting the consumer
Config into top-level wire fields (cross-cutting, `version`) and the experimental
sub-block; Rust sees only the post-split shape.

### 10.3 Cross-cutting policy honor matrix

Each backend declares which phases honor which cross-cutting field (`filesystem`,
`network`, `ui`). The matrix shape is the proposal-level contract: a row per
cross-cutting field, a column per phase, with values from the closed set
`applied` / `rejected` / `ignored`. Specific values per backend are documented in each
backend's plan doc (§11.6). For IsolationSession, illustrative values (final values
documented in the backend's plan doc):

| Field | provision | start | exec | stop | deprovision |
|---|---|---|---|---|---|
| `filesystem` | applied | rejected | rejected | rejected | rejected |
| `network` | applied | rejected | rejected | rejected | rejected |
| `ui` | applied | rejected | rejected | rejected | rejected |

For WindowsSandbox, filesystem policy (readwrite/readonly/denied HOST paths) is
applied at provision and frozen for the life of the sandbox; later phases reject it.
`network` and `ui` are not yet honored at any phase (network isolation is enforced
unconditionally by the in-guest agent). WindowsSandbox has no Entra `user` bundle.

> **Known gap (`deniedPaths`).** WindowsSandbox honors `deniedPaths` only as a
> best-effort provision-time rejection (a `.wsb` mapped share cannot express a Deny
> ACE), not as a hardened security boundary. See the "Known gap (`deniedPaths`)"
> caveat in [`docs/windows-sandbox/windows-sandbox.md`](../windows-sandbox/windows-sandbox.md).

| Field | provision | start | exec | stop | deprovision |
|---|---|---|---|---|---|
| `filesystem` | applied | rejected | rejected | rejected | rejected |
| `network` | rejected | rejected | rejected | rejected | rejected |
| `ui` | rejected | rejected | rejected | rejected | rejected |

- **Compile-time enforcement at the SDK.** Each per-(backend, phase) Config (§6.1)
  declares only the cross-cutting fields the matrix marks as `applied` for that phase
  *and* that the runtime currently honors. TypeScript rejects callers passing fields
  the backend does not honor at that phase, and also fields the matrix would mark as
  `applied` but the runtime does not yet implement. For IsolationSession's matrix
  above, `IsolationSessionProvisionConfig` is the only Config that carries any
  cross-cutting fields. The SDK currently exposes `filesystem` only; `network` and
  `ui` will be added at provision when the IsolationSession runtime honors them.
  The start, exec, stop, and deprovision Configs carry none of these fields. Callers
  cannot accidentally pass them.
- **Runtime enforcement at Rust.** The backend's `validate_<phase>` hooks reject
  cross-cutting fields received from raw-JSON callers (or from a future SDK release
  whose typing has fallen out of step) that the matrix marks as `rejected`. Failures
  surface as `policy_validation` (§8). The Rust check is the authoritative contract
  for any wire-format consumer that bypasses the SDK; the SDK check is a strictly
  stricter (compile-time) restatement of the same matrix for TypeScript callers.

Per-phase honor is the backend's choice and must be documented in its plan doc. When
the matrix evolves (e.g., a new cross-cutting field lands at the SDK layer), each
backend's per-phase Configs and Rust runtime checks must be updated in lockstep.

## 11. Plug-in guide for new backends

A backend author adding a new state-aware backend (or extending an existing ephemeral
backend with state-aware support) follows this workflow. The §7.4 worked example
illustrates the end-to-end shape; the steps below are the operational checklist.

### 11.1 Decide the participation mode

Pick one of the three modes from §4: ephemeral-only, state-aware-only, or both.

### 11.2 Implement the trait

The `StatefulSandboxBackend` trait signatures are in §9.2. Declare:

- `const ID_PREFIX: &'static str` — the leading `<tag>:` segment for this backend's
  `sandbox_id` values; also used by the dispatcher for non-provision routing (§5).
- `const BACKEND_KEY: &'static str` — the wire-format `containment` value for this
  backend, matching the SDK's `StateAwareContainmentBackend` member name (e.g.,
  `"isolation_session"`). Used by the dispatcher to navigate
  `experimental.<BACKEND_KEY>.<phase>` for typed-config deserialisation and to resolve
  `provision`-phase requests (§5).
- Per-phase config associated types (`ProvisionConfig`, ..., `DeprovisionConfig`).
- Per-phase metadata associated types (`ProvisionMetadata`, ..., `DeprovisionMetadata`).
  Use `()` for any associated type the backend does not need.

Implement `exec` — the only required method. Override `provision`, `start`, `stop`, or
`deprovision` only when the backend has substantive work to do in that phase; the trait
provides default no-op bodies otherwise. The default `provision` mints a synthetic
`sandbox_id` of the form `<ID_PREFIX>:<random-token>`; backends with native provision
(allocating a session, registering with the underlying service) override and produce
their own structured id.

Override `validate_<phase>` hooks for backend-specific pre-execution checks (config
field semantics, policy honor enforcement, id format verification beyond prefix
matching). Defaults are no-ops; only override the phases the backend has checks for.
Validation runs before the phase method; failures short-circuit and surface as typed
`MxcError` codes without invoking the backend.

### 11.3 Define typed `*Config` interfaces in the SDK

For each of the five lifecycle phases, add a typed TypeScript interface to
`@microsoft/mxc-sdk`. Each Config carries only the fields valid for that backend at
that phase: `version?` always, the cross-cutting `filesystem` / `network` / `ui`
fields in the phases where the backend honors them (§10.3), and any backend-specific
fields. Phases with no backend-specific or cross-cutting fields declare a Config
carrying only `version?`. Example shape (mirroring §6.1):

```typescript
interface MyBackendProvisionConfig {
  version?: string;
  // cross-cutting fields for phases where MyBackend's matrix marks `applied`
}

interface MyBackendStartConfig {
  version?: string;
  // backend-specific start fields
}

// ... and similarly for exec, stop, deprovision
```

Add an arm to `ConfigsForBackend<C>` mapping the new backend's `ContainmentBackend`
member to its five phase Configs:

```typescript
type ConfigsForBackend<C extends StateAwareContainmentBackend> =
  C extends 'isolation_session' ? { /* IS phase Configs */ } :
  C extends 'my_backend' ? {
    provision: MyBackendProvisionConfig;
    start: MyBackendStartConfig;
    exec: MyBackendExecConfig;
    stop: MyBackendStopConfig;
    deprovision: MyBackendDeprovisionConfig;
  } : never;
```

If the backend was not previously SDK-exposed, also extend `ContainmentBackend` and add
an entry to `StateAwareContainmentBackend`.

### 11.4 Register in the `ContainmentBackend` enum

The dispatch layer in the executor matches on `ContainmentBackend` to route calls. Add a
variant for the new backend along with a dispatch arm that invokes the trait method via
`dispatch_state_aware`. The trait impl declares both `ID_PREFIX` and `BACKEND_KEY` (§5);
`ID_PREFIX` is the routing key for non-provision calls (so pick a short distinct tag
and treat it as permanent — persisted ids carry it), and `BACKEND_KEY` is the
wire-format containment value used for `provision`-phase routing and
`experimental.<BACKEND_KEY>.<phase>` deserialisation. Compile-time errors will catch
capability mismatches automatically (§9.4).

### 11.5 Add a config-parser case

The state-aware wire format expects `experimental.<backend>.<phase>` blocks for backends
that declare per-phase configs. Add typed fields to the `experimental` block of the wire
model (`wire.rs`) for the new backend's JSON shape, then regenerate the schema. Add a
converter that produces the typed domain models the dispatch layer consumes.

### 11.6 Document the backend

A per-backend document at `docs/<backend-or-feature>/<plan-name>.md` is required (e.g.,
`docs/isolation-session/state-aware-plan.md` for IsolationSession's state-aware support
— mirroring the directory pattern used elsewhere in MXC docs). It must cover:

- **Per-phase config shapes.** The fields of each `*Config` interface, with allowed
  values and defaults.
- **Per-phase metadata shapes.** The fields of each `*Metadata` interface returned by
  the backend (any subset of provision, start, stop, deprovision). Phases that return
  no metadata are omitted from the bundle.
- **Cross-cutting policy honor matrix.** For each cross-cutting field (`filesystem`,
  `network`, `ui`), which phases the backend applies, rejects, or ignores it at.
  Per §10.3.
- **Mode-specific fields.** For backends participating in both ephemeral and state-aware
  modes: which fields are valid in each mode. Fields whose only sensible state-aware
  value is fixed should be hardcoded inside the state-aware implementation rather than
  exposed in the config.
- **Idempotence behaviour per phase.** Whether double-stop returns success or
  `already_stopped`; whether double-provision creates a new resource or reuses one;
  what happens on deprovision-while-running.
- **Concurrency story.** Whether multiple `exec` calls against the same `sandboxId`
  may run simultaneously, or are serialised by the backend's underlying API.
- **Error mapping table.** Which native errors from the backend's underlying API map to
  which MXC error codes (§8). The catch-all `backend_error` is acceptable when no
  specific code fits, but the table should still describe what `details` contains in
  that case.

### 11.7 Add tests

Two categories:

- **Feature-unavailable test (CI-runnable).** The backend is exercised on a machine
  without its runtime dependency (no service, no daemon, no kernel feature). The
  expected result is a clean `backend_unavailable` error rather than a panic or hang.
- **Integration test on real infrastructure.** The full lifecycle (provision, start,
  exec, stop, deprovision) plus a few exec variants. May be runner-script-driven and
  manually triggered if CI cannot reach the required infrastructure.

### 11.8 Update `.github/copilot-instructions.md`

Per the existing MXC contribution process, the central reference list of backends and
key docs is updated for any backend addition or significant change.

## 12. Failure semantics

State-aware calls can fail at any phase. MXC does not impose a recovery mechanism;
recovery is the caller's responsibility. This section describes the typical sandbox
state after each phase fails, along with common recovery patterns.

### 12.1 Post-failure sandbox state by phase

| Phase failure | Sandbox state | Typical caller action |
|---|---|---|
| `provision` fails | No `sandboxId` was returned | Retry, or surface the failure |
| `start` fails | Sandbox is provisioned but not running | `deprovision` to clean up, or retry `start` |
| `exec` fails | Sandbox is running (the failure occurred during exec, not before) | Retry `exec`, or proceed to `stop` / `deprovision` |
| `stop` fails | Ambiguous: sandbox may be stopped, may still be running | Retry `stop`, or `deprovision` and accept potential resource leak from the backend's view |
| `deprovision` fails | Ambiguous: resource may still exist, may have been cleaned up | Treat as best-effort; the next call against the `sandboxId` will surface `stale_id` if the resource is gone |

The "ambiguous" entries are a consequence of MXC's stateless conduit model: MXC does not
track the sandbox's last-known state, so after a failure the caller and the backend may
disagree on what state the resource is in. A subsequent call resolves the ambiguity by
surfacing either success or `stale_id`.

### 12.2 Mid-call SDK process death

If the SDK consumer's process dies while a state-aware call is in flight, the executor
subprocess may still be running, and the backend's view of the resource depends on
whether the underlying API call completed before the process died. The sandbox state is
indeterminate.

Recovery uses the persisted `sandboxId`: on consumer restart, an attempt to
`deprovision` either succeeds (cleanup completes) or returns `stale_id` (resource
already gone). Either outcome leaves the caller in a known state. This pattern relies
on the consumer having persisted the `sandboxId` before the in-flight call began.

If `provision` itself dies mid-call, the `sandboxId` never reached the caller. Any
resource that was created is orphaned from the caller's perspective. Some backends
offer auto-reap policies tied to caller-process lifetime that can clean up such orphans
for ephemeral use; for state-aware use, where lifetimes are explicit and indefinite, an
operator-side cleanup tool (out of MXC's scope) is the explicit catch.

### 12.3 Best-effort recovery, not guaranteed

These patterns are best-effort, not transactional guarantees. The proposal does not
introduce two-phase commit, distributed locks, or other heavyweight recovery primitives
in MXC. Each backend's plan doc (§11.6) carries its specific recovery semantics.

## 13. Graduation path

The state-aware API surface (the five lifecycle phases, the wire-format envelope, the
error envelope, the trait) is stable from `0.6.0` onwards — it is not gated by an
`--experimental` flag. The only graduation axis is per-backend: whether a given
backend's state-aware participation, per-stage config shapes, and error mappings are
stable enough to rely on. A backend whose state-aware participation is still
experimental requires `experimental: true` on every state-aware call, just as one-shot
calls against experimental backends do today.

### 13.1 Wire-format placement rule

Per-stage config for backend X stays under `experimental.<backend>.<phase>` while
backend X's state-aware participation is experimental. When backend X's state-aware
participation graduates to stable, per-stage config migrates to top-level
`<backend>.<phase>`.

The `phase`-as-discriminator rule from §7.1 continues to apply post-graduation, just at
the top level: top-level `<backend>: { ... }` carries one-shot config when the call has
no `phase`, and top-level `<backend>: { provision: {...}, start: {...}, ... }` carries
per-phase configs when the call has `phase`. The two shapes do not coexist in a single
call.

### 13.2 Worked scenarios

A backend's ephemeral and state-aware paths graduate independently. The same backend
can have a stable ephemeral path and an experimental state-aware path simultaneously,
or vice versa — they are separate graduation events.

**Backend's ephemeral path graduates; state-aware path stays experimental.** The
backend's ephemeral one-shot config moves from `experimental.<backend>` to top-level
`<backend>`, following the existing one-shot graduation pattern. Its state-aware
per-stage configs stay under `experimental.<backend>.<phase>`.

**Backend's state-aware path graduates.** Per-stage configs migrate from
`experimental.<backend>.<phase>` to top-level `<backend>.<phase>`. The
`experimental: true` SDK option is no longer required for that backend's state-aware
calls (and the executor stops gating them behind `--experimental`). For example, a
`start` call against IsolationSession migrates from this shape:

```json
{
  "version": "0.6.0-alpha",
  "phase": "start",
  "sandboxId": "iso:reg-abc:prov-123",
  "experimental": {
    "isolation_session": {
      "start": { "configurationId": "small" }
    }
  }
}
```

to this shape after the backend's state-aware path graduates:

```json
{
  "version": "0.7.0-alpha",
  "phase": "start",
  "sandboxId": "iso:reg-abc:prov-123",
  "isolation_session": {
    "start": { "configurationId": "small" }
  }
}
```

### 13.3 Versioning

Each backend's graduation event (ephemeral, state-aware, or both at once) triggers a
schema version bump in `docs/versioning.md`, following the existing MXC convention for
graduating features. The version bump and the associated SDK type changes (such as
dropping `experimental: true` requirements for graduated containment values) ship as a
single release.

## 14. Out of scope for v1

The following items are explicitly deferred. Each has a brief rationale and a likely
path forward.

- **Detached or long-running execs.** A model where `exec` returns a process id and
  the spawned process outlives the SDK call. The JS-async fire-and-forget pattern
  (don't `await`
  `execInSandboxAsync`) IS supported via the existing functions — the spawned process
  is tethered to the SDK consumer's lifetime, but the caller can move on without
  awaiting. True OS-level detachment (process owned by the OS service, independent of any
  caller) needs a different SDK contract (e.g., a future `execInSandboxDetached`
  returning a process id, no waiting for exit). Deferred to a later version with that
  dedicated function.
- **Additional lifecycle stages** (snapshot, suspend, attach, restore). Backends with
  native support can expose them privately under
  `experimental.<backend>.<custom-stage>` until universalisation.
- **Cross-machine `SandboxId` portability.** Ids are opaque, but their interpretation
  is backend-local in v1. A portable format with explicit scope tags is separate work.
- **Container-wide timeouts enforced by MXC.** Tracking elapsed time across calls
  would require state. Backends impose their own timeout semantics through their
  underlying APIs.
- **Per-backend metadata for `exec`.** Provision, start, stop, and deprovision return
  per-phase typed `*Result<C>` with optional metadata (§6, §7). Exec does not — adding
  metadata to a live-streaming response requires an out-of-band channel (sidechannel
  file descriptor, sentinel-marked envelope appended after the script's stdout, or
  switching to fully buffered, which loses live-streaming). Defer until a backend has
  a concrete need.
