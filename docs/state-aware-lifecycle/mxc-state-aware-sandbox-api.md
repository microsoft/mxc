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
15. [Open questions for MXC team review](#15-open-questions-for-mxc-team-review)

## 1. Summary

This document proposes a state-aware sandbox API for MXC, surfaced alongside the existing
one-shot `spawnSandbox*` family. Five lifecycle phases are exposed at the SDK level:
provision, start, exec, stop, deprovision. Each is a discrete call. Provision returns an
opaque `SandboxId` string the caller persists and forwards to subsequent calls. Per-stage
configuration is typed per-backend per-phase under `experimental.<backend>.<phase>`;
placement promotes to top-level once both the API and the backend's participation are
stable. Backends opt in by implementing a new `StatefulSandboxBackend` Rust trait. The
existing `ScriptRunner` trait is unchanged. A backend's participation mode (state-aware,
ephemeral, or both) is declared by which trait or traits it implements.

The mental model: `spawnSandbox` is the composition of the five phases into one call.
State-aware exposes them individually so callers can hold a sandbox between calls, run
multiple workloads inside it, and tear it down explicitly.

Sandbox state is owned by the backend (e.g., IsoEnvBroker for IsolationSession). The
`SandboxId` is the only handle the caller gets; persisting it between calls is the
caller's responsibility. MXC retains no state between calls and does not become a sandbox
orchestrator. Backends with no meaningful state continue to expose only the one-shot
surface; state-aware participation is fully opt-in.

The proposal adds artefacts at five layers of MXC. Each row points into the section that
elaborates.

| MXC layer | What's new | What's unchanged |
|---|---|---|
| TypeScript SDK (§6) | Five new functions: `provisionSandbox`, `startSandbox`, `execInSandbox` / `execInSandboxAsync`, `stopSandbox`, `deprovisionSandbox`. Branded `SandboxId` type. Per-phase typed `*Config` types per backend. Per-phase typed `*Result` types per backend. `AbortSignal` cancellation. Typed exception classes per error code. | `spawnSandbox` family preserved. `SandboxPolicy` reused as the cross-cutting policy across both surfaces. `SandboxingMethod` extension mechanism reused. Existing typed `*Config` naming convention reused. |
| JSON wire format (§7) | Top-level `phase` discriminator. Top-level `sandboxId`. Per-phase nesting under `experimental.<backend>.<phase>`. Named envelope types as a TypeScript discriminated union over `phase`. | One-shot configs (no `phase`) work unchanged. Cross-cutting `filesystem` / `network` / `ui` fields at top level for state-aware too — backends declare per-phase honor. |
| Rust executor (§9) | Dispatch arm for state-aware. New `StatefulSandboxBackend` trait. Rust mirror of the wire envelope (private to parser, matching `RawConfig` pattern). | `ScriptRunner` trait. Existing one-shot dispatch path. Existing backends function without modification. |
| Error model (§8) | Closed enum of 12 error codes. `MxcError` base + per-code subclasses. `details` open object as escape hatch for backend-specific structured information. | Existing one-shot error paths preserved. |
| Plug-in surface (§11) | Implement `StatefulSandboxBackend` (in addition to or instead of `ScriptRunner`). Define typed per-phase `*Config` interfaces. Document the cross-cutting policy honor matrix. | Ephemeral-only backends require no changes. The `ContainmentBackend` Rust enum is extended, not replaced. |

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
  of a stateful sandbox belongs to the backend's API surface (IsoEnvBroker, in the
  IsolationSession case); persisting it across calls is the caller's responsibility.
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
fields, branded `SandboxId` type, typed `*Config` shape). The MXC dispatch layer
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

Every stateful backend implements all five phases. A backend whose underlying API has
no meaningful equivalent for a particular phase implements that phase as a no-op (returns
success without side effects). The backend's documentation states which phases are
no-ops. The MXC dispatch layer treats substantive and no-op implementations identically;
SDK signatures do not differentiate them.

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
(TS SDK, JSON wire format, CLI output); its internal structure is the backend's concern.

The backend generates the `SandboxId` during `provision`. A backend whose underlying API
requires caller-supplied identifiers (e.g., IsoEnvBroker, which uses registration and
provisioning IDs) mints them inside the backend implementation and encodes them into the
id string. A backend whose underlying API generates identifiers itself (Docker, future
Hyper-V) captures the generated value and encodes it. The encoding is opaque to MXC.

Each backend is recommended to prefix its ids with a backend-specific tag (e.g.,
`iso:...` for IsolationSession, `docker:...` for a future Docker backend). This makes
mismatch detection cheap: an id from one backend accidentally passed to another fails
deserialisation on the receiving backend rather than producing a confusing
"resource-not-found" error. The convention is recommended, not mandatory.

The SDK exposes the id as a branded TypeScript string:

```typescript
type SandboxId = string & { readonly __mxcBrand: 'SandboxId' };
```

The runtime value is a plain string. The brand exists at compile time only and prevents
callers from accidentally passing other strings (a `containerId`, a path, a literal) where
a `SandboxId` is expected.

Persisting the id between calls is the caller's responsibility. The caller chooses the
storage mechanism. MXC neither tracks the id after `provision` returns nor verifies its
validity until the caller passes it back. If an id refers to a resource that no longer
exists, the next call returns `error.code: "stale_id"` (§8); the caller decides whether
to re-provision or treat the failure terminally.

**Disambiguation: `sandboxId` vs `containerId`.** Two different identifiers exist on the
wire format and have different roles:

| Field | Where it appears | Source | Purpose |
|---|---|---|---|
| `sandboxId` | State-aware wire envelope (§7); SDK return value from `provisionSandbox` | System-generated by the backend | Opaque routing identifier; must be passed to subsequent state-aware calls |
| `containerId` | One-shot wire envelope (per `docs/config-schema.md`) | Caller-supplied (or auto-generated random hex) | Human-readable label, used as e.g. AppContainer profile name |

State-aware calls always carry `sandboxId` (returned from provision, passed to the rest);
they do not carry `containerId`. One-shot calls carry `containerId` (when present); they
do not carry `sandboxId`.

## 6. TypeScript SDK

The SDK adds five new functions, exported from `@microsoft/mxc-sdk` alongside the existing
one-shot entry points. Each function corresponds to a lifecycle phase from §4.

### 6.1 Type definitions

```typescript
type SandboxId = string & { readonly __mxcBrand: 'SandboxId' };

type Phase = 'provision' | 'start' | 'exec' | 'stop' | 'deprovision';

type StateAwareSandboxingMethod = Extract<SandboxingMethod, 'isolation_session'>;
// extended as state-aware-capable backends are added

interface ExperimentalStateAwareConfigs {
  isolation_session?: IsolationSessionStateAwareConfigs;
  // future state-aware-capable backends add typed entries here
}

interface IsolationSessionStateAwareConfigs {
  start?: IsolationSessionStartConfig;
  // provision, exec, stop, deprovision omitted — IsolationSession has no per-phase
  // config for those phases. Other backends may include any subset.
}

interface IsolationSessionStartConfig {
  configurationId?: 'small' | 'medium' | 'large' | 'commandLine';
}

interface IsolationSessionProvisionMetadata {
  agentUserName: string;
}

// Per-phase config lookup helpers used by the SDK function options:
type ConfigsForBackend<C extends StateAwareSandboxingMethod> =
  NonNullable<ExperimentalStateAwareConfigs[C]>;

type ProvisionConfigFor<C extends StateAwareSandboxingMethod> =
  'provision' extends keyof ConfigsForBackend<C>
    ? ConfigsForBackend<C>['provision']
    : undefined;
type StartConfigFor<C extends StateAwareSandboxingMethod> =
  'start' extends keyof ConfigsForBackend<C>
    ? ConfigsForBackend<C>['start']
    : undefined;
type ExecConfigFor<C extends StateAwareSandboxingMethod> =
  'exec' extends keyof ConfigsForBackend<C>
    ? ConfigsForBackend<C>['exec']
    : undefined;
type StopConfigFor<C extends StateAwareSandboxingMethod> =
  'stop' extends keyof ConfigsForBackend<C>
    ? ConfigsForBackend<C>['stop']
    : undefined;
type DeprovisionConfigFor<C extends StateAwareSandboxingMethod> =
  'deprovision' extends keyof ConfigsForBackend<C>
    ? ConfigsForBackend<C>['deprovision']
    : undefined;

// Per-backend metadata bundle (analogous to ExperimentalStateAwareConfigs but for
// per-phase return values). Backends omit phases that return no metadata.
interface ExperimentalStateAwareMetadata {
  isolation_session?: {
    provision?: IsolationSessionProvisionMetadata;
    // IsolationSession returns no metadata for start, stop, deprovision
  };
  // future state-aware-capable backends add typed entries here
}

type ProvisionMetadataFor<C extends StateAwareSandboxingMethod> =
  'provision' extends keyof NonNullable<ExperimentalStateAwareMetadata[C]>
    ? NonNullable<ExperimentalStateAwareMetadata[C]>['provision']
    : undefined;
type StartMetadataFor<C extends StateAwareSandboxingMethod> =
  'start' extends keyof NonNullable<ExperimentalStateAwareMetadata[C]>
    ? NonNullable<ExperimentalStateAwareMetadata[C]>['start']
    : undefined;
type StopMetadataFor<C extends StateAwareSandboxingMethod> =
  'stop' extends keyof NonNullable<ExperimentalStateAwareMetadata[C]>
    ? NonNullable<ExperimentalStateAwareMetadata[C]>['stop']
    : undefined;
type DeprovisionMetadataFor<C extends StateAwareSandboxingMethod> =
  'deprovision' extends keyof NonNullable<ExperimentalStateAwareMetadata[C]>
    ? NonNullable<ExperimentalStateAwareMetadata[C]>['deprovision']
    : undefined;

interface ProvisionResult<C extends StateAwareSandboxingMethod> {
  sandboxId: SandboxId;
  metadata?: ProvisionMetadataFor<C>;
}

interface StartResult<C extends StateAwareSandboxingMethod> {
  metadata?: StartMetadataFor<C>;
}

interface StopResult<C extends StateAwareSandboxingMethod> {
  metadata?: StopMetadataFor<C>;
}

interface DeprovisionResult<C extends StateAwareSandboxingMethod> {
  metadata?: DeprovisionMetadataFor<C>;
}

interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

// Per-phase options interfaces. All carry the cross-cutting `policy: SandboxPolicy`
// (single source of truth, shared with one-shot), the per-phase backend `config`
// (typed per backend), and an optional `signal` for cancellation.
interface ProvisionSandboxOptions<C extends StateAwareSandboxingMethod> {
  policy?: SandboxPolicy;
  config?: ProvisionConfigFor<C>;
  signal?: AbortSignal;
}

interface StartSandboxOptions<C extends StateAwareSandboxingMethod> {
  policy?: SandboxPolicy;
  config?: StartConfigFor<C>;
  signal?: AbortSignal;
}

interface ExecInSandboxOptions<C extends StateAwareSandboxingMethod> {
  policy?: SandboxPolicy;
  config?: ExecConfigFor<C>;
  signal?: AbortSignal;
}

interface StopSandboxOptions<C extends StateAwareSandboxingMethod> {
  policy?: SandboxPolicy;
  config?: StopConfigFor<C>;
  signal?: AbortSignal;
}

interface DeprovisionSandboxOptions<C extends StateAwareSandboxingMethod> {
  policy?: SandboxPolicy;
  config?: DeprovisionConfigFor<C>;
  signal?: AbortSignal;
}
```

`SandboxPolicy` is the existing cross-platform policy type from `sdk/src/types.ts`,
reused unchanged. `ProcessConfig` is the existing per-process settings type
(`commandLine`, `cwd`, `env`, `timeout`), also reused.

When a backend declares no config for a particular phase, the corresponding helper type
resolves to `undefined`. TypeScript then refuses to accept any non-`undefined` value for
that phase's `config` field — callers can't accidentally pass start config to a backend
that has no start config. The same machinery applies on the return side: when a backend
declares no metadata for a phase, `<Phase>MetadataFor<C>` resolves to `undefined` and
the corresponding `*Result<C>` is structurally empty (its `metadata` field is statically
undefined).

### 6.2 Method signatures

```typescript
function provisionSandbox<C extends StateAwareSandboxingMethod>(
  containment: C,
  options?: ProvisionSandboxOptions<C>,
): Promise<ProvisionResult<C>>;

function startSandbox<C extends StateAwareSandboxingMethod>(
  containment: C,
  sandboxId: SandboxId,
  options?: StartSandboxOptions<C>,
): Promise<StartResult<C>>;

function execInSandbox<C extends StateAwareSandboxingMethod>(
  containment: C,
  sandboxId: SandboxId,
  process: ProcessConfig,
  options?: ExecInSandboxOptions<C>,
): pty.IPty;

function execInSandboxAsync<C extends StateAwareSandboxingMethod>(
  containment: C,
  sandboxId: SandboxId,
  process: ProcessConfig,
  options?: ExecInSandboxOptions<C>,
): Promise<ExecResult>;

function stopSandbox<C extends StateAwareSandboxingMethod>(
  containment: C,
  sandboxId: SandboxId,
  options?: StopSandboxOptions<C>,
): Promise<StopResult<C>>;

function deprovisionSandbox<C extends StateAwareSandboxingMethod>(
  containment: C,
  sandboxId: SandboxId,
  options?: DeprovisionSandboxOptions<C>,
): Promise<DeprovisionResult<C>>;
```

`execInSandbox` returns an `IPty` for live streaming (caller subscribes to `onData` /
`onExit`); `execInSandboxAsync` is a buffered convenience that accumulates output and
resolves on exit. This mirrors the existing `spawnSandbox` (returns `IPty`) /
`spawnSandboxAsync` (returns Promise) split.

The `containment` parameter appears on every call. Every JSON payload carries its own
`containment` so the dispatch layer can route without context from prior calls.

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
  SandboxPolicy,
} from '@microsoft/mxc-sdk';

const tools = getAvailableToolsPolicy();
const policy: SandboxPolicy = {
  version: '0.5.0-alpha',
  filesystem: {
    readwritePaths: ['C:\\workspace'],
    readonlyPaths: tools.readonlyPaths,
  },
  network: { allowOutbound: true, allowedHosts: ['api.anthropic.com'] },
};

// Provision — caller passes cross-cutting policy; IsolationSession honors it at this
// phase per its documented matrix (§10.3).
const { sandboxId } = await provisionSandbox('isolation_session', { policy });

// Start — backend-specific config picks the session size.
await startSandbox('isolation_session', sandboxId, {
  config: { configurationId: 'small' },
});

// Exec — buffered convenience for short workloads.
const result = await execInSandboxAsync('isolation_session', sandboxId, {
  commandLine: 'echo hello',
  timeout: 5000,
});
console.log(result.stdout);  // "hello\n"

// Exec — streaming for long-running workloads. Returns IPty.
const session = execInSandbox('isolation_session', sandboxId, {
  commandLine: 'C:\\workspace\\agent.exe --watch',
});
session.onData((chunk) => process.stdout.write(chunk));
session.onExit(({ exitCode }) => console.log(`agent exit: ${exitCode}`));

// Stop and deprovision when done.
await stopSandbox('isolation_session', sandboxId);
await deprovisionSandbox('isolation_session', sandboxId);
```

### 6.4 Composition with the one-shot surface

`spawnSandbox` is the composition of the five state-aware phases run end-to-end. The two
surfaces share `SandboxPolicy` and `SandboxingMethod`; they differ in granularity. A
backend that participates in both modes can be invoked through either surface; a backend
that participates in only one returns `unsupported_phase` from the other (§8).

State-aware-capable backends extend `SandboxingMethod` and `StateAwareSandboxingMethod`
the same way ephemeral backends extend `SandboxingMethod`. Cancellation via
`AbortSignal` is supported on all state-aware methods. Detached / fire-and-forget exec
(process outliving the SDK call) is deferred to v2 (§14).

### 6.5 Policy discovery

The existing policy-discovery helpers (`getAvailableToolsPolicy`,
`getUserProfilePolicy`, `getTemporaryFilesPolicy`) compose with state-aware functions
unchanged. They produce `FilesystemPolicyResult` fragments that callers merge into
`SandboxPolicy.filesystem` (as in the §6.3 example), then pass via the `policy` field.

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
  containment: SandboxingMethod;
  containerId?: string;
  process: ProcessConfig;
  filesystem?: FilesystemConfig;
  network?: NetworkConfig;
  ui?: UiConfig;
  lifecycle?: LifecycleConfig;
  appContainer?: AppContainerConfig;
  lxc?: LxcConfig;
  experimental?: ExperimentalOneShotConfigs;     // existing one-shot shape per docs/config-schema.md
}

interface StateAwareRequest {
  phase: Phase;                                   // discriminator: present
  version?: string;
  containment: StateAwareSandboxingMethod;
  sandboxId?: SandboxId;                          // required for non-provision phases
  process?: ProcessConfig;                        // exec only
  filesystem?: FilesystemConfig;                  // backend declares per-phase honor
  network?: NetworkConfig;                        // backend declares per-phase honor
  ui?: UiConfig;                                  // backend declares per-phase honor
  experimental?: ExperimentalStateAwareConfigs;
}

type MxcRequest = OneShotRequest | StateAwareRequest;
```

The wire format is the JSON serialisation of an `MxcRequest` value. There is no
"stringified blob" anywhere in the contract; everything except `ErrorEnvelope.details` is
statically typed.

Top-level fields shared by both branches:

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | string | No | Schema version (semver). |
| `containment` | `SandboxingMethod` member | Yes | Backend selection. |
| `experimental` | object | No | Backend-specific config block. Shape depends on `phase` (§7.2). |

State-aware-only fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `phase` | `Phase` member | Yes | Discriminator. Absence means a one-shot request. |
| `sandboxId` | branded string | Required for `start` / `exec` / `stop` / `deprovision`; absent on `provision`. | Opaque sandbox id returned by `provision`. |
| `process` | `ProcessConfig` | Required for `exec`; absent otherwise. | Cross-backend execution fields. |

Cross-cutting fields available to state-aware (state-aware-only at top level — backends
declare which phases honor them, see §10.3):

| Field | Type | Description |
|---|---|---|
| `filesystem` | `FilesystemConfig` | Filesystem access policy. |
| `network` | `NetworkConfig` | Network access policy. |
| `ui` | `UiConfig` | UI access policy. |

One-shot-only fields (`containerId`, `lifecycle`, `appContainer`, `lxc`) are not
enumerated here; their definitions live in `docs/config-schema.md`.

### 7.2 The `experimental` block

`ExperimentalStateAwareConfigs` is a typed bundle. Outer keys are state-aware-capable
backend names (members of `StateAwareSandboxingMethod`); inner per-backend bundles
enumerate the phases that backend declares config for. Each phase's value is a typed
`<Backend><Phase>Config` interface defined alongside the backend in the SDK package.

| Layer | Type | Constraint |
|---|---|---|
| Outer key | `StateAwareSandboxingMethod` member | Must be a state-aware-capable backend |
| Inner key (state-aware only) | A subset of `Phase` per backend's needs | Backends omit phases with no config |
| Innermost value | Typed `<Backend><Phase>Config` interface | Defined alongside the backend in the SDK |

Backends that declare no config for a phase omit the field from their bundle; TypeScript
then refuses to accept a config for that phase from callers. Backends that declare config
for a phase get full compile-time autocompletion on the field shape.

For one-shot calls (phase absent), `experimental.<backend>` directly holds the backend's
one-shot config object (e.g., `experimental.wslc?: WslcConfig`), as documented in
`docs/config-schema.md`. The TypeScript types make this distinction structural:
`OneShotRequest.experimental` and `StateAwareRequest.experimental` have different shapes.

### 7.3 Response convention

The response convention is phase-aware.

**Non-exec phases** (provision / start / stop / deprovision): the executor emits a single
JSON envelope on stdout, then exits with 0 on success or non-zero on failure.

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
| `provision` | `{ sandboxId: SandboxId; metadata?: object }` |
| `start` | `{ metadata?: object }` |
| `stop` | `{ metadata?: object }` |
| `deprovision` | `{ metadata?: object }` |

**Exec phase, dispatch succeeded**: the script's stdout/stderr stream live, matching
ProcessContainer's existing behaviour. The executor's stdout/stderr inherit through to
the SDK (PTY by default; piped via `child_process` in non-PTY mode). Process exit code is
the script's exit code. No JSON envelope is emitted in this case — the SDK constructs
`{ stdout, stderr, exitCode }` from PTY/process events, exactly as `spawnSandboxAsync`
does.

**Exec phase, dispatch failed**: the executor emits a JSON envelope on stdout (same shape
as non-exec phases) and exits non-zero. No script ever runs, so stdout otherwise is empty
and the envelope is unambiguous.

The SDK distinguishes for exec by inspecting stdout: if exit is non-zero AND stdout's
entire content parses as a complete `{ error: { ... } }` envelope, treat it as a typed
dispatch error; otherwise it's a script failure and the SDK reports `exitCode` directly.

`ErrorEnvelope.details` is the only `Record<string, unknown>` in the contract. It's the
escape hatch backends use to convey structured failure information that's
genuinely-per-error-code (a backend's native HRESULT, partial output captured before a
timeout, etc.). Each backend's plan doc (§11) specifies what `details` contains for which
error codes.

### 7.4 Worked example: IsolationSession end-to-end

A complete state-aware lifecycle, threading TS call → JSON the SDK serialises and passes
to the executor via `--config-base64` → Rust trait method that dispatches → response
shape, across all five phases.

#### Phase 1 — provision

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
  "version": "0.5.0-alpha",
  "containment": "isolation_session",
  "phase": "provision",
  "filesystem": { "readwritePaths": ["C:\\workspace"] },
  "network": { "defaultPolicy": "allow", "allowedHosts": ["api.anthropic.com"] }
}
```

```rust
backend.provision(Some(&policy), None)
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
await startSandbox('isolation_session', sandboxId, {
  config: { configurationId: 'small' },
});
```

```json
{
  "version": "0.5.0-alpha",
  "containment": "isolation_session",
  "phase": "start",
  "sandboxId": "iso:reg-abc:prov-123",
  "experimental": { "isolation_session": { "start": { "configurationId": "small" } } }
}
```

```rust
backend.start("iso:reg-abc:prov-123", None, Some(&IsolationSessionStartConfig {
    configuration_id: IsolationSessionConfigurationId::Small,
}))
// returns Ok(StartResult { metadata: None })
```

```json
{ "result": {} }
```

#### Phase 3 — exec (buffered)

```typescript
const r = await execInSandboxAsync('isolation_session', sandboxId, {
  commandLine: 'echo hello',
  timeout: 5000,
});
// r = { stdout: "hello\n", stderr: "", exitCode: 0 }
```

```json
{
  "version": "0.5.0-alpha",
  "containment": "isolation_session",
  "phase": "exec",
  "sandboxId": "iso:reg-abc:prov-123",
  "process": { "commandLine": "echo hello", "timeout": 5000 }
}
```

```rust
backend.exec("iso:reg-abc:prov-123", None, None, &ProcessConfig {
    command_line: "echo hello".into(),
    timeout: Some(5000),
    ..Default::default()
})
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
await stopSandbox('isolation_session', sandboxId);
```

```json
{
  "version": "0.5.0-alpha",
  "containment": "isolation_session",
  "phase": "stop",
  "sandboxId": "iso:reg-abc:prov-123"
}
```

```rust
backend.stop("iso:reg-abc:prov-123", None, None)
// returns Ok(StopResult { metadata: None })
```

```json
{ "result": {} }
```

#### Phase 5 — deprovision

```typescript
await deprovisionSandbox('isolation_session', sandboxId);
```

```json
{
  "version": "0.5.0-alpha",
  "containment": "isolation_session",
  "phase": "deprovision",
  "sandboxId": "iso:reg-abc:prov-123"
}
```

```rust
backend.deprovision("iso:reg-abc:prov-123", None, None)
// returns Ok(DeprovisionResult { metadata: None })
```

```json
{ "result": {} }
```

#### Mapping summary

The SDK auto-wraps backend-specific config under `experimental.<backend>.<phase>` when
serialising state-aware calls. `SandboxPolicy.filesystem` / `.network` / `.ui` map to
top-level wire fields via the same logic the existing `createConfigFromPolicy` uses for
one-shot. Cross-backend exec fields (`commandLine`, `cwd`, `env`, `timeout`) flow through
the top-level `process` block, not through `experimental`. For non-exec phases the
executor emits a single JSON envelope on stdout; for exec the script's output streams
raw and the SDK constructs the result from PTY events. Responses unwrap any `result`
envelope at the SDK boundary so the caller sees a plain `ProvisionResult` / `StartResult` /
`ExecResult` / `StopResult` / `DeprovisionResult`.

## 8. Error model

Errors crossing the wire-format boundary are typed by a closed enum of error codes
defined at the MXC layer. Backends map their native errors to these codes; the SDK maps
each code to a typed TypeScript exception class. An `MxcStaleIdError` thrown from
IsolationSession behaves the same as one thrown from any other state-aware backend, so
caller error-handling code is portable across backends.

### 8.1 Error code enum

| Code | Meaning |
|---|---|
| `malformed_request` | Envelope-level error: missing required field, unknown phase, malformed JSON |
| `unsupported_containment` | The `containment` value is not a recognised backend |
| `unsupported_phase` | The backend does not support the requested call mode (state-aware call against an ephemeral-only backend, or one-shot call against a state-aware-only backend) |
| `backend_unavailable` | The backend's runtime dependency is missing or unreachable (broker not running, daemon stopped) |
| `malformed_id` | The `sandboxId` does not deserialise into the backend's native form |
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

### 8.3 TypeScript exception classes

The SDK throws (rejects) typed exception classes, one per error code, all extending a
common base:

```typescript
class MxcError extends Error {
  readonly code: ErrorCode;
  readonly details?: Record<string, unknown>;
}

// Per-code subclasses, named by converting the snake_case code to PascalCase with
// 'Mxc' prefix; the class name ends with 'Error'. If the code already ends with
// '_error' (i.e., `backend_error`), the existing suffix is preserved (so the class
// is `MxcBackendError`, not `MxcBackendErrorError`):
class MxcStaleIdError extends MxcError { /* code = 'stale_id' */ }
class MxcPolicyValidationError extends MxcError { /* code = 'policy_validation' */ }
class MxcBackendError extends MxcError { /* code = 'backend_error' */ }
```

Callers can pattern-match either via `instanceof` on the typed class or by inspecting
`error.code` directly. Both forms are supported; the typed-class form is generally
preferred in TypeScript code.

## 9. Rust layer architecture

The Rust layer adds a new `StatefulSandboxBackend` trait alongside the existing
`ScriptRunner` trait. Each backend implementation in the workspace is a struct that
implements one trait, the other, or both, depending on its declared participation mode
(§4).

### 9.1 Wire envelope (Rust mirror)

MXC's existing parser at `src/wxc_common/src/config_parser.rs` uses private `Raw*`
intermediate structs that mirror the wire-format JSON shape (with serde renames to handle
camelCase keys), then converts them into typed domain models via `convert_*` helpers
(e.g., `RawConfig` → `CodexRequest`) before dispatch. The state-aware path extends this
same pattern.

```rust
// In config_parser.rs — private to the parser, alongside the existing Raw* structs.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawMxcRequest {
    StateAware(RawStateAwareRequest),
    OneShot(RawConfig),
}

#[derive(Deserialize)]
struct RawStateAwareRequest {
    version: Option<String>,
    containment: Option<String>,
    phase: String,
    #[serde(rename = "sandboxId")]
    sandbox_id: Option<String>,
    process: Option<RawProcess>,
    filesystem: Option<RawFilesystem>,
    network: Option<RawNetwork>,
    ui: Option<RawUi>,
    experimental: Option<RawStateAwareExperimental>,
}

#[derive(Deserialize)]
struct RawStateAwareExperimental {
    #[serde(rename = "isolation_session")]
    isolation_session: Option<RawIsolationSessionConfigs>,
    // future state-aware-capable backends add typed entries here
}

#[derive(Deserialize)]
struct RawIsolationSessionConfigs {
    start: Option<RawIsolationSessionStartConfig>,
    // omit phases without config
}
```

Discrimination is by presence of the `phase` field. With `#[serde(untagged)]`, serde
attempts each variant in order; the state-aware variant requires `phase`, so its absence
falls through to the one-shot branch.

Conversion from `Raw*` into typed domain models happens in `convert_*` helpers analogous
to the existing `convert_raw_config` → `CodexRequest`. Domain models are exposed to the
dispatch layer; the `Raw*` types stay private to the parser.

### 9.2 The trait

Backends implement the trait with associated types for each phase's config and for
each phase's return metadata. Use `()` for any associated type the backend does not
need.

```rust
pub trait StatefulSandboxBackend {
    type ProvisionConfig: serde::de::DeserializeOwned;
    type StartConfig: serde::de::DeserializeOwned;
    type ExecConfig: serde::de::DeserializeOwned;
    type StopConfig: serde::de::DeserializeOwned;
    type DeprovisionConfig: serde::de::DeserializeOwned;
    type ProvisionMetadata: serde::Serialize;
    type StartMetadata: serde::Serialize;
    type StopMetadata: serde::Serialize;
    type DeprovisionMetadata: serde::Serialize;

    fn provision(
        &mut self,
        policy: Option<&SandboxPolicy>,
        config: Option<&Self::ProvisionConfig>,
    ) -> Result<ProvisionResult<Self::ProvisionMetadata>, MxcError>;

    fn start(
        &mut self,
        sandbox_id: &str,
        policy: Option<&SandboxPolicy>,
        config: Option<&Self::StartConfig>,
    ) -> Result<StartResult<Self::StartMetadata>, MxcError>;

    fn exec(
        &mut self,
        sandbox_id: &str,
        policy: Option<&SandboxPolicy>,
        config: Option<&Self::ExecConfig>,
        process: &ProcessConfig,
    ) -> Result<ExecHandle, MxcError>;

    fn stop(
        &mut self,
        sandbox_id: &str,
        policy: Option<&SandboxPolicy>,
        config: Option<&Self::StopConfig>,
    ) -> Result<StopResult<Self::StopMetadata>, MxcError>;

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        policy: Option<&SandboxPolicy>,
        config: Option<&Self::DeprovisionConfig>,
    ) -> Result<DeprovisionResult<Self::DeprovisionMetadata>, MxcError>;
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

`SandboxPolicy` is the typed Rust equivalent of the SDK type from `sdk/src/types.ts`,
with serde renames to camelCase. `ProcessConfig` and `MxcError` are similarly typed.
`PipeHandle` is a platform-abstracted pipe-handle wrapper — a kernel `HANDLE` on Windows,
a file descriptor on Linux. `ExecHandle` exposes the running process's pipe handles for
relay; the executor's outer driver reads from `stdout`/`stderr` and writes to `stdin`,
awaits exit via `waiter`, and calls `terminator` on cancellation signals.

Methods take `&mut self`, matching the existing `ScriptRunner::run` signature. Backends
do not need to accumulate state between calls within a backend instance — within a
single call a backend may use mutability to hold open broker connections, but no state
needs to survive across phase calls.

### 9.3 Dispatch

```rust
/// Dispatch outcome. Distinguishes structured-envelope responses (non-exec phases or
/// dispatch failure) from exec success (where stdio has already streamed live through
/// the relay).
enum DispatchOutcome {
    Envelope(ResponseEnvelope),
    ExecCompleted { exit_code: i32 },
}

fn run(req: MxcRequest) -> Result<DispatchOutcome, MxcError> {
    match req {
        MxcRequest::OneShot(r) => Ok(DispatchOutcome::Envelope(run_one_shot(r))),

        MxcRequest::StateAware(r) => match r.containment {
            ContainmentBackend::IsolationSession => {
                let mut backend = IsolationSessionRunner::new();
                dispatch_state_aware::<IsolationSessionRunner>(&mut backend, r)
            }
            // additional state-aware backends added here
            _ => Err(MxcError::UnsupportedPhase),
        },
    }
}

fn dispatch_state_aware<B: StatefulSandboxBackend>(
    backend: &mut B,
    req: StateAwareRequest,
) -> Result<DispatchOutcome, MxcError> {
    let policy = req.policy.as_ref();

    match req.phase {
        Phase::Provision => {
            let config = req.deserialize_provision_config::<B::ProvisionConfig>()?;
            let result = backend.provision(policy, config.as_ref())?;
            Ok(DispatchOutcome::Envelope(provision_envelope(result)))
        }
        Phase::Start => {
            let id = req.require_sandbox_id()?;
            let config = req.deserialize_start_config::<B::StartConfig>()?;
            let result = backend.start(&id, policy, config.as_ref())?;
            Ok(DispatchOutcome::Envelope(start_envelope(result)))
        }
        Phase::Exec => {
            let id = req.require_sandbox_id()?;
            let process = req.require_process()?;
            let config = req.deserialize_exec_config::<B::ExecConfig>()?;
            let handle = backend.exec(&id, policy, config.as_ref(), &process)?;
            // relay_exec_to_stdio streams the script's pipes to the executor's
            // stdout/stderr/stdin live, awaits exit, and returns the script's exit code.
            let exit_code = relay_exec_to_stdio(handle)?;
            Ok(DispatchOutcome::ExecCompleted { exit_code })
        }
        Phase::Stop => {
            let id = req.require_sandbox_id()?;
            let config = req.deserialize_stop_config::<B::StopConfig>()?;
            let result = backend.stop(&id, policy, config.as_ref())?;
            Ok(DispatchOutcome::Envelope(stop_envelope(result)))
        }
        Phase::Deprovision => {
            let id = req.require_sandbox_id()?;
            let config = req.deserialize_deprovision_config::<B::DeprovisionConfig>()?;
            let result = backend.deprovision(&id, policy, config.as_ref())?;
            Ok(DispatchOutcome::Envelope(deprovision_envelope(result)))
        }
    }
}
```

Helper functions for handle-validation, config deserialisation, and envelope wrapping
are mechanical and elided. The executor's outer driver invokes `run` and handles each
outcome:

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
| SDK (TypeScript) | Recognised `containment` and `phase`; presence of `sandboxId` per phase; required cross-backend fields (`process.commandLine` for exec); typed config shape (autocompletion + compile-time check) | Thrown at the call site, before any subprocess runs |
| MXC dispatch (Rust, in the executor) | Re-validates envelope; verifies the backend supports the requested phase; deserialises typed configs from JSON | `error.code: malformed_request`, `unsupported_phase`, `unsupported_containment`, `backend_unavailable`, `policy_validation` (config shape) |
| Backend implementation | Validates config field values against backend-specific rules; deserialises `sandboxId` into the backend's native form; honors cross-cutting policy per backend's matrix (§10.3) | `error.code: policy_validation` (semantic), `malformed_id`, `stale_id`, `backend_error` |

Each layer validates only what it cheaply can. The SDK's typed config catches structural
errors at compile time. The dispatch layer catches structural errors that escaped the
SDK (e.g., from non-TypeScript callers). The backend catches semantic errors that depend
on runtime state (e.g., "the configuration ID is recognised but not allowed for this
agent user").

### 10.2 Backend-side config typing

A typical state-aware backend defines its `*Config` types alongside the trait
implementation, in both Rust and TypeScript. The Rust types use `#[derive(Deserialize)]`
with serde renames to camelCase. The TypeScript types are exported from the SDK package
and slot into `ExperimentalStateAwareConfigs`.

```rust
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IsolationSessionStartConfig {
    pub configuration_id: IsolationSessionConfigurationId,
}
```

```typescript
interface IsolationSessionStartConfig {
  configurationId?: 'small' | 'medium' | 'large' | 'commandLine';
}
```

The wire JSON is `{ "configurationId": "small" }` either way. The SDK and dispatch layer
agree on shape; the backend gets a typed Rust struct ready for use.

### 10.3 Cross-cutting policy honor matrix

Each backend declares which phases honor which `SandboxPolicy` fields. Caller-supplied
fields at unsupported phases produce `policy_validation`.

The shape of the matrix is the proposal-level contract: a row per cross-cutting
`SandboxPolicy` field, a column per phase, with values from the closed set
`applied` / `rejected` / `ignored`. Specific values per backend are documented in each
backend's plan doc (§11.6). For IsolationSession, illustrative values (final values
documented in the backend's plan doc):

| Field | provision | start | exec | stop | deprovision |
|---|---|---|---|---|---|
| `policy.filesystem` | applied | rejected | rejected | rejected | rejected |
| `policy.network` | applied | rejected | rejected | rejected | rejected |
| `policy.ui` | applied | rejected | rejected | rejected | rejected |

`SandboxPolicy` is shared across all phase calls (single source of truth — when its
fields evolve, all backends inherit them automatically). Per-phase honor is the
backend's choice and must be documented.

## 11. Plug-in guide for new backends

A backend author adding a new state-aware backend (or extending an existing ephemeral
backend with state-aware support) follows this workflow. The §7.4 worked example
illustrates the end-to-end shape; the steps below are the operational checklist.

### 11.1 Decide the participation mode

Pick one of the three modes from §4: ephemeral-only, state-aware-only, or both.

### 11.2 Implement the trait

The `StatefulSandboxBackend` trait signatures are in §9.2. Define associated types: per-phase
configs (`ProvisionConfig`, `StartConfig`, `ExecConfig`, `StopConfig`, `DeprovisionConfig`)
and per-phase metadata (`ProvisionMetadata`, `StartMetadata`, `StopMetadata`,
`DeprovisionMetadata`). Use `()` for any associated type the backend does not need.

Identifier generation happens inside the backend's `provision` method. Choose the
encoding (UUID, structured JSON, prefix-tagged string) and serialise the result into the
`sandbox_id: String` field of `ProvisionResult`. The recommended convention is a
backend-specific tag prefix (§5).

### 11.3 Define typed `*Config` interfaces in the SDK

For each phase the backend declares config for, add a typed TypeScript interface to
`@microsoft/mxc-sdk`. Example shape:

```typescript
interface MyBackendStartConfig {
  // backend-specific fields with typed values
}
```

Slot the interfaces into `ExperimentalStateAwareConfigs`:

```typescript
interface ExperimentalStateAwareConfigs {
  isolation_session?: IsolationSessionStateAwareConfigs;
  my_backend?: MyBackendStateAwareConfigs;  // new
}

interface MyBackendStateAwareConfigs {
  start?: MyBackendStartConfig;
  // omit phases without config
}
```

If the backend was not previously SDK-exposed, also extend `SandboxingMethod` and add
an entry to `StateAwareSandboxingMethod`.

### 11.4 Register in the `ContainmentBackend` enum

The dispatch layer in the executor matches on `ContainmentBackend` to route calls. Add a
variant for the new backend and a dispatch arm that invokes the trait method via
`dispatch_state_aware`. Compile-time errors will catch capability mismatches
automatically (§9.4).

### 11.5 Add a config-parser case

The state-aware wire format expects `experimental.<backend>.<phase>` blocks for backends
that declare per-phase configs. Add typed `Raw*` intermediate structs in
`config_parser.rs` (matching the existing `RawConfig` pattern) that deserialise the new
backend's JSON shape. Add a converter that produces the typed domain models the
dispatch layer consumes.

### 11.6 Document the backend

A per-backend document at `docs/<backend>-plan.md` (or equivalent) is required. It must
cover:

- **Per-phase config shapes.** The fields of each `*Config` interface, with allowed
  values and defaults.
- **Per-phase metadata shapes.** The fields of each `*Metadata` interface returned by
  the backend (any subset of provision, start, stop, deprovision). Phases that return
  no metadata are omitted from the bundle.
- **Cross-cutting policy honor matrix.** For each `SandboxPolicy` field
  (`filesystem`, `network`, `ui`), which phases the backend applies, rejects, or
  ignores it at. Per §10.3.
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
  without its runtime dependency (no broker, no daemon, no kernel feature). The
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

State-aware functionality matures along two independent axes:

1. **State-aware API stability.** Whether the surface defined in this proposal (the
   five lifecycle phases, the wire format, the error envelope, the trait) is stable
   enough to be relied on without the experimental opt-in.
2. **Per-backend state-aware participation.** Whether a given backend's state-aware
   implementation, per-stage config shapes, and error mappings are stable enough to
   rely on.

### 13.1 Wire-format placement rule

Per-stage config for backend X stays under `experimental.<backend>.<phase>` while
**either** the state-aware API itself is experimental **or** backend X's state-aware
participation is experimental. When both are stable, per-stage config migrates to
top-level `<backend>.<phase>`.

The `phase`-as-discriminator rule from §7.1 continues to apply post-graduation, just at
the top level: top-level `<backend>: { ... }` carries one-shot config when the call has
no `phase`, and top-level `<backend>: { provision: {...}, start: {...}, ... }` carries
per-phase configs when the call has `phase`. The two shapes do not coexist in a single
call.

### 13.2 Worked scenarios

**State-aware API graduates while IsolationSession stays experimental.** Per-stage
configs remain at `experimental.isolation_session.<phase>`. Callers using
IsolationSession's state-aware path still pass the experimental flag. New
state-aware-capable backends stabilise on their own timelines.

**Backend's ephemeral path graduates while state-aware is still experimental.** The
backend's ephemeral one-shot config can move from `experimental.<backend>` to top-level
`<backend>` independently, following the existing one-shot graduation pattern.
State-aware participation stays under `experimental.<backend>.<phase>` until the
state-aware API itself graduates. The
same backend can have a stable ephemeral path and an experimental state-aware path
simultaneously.

**Both graduate together.** Per-stage configs migrate from
`experimental.<backend>.<phase>` to top-level `<backend>.<phase>`. The `--experimental`
flag is no longer required for that backend's state-aware calls. For example, a `start`
call against IsolationSession migrates from this shape:

```json
{
  "version": "0.5.0-alpha",
  "containment": "isolation_session",
  "phase": "start",
  "sandboxId": "iso:reg-abc:prov-123",
  "experimental": {
    "isolation_session": {
      "start": { "configurationId": "small" }
    }
  }
}
```

to this shape after both axes have graduated:

```json
{
  "version": "0.6.0-alpha",
  "containment": "isolation_session",
  "phase": "start",
  "sandboxId": "iso:reg-abc:prov-123",
  "isolation_session": {
    "start": { "configurationId": "small" }
  }
}
```

**Sub-graduating a backend's state-aware participation alone (while the API is still
experimental) is not supported.** A backend's state-aware story cannot stabilise faster
than the API surface it depends on. Both must graduate together for state-aware config
placement to migrate.

### 13.3 Versioning

Each graduation event triggers a schema version bump in `docs/versioning.md`,
following the existing MXC convention for graduating features. The version bump and
the associated SDK type changes (such as dropping `experimental: true` requirements for
graduated containment values) ship as a single release.

## 14. Out of scope for v1

The following items are explicitly deferred. Each has a brief rationale and a likely
path forward.

- **Detached or long-running execs.** A model where `exec` returns a process id and
  the spawned process outlives the SDK call (analogous to `IsoSessionCli`'s
  fire-and-forget `create-process`). The JS-async fire-and-forget pattern (don't `await`
  `execInSandboxAsync`) IS supported via the existing functions — the spawned process
  is tethered to the SDK consumer's lifetime, but the caller can move on without
  awaiting. True OS-level detachment (process owned by the broker, independent of any
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

## 15. Open questions for MXC team review

The proposal makes specific choices in several places where the team may want to weigh
in. Defaults are workable; alternatives are listed where relevant.

- **TypeScript method names.** `provisionSandbox`, `startSandbox`, `execInSandbox` /
  `execInSandboxAsync`, `stopSandbox`, `deprovisionSandbox`. Aligned with the existing
  `spawnSandbox*` family vocabulary; "spawning" reads as the composition of these
  phases. Worth a focused naming review.
- **Rust trait name.** `StatefulSandboxBackend` paired with the existing `ScriptRunner`.
  Alternatives: `StatefulBackend`, `LifecycleBackend`, `StatefulSandbox`.
- **Error code names.** The 12 codes in §8 warrant a focused review pass for naming,
  grouping, and the boundary between specific codes and `backend_error.details`.
- **`phase` field placement.** Top-level (matches existing fields like `containment`)
  versus nested under `experimental.lifecycle.phase` while state-aware is experimental.
  The proposal's default avoids JSON-shape changes at graduation.
- **`containment` repetition on every call.** The §6.3 example repeats
  `'isolation_session'` six times. An SDK-level helper that binds containment once is a
  possible ergonomic addition.
- **Associated types vs. `serde_json::Value` at the trait boundary.** §9.2's trait uses
  associated types for typed configs; an alternative is `&serde_json::Value` with the
  backend deserialising inside each method. The associated-type form gives compile-time
  guarantees at the cost of trait verbosity; the `Value` form matches the existing
  `ScriptRunner::run(&CodexRequest)` style more closely. Worth a focused review.
- **Typed `ErrorEnvelope.details` per backend.** §7.3 and §8.2 leave `details` as
  `Record<string, unknown>`, the only such field in the contract. The same
  associated-type pattern §9.2 uses for `Self::ProvisionMetadata` could apply: a
  `Self::ErrorDetails: serde::Serialize` per backend, mirrored in the SDK as
  `ErrorDetailsFor<C>` via the existing conditional-type machinery. The Rust backend
  is what constructs `details` and knows the shape at write time, so the typing has
  no information that the open form does not. The current shape matches HTTP / gRPC
  error-envelope conventions; the typed shape would let `details` drop out of the
  contract's `Record<string, unknown>` carve-out entirely. Worth a focused review.
- **Per-backend metadata for `exec`.** §6 and §7 define per-phase typed `*Result<C>` for
  provision, start, stop, and deprovision. Exec is exempt: adding metadata to a
  live-streaming response requires an out-of-band channel — a sidechannel file
  descriptor, a sentinel-marked envelope appended after the script's stdout, or
  switching exec to fully buffered (losing the live-streaming UX). Worth revisiting
  when a backend has a concrete need.
