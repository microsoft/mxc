# MXC IsolationSession Backend — State-Aware (TypeScript)

> **Audience:** MXC developers

This document describes the IsolationSession backend's TypeScript SDK surface under
the state-aware lifecycle API. It is the SDK companion to the
[Rust backend guide](state-aware-rust.md).
The Rust doc covers runtime semantics (validation, error mapping, idempotence,
concurrency); this doc covers SDK API surface, types, and consumer usage patterns.

## Scope

### In scope

- Public request, operation-options, and metadata shapes for IsolationSession.
- End-to-end TS usage examples.
- Test-helper pattern for state-aware integration tests on hosts that may lack
  IsolationSession runtime support.

### Out of scope

- Runtime validation rules — see the [Rust spec](state-aware-rust.md)
  for the policy matrix, idempotence,
  concurrency, and error mapping.
- The wire-format envelope — see the
  [main design doc](../../container-lifecycle.md) §7.
- Cross-backend lifecycle and error handling — see the SDK documentation and
  [Rust backend guide](state-aware-rust.md).

## Requests, operation options, and metadata

The SDK exposes only the fields the IsolationSession runtime currently honors at each
phase. See the [Rust spec](state-aware-rust.md) for the full Rust-side
contract (including fields not yet exposed via the SDK).

Like the other high-level v1 APIs, these typed lifecycle APIs are V1
contract-mapped. The Node SDK owns and emits exact stable contract `1.0.0`;
callers do not supply a schema version. Caller-selected versions are reserved
for raw exact APIs.

| Phase | Input | Metadata |
|---|---|---|
| provision | `ProvisionRequest<'isolation_session'>`, optional `ProvisionOptions` | `IsolationSessionProvisionMetadata` |
| start | `ContainerId`, optional `StartOptions` | none |
| exec | `ContainerId`, `ExecutionRequest<'isolation_session'>`, execution-specific options | `ExecutionResult` or a live SDK process |
| stop | `ContainerId`, optional `StopOptions` | none |
| deprovision | `ContainerId`, optional `DeprovisionOptions` | none |

### Provision

**Request (`ProvisionRequest<'isolation_session'>`):**

| Field | Type | Default | Description |
|---|---|---|---|
| `containment` | `'isolation_session'` | — (**required**) | SDK-owned containment discriminator. |
| `network` | `IsolationSessionNetworkConfig` | — (**required**) | The backend's actual unrestricted posture: `{ egress: { default: 'allow' }, ingress: { default: 'allow', hostLoopback: 'allow' } }`. Legacy fields are rejected. Rules, proxies, mixed postures, and omission are rejected, and `network` is not accepted on post-provision phases. |
| `appId` | string | absent | Optional identifier for the calling application, associating the provisioned agent user with its owning app. **A packaged application must supply its Package Family Name in the form `PFN:<packageFamilyName>`** (for example `PFN:Contoso.App_8wekyb3d8bbwe`). An unpackaged application may pass any string. Carried inside the `sandboxId` so later lifecycle phases can recover it without the caller re-supplying it. Validated structurally only (no control characters, at most 256 characters); rejections surface as `MxcError` with `code: 'policy_validation'`. Whitespace and case are preserved exactly, and an explicitly supplied empty string is a **distinct** value from omitting the field. Provision-phase only — it is fixed for the sandbox's lifetime and is not a field of `StartOptions`. |

**Metadata (`IsolationSessionProvisionMetadata`):**

| Field | Type | Description |
|---|---|---|
| `agentUserName` | string | OS-assigned account name, also carried inside the `ContainerId` where it is the addressing key for later phases. |
| `agentUserSid` | string | SID of the agent user. Diagnostic only. |
| `ephemeralWorkspacePath` | string | A directory shared between the caller and this isolated user for staging files into the session. Each isolated user sees only its own workspace; the caller can access every concurrent sandbox's workspace. Deleted when the sandbox is deprovisioned. Does not change the working directory. |

`appId` is deliberately **not** echoed in the metadata — the caller supplied the
value, so returning it would be redundant surface. The `ContainerId` remains
**opaque** to callers: the payload is an MXC implementation detail, and nothing
in the SDK parses past the `iso:` prefix.

### Start

`startContainer(containerId, options?)` accepts `StartOptions`: optional
experimental authorization and telemetry.

**Metadata:** none.

### Exec

**Request (`ExecutionRequest<'isolation_session'>`):**

| Field | Type | Description |
|---|---|---|
| `command` | string (required) | Workload command. |
| `workingDirectory` | string | Child working directory. |
| `environment` | `Record<string, string>` | Environment entries. |
| `inheritDefaultEnvironment` | boolean | Layer entries over the agent user's default environment. |
| `timeoutMs` | number | Workload timeout in milliseconds. |
| `telemetry` | `TelemetryConfig` | Per-request telemetry setting; invocation options override it when supplied. |

`spawnInContainer` returns `Promise<MxcProcess>` and `runInContainer` returns
`Promise<ExecutionResult>`. Their options are `SpawnInContainerOptions` and
`RunInContainerOptions`.
`spawnInContainerWithPty` takes `SpawnInContainerWithPtyOptions`, including
optional initial terminal `size`, and returns `Promise<MxcPtyProcess>`.

### Stop, Deprovision

`StopOptions` and `DeprovisionOptions` carry optional experimental authorization
and telemetry. Neither phase returns metadata.

## End-to-end example

```typescript
import {
  provisionContainer,
  startContainer,
  runInContainer,
  stopContainer,
  deprovisionContainer,
} from '@microsoft/mxc-sdk/v1';

const { containerId } = await provisionContainer(
  // Required. The container's network cannot be filtered or denied, so
  // provision explicitly describes all three axes as unrestricted.
  {
    containment: 'isolation_session',
    network: {
      egress: { default: 'allow' },
      ingress: { default: 'allow', hostLoopback: 'allow' },
    },
  },
);

await startContainer(containerId);
const r = await runInContainer(
  containerId,
  { command: 'echo hi' },
);
console.log(r.stdout); // "hi"

await stopContainer(containerId);
await deprovisionContainer(containerId);
```

## Test helpers

`sdk/node/tests/integration/test-helpers.ts` exports three helpers for state-aware
integration tests on hosts that may lack the runtime:

- `runOrSkipIfBackendUnavailable<T>(t, label, fn)` — wraps a call and converts
  `backend_unavailable` / `unsupported_phase` `MxcError`s into `t.skip()`. Other
  errors propagate.
- `safeDeprovision<C>(containerId)` — best-effort deprovision; swallows errors so
  cleanup never masks the original failure.
- `probeStateAwareRuntime<C>(containment)` — module-load probe. Returns a skip-reason
  string or `undefined`. Pair with `describe`'s `{ skip }` option for module-level
  gating via top-level `await`.

Pattern:

```typescript
const skipReason = os.platform() !== 'win32'
  ? 'IsolationSession is Windows-only'
  : await probeStateAwareRuntime('isolation_session');

describe('IsolationSession state-aware lifecycle E2E', { skip: skipReason }, () => {
  it('runs full lifecycle', async () => { /* ... */ });
});
```

## References

- [State-aware design (main)](../../container-lifecycle.md)
- [Container lifecycle overview](../../../../container-lifecycle.md)
- [Rust spec](state-aware-rust.md) — runtime semantics
- [One-shot bringup](oneshot.md)
