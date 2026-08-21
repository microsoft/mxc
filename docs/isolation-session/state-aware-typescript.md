# MXC IsolationSession Backend — State-Aware (TypeScript)

This document describes the IsolationSession backend's TypeScript SDK surface under
the state-aware lifecycle API ([design](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md)).
It is the SDK companion to the [Rust spec](state-aware-rust.md).
The Rust doc covers runtime semantics (validation, error mapping, idempotence,
concurrency); this doc covers SDK API surface, types, and consumer usage patterns.

## Scope

### In scope

- Per-(backend, phase) Config and Metadata shapes the SDK exposes for IsolationSession.
- End-to-end TS usage examples.
- Test-helper pattern for state-aware integration tests on hosts that may lack
  IsolationSession runtime support.

### Out of scope

- Runtime validation rules — see the [Rust spec](state-aware-rust.md)
  for the policy matrix, idempotence,
  concurrency, and error mapping.
- The wire-format envelope — see the
  [main design doc](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md) §7.
- Cross-backend lifecycle, method signatures, and the typed `MxcError` —
  see the main design doc §4, §6, §8.

## Per-phase Configs and Metadata

The SDK exposes only the fields the IsolationSession runtime currently honors at each
phase. See the [Rust spec](state-aware-rust.md) for the full Rust-side
contract (including fields not yet exposed via the SDK).

| Phase | Config | Metadata |
|---|---|---|
| provision | `IsolationSessionProvisionConfig` | `IsolationSessionProvisionMetadata` |
| start | `IsolationSessionStartConfig` | none |
| exec | `IsolationSessionExecConfig` | n/a (exec returns an exit code, not metadata) |
| stop | `IsolationSessionStopConfig` | none |
| deprovision | `IsolationSessionDeprovisionConfig` | none |

### Provision

**Config (`IsolationSessionProvisionConfig`):**

| Field | Type | Default | Description |
|---|---|---|---|
| `version` | string | SDK `SUPPORTED_VERSION` | Schema-version override. |
| `network` | `{ defaultPolicy: 'allow'; allowLocalNetwork: true }` | — (**required**) | Unrestricted-network acknowledgment. The container runs on a network MXC cannot filter or deny (outbound open; a process inside can listen on a port reachable from outside via localhost), so the caller must explicitly acknowledge it. This exact value is the only one accepted; any other network policy (or omission) is rejected at provision, and `network` is not accepted on the post-provision phases (the posture is fixed at provision). |
| `appId` | string | absent | Optional identifier for the calling application, associating the provisioned agent user with its owning app. **A packaged application must supply its Package Family Name in the form `PFN:<packageFamilyName>`** (for example `PFN:Contoso.App_8wekyb3d8bbwe`). An unpackaged application may pass any string. Carried inside the `sandboxId` so later lifecycle phases can recover it without the caller re-supplying it. Validated structurally only (no control characters, at most 256 characters); rejections surface as `MxcError` with `code: 'policy_validation'`. Whitespace and case are preserved exactly, and an explicitly supplied empty string is a **distinct** value from omitting the field. Provision-phase only — it is fixed for the sandbox's lifetime, and the `IsolationSessionStartConfig` type rejects it at compile time. |

**Metadata (`IsolationSessionProvisionMetadata`):**

| Field | Type | Description |
|---|---|---|
| `agentUserName` | string | OS-assigned account name, also carried inside the `SandboxId` where it is the addressing key for later phases. |
| `agentUserSid` | string | SID of the agent user. Diagnostic only. |
| `ephemeralWorkspacePath` | string | A directory shared between the caller and this isolated user for staging files into the session. Each isolated user sees only its own workspace; the caller can access every concurrent sandbox's workspace. Deleted when the sandbox is deprovisioned. Does not change the working directory. |

`appId` is deliberately **not** echoed in the metadata — the caller supplied the
value, so returning it would be redundant surface. The `SandboxId` remains
**opaque** to callers: the payload is an MXC implementation detail, and nothing
in the SDK parses past the `iso:` prefix.

### Start

**Config (`IsolationSessionStartConfig`):**

| Field | Type | Default | Description |
|---|---|---|---|
| `version` | string | SDK `SUPPORTED_VERSION` | Schema-version override. |

**Metadata:** none.

### Exec

**Config (`IsolationSessionExecConfig`):**

| Field | Type | Description |
|---|---|---|
| `version` | string | Schema-version override. |
| `process` | `ProcessConfig` (required) | Cross-cutting process info — `commandLine`, `cwd`, `env`, `timeout`. |

**Metadata:** n/a — exec returns an exit code and streamed stdio, not a structured result.

### Stop, Deprovision

Each Config carries only `version?`. Neither phase returns metadata.

## End-to-end example

```typescript
import {
  provisionSandbox,
  startSandbox,
  execInSandboxAsync,
  stopSandbox,
  deprovisionSandbox,
  SandboxSpawnOptions,
} from '@microsoft/mxc-sdk';

const opts: SandboxSpawnOptions = { experimental: true };

const { sandboxId } = await provisionSandbox(
  'isolation_session',
  // Required. The container's network cannot be filtered or denied, so
  // provision accepts only this explicit acknowledgment of that posture —
  // and the config argument itself is mandatory for this backend precisely
  // because the field is.
  { network: { defaultPolicy: 'allow', allowLocalNetwork: true } },
  opts,
);

await startSandbox(sandboxId, {}, opts);
const r = await execInSandboxAsync(sandboxId, { process: { commandLine: 'echo hi' } }, opts);
console.log(r.stdout); // "hi"

await stopSandbox(sandboxId, undefined, opts);
await deprovisionSandbox(sandboxId, undefined, opts);
```

## Test helpers

`sdk/node/tests/integration/test-helpers.ts` exports three helpers for state-aware
integration tests on hosts that may lack the runtime:

- `runOrSkipIfBackendUnavailable<T>(t, label, fn)` — wraps a call and converts
  `backend_unavailable` / `unsupported_phase` `MxcError`s into `t.skip()`. Other
  errors propagate.
- `safeDeprovision<C>(sandboxId)` — best-effort deprovision; swallows errors so
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

- [State-aware design (main)](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md)
- [State-aware design (overview)](../state-aware-lifecycle/mxc-state-aware-sandbox-api-overview.md)
- [Rust spec](state-aware-rust.md) — runtime semantics
- [One-shot bringup](oneshot.md)
