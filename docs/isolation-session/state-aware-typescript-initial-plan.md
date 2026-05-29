# MXC IsolationSession Backend — State-Aware TypeScript Initial Plan

This document describes the IsolationSession backend's TypeScript SDK surface under
the state-aware lifecycle API ([design](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md)).
It is the SDK companion to the [Rust initial plan](state-aware-rust-initial-plan.md).
The Rust doc covers runtime semantics (validation, error mapping, idempotence,
concurrency); this doc covers SDK API surface, types, and consumer usage patterns.

## Scope

### In scope

- Per-(backend, phase) Config and Metadata shapes the SDK exposes for IsolationSession.
- The `IsolationSessionUserConfig` class and its `wamToken` redaction behaviour.
- End-to-end TS usage examples — local and Entra variants.
- Test-helper pattern for state-aware integration tests on hosts that may lack
  IsolationSession runtime support.

### Out of scope

- Runtime validation rules — see the [Rust plan](state-aware-rust-initial-plan.md)
  for the Entra `user` validation matrix, policy honor matrix, idempotence,
  concurrency, and error mapping.
- The wire-format envelope — see the
  [main design doc](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md) §7.
- Cross-backend lifecycle, method signatures, and the typed `MxcError` —
  see the main design doc §4, §6, §8.

## Per-phase Configs and Metadata

The SDK exposes only the fields the IsolationSession runtime currently honors at each
phase. See the [Rust plan](state-aware-rust-initial-plan.md) for the full Rust-side
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
| `filesystem` | `FilesystemConfig` | absent | `readwritePaths` and `readonlyPaths` honored at provision; `deniedPaths` rejected. |
| `user` | `IsolationSessionUserConfig` | absent | Optional Entra credentials (see below). |

**Metadata (`IsolationSessionProvisionMetadata`):**

| Field | Type | Description |
|---|---|---|
| `agentUserName` | string | OS-assigned account name. Diagnostic only — not used as an addressing key. |

### Start

**Config (`IsolationSessionStartConfig`):**

| Field | Type | Default | Description |
|---|---|---|---|
| `version` | string | SDK `SUPPORTED_VERSION` | Schema-version override. |
| `configurationId` | `'small' \| 'medium' \| 'large' \| 'composable'` | runtime default `'composable'` | Session size profile. |
| `user` | `IsolationSessionUserConfig` | absent | Required when the sandbox was provisioned with a `user` bundle; rejected otherwise. When required, `upn` must match the UPN supplied at provision (case-insensitive). |

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

## `IsolationSessionUserConfig`

```typescript
export class IsolationSessionUserConfig {
  readonly upn: string;
  readonly wamToken: string;
  constructor(upn: string, wamToken: string);
}
```

`wamToken` is treated as a secret: `util.inspect` (and therefore `console.log`)
redacts it as `<redacted>`. `JSON.stringify` preserves both fields verbatim so the
wire envelope carries the real token.

The Config field on `IsolationSessionProvisionConfig` and `IsolationSessionStartConfig`
is typed as the class itself, which means plain `{ upn, wamToken }` literals are not
assignable — callers must construct via `new IsolationSessionUserConfig(...)` to
guarantee consistent redaction across logging paths.

## End-to-end examples

### Local

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
  { filesystem: { readwritePaths: ['C:\\workspace'] } },
  opts,
);

await startSandbox(sandboxId, { configurationId: 'composable' }, opts);
const r = await execInSandboxAsync(sandboxId, { process: { commandLine: 'echo hi' } }, opts);
console.log(r.stdout); // "hi"

await stopSandbox(sandboxId, undefined, opts);
await deprovisionSandbox(sandboxId, undefined, opts);
```

### Entra

Provisioning with a `user` bundle selects the Entra path; the returned id encodes
the UPN, and every subsequent start on that sandbox must carry a matching `user`:

```typescript
import { IsolationSessionUserConfig } from '@microsoft/mxc-sdk';

const user = new IsolationSessionUserConfig('alice@contoso.com', wamToken);

const { sandboxId } = await provisionSandbox(
  'isolation_session',
  { filesystem: { readwritePaths: ['C:\\workspace'] }, user },
  opts,
);

await startSandbox(sandboxId, { configurationId: 'composable', user }, opts);
// exec / stop / deprovision unchanged from the local example above.
```

Validation rules for the Entra path (UPN matching, malformed-bundle handling, error
codes) live in the [Rust plan](state-aware-rust-initial-plan.md).

## Test helpers

`sdk/tests/integration/test-helpers.ts` exports three helpers for state-aware
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

The Entra path can't be exercised in CI without WAM credentials; the Rust-side
[state-aware test runner](../../tests/scripts/run_isolation_session_state_aware_tests.ps1)
covers the validation rejections.

## References

- [State-aware design (main)](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md)
- [State-aware design (overview)](../state-aware-lifecycle/mxc-state-aware-sandbox-api-overview.md)
- [Rust initial plan](state-aware-rust-initial-plan.md) — runtime semantics
- [Initial bringup plan (one-shot)](initial-bringup-plan.md)
