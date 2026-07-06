# MXC IsolationSession Backend — State-Aware (TypeScript)

This document describes the IsolationSession backend's TypeScript SDK surface under
the state-aware lifecycle API ([design](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md)).
It is the SDK companion to the [Rust spec](state-aware-rust.md).
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

- Runtime validation rules — see the [Rust spec](state-aware-rust.md)
  for the Entra `user` validation, policy matrix, idempotence,
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
| `user` | `IsolationSessionUserConfig` | absent | Optional Entra credentials (see below). |

**Metadata (`IsolationSessionProvisionMetadata`):**

| Field | Type | Description |
|---|---|---|
| `agentUserName` | string | OS-assigned account name. Diagnostic only — not used as an addressing key. |
| `agentUserSid` | string | SID of the agent user. Diagnostic only. |
| `ephemeralWorkspacePath` | string | A directory shared between the caller and this isolated user for staging files into the session. Each isolated user sees only its own workspace; the caller can access every concurrent sandbox's workspace. Deleted when the sandbox is deprovisioned. Does not change the working directory. |

### Start

**Config (`IsolationSessionStartConfig`):**

| Field | Type | Default | Description |
|---|---|---|---|
| `version` | string | SDK `SUPPORTED_VERSION` | Schema-version override. |
| `user` | `IsolationSessionUserConfig` | absent | Optional. For an Entra sandbox, re-supply the `user` (same UPN, current WAM token) so the OS can validate the token against the agent user assigned at provision. Omit for a local sandbox. Shape-validated only — MXC does not match the UPN against the sandbox id. |

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
  {},
  opts,
);

await startSandbox(sandboxId, {}, opts);
const r = await execInSandboxAsync(sandboxId, { process: { commandLine: 'echo hi' } }, opts);
console.log(r.stdout); // "hi"

await stopSandbox(sandboxId, undefined, opts);
await deprovisionSandbox(sandboxId, undefined, opts);
```

### Entra

Provisioning with a `user` bundle selects the Entra path. The returned id is an
opaque OS-assigned handle (it does not encode the UPN); re-supply the `user` at
start so the OS can validate the current WAM token:

```typescript
import { IsolationSessionUserConfig } from '@microsoft/mxc-sdk';

const user = new IsolationSessionUserConfig('alice@contoso.com', wamToken);

const { sandboxId } = await provisionSandbox(
  'isolation_session',
  { user },
  opts,
);

await startSandbox(sandboxId, { user }, opts);
// exec / stop / deprovision unchanged from the local example above.
```

Validation rules for the Entra path (bundle shape-validation, error
codes) live in the [Rust spec](state-aware-rust.md).

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

The Entra path can't be exercised in CI without WAM credentials; the Rust-side
[state-aware test runner](../../tests/scripts/run_isolation_session_state_aware_tests.ps1)
covers the validation rejections.

## References

- [State-aware design (main)](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md)
- [State-aware design (overview)](../state-aware-lifecycle/mxc-state-aware-sandbox-api-overview.md)
- [Rust spec](state-aware-rust.md) — runtime semantics
- [One-shot bringup](oneshot.md)
