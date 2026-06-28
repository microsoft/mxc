# MXC IsolationSession Backend — State-Aware (Rust)

This document describes the IsolationSession backend's behaviour under the
state-aware lifecycle API ([design](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md)).
It is the per-backend specification required by §11.6 of that design and
covers the five state-aware phases — provision, start, exec, stop,
deprovision — plus the cross-cutting policy matrix, idempotence behaviour,
concurrency story, and error mapping.

## Scope

### In scope

- The Rust layer of state-aware IsolationSession in `wxc-exec.exe`, behind
  the `--features isolation_session` Cargo feature and the `--experimental`
  CLI flag.
- The wire format consumed by `wxc-exec.exe` for state-aware requests
  (top-level `phase` discriminator, `sandboxId`,
  `experimental.isolation_session.<phase>` typed config blocks).
- Mapping from the OS-side service's HRESULTs to the wire-format `MxcError`
  codes.

### Out of scope (for v1)

- **Explicit `AbortSignal` plumbing.** v1 cancellation is OS-level: the
  caller kills `wxc-exec.exe`, the OS-side service's per-process timer or
  the existing 3-tier shutdown (close stdin → `SendCtrlClose` → `Terminate`)
  reaps the agent. See [Cancellation](#cancellation) below.
- **Concurrent state-aware sessions.** v1 supports a single state-aware
  sandbox per consumer. See [Concurrency](#concurrency) for the constraint.

## Per-phase config and metadata shapes

The `StatefulSandboxBackend` impl on `IsolationSessionRunner` declares
associated types for each phase. Phases without a config use `()`; phases
without metadata use `()`.

| Phase | `*Config` | `*Metadata` |
|---|---|---|
| provision | `IsolationSessionProvisionConfig` | `IsolationSessionProvisionMetadata` |
| start | `IsolationSessionConfig` | `()` |
| exec | `()` | (n/a — exec returns an exit code, not metadata) |
| stop | `()` | `()` |
| deprovision | `()` | `()` |

### Provision

**Config (`IsolationSessionProvisionConfig`):**

| Field | Type | Default | Description |
|---|---|---|---|
| `user` | `IsolationSessionUser` (object) \| absent | absent | Optional Entra cloud-agent credentials. When present, the UPN and WAM token are passed to `AddUserAsync` and the resulting sandbox is Entra-backed. When absent, provision calls `AddUserAsync` with empty strings and produces a local-agent sandbox. The bundle is `{ upn: string, wamToken: string }`; both fields required when supplied. `wamToken` is passed verbatim to the OS-side service and never stored by MXC. The wire path is `experimental.isolation_session.provision.user`. |

**Metadata (`IsolationSessionProvisionMetadata`):**

| Field | Type | Description |
|---|---|---|
| `agentUserName` | string | The OS-assigned agent account name returned by `AddUserAsync`. Diagnostic only — not used as an addressing key. Format is OS-internal and not stable across builds. |

The provisioned `sandboxId` is always `iso:<agentUserName>`, where
`agentUserName` is the opaque account name the OS assigns at `AddUserAsync`
(also returned in `IsolationSessionProvisionMetadata.agentUserName`). The
same shape is used for local and Entra sandboxes alike — the tail is opaque,
so no later phase can infer Entra-ness from it; the Entra WAM token is
re-supplied at start instead. The exact `agentUserName` format is OS-internal
and not stable across builds.

### Start

**Config (`IsolationSessionConfig`):**

| Field | Type | Default | Description |
|---|---|---|---|
| `user` | `IsolationSessionUser` (object) \| absent | absent | Optional. Supply for an Entra sandbox to re-provide the WAM token (the opaque `sandboxId` tail can't carry it); omit for a local sandbox. When supplied it is shape-validated (`upn` contains `@`, `wamToken` non-empty) by `validate_start`, surfacing shape errors as `policy_validation`; the OS validates the token against the agent user assigned at provision. The wire path is `experimental.isolation_session.start.user`. |

This is the same `IsolationSessionConfig` shape used by the one-shot
`experimental.isolation_session` block, with one mode difference: `user` is
honoured here at state-aware start, but rejected on the one-shot path
(`validate_runner` returns `policy_validation` if a one-shot request carries
it).

**Metadata (none).** Start returns an empty `result: {}` envelope on success.

### Exec

**Config (none).** Exec uses only the cross-cutting `process` block on the
top-level wire envelope (`commandLine`, `cwd`, `env`, `timeout`).

**Output.** Stdout is the agent process's live-streamed output (the SDK
discriminates this from a JSON envelope by exit code + stdout-parseability;
the dispatcher never emits a JSON envelope on stdout for exec on success).
The wxc-exec process exit code is the agent process's exit code.

### Stop

**Config (none).** Stop terminates the active session. Idempotent semantics
described in [Idempotence](#idempotence-per-phase).

**Metadata (none).** Empty `result: {}` envelope.

### Deprovision

**Config (none).** Deprovision removes the agent user. After this returns,
`sandboxId` is no longer addressable — any subsequent op against it surfaces
`stale_id`.

**Metadata (none).** Empty `result: {}` envelope.

## Cross-cutting policy honor matrix

IsolationSession rejects every `policy.filesystem` field (`readwritePaths`,
`readonlyPaths`, `deniedPaths`), all `policy.network` policy, and
`policy.network.proxy` at every phase — provision included. The backend has
no host-folder-sharing, network, or proxy primitive, so there is nothing to
honor. The only caller-supplied knob it accepts is the optional Entra `user`
bundle, at provision and start.

| Field | provision | start | exec | stop | deprovision |
|---|---|---|---|---|---|
| `policy.filesystem.{readwritePaths,readonlyPaths}` | rejected | rejected | rejected | rejected | rejected |
| `policy.filesystem.deniedPaths` | rejected | rejected | rejected | rejected | rejected |
| `policy.network.{allowedHosts,blockedHosts,defaultPolicy}` | rejected | rejected | rejected | rejected | rejected |
| `policy.network.proxy` | rejected | rejected | rejected | rejected | rejected |
| `policy.ui` | rejected | rejected | rejected | rejected | rejected |
| `experimental.isolation_session.{provision,start}.user` | **honored** | **honored** | n/a | n/a | n/a |

Rejection of `policy.*` fields surfaces as `error.code = "policy_validation"`.
A malformed `user` shape (UPN missing `@`, empty `wamToken`) likewise surfaces
as `policy_validation`. Start does not cross-check the `user` bundle against
the `sandboxId` tail — the tail is opaque — so there is no identity-mismatch
`malformed_request` path; the OS validates the WAM token against the agent
user it assigned at provision.

## Mode-specific fields

### Fields valid in both modes

- `process.commandLine` — required for one-shot and for state-aware exec;
  ignored at non-exec state-aware phases (the parser allows `process` to be
  absent for non-exec phases).
- `process.cwd`, `process.env`, `process.timeout` — optional in both modes,
  honoured per-process (each exec receives its own block).

### Policy fields and mode parity

Both modes share the same policy matrix above. Every `policy.filesystem`
field (`readwritePaths`, `readonlyPaths`, `deniedPaths`), all `policy.network`
policy, `policy.network.proxy`, and `policy.ui` are rejected at every phase —
the backend has no host-folder-sharing, network, or proxy primitive. One-shot
enforces this via `validate_runner`; state-aware enforces it via the
`validate_<phase>` hooks.

### Fields valid in state-aware only

- `phase` — the discriminator. Required for state-aware; absent for one-shot.
- `sandboxId` — required for non-provision phases.
- `experimental.isolation_session.<phase>` — typed per-phase config blocks
  (`provision` carries optional `user`; `start` carries optional `user`;
  `exec` / `stop` / `deprovision` use `()`).
- `experimental.isolation_session.{provision,start}.user` — Entra cloud-agent
  credentials. Honoured here; the same field on a one-shot `experimental.isolation_session`
  is rejected with `policy_validation`.

## Idempotence per phase

| Phase | Repeated call | Notes |
|---|---|---|
| provision | non-idempotent | Each provision mints a fresh `provisionId` / agent user. Two provision calls produce two distinct sandboxes. Acceptable: callers manage `sandboxId` state themselves. |
| start | OS-side dependent | Starting an already-started session surfaces an HRESULT from `StartSessionAsync`; mapped to `backend_error` (no specific MXC code). Callers should not call start twice; if they do, the second call's failure does not corrupt the first session. |
| exec | per-call | Each exec creates a fresh agent process via `RunProcessWithOptionsAsync`. No deduplication — repeated `commandLine` runs the command repeatedly. |
| stop | OS-side dependent | Stopping an already-stopped session surfaces an HRESULT from `StopSessionAsync`; mapped to `backend_error`. The agent user remains — only the running session is gone. |
| deprovision | becomes `stale_id` | After a successful deprovision, the agent user is gone. A second deprovision on the same `sandboxId` triggers the OS-side `FindActiveAgentUserByProvisionId` lookup failure (`HRESULT_FROM_WIN32(ERROR_NOT_FOUND)`), which the runner maps to `MxcError::StaleId`. |

## Concurrency

### Multiple sandboxes

Distinct `sandboxId`s map to distinct OS agent users (each `AddUserAsync`
mints a fresh account). There is no shared registration between them, so
concurrent provisions are independent and all succeed.

### Multiple exec calls against the same sandbox

The runner's `exec` impl reuses the existing one-shot `create_process` path
synchronously: `manager.create_process(&options)` blocks until the agent
process exits and the relay drains. Two concurrent exec calls against the
same `sandboxId` from two `wxc-exec` processes are not coordinated by MXC;
the OS-side service serialises (or rejects, depending on session state) at
its own layer.

### Deprovision and concurrent sandboxes

`deprovision` removes only its own agent user (`deprovision_agent_user`).
Because each sandbox is a distinct OS agent user with no shared registration,
deprovisioning one sandbox does not affect any other concurrent sandbox —
they remain independently addressable until each is deprovisioned in turn.

## Error mapping

`IsolationSessionError` (the runner's internal categorisation) maps 1:1 to
wire-format `MxcError` codes via `map_lifecycle_error`:

| `IsolationSessionError` variant | Wire `error.code` | Trigger |
|---|---|---|
| `Policy(...)` | `policy_validation` | Caller-supplied policy field that this phase does not accept — see the honor matrix above. Rejected by `validate_<phase>` hooks (state-aware) or `validate_runner` (one-shot). |
| `ServiceUnavailable(...)` | `backend_unavailable` | `IsoSessionOps` activation failure: the `Windows.AI.IsolationSession.Preview` API is unavailable on this OS build (not registered, or the OS feature gate is off). HRESULTs `CLASS_E_CLASSNOTAVAILABLE` (`0x80040111`) or `REGDB_E_CLASSNOTREG` (`0x80040154`). |
| `Stale(...)` | `stale_id` | OS-side `AgentManager::FindActiveAgentUserByProvisionId` returns `HRESULT_FROM_WIN32(ERROR_NOT_FOUND)` (`0x80070490`) — the `provisionId` is missing from both the in-memory cache and the persisted registry. After `deprovision`, every non-provision op against the dead `sandboxId` triggers this. |
| `Lifecycle(...)` | `backend_error` | Any other HRESULT from a lifecycle op. The error message embeds the operation name, HRESULT, OS-side message, and remediation hint where present. |

`error.details` is empty in v1. The HRESULT and OS-side message live inside
`error.message` rather than as a structured field.

## Cancellation

State-aware exec (and other phases) use OS-level cancellation in v1:

- The SDK kills the `wxc-exec` process via process termination.
- The agent process's pipes EOF, the relay threads exit.
- The OS-side service's per-process timer (set from
  `process.timeout`) reaps the agent if the runner does not.
- The runner's existing 3-tier shutdown (`CloseStandardInput` →
  `SendCtrlClose` → `Terminate`) handles the timeout case from inside the
  agent process before returning.

`ExecHandle.terminator` is currently a no-op closure on the
IsolationSession path because the backend reuses the one-shot
`create_process` synchronously and there is no mid-flight cancellation
seam. Future work — explicit Rust-layer `AbortSignal` plumbing — would
require splitting `create_process` into a non-blocking start + a separate
waiter, with `terminator` invoking `IsoSessionProcess::Terminate()`.

## Known issues

### Concurrent state-aware sandboxes

v1 targets a single state-aware sandbox per consumer (see the
[Out of scope](#out-of-scope-for-v1) note). The earlier cross-sandbox
deprovision hazard no longer applies — each sandbox is an independent OS
agent user with no shared registration — so this is a v1 scoping choice,
not an OS limitation.

## References

- [State-aware design (full)](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md)
- [State-aware design (overview)](../state-aware-lifecycle/mxc-state-aware-sandbox-api-overview.md)
- [TypeScript spec](state-aware-typescript.md) — SDK companion
  to this doc; covers SDK API surface, types, and TS usage examples.
- [One-shot bringup](oneshot.md) — the
  predecessor doc for IsolationSession's first integration; this doc
  covers state-aware on top of that foundation.
