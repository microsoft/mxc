# MXC IsolationSession Backend — State-Aware Rust Initial Plan

This document describes the IsolationSession backend's behaviour under the
state-aware lifecycle API ([design](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md)).
It is the per-backend plan required by §11.6 of that design and covers the
five state-aware phases — provision, start, exec, stop, deprovision —
plus the cross-cutting policy honor matrix, idempotence behaviour,
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

### Out of scope (for this initial plan)

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
| `user` | `IsolationSessionUser` (object) \| absent | absent | Optional Entra cloud-agent credentials. When present, provision routes through `IIsoSessionOps2::AddUserAsync2` and the resulting sandbox is Entra-backed. When absent, provision uses the v1 `AddUserAsync` path and produces a local-agent sandbox. The bundle is `{ upn: string, wamToken: string }`; both fields required when supplied. `wamToken` is passed verbatim to the OS-side service and never stored by MXC. The wire path is `experimental.isolation_session.provision.user`. |

**Metadata (`IsolationSessionProvisionMetadata`):**

| Field | Type | Description |
|---|---|---|
| `agentUserName` | string | The OS-assigned agent account name returned by `AddUserAsync` / `AddUserAsync2`. Diagnostic only — not used as an addressing key. Format is OS-internal and not stable across builds. |

The provisioned `sandboxId` shape depends on whether `user` was supplied:

- **Local sandbox** (no `user`): `iso:wxc-<8-hex>`, where the 8-hex suffix is
  `mint_random_token()`. Example: `iso:wxc-1b65bd11`.
- **Entra sandbox** (`user` supplied): `iso:<UPN>`. The UPN is the OS-layer
  `provisionId` for Entra agents — no separate identifier exists — so encoding
  it as the tail keeps every later phase stateless. Example:
  `iso:alice@contoso.com`.

### Start

**Config (`IsolationSessionConfig`):**

| Field | Type | Default | Description |
|---|---|---|---|
| `configurationId` | `"small" \| "medium" \| "large" \| "composable"` | `"composable"` | Maps to the OS-side `IsoSessionConfigId`. `composable` is the lightweight, ConPTY-friendly default; `small` triggers a known cache-teardown bug on the current OS build (see [Known issues](#known-issues)) and is not recommended. |
| `user` | `IsolationSessionUser` (object) \| absent | absent | Required when starting an Entra sandbox (one whose `sandboxId` tail contains `@`); rejected for local sandboxes. When required, `user.upn` must match the `sandboxId` tail (case-insensitive) and `wamToken` must be non-empty — `validate_start` enforces this matrix and surfaces mismatches as `malformed_request`. Routes start through `IIsoSessionOps2::StartSessionAsync2`. The wire path is `experimental.isolation_session.start.user`. |

This is the same `IsolationSessionConfig` shape used by the one-shot
`experimental.isolation_session` block, with one mode difference: `user` is
honoured here at state-aware start, but rejected on the one-shot path
(`validate_runner` returns `policy_validation` if a one-shot request carries
it). The wire path for `configurationId` is
`experimental.isolation_session.start.configurationId`.

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

**Config (none).** Deprovision removes the agent user *and* unregisters the
client app. After this returns, `sandboxId` is no longer addressable — any
subsequent op against it surfaces `stale_id`.

**Metadata (none).** Empty `result: {}` envelope.

## Cross-cutting policy honor matrix

IsolationSession honors `readwritePaths` and `readonlyPaths` at provision
(applied via `ShareFolderBatchAsync`), and rejects everything else at
every phase. The grant lifecycle is bound to the agent user, so
filesystem policy is bound to provision and immutable thereafter — every
non-provision phase rejects any non-empty filesystem field. The OS-side
service has no equivalent for `deniedPaths`, network, or UI policy, so
those are rejected at every phase including provision.

| Field | provision | start | exec | stop | deprovision |
|---|---|---|---|---|---|
| `policy.filesystem.{readwritePaths,readonlyPaths}` | **honored** | rejected | rejected | rejected | rejected |
| `policy.filesystem.deniedPaths` | rejected | rejected | rejected | rejected | rejected |
| `policy.network.{allowedHosts,blockedHosts,defaultPolicy}` | rejected | rejected | rejected | rejected | rejected |
| `policy.network.proxy` | rejected | rejected | rejected | rejected | rejected |
| `policy.ui` | rejected | rejected | rejected | rejected | rejected |
| `experimental.isolation_session.{provision,start}.user` | **honored** | **honored** | n/a | n/a | n/a |

Rejection of `policy.*` fields surfaces as `error.code = "policy_validation"`.
Rejection of malformed `user` shape (UPN missing `@`, empty `wamToken`) surfaces
as `policy_validation`; rejection at start due to a sandboxId/user inconsistency
(missing user for Entra sandbox, user supplied for local sandbox, or UPN
mismatch) surfaces as `malformed_request`.

## Mode-specific fields

### Fields valid in both modes

- `process.commandLine` — required for one-shot and for state-aware exec;
  ignored at non-exec state-aware phases (the parser allows `process` to be
  absent for non-exec phases).
- `process.cwd`, `process.env`, `process.timeout` — optional in both modes,
  honoured per-process (each exec receives its own block).
- `experimental.isolation_session.configurationId` (one-shot) /
  `experimental.isolation_session.start.configurationId` (state-aware) —
  same enum (`small` / `medium` / `large` / `composable`).

### Policy fields and mode parity

Both modes share the same policy-honor matrix above:

- `policy.filesystem.readwritePaths` / `readonlyPaths` are honored at
  provision (state-aware) or at the start of the lifecycle (one-shot,
  via `ScriptRunner::validate_runner` then `share_folders` in
  `IsolationSessionRunner::execute`). Rejected at all later state-aware
  phases.
  - Before forwarding to `ShareFolderBatchAsync`, `share_folders` runs
    the entries through a small filter (`filter_protected_paths` in
    `isolation_session_runner.rs`, bracketed by `BEGIN:` / `END:`
    markers) that silently drops a fixed set of system-folder paths —
    drive roots, `SystemRoot`, parent of `USERPROFILE`, `ProgramFiles`,
    `ProgramFiles(x86)`, and `ProgramData`. The mitigation exists
    because `ShareFolderBatchAsync` applies ACEs with subtree
    inheritance; the proper fix belongs in the OS API. See the region
    comment for removal conditions.
- `policy.filesystem.deniedPaths`, `policy.network`, `policy.ui`, and
  `policy.network.proxy` are rejected at every phase (one-shot via
  `validate_runner`, state-aware via `validate_<phase>` hooks).

### Fields valid in state-aware only

- `phase` — the discriminator. Required for state-aware; absent for one-shot.
- `sandboxId` — required for non-provision phases.
- `experimental.isolation_session.<phase>` — typed per-phase config blocks
  (`provision` carries optional `user`; `start` carries `configurationId` and
  optional `user`; `exec` / `stop` / `deprovision` use `()`).
- `experimental.isolation_session.{provision,start}.user` — Entra cloud-agent
  credentials. Honoured here; the same field on a one-shot `experimental.isolation_session`
  is rejected with `policy_validation`.

## Idempotence per phase

| Phase | Repeated call | Notes |
|---|---|---|
| provision | non-idempotent | Each provision mints a fresh `provisionId` / agent user. Two provision calls produce two distinct sandboxes. Acceptable: callers manage `sandboxId` state themselves. |
| start | OS-side dependent | Starting an already-started session surfaces an HRESULT from `StartSessionAsync`; mapped to `backend_error` (no specific MXC code). Callers should not call start twice; if they do, the second call's failure does not corrupt the first session. |
| exec | per-call | Each exec creates a fresh agent process via `RunProcessWithOptionsAsync`. No deduplication — repeated `commandLine` runs the command repeatedly. |
| stop | OS-side dependent | Stopping an already-stopped session surfaces an HRESULT from `StopSessionAsync`; mapped to `backend_error`. The cohort registration and agent user remain — only the running session is gone. |
| deprovision | becomes `stale_id` | After a successful deprovision, the agent user and registration are gone. A second deprovision on the same `sandboxId` triggers the OS-side `FindActiveAgentUserByProvisionId` lookup failure (`HRESULT_FROM_WIN32(ERROR_NOT_FOUND)`), which the runner maps to `MxcError::StaleId`. |

## Concurrency

### Multiple sandboxes

Distinct `sandboxId`s have distinct `provisionId`s (each minted by
`mint_random_token`). They share a single registration string (`"regid"`,
hardcoded by the `IsoSessionOps` wrapper). The OS-side service's
`RegisterApp` is idempotent for duplicate calls (returns
`ALREADY_REGISTERED` as success), so concurrent provisions all succeed.

### Multiple exec calls against the same sandbox

The runner's `exec` impl reuses the existing one-shot `create_process` path
synchronously: `manager.create_process(&options)` blocks until the agent
process exits and the relay drains. Two concurrent exec calls against the
same `sandboxId` from two `wxc-exec` processes are not coordinated by MXC;
the OS-side service serialises (or rejects, depending on session state) at
its own layer.

### Deprovision side-effect on concurrent sandboxes

`deprovision` calls both `deprovision_agent_user` and `unregister_client`.
The second call tears down the *shared* registration, so any other
concurrent state-aware sandbox using the same registration breaks at its
next op (sees `stale_id` from `FindClientIdentity` lookup failure). v1 does
not target concurrent state-aware sandboxes; if that becomes a real
requirement, this needs either reference-counting on the registration or a
"leave-registration-alone" deprovision mode.

## Error mapping

`IsolationSessionError` (the runner's internal categorisation) maps 1:1 to
wire-format `MxcError` codes via `map_lifecycle_error`:

| `IsolationSessionError` variant | Wire `error.code` | Trigger |
|---|---|---|
| `Policy(...)` | `policy_validation` | Caller-supplied policy field that this phase does not accept — see the honor matrix above. Rejected by `validate_<phase>` hooks (state-aware) or `validate_runner` (one-shot). |
| `ServiceUnavailable(...)` | `backend_unavailable` | `IsoSessionOps` activation failure: `IsoSessionApp.dll` not registered, or `Feature_IsoBrokerSessionApis` disabled at the OS-side. HRESULTs `CLASS_E_CLASSNOTAVAILABLE` (`0x80040111`) or `REGDB_E_CLASSNOTREG` (`0x80040154`). |
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

### `Small` configurationId

Selecting `configurationId: "small"` triggers a cache-teardown bug in the
OS-side service: the `RemoveUserAsync` call against a cached `Small` agent
user causes the service's RPC endpoint to disconnect with `0x800706be`
(`RPC_S_CALL_FAILED`), and subsequent calls fail until the service
restarts. `Composable` is unaffected. Use `composable` (the default).

### Concurrent state-aware sandboxes

See [Concurrency](#concurrency) — `deprovision` tears down the shared
registration and breaks any other in-flight state-aware sandbox. v1's
single-sandbox-per-consumer model is the workaround.

## References

- [State-aware design (full)](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md)
- [State-aware design (overview)](../state-aware-lifecycle/mxc-state-aware-sandbox-api-overview.md)
- [TypeScript initial plan](state-aware-typescript-initial-plan.md) — SDK companion
  to this doc; covers SDK API surface, types, and TS usage examples.
- [Initial bringup plan (one-shot)](initial-bringup-plan.md) — the
  predecessor doc for IsolationSession's first integration; this doc
  covers state-aware on top of that foundation.
