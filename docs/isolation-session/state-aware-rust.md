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
| start | `IsolationSessionStartConfig` | `()` |
| exec | `()` | (n/a — exec returns an exit code, not metadata) |
| stop | `()` | `()` |
| deprovision | `()` | `()` |

### Provision

**Config (`IsolationSessionProvisionConfig`):**

| Field | Type | Default | Description |
|---|---|---|---|
| `user` | `IsolationSessionUser` (object) \| absent | absent | Optional Entra cloud-agent credentials. When present, the UPN and WAM token are passed to `AddUserAsync` and the resulting sandbox is Entra-backed. When absent, provision calls `AddUserAsync` with empty strings and produces a local-agent sandbox. The bundle is `{ upn: string, wamToken: string }`; both fields required when supplied. `upn` is trimmed of surrounding whitespace both for the shape check and for the value handed to the OS, so validation and transmission cannot disagree. `wamToken` is passed verbatim to the OS-side service (it is an opaque bearer credential, so trimming could corrupt it) and never stored by MXC. The wire path is `experimental.isolation_session.provision.user`. |

| `appId` | string \| absent | absent | Optional identifier for the calling application. For a **packaged** application this is the Package Family Name; for an unpackaged one it may be any string. Carried verbatim inside the `sandboxId` (see below) so later phases recover it without the caller re-supplying it. **Nothing consumes it today** — it is accepted now so a future OS contract that acts on the calling application's identity does not require a breaking change. Validated **structurally only** (no control characters; at most 256 characters) — MXC is a pass-through carrier here and does not judge what a valid application identity looks like, so enforcing a PFN grammar would risk rejecting forms a future OS API accepts. Preserved verbatim: no trimming, no case folding, no normalisation. An explicitly-supplied **empty string is a distinct value from absent** and round-trips as such (a future OS API may assign it meaning, and MXC never synthesizes an empty string the caller did not send); JSON `null` is a second spelling of absent. Rejections surface as `policy_validation` from `validate_provision`, before any OS call. The wire path is `experimental.isolation_session.provision.appId`. |

**Metadata (`IsolationSessionProvisionMetadata`):**

| Field | Type | Description |
|---|---|---|
| `agentUserName` | string | The OS-assigned agent account name returned by `AddUserAsync`, also carried inside the `sandboxId` payload where it serves as the addressing key for every post-provision phase. Format is OS-internal and not stable across builds. |
| `agentUserSid` | string | The security identifier (SID) of the agent user, returned by `AddUserAsync`. Diagnostic only. |
| `ephemeralWorkspacePath` | string | A directory shared between the calling user and this isolated agent user, through which the caller can stage files into the session. Each isolated user can access only its own workspace; the caller can access every concurrent sandbox's workspace. Created at provision and deleted when the sandbox is deprovisioned. It does **not** change the workload's working directory. |

`appId` is deliberately **not** echoed in the metadata — the caller supplied
the value, so echoing it would be redundant surface.

#### The `sandboxId` format

```text
iso:<base64url-nopad( JSON object, UTF-8 )>
```

The `iso` prefix and the first `:` are the cross-backend routing contract; the
dispatcher reads only that much. Everything after it is this backend's private
payload — each backend defines its own tail format, and callers must continue to
treat the id as **opaque**. Extraction is internal to MXC.

**v1 payload:**

| Key | Type | Required | Description |
|---|---|---|---|
| `version` | integer | yes | Payload schema version. `1` today. |
| `agentUserName` | string | yes | The OS-assigned account name; the addressing key for every post-provision phase. |
| `appId` | string | no | The caller's `appId`. Absent key means absent. |

**Why an encoded payload rather than delimited segments.** The parser has to
know exactly which fields are present without relying on any assumption about
separator characters. The `agentUserName` is OS-assigned and its format is
explicitly not guaranteed stable, so no charset assumption about it is safe —
a delimited form would mis-parse a name containing the delimiter *silently*.
The base64url alphabet (`A-Z a-z 0-9 - _`) provably contains no `:`, no path
separator, no shell metacharacter, no whitespace and no NUL, which makes the
whole class of separator and path-traversal bugs unrepresentable rather than
merely prevented by careful parsing.

**The envelope is frozen.** The tail is *always* base64url-nopad of a JSON
object. The envelope itself is not versioned and will not change; all evolution
happens as keys inside the JSON. If it ever genuinely had to change, that is a
hard break handled by a new prefix or a coordinated rollout, not by carrying an
outer version segment indefinitely against a remote contingency.

**Versioning rules.** The `version` gate is one-directional: a payload *newer*
than the reader understands is rejected (with a message saying so, because the
remediation is "upgrade MXC", not "this id is corrupt"); an *older* one is the
reader's choice. Bump `version` **only** for a change an old reader must not
silently mishandle — adding an optional key does **not** bump it, since a
version that moved on every additive change would reject ids old readers could
have handled. Unknown keys are ignored on decode, so additive evolution is
transparent.

**Determinism.** The payload is serialised from a struct rather than a map, so
key order is fixed and the same content always yields the same id string.

**Legacy ids.** Ids minted before this format (`iso:<agentUserName>` in the
clear) no longer decode and surface as `malformed_id` on every phase that takes
an id. **Both** the running session and the agent user account survive a binary
upgrade: nothing in MXC tears either down when the executable is replaced, and
outliving the process is the premise of the whole state-aware lifecycle — `exec`
runs in a different process from `start` and addresses the same live session. A
session ends at an explicit `stop`, or when `deprovision` removes the agent user
(which terminates any session still running under it). A sandbox provisioned by
an older binary should therefore be stopped and deprovisioned **before**
upgrading.

The *legacy id string* becomes unusable, but the sandbox itself does not become
unreachable: the payload binds nothing to the binary that minted it, so
re-encoding the old agent user name as a current payload
(`{"version":1,"agentUserName":"<old-name>"}`, base64url) produces a valid id
that addresses the same sandbox. For a legacy id this needs nothing recorded in
advance — the old format is `iso:<agentUserName>` **in the clear**, so the name
is readable straight from the stranded id. (Provision also returns it as
`agentUserName` metadata.) It is a recovery procedure rather than a supported
migration path, but it means a sandbox stranded by an in-place upgrade can
always be cleaned up through MXC.

### Start

**Config (`IsolationSessionStartConfig`):**

| Field | Type | Default | Description |
|---|---|---|---|
| `user` | `IsolationSessionUser` (object) \| absent | absent | Optional. Supply for an Entra sandbox to re-provide the WAM token (the `sandboxId` payload does not carry it); omit for a local sandbox. When supplied it is shape-validated (`upn` contains `@`, `wamToken` non-empty) by `validate_start`, surfacing shape errors as `policy_validation`; the OS validates the token against the agent user assigned at provision. The wire path is `experimental.isolation_session.start.user`. |

The one-shot surface takes **no backend configuration at all**. `user` is
state-aware-only, so on a one-shot request it is simply an unrecognised key in
the deliberately permissive `experimental` block and is ignored — the run
proceeds as a local (non-Entra) agent.

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
`readonlyPaths`, `deniedPaths`) at every phase — provision included. The
backend has no host-folder-sharing primitive, so there is nothing to honor.

The container's network is unrestricted (outbound open; a process inside can
listen on a port reachable from outside via localhost) and MXC has no
primitive to filter or deny it. So the network policy is honesty-gated rather
than silently accepted: **provision** (and one-shot) accept only the canonical
unrestricted-network acknowledgment — `defaultPolicy=allow` +
`allowLocalNetwork=true`, no `allowedHosts`/`blockedHosts`, no proxy, default
enforcement — and refuse anything else, including an absent policy (which
defaults to the unenforceable `block`). On the **post-provision** phases the
network posture is fixed at provision, so any supplied network policy is
rejected and an absent one is inherited.

UI policy is rejected at every phase, on both surfaces, and **no `ui` posture is
truthful for this backend** — there is no value combination that could be
accepted instead.

The section states *intent about the contained code's relationship to the user's
environment*, and it was modelled on a process/job boundary, where "the
clipboard" and "the desktop" are the user's. An isolation session is a *separate
OS session*: it isolates the host's UI from the contained code, but does not deny
the contained code UI capabilities within its own session. Measured inside a live
session, window creation, GDI, and the session's own clipboard all work; only
input injection is blocked. Field by field:

| Field | What it asserts | In an isolation session |
|---|---|---|
| `disable: true` | no window creation, no GDI, no `NtUser*`/`NtGdi*` | false — all of it works |
| `disable: false` | may drive a GUI the user can see | false — windows are unreachable and invisible |
| `clipboard: none` / `read` / `write` | a specific relationship to the user's clipboard | false — reaches only the session's own, in both directions |
| `clipboard: all` | may read and write the user's clipboard | false — same reason |
| `injection: false` | no synthetic input | **true** — `SendInput` returns `ERROR_ACCESS_DENIED` |
| `injection: true` | may inject synthetic input | false — injection is blocked regardless |

Only `injection: false` is honest, and it cannot be expressed on its own: the
other two fields materialize to defaults that are both false here. So there is
nothing to accept, and no acknowledgment-style gate is possible — unlike
`network`, where the canonical unrestricted acknowledgment *is* a true statement
about the container.

Accepting a `ui` block would also assert the Win32k attack-surface reduction that
`disable: true` implies. That one is not a boundary property at all: a Win32k
kernel exploit escapes a session exactly as it escapes a job, and session
isolation does nothing for it.

**An omitted `ui` is accepted, and applies no restriction.** The schema's
default-deny reading ("an omitted `ui` is equivalent to full lockdown") does
**not** hold on this backend. The asymmetry with the network gate — which
*requires* a positive acknowledgment and refuses an absent policy — is
deliberate, and rests on how the two defaults fail. An absent `network` defaults
to `block` while the container's network is genuinely open to the outside world,
so the caller is exposed and must acknowledge it. An absent `ui` defaults to
lockdown while the contained code's UI reach never leaves its own session, so
nothing is exposed to acknowledge. Absence is also not a caller statement of
intent; refusing it would fail every request that omits the section, which is
ceremony rather than a control.

The only caller-supplied knob the backend accepts beyond the network
acknowledgment is the optional Entra `user` bundle, at provision and start.

The matrix covers the full surface a caller can express, on both the one-shot
and state-aware paths. Dispositions come from the closed set in §10.3 of the
[state-aware design](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md),
plus `required` for the network acknowledgment and `n/a` where a field has no
meaning for this backend.

| Field | one-shot | provision | start | exec | stop | deprovision |
|---|---|---|---|---|---|---|
| `policy.filesystem.{readwritePaths,readonlyPaths}` | rejected | rejected | rejected | rejected | rejected | rejected |
| `policy.filesystem.deniedPaths` | rejected | rejected | rejected | rejected | rejected | rejected |
| `policy.network` — canonical `allow` acknowledgment (`defaultPolicy=allow` + `allowLocalNetwork=true`, no host rules, no proxy, default enforcement) | **required** | **required** | rejected | rejected | rejected | rejected |
| `policy.network` — any other **supplied** value (host rules, proxy, `defaultPolicy=block`) | rejected | rejected | rejected | rejected | rejected | rejected |
| `policy.network` — **absent** | rejected (defaults to the unenforceable `block`) | rejected (same) | inherited from provision | inherited | inherited | inherited |
| `policy.ui` | rejected | rejected | rejected | rejected | rejected | rejected |
| `lifecycle.destroyOnExit` | `true` accepted; `false` rejected | rejected (whole section) | rejected | rejected | rejected | rejected |
| `lifecycle.preservePolicy` | `false` accepted; `true` rejected | rejected (whole section) | rejected | rejected | rejected | rejected |
| `fallback.allowDaclMutation` | n/a | n/a | n/a | n/a | n/a | n/a |
| `containerId` | accepted, no effect | accepted, no effect | accepted, no effect | accepted, no effect | accepted, no effect | accepted, no effect |
| `process.commandLine` | **honored** | accepted, ignored | accepted, ignored | **honored** | accepted, ignored | accepted, ignored |
| `process.{cwd,env,timeout}` | **honored** | accepted, ignored | accepted, ignored | **honored** | accepted, ignored | accepted, ignored |
| `experimental.isolation_session.user` (flat) | accepted, ignored | accepted, ignored | accepted, ignored | accepted, ignored | accepted, ignored | accepted, ignored |
| `experimental.isolation_session.<this phase>.user` | accepted, ignored | **honored** | **honored** | n/a | n/a | n/a |
| `experimental.isolation_session.provision.appId` | accepted, ignored | **honored** | n/a | n/a | n/a | n/a |
| `experimental.isolation_session.<another phase>.*` | accepted, ignored | accepted, ignored | accepted, ignored | accepted, ignored | accepted, ignored | accepted, ignored |
| `processContainer` / `lxc` / `seatbelt` (stable sections) | rejected | rejected | rejected | rejected | rejected | rejected |
| another backend's `experimental.<backend>` section | rejected | rejected | accepted, ignored if it is the only one | accepted, ignored if the only one | accepted, ignored if the only one | accepted, ignored if the only one |

Notes on the rows that are not a simple accept/reject:

- **`lifecycle`** is refused by *value* on one-shot and by *section* on
  state-aware. The in-proc API exposes no session-lifetime knob: one-shot always
  stops the session and removes the agent user before returning, which is
  exactly what `destroyOnExit: true` (the default) asks for — so the default is
  honest and accepted. `destroyOnExit: false` asks the session to outlive the
  call and cannot be delivered; `preservePolicy: true` is meaningless because
  filesystem and network policy are rejected outright, leaving nothing to
  preserve. On the state-aware path the parser rejects the whole `lifecycle`
  section for every backend, so no per-value handling applies.
- **`fallback`** is `n/a` rather than `rejected`. `allowDaclMutation` gates an
  AppContainer-only DACL fallback this backend never performs, so either value
  is vacuously satisfied and neither asserts anything untrue. Bringing it under
  the single-backend-section check uniformly across backends is tracked
  separately.
- **A lone foreign `experimental.<backend>` section on a non-provision phase** is
  accepted and ignored, not rejected. Those requests carry no `containment`, so
  `validate_experimental_backend_keys` has no resolved backend to compare
  against; it rejects two or more foreign keys as unambiguously wrong but
  tolerates exactly one. The *stable* sections (`processContainer`, `lxc`,
  `seatbelt`) are rejected on every phase by the separate stray-section check.
  Closing the lone-foreign-key case requires resolving the backend from the
  `sandboxId` prefix, which is cross-backend work tracked separately.
- **`containerId`** is a caller-supplied label, not a restriction. This backend
  addresses sandboxes by the OS-assigned agent user name, so the field has no
  effect and ignoring it asserts nothing.
- **`process` on non-exec state-aware phases** is accepted and ignored. The
  dispatcher reads `process` only on `exec`, so a `commandLine`, `cwd`, `env` or
  `timeout` supplied at provision / start / stop / deprovision has no effect and
  no error. Nothing runs at those phases, so nothing is lost — but the request is
  not what the caller believes it is. Supply `process` only on `exec`.
- **Mis-slotted `experimental.isolation_session` payloads are accepted and
  ignored, not rejected.** `deserialize_config` navigates exactly
  `experimental.<backend>.<the request's own phase>`; anything else in that block
  is read by nothing. Three shapes reach that state:
  - the flat `experimental.isolation_session.user` on either surface (it is not
    a field of any config type — the one-shot surface takes no backend
    configuration, and state-aware reads `user` only from the request's own
    phase block);
  - a nested `provision` / `start` block on a *one-shot* request;
  - a block under a phase that is not this request's phase, e.g.
    `{"phase": "start", …, "isolation_session": {"provision": {…}}}`.

  Each is a caller supplying a documented field in an undocumented position, and
  the resulting sandbox is *local* rather than Entra-backed. That is a capability
  downgrade rather than an escalation — the local agent user is more restricted —
  and it surfaces downstream as an authentication failure. Detecting mis-slotted
  payloads generically is a cross-backend concern and is deliberately not solved
  here. Nest the bundle under the request's own phase; the SDK already does.

Rejection of `policy.*` fields surfaces on the **state-aware** surface as
`error.code = "policy_validation"`. On the **one-shot** surface the typed variant
is discarded (`ScriptResponse::error`) and the envelope carries
`error.code = "backend_error"` with the reason in the message; one-shot has no
typed policy code today. A malformed `user` shape (UPN missing `@`, empty
`wamToken`) likewise surfaces as `policy_validation`, as does a structurally
invalid `appId`. Start does not cross-check the `user` bundle against the
`sandboxId` payload — the payload carries no Entra marker — so there is no
identity-mismatch `malformed_request` path; the OS validates the WAM token
against the agent user it assigned at provision.

## Mode-specific fields

### Fields valid in both modes

- `process.commandLine` — required for one-shot and for state-aware exec;
  accepted and ignored at non-exec state-aware phases (the dispatcher reads
  `process` only on `exec`, and nothing runs at the other phases).
- `process.cwd`, `process.env`, `process.timeout` — optional in both modes,
  honoured per-process (each exec receives its own block).

### Policy fields and mode parity

Both modes share the same policy matrix above. Every `policy.filesystem`
field (`readwritePaths`, `readonlyPaths`, `deniedPaths`) is rejected at every
phase (no host-folder-sharing primitive). `policy.ui` is likewise rejected at
every phase (no UI-restriction primitive). The network policy is honesty-gated
per the matrix — provision requires the canonical unrestricted-network
acknowledgment and post-provision rejects any supplied network policy
(inheriting an absent one). One-shot enforces all of this via `validate_runner`;
state-aware enforces it via the `validate_<phase>` hooks.

The one asymmetry is `lifecycle`: one-shot refuses it by value (the defaults
match what the backend actually does), while the state-aware parser refuses the
whole section for every backend. See the matrix notes above.

### Fields valid in state-aware only

- `phase` — the discriminator. Required for state-aware; absent for one-shot.
- `sandboxId` — required for non-provision phases.
- `experimental.isolation_session.<phase>` — typed per-phase config blocks
  (`provision` carries optional `user`; `start` carries optional `user`;
  `exec` / `stop` / `deprovision` use `()`).
- `experimental.isolation_session.{provision,start}.user` — Entra cloud-agent
  credentials. Honoured here. The one-shot surface takes no backend
  configuration at all, so the same field on a one-shot
  `experimental.isolation_session` is an unrecognised key in the permissive
  `experimental` block and is accepted and ignored.

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
| `ServiceUnavailable(...)` | `backend_unavailable` | Activation failure of the in-proc IsolationSession runtime API: it is unavailable on this OS build (not registered, or the OS feature gate is off). HRESULTs `CLASS_E_CLASSNOTAVAILABLE` (`0x80040111`) or `REGDB_E_CLASSNOTREG` (`0x80040154`). |
| `Stale(...)` | `stale_id` | The OS service reports `HRESULT_FROM_WIN32(ERROR_NOT_FOUND)` (`0x80070490`) — the agent user is unknown to it. After `deprovision`, every non-provision op against the dead `sandboxId` triggers this. |
| `Lifecycle(...)` | `backend_error` | Any other failure of a lifecycle op, whether the API reported it semantically or the call itself could not be completed. |

### Structured failure fields

The components of an API failure travel as **discrete fields** on the wire error
envelope — `operation`, `nativeCode` and `remediation` — rather than being concatenated
into `message`. `message` holds the bare human-readable text; for a semantic API failure
that is the API's own message, passed through verbatim.

| Failure | `operation` | `nativeCode` | `remediation` |
|---|---|---|---|
| Semantic API failure (the call completed and reported an error) | ✅ | ✅ | when the API supplies one |
| Transport failure (the call could not be completed, or a result property could not be read) | ✅ | ✅ | — |
| Activation failure (`backend_unavailable`) | ✅ | ✅ | — |
| The API's status code itself could not be read | ✅ | — | best-effort |
| MXC-internal failure (relay threads, console handles) | — | — | — |
| `Policy` and the MXC-side `malformed_*` rejections | — | — | — |

**Invariant:** `nativeCode` implies `operation`, and `remediation` implies `operation`.
`operation` marks that an API operation was in flight; neither refinement appears alone.

`operation` is the interface-qualified member name — for example
`IsoSessionOps.StopSessionAsync`. It is deliberately low-cardinality and free of call
parameters (a failing environment-variable insert names the variable in `message`, not
in `operation`) so that consumers can aggregate on it. Where a lifecycle call succeeds
but reading one of its result properties fails, `operation` stays the lifecycle call and
the finer step is described in `message`.

These values are **best-effort diagnostics, not a versioned contract**: they mirror the
projected WinRT class and method names, which this repo does not own. Branch on `code`;
treat `operation` as telemetry and log detail. See the
[cross-backend contract](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md) §7.3.

`nativeCode` is the HRESULT rendered as lowercase hex, e.g. `0x80070490`.

`message` is the API's own text, passed through verbatim, and is never empty: when the
API reports a failure without a message, a short stand-in is substituted, because the
operation and status now live in their own fields and no longer backfill it.

`error.details` is unused by this backend. It remains the escape hatch for
backend-specific structured data that has no cross-backend meaning; the three named
fields above are backend-neutral and so live on the envelope itself.

### The `stale_id` promotion is semantic-path only

`ERROR_NOT_FOUND` is promoted to `stale_id` **only** when it arrives through the API's
semantic error channel, and **only** for non-provision operations.

- *Semantic only:* the in-proc client maps its internal codes to standard HRESULTs when
  it builds the error object, and that mapping is what gives `0x80070490` the meaning
  "agent user not provisioned". The same value arriving as a transport failure has no
  such provenance — it could be any "not found" from activation or RPC — so promoting it
  would emit a false `stale_id`, whose remediation is "re-provision; treat the id as
  dead", and destroy a healthy sandbox.
- *Non-provision only:* provision mints the agent user. There is no `sandboxId` yet, so
  reporting a stale one would be incoherent.

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
