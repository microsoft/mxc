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

### In-process callers reach the same lifecycle

The Rust SDK (`mxc-sdk`) and the C ABI over it (`mxc_ffi`), each with an
`isolation_session` feature, take the same phases and the same request JSON as
`wxc-exec`; only the entry point differs.

| Phase | `wxc-exec` | In-process |
|---|---|---|
| provision / start / stop / deprovision | `wxc-exec --config …` | `mxc_sdk::run_state_aware_json`, `mxc_state_aware` |
| exec, attached to the caller's stdio | `wxc-exec --config …` | `mxc_sdk::exec_attached`, `mxc_state_aware_exec_attached` |
| exec, caller drives the pipes | *(no CLI equivalent)* | `mxc_sdk::exec_sandbox`, `mxc_state_aware_exec` |

Requirements on an in-process caller:

- **Both stdout and stdin must be terminals**, or the attached exec path
  refuses. On a terminal it allocates a pseudo-console inside the sandbox, so an
  embedding console application gets a working interactive shell. Use the
  streaming entry point for a workload with no terminal.
- **Only one attached exec at a time per process.** A second concurrent call is
  refused.
- **An attached exec takes over this process's console for its duration**:
  raw VT, so no echo, no line input, and keystrokes — `Ctrl-C` included — go to
  the sandboxed workload rather than to this process. Restored on return.
- **`start` cannot run from Session 0.** `StartSessionAsync` fails with
  *"requires an interactive session"* (`0x80040233`), so a caller running as a
  service, or over a remote SYSTEM-context shell, cannot complete the lifecycle.
  `provision` succeeds first and mints an OS account that must be deprovisioned.
- **A caller in a single-threaded apartment is refused.** Any other caller enters
  a multi-threaded apartment held for the manager's lifetime and balanced on
  drop. A UI application must marshal onto a background thread.
  `mxc-sdk/examples/sta_probe.rs` measures this against a live host.

The **one-shot** surface is not reachable in-process: `mxc_sdk::run` and
`spawn_sandbox` return `unsupported_containment`.

### Out of scope (for v1)

- **Explicit `AbortSignal` plumbing.** v1 cancellation is OS-level: the
  caller kills `wxc-exec.exe`, the OS-side service's per-process timer or
  the existing 3-tier shutdown (close stdin → `SendCtrlClose` → `Terminate`)
  reaps the agent. See [Cancellation](#cancellation) below.
- **Concurrent state-aware sessions.** v1 targets a single state-aware
  sandbox per consumer. This is a scoping choice, not an OS limitation — see
  [Concurrent state-aware sandboxes](#concurrent-state-aware-sandboxes).

## Per-phase config and metadata shapes

The `StatefulSandboxBackend` impl on `IsolationSessionRunner` declares
associated types for each phase. Phases without a config use `()`; phases
without metadata use `()`.

| Phase | `*Config` | `*Metadata` |
|---|---|---|
| provision | `IsolationSessionProvisionConfig` | `IsolationSessionProvisionMetadata` |
| start | `()` | `()` |
| exec | `()` | (n/a — exec returns an exit code, not metadata) |
| stop | `()` | `()` |
| deprovision | `()` | `()` |

### Provision

**Config (`IsolationSessionProvisionConfig`):**

| Field | Type | Default | Description |
|---|---|---|---|
| `appId` | string \| absent | absent | Optional identifier for the calling application, associating the provisioned agent user with its owning app. **A packaged application must supply its Package Family Name in the form `PFN:<packageFamilyName>`** (for example `PFN:Contoso.App_8wekyb3d8bbwe`). An unpackaged application may pass any string. Carried inside the `sandboxId` so later lifecycle phases can recover it without the caller re-supplying it. Validated **structurally only** (no control characters; at most 256 characters) — MXC does not judge what a valid application identity looks like, so enforcing a PFN grammar would risk rejecting forms a future OS API accepts. There is no trimming, case folding, or normalisation. An explicitly-supplied **empty string is a distinct value from absent** and round-trips as such; JSON `null` is a second spelling of absent. Rejections surface as `policy_validation` from `validate_provision`, before any OS call. The wire path is `experimental.isolation_session.provision.appId`. |

**Metadata (`IsolationSessionProvisionMetadata`):**

| Field | Type | Description |
|---|---|---|
| `agentUserName` | string | The OS-assigned agent account name returned by the selected `AddUser` overload (`AddUserAsync2`, or `AddUserAsync` on hosts without app-scoped support), also carried inside the `sandboxId` payload where it serves as the addressing key for every post-provision phase. Format is OS-internal and not stable across builds. |
| `agentUserSid` | string | The security identifier (SID) of the agent user, returned by the selected `AddUser` overload (`AddUserAsync2`, or `AddUserAsync` on hosts without app-scoped support). Diagnostic only. |
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

**Upgrading with live sandboxes.** **Both** the running session and the agent
user account survive a binary upgrade: nothing in MXC tears either down when the
executable is replaced, and outliving the process is the premise of the whole
state-aware lifecycle — `exec` runs in a different process from `start` and
addresses the same live session. A session ends at an explicit `stop`, or when
`deprovision` removes the agent user (which terminates any session still running
under it). An id the running build cannot decode is refused as `malformed_id` on
every phase that takes one, and a sandbox left behind that way cannot be
addressed through MXC afterwards — so stop and deprovision **before** replacing
the executable.

### Start

**Config (none).** Start takes only the `sandboxId`; it accepts no per-phase
payload. The one-shot surface likewise takes **no backend configuration at
all**, so anything under `experimental.isolation_session` there is simply an
unrecognised key in the deliberately permissive `experimental` block and is
ignored.

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
acknowledgment is the optional `appId`, at provision.

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
  is read by nothing. Two shapes reach that state:
  - a nested `provision` block on a *one-shot* request;
  - a block under a phase that is not this request's phase, e.g.
    `{"phase": "start", …, "isolation_session": {"provision": {…}}}`.

  Each is a caller supplying a documented field in an undocumented position, so
  the value is silently not applied. Detecting mis-slotted
  payloads generically is a cross-backend concern and is deliberately not solved
  here. Nest the config under the request's own phase; the SDK already does.

The exact `0.9.0-alpha` state-aware request roots reject structurally excluded
fields before backend validation. For example, supplied `ui`, noncanonical
provision `network` shapes, and policy on phases that do not define it surface
as `malformed_request`. Requests that pass the exact structural contract but
violate a backend semantic invariant surface as `policy_validation`; a
structurally valid but oversized `appId` is one such case.

On the **one-shot** surface the backend's typed policy variant is discarded
(`ScriptResponse::error`) and the envelope carries `error.code =
"backend_error"` with the reason in the message. A supplied `network.proxy` is
also structurally refused as `malformed_request`.

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
  (`provision` carries optional `appId`; `start` / `exec` / `stop` /
  `deprovision` use `()`).
- `experimental.isolation_session.provision.appId` — the calling application's
  identifier. Honoured here. The one-shot surface takes no backend
  configuration at all, so the same field on a one-shot
  `experimental.isolation_session` is an unrecognised key in the permissive
  `experimental` block and is accepted and ignored.

## Idempotence per phase

| Phase | Repeated call | Notes |
|---|---|---|
| provision | non-idempotent | Each provision mints a fresh agent user. Two provision calls produce two distinct sandboxes. Acceptable: callers manage `sandboxId` state themselves. |
| start | OS-side dependent | Starting an already-started session surfaces an HRESULT from `StartSessionAsync`; mapped to `backend_error` (no specific MXC code). Callers should not call start twice; if they do, the second call's failure does not corrupt the first session. |
| exec | per-call | Each exec creates a fresh agent process via `RunProcessWithOptionsAsync`. No deduplication — repeated `commandLine` runs the command repeatedly. |
| stop | OS-side dependent | Stopping an already-stopped session surfaces an HRESULT from `StopSessionAsync`; mapped to `backend_error`. The agent user remains — only the running session is gone. |
| deprovision | becomes `stale_id` | After a successful deprovision, the agent user is gone. A second deprovision on the same `sandboxId` fails the OS-side agent-user lookup (`HRESULT_FROM_WIN32(ERROR_NOT_FOUND)`), which the runner maps to `MxcError::StaleId`. |

## Concurrency

### Multiple sandboxes

Distinct `sandboxId`s map to distinct OS agent users (each provisioning call —
`AddUserAsync2`, or `AddUserAsync` on hosts without app-scoped support — mints a
fresh account). There is no shared registration between them, so
concurrent provisions are independent and all succeed.

### Multiple exec calls against the same sandbox

The runner's `exec` impl blocks under **`Relayed`**: it reuses the
one-shot `create_process` path, and that call runs until the agent process
exits and the relay drains. Under **`Piped`** it starts the
process and returns without waiting, handing back the live pipe handles and a
waiter, so the caller decides when to block. Either way, two concurrent exec
calls against the same `sandboxId` are not coordinated by MXC; the OS-side
service serialises (or rejects, depending on session state) at its own layer.

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
| `Policy(...)` | `policy_validation` | A structurally representable request violates a backend semantic invariant — see the honor matrix above. Rejected by `validate_<phase>` hooks (state-aware) or `validate_runner` (one-shot); fields excluded by an exact request root fail earlier as `malformed_request`. |
| `ServiceUnavailable(...)` | `backend_unavailable` | Activation failure of the in-proc IsolationSession runtime API: it is unavailable on this OS build (not registered, or the OS feature gate is off). HRESULTs `CLASS_E_CLASSNOTAVAILABLE` (`0x80040111`) or `REGDB_E_CLASSNOTREG` (`0x80040154`). |
| `Stale(...)` | `stale_id` | The OS service reports `HRESULT_FROM_WIN32(ERROR_NOT_FOUND)` (`0x80070490`) — the agent user is unknown to it. After `deprovision`, every non-provision op against the dead `sandboxId` triggers this. |
| `Lifecycle(...)` | `backend_error` | Any other failure of a lifecycle op, whether the API reported it semantically or the call itself could not be completed. |

### Structured failure fields

The components of a failure travel as **discrete fields** on the wire error envelope —
`operation`, `nativeCode` and `remediation` — rather than being concatenated into
`message`. `message` holds the bare human-readable text; for a semantic API failure that
is the API's own message, passed through verbatim.

| Failure | `operation` | `nativeCode` | `remediation` |
|---|---|---|---|
| Semantic API failure (the call completed and reported an error) | ✅ | ✅ | when the API supplies one |
| Transport failure (the call could not be completed, or a result property could not be read) | ✅ | ✅ | — |
| Activation failure (`backend_unavailable`) | ✅ | ✅ | — |
| The API's status code itself could not be read | ✅ | — | best-effort |
| Single-threaded-apartment refusal | — | — | ✅ |
| MXC-internal failure (relay threads, console handles) | — | — | — |
| `Policy` and the MXC-side `malformed_*` rejections | — | — | — |

**Invariant:** `operation` marks that an API operation was in flight.

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
operation and status live in their own fields rather than being folded into the message.

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

- On the `wxc-exec` route, cancellation is process termination.
- The agent process's pipes EOF, the relay threads exit.
- The OS-side service's per-process timer (set from
  `process.timeout`) reaps the agent if the runner does not. On the
  streaming path that timer is armed with a **margin** past the caller's
  deadline, so it acts purely as a watchdog: the service kills with an
  ordinary exit code (the host suite pins it as exit code 1), so if it
  fired first a genuine timeout would be indistinguishable from a normal
  exit and could not be reported as one. The run-to-completion path arms
  it unchanged — it has no timeout channel to report through.
- The runner's existing 3-tier shutdown (`CloseStandardInput` →
  `SendCtrlClose` → `Terminate`) handles the timeout case from inside the
  agent process before returning.

`ExecHandle.terminator` is a no-op closure on the IsolationSession path
under `Relayed`, which reuses the one-shot
`create_process` synchronously and so has no mid-flight cancellation
seam. Under `Piped` the backend instead starts the process
without waiting and returns a terminator that calls
`IsoSessionProcess::Terminate()`, alongside the real pipe handles and a
waiter that blocks on exit.

That terminator now reports whether the platform **accepted** the kill:
`ExecHandle.terminator` returns a `Result`, and the answer
`StartedProcess::terminate` already computed reaches the caller through
`SandboxProcess::kill`. What it still cannot say is whether the process
actually died — that would need the bounded post-kill wait's result,
which the handle type does not carry.

The waiter likewise distinguishes a timeout from an exit, returning
`ExecOutcome::TimedOut` when the deadline elapsed while the process was
running. Neither available signal proves that on its own: `WaitForExit`
answers `-1` on timeout and `ExitCode()` reads `STILL_ACTIVE` (259), and
both are legal exit codes for untrusted code. Their conjunction
establishes whether the process was still running when it was sampled,
which is what the ladder decision needs.

A spent deadline is **sticky**. The two reads are not atomic, so a
process can exit in the window between them; that still reports
`TimedOut`, because the sentinel proves the deadline elapsed while the
process ran and a later-observed exit code does not un-spend it.
Reporting that code would hide a missed deadline from a caller who asked
for one. The sibling WSLc backend draws the same line, tracking
`deadline_elapsed` separately from `timed_out`. The one irreducible case
is `-1`/`-1`, where the sentinel and the exit code collide and nothing
distinguishes them, so it is read as the exit.

`TimedOut` promises the process is **gone**, not that MXC killed it, and
it reaches only the foreground process: `IsoSessionProcess` exposes
`Terminate` and `ExitCode` and no tree primitive, so a descendant the
workload backgrounded outlives a reported timeout on either path and is
reclaimed when the session is stopped and deprovisioned.

An exited process is never routed through the shutdown ladder, which reads only `ExitCode()`
and so cannot tell a `259` exit from a live process. The adapter maps
`TimedOut` onto `ErrorKind::TimedOut`, which is what
`mxc_sdk::Sandbox::wait` reads as `WaitOutcome::TimedOut`. That outcome
is reachable only under `Piped`; the `Relayed` arm reports `Exited`.

Teardown is bounded only insofar as the kill is: the streaming adapter's
`Drop` joins the waiter when the kill was accepted, and abandons the
thread when it was refused rather than blocking forever in a `Drop` the
caller cannot opt out of. A process that survives an *accepted* kill can
still park that waiter by either of
two routes — in its leading `WaitForExit` (INFINITE when the caller
supplied no timeout), or, when a timeout was supplied, in the graceful
ladder's tier 3, which is `Terminate` followed by an INFINITE
`WaitForExit(0)`. Neither is certain to stall: tier 3's `Terminate` is a
fresh attempt that may land where the first did not. The narrow claim is
that nothing bounds the
join if the process does survive. The terminator is now fallible end to
end, so a *refused* kill is reported and the join is skipped; bounding
the join after an *accepted* kill that never took effect is future work,
and needs the backend to confirm the process actually died. A **confirmed
exit** retires the terminator entirely: once the waiter has reported an
outcome there is nothing to kill, so `kill` succeeds without running the
terminator and an earlier refusal no longer applies.

## Known issues

### Concurrent state-aware sandboxes

v1 targets a single state-aware sandbox per consumer (see the
[Out of scope](#out-of-scope-for-v1) note). Each sandbox is an independent OS
agent user with no shared registration, so this is a v1 scoping choice, not an
OS limitation.

## References

- [State-aware design (full)](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md)
- [State-aware design (overview)](../state-aware-lifecycle/mxc-state-aware-sandbox-api-overview.md)
- [TypeScript spec](state-aware-typescript.md) — SDK companion
  to this doc; covers SDK API surface, types, and TS usage examples.
- [One-shot bringup](oneshot.md) — the
  predecessor doc for IsolationSession's first integration; this doc
  covers state-aware on top of that foundation.
