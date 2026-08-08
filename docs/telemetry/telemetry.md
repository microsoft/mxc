# MXC Telemetry — Pure Rust TraceLogging Architecture

MXC uses the Rust [`tracelogging`](https://crates.io/crates/tracelogging) crate
(published by Microsoft) for TraceLogging ETW telemetry. No C++ shim, WIL, or
FFI is required.

> **Not to be confused with the local audit log.** MXC also writes structured
> **local diagnostic audit records** that are *not* ETW, *not* uploaded, and
> *not* consent-gated. They are a separate mechanism with a separate sink; see
> [Local audit log records](#local-audit-log-records) below. Nothing in that
> section touches the `Microsoft.MXC` provider described here.

## Overview

```
┌──────────────────────────────────────────────────────┐
│  wxc_common::telemetry                               │
│  (Rust — config resolution, sanitisation, types)     │
│                                                      │
│  init() / log_execution() / log_error() / shutdown() │
└───────────────┬──────────────────────────────────────┘
                │  Direct Rust function calls
                ▼
┌──────────────────────────────────────────────────────┐
│  mxc_telemetry (Rust crate)                          │
│  src/lib.rs — define_provider! + write_event!        │
│                                                      │
│  Windows: ETW events via tracelogging crate          │
│  Linux/macOS: no-op stubs                            │
└──────────────────────────────────────────────────────┘
```

## Why the Rust `tracelogging` Crate (Not WIL C++ Shim)

An earlier design used a WIL C++ shim compiled via the `cc` crate. PR review
feedback correctly noted that the WIL dependency added C++ compilation, NuGet
download, FFI unsafety, and blocked non-Windows contributors from building the
crate. The Rust `tracelogging` crate provides the core ETW primitives needed,
and the small set of WIL features MXC actually uses can be replicated with
Rust constants and `write_event!` struct fields.

### Feature comparison

| Feature | WIL (`wil/TraceLogging.h`) | Rust `tracelogging` crate | MXC approach |
|---|---|---|---|
| **Provider group GUID** | `TraceLoggingOptionMicrosoftTelemetry()` | `group_id("...")` in `define_provider!` | `build.rs` generates `provider_def.rs` with/without `group_id` based on env var |
| **Sampling keywords** | `MICROSOFT_KEYWORD_MEASURES` named constant | Raw `u64` in `keyword(...)` | `const MICROSOFT_KEYWORD_MEASURES: u64 = 0x0000_4000_0000_0000` |
| **Common event fields** | `_GENERIC_PARTB_FIELDS_ENABLED` pattern | `struct("Name", { ... })` in `write_event!` | `struct("COMMON_MXC_PARAMS", { Version, Channel, IsDebugging, UTCReplace_AppSessionGuid })` |
| **Provider lifecycle** | `IMPLEMENT_TRACELOGGING_CLASS` singleton | `define_provider!` static + `register()`/`unregister()` | `OnceLock<ProviderState>` for version/channel, manual lifecycle |
| **Privacy Data Tags** | `TelemetryPrivacyDataTag(PDT_*)` | `u64("PartA_PrivTags", &val)` field | `PDT_PRODUCT_AND_SERVICE_USAGE` on all events |
| **Activity tracking** | `DEFINE_TELEMETRY_ACTIVITY` | Manual `Opcode` | Not needed for current events |

The remaining gap (activity tracking) is not needed for current events.
If needed later, it can be added incrementally.



## Common Event Fields (Part C)

Every MXC telemetry event includes a `COMMON_MXC_PARAMS` struct grouping
shared Part C custom event fields:

| Field | Type | Description |
|-------|------|-------------|
| `Version` | string | MXC crate version from `CARGO_PKG_VERSION` |
| `Channel` | string | `"dev"` for debug builds, `"release"` for release |
| `IsDebugging` | bool | `cfg!(debug_assertions)` — true for debug builds |
| `UTCReplace_AppSessionGuid` | bool | Always `true` — tells UTC to replace the app session GUID with a per-session identifier for privacy |

## Events

### MXC.Execution

Emitted when a one-shot execution completes (success or failure). It is also
emitted on early-exit failures in the one-shot executors — configuration,
policy, and backend-init failures that terminate before a runner produces a
result (with `mxc.exit_code` = 1 and `mxc.outcome` = `failure`).

The state-aware lifecycle (`provision` / `start` / `exec` / `stop` /
`deprovision`) is also instrumented: each dispatched phase emits one
`MXC.Execution` tagged with `mxc.phase`. Non-`exec` phases and `exec` dry-runs
report success with `mxc.exit_code` = 0; a completed `exec` reports the sandbox
process exit code; a dispatch error reports `failure` plus an `MXC.Error`. As in
the one-shot path, a clean non-zero sandbox exit is not treated as an MXC error.

| Field | Type | Description |
|-------|------|-------------|
| `mxc.backend` | string | Containment backend name |
| `mxc.exit_code` | int32 | Process exit code |
| `mxc.outcome` | string | `"success"` or `"failure"` |
| `mxc.duration_ms` | uint64 | Total execution time |
| `mxc.failure_reason` | string | Failure category (if applicable) |
| `mxc.phase` | string | State-aware lifecycle phase (`provision`\|`start`\|`exec`\|`stop`\|`deprovision`); empty for one-shot executions |
| `__TlgCV__` | string | Microsoft Correlation Vector (MS-CV) — the lifecycle correlation key (see [Correlating a lifecycle](#correlating-a-lifecycle)); empty for one-shot executions |

Emitted on execution errors.

| Field | Type | Description |
|-------|------|-------------|
| `mxc.backend` | string | Containment backend name |
| `mxc.error_type` | string | Error category (`config_error`, `policy_error`, `process_error`, `timeout`, `init_error`, `internal_error`, `cancelled`, `unknown`) |
| `mxc.exit_code` | int32 | Process exit code |
| `mxc.phase` | string | State-aware lifecycle phase; empty for one-shot executions |
| `__TlgCV__` | string | Microsoft Correlation Vector (MS-CV) — the lifecycle correlation key (see [Correlating a lifecycle](#correlating-a-lifecycle)); empty for one-shot executions |

> **No free-form error text is emitted.** Error messages can contain paths,
> usernames, or credentials, so `MXC.Error` deliberately carries only the
> bounded `error_type` category and the numeric `exit_code` — never the
> message string itself.

### Correlating a lifecycle

The state-aware lifecycle runs each phase (`provision` → `start` → `exec` →
`stop` → `deprovision`) as a **separate `wxc-exec` process**. The
`UTCReplace_AppSessionGuid` common field is therefore per-process and cannot join
events from different phases of the same sandbox. The stable join key is the
**Microsoft Correlation Vector (MS-CV)**, emitted under TraceLogging's reserved
`__TlgCV__` field.

MS-CV is a hierarchical, propagatable identifier of the form
`<base>.<element>.<element>…` — a random base (128 bits, 22 base64 chars) plus a
dotted chain of decimal elements. MXC uses it as follows:

- **`provision`** seeds a fresh random base (`correlation_vector::seed()`) and
  returns it to the client in its result envelope as `result.correlationVector`.
  This is the lifecycle's root vector.
- The client **relays** that vector verbatim into every later phase (the SDK
  surfaces it as `ProvisionResult.correlationVector` and accepts it back as
  `SandboxSpawnOptions.correlationVector`, sent on the wire as the top-level
  `correlationVector` field).
- Each non-`provision` phase **spins** the relayed base
  (`correlation_vector::spin()`) to derive a distinct child vector that still
  shares the lifecycle's base prefix. Spin (rather than a plain extend) is used
  because `exec` is multi-invocation and the client is a dumb relay — a plain
  extend would collapse every phase to the same `base.0`, whereas spin folds in a
  coarse timestamp + entropy so sibling phases get distinct, ordered vectors.

An analyst groups all phases of one lifecycle by the shared **base prefix** of
`__TlgCV__`, and orders/​distinguishes phases within it by the spun elements.

An MS-CV is capped at 127 characters. In the unlikely event a long-lived
lifecycle grows the vector to that cap, the next operator **freezes** it: it
appends the `!` terminator (dropping the trailing element **whole**, at an
element boundary, if needed to stay within the cap — never truncating a
multi-digit element to a falsified value like `.42` → `.4`) and the vector is
never mutated again. `increment` likewise freezes when its trailing element is
already at `u32::MAX` and so cannot advance (the spec's value-overflow
behaviour). Every later phase then relays and emits that same frozen vector
verbatim, so correlation by base prefix still holds — only the per-phase
ordering elements stop advancing.

**Canonical validation.** A relayed vector is only built on (spun) when it is
*relayable* — a well-formed mutable vector (canonical 22-char base64 base whose
final char encodes a zero low nibble, followed by one or more canonical decimal
`u32` elements) or a valid frozen (`!`-terminated) vector. Elements must be
canonical: no leading zeros (`0` is allowed, `01` is not), no sign, no
whitespace — a non-canonical element such as `01` would silently reshape the
vector (`01` → `2` on increment) and break lexical sortability, so it is
rejected. Anything not relayable — missing, empty, malformed, or a hostile
`!`-terminated value like `user@contoso.com!` — is reseeded to a fresh random
base rather than emitted verbatim.

The correlation vector is **not** derived from the `sandbox_id`, so no
caller-supplied identity (e.g. a UPN embedded in an IsolationSession
`iso:<upn>` id) is ever involved: the base is pure randomness. Spin is defensive
— a missing, empty, or malformed relayed value falls back to a fresh seed rather
than panicking telemetry. `__TlgCV__` is empty for one-shot executions (which have
no lifecycle to correlate) and for a crash during `provision` before the vector is
stashed. It is only computed and emitted when experimental telemetry is active, so
provision output is unchanged when telemetry is off.

**Why a relayed random vector rather than a hashed `sandbox_id`.** An alternative
design would derive the correlation key deterministically from the `sandbox_id`
(e.g. a hash), avoiding the wire/SDK relay entirely. We deliberately do **not** do
this, for two reasons:

1. **PII-safety.** A `sandbox_id` is caller-influenced and can embed identity — an
   IsolationSession id is literally `iso:<upn>`. Hashing narrows but does not
   eliminate the exposure (a hash is a stable pseudonym and, for a low-entropy
   input like a known UPN, is reversible by dictionary). A base seeded from pure
   OS randomness carries no caller identity at all, which is the stronger and
   simpler guarantee.
2. **WIL TraceLogging fidelity.** This implementation intentionally mirrors the WIL
   TraceLogging correlation-vector design: a random 128-bit base extended/spun with
   MS-CV v2 operators and emitted under the reserved `__TlgCV__` field. A bespoke
   `sandbox_id`-hash scheme would diverge from that well-understood format and lose
   the hierarchical parent/child structure (base prefix + spun elements) that lets
   an analyst reconstruct phase ordering, not just group-by a flat key.

The client relay is therefore a required part of the design, not incidental
plumbing: it is how the random root vector minted at `provision` reaches the later
per-phase executor processes, which otherwise share no state.

### Crash telemetry (panic hook)

When telemetry is active, the executors install a global
[`std::panic::set_hook`] handler — both the one-shot executors and the
state-aware path (`run_state_aware_main`). If any thread panics, the hook emits
a failure `MXC.Execution` plus an `MXC.Error` categorised as `internal_error`
(with `mxc.exit_code` = 101, the conventional Rust panic/abort exit code),
attributed to the containment backend recorded at telemetry init and, on the
state-aware path, the `mxc.phase` in progress. Consistent
with the PII policy, **no panic message or backtrace text is emitted** — only
the bounded category and exit code. The hook chains the previously-installed
hook, so the default stderr backtrace still prints.

> **Limitation:** Only failures that occur **after** telemetry initialisation
> can be reported. A panic during argument parsing or config load — before
> `telemetry::init` runs — cannot emit an event, because the provider is not yet
> registered.

> **Limitation:** On backends that *recover* panics via `catch_unwind` (the LXC
> runner does this for container-cleanup safety), the panic hook still fires
> during unwinding and records the crash event with the `101` sentinel exit
> code, then claims the exactly-once terminal-emit slot. The recovered
> `MXC.Execution` completion event is therefore suppressed, so telemetry reports
> `mxc.exit_code` = 101 even though the recovered process ultimately exits with a
> different code (`-1`). The `101` here is a "a panic occurred" sentinel, not a
> claim about the observed process exit code; `outcome` and `error_type` remain
> accurate. Backends that do not catch panics (the Windows one-shot executor)
> abort with `101`, so the recorded code matches the real exit.

### Cancellation telemetry (console control handler)

On Windows, when telemetry is active, `wxc-exec`'s console control handler emits
a failure `MXC.Execution` plus an `MXC.Error` categorised as `cancelled` when the
operator interrupts a run (Ctrl-C, console close, or a system shutdown/logoff).
The reported `mxc.exit_code` is 130 (the conventional "terminated by Ctrl-C"
code, 128 + SIGINT) — a bounded attribution sentinel, since the OS ultimately
terminates the process with its own status. The handler runs on a short,
OS-imposed budget and does not shut the provider down; the events carry no
free-form text.

## Cross-Platform Behaviour

| Platform | Behaviour |
|----------|-----------|
| Windows | Full ETW telemetry via `tracelogging` crate |
| Linux | No-op — all telemetry functions return immediately |
| macOS | No-op — all telemetry functions return immediately |

---

## Local audit log records

Separate from the ETW telemetry above, MXC emits **structured local diagnostic
audit records**: one JSON object per line, written only to the auxiliary
diagnostic sinks. They exist so facts MXC already knows — a process exit code, a
tier fallback, a teardown result, a rejected config — are *machine-readable*
instead of being discarded or rendered only as prose.

**These are not ETW events.** No provider, no keyword, no privacy tag, no
correlation vector, and no consent gate. Nothing leaves the host.

### Enabling them

A record is written when — and only when — a diagnostic sink is attached. There
is no additional flag:

```powershell
# File sink: every audit record lands here alongside the normal diagnostics.
wxc-exec.exe --log-file .\mxc-audit.log .\config.json

# Named-pipe sink (Windows): use the same high-entropy token in both processes.
$env:MXC_DIAG_PIPE_TOKEN = [guid]::NewGuid().ToString('N')
$env:MXC_DIAG_PIPE_TOKEN
# Terminal 1: start the console with the shared token.
mxc-diagnostic-console.exe

# Terminal 2: enable the pipe sink for wxc-exec with the same token.
$env:MXC_DIAG_PIPE_TOKEN = '<the same token>'
$env:MXC_DIAG_CONSOLE = '1'
wxc-exec.exe .\config.json
```

With neither configured, the emit call is a cheap no-op.

Records deliberately do **not** reach the primary console/buffer sink — that
channel is the SDK caller's captured stdout / debug buffer, and writing to it
would change the observable output of every existing consumer. The diagnostic
logger routes them only to the explicitly configured auxiliary sinks.

### Format

```
{"event":"mxc.ProcessExited","backend":"processcontainer","identity":"sandbox-a3f1c8e40029bd17","tier":"base-container","pid":1234,"exit_code":0}
```

As it appears in a `--log-file` (the existing `[<unix-seconds>] ` stamp is
prepended by the file sink):

```
[1785549205] {"event":"mxc.ProcessExited","backend":"processcontainer",…}
```

The following invariants are enforced by MXC:

1. **`event` is always the first key**, so a consumer can classify a line with a
   prefix match (`{"event":"mxc.`) before parsing it.
2. **Field order is the call site's declaration order** — deterministic per
   record.
3. **Values are strings, integers, or booleans only.** No nested objects, no
   arrays; a set-valued field is a comma-joined bounded string plus an explicit
   `_count` companion.
4. **String values are `serde_json`-escaped**, so an embedded quote, backslash,
   or newline can never break the one-record-per-line invariant.
5. **Event names come from the closed `AuditEventName` enum** — a typo is a
   compile error, not a silently unmatched record.

Parsing is therefore just `ConvertFrom-Json` / `jq`:

```powershell
Get-Content .\mxc-audit.log |
  ForEach-Object { if ($_ -match '^\[\d+\]\s(\{.*\})$') { $Matches[1] } } |
  ConvertFrom-Json |
  Where-Object { $_.event -like 'mxc.*' } |
  Format-Table event, backend, identity, tier
```

### Content rules

The same bounded-vocabulary discipline as the ETW events applies, and for the
same reason: a diagnostic log file is routinely attached to a bug report or
collected by a fleet log agent.

* **No free-form text.** Reasons, statuses, and methods are closed enums with an
  `as_str()`; error detail is reduced to a numeric code.
* **No config values, no filesystem paths, no command lines.** Config field
  *paths* (`process.commandLine`) are permitted — they are bounded and already
  public in the schema. Field *values* are not.
* **No raw user identities.** Identity-bearing sandbox records use a constant
  redaction marker instead of a user identifier. A truncated SHA-256 is not used:
  a low-entropy identity could be recovered by dictionary attack. The cost is
  that these sandboxes have no MXC-side join key in the local log.
* **No caller-supplied identifiers verbatim.** A sandbox identity derived from
  configuration (the AppContainer profile name is the caller's `containerId`)
  is retained only when it matches one of the closed set of shapes MXC itself
  mints — the literal default `CLI`, `sandbox-<16 hex>`, or the state-aware
  `iso:<token>` / `wsb:<token>` ids (≤64 chars, opaque token characters only).
  Any other `containerId` the caller chose is replaced with `redacted`,
  regardless of how opaque it looks — character/length checks alone cannot
  prove a value wasn't caller-chosen.
* **Counts, not names, for network rules.** Rule names can contain host and
  process identifiers, so only counts are recorded.

### Record inventory

Fields are record-specific. Process-boundary records include `backend`,
`identity`, `tier` (for `process_container`), and `pid`. Early records emitted
before a sandbox exists carry only the fields shown in the table below; in
particular, `mxc.PolicyHash` has `backend`, `policy_hash`, and
`config_schema_version`, `mxc.EnforcementDegraded` has `backend` and `tier`,
and `mxc.ConfigRejected` has `backend` plus its rejection fields.

| Record | When | Fields beyond the common ones |
|---|---|---|
| `mxc.PolicyHash` | Every launch, after the effective request is resolved | `backend`, `policy_hash`, `config_schema_version` |
| `mxc.SandboxIdentity` | After a successful state-aware phase | `backend`, `identity`, `phase` |
| `mxc.EnforcementDegraded` | ProcessContainer dispatch resolved below the preferred tier | `backend`, `tier`, `needs_dacl_augmentation`, `effective_enforcement_level`, `degradation_reasons`, `degradation_reason_count` |
| `mxc.NetworkPolicyApplied` | After network policy setup, on success **and** failure | `backend`, `identity`, `tier` (no `pid` yet), plus `enforcement_mode`, `default_policy`, `proxy_port`, `firewall_rules_created`, `firewall_applied`, `status` |
| `mxc.ProcessExited` | Sandboxed process exited on its own | `exit_code` |
| `mxc.ProcessTimedOut` | `scriptTimeout` breached | `timeout_ms` |
| `mxc.ProcessKillFailed` | A kill/terminate call failed (**failure only**) | `kill_method`, `error_code` |
| `mxc.SandboxTornDown` | Per-run resources released, once per handle | `backend`, `identity`, `tier`, `pid`, `status`, `firewall_rules_removed`, `firewall_removal_ok`, `bfs_removed`, `proxy_stopped`, `preserve_policy`, `container_released`, `skip_reason` |
| `mxc.ConfigRejected` | A request was refused before it could run | `backend`, `reason`, `offending_field`, `phase` |

Notes on the ones that are easy to misread:

* **`mxc.EnforcementDegraded` is absent on a clean run.** It fires only when
  selected enforcement is below the preferred level, additional host setup was
  needed, or a bounded reason was recorded. The effective level is a closed MXC
  vocabulary describing the enforcement mechanism selected by MXC; it is not an
  assertion about an independent OS telemetry field. The streaming path emits
  the record *before* the spawn, so it exists even when the spawn then fails.
* **`mxc.ProcessKillFailed` is not automatically a defect.** Termination can
  race with normal process exit. The record is captured but never propagated —
  the kill path stays best-effort and non-fatal.
* **`mxc.SandboxTornDown` reports unavailable cleanup honestly.** If a cleanup
  operation is not implemented for a backend, the record reports that fact
  rather than claiming a cleanup that did not happen.
* **`mxc.PolicyHash` covers the *policy*, not the command.** See below.

### The policy hash

MXC produces `sha256:<64 hex>` over an explicit **allow-list** projection of the
effective request, canonicalised (object keys sorted at every depth, array order
preserved). It is computed after every policy-affecting mutation, so it
describes what actually ran, not what was requested.

An allow-list is deliberate: a field added to the model later is excluded until
someone opts it in, which fails safe rather than accidentally hashing a secret.
To stop that from rotting into a silent coverage gap, the projection
**exhaustively destructures** `ExecutionRequest` and `ExperimentalConfig` — adding
a field to either is a compile error until it is classified.

Excluded, and why:

| Excluded | Reason |
|---|---|
| `script_code` | The command line is *what runs*, not the policy it runs under; it routinely embeds credentials. |
| `env` | Environment variables are the classic secret carrier. |
| `experimental.telemetry`, `experimental.test` | No enforcement effect. |
| `experimental.*.user` | Carries identity credentials. Stripped recursively; the rest of the isolation-session section *is* hashed. |
| proxy `original_url` | Can embed `user:password@`. The host and port *are* hashed. |
| `dry_run`, `testing_features_enabled` | Invocation modes, not policy. |

The rest of `experimental` **is** hashed — `windows_sandbox`, `wslc`, and
`isolation_session` carry those backends' entire enforcement policy, so omitting
them would make two materially different policies hash identically.

`config_schema_version` is named for the *schema*: it does not change when the
policy changes and must never be read as a policy version.

**Residual disclosure property (accepted).** The hash is deterministic and
unkeyed, so it is a confirmation oracle for the fields it covers: a reader who
already knows every hashed field but one can brute-force the remaining one. In
practice that means testing a guess at a single `readwritePaths` entry while
already knowing the container id, working directory, timeout, capability list,
and every other path exactly. This is accepted because the alternative (a keyed
digest) needs a machine-local secret whose storage and rotation are out of scope
for a local log, and because the genuinely sensitive inputs — command line,
environment, tokens, proxy userinfo — are excluded from the hash entirely, so no
oracle exists for them at any difficulty. **Do not add a low-entropy secret to
the projection without switching to a keyed construction first.**

### Platform scope

The records are **not** uniformly available across platforms, and a missing
record must not be read as "the event did not happen":

| Record | Windows ProcessContainer | Windows state-aware | Linux (LXC / Bubblewrap) | macOS (Seatbelt) |
|---|---|---|---|---|
| `mxc.PolicyHash` | ✅ | ✅ | ✅ | ✅ |
| `mxc.SandboxIdentity` | — | ✅ | — | — |
| `mxc.ConfigRejected` | ✅ (`wxc-exec`) | ✅ | — | — |
| `mxc.EnforcementDegraded` | ✅ | — | n/a (no tier model) | n/a |
| `mxc.NetworkPolicyApplied` | ✅ (T2/T3) | — | — | — |
| `mxc.ProcessExited` / `TimedOut` / `KillFailed` | ✅ (including isolation-session one-shot) | — | — | — |
| `mxc.SandboxTornDown` | ✅ | — | — | — |

The shared audit types compile identically on all three platforms; the gap is
that the *emission sites* were added only to the
Windows runners and the `wxc-exec` binary, because the originating requirement
was Windows-only. Extending them to `lxc-exec` and `mxc-exec-mac` is tracked
follow-up work, not a design decision that Linux and macOS do not need an audit
trail.

The isolation-session `ProcessTimedOut` and `ProcessKillFailed` records are
emitted by the one-shot runner, where `wxc-exec` supplies the local diagnostic
logger to the backend. The state-aware backend trait does not currently carry a
logger into its `exec` method, so state-aware isolation-session exec remains
unrecorded by these MXC-local process-boundary events.



| Requirement | Existing OS coverage | MXC local coverage | Join/correlation notes |
|---|---|---|---|
| M-ETW-1 process outcome | Existing OS process-lifecycle records cover normal exit. The OS does not provide a verified timeout or kill-failure record for this requirement. | `mxc.ProcessTimedOut` and `mxc.ProcessKillFailed` cover the one-shot MXC boundary; state-aware exec is not currently logger-backed. | Join the OS lifecycle identity to the MXC sandbox identity where available; use the process ID for process records. |
| M-ETW-2 enforcement degradation | Not applicable to this backend: `isolation_session` has no MXC process-container tier/fallback model. | `mxc.EnforcementDegraded` covers process-container tier selection and includes `effective_enforcement_level`. | No isolation-session tier join is expected. |
| M-ETW-3 policy hash | No policy hash field is emitted by the isolation-session OS provider. | `mxc.PolicyHash` records the effective MXC policy locally, excluding secrets and command content. | Correlate by the invocation/lifecycle context; the hash is an MXC record, not an OS field. |
| M-ETW-4 network policy | Not applicable today: MXC rejects isolation-session network and proxy policy before OS provisioning. | `mxc.NetworkPolicyApplied` covers supported process-container network setup only. | This row changes only if the separate M1 network-proxy requirement is implemented. |
| M-ETW-5 teardown | Existing OS lifecycle and security records cover OS cleanup. | `mxc.SandboxTornDown` covers supported process-container cleanup; isolation-session phase outcomes remain in the existing lifecycle records. | Join by the lifecycle identity where available; OS cleanup may outlive the MXC process boundary. |
| M-ETW-6 provider selection and correlation | `mxc.ConfigRejected` records MXC-owned rejection reason, field, and phase locally. | MXC validation commonly occurs before the OS call, so no OS rejection event should be expected for those records. |
| M-ETW-7 configuration rejection | Existing OS records do not expose the MXC parser's bounded field path and rejection category. | `mxc.ConfigRejected` records the bounded reason, offending field, backend, and phase. | The human-readable error remains on the existing operator-facing channel; the audit record contains no rich error text. |

This table documents coverage and correlation; it does not convert the local
audit records into OS telemetry. OS event names and capture procedures vary by
OS build and are outside this local audit format.

### Stability contract

The `event` name is the anchor. If a record's field set has to change
incompatibly, mint a new record name rather than redefining an existing one.
New record names and new fields are additive; a consumer that filters on
`{"event":"mxc.` sees only what it recognises.

The shared record format is cross-platform, so Windows, Linux, and macOS
compile and test the same serialization code.
See [Platform scope](#platform-scope) for which *emission sites* exist where —
that is where the real asymmetry lives.

---

## Private GUID Substitution (Internal Builds)

MXC supports an optional Microsoft telemetry group GUID for internal builds.
The mechanism is public; only the GUID value is private.

### How it works

```
build.rs execution flow
========================

1. Check MXC_TELEMETRY_PROVIDER_GROUP_GUID env var
   ├── NOT set → generate: define_provider!(MXC_PROVIDER, "Microsoft.MXC");
   └── SET → generate: define_provider!(MXC_PROVIDER, "Microsoft.MXC",
                            group_id("{guid}"));

2. lib.rs includes the generated provider_def.rs via include!()
```

The provider GUID is **not** specified in either branch. The `tracelogging`
crate's `define_provider!` macro derives it deterministically from the provider
name using the standard ETW name-hash algorithm (the same algorithm used by
`<TraceLoggingProvider.h>`, WIL's `IMPLEMENT_TRACELOGGING_CLASS`, and .NET's
`EventSource`). For `"Microsoft.MXC"` the derived GUID is
`{7f10def4-a258-5fea-510e-2c3bb976687f}`. Keeping the name and GUID in lockstep
this way prevents drift and avoids hard-coding a literal that could collide
with another team's GUID.

### CI pipeline steps

Internal Microsoft builds set `MXC_TELEMETRY_PROVIDER_GROUP_GUID` to the real
Microsoft telemetry group GUID before `cargo build` on Windows, so events route
through the telemetry pipeline. Community forks that lack access to the private
GUID do not set this variable - the provider is registered without a group GUID
(plain ETW only).

> **Follow-up:** The provider group GUID is now provided by a secret variable
> on the official Windows build pipeline, so official builds can route events
> through the telemetry pipeline. The build has always honored the variable
> (see *Local developer testing* below); public builds and community forks,
> which do not have access to the variable, continue to register the provider
> without a group GUID (plain ETW only).

### Local developer testing

```powershell
# Test with a dummy group GUID (not the real one)
$env:MXC_TELEMETRY_PROVIDER_GROUP_GUID = '00000000-1111-2222-3333-444444444444'
cargo build -p mxc_telemetry

# Test without (public build)
Remove-Item Env:\MXC_TELEMETRY_PROVIDER_GROUP_GUID
cargo build -p mxc_telemetry
```

### What's public vs. private

| Item | Public? | Why |
|------|---------|-----|
| Provider name `"Microsoft.MXC"` | Yes | Standard ETW naming |
| Provider GUID `{7f10def4-a258-5fea-510e-2c3bb976687f}` | Yes | Derived from the name; identifies the provider, harmless |
| `build.rs` env var mechanism | Yes | Mechanism is public |
| `MXC_TELEMETRY_PROVIDER_GROUP_GUID` env var name | Yes | Key is public; value is private |
| Actual Microsoft telemetry group GUID | No | Private - set in CI only |

## SDK License Override (EULA for npm Package)

The public GitHub repo ships `sdk/node/LICENSE.md` as a plain MIT license. For
internal npm publishes, a separate EULA containing a **Section 2 - DATA**
clause (covering telemetry disclosure, opt-out, and GDPR) will be updated at
pack/publish time.

### How it works

```
1. CI pipeline (or local script) sets MXC_LICENSE_OVERRIDE env var
   pointing to the markdown file of the EULA including additional telemetry language.
   Note that the new EULA will include language outlining what data can be collected but
   will otherwise remain MIT licensed.

2. A license-override script (added in a follow-up build-integration PR) runs:
   MXC_LICENSE_OVERRIDE is set:
   - Back up sdk/node/LICENSE.md -> sdk/node/LICENSE.md.public
   - Copy new EULA over sdk/node/LICENSE.md
   MXC_LICENSE_OVERRIDE is NOT set:
   - Restore sdk/node/LICENSE.md from .public backup (if exists)

3. npm pack / npm publish picks up the new EULA as the LICENSE.md
   in the published package (sdk/node/package.json "files" includes LICENSE.md).

4. After publish, the revert path restores the original EULA document.
```
