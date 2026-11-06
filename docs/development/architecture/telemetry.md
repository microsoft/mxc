# MXC Telemetry — Windows TraceLogging Architecture

> **Audience:** MXC developers

MXC uses the Rust [`tracelogging`](https://crates.io/crates/tracelogging) crate
(published by Microsoft) for **Windows-only** TraceLogging ETW telemetry. No
C++ shim, WIL, or FFI is required.

> **The M-ETW requirements are satisfied by ETW events, not the local audit
> log.** MXC may also write structured
> **local diagnostic audit records** that are *not* ETW, *not* uploaded, and
> *not* consent-gated. They are a separate mechanism with a separate sink; see
> [Local audit log records](#local-audit-log-records) below. Nothing in that
> section touches the `Microsoft.MXC` provider described here.

## Overview

```
┌──────────────────────────────────────────────────────┐
│  mxc_sdk::mxc_common::telemetry                      │
│  (Rust — config resolution, sanitisation, types)     │
│                                                      │
│  init() / log_execution_start() / log_execution_end() │
│  log_error() / log_verbose() / shutdown()               │
└───────────────┬──────────────────────────────────────┘
                │  Direct Rust function calls
                ▼
┌──────────────────────────────────────────────────────┐
│  mxc_sdk::mxc_telemetry (Rust module)                │
│  src/core/mxc_telemetry/mod.rs                       │
│  define_provider! + write_event!                     │
│                                                      │
│  Windows: ETW events via tracelogging crate          │
│  Linux/macOS: compile-time no-op stubs               │
└──────────────────────────────────────────────────────┘
```

## TraceLogging implementation

The Rust `tracelogging` crate provides MXC's required ETW primitives without a
C++ build, NuGet dependency, or FFI boundary. MXC supplies the remaining
provider metadata through Rust constants and `write_event!` struct fields.

### Feature comparison

| Feature | WIL (`wil/TraceLogging.h`) | Rust `tracelogging` crate | MXC approach |
|---|---|---|---|
| **Provider group GUID** | WinExt telemetry group | `group_id("...")` in `define_provider!` | One `Microsoft.MXC` registration uses the WinExt group for all events; see [Private GUID Substitution](#private-guid-substitution-internal-builds) |
| **Sampling keywords** | Measures / Critical Data constants | Raw `u64` in `keyword(...)` | Supplied at build time by the signed telemetry component (see [Telemetry component](#telemetry-component)); ordinary local builds use `0x1` for both. Grouped builds select metadata by event and source contract as described below |
| **Common event fields** | `_GENERIC_PARTB_FIELDS_ENABLED` pattern | `struct("Name", { ... })` in `write_event!` | `struct("COMMON_MXC_PARAMS", { Version, Channel, IsDebugging, UTCReplace_AppSessionGuid })` |
| **Provider lifecycle** | `IMPLEMENT_TRACELOGGING_CLASS` singleton | `define_provider!` static + `register()`/`unregister()` | `OnceLock<ProviderState>` for version/channel, manual lifecycle |
| **Privacy Product** | Common Schema Part A product | `u16(...)` field | `PartA_PrivacyProduct` (the privacy-approved MXC product, from the telemetry component) on all events |
| **Privacy Data Category** | Common Schema Part A data category | `u16(...)` field | `PartA_PrivacyDataCategory` (Client Diagnostic Data, from the telemetry component) on all events |
| **Privacy Data Tags** | `TelemetryPrivacyDataTag(PDT_*)` | `u64("PartA_PrivTags", &val)` field | Usage/Performance values from the telemetry component, selected with the keyword. Ordinary local builds use `0`; the field and its position remain unchanged |
| **Activity tracking** | `DEFINE_TELEMETRY_ACTIVITY` | Manual `Opcode` | Not needed for current events |

The remaining gap (activity tracking) is not needed for current events.
If needed later, it can be added incrementally.

### Event keyword and privacy-tag selection

For Windows builds with the WinExt group configured, `MXC.ExecutionStart`, `MXC.ExecutionEnd`,
`MXC.Error`, and `MXC.ProcessExited` use the Critical Data keyword and the Performance
privacy tag when the request uses development contract `1.1.0-alpha`.
Published `0.9.0-alpha` and `1.0.0` requests, and requests without source-contract
attribution, retain the Measures keyword and the Usage privacy tag.
The numeric values are not in this repository; they come from the telemetry component.
Published requests retain Measures and Usage for the other event families.
Development `1.1.0-alpha` requests emit only those four events, suppressing
VerboseDenials, ProcessTimedOut, ProcessKillFailed, PolicyHash,
SandboxNetworkPolicyApplied, SandboxTornDown and ConfigRejected.
Without a group, ordinary local
builds use keyword `0x1` and privacy tag `0` for both categories.

The selection travels with request-scoped session context, including streaming
handles and worker threads. The shared writer selects the keyword and tag
together. Event names, field order and types are unchanged for every contract.
Published contracts and requests without source-contract attribution retain the
full inventory, request opt-in, MXC consent and administrative policy gates.
Excluded verbose telemetry is not read or prepared for transport; caller-requested
local denial reports and verbose artifacts remain available.

Development `1.1.0-alpha` requests collect the four Required events by default.
The request's `telemetry` object (including `enabled: false`) and MXC consent
are not consulted. Initialization runs for every such request and collection
requires only a build eligible for Required collection: routed through the internal
group, or the debug-only local test mode (`MXC_TELEMETRY_TEST_KEYWORDS=1`).
Administrative policy is not consulted, so no registry setting disables it.

The gate is selected from the request-scoped contract, so published and
development requests running concurrently do not share authorization. UTC's
Required/Optional controls apply to Windows Diagnostic Data, not to MXC's WinExt
events.
Consent-free collection is not implemented by the inventory or metadata selection.

All events write through `MXC_PROVIDER` with the MXC privacy product.
The existing shared reference count owns that single registration; final
shutdown unregisters it. Registration failure leaves telemetry inactive,
and a later initialization can retry.

Ordinary local/OSS builds retain provider-local keyword `0x1` and privacy tag
`0` for every event. For local metadata tests only,
`MXC_TELEMETRY_TEST_KEYWORDS=1` generates the real category masks and privacy
tags without joining a routing group. The build rejects this
setting outside Windows debug `test-support` builds or with a nonempty
provider-group input. This test input grants no collection authorization.


## Common Event Fields (Part A)

Every MXC telemetry event carries the WinExt-required Common Schema fields
`PartA_PrivacyProduct` and `PartA_PrivacyDataCategory`. The
`PartA_PrivTags` field is also always present. Ordinary public and local
builds use `0`; grouped builds use Performance for the four development
events and Usage otherwise, as described above. The product is
privacy-approved and registered in the WinExt product list. The provider-group
identifier and these values come from the telemetry component and must not be
copied into source, tests, documentation, or commits.

## Common Event Fields (Part C)

Every MXC telemetry event includes a `COMMON_MXC_PARAMS` struct grouping
shared Part C custom event fields:

| Field | Type | Description |
|-------|------|-------------|
| `Version` | string | MXC crate version from `CARGO_PKG_VERSION` |
| `Channel` | string | `"dev"` for debug builds, `"release"` for release |
| `IsDebugging` | bool | `cfg!(debug_assertions)` — true for debug builds |
| `UTCReplace_AppSessionGuid` | bool | Always `true` — tells UTC to replace the app session GUID with a per-session identifier for privacy |

Every event also includes `mxc.session_id`, a lowercase hyphenated UUID string
shared by every emitted event in one container lifecycle. It is request-scoped,
not cached in `ProviderState`; streaming handles restore it during backend
poll/wait/kill and final cleanup, including after moving to another thread.
Disabled invocations suppress backend telemetry even when another request owns
the provider. See [Correlating a lifecycle](#correlating-a-lifecycle).

Unreleased consent resource version `4` discloses the random lifecycle session
inventory, pending privacy/release-owner review, and requires
explicit re-consent for earlier grants. Administrative policy, per-request
opt-in, emission reauthorization, privacy tags and non-Windows no-ops remain
unchanged.

## Windows-only M-ETW specification

The following requirements are implemented through the local
`Microsoft.MXC` TraceLogging provider on Windows. "Local" means that MXC
registers a provider and writes ETW events into the Windows ETW subsystem; MXC
does not start a collection session, upload events, contact a network service,
or create a background process. Events exist only when a local ETW consumer
enables the provider.

The provider is defined by the name `Microsoft.MXC`. The signed telemetry
component supplies its WinExt routing group for all events; event metadata is
selected from the source contract — see
[Telemetry component](#telemetry-component) below. Debug and unrouted builds
have no group, so `group_id(...)` is omitted, `MXC_EVENT_KEYWORD` is a
provider-local bit with no UTC meaning, and `MXC_PRIVACY_TAG` is `0`: events
are ordinary local ETW and are not directed to an upload pipeline by MXC.

The M-ETW scope is Windows `process_container` and `isolation_session`.
Linux/macOS retain no-op telemetry stubs and are not requirement-behavior
targets for this work.

The following table describes the published-contract inventory. Development
`1.1.0-alpha` retains only ExecutionStart, ExecutionEnd, Error and ProcessExited.

| Requirement | ETW event | Required fields | Backend coverage |
|---|---|---|---|
| Process outcome (M-ETW-1) | `MXC.ProcessExited`, `MXC.ProcessTimedOut`, `MXC.ProcessKillFailed` | `identity`, `processId`, plus `exitCode`, `timeoutMs`, or `error` | ProcessContainer and IsolationSession |
| Enforcement degradation (M-ETW-2) | — | — | Not applicable: no current backend selects among enforcement levels |
| Policy hash (M-ETW-3) | `MXC.PolicyHash` | Stable `policyHash` and/or `policyVersion` | ProcessContainer and IsolationSession |
| Network policy (M-ETW-4) | `MXC.SandboxNetworkPolicyApplied` | `identity`, `enforcementMode`, `defaultPolicy`, `proxyPort` | ProcessContainer; not applicable when IsolationSession rejects network policy before provisioning |
| Sandbox teardown (M-ETW-5) | `MXC.SandboxTornDown` | `identity`, `status`, and released-resource fields | ProcessContainer and IsolationSession |
| IsolationSession telemetry (M-ETW-6) | Same `Microsoft.MXC` provider | Applicable process-outcome/policy-hash/teardown/configuration-rejection events use the same ETW provider | IsolationSession uses the MXC provider; no separate OS IsolationSession provider is assumed |
| Configuration rejection (M-ETW-7) | `MXC.ConfigRejected` | `correlationId` or identity, bounded reason/error code, offending field path | ProcessContainer and IsolationSession validation paths |

### ETW privacy and collection contract

- Execution, error, and M-ETW requirement events contain bounded enums, opaque
  MXC identities, numeric status fields, schema field paths, and the random
  lifecycle session ID described above.
  `MXC.Verbose` is separately limited to the sanitized, typed inventory below.
- Events do not contain command lines, environment values, complete file paths,
  UPNs, tokens, sandbox output, raw ETL, actionable denial documents, general
  logger text, or free-form error text.
- `MXC.PolicyHash` uses the same effective container identity as the runner
  (`CLI` when no container ID was supplied), then applies the standard identity
  redaction. Valid opaque IDs are preserved; UPN-shaped or otherwise unsafe
  identities are replaced with a bounded marker.
- ETW emission is independent of the local JSON/file/pipe diagnostic sinks.
  Enabling a local sink does not enable ETW, and disabling local sinks does not
  suppress ETW when the `Microsoft.MXC` provider is enabled by a consumer.
- `MXC.SandboxNetworkPolicyApplied` records the network-policy application
  attempt and its requested mode. `MXC.ExecutionEnd` remains authoritative for
  whether the overall execution succeeded; no network-enforcement semantics are
  changed by this telemetry contract.
- Neither provider-group input is set in public/OSS builds. When both are
  unset, all keywords and privacy tags use the local-only values
  (see [Private GUID Substitution](#private-guid-substitution-internal-builds)).
- MXC does not call an uploader, start an ETW session, create a service, or
  create a long-lived process. A human or local diagnostic tool must
  explicitly enable a session such as WPR/WPA or `logman`.
- Provider registration is scoped to the executor process. The provider is
  unregistered on normal terminal paths; the operating system cleans up on
  abnormal process termination.
- Non-Windows builds compile the same API as no-ops. They do not claim the
  Windows ETW requirements are met.

## Events

The provider-qualified event identities include
`Microsoft.MXC/MXC.ExecutionStart`, `Microsoft.MXC/MXC.ExecutionEnd`,
`Microsoft.MXC/MXC.Error`, and
`Microsoft.MXC/MXC.VerboseDenials`. `Microsoft.MXC` is the TraceLogging provider
name. The M-ETW requirement events listed above share that provider.

### MXC.ExecutionStart and MXC.ExecutionEnd

These two events replace `MXC.Execution`; that old event name is no longer
emitted. Collector filters and queries must use the new names. Both events
retain the former execution fields, types and lifecycle session ID. Published
contracts also retain their privacy metadata. Both events additionally carry
`mxc.capture_denials`.

`MXC.ExecutionStart` is emitted after telemetry authorization and correlation
setup, before execution or lifecycle dispatch, including before handled
launch/validation failures. It means an invocation began, not that a child
process launched. Its result fields are placeholders: `mxc.outcome` is
`started`, `mxc.exit_code` and `mxc.duration_ms` are `0`, and
`mxc.failure_reason` is empty. The exit-code placeholder does not mean success.

`MXC.ExecutionEnd` is emitted when a create-and-run execution completes
(success or failure). It is also emitted on early-exit failures in the executors — configuration,
policy, and backend-init failures that terminate before a runner produces a
result (with `mxc.exit_code` = 1 and `mxc.outcome` = `failure`).

Lifecycle operations (`provision-session` / `provision` / `start` / `exec` / `stop` /
`deprovision` / `deprovision-session`) are also instrumented: each dispatched phase emits one Start
and one End tagged with `mxc.phase`. Non-`exec` phases and `exec` dry-runs
report success with `mxc.exit_code` = 0; a completed `exec` reports the sandbox
process exit code; a dispatch error reports `failure` plus an `MXC.Error`. As in
the create-and-run path, a clean non-zero sandbox exit is not treated as an MXC error.

Streaming SDK calls emit Start before spawn and End on terminal observation,
confirmed cancellation, timeout, or handle disposal, not when spawn returns.
Start does not claim the terminal slot or release the provider. End retains
the existing exactly-once terminal ownership, including best-effort executor
panic/cancellation reporting. Each emission independently rechecks consent
and policy, so withdrawal can suppress End after Start.

Hard process termination, native crashes, or collection/delivery loss can leave
an unmatched Start; absence of End is not proof of a crash. Requests rejected
before telemetry initialization have no guaranteed pair. No retries or uploads
are added. `mxc.session_id` groups the lifecycle, not each repeated operation;
use `__TlgCV__` to distinguish lifecycle dispatches. No new per-invocation
identifier is introduced.

`mxc.capture_denials` reports the selected ProcessContainer access-check mode:
`enforce` (normal policy enforcement without learning-mode denial recording),
`deny-and-record`, or `allow-and-record`. Other backends and missing applicable invocation context
use `not_applicable`. The normalized capability classifier is shared with
backend diagnostics, uses exact case-insensitive names, and gives permissive
mode precedence. JSON and typed SDK configuration therefore include the
`learningMode` and `captureDenials` mappings. The executor snapshots its
`--audit` and diagnostic-console overrides before Start, without moving trace
setup, validation failures, or the existing capability mutations ahead of it.
This is selected configuration, not an assertion that dispatch or OS setup
succeeded. No commands, policy contents, or arbitrary capability names are
added to telemetry.

The invocation scope saves/restores the mode alongside session attribution.
Streaming handles and backend workers retain the session ID, mode, and invocation
suppression state across thread handoffs and cleanup. Missing session attribution
reports `unknown` without disabling an otherwise authorized invocation; an opted-out
invocation remains suppressed even while another request owns the provider. The process
context supplies it to best-effort panic/cancellation reporting using the
existing nonblocking recovery. Mode is not cached in process-wide provider
state, and disabled invocations do not inherit another request's mode.

| Field | Type | Description |
|-------|------|-------------|
| `mxc.sandbox_kind` | string | Containment kind requested by the caller (`process`, `vm`, or a concrete backend name) |
| `mxc.backend` | string | Backend identifier; ProcessContainer reports `processcontainer` |
| `mxc.capture_denials` | string | Selected mode: `enforce`, `deny-and-record`, `allow-and-record`, or `not_applicable`; not proof of successful setup |
| `mxc.exit_code` | int32 | End: process exit code; Start: `0` placeholder |
| `mxc.outcome` | string | Start: `"started"`; End: `"success"` or `"failure"` |
| `mxc.duration_ms` | uint64 | End: elapsed execution time; Start: `0` |
| `mxc.failure_reason` | string | End: failure category if applicable; Start: empty |
| `mxc.phase` | string | Lifecycle phase (`provision-session`\|`provision`\|`start`\|`exec`\|`stop`\|`deprovision`\|`deprovision-session`); empty for create-and-run execution |
| `__TlgCV__` | string | Microsoft Correlation Vector (MS-CV) — the lifecycle correlation key (see [Correlating a lifecycle](#correlating-a-lifecycle)); empty for one-shot executions |

### MXC.Error

Emitted on execution errors.

| Field | Type | Description |
|-------|------|-------------|
| `mxc.sandbox_kind` | string | Containment kind requested by the caller (`process`, `vm`, or a concrete backend name) |
| `mxc.backend` | string | Backend identifier; ProcessContainer reports `processcontainer` |
| `mxc.error_type` | string | Error category (`config_error`, `policy_error`, `process_error`, `timeout`, `init_error`, `internal_error`, `cancelled`, `unknown`) |
| `mxc.exit_code` | int32 | Process exit code |
| `mxc.phase` | string | State-aware lifecycle phase; empty for one-shot executions |
| `__TlgCV__` | string | Microsoft Correlation Vector (MS-CV) — the lifecycle correlation key (see [Correlating a lifecycle](#correlating-a-lifecycle)); empty for one-shot executions |

> **No free-form error text is emitted.** Error messages can contain paths,
> usernames, or credentials, so `MXC.Error` deliberately carries only bounded
> attribution fields, the `error_type` category, and the numeric `exit_code` —
> never the message string itself.

### MXC.VerboseDenials

Emitted when a telemetry-enabled ProcessContainer run successfully produces a
Learning Mode `captureDenials` verbose logging artifact. MXC reads the
versioned `*.verbose.json` sibling and dispatches document versions 3, 4, and 5
to their separate closed schemas. It rejects cross-version or unknown
vocabulary, derives each provider GUID from the version's closed provider
vocabulary, removes schema `eventName`, every verbose property name and value,
and structured network endpoints, then regroups signatures that become
identical and sums their counts before compact serialization. Version 5
retains the WFP provider and its closed typed reason and
configuration-recommendation fields. Unsupported document versions are
rejected. The event never contains the actionable denials file, raw ETL,
commands, sandbox output, or general logger text.

One verbose document may require multiple ETW events. Every `mxc.content`
value is an independently parseable compact JSON array of complete verbose
signature objects; MXC never splits a JSON object or UTF-8 code point.
Streaming callers must use `wait` to finalize capture metadata. A terminal
result observed only through nonblocking `try_wait` emits completion telemetry
but not the optional verbose artifact event.

| Field | Type | Description |
|-------|------|-------------|
| `mxc.sandbox_kind` | string | Caller-requested containment kind |
| `mxc.backend` | string | Concrete containment backend |
| `mxc.phase` | string | Lifecycle phase; empty for current one-shot capture |
| `__TlgCV__` | string | Lifecycle correlation vector; empty for current one-shot capture |
| `mxc.document_id` | string | Random identifier shared only by chunks of one verbose artifact |
| `mxc.document_version` | uint32 | `VerboseLoggingDocument` schema version |
| `mxc.chunk_index` | uint32 | Zero-based chunk index |
| `mxc.chunk_count` | uint32 | Total number of chunks |
| `mxc.document_bytes` | uint64 | Compact telemetry-projection byte count |
| `mxc.document_sha256` | string | SHA-256 of the compact telemetry projection |
| `mxc.content` | string | Valid compact JSON array of complete verbose signatures |
| `mxc.summary` | string | Valid compact JSON verbose-document summary |

Consumers group by the existing app-session identifier plus
`mxc.document_id`, order by `mxc.chunk_index`, parse and concatenate the
`mxc.content` arrays, then rebuild `{version, signatures, summary}`. The byte
count and SHA-256 allow consumers to reject incomplete or corrupted
reconstructions.

### Data inventory

MXC's optional diagnostic events contain:

- MXC version and channel
- Whether the build has debug assertions enabled (`IsDebugging`)
- Caller-requested sandbox kind and the concrete backend selected on the host
- Run outcome, exit code, duration, bounded failure category, and lifecycle
  phase
- `UTCReplace_AppSessionGuid`, which asks the telemetry pipeline to supply a
  random per-session app identifier
- An MXC-internal random lifecycle correlation vector
- Sanitized Learning Mode verbose signatures when `captureDenials` produces a
  verbose artifact: provider/event identifiers, PID, closed outcome reason,
  access/resource classifications, occurrence counts, and truncation state.
  Provider GUIDs are derived from a closed provider enum; verbose property
  names and values are dropped.

MXC does not emit commands, credentials, complete file paths, usernames,
workload-derived properties, sandbox output, raw ETL, actionable denial
documents, general logger text, or free-form error text.

### Privacy review status

The current `en-US` consent resource is version 4, which is privacy-reviewed.
The consent wording applies only to the consent-gated optional events of the
published contracts. The four Required events of the development contract do
not use it. The
verbose-event inventory, current WinExt classification, retention, access,
regional processing, deletion, and localization/accessibility decisions
require explicit privacy/release review. The canonical wording and presenter
contract are documented in
[Telemetry consent design](telemetry-consent-design.md).

### Correlating a lifecycle

Use **`mxc.session_id`** to join events from `provision`, `start`, any number of
`exec` calls, `stop`, and `deprovision`. SDK calls can run in-process or in
separate `wxc-exec` processes; neither SDK consumers nor request JSON supply or
relay the ID. `UTCReplace_AppSessionGuid` retains its existing UTC semantics
and is not the cross-process lifecycle join key.

Provision seeds a Microsoft Correlation Vector (MS-CV), whose canonical base
encodes 16 random bytes in 22 unpadded base64 characters. Once provision returns
a sandbox ID, MXC persists the root internally under
`%LOCALAPPDATA%\mxc\correlation\<sha256(sandbox_id)>.cv`. Later phases recall that
root and spin distinct child vectors. The root's bytes, with UUID version/variant
bits set, become the same lowercase UUIDv4-formatted `mxc.session_id` on every
event. No additional session file or released SDK parameter is needed.
`__TlgCV__` retains the hierarchical vector for phase-level analysis.

Each create-and-run execution instead generates a fresh session UUID directly
from OS randomness; its `__TlgCV__` remains empty. Neither identifier is derived
from a user, device, command, executable name, or sandbox ID. The sandbox-ID hash
is only a local storage lookup key and is not emitted as the session ID.
The existing CV generator has a clock/nonce fallback when OS randomness fails;
lifecycle IDs inherit that exceptional fallback, not a cryptographic guarantee.
The direct create-and-run UUID path does not use this fallback.

`provision-session` and `deprovision-session` each seed an independent vector
when telemetry is authorized. They do not read, create, refresh, sweep, or
delete the sandbox correlation store. Session IDs are not correlation-store
keys or vector seeds. Their `mxc.session_id` values are independently generated
diagnostic identifiers, not the backend's session identity. This applies to the executor, raw JSON entry points,
and typed engine calls. Sandbox operations retain their existing store cleanup.

The per-user store serializes operations with a cross-process file lock and
atomically replaces records. When a record is missing, corrupt, or pruned, the
phase uses a new root but does not write it. After a successful, non-dry-run
`start`, `exec`, or `stop`, MXC persists that root under the same lock (keeping
any record a concurrent request already wrote), so later phases correlate even
if telemetry was disabled during provision. Dry runs and rejected requests leave
the store unchanged. That new segment cannot recover
earlier events' ID.

Correlation in this case is best effort. If telemetry is first enabled after
provision and two phases for the same sandbox overlap before any root has been
persisted, each can start with a different root. The first successful phase
wins and every later phase reuses it. The losing invocation's own events stay
consistent with each other but are not linked to the stored lifecycle. MXC does
not serialize whole operations to prevent this. When telemetry is enabled from
provision, correlation is not affected. A successful new provision replaces any previous root; if
telemetry is disabled, it removes stale state rather than linking a reused
sandbox ID to an old lifecycle.

Successful deprovision and terminal `not_provisioned` results remove the record,
even when telemetry is disabled. Failed and dry-run deprovision retain it.
Loads refresh active records; opportunistic pruning removes unrelated records
older than 30 days and temporary files older than one day, with bounded sweeps.
Disabling telemetry does not generate new roots; cleanup can remove existing
state. Withdrawn consent continues to suppress emission.

Store unavailability reports a diagnostic and permits a disconnected root
without changing sandbox results. Cross-process continuity cannot be guaranteed
without the shared record, including across different user accounts. Invalid
session context or direct UUID-generation failure records `unknown`, with a
fixed-code warning on normal initialization. Out-of-band executor panic and
cancellation paths resume the stashed session on a best-effort, nonblocking basis.
These IDs are diagnostic correlation, not authenticated identities.

### Crash telemetry (panic hook)

When telemetry is active, the executors install a global
[`std::panic::set_hook`] handler — both the one-shot executors and the
state-aware path (`run_state_aware_main`). If any thread panics, the hook emits
a failure `MXC.ExecutionEnd` plus an `MXC.Error` categorised as `internal_error`
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
> `MXC.ExecutionEnd` completion event is therefore suppressed, so telemetry reports
> `mxc.exit_code` = 101 even though the recovered process ultimately exits with a
> different code (`-1`). The `101` here is a "a panic occurred" sentinel, not a
> claim about the observed process exit code; `outcome` and `error_type` remain
> accurate. Backends that do not catch panics (the Windows one-shot executor)
> abort with `101`, so the recorded code matches the real exit.

### Cancellation telemetry (console control handler)

On Windows, when telemetry is active, `wxc-exec`'s console control handler emits
a failure `MXC.ExecutionEnd` plus an `MXC.Error` categorised as `cancelled` when the
operator interrupts a run (Ctrl-C, console close, or a system shutdown/logoff).
The reported `mxc.exit_code` is 130 (the conventional "terminated by Ctrl-C"
code, 128 + SIGINT) — a bounded attribution sentinel, since the OS ultimately
terminates the process with its own status. The handler runs on a short,
OS-imposed budget and does not shut the provider down; the events carry no
free-form text.

## Consent

The development `1.1.0-alpha` contract emits only the four Required events. MXC
moved these events to Required telemetry to keep MXC secure, reliable, and up to
date, so they are gated by build eligibility and provider availability, not
by the per-run request, MXC consent or administrative policy.

Published contracts keep the optional model: emission is gated by the per-run
request, MXC-owned consent, administrative policy, and provider availability.
See [`telemetry-consent-design.md`](telemetry-consent-design.md). Local diagnostic
audit records are a separate operator-selected sink and are not uploaded.

The privacy-reviewed version 4 `en-US` consent wording is the canonical
disclosure for the optional events. Its title, body, action labels, and privacy link are documented in
[Telemetry consent design](telemetry-consent-design.md#canonical-consent-resource)
and must be rendered verbatim by every EXE and SDK presenter.

The optional ETW events contain MXC version/channel, debug-build state,
caller-requested sandbox kind, selected backend, bounded outcomes and failure
categories, numeric status values, lifecycle phase, policy fingerprints, and
opaque/redacted identities. They do not contain commands, file paths,
credentials, customer content, or free-form error text.

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
diagnostic sinks. They exist so facts MXC already knows — a process exit code,
a teardown result, a rejected config — are *machine-readable*
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
{"event":"mxc.ProcessExited","backend":"processcontainer","identity":"redacted","tier":"base-container","pid":1234,"exit_code":0}
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
  configuration (the caller's `containerId`) is retained only when it matches
  one of the closed set of shapes MXC itself mints — the literal default `CLI`
  or the state-aware `iso:<token>` / `wsb:<token>` ids (≤64 chars, opaque token
  characters only).
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
`config_schema_version`, and `mxc.ConfigRejected` has `correlation_id` and
`backend` plus its rejection fields.

`correlation_id` is a per-invocation opaque hex token, minted once per process
and stable for its lifetime. It exists because a rejection is refused *before* a
sandbox identity is assigned, so it is the only key that groups several
rejection records from the same invocation. A successful launch emits no
`mxc.ConfigRejected` at all.

| Record | When | Fields beyond the common ones |
|---|---|---|
| `mxc.PolicyHash` | Every launch, after the effective request is resolved | `backend`, `policy_hash`, `config_schema_version` |
| `mxc.SandboxIdentity` | After a successful state-aware phase | `backend`, `identity`, `phase` |
| `mxc.NetworkPolicyApplied` | After network policy setup, on success **and** failure | `backend`, `identity`, `tier` (no `pid` yet), plus `enforcement_mode`, `default_policy`, `proxy_port`, `firewall_rules_created`, `firewall_applied`, `status` |
| `mxc.ProcessExited` | Sandboxed process exited on its own | `exit_code` |
| `mxc.ProcessTimedOut` | `scriptTimeout` breached | `timeout_ms` |
| `mxc.ProcessKillFailed` | A kill/terminate call failed (**failure only**) | `kill_method`, `error_code` |
| `mxc.SandboxTornDown` | Per-run resources released, once per handle | ProcessContainer: `backend`, `identity`, `tier`, `pid`, `status`, `firewall_rules_removed`, `firewall_removal_ok`, `proxy_stopped`, `preserve_policy`, `container_released`, `skip_reason`. IsolationSession: `backend`, `identity`, `phase`, `status`, `session_stopped`, `agent_user_deprovisioned`, `client_unregistered` |
| `mxc.ConfigRejected` | A request was refused before it could run | `correlation_id`, `backend`, `reason`, `offending_field`, `phase` |

### Error semantics

**`ActivityError` is an OS-side ETW field, not an MXC record field.** MXC does
not emit, define, or interpret it, and it does not appear in the local audit
format described here. A non-zero `ActivityError` on an OS Sandboxing-provider
event is an OS-internal outcome; it does not report on MXC policy enforcement.

Notes on the ones that are easy to misread:

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
**exhaustively destructures** `ExecutionRequest` — adding a field is a compile
error until it is classified.

Excluded, and why:

| Excluded | Reason |
|---|---|
| `script_code` | The command line is *what runs*, not the policy it runs under; it routinely embeds credentials. |
| `env` | Environment variables are the classic secret carrier. |
| `source_contract` | External exact-contract provenance used for diagnostics and telemetry attribution, not enforcement. |
| `telemetry`, internal `test` feature | No enforcement effect. |
| proxy `original_url` | Can embed `user:password@`. The host and port *are* hashed. |
| `dry_run` | Invocation mode, not policy. |
| `experimental_enabled` | Authorizes selecting an experimental backend, not enforcement; changing it leaves policy identity unchanged. |

The retired network compatibility marker, legacy network model fields, and
built-in test proxy discriminator are no longer part of the projection. Hashes
from builds that included them can differ even when the supported effective
policy is unchanged; compare policy hashes across builds only with those
projection changes in mind.

Enforcement-relevant backend configuration is hashed from
`ExecutionRequest.windows_sandbox` and `ExecutionRequest.wslc`. The canonical
projection exposes them at the `windowsSandbox` and `wslc` root keys.
IsolationSession has no corresponding one-shot runtime configuration in this
projection.

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
| `mxc.NetworkPolicyApplied` | ✅ (PSEC) | — | — | — |
| `mxc.ProcessExited` / `TimedOut` / `KillFailed` | ✅ (including isolation-session one-shot) | ✅ (isolation-session exec) | — | — |
| `mxc.SandboxTornDown` | ✅ | ✅ (isolation-session stop/deprovision) | — | — |

The shared audit types compile identically on all three platforms; the gap is
that the *emission sites* were added only to the
Windows runners and the `wxc-exec` binary, because the originating requirement
was Windows-only. Extending them to `lxc-exec` and `mxc-exec-mac` is tracked
follow-up work, not a design decision that Linux and macOS do not need an audit
trail.

The isolation-session process-boundary records are emitted from the shared
`create_process` path, so they cover both the one-shot runner and state-aware
`exec`. State-aware phases obtain a sink via
`Logger::inherit_thread_diagnostic_sink()` rather than through a `Logger`
parameter on the `StatefulSandboxBackend` trait, so no trait signature change
was required to record them.



### Requirement coverage by backend

The originating requirements (M-ETW-1 … M-ETW-7) name two backends:
`process_container` and `isolation_session`. This matrix records, per requirement, whether each backend emits the
corresponding `Microsoft.MXC` ETW event. The separate `mxc.*` JSON audit
records remain available through explicitly configured diagnostic sinks, but
they are not the ETW transport. "n/a" means the requirement cannot apply, not
that it was skipped.

| Requirement | ProcessContainer (PSEC) | IsolationSession one-shot | IsolationSession state-aware |
|---|---|---|---|
| Process outcome (M-ETW-1) | ✅ | ✅ | ✅ (shared `create_process`) |
| Enforcement degradation (M-ETW-2) | n/a | n/a | n/a |
| Policy hash (M-ETW-3) | ✅ | ✅ | ✅ |
| Network policy (M-ETW-4) | ✅ (`enforcement_mode: capabilities` — policy travels in the sandbox spec and the OS enforces it, so `firewall_rules_created` is honestly `0`) | n/a — MXC rejects network and proxy policy for this backend before provisioning | n/a |
| Sandbox teardown (M-ETW-5) | ✅ | ✅ | ✅ (`stop` and `deprovision` phases) |
| IsolationSession telemetry (M-ETW-6) | n/a | ✅ Applicable lifecycle events use `Microsoft.MXC`; no separate OS provider is assumed | ✅ Same provider path |
| Configuration rejection (M-ETW-7) | ✅ | ✅ | ✅ (`phase` names the rejecting phase) |

M-ETW-6 is satisfied for MXC-owned IsolationSession lifecycle events through
the `Microsoft.MXC` provider. The IsolationSession API does not expose a
separate OS provider that MXC can control; no such provider is invented or
required. The corresponding JSON audit records remain separate and are not
counted as ETW.

The `n/a` cells are structural, not deferred work. No current backend selects
among enforcement levels, so there is nothing to degrade (M-ETW-2). MXC refuses
isolation-session network/proxy configuration at parse time, so there is no
applied network policy to report (M-ETW-4); that row changes only if the
separate network-proxy requirement is implemented for that backend.

Backends outside the requirement's scope — Windows Sandbox, WSLC,
MicroVM/Hyperlight, ACI, LXC, Bubblewrap, and Seatbelt — are not covered by this
matrix. See [Platform scope](#platform-scope).

### Correlating with existing OS telemetry

| Requirement | Existing OS coverage | MXC local coverage | Join/correlation notes |
|---|---|---|---|
| Process outcome (M-ETW-1) | Existing OS process-lifecycle records cover normal exit. The OS does not provide a verified timeout or kill-failure record for this requirement. | `mxc.ProcessTimedOut` and `mxc.ProcessKillFailed` cover the MXC boundary for both one-shot and state-aware paths. | Join the OS lifecycle identity to the MXC sandbox identity where available; use the process ID for process records. |
| Enforcement degradation (M-ETW-2) | Not applicable: no current backend selects among enforcement levels. | — | — |
| Policy hash (M-ETW-3) | No policy hash field is emitted by the isolation-session OS provider. | `mxc.PolicyHash` records the effective MXC policy locally, excluding secrets and command content. | Correlate by the invocation/lifecycle context; the hash is an MXC record, not an OS field. |
| Network policy (M-ETW-4) | Not applicable to `isolation_session`: MXC rejects its network and proxy policy before OS provisioning. | `mxc.NetworkPolicyApplied` covers OS-enforced PSEC network setup. | This row changes only if the separate M1 network-proxy requirement is implemented. |
| Sandbox teardown (M-ETW-5) | Existing OS lifecycle and security records cover OS cleanup. | `mxc.SandboxTornDown` covers process-container cleanup and isolation-session `stop`/`deprovision`, naming each reported release outcome without duplicating the agent-user/container result. | Join by the lifecycle identity where available; OS cleanup may outlive the MXC process boundary. |
| IsolationSession telemetry (M-ETW-6) | Existing OS providers record isolation-session lifecycle, but not all MXC-side policy or rejection detail; no separate OS provider is assumed. | `Microsoft.MXC` carries applicable MXC-owned IsolationSession lifecycle events; the JSON audit records remain a separate local sink. | Join MXC lifecycle events by the existing lifecycle correlation context where available. |
| Configuration rejection (M-ETW-7) | Existing OS records do not expose the MXC parser's bounded field path and rejection category. | `mxc.ConfigRejected` records the bounded reason, offending field, backend, phase, and a per-invocation `correlation_id`. | MXC validation commonly occurs before the OS call, so no OS rejection event should be expected for these records. The human-readable error remains on the existing operator-facing channel; the audit record contains no rich error text. |

This table documents ETW coverage and correlation. The separate JSON audit
records are not converted into OS telemetry, and OS event names/capture
procedures vary by OS build.

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

MXC generates one registration with the provider name `Microsoft.MXC` and its
derived GUID. All events use the WinExt group and the MXC privacy product;
there is no Windows Core registration. The mechanism is public; the actual
group value is private. The build validates GUID syntax, not group identity
or production approval.

### How it works

| Handle | Private build input | Metadata when configured |
|---|---|---|
| `MXC_PROVIDER` | Signed telemetry component | Measures/Usage, or Critical Data/Performance for the four selected development events |

An unrouted build produces a local-only registration with keyword
`0x1` and privacy tag `0` for every event. The obsolete
`MXC_TELEMETRY_CORE_PROVIDER_GROUP_GUID` and
`MXC_TELEMETRY_PROVIDER_GROUP_GUID` inputs fail Windows builds when nonempty.
Non-Windows builds ignore them.

The shared event writer selects the keyword and privacy tag using the event
and request's source contract, always on the same registration. Field names, types
and order, including `PartA_PrivTags`, remain unchanged. The guarded local
metadata-test input supplies both category masks/tags without joining a
group and cannot be combined with the routing input.

The provider GUID is **not** specified in either branch. The `tracelogging`
crate's `define_provider!` macro derives it deterministically from the provider
name using the standard ETW name-hash algorithm (the same algorithm used by
`<TraceLoggingProvider.h>`, WIL's `IMPLEMENT_TRACELOGGING_CLASS`, and .NET's
`EventSource`). For `"Microsoft.MXC"` the derived GUID is
`{7f10def4-a258-5fea-510e-2c3bb976687f}`. Keeping the name and GUID in lockstep
this way prevents drift and avoids hard-coding a literal that could collide
with another team's GUID.

The zero-value default (no group GUID → keyword `0x1`, privacy tag `0`)
mirrors Microsoft's own public WSL repo, which defines these same telemetry
constants as literal `0` for non-official builds.

### Telemetry component

Release builds read the group, keywords, privacy tags, product and data
category from a signed `mxc_telemetry.dll` that is built in a private
repository. The component only carries data; MXC never loads it at run time.

The signed x64 and ARM64 DLLs are committed under
`src/mxc-sdk/resources/telemetry-component/<arch>/` so source builds are
routed too. Release builds on Windows use the DLL for the build host's
architecture. Debug builds, and builds where that DLL is absent, are unrouted.
`MXC_TELEMETRY_COMPONENT_PATH` overrides the DLL; set it to an empty value to
force an unrouted release build. To refresh the DLLs, rebuild them in the
private pipeline and replace both files. The values are plain data in the DLL,
so anyone can read them, and forks inherit the routing.

When a DLL is selected on a Windows build host, the MXC build script:

1. opens the DLL with writers denied and verifies its Authenticode signature
   and signer name, and fails the build if either is wrong;
2. loads it and calls the exported `mxc_telemetry_metadata_v1` function, which
   returns `1;<group>;<keyword>;<privacy tag>;<critical keyword>;<critical privacy tag>;<product>;<data category>`;
3. passes the numbers to the crate as `MXC_BUILD_*` environment variables read
   with `env!`.

Without a component, builds use placeholder values that are never routed.
`MXC_TELEMETRY_PROVIDER_GROUP_GUID` is no longer supported: a nonempty value
fails Windows builds, so routing always comes from the verified component.

### CI pipeline steps

The private pipeline builds and signs the component DLL; its output is copied
into `src/mxc-sdk/resources/telemetry-component/`. Do not copy private values
into repository files or logs.

Published contracts retain their existing registration, Measures/Usage
metadata, request opt-in, consent and policy gates. Debug builds and builds
with an empty `MXC_TELEMETRY_COMPONENT_PATH` retain local-only metadata.

The public Windows test artifact explicitly clears the component input. Its
local metadata tests cannot verify the routing values or establish Microsoft
ingestion.

### WinExt routing acceptance

On an approved disposable Windows VM, use a release build with the signed
component. For published contracts keep MXC's explicit consent, request
opt-in, and permitting MXC policy satisfied. Development requests need no
consent or opt-in. Verify actual collection for both, including successful
process exit and operational failure; verify published suppression after
consent withdrawal. Development requests keep emitting at every
administrative policy value, including `0`.

Windows Required/Optional settings do not authorize or gate these WinExt
events. Do not use acceptance at a Windows diagnostic-data level as evidence
of an MXC Required/Optional consent model. Local ETW proves emission and
metadata, not acceptance by the Microsoft collection pipeline.

### Local developer testing

```powershell
# Release build with the bundled signed component (routed)
cargo build --release -p mxc-sdk

# Release build without routing (local-only metadata)
$env:MXC_TELEMETRY_COMPONENT_PATH = ''
cargo build --release -p mxc-sdk
Remove-Item Env:\MXC_TELEMETRY_COMPONENT_PATH
```

### What's public vs. private

| Item | Public? | Why |
|------|---------|-----|
| Provider name `"Microsoft.MXC"` | Yes | Standard ETW naming |
| Provider GUID `{7f10def4-a258-5fea-510e-2c3bb976687f}` | Yes | Derived from the name; identifies the provider, harmless |
| `build.rs` component mechanism | Yes | Mechanism is public |
| Signed `mxc_telemetry.dll` | Yes | Committed so source builds are routed |
| Component source and pipeline | No | Private repository |

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
