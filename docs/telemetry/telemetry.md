# MXC Telemetry — Pure Rust TraceLogging Architecture

MXC uses the Rust [`tracelogging`](https://crates.io/crates/tracelogging) crate
(published by Microsoft) for TraceLogging ETW telemetry. No C++ shim, WIL, or
FFI is required.

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

## TraceLogging implementation

The Rust `tracelogging` crate provides MXC's required ETW primitives without a
C++ build, NuGet dependency, or FFI boundary. MXC supplies the remaining
provider metadata through Rust constants and `write_event!` struct fields.

### Feature comparison

| Feature | WIL (`wil/TraceLogging.h`) | Rust `tracelogging` crate | MXC approach |
|---|---|---|---|
| **Provider group GUID** | `TraceLoggingOptionMicrosoftTelemetry()` | `group_id("...")` in `define_provider!` | `build.rs` generates `provider_def.rs` with/without `group_id` based on env var |
| **Sampling keywords** | `MICROSOFT_KEYWORD_MEASURES` named constant | Raw `u64` in `keyword(...)` | `const MICROSOFT_KEYWORD_MEASURES: u64 = 0x0000_4000_0000_0000` |
| **Common event fields** | `_GENERIC_PARTB_FIELDS_ENABLED` pattern | `struct("Name", { ... })` in `write_event!` | `struct("COMMON_MXC_PARAMS", { Version, Channel, IsDebugging, UTCReplace_AppSessionGuid })` |
| **Provider lifecycle** | `IMPLEMENT_TRACELOGGING_CLASS` singleton | `define_provider!` static + `register()`/`unregister()` | `OnceLock<ProviderState>` for version/channel, manual lifecycle |
| **Privacy Product** | Common Schema Part A product | `u16(...)` field | `PartA_PrivacyProduct = 11` (`MXC (Microsoft Execution Containers)`) on all events |
| **Privacy Data Category** | Common Schema Part A data category | `u16(...)` field | `PartA_PrivacyDataCategory = 1` (`Client Diagnostic Data`) on all events |
| **Privacy Data Tags** | `TelemetryPrivacyDataTag(PDT_*)` | `u64("PartA_PrivTags", &val)` field | `PDT_PRODUCT_AND_SERVICE_USAGE` on all events |
| **Activity tracking** | `DEFINE_TELEMETRY_ACTIVITY` | Manual `Opcode` | Not needed for current events |

The remaining gap (activity tracking) is not needed for current events.
If needed later, it can be added incrementally.

## Common Event Fields (Part A)

Every MXC telemetry event carries the WinExt-required Common Schema privacy
metadata:

| Field | Type | Value |
|-------|------|-------|
| `PartA_PrivacyProduct` | uint16 | `11` — `MXC (Microsoft Execution Containers)` |
| `PartA_PrivacyDataCategory` | uint16 | `1` — `Client Diagnostic Data` |
| `PartA_PrivTags` | uint64 | `Product and Service Usage Data` |

Product `11` is privacy-approved and registered in the WinExt product list.
The OS/Common Schema catalog update is tracked by UTC bug `63666074`. MXC's
events use the sampled `MICROSOFT_KEYWORD_MEASURES` keyword and explicit
product consent, so they are optional diagnostic data rather than required
(CORE) or critical-optional events. If the sampling level, event purpose, or
collected fields change, the privacy tag and approval classification must be
re-evaluated.

The WinExt provider-group identifier remains a secure build input. It must not
be copied into source, tests, documentation, or commit messages.

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

The provider-qualified uploaded event identities are
`Microsoft.MXC/MXC.Execution` and `Microsoft.MXC/MXC.Error`. `Microsoft.MXC`
is the TraceLogging provider name; `MXC.Execution` and `MXC.Error` are the
event names.

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
| `mxc.sandbox_kind` | string | Containment kind requested by the caller (`process`, `vm`, or a concrete backend name) |
| `mxc.backend` | string | Concrete containment backend selected on the host |
| `mxc.exit_code` | int32 | Process exit code |
| `mxc.outcome` | string | `"success"` or `"failure"` |
| `mxc.duration_ms` | uint64 | Total execution time |
| `mxc.failure_reason` | string | Failure category (if applicable) |
| `mxc.phase` | string | State-aware lifecycle phase (`provision`\|`start`\|`exec`\|`stop`\|`deprovision`); empty for one-shot executions |

### MXC.Error

Emitted on execution errors.

| Field | Type | Description |
|-------|------|-------------|
| `mxc.sandbox_kind` | string | Containment kind requested by the caller (`process`, `vm`, or a concrete backend name) |
| `mxc.backend` | string | Concrete containment backend selected on the host |
| `mxc.error_type` | string | Error category (`config_error`, `policy_error`, `process_error`, `timeout`, `init_error`, `internal_error`, `cancelled`, `unknown`) |
| `mxc.exit_code` | int32 | Process exit code |
| `mxc.phase` | string | State-aware lifecycle phase; empty for one-shot executions |

> **No free-form error text is emitted.** Error messages can contain paths,
> usernames, or credentials, so `MXC.Error` deliberately carries only the
> bounded `error_type` category and the numeric `exit_code` — never the
> message string itself.


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
> different code (`-1`). the `101` here is a "a panic occurred" sentinel, not a
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

## Consent

Telemetry emission is gated by the per-run request, MXC-owned consent,
administrative policy, and provider availability. See
[`docs/telemetry/telemetry-consent-design.md`](telemetry-consent-design.md).

## Diagnosing "telemetry is on but I see no events"

Every gate fails closed, so a suppressed run is otherwise indistinguishable
from a broken one. Run the executor with `--debug` and look for a
`telemetry:` line, which names the gate that stopped collection:

| `--debug` line | Meaning |
|---|---|
| `not requested for this run` | The config did not set `telemetry.enabled: true`. |
| `requested but suppressed (consent=…, policy=…)` | The run asked, but MXC consent is not `granted` and/or administrative policy is `blocked`. |
| `ETW provider registration failed` | The provider could not register; no events can be written. |
| `events are emitted to local ETW only` | The build has **no provider group GUID**, so events reach local ETW but are never routed to the Microsoft pipeline. |

Two points that commonly cause confusion:

- **The Windows diagnostic-data setting is not an input.** Turning on
  "Optional diagnostic data" does not grant MXC consent. MXC owns its own
  consent store and never reads or infers from the system setting, so
  `--telemetry-consent-status` must report `effectiveState: "granted"`
  before anything is collected.
- **A build without `MXC_TELEMETRY_PROVIDER_GROUP_GUID` never uploads.**
  Without the group GUID the `Microsoft.MXC` provider is a plain ETW
  provider that UTC does not collect, so events are visible to a local ETW
  trace but will never appear in a Microsoft-side pipeline — regardless of
  consent. Internal builds must set that variable at build time.
- **`MICROSOFT_KEYWORD_MEASURES` is sampled.** Both MXC events use the
  Measures keyword, which UTC collects from only a sampled subset of
  devices, so an ordinary opted-in machine is not guaranteed to contribute
  events even when everything else is correct. This is a property of the
  keyword, not a defect: on a device forced into the collection population
  (`AllowTelemetry=3` plus DiagTrack test hooks, notably
  `SkipDownloadedSettings`) every emitted Measures event was ingested.
  Verify on such a device before concluding that a build is broken.

To confirm UTC ingestion on a dev machine, set
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey`
→ `EnableEventTranscript` (`REG_DWORD`) to `1`, restart the `DiagTrack`
service, and query
`C:\ProgramData\Microsoft\Diagnosis\EventTranscript\EventTranscript.db`
for `full_event_name LIKE '%MXC%'` — an ingested run appears as
`Microsoft.MXC.MXC.Execution`. Remove the value when finished; it makes
UTC persist a readable local copy of all collected diagnostic data.


`src/testing/wxc_e2e_tests/tests/e2e_telemetry_etw.rs` exercises this
end-to-end: it builds `wxc-exec.exe` with a fake provider group GUID, grants
consent, and decodes a live ETW trace to prove events are emitted when
consent is granted and not emitted when it is denied. It is `#[ignore]`d
because it runs its own `cargo build` and needs rights to create an ETW
session:

```
cargo test -p wxc_e2e_tests --test e2e_telemetry_etw -- --ignored
```

## Privacy review status

The version 1 `en-US` consent wording is approved for release review. The
canonical title, body, action labels, and privacy link are documented in
[Telemetry consent design](telemetry-consent-design.md#canonical-consent-resource)
and must be rendered verbatim by every EXE and SDK presenter.

### Data sent

MXC's optional diagnostic events contain:

- MXC version and channel
- Whether the build has debug assertions enabled (`IsDebugging`)
- Caller-requested sandbox kind and the concrete backend selected on the host
- Run outcome and exit code
- Run duration
- Bounded failure category
- State-aware lifecycle phase
- `UTCReplace_AppSessionGuid`, which asks the telemetry pipeline to supply a
  random per-session app identifier
- An MXC-internal lifecycle correlation identifier. SDK callers neither supply
  nor receive it.

MXC does not emit commands, file paths, credentials, customer content, or
free-form error text. The consent notice's phrase “other customer content”
covers any such values that a host or sandbox may process but MXC does not
include in these events.

### Review status

The consent wording and canonical resource are approved for release review.
The broader data inventory, retention, access, regional processing, deletion,
and localization/accessibility decisions remain pending explicit privacy
review.
