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
GUID do not set this variable — the provider is registered without a group GUID
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
| Provider name `"Microsoft.MXC"` | ✅ | Standard ETW naming |
| Provider GUID `{7f10def4-a258-5fea-510e-2c3bb976687f}` | ✅ | Derived from the name; identifies the provider, harmless |
| `build.rs` env var mechanism | ✅ | Mechanism is public |
| `MXC_TELEMETRY_PROVIDER_GROUP_GUID` env var name | ✅ | Key is public; value is private |
| Actual Microsoft telemetry group GUID | ❌ | Private — set in CI only |

## SDK License Override (EULA for npm Package)

The public GitHub repo ships `sdk/LICENSE.md` as a plain MIT license. For
internal npm publishes, a separate EULA containing a **Section 2 — DATA**
clause (covering telemetry disclosure, opt-out, and GDPR) will be updated at
pack/publish time. 

### How it works

```
1. CI pipeline (or local script) sets MXC_LICENSE_OVERRIDE env var
   pointing to the markdown file of the EULA including additional telemetry language.
   Note that the new EULA will include language outlining what data can be collected but
   will otherwise remain MIT licensed.

2. A license-override script (added in a follow-up build-integration PR) runs:
   ├── MXC_LICENSE_OVERRIDE is set:
   │   ├── Back up sdk/LICENSE.md → sdk/LICENSE.md.public
   │   └── Copy new EULA over sdk/LICENSE.md
   └── MXC_LICENSE_OVERRIDE is NOT set:
       └── Restore sdk/LICENSE.md from .public backup (if exists)

3. npm pack / npm publish picks up the new EULA as the LICENSE.md
   in the published package (sdk/package.json "files" includes LICENSE.md).

4. After publish, the revert path restores the original EULA document.
```
