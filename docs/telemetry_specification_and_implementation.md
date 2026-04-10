# MXC Telemetry — Specification & Implementation Plan

## Overview

MXC adds telemetry using Microsoft's 1DS C++ SDK
([`cpp_client_telemetry`](https://github.com/microsoft/cpp_client_telemetry)),
integrated via a Rust FFI layer. The SDK sends anonymous adoption metrics
(execution counts, backend usage, latency, error rates) to Microsoft's data
collection endpoints with geographic routing (US, EU, global, AU, JP).

Telemetry requires explicit user consent. On first interactive run, the tool
displays a CLI consent prompt. No data is emitted without consent. No personally
identifiable information (PII) is ever collected.

### Key Properties

| Property | Value |
|----------|-------|
| **PII collected** | None |
| **Default (release)** | Telemetry off until user consents |
| **Default (prerelease)** | Telemetry on in non-interactive mode; prompt shown in interactive |
| **SDK** | 1DS C++ SDK via Rust FFI (pure C API `mat.h`) |
| **Events** | `MXC.Execution`, `MXC.Error` |
| **Regional endpoints** | US, EU, Global, AU, JP — auto-detected from Windows locale |
| **Overhead** | ≤ 5 ms added wall-clock time |

---

## Architecture

```
wxc-exec.exe / lxc-exec (CLI binary)
  │
  ├── telemetry::init(config)
  │     ├── Check JSON config "telemetry.enabled" field (explicit override)
  │     ├── Check consent file (~/.cache/mxc/telemetry-consent.json)
  │     ├── If consent unknown + stdin is TTY → show consent prompt
  │     ├── Resolve region (explicit config > auto-detect > global)
  │     └── Call TelemetryClient::open(json_config)
  │
  ├── ScriptRunner::run(request, logger)    ← existing execution, unchanged
  │
  ├── telemetry::log_execution(client, result)
  │     └── Builds MXC.Execution event with properties
  │
  └── telemetry::shutdown(client)
        └── flush_and_teardown() with 2s max wait
```

### Component Stack

```
┌─────────────────────────────────────────────┐
│ wxc_common::telemetry                        │
│   High-level init / log / shutdown API       │
│   Consent file management                    │
│   Region auto-detection (GetUserDefaultGeo)  │
│   Error message sanitization                 │
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│ wxc_1ds_ffi  (new Rust crate)                │
│   Safe TelemetryClient wrapper               │
│   TelemetryEvent builder                     │
│   TelemetryRegion enum                       │
│   Raw FFI declarations (ffi.rs)              │
└──────────────┬──────────────────────────────┘
               │ extern "C" FFI
┌──────────────▼──────────────────────────────┐
│ shim.c                                       │
│   Wraps mat.h static inline functions        │
│   into real symbols for Rust linking         │
└──────────────┬──────────────────────────────┘
               │ static link
┌──────────────▼──────────────────────────────┐
│ cpp_client_telemetry (libmat.a / mat.lib)    │
│   1DS C++ SDK compiled from source           │
│   Async upload, SQLite offline cache         │
│   Regional endpoint routing built-in         │
└──────────────┬──────────────────────────────┘
               │ HTTPS
┌──────────────▼──────────────────────────────┐
│ Microsoft data collection endpoints          │
│   https://{region}-mobile.events.data.       │
│   microsoft.com/OneCollector/1.0/            │
└─────────────────────────────────────────────┘
```

---

## Telemetry Events

### `MXC.Execution`

Emitted once per `wxc-exec` / `lxc-exec` invocation at process exit.

| Property | Type | Example | Description |
|----------|------|---------|-------------|
| `mxc.backend` | string | `appcontainer` | Containment backend used |
| `mxc.outcome` | string | `success` | `success` or `failure` |
| `mxc.exit_code` | int64 | `0` | Process exit code |
| `mxc.duration_ms` | int64 | `1234` | Total wall-clock execution time |
| `mxc.init_duration_ms` | int64 | `50` | Container init time |
| `mxc.version` | string | `0.2.0` | MXC version |
| `mxc.build_type` | string | `release` | `prerelease` or `release` |
| `mxc.region` | string | `eu` | Configured telemetry region |
| `mxc.failure_reason` | string | `policy_error` | Only on failure (bounded enum) |

### `MXC.Error`

Emitted on error, in addition to `MXC.Execution`.

| Property | Type | Example | Description |
|----------|------|---------|-------------|
| `mxc.backend` | string | `appcontainer` | Containment backend |
| `mxc.error_type` | string | `policy_error` | Bounded enum |
| `mxc.error_message` | string | `Firewall rule creation failed` | Sanitized (no PII) |
| `mxc.version` | string | `0.2.0` | MXC version |

### Failure Reason Enum

`config_error` · `policy_error` · `process_error` · `timeout` · `init_error` · `unknown`

### PII Guardrails

The following **never** appear in any event property:

- File paths, script content, working directory
- Environment variable values
- Usernames, machine names, IP addresses

Error messages are passed through a sanitization function that strips known PII
patterns before inclusion in events.

---

## Consent & Opt-In / Opt-Out

### Resolution Priority

| Priority | Source | Effect |
|----------|--------|--------|
| 1 (highest) | JSON config `"telemetry": { "enabled": true/false }` | Explicit override, always wins |
| 2 | Consent file (`telemetry-consent.json`) | User's prior interactive choice |
| 3 | Interactive prompt (if stdin is TTY) | Asks user, persists choice to consent file |
| 4 (lowest) | Build-type default | prerelease=on, release=off |

### First-Run Consent Prompt

When consent is unknown and stdin is a terminal:

```
────────────────────────────────────────────────────────
Help improve MXC!

MXC collects anonymous usage data (backend type, execution
outcome, latency) to improve the product. No personally
identifiable information (PII) is collected.

Privacy statement: https://go.microsoft.com/fwlink/?LinkId=521839

Do you consent to telemetry collection? [Y/n]:
────────────────────────────────────────────────────────
```

- Rendered on **stderr** (not stdout)
- `y`, `Y`, or Enter → consent, telemetry enabled
- `n` or `N` → decline, telemetry disabled
- Invalid input → re-prompt (max 3 times, then treat as "no")
- Ctrl+C → exit cleanly, no consent file written

### Consent File

| Platform | Path |
|----------|------|
| Windows | `%LOCALAPPDATA%\mxc\telemetry-consent.json` |
| Linux | `~/.cache/mxc/telemetry-consent.json` |

```json
{
  "enabled": true,
  "consented_at": "2026-04-10T14:30:00Z"
}
```

The directory is created automatically. Corrupt files are treated as "consent
unknown" (re-prompts on next interactive run).

### Non-Interactive Mode (CI / Automation)

When stdin is not a terminal, no prompt is shown. The build-type default applies:

- **Release builds**: telemetry off (no data emitted)
- **Prerelease builds**: telemetry on (enables adoption tracking for beta testers)

---

## Regional Endpoint Routing

### Supported Regions

| Region | Endpoint |
|--------|----------|
| `global` (default) | `https://mobile.events.data.microsoft.com/OneCollector/1.0/` |
| `us` | `https://us-mobile.events.data.microsoft.com/OneCollector/1.0/` |
| `eu` | `https://eu-mobile.events.data.microsoft.com/OneCollector/1.0/` |
| `au` | `https://au-mobile.events.data.microsoft.com/OneCollector/1.0/` |
| `jp` | `https://jp-mobile.events.data.microsoft.com/OneCollector/1.0/` |

### Region Resolution

1. **Explicit config**: `"telemetry": { "region": "eu" }` — always wins
2. **Auto-detection** (Windows): `GetUserDefaultGeoName` → ISO 3166-1 country
   code → mapped to the nearest 1DS region:
   - EU-27 + UK, NO, CH, IS, LI → `eu`
   - US → `us`
   - AU, NZ → `au`
   - JP → `jp`
   - All others → `global`
3. **Fallback**: `global` (API failure, Linux, unknown country code)

---

## JSON Configuration

Add an optional `telemetry` section to any MXC config file:

```json
{
  "version": "0.4.0-alpha",
  "process": {
    "commandLine": "python app.py",
    "timeout": 30000
  },
  "telemetry": {
    "enabled": true,
    "region": "eu"
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | (consent-based) | Explicit override for telemetry on/off |
| `region` | string | auto-detected | Collector region: `us`, `eu`, `global`, `au`, `jp` |

When `telemetry` is absent, the consent file and build-type defaults apply.
Malformed telemetry sections are treated as absent (safe default).

---

## Source Code Layout

```
src/
├── wxc_1ds_ffi/                     # NEW: Rust FFI crate
│   ├── Cargo.toml                   # thiserror dep + cc/cmake build-deps
│   ├── build.rs                     # CMake → libmat.a + cc → shim.o
│   ├── shim.c                       # C shim wrapping mat.h inlines
│   └── src/
│       ├── lib.rs                   # Safe TelemetryClient wrapper
│       ├── ffi.rs                   # extern "C" declarations
│       └── types.rs                 # TelemetryEvent, TelemetryError, TelemetryRegion
│
├── wxc_common/src/
│   ├── models.rs                    # MODIFIED: + TelemetryConfig struct
│   ├── config_parser.rs             # MODIFIED: + telemetry section parsing
│   └── telemetry.rs                 # NEW: init/log/shutdown + consent + region detect
│
├── wxc/src/main.rs                  # MODIFIED: telemetry hooks at start/end
└── lxc/src/main.rs                  # MODIFIED: same pattern

third_party/
└── cpp_client_telemetry/            # Git submodule (1DS C++ SDK, v3.10.40.1)
```

### FFI Layer Design

The 1DS C API (`mat.h`) uses `static inline` functions that call through a
function pointer. Since Rust can't link against inline functions, a thin C shim
(`shim.c`) wraps them into real exported symbols:

```c
// shim.c
evt_handle_t mxc_evt_open(const char* config)      { return evt_open(config); }
evt_status_t mxc_evt_log(evt_handle_t h, evt_prop* e) { return evt_log(h, e); }
evt_status_t mxc_evt_flush_and_teardown(evt_handle_t h) { return evt_flushAndTeardown(h); }
// ... 6 more functions
```

The Rust side declares matching `extern "C"` bindings and wraps them in a safe
`TelemetryClient` struct with `Drop` for automatic cleanup.

---

## Build System Changes

### Git Submodule

`cpp_client_telemetry` has no binary distribution. It is included as a git
submodule at `third_party/cpp_client_telemetry` pinned to `v3.10.40.1`.

```bash
git submodule update --init --recursive
```

### `build.rs` Integration

The `wxc_1ds_ffi` crate's `build.rs`:

1. **Checks** for the submodule presence (fails with a clear message if missing)
2. **Builds** the 1DS library via CMake as a static archive
3. **Compiles** `shim.c` via the `cc` crate
4. **Emits** platform-specific link directives:
   - Windows: `wininet`, `ws2_32`, `crypt32`, `rpcrt4`
   - Linux: `curl`, `sqlite3`, `z`, `pthread`, `stdc++`

### GitHub Actions CI

Changes to `.github/workflows/build.yml`:

| Job | Change |
|-----|--------|
| `wxc-exec-lint` | Add `submodules: recursive` to checkout |
| `wxc-exec-build` (x64 + ARM64) | Add `submodules: recursive` + cache `target/` keyed on submodule SHA |
| `wxc-typescript-sdk` | Add `submodules: recursive` for consistency |
| `wxc-typescript-cli` | Add `submodules: recursive` for consistency |

All current Windows CI runners (`windows-latest`, `windows-2025`, `windows-11-arm`)
include VS 2022 C++ and CMake. No additional toolchain setup needed.

### Build Time Impact

| Scenario | Added Time |
|----------|-----------|
| First build (cold cache) | ~30–60s (C++ compilation) |
| Incremental (Rust changes only) | ~0s (CMake output cached in `target/`) |
| CI with cache hit | ~5s (cache restore overhead) |
| CI cache miss (submodule bumped) | ~30–60s (full CMake rebuild) |

---

## TypeScript SDK / CLI

The TypeScript layer is a transparent pass-through. It does NOT independently
run telemetry — it simply passes the `telemetry` section from the caller's
config to `wxc-exec` via the JSON config file.

```typescript
// sdk/src/types.ts
export interface TelemetryConfig {
  enabled?: boolean;
  region?: string;
}
```

The SDK and CLI type definitions include the `TelemetryConfig` interface so
callers can set `telemetry: { enabled: true, region: "eu" }` in their config
objects.

---

## Functional Requirements

| ID | Requirement |
|----|-------------|
| FR-001 | Emit `MXC.Execution` event for every invocation |
| FR-002 | Events include: backend, exit_code, duration_ms, init_duration_ms, version, build_type, region |
| FR-003 | Events MUST NOT include PII (paths, env vars, usernames, IPs) |
| FR-004 | Adoption metrics captured as event properties for server-side aggregation |
| FR-005 | `"telemetry": { "enabled": true }` activates telemetry |
| FR-006 | `"telemetry": { "enabled": false }` suppresses telemetry |
| FR-007 | Resolution: JSON config > consent file > build-type default |
| FR-008 | Telemetry failures never affect execution output or exit code |
| FR-009–011 | TypeScript SDK/CLI pass through `telemetry` section transparently |
| FR-012 | Regional endpoint routing (US, EU, global, AU, JP) |
| FR-012a | EU region → EUDB-compliant endpoint |
| FR-012b | Auto-detect region from Windows locale when not configured |
| FR-013 | 1DS C++ SDK via Rust FFI (pure C API) |
| FR-014 | Existing Logger/ETW unchanged |
| FR-015 | README Telemetry section documenting all behavior |
| FR-016 | Async upload, ≤ 5 ms overhead |
| FR-017 | `flush_and_teardown()` before exit, 2s max wait |
| FR-018–022 | CI pipeline: submodule checkout, CMake caching, error guard |
| FR-023–027 | First-run consent prompt: TTY detection, consent file, prompt UX |

## Success Criteria

| ID | Criterion |
|----|-----------|
| SC-001 | Every execution produces an `MXC.Execution` event |
| SC-002 | No telemetry emitted without consent |
| SC-003 | Zero PII in any event property |
| SC-004 | Per-backend adoption data available |
| SC-005 | Unreachable collector does not affect execution |
| SC-006 | TypeScript correctly passes telemetry config through |
| SC-007 | ≤ 5 ms overhead |
| SC-008 | Short-lived runs flush events before exit |
| SC-009 | End-to-end test confirms events reach backend |

---

## Edge Cases

| Scenario | Behavior |
|----------|----------|
| Collector unreachable | Best-effort, fire-and-forget; no user-visible errors |
| Abnormal exit (crash) | 1DS offline cache may retry; event loss acceptable |
| Malformed `telemetry` section | Treated as absent; warning on stderr |
| Unknown `region` value | Falls back to `global` |
| `GetUserDefaultGeoName` failure | Falls back to `global` |
| Corrupt consent file | Re-prompts if TTY, otherwise build-type default |
| Ctrl+C during prompt | Clean exit, no consent file written |
| Consent directory missing | Created automatically; failure is non-fatal |

---

## Implementation Tasks

### Setup

- Add `cpp_client_telemetry` as git submodule at `third_party/`
- Create `wxc_1ds_ffi` crate with `Cargo.toml`, `build.rs`, `shim.c`
- Add `wxc_1ds_ffi` to workspace, add `Win32_Globalization` feature to `windows` crate
- Update `build.bat` and `build.sh` for submodule init
- Update GitHub Actions for submodule checkout + CMake caching

### FFI Layer

- Implement `shim.c` (9 functions wrapping `mat.h` inlines)
- Implement `build.rs` (CMake + cc + submodule guard)
- Implement `ffi.rs` (extern "C" declarations + repr(C) types)
- Implement `types.rs` (TelemetryRegion, TelemetryEvent, TelemetryError)
- Implement `lib.rs` (safe TelemetryClient wrapper with Drop)

### Core Telemetry Module

- Add `TelemetryConfig` to `models.rs`, parse in `config_parser.rs`
- Implement `telemetry.rs`: FailureReason enum, sanitize_error_message,
  build_execution_event, build_error_event, init, log_execution, log_error, shutdown
- Implement consent file read/write, TTY detection, consent prompt
- Implement `detect_region()` via `GetUserDefaultGeoName`
- Integrate into `wxc/src/main.rs` and `lxc/src/main.rs`

### TypeScript

- Add `TelemetryConfig` interface to `sdk/src/types.ts` and `cli/src/types.ts`
- Pass `telemetry` section through in SDK executor and CLI handler



## References

- [1DS C++ SDK](https://github.com/microsoft/cpp_client_telemetry) — Apache-2.0
- [Microsoft Privacy Statement](https://go.microsoft.com/fwlink/?LinkId=521839)
- [MXC Configuration Schema](schema.md)
- [MXC Versioning Design](versioning.md)
