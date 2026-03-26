# Data Model: Observability — OpenTelemetry Instrumentation & Adoption Metrics

**Date**: 2026-03-25  
**Feature**: [spec.md](spec.md)

---

## New Entity: `TelemetryConfig`

**Location**: `src/wxc_common/src/models.rs`  
**Pattern**: Mirrors existing `SandboxConfig`, `LxcConfig` — serde struct with `#[serde(default)]`.

```rust
/// Controls OTel telemetry for a single `wxc-exec` / `lxc-exec` invocation.
/// Telemetry is OFF by default (opt-in).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// Set to `true` to activate OTel span and metric emission.
    /// Alternatively, set env var `MXC_ENABLE_TELEMETRY=1`.
    pub enabled: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}
```

**Validation rules**:
- Malformed JSON in the `telemetry` section → treated as `TelemetryConfig::default()` (enabled = false).
- `enabled: true` in config OR `MXC_ENABLE_TELEMETRY=1` env var → telemetry is active.
- Both off → telemetry is inactive.

---

## Modified Entity: `CodexRequest`

**Location**: `src/wxc_common/src/models.rs`  
**Change**: Add one field.

```rust
pub struct CodexRequest {
    // ... existing fields unchanged ...
    pub telemetry: TelemetryConfig,   // NEW — defaults to disabled
}
```

---

## New Entity: `TelemetryHandles` (internal, not serialized)

**Location**: `src/wxc_common/src/telemetry.rs`  
**Purpose**: Owns the live OTel providers so they can be shut down gracefully before exit.

```rust
pub struct TelemetryHandles {
    tracer_provider: opentelemetry_sdk::trace::TracerProvider,
    meter_provider: opentelemetry_sdk::metrics::SdkMeterProvider,
}
```

**Lifecycle**: Created by `telemetry::init()`, consumed (and shut down) by `telemetry::shutdown()`. Never serialized or exposed outside `wxc_common`.

---

## JSON Schema Extension: `telemetry` section

**Affected schemas**: `docs/schema.md` and the TypeScript `types.ts` / `SandboxConfig` interfaces in the SDK.

### JSON
```json
{
  "script": "...",
  "containment": "appcontainer",
  "telemetry": {
    "enabled": true
  }
}
```

### TypeScript interface extension (`sdk/src/types.ts`)
```typescript
export interface WxcTelemetryConfig {
  /** Enable OTel telemetry. Defaults to false (opt-in). */
  enabled?: boolean;
}
```

Added as an optional field to the existing root config interface:
```typescript
export interface SandboxConfig {
  // ... existing fields ...
  telemetry?: WxcTelemetryConfig;
}
```

---

## Telemetry State Machine

```
              ┌──────────────────────────────────────────────────┐
              │  Determine enabled state (called once at startup) │
              └──────────────────────────────┬───────────────────┘
                                             │
              ┌──────────────────────────────▼──────────────────────────────┐
              │  MXC_ENABLE_TELEMETRY=1 in env  OR  config.telemetry.enabled │
              └──────────────────────┬──────────────────────┬───────────────┘
                                   YES                      NO
                                    │                        │
               ┌────────────────────▼──┐          ┌─────────▼────────────┐
               │ init() → installs OTel│          │ init() → NoopProvider │
               │ TracerProvider +      │          │ No network, no alloc  │
               │ MeterProvider         │          └──────────────────────┘
               └────────────────────┬──┘
                                    │ (execution runs)
               ┌────────────────────▼──────────────┐
               │ shutdown() → force_flush (≤2s)     │
               │           → provider.shutdown()    │
               └────────────────────────────────────┘
```

---

## Span Hierarchy Per Invocation

```
mxc.execute                          ← root span (attributes: mxc.backend, mxc.version)
├── mxc.container.init               ← container profile creation / setup
├── mxc.policy.filesystem            ← BFS filesystem policy setup     [Windows only]
├── mxc.policy.network               ← firewall / network policy setup [Windows only]
├── mxc.script.run                   ← child process lifetime          (exit_code recorded here)
└── mxc.container.teardown           ← cleanup (profile delete, rule removal)
```

Error events are recorded on the innermost span where the error occurs, plus propagated to `mxc.execute` via span status `ERROR`.

---

## Metric Schema

| Metric Name | Instrument | Unit | Attribute dimensions |
|-------------|-----------|------|---------------------|
| `mxc.executions` | Counter | `{execution}` | `mxc.backend` (string), `mxc.outcome` (`success`/`failure`) |
| `mxc.failures` | Counter | `{execution}` | `mxc.backend` (string), `mxc.failure_reason` (bounded enum) |
| `mxc.execution.duration` | Histogram | `ms` | `mxc.backend` (string) |

### `mxc.backend` values
`appcontainer` · `sandbox` · `lxc` · `wslc`

### `mxc.outcome` values
`success` · `failure`

### `mxc.failure_reason` values (bounded)
`config_error` · `policy_error` · `process_error` · `timeout` · `unknown`

---

## State Transitions

| Event | Span action | Metric action |
|-------|-------------|---------------|
| Execution starts | Open `mxc.execute` span | — |
| Container init starts/ends | Open/close `mxc.container.init` | — |
| Policy applied | Open/close `mxc.policy.*` spans | — |
| Script exits with code 0 | Close `mxc.script.run`, record `exit_code=0` | Increment `mxc.executions{outcome=success}`, record `mxc.execution.duration` |
| Script exits non-zero | Close `mxc.script.run`, record `exit_code=N` | Increment `mxc.executions{outcome=failure}`, `mxc.failures{reason=process_error}`, record duration |
| Validation error | Record error event on `mxc.execute`, set status ERROR | Increment `mxc.failures{reason=config_error}` |
| Policy error | Record error event on active policy span | Increment `mxc.failures{reason=policy_error}` |
| Timeout | Record error on `mxc.script.run` | Increment `mxc.failures{reason=timeout}` |
| Process exit | `force_flush`, `shutdown` | All metric readers flushed |
