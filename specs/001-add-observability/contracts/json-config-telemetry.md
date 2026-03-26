# Contract: JSON Configuration Schema — `telemetry` section

**Feature**: [../spec.md](../spec.md)  
**Contract type**: JSON input schema extension  
**Affected files**: `docs/schema.md`, `src/wxc_common/src/config_parser.rs`, `sdk/src/types.ts`, `cli/src/types.ts`

---

## New top-level field: `telemetry`

The `telemetry` field is an **optional** object at the root of the MXC JSON configuration. When absent or `null`, telemetry is **disabled** (opt-in semantics).

### Schema

```json
{
  "telemetry": {
    "enabled": false
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `telemetry.enabled` | `boolean` | `false` | Set to `true` to activate OTel span and metric emission. Has the same effect as setting `MXC_ENABLE_TELEMETRY=1` in the environment. |

### Validation rules

- The entire `telemetry` section is optional. When absent, behaviour is equivalent to `{ "enabled": false }`.
- Only `enabled` is a valid key. Unknown keys in the `telemetry` object are **ignored** (forward-compatible).
- A value of `null` for `telemetry` is treated as `{ "enabled": false }`.
- A non-boolean value for `enabled` (e.g. `0`, `"true"`) is treated as `false` (safe default).

### Precedence

| `MXC_ENABLE_TELEMETRY` env | `telemetry.enabled` in config | Result |
|---------------------------|------------------------------|--------|
| `1` | any | **enabled** |
| not set / other | `true` | **enabled** |
| not set / other | `false` / absent | **disabled** |

### Example — telemetry enabled via config

```json
{
  "script": "python -c \"print('hello')\"",
  "containment": "appcontainer",
  "appContainer": {
    "name": "my-sandbox"
  },
  "telemetry": {
    "enabled": true
  }
}
```

### Example — telemetry disabled (default; field absent)

```json
{
  "script": "python -c \"print('hello')\"",
  "containment": "appcontainer"
}
```

---

## TypeScript interface contract

**File**: `sdk/src/types.ts` (and mirrored in `cli/src/types.ts`)

```typescript
/**
 * Controls OpenTelemetry telemetry for this MXC invocation.
 * Telemetry is OFF by default (opt-in).
 */
export interface WxcTelemetryConfig {
  /**
   * Set to true to emit OTel traces and metrics.
   * Equivalent to setting MXC_ENABLE_TELEMETRY=1.
   * @default false
   */
  enabled?: boolean;
}
```

Added as an optional field on the root config interface:

```typescript
export interface SandboxConfig {
  // ... existing fields unchanged ...
  /**
   * Optional telemetry configuration.
   * When absent or `enabled: false`, no OTel data is emitted.
   */
  telemetry?: WxcTelemetryConfig;
}
```

---

## Environment variable contract

| Variable | Values | Effect |
|----------|--------|--------|
| `MXC_ENABLE_TELEMETRY` | `1` | Enable OTel telemetry for this invocation (overrides config) |
| `MXC_ENABLE_TELEMETRY` | anything else / unset | No effect; config `enabled` field governs |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | URL (e.g. `http://localhost:4318`) | OTLP HTTP export target. When absent, no remote export occurs. |
| `TRACEPARENT` | W3C traceparent string | Injected by the TypeScript SDK when calling `wxc-exec` as a subprocess, enabling distributed trace context propagation. |

---

## Backward compatibility

This is a **purely additive** schema change. All existing JSON configuration files remain valid. The `telemetry` field defaults to `{ "enabled": false }` when absent, so no behavioral change for existing users.
