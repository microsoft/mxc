# Research: Observability — OpenTelemetry Instrumentation & Adoption Metrics

**Date**: 2026-03-25  
**Feature**: [spec.md](spec.md)  
**Status**: Complete — all unknowns resolved

---

## R1: Rust OTel Crate Selection

**Decision**: Use the following workspace-level Rust dependencies:

| Crate | Version | Purpose |
|-------|---------|---------|
| `opentelemetry` | `0.31` | Core API traits (Tracer, Meter, Context) |
| `opentelemetry_sdk` | `0.31` | BatchSpanProcessor, PeriodicReader, TracerProvider, SdkMeterProvider |
| `opentelemetry-otlp` | `0.31` | OTLP gRPC/HTTP exporter (behind `http-proto` or `grpc-tonic` feature) |
| `opentelemetry-semantic-conventions` | `0.31` | Standard attribute key constants |
| `tracing` | `0.1` | Structured span/event macros (`#[instrument]`, `tracing::info_span!`) |
| `tracing-opentelemetry` | `0.32` | Bridge: routes `tracing` spans into the OTel pipeline |
| `tracing-subscriber` | `0.3` | Compose `EnvFilter` + `fmt` + `OpenTelemetryLayer` into a single subscriber |

> **Version alignment note**: `tracing-opentelemetry` is intentionally one major version ahead of the
> `opentelemetry` crates (e.g. tracing-opentelemetry 0.32 is compatible with opentelemetry 0.31).
> This is a documented property of the crate — see [issue #170](https://github.com/tokio-rs/tracing-opentelemetry/issues/170).
> All four `opentelemetry*` crates move in lockstep (same minor version required).
> **Verified against crates.io 2026-03-25**: latest = opentelemetry 0.31.0, opentelemetry-otlp 0.31.1,
> tracing-opentelemetry 0.32.1.

**Rationale**: `tracing` + `tracing-opentelemetry` is the MXC Constitution's prescribed pattern (Principle IV). It gives structured spans via familiar macros while routing into the OTel pipeline for export. Using `opentelemetry_sdk` (not just the API) in `wxc_common` lets us own provider init/shutdown. The OTLP exporter handles the standard `OTEL_EXPORTER_OTLP_ENDPOINT` env var automatically — no custom export code required.

**Alternatives considered**:
- `opentelemetry-stdout` for testing — used only in tests, not production code.
- `opentelemetry-zipkin` / `opentelemetry-jaeger` — rejected; OTLP is the modern standard and supports both traces and metrics with a single exporter.
- Adding a new `wxc_telemetry` crate — rejected; the telemetry init/shutdown module is small enough to live as `telemetry.rs` in `wxc_common`, following the existing one-concern-per-file module pattern.

**Feature flags** for `opentelemetry-otlp 0.31`:
- HTTP export: `features = ["http-proto", "reqwest-client"]` — avoids Tonic/gRPC chain on Windows.
- gRPC is an option if the operator has a Tonic-compatible endpoint; not the default.
- ⚠️ Feature flag names changed between 0.28 and 0.31 in this crate. During T001, run
  `cargo add opentelemetry-otlp@0.31 --features http-proto,reqwest-client` and review the
  Cargo.lock/docs to confirm feature names are still correct before committing.

---

## R2: Rust Telemetry Module Architecture

**Decision**: Single new file `src/wxc_common/src/telemetry.rs` with three public functions:

```
pub fn is_enabled() -> bool
pub fn init() -> Option<TelemetryHandles>
pub fn shutdown(handles: TelemetryHandles)
```

`TelemetryHandles` owns the `TracerProvider` and `SdkMeterProvider` so both can be shut down in a single call. `init()` returns `None` when telemetry is disabled (no `MXC_ENABLE_TELEMETRY=1` and config `enabled != true`), making the opt-in gate a compile-time zero-cost path when disabled.

Both `wxc/src/main.rs` and `lxc/src/main.rs` call `telemetry::init(enabled_from_config)` early in `main()`, hold the returned `Option<TelemetryHandles>`, run their execution logic instrumented with `tracing` spans, then call `telemetry::shutdown(handles)` before `process::exit`.

**Rationale**: Both binaries share one implementation. No duplication. Follows the existing `wxc_common` shared-library pattern.

---

## R3: W3C Trace Context Propagation (TypeScript → Rust subprocess)

**Decision**: When the TypeScript SDK/CLI spawns `wxc-exec` or `lxc-exec` as a child process, it serializes the active span's W3C `traceparent` header value and passes it as the `TRACEPARENT` environment variable to the child process.

The Rust binary reads `std::env::var("TRACEPARENT")` at startup and manually constructs an `opentelemetry::Context` with the extracted `SpanContext`. This context is then set as the parent for the root `mxc.execute` span.

**Propagation format**: W3C Trace Context (`traceparent: 00-<trace-id>-<parent-id>-<flags>`). No `tracestate` required for MVP.

**Rationale**: `wxc-exec` is a subprocess, not an HTTP server. There is no HTTP transport for the standard `TextMapPropagator`. Passing via env var is the established pattern for CLI subprocess context propagation. The TypeScript OTel SDK provides `propagation.inject()` that writes into a carrier object; the carrier is then spread into `spawnOptions.env`.

**Alternatives considered**:
- Passing traceparent via a custom CLI flag — rejected; pollutes the public CLI surface area.
- Using a named pipe for context — rejected; over-engineered, not standard.

---

## R4: TypeScript OTel Package Selection

**Decision**: Use the following npm packages (added as `dependencies` in sdk and cli `package.json`):

| Package | Version | Purpose |
|---------|---------|---------|
| `@opentelemetry/api` | `^1.9` | Core API (Tracer, Meter, propagation, context) |
| `@opentelemetry/sdk-trace-node` | `^1.29` | Node.js trace SDK, BatchSpanProcessor |
| `@opentelemetry/sdk-metrics` | `^1.29` | MeterProvider, PeriodicExportingMetricReader |
| `@opentelemetry/exporter-trace-otlp-http` | `^0.57` | OTLP HTTP trace export |
| `@opentelemetry/exporter-metrics-otlp-http` | `^0.57` | OTLP HTTP metrics export |

**Rationale**: Using `@opentelemetry/sdk-trace-node` (lighter) rather than the full `@opentelemetry/sdk-node` (which auto-instruments everything including `http`, `fs`, etc.). MXC is intentionally narrow — auto-instrumentation of Node.js internals would produce noisy, potentially PII-bearing spans on file paths accessed by the SDK. Manual instrumentation is preferred.

**Alternatives considered**:
- `@opentelemetry/sdk-node` — rejected for the CLI/SDK because auto-instrumentation creates PII risk (records fs paths, env vars). A focused manual setup is safer.
- Console exporter in production — only for testing; not shipped.

---

## R5: BatchSpanProcessor & PeriodicReader Configuration

**Decision**: Use the following SDK defaults (no custom configuration in code; rely on standard OTel env vars for operator tuning):

| Setting | Default Value | OTel Env Var Override |
|---------|--------------|----------------------|
| Batch export interval | 5 000 ms | `OTEL_BSP_SCHEDULE_DELAY` |
| Max batch size | 512 | `OTEL_BSP_MAX_EXPORT_BATCH_SIZE` |
| Export timeout | 30 000 ms | `OTEL_BSP_EXPORT_TIMEOUT` |
| Metric export interval | 60 000 ms | `OTEL_METRIC_EXPORT_INTERVAL` |
| Force-flush timeout | 2 000 ms | Hard-coded in shutdown path (not overridable) |

**Rationale**: Default values are appropriate for a CLI tool. Operators who collect telemetry centrally can tune via standard env vars without touching code. The 2-second force-flush cap (FR-017) is unconditional to guarantee the process always exits in reasonable time.

---

## R6: Span and Metric Schema

### Span Names and Attributes

| Span Name | Parent | Description |
|-----------|--------|-------------|
| `mxc.execute` | (root or injected TS parent) | Full invocation lifetime |
| `mxc.container.init` | `mxc.execute` | Container profile / process setup |
| `mxc.policy.filesystem` | `mxc.execute` | BFS / filesystem policy application |
| `mxc.policy.network` | `mxc.execute` | Firewall / network policy application |
| `mxc.script.run` | `mxc.execute` | Child process spawned; waiting for exit |
| `mxc.container.teardown` | `mxc.execute` | Cleanup (profile deletion, rule removal) |

**Permitted span attributes** (exhaustive — nothing outside this list):

| Attribute Key | Type | Example | On which spans |
|---------------|------|---------|----------------|
| `mxc.backend` | string | `appcontainer` | root + all children |
| `mxc.exit_code` | int | `0` | `mxc.execute`, `mxc.script.run` |
| `mxc.version` | string | `0.1.5` | `mxc.execute` only |
| `mxc.containment.name` | string | `mxc-abc123` (auto-generated UUID prefix) | `mxc.container.init` |
| `error.type` | string | `policy_error` | Error spans only |

**Explicitly PROHIBITED attributes** (PII guard):
- Any file path, script content, working directory, environment variable value, username, machine name, IP address, port number.

### Metric Names and Dimensions

| Metric Name | Kind | Unit | Dimensions |
|-------------|------|------|-----------|
| `mxc.executions` | Counter | `{execution}` | `mxc.backend`, `mxc.outcome` (`success`\|`failure`) |
| `mxc.failures` | Counter | `{execution}` | `mxc.backend`, `mxc.failure_reason` (bounded enum) |
| `mxc.execution.duration` | Histogram | `ms` | `mxc.backend` |

**`mxc.failure_reason` bounded enum values**:  
`config_error` · `policy_error` · `process_error` · `timeout` · `unknown`

---

## R7: JSON Configuration Schema Extension

**Decision**: Add an optional `telemetry` top-level object to the existing JSON config schema.

```json
{
  "telemetry": {
    "enabled": true
  }
}
```

`enabled` defaults to `false` (opt-in). Malformed `telemetry` section → treated as `{ "enabled": false }` (safe default per spec).

The field maps to a new `TelemetryConfig` struct with a single `enabled: bool` field, following the existing pattern of `SandboxConfig`, `LxcConfig`, etc.

---

## R8: No-Op Path (Telemetry Disabled)

**Decision**: When telemetry is disabled (default), the `telemetry::init()` function installs a `NoopTracerProvider` and no `MeterProvider`. The `tracing-subscriber` is still initialized (for console output) but the `OpenTelemetryLayer` is not added. This means:

- Zero network connections attempted.
- Zero allocations for span/metric data structures.
- `cargo test` passes without any OTel collector present.

**Rationale**: The no-op path must have provably zero overhead so that the ≤5 ms overhead guarantee is testable by comparison: `enabled=false` run is the baseline.

---

## Summary of New Dependencies

### Cargo workspace additions (`src/Cargo.toml`)

```toml
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tracing-opentelemetry = "0.29"
opentelemetry = "0.28"
opentelemetry_sdk = { version = "0.28", features = ["rt-tokio", "trace", "metrics"] }
opentelemetry-otlp = { version = "0.28", features = ["http-proto", "reqwest-client", "metrics"] }
opentelemetry-semantic-conventions = "0.28"
```

These go in `[workspace.dependencies]`; each crate that uses them declares `dep.workspace = true`.

### npm package additions

**sdk/package.json** and **cli/package.json** (dependencies):
```json
"@opentelemetry/api": "^1.9.0",
"@opentelemetry/sdk-trace-node": "^1.29.0",
"@opentelemetry/sdk-metrics": "^1.29.0",
"@opentelemetry/exporter-trace-otlp-http": "^0.57.0",
"@opentelemetry/exporter-metrics-otlp-http": "^0.57.0"
```
