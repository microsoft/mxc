# Tasks: Add Observability (OpenTelemetry)

**Input**: Design documents from `specs/001-add-observability/`
**Prerequisites**: plan.md ✅ spec.md ✅ research.md ✅ data-model.md ✅ contracts/ ✅

**Tests**: TDD required per constitution (Principle II). Unit tests are written first (Red),
then implementation (Green). All tests live in `#[cfg(test)]` modules in the same `.rs` file.

---

## Summary

| Phase | Stories | Tasks | Parallelizable |
|-------|---------|-------|---------------|
| 1 - Setup | — | T001–T003 | T002, T003 |
| 2 - Foundational | — | T004–T008 | T007, T008 |
| 3 - US1: Rust Core Observability (P1) 🎯 MVP | US1 | T009–T017 | T009, T013, T014 |
| 4 - US2: Telemetry Opt-In (P2) | US2 | T018–T021 | T018, T019 |
| 5 - US3: Adoption Metrics (P3) | US3 | T022–T027 | T022, T023, T026, T027 |
| 6 - US4: TypeScript SDK/CLI (P4) | US4 | T028–T033 | T028, T029, T030, T031 |
| 7 - Polish | — | T034–T040 | T037, T038, T040 |

**Total**: 40 tasks across 4 user stories  
**MVP scope**: Phases 1–4 (US1 + US2), delivering default-off Rust OTel spans before metrics or TypeScript instrumentation.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Add OTel dependencies to both Rust workspace and TypeScript packages so all subsequent phases can reference them.

- [ ] T001 Add OTel workspace-level crate deps to `src/Cargo.toml` — add `opentelemetry = "0.31"`, `opentelemetry_sdk = "0.31"` (features: `rt-tokio`), `opentelemetry-otlp = "0.31"` (features: `http-proto`, `reqwest-client`), `opentelemetry-semantic-conventions = "0.31"`, `tracing = "0.1"`, `tracing-opentelemetry = "0.32"`, `tracing-subscriber = "0.3"` (features: `env-filter`) under `[workspace.dependencies]`; **verify `http-proto` and `reqwest-client` feature names against `opentelemetry-otlp` 0.31 docs before committing** (feature names changed in this version range)
- [ ] T002 [P] Add `@opentelemetry/api ^1.9`, `@opentelemetry/sdk-trace-node ^1.29`, `@opentelemetry/sdk-metrics ^1.29`, `@opentelemetry/exporter-trace-otlp-http ^0.57`, `@opentelemetry/exporter-metrics-otlp-http ^0.57` as runtime `dependencies` in `sdk/package.json`
- [ ] T003 [P] Add same five `@opentelemetry/*` packages as runtime `dependencies` in `cli/package.json`

**Checkpoint**: `cargo build` and `npm install` succeed with new deps — no usage yet.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core data model changes and telemetry module skeleton. MUST be complete before any user story instrumentation begins.

⚠️ **CRITICAL**: No user story work begins until T004–T008 are all complete.

- [ ] T004 Add `TelemetryConfig` struct to `src/wxc_common/src/models.rs` — derive `Debug, Clone, Serialize, Deserialize`, add `#[serde(default)]`, one field `pub enabled: bool`, implement `Default` returning `Self { enabled: false }`; add Microsoft copyright header if not already present
- [ ] T005 Add `pub telemetry: TelemetryConfig` field (with `#[serde(default)]`) to the `CodexRequest` struct in `src/wxc_common/src/models.rs`
- [ ] T006 Add `RawTelemetry { enabled: Option<bool> }` struct with `#[serde(default, deny_unknown_fields = false)]` and `telemetry: Option<RawTelemetry>` field to `RawConfig` in `src/wxc_common/src/config_parser.rs`; map to `TelemetryConfig { enabled: raw.telemetry.and_then(|t| t.enabled).unwrap_or(false) }` in `load_request()`
- [ ] T007 [P] Create `src/wxc_common/src/telemetry.rs` with Microsoft copyright header; define `pub struct TelemetryHandles` holding provider fields as stubs; declare `pub fn is_enabled(_config_enabled: bool) -> bool { false }`, `pub fn init(_enabled: bool) -> Option<TelemetryHandles> { None }`, `pub fn shutdown(_handles: TelemetryHandles) {}` so the crate compiles
- [ ] T008 [P] Add `pub mod telemetry;` to `src/wxc_common/src/lib.rs`

**Checkpoint**: `cargo build` succeeds. `cargo test` passes (no new test failures). All four existing test configs still execute.

---

## Phase 3: User Story 1 — Rust Core Execution Observability (Priority: P1) 🎯 MVP

**Goal**: Every `wxc-exec` and `lxc-exec` execution emits a root `mxc.execute` span with five child spans covering the full execution lifecycle.

**Independent Test**: Run `wxc-exec examples/01_hello_world.json` with a local OTel collector and `MXC_ENABLE_TELEMETRY=1`. Verify root span `mxc.execute` appears with `mxc.backend`, `mxc.exit_code`, and duration; verify child spans exist for `mxc.container.init`, `mxc.policy.filesystem`, `mxc.policy.network`, `mxc.script.run`, `mxc.container.teardown`. Verify no test run without `MXC_ENABLE_TELEMETRY=1` emits any span.

### Tests for US1 (TDD Red phase — write first, confirm they FAIL before T011)

- [ ] T009 [P] [US1] Write `#[cfg(test)]` tests in `src/wxc_common/src/telemetry.rs` — assert `init(true).is_some()` (**this assertion fails on the stub** — it drives the T011 implementation) and `init(false).is_none()` (passes on stub); confirm `cargo test` fails on the `init(true)` assertion before T011 is implemented
- [ ] T010 [US1] Write `#[cfg(test)]` test in `src/wxc_common/src/telemetry.rs` — `shutdown()` completes within 2 500 ms wall-clock time when called with a real provider (use `opentelemetry-stdout` exporter in test); confirm `cargo test` fails

### Implementation for US1

- [ ] T011 [US1] Implement `telemetry::init(enabled: bool) -> Option<TelemetryHandles>` in `src/wxc_common/src/telemetry.rs` — when disabled return `None`; when enabled: build `OtlpSpanExporter` (HTTP/proto), wrap in `BatchSpanProcessor::builder()`, build `TracerProvider`, build `SdkMeterProvider` with `PeriodicReader`, install `tracing_subscriber::registry()` with `EnvFilter::from_default_env()` + `Layer::new()` (OTel layer) + `fmt::layer()` (console layer); set as global providers; return `Some(TelemetryHandles { tracer_provider, meter_provider })`
- [ ] T012 [US1] Implement `telemetry::shutdown(handles: TelemetryHandles)` in `src/wxc_common/src/telemetry.rs` — call `handles.tracer_provider.force_flush()` and `handles.meter_provider.force_flush()` inside a `tokio::time::timeout(Duration::from_secs(2), ...)` block; then call `shutdown()` on both; swallow errors (FR-008)
- [ ] T013 [P] [US1] Instrument `src/wxc/src/main.rs` — call `telemetry::is_enabled(request.telemetry.enabled)` after parsing; call `telemetry::init(enabled)`; open root `tracing::info_span!("mxc.execute", "mxc.backend" = %backend, "mxc.version" = env!("CARGO_PKG_VERSION"))` using `Span::enter()`; add `mxc.exit_code` attribute before span closes; set `SpanStatus::Error` with sanitized message on error paths; call `telemetry::shutdown(handles)` before `process::exit()`
- [ ] T014 [P] [US1] Instrument `src/lxc/src/main.rs` — mirror T013 exactly for the `lxc-exec` binary, using `"mxc.backend" = "lxc"` attribute
- [ ] T015 [US1] Add `mxc.container.init` and `mxc.container.teardown` child spans inside `src/wxc/src/` at the container lifecycle call sites — use `tracing::info_span!("mxc.container.init")` wrapping the init logic and `tracing::info_span!("mxc.container.teardown")` wrapping teardown; ensure spans are children of `mxc.execute` via tracing context propagation
- [ ] T016 [US1] Add `mxc.policy.filesystem` and `mxc.policy.network` child spans to the policy-application call sites in `src/wxc/src/` and/or `src/wxc_common/src/` — wrap each policy validation block in a `tracing::info_span!`; do NOT include policy values (no file paths, no IP addresses) in span attributes
- [ ] T017 [US1] Add `mxc.script.run` child span to the `ScriptRunner::run` / `run_script` call site in `src/wxc_common/src/script_runner.rs` — wrap the script execution in `tracing::info_span!("mxc.script.run")`; do NOT include `script_code`, arguments, or working directory in span attributes

**Checkpoint**: US1 independently testable. `cargo test --release` passes. `wxc-exec` with a local OTel collector and `MXC_ENABLE_TELEMETRY=1` shows all six spans.

---

## Phase 4: User Story 2 — Telemetry Opt-In (Priority: P2)

**Goal**: Telemetry is off by default. A single definitive `is_enabled()` function combines `MXC_ENABLE_TELEMETRY=1` (env var) OR `telemetry.enabled: true` (JSON config) semantics. Both Rust binaries respect the gate identically.

**Independent Test**: Run `wxc-exec` with no env vars → zero spans in collector. Set `MXC_ENABLE_TELEMETRY=1` → spans appear. Remove env var, add `"telemetry": { "enabled": true }` to config → spans appear. Confirm TypeScript CLI also activates when `MXC_ENABLE_TELEMETRY=1`.

### Tests for US2 (TDD Red phase)

- [ ] T018 [P] [US2] Write `#[cfg(test)]` unit tests for `is_enabled()` in `src/wxc_common/src/telemetry.rs` — four cases: (1) env unset + config false → `false`; (2) env `"1"` + config false → `true`; (3) env unset + config true → `true`; (4) env `"1"` + config true → `true`; use `std::env::set_var` / `remove_var` inside each test (confirm `cargo test` fails on current stub returning `false`)
- [ ] T019 [P] [US2] Write `#[cfg(test)]` unit tests for `TelemetryConfig` parsing in `src/wxc_common/src/config_parser.rs` — (1) JSON without `telemetry` key → `enabled: false`; (2) `"telemetry": { "enabled": true }` → `enabled: true`; (3) `"telemetry": null` → `enabled: false`; (4) `"telemetry": { "enabled": "oops" }` → deserialization falls back to `enabled: false` via `#[serde(default)]`

### Implementation for US2

- [ ] T020 [US2] Implement `telemetry::is_enabled(config_enabled: bool) -> bool` in `src/wxc_common/src/telemetry.rs` — replace stub: `std::env::var("MXC_ENABLE_TELEMETRY").as_deref() == Ok("1") || config_enabled`
- [ ] T021 [US2] Update `src/wxc/src/main.rs` and `src/lxc/src/main.rs` to call `telemetry::is_enabled(request.telemetry.enabled)` and pass the result to `telemetry::init()`; verify both binaries now correctly honour the opt-in gate

**Checkpoint**: US2 independently testable. Default-off confirmed: `wxc-exec` with a live OTel collector and NO env var → zero spans. Both env var and config mechanisms activate telemetry independently.

---

## Phase 5: User Story 3 — Product Adoption Metrics (Priority: P3)

**Goal**: Every execution increments `mxc.executions` and records duration in `mxc.execution.duration`. Failures additionally increment `mxc.failures`. All metric dimensions are bounded enums (no free-form strings → no PII).

**Independent Test**: Run `wxc-exec` five times across two backends with `MXC_ENABLE_TELEMETRY=1` and an OTel metrics collector. Query collector: `mxc.executions{mxc.backend="appcontainer"}` count = N; `mxc.execution.duration` histogram has N data points per backend; `mxc.failures` count matches intentional failures; dimensions are only `mxc.backend` and `mxc.outcome`/`mxc.failure_reason`.

### Tests for US3 (TDD Red phase)

- [ ] T022 [P] [US3] Write `#[cfg(test)]` tests in `src/wxc_common/src/telemetry.rs` — `init(true)` returns `Some(handles)` where `handles.meter` can create `mxc.executions`, `mxc.failures`, `mxc.execution.duration` instruments without panic; `init(false)` returns `None` and no meter is allocated (confirm `cargo test` fails)
- [ ] T023 [P] [US3] Write `#[cfg(test)]` tests for metric recording helpers — `record_execution(&handles, "appcontainer", "success")` does not panic and increments counter; `record_failure(&handles, "appcontainer", "process_error")` does not panic; `record_duration(&handles, "appcontainer", 42_u64)` does not panic (confirm `cargo test` fails)

### Implementation for US3

- [ ] T024 [US3] Extend `TelemetryHandles` in `src/wxc_common/src/telemetry.rs` — add `meter: opentelemetry::metrics::Meter` field; in `init(true)` create it from `SdkMeterProvider` via `provider.meter("mxc")`; create and store (or register) three instruments: `mxc.executions` (`u64` Counter, description + unit `{executions}`), `mxc.failures` (`u64` Counter), `mxc.execution.duration` (`f64` Histogram, unit `ms`)
- [ ] T025 [US3] Add three public helpers to `src/wxc_common/src/telemetry.rs`:
  - `pub fn record_execution(handles: &TelemetryHandles, backend: &str, outcome: &str)` — validates backend is one of `[appcontainer, sandbox, lxc, wslc]` and outcome is one of `[success, failure]` before recording; silently no-ops on unrecognized values
  - `pub fn record_failure(handles: &TelemetryHandles, backend: &str, reason: &str)` — validates reason is one of `[config_error, policy_error, process_error, timeout]`
  - `pub fn record_duration(handles: &TelemetryHandles, backend: &str, duration_ms: f64)`
- [ ] T026 [P] [US3] Call metric recording helpers at execution exit in `src/wxc/src/main.rs` — after `run()` completes, call `record_execution`, `record_duration`; on error path call `record_failure` with categorized reason
- [ ] T027 [P] [US3] Call metric recording helpers at execution exit in `src/lxc/src/main.rs` — mirror T026 for `lxc-exec`

**Checkpoint**: US3 independently testable. Metrics collector shows per-backend counters and histogram after multiple runs.

---

## Phase 6: User Story 4 — TypeScript SDK/CLI OTel Instrumentation (Priority: P4)

**Goal**: The TypeScript SDK and CLI emit parent spans wrapping `wxc-exec` subprocess calls. W3C `TRACEPARENT` env var connects TS parent spans to Rust child spans in a single distributed trace.

**Independent Test**: Write a short TypeScript script using the SDK `run()` method with `MXC_ENABLE_TELEMETRY=1` and a local OTel collector. Verify the TS-layer span `mxc.sdk.run` appears with `mxc.backend` and `mxc.outcome` attributes; verify `mxc.execute` Rust span has the same trace ID (linked via `TRACEPARENT`). Verify `mxc-cli run` emits its own parent span.

### Tests for US4 (TDD Red phase)

- [ ] T028 [P] [US4] Create `sdk/src/telemetry.test.ts` — write unit test: `initTelemetry(false)` returns `null`; `initTelemetry(true)` with `OTEL_EXPORTER_OTLP_ENDPOINT` set returns non-null SDK object (confirm `npm test` fails)
- [ ] T029 [P] [US4] Write unit test in `sdk/src/telemetry.test.ts` — `getTraceParent()` when no active span returns `undefined`; with a fake span context returns a string matching `/^00-[0-9a-f]{32}-[0-9a-f]{16}-0[01]$/` (W3C `traceparent` format)

### Implementation for US4

- [ ] T030 [P] [US4] Add `WxcTelemetryConfig { enabled?: boolean }` interface and `telemetry?: WxcTelemetryConfig` optional field to the root config interface in `sdk/src/types.ts`; mirror the same interface in `cli/src/types.ts` (or shared types module if one exists)
- [ ] T031 [P] [US4] Create `sdk/src/telemetry.ts` with Microsoft copyright header — implement `initTelemetry(enabled: boolean): TelemetrySdk | null` (returns `null` when disabled; builds `NodeTracerProvider` with `BatchSpanProcessor` + `OTLPTraceExporter`, `MeterProvider` with `PeriodicExportingMetricReader` + `OTLPMetricExporter` when enabled); `shutdownTelemetry(sdk: TelemetrySdk): Promise<void>` (calls `sdk.tracerProvider.shutdown()`); `getTraceParent(): string | undefined` (serializes active span context as W3C `traceparent` via `propagation.inject()` into a plain-object carrier and returns `carrier.traceparent`)
- [ ] T032 [US4] Update `sdk/src/index.ts` — export `initTelemetry`, `shutdownTelemetry` from `sdk/src/telemetry.ts`; when spawning `wxc-exec` child process, call `getTraceParent()` and add `TRACEPARENT` to `spawnOptions.env` if a value is returned; create parent span `mxc.sdk.run` with attributes `mxc.backend` (from config), `mxc.outcome` (from result exit code) wrapping the subprocess spawn; close span after child exits
- [ ] T033 [US4] Update `cli/src/cli.ts` — call `initTelemetry(process.env.MXC_ENABLE_TELEMETRY === "1")` at CLI startup; wrap each command handler in a `mxc.cli.command` span with `cli.command` attribute; inject `TRACEPARENT` into subprocess env (same as T032 pattern); call `shutdownTelemetry()` in `process.on("exit")` handler

**Checkpoint**: US4 independently testable. OTel collector receives both `mxc.sdk.run` (TS) and `mxc.execute` (Rust) spans with matching trace IDs.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [ ] T034 Update `docs/schema.md` — add documentation for the new top-level `telemetry` field, with the full schema table from `contracts/json-config-telemetry.md` (field, type, default, description), the precedence table (`MXC_ENABLE_TELEMETRY` vs `enabled: true`), and two JSON examples (enabled via config; default absent)
- [ ] T035 Add `## Telemetry` section to `Readme.md` — describe: (a) telemetry is off by default; (b) how to enable via `MXC_ENABLE_TELEMETRY=1` or `"telemetry": {"enabled": true}`; (c) list all collected span attributes (`mxc.backend`, `mxc.exit_code`, `mxc.version`) and metrics (`mxc.executions`, `mxc.failures`, `mxc.execution.duration`) with their dimensions; (d) explicit statement that no PII is collected (FR-015)
- [ ] T036 Verify `specs/001-add-observability/spec.md` contains no remaining `MXC_NO_TELEMETRY`, `telemetry.disabled`, or `sdk-node` references — all opt-in/opt-out terminology inconsistencies were corrected directly in spec.md during the `/speckit.analyze` review phase; grep the file and confirm zero matches
- [ ] T037 [P] Run `cargo fmt --all` and `cargo clippy --all-targets -D warnings` across the workspace; fix any warnings introduced by OTel crate additions in `src/wxc_common/`, `src/wxc/`, `src/lxc/`
- [ ] T038 [P] Run `cargo test --release` and confirm all new `#[cfg(test)]` tests pass; run `npm test` in `sdk/` and `cli/` and confirm TypeScript tests pass
- [ ] T039 [FR-014] Verify Logger/ETW regression: run all existing test configs (`test_configs/basic_appcontainer.json`, `basic_permissive.json`, `basic_sandbox.json`, `basic_lxc.json`) with `MXC_ENABLE_TELEMETRY` unset after T011 lands; assert existing stdout/stderr output and `Logger` console/buffer output are identical to pre-telemetry baseline — confirms the `tracing_subscriber` global subscriber installation does not silently suppress existing Logger output
- [ ] T040 [P] [SC-007] Performance benchmark: invoke `wxc-exec` 100× with `MXC_ENABLE_TELEMETRY=1` (and `OTEL_EXPORTER_OTLP_ENDPOINT` unset so export is no-op) and 100× without; assert p95 wall-clock delta ≤ 5 ms; document result in PR description

---

## Dependencies

```
Phase 1 (Setup) ──────────────────────────────────────────────────────────────────┐
                                                                                   │
Phase 2 (Foundation) ◄──────────────────────────────────────────────────────────┐  │
                                                                                 │  │
Phase 3 (US1 — Spans) ◄──────────────────────────────────────────────────────┐  │  │
                                                                              │  │  │
Phase 4 (US2 — Opt-In) ◄─────────────────────────────────────────────────┐  │  │  │
                         │                                                │  │  │  │
                         ├──► Phase 5 (US3 — Metrics)                    │  │  │  │
                         │                                                │  │  │  │
                         └──► Phase 6 (US4 — TypeScript)                 │  │  │  │
                              [can run parallel with Phase 5]             │  │  │  │
                                                                          │  │  │  │
Phase 7 (Polish) ◄────────────────────────────────────────────────────────┘──┘──┘──┘
```

**US completion order**: US1 (P1) → US2 (P2) → US3 (P3) ‖ US4 (P4)

---

## Parallel Execution Examples

### After T008 (Foundation complete)

| LLM Instance A | LLM Instance B | LLM Instance C |
|----------------|----------------|----------------|
| T009 (US1 test — init) | T010 (US1 test — shutdown) | — |
| T013 (wxc main.rs) | T014 (lxc main.rs) | — |
| T018 (US2 test — is_enabled) | T019 (US2 test — serde) | — |
| T022 (US3 test — instruments) | T023 (US3 test — helpers) | — |
| T026 (wxc metrics) | T027 (lxc metrics) | — |
| T028 (TS init test) | T029 (TS traceparent test) | T030 (types.ts) |
| T031 (sdk/telemetry.ts) | T037 (lint) | T038 (test run) |

---

## Implementation Strategy

1. **MVP first** (Phases 1–4): Delivers default-off Rust OTel spans visible in any OTLP collector. No metrics, no TypeScript changes. Gives immediate value for debugging.
2. **Add metrics** (Phase 5): US3 adds counters and histograms. No external APIs change — purely additive.
3. **TypeScript layer** (Phase 6): US4 wires the TS SDK/CLI. Can be done in parallel with Phase 5 by a different engineer or branch.
4. **Polish** (Phase 7): Spec fix, docs, lint, full test run — always last.

> **Note**: Every phase leaves the codebase in a releasable state. The only "breaking" change is in `CodexRequest` serialization (T005) — but since `#[serde(default)]` is used and the `telemetry` field defaults to disabled, all existing JSON configs remain valid.
