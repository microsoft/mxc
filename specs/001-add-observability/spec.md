# Feature Specification: Observability — OpenTelemetry Instrumentation & Adoption Metrics

**Feature Branch**: `001-add-observability`  
**Created**: 2026-03-25  
**Status**: Draft  


## User Scenarios & Testing *(mandatory)*

### User Story 1 — Rust Core Execution Observability (Priority: P1)

An operator or developer runs `wxc-exec` to execute a sandboxed script. They want to
understand what happened during execution — which container backend was used, how long
initialization and execution took, and whether any errors or policy violations occurred —
without having to read raw process output or ETW traces.

After this story is implemented, every Rust execution path emits OTel spans and events that
can be captured by any OTel-compatible collector attached to the process.

**Why this priority**: This is the foundational observability layer. Without Rust-level OTel
spans, there is nothing to build adoption metrics on top of, and the TypeScript layer has no
semantic context to propagate. It also makes immediately actionable the requirement to add
telemetry "where no telemetry is present."

**Independent Test**: Run `wxc-exec` with a valid JSON configuration against any backend
(AppContainer, Sandbox, or LXC). Attach an OTel collector configured to export to console or
a local OTLP receiver. Verify that a root span encompassing the full execution appears, that
child spans exist for container initialization and script execution, and that span attributes
include backend type, exit code, and duration — with no PII fields present.

**Acceptance Scenarios**:

1. **Given** a valid JSON configuration and an OTel collector attached,
   **When** `wxc-exec` runs a script to completion,
   **Then** a structured trace containing a root span with child spans for container init,
   policy application, and script execution is emitted to the collector.

2. **Given** `wxc-exec` is configured with the AppContainer backend,
   **When** execution completes successfully,
   **Then** the emitted root span includes attributes: `mxc.backend=appcontainer`,
   `mxc.exit_code=0`, and duration; and does NOT include script content, file paths,
   usernames, or machine names.

3. **Given** `wxc-exec` encounters an error (e.g., policy validation failure),
   **When** the error is raised,
   **Then** an error event is recorded on the active span with an error message, and the
   span status is set to ERROR — without recording the full script content.

4. **Given** telemetry has not been explicitly enabled (see US2),
   **When** `wxc-exec` runs,
   **Then** no spans or events are emitted and no external connections are attempted.

---

### User Story 2 — Telemetry Opt-In (Priority: P2)

A developer or team that wants to observe MXC executions can explicitly enable telemetry.
By default telemetry is off, so no data is emitted unless the user takes a deliberate action
to turn it on. Once enabled, they can also turn it back off at any time.

**Why this priority**: Telemetry is off by default — this is the safest posture for a
security-focused sandboxing tool deployed in sensitive and air-gapped environments. Users
must actively opt in to emit data, which makes the opt-in path equally important as the
core instrumentation: without a clear, working enable mechanism, the feature has no value.
This story must ship before or alongside any story that emits data.

**Independent Test**: Without any telemetry env var set, run `wxc-exec` and confirm
zero spans/metrics reach a local OTel collector (default-off). Then set `MXC_ENABLE_TELEMETRY=1`
and rerun — confirm spans and metrics appear. Independently confirm that
`"telemetry": { "enabled": true }` in the JSON config also activates telemetry.
Repeat both steps for the TypeScript CLI.

**Acceptance Scenarios**:

1. **Given** the environment variable `MXC_ENABLE_TELEMETRY=1` is set,
   **When** `wxc-exec` is invoked,
   **Then** OTel spans and metrics are emitted and exported to any configured OTLP endpoint.

2. **Given** a JSON configuration file includes `"telemetry": { "enabled": true }`,
   **When** `wxc-exec` is invoked with that configuration,
   **Then** telemetry is activated for that invocation regardless of the environment variable.

3. **Given** neither `MXC_ENABLE_TELEMETRY=1` nor `"enabled": true` in config is present,
   **When** `wxc-exec` runs,
   **Then** no OTel spans, metrics, or events are emitted and no network connections
   are made by the telemetry subsystem (default-off behavior).

4. **Given** the opt-in environment variable is set,
   **When** the TypeScript CLI (`mxc-cli`) is invoked,
   **Then** the CLI passes the opt-in signal to `wxc-exec` and activates its own OTel
   instrumentation.

---

### User Story 3 — Product Adoption Metrics (Priority: P3)

The MXC product team wants to understand how the tool is being adopted in the wild:
which execution backends are in use, how often the tool is invoked, and what the overall
success and failure rate is. This data enables prioritization of backend investment and
validates distribution and adoption growth.

Adoption metrics are emitted as OTel metrics (counters and histograms) alongside the
existing trace spans.

**Why this priority**: Adoption metrics require the foundational OTel infrastructure from US1
and the opt-out mechanism from US2. They also represent new data types (metrics vs traces) and
are designed for user-driven collection: telemetry is emitted to OTLP only when
`OTEL_EXPORTER_OTLP_ENDPOINT` is configured by the user.

**Independent Test**: Run `wxc-exec` multiple times with different backends (AppContainer, LXC)
and confirm that execution count counters, backend-type breakdowns, and latency histograms are
emitted as OTel metrics and are independently queryable from trace spans.

**Acceptance Scenarios**:

1. **Given** an OTel metrics collector is attached,
   **When** `wxc-exec` completes an execution,
   **Then** the following metrics are incremented/recorded: execution count (by backend),
   success/failure count (by backend), and execution latency (histogram, by backend).

2. **Given** multiple executions occur across different backends,
   **When** a team member queries the metrics endpoint,
   **Then** per-backend breakdowns are available without any PII-bearing dimensions.

3. **Given** the opt-out mechanism is active,
   **When** `wxc-exec` runs,
   **Then** no metrics are emitted (consistent with US2 opt-out behavior).

4. **Given** the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable is set to a valid OTLP
   endpoint,
   **When** `wxc-exec` runs,
   **Then** metrics and spans are exported to that endpoint on the configured interval;
   if the env var is absent, no remote export occurs.

---

### User Story 4 — TypeScript SDK/CLI OTel Instrumentation (Priority: P4)

A developer using the TypeScript SDK (`@microsoft/mxc-sdk`) or the `mxc-cli` to automate
script execution wants the same OTel observability available from the TypeScript layer: spans
for each SDK invocation and method call, correlated with the underlying Rust execution spans.

**Why this priority**: The TypeScript layer is the primary integration surface for Node.js and
Electron callers. Without TS-layer instrumentation, spans from the TS layer are silently dropped
from any distributed trace. This is lower priority than the Rust core because the Rust binary
always runs regardless of which TS API is used.

**Independent Test**: Write a TypeScript program using the SDK's `run()` method with an OTel
SDK configured to export to console. Verify that a TS-layer span wraps the `wxc-exec` child
process invocation, that span context (trace ID) is propagated as an environment variable or
header to `wxc-exec`, and that the resulting trace connects the TS and Rust spans. Verify opt-out
also silences the TS-layer spans.

**Acceptance Scenarios**:

1. **Given** the OTel SDK is initialized in the TypeScript process,
   **When** `WxcExecutor.run()` is called,
   **Then** a TS-layer span is created wrapping the subprocess call, and spans emitted
   by `wxc-exec` are linked as children or connected via trace context propagation.

2. **Given** only the TypeScript CLI is used (no custom SDK code),
   **When** `mxc-cli run` is invoked,
   **Then** a CLI-level span is emitted for the invocation, including command name,
   backend type from the config, and outcome — without script content or user identity.

3. **Given** `MXC_ENABLE_TELEMETRY` is not set,
   **When** any TypeScript SDK or CLI method is called,
   **Then** no TS-layer spans or metrics are emitted.

---

### Edge Cases

- What happens when the OTel exporter is configured but the collector is unreachable?
  Telemetry failures MUST NOT surface as user-visible errors or cause execution failures;
  telemetry is best-effort and fire-and-forget.
- What happens when `wxc-exec` exits abnormally (crash, killed by OS)?
  The root span should be closed with an error status if possible; otherwise the trace
  may be incomplete and this is acceptable.
- What happens when the `telemetry` JSON configuration section is present but malformed?
  Malformed telemetry config MUST be treated as if telemetry is disabled (safe default)
  and a warning emitted to stderr.
- What happens when `MXC_ENABLE_TELEMETRY` is set to a non-`"1"` value (e.g., "true", "yes")?
  Only the value `"1"` enables telemetry via `MXC_ENABLE_TELEMETRY`; other values are treated as absent.
  (This is a deliberate strict parsing rule to prevent accidental activation.)
- Can PII be accidentally emitted through error messages or span descriptions?
  All error messages captured in spans MUST be sanitized: file paths, script content,
  and environment variable values MUST NOT appear in span attributes or events.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The Rust execution layer MUST emit OTel trace spans for each of the following
  operations: container initialization, policy application (filesystem and network), script
  execution, and container teardown.
- **FR-002**: Each emitted OTel span MUST include structured attributes: `mxc.backend`
  (enum: appcontainer, sandbox, lxc, wslc), `mxc.exit_code` (integer), and span duration.
- **FR-003**: Emitted spans and metrics MUST NOT include: script source code, command-line
  argument values, file paths, environment variable values, usernames, machine hostnames,
  or IP addresses.
- **FR-004**: The Rust execution layer MUST emit OTel metrics: an execution count counter
  (dimensions: backend, outcome), a failure count counter (dimensions: backend, failure reason
  category), and an execution latency histogram (dimensions: backend).
- **FR-005**: Setting the environment variable `MXC_ENABLE_TELEMETRY=1` MUST activate all OTel
  span and metric emission for that process invocation.
- **FR-006**: Setting `"telemetry": { "enabled": true }` in the JSON configuration MUST
  activate all OTel span and metric emission for that invocation.
- **FR-007**: When neither opt-in mechanism is active, telemetry MUST be suppressed by default
  (no spans, metrics, or events emitted; no network connections attempted).
- **FR-008**: Telemetry failures (exporter unreachable, initialization error) MUST NOT propagate
  as user-visible errors, affect execution output, or alter the exit code of `wxc-exec`.
- **FR-009**: The TypeScript SDK MUST emit OTel spans wrapping `WxcExecutor.run()` calls,
  including attributes: command name, backend type (parsed from config), and outcome.
- **FR-010**: The TypeScript CLI MUST emit OTel spans per `mxc-cli` command invocation.
- **FR-011**: The TypeScript layer MUST respect `MXC_ENABLE_TELEMETRY=1` and activate its own
  OTel spans and metrics only when it is set; it MUST suppress all OTel output by default.
- **FR-012**: When the standard `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable is set,
  the OTel SDK MUST export spans and metrics to that endpoint. When it is absent, the exporter
  MUST default to no-op (no remote connections). No proprietary or Microsoft-operated endpoint
  is configured by MXC itself.
- **FR-013**: All OTel instrumentation MUST use the standard OpenTelemetry SDK for the
  respective language (Rust OTel crates; `@opentelemetry` npm packages for TypeScript);
  no proprietary telemetry SDKs.
- **FR-014**: Existing `Logger` and ETW instrumentation MUST remain fully functional;
  OTel instrumentation is additive and MUST NOT replace or break existing debug output.
- **FR-015**: The project README MUST include a dedicated `Telemetry` section that describes:
  (a) that telemetry is off by default, (b) how to enable it (`MXC_ENABLE_TELEMETRY=1` or
  JSON config), (c) the exact set of attributes/metrics collected, and (d) the explicit
  guarantee that no PII is collected. No runtime notice or consent prompt is required.
- **FR-016**: All OTel span and metric export MUST use an async, non-blocking exporter
  (e.g., `BatchSpanProcessor` / `PeriodicReader`). Synchronous or blocking exporters are
  prohibited. The total overhead added to `wxc-exec` wall-clock execution time by the
  telemetry subsystem MUST NOT exceed 5 ms.
- **FR-017**: The Rust binary MUST call `force_flush()` followed by `shutdown()` on the
  OTel `TracerProvider` and `MeterProvider` before process exit. The maximum time to wait
  for the flush to complete is 2 seconds; if the flush does not complete within that window
  the process MUST exit regardless. The TypeScript SDK/CLI MUST do the equivalent
  (`provider.shutdown()`) before the Node.js process exits.

### Key Entities

- **Telemetry Configuration**: An optional section in the MXC JSON config schema that controls
  telemetry behavior for an invocation. Key fields: `enabled` (boolean, default: false).
  Exporter destination is not configured in the JSON schema; it is controlled by the standard
  `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable.
- **Opt-In Signal**: The state derived by combining the `MXC_ENABLE_TELEMETRY` environment variable
  and the JSON config `telemetry.enabled` flag. If either is active, telemetry is enabled.
- **Execution Span**: A trace span covering the full lifetime of a single `wxc-exec` run,
  with child spans per phase (init, policy, execute, teardown).
- **Adoption Metric**: An OTel counter or histogram that records usage without any
  user-identifying dimensions. Dimensions are limited to: backend type, outcome
  (success/failure), and failure reason category (no finer granularity).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Every successful and failed execution of the Rust binary produces at least one
  OTel trace span containing backend type, exit code, and duration — verifiable by attaching
  a local OTel collector to any invocation.
- **SC-002**: With no opt-in signal present, zero OTel spans or metrics are emitted in both
  the Rust and TypeScript layers — verifiable with zero events reaching a local collector.
  Setting `MXC_ENABLE_TELEMETRY=1` activates telemetry — verifiable with spans appearing.
- **SC-003**: No OTel event, span attribute, or metric dimension contains any of the following:
  script source code, file paths, environment variable values, usernames, or machine names —
  verifiable by static code review and integration test assertions against emitted telemetry.
- **SC-004**: Execution count and latency metrics are emitted per-backend so the team can
  distinguish AppContainer, Sandbox, LXC, and WSLC adoption trends independently.
- **SC-005**: When the OTel exporter is unreachable, `wxc-exec` exit code and stdout/stderr
  output are identical to a run with telemetry disabled — verifiable by comparing outputs.
- **SC-006**: The TypeScript SDK emits TS-layer spans that are linked to the Rust-layer spans
  via OTel trace context propagation — verifiable by checking trace IDs match in an OTel
  collector receiving spans from both layers.
- **SC-007**: When telemetry is enabled, the total added wall-clock overhead to a `wxc-exec`
  run MUST NOT exceed 5 ms — verifiable by timing 100 identical runs with and without
  `MXC_ENABLE_TELEMETRY=1` and comparing p95 latency.
- **SC-008**: On a run where `wxc-exec` completes in under 500 ms, all emitted spans and
  metrics still appear in the OTel collector — verifiable by confirming the collector
  received the data for short-lived executions.

## Scope

### In Scope

- OTel trace spans for all four Rust execution backends (AppContainer, Sandbox, LXC, WSLC).
- OTel metrics (counters and histograms) for execution volume, outcome, and latency per backend.
- Opt-in via `MXC_ENABLE_TELEMETRY=1` env var and `"telemetry": { "enabled": true }` config field.
- TypeScript SDK and CLI OTel span instrumentation and opt-in propagation.
- JSON configuration schema extension for the `telemetry` section.
- Privacy audit: static enforcement that no PII fields are captured in any span or metric.

### Out of Scope

- Replacing or removing existing `Logger` / ETW instrumentation.
- Building a custom telemetry dashboard or data pipeline.
- OTel log signal (only traces and metrics in this feature; logs are covered by existing ETW/Logger).
- Runtime consent prompts or first-run telemetry notices (disclosure is README-only).
- Changing existing exit codes, stdout format, or any user-visible behavior of `wxc-exec`.
- Telemetry for the build system or CI pipeline.

## Assumptions

- Telemetry is disabled by default (opt-in, not opt-out); users who want telemetry
  set `MXC_ENABLE_TELEMETRY=1` or add `"telemetry": { "enabled": true }` to their config.
- The `tracing` crate + `tracing-opentelemetry` bridge is the preferred Rust OTel integration
  pattern (as specified in the MXC Constitution, Principle IV).
- The TypeScript `@opentelemetry/sdk-trace-node` and `@opentelemetry/api` packages are used for the
  TypeScript layer (not `sdk-node`, which auto-instruments Node.js internals creating PII risk — see research.md R4).
- Trace context propagation from the TypeScript layer to `wxc-exec` is done via an environment
  variable (W3C TraceContext format), since `wxc-exec` is invoked as a child process.
- The failure reason category dimension on metrics is a bounded enum (e.g., config_error,
  policy_error, process_error, timeout) — not a free-form string — to prevent accidental PII.
- Malformed telemetry configuration is treated as `enabled: false` (safe default) rather than failing the run.
- The existing Cargo workspace structure is extended, not restructured, to add OTel dependencies.

## Clarifications

### Session 2026-03-25

- Q: Where should OTel data be sent by default — who controls the telemetry destination? → A: No default remote exporter; telemetry exports only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set by the user (Option C — standard OTel convention, lowest privacy risk).
- Q: Should telemetry be on by default (opt-out) or off by default (opt-in)? → A: Off by default — opt-in (Option B). Users must explicitly set `MXC_ENABLE_TELEMETRY=1` or `"telemetry": { "enabled": true }` in config to activate telemetry. This is the safest default for a security sandboxing tool deployed in sensitive environments.
- Q: How should users be informed about what telemetry collects — README only or a runtime notice? → A: README only (Option A). A dedicated Telemetry section in the README documents what is collected and the no-PII guarantee. No runtime notice or consent prompt is emitted.
- Q: What is the acceptable telemetry performance overhead budget? → A: Async-only exporter required; overhead MUST NOT exceed 5 ms added to total execution wall time (Option A).
- Q: Should the OTel provider be force-flushed before process exit to prevent span loss on short-lived runs? → A: Yes — force_flush() + shutdown() required before exit, max 2-second wait (Option A). This applies to both the Rust binary and the TypeScript SDK/CLI.
