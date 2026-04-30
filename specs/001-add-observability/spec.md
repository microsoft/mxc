# Feature Specification: Observability — TraceLogging ETW Telemetry & Adoption Metrics

**Feature Branch**: `001-add-observability`  
**Created**: 2026-03-25  
**Revised**: 2026-04-28 — replaced 1DS C++ SDK with TraceLogging ETW via `tracelogging` Rust crate  
**Status**: Draft  


## User Scenarios & Testing *(mandatory)*

### User Story 1 — Rust Core Execution Observability (Priority: P1)

An operator or developer runs `wxc-exec` to execute a sandboxed script. They want to
understand what happened during execution — which container backend was used, how long
initialization and execution took, and whether any errors or policy violations occurred —
without having to read raw process output or ETW traces.

After this story is implemented, every Rust execution path emits TraceLogging ETW events
that can be captured by any ETW controller (e.g., `tracelog`, `logman`, WPR, or a
custom ETW consumer).

**Why this priority**: This is the foundational observability layer. Without Rust-level ETW
events, there is nothing to build adoption metrics on top of, and the TypeScript layer has no
semantic context to propagate. It also makes immediately actionable the requirement to add
telemetry "where no telemetry is present."

**Independent Test**: Run `wxc-exec` with a valid JSON configuration against any backend
(AppContainer, Sandbox, or LXC) with telemetry enabled. Verify that an `MXC.Execution`
ETW event is emitted containing backend type, exit code, and duration — with no PII
fields present. Events can be captured via `tracelog` or `logman`.

**Acceptance Scenarios**:

1. **Given** a valid JSON configuration and telemetry enabled,
   **When** `wxc-exec` runs a script to completion,
   **Then** an `MXC.Execution` ETW event is emitted containing fields for backend type,
   exit code, duration, init duration, and version.

2. **Given** `wxc-exec` is configured with the AppContainer backend,
   **When** execution completes successfully,
   **Then** the emitted `MXC.Execution` event includes `mxc.backend=appcontainer`,
   `mxc.exit_code=0`, `mxc.outcome=success`, and `mxc.duration_ms`; and does NOT include
   script content, file paths, usernames, or machine names.

3. **Given** `wxc-exec` encounters an error (e.g., policy validation failure),
   **When** the error is raised,
   **Then** an `MXC.Error` ETW event is emitted with a sanitized error message and a
   bounded `mxc.error_type` category — without recording the full script content.

4. **Given** telemetry has not been explicitly enabled,
   **When** `wxc-exec` runs without `--experimental` or without `experimental.telemetry.enabled`,
   **Then** no ETW events are emitted (the TraceLogging provider is not registered).

---

### User Story 2 — Product Adoption Metrics (Priority: P2)

The MXC product team wants to understand how the tool is being adopted in the wild:
which execution backends are in use, how often the tool is invoked, and what the overall
success and failure rate is. This data enables prioritization of backend investment and
validates distribution and adoption growth.

Adoption metrics are emitted as ETW event fields (backend, outcome, duration) alongside
the existing execution events, enabling consumer-side aggregation for counters and histograms.

**Why this priority**: Adoption metrics require the foundational ETW infrastructure from US1
and the opt-out mechanism. They are designed to enable operators and the product
team to understand adoption patterns.

**Independent Test**: Run `wxc-exec --experimental` multiple times with different backends (AppContainer, LXC)
and confirm that execution count, backend-type breakdowns, and latency data are available
as ETW event fields that can be aggregated by any ETW consumer.

**Acceptance Scenarios**:

1. **Given** an ETW trace session is capturing the `Microsoft.MXC` provider,
   **When** `wxc-exec` completes an execution,
   **Then** the following metrics are recorded: execution count (by backend),
   success/failure count (by backend), and execution latency (histogram, by backend).

2. **Given** multiple executions occur across different backends,
   **When** a team member queries the captured ETW trace,
   **Then** per-backend breakdowns are available without any PII-bearing dimensions.

3. **Given** the opt-out mechanism is active,
   **When** `wxc-exec` runs,
   **Then** no metrics are emitted (consistent with opt-out behavior).

4. **Given** the JSON config includes `"experimental": { "telemetry": { "enabled": true } }`
   and `--experimental` is passed,
   **When** `wxc-exec` runs,
   **Then** events are emitted to the local ETW subsystem where any registered consumer
   can capture them.

---

### User Story 3 — TypeScript SDK/CLI Telemetry Propagation (Priority: P3)

A developer using the TypeScript SDK (`@microsoft/mxc-sdk`) or the `mxc-cli` to automate
script execution wants telemetry configuration to be correctly propagated to the Rust binary
so that ETW events are emitted when telemetry is enabled.

**Why this priority**: The TypeScript layer is the primary integration surface for Node.js and
Electron callers. Without correct telemetry propagation, the Rust binary cannot honor the
caller's telemetry preferences (enabled/disabled). This is lower priority than the
Rust core because the Rust binary always runs regardless of which TS API is used.

**Independent Test**: Write a TypeScript program using the SDK's `run()` method with a
config object containing `experimental: { telemetry: { enabled: true } }`. Verify that the
spawned `wxc-exec` JSON config includes the `experimental.telemetry` section. Verify that
omitting the `telemetry` field results in no telemetry override.

**Acceptance Scenarios**:

1. **Given** the TypeScript SDK is called with `experimental: { telemetry: { enabled: true } }`,
   **When** `WxcExecutor.run()` is called,
   **Then** the JSON config passed to `wxc-exec` includes
   `"experimental": { "telemetry": { "enabled": true } }` and the Rust binary emits ETW events.

2. **Given** only the TypeScript CLI is used (no custom SDK code),
   **When** `mxc-cli run` is invoked with a config containing
   `"experimental": { "telemetry": { "enabled": true } }`,
   **Then** the JSON config includes the telemetry section and the Rust binary
   emits events to the local ETW subsystem.

3. **Given** the `experimental.telemetry` section is omitted from the config (release build),
   **When** any TypeScript SDK or CLI method is called,
   **Then** no telemetry override is injected and the Rust binary defaults to telemetry off.

---

### Edge Cases

- What happens when the `experimental.telemetry` section is present but malformed?
  Malformed telemetry config MUST be treated as if telemetry is disabled
  (safe default) and a warning emitted to stderr.
- Can PII be accidentally emitted through error messages or event properties?
  All error messages captured in events MUST be sanitized: file paths, script content,
  and environment variable values MUST NOT appear in event fields.
- What happens when `--experimental` is not passed but `experimental.telemetry` is in the config?
  Telemetry MUST NOT be activated. The `--experimental` CLI flag is a required gate.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The Rust execution layer MUST emit a TraceLogging `MXC.Execution` ETW event
  for every invocation of `wxc-exec`, capturing the full execution lifecycle including
  container initialization, policy application, script execution, and teardown timing.
  Linux (`lxc-exec`) telemetry is a P2 requirement (see Linux Support section).
- **FR-002**: Each emitted ETW event MUST include structured fields: `mxc.backend`
  (enum: appcontainer, sandbox, lxc, wslc), `mxc.exit_code` (integer), `mxc.duration_ms`
  (integer), `mxc.init_duration_ms` (integer), and `mxc.version` (string).
- **FR-003**: Emitted ETW events MUST NOT include: script source code, command-line
  argument values, file paths, environment variable values, usernames, machine hostnames,
  or IP addresses.
- **FR-004**: The Rust execution layer MUST emit ETW telemetry events containing adoption
  metrics as event fields: execution count (by backend and outcome), failure count
  (by backend and failure reason category), and execution latency in milliseconds (by
  backend). Consumer-side aggregation on ETW traces provides counter and histogram
  equivalents from these event fields.
- **FR-005**: Setting `"experimental": { "telemetry": { "enabled": true } }` in the JSON
  configuration with the `--experimental` CLI flag MUST activate TraceLogging ETW event
  emission for that invocation (explicit opt-in).
- **FR-006**: Setting `"experimental": { "telemetry": { "enabled": false } }` in the JSON
  configuration MUST suppress TraceLogging ETW event emission for that invocation
  (explicit opt-out), overriding the default.
- **FR-007**: The telemetry resolution logic MUST follow this priority order:
  1. `--experimental` CLI flag must be present (gate).
  2. `experimental.telemetry.enabled` in JSON config — explicit override, always wins.
  3. Default: off (telemetry requires explicit opt-in).
  Consent is the responsibility of the calling agent (SDK consumer), not MXC.
- **FR-008**: Telemetry failures (provider registration failure, event write error) MUST NOT
  propagate as user-visible errors, affect execution output, or alter the exit code of
  `wxc-exec`.
- **FR-009**: The TypeScript SDK MUST pass the `experimental.telemetry` section from the
  caller-provided config object through to the JSON config file used to spawn `wxc-exec`.
  The SDK MUST NOT read environment variables for telemetry configuration.
- **FR-010**: The TypeScript CLI MUST pass the `experimental.telemetry` section from the
  JSON config file through to the executor, ensuring the Rust binary receives the correct
  telemetry configuration.
- **FR-011**: The TypeScript layer MUST NOT independently interpret or override the
  `experimental.telemetry` section; it is a transparent pass-through to the Rust binary.
- **FR-012**: TraceLogging events are emitted to the local ETW subsystem. No remote
  endpoints or regional routing is required. ETW consumers (trace controllers, WPR,
  `logman`, or a 1DS UTC agent if deployed separately) are responsible for collecting
  and routing events.
- **FR-013**: Telemetry instrumentation MUST use the `tracelogging` Rust crate (v1.2+)
  from the [microsoft/tracelogging](https://github.com/microsoft/tracelogging) repository.
  Events are emitted via TraceLogging ETW using `define_provider!` and `write_event!`
  macros. No C/C++ FFI, git submodule, or CMake build is required.
- **FR-014**: Existing `Logger` and ETW instrumentation MUST remain fully functional;
  TraceLogging telemetry is additive and MUST NOT replace or break existing debug output.
- **FR-015**: The project README MUST include a dedicated `Telemetry` section that describes:
  (a) that telemetry is an experimental feature requiring `--experimental`,
  (b) how to enable it (`experimental.telemetry.enabled: true` in JSON config),
  (c) how to disable it (`experimental.telemetry.enabled: false`),
  (d) the exact set of event fields collected,
  (e) the explicit guarantee that no PII is collected, and
  (f) how to capture events using ETW tools (`tracelog`, `logman`, WPR).
- **FR-016**: TraceLogging events are written synchronously to the ETW subsystem via
  `write_event!`. The total overhead added to `wxc-exec` wall-clock execution time by
  the telemetry subsystem MUST NOT exceed 5 ms.
- **FR-017**: The Rust binary MUST call `MY_PROVIDER.unregister()` on the TraceLogging
  provider before process exit to ensure clean ETW session teardown.
- **FR-018**: No changes to the GitHub Actions CI pipeline checkout step are required.
  The `tracelogging` crate is a standard Cargo dependency with no submodule or
  external toolchain requirements.
- **FR-019**: No additional CI build agent toolchain requirements are introduced.
  The `tracelogging` crate compiles with the standard Rust toolchain and links
  `advapi32.lib` (a Windows system library).
- **FR-020** *(removed)*: CMake caching is no longer needed; there is no C++ build step.
- **FR-021**: The `wxc-exec-lint` CI job MUST continue to pass `cargo clippy` and
  `cargo fmt` checks after the `tracelogging` dependency is added to the workspace.
- **FR-022** *(removed)*: Submodule guard is no longer needed; the `tracelogging` crate
  is fetched by Cargo like any other dependency.
- **FR-023** *(removed)*: Consent prompt eliminated — consent is the SDK consumer's responsibility.\n- **FR-024** *(removed)*: TTY detection eliminated — no interactive prompt.\n- **FR-025** *(removed)*: Consent file eliminated — no persistent consent storage.\n- **FR-026** *(removed)*: Consent resolution chain simplified — see FR-007.\n- **FR-027** *(removed)*: Consent prompt UX eliminated.

### Key Entities

- **Telemetry Configuration**: An optional section under `experimental.telemetry` in the
  MXC JSON config schema that controls telemetry behavior for an invocation. Key field:
  `enabled` (boolean). Requires the `--experimental` CLI flag to be active.
- **Calling Agent**: The process that invokes MXC (e.g., GitHub Copilot, Nanoclaw). The agent
  is responsible for obtaining user consent and passing it to MXC via the JSON config
  `experimental.telemetry.enabled` field. Consent management is entirely the agent's
  responsibility — MXC does not implement consent prompts or persistent consent storage.
- **Opt-In Signal**: The state derived from (in priority order): (1) `--experimental` CLI
  flag (gate), (2) `experimental.telemetry.enabled` field (explicit override),
  (3) default: off (telemetry requires explicit opt-in).
- **Execution Event**: A TraceLogging `MXC.Execution` ETW event covering the full lifetime
  of a single `wxc-exec` run, with fields for backend, outcome, exit code, duration, and
  version.
- **Error Event**: A TraceLogging `MXC.Error` ETW event emitted on failure, with a bounded
  error type category and a sanitized error message.
- **Adoption Metric**: Adoption data is derived from `MXC.Execution` event fields
  (backend type, outcome, duration) via consumer-side aggregation on ETW traces.
  Dimensions are limited to: backend type, outcome (success/failure), and failure reason
  category (no finer granularity).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Every successful and failed execution of the Rust binary produces at least one
  TraceLogging `MXC.Execution` ETW event containing backend type, exit code, and duration —
  verifiable by capturing events via `tracelog` / `logman` or a programmatic ETW consumer.
- **SC-002**: With no `experimental.telemetry` section in the JSON config or without the
  `--experimental` flag (release build), zero ETW events are emitted and the TraceLogging
  provider is not registered — verifiable with ETW tracing.
  Adding `--experimental` with `\"experimental\": { \"telemetry\": { \"enabled\": true } }`
  activates telemetry.
- **SC-003**: No ETW event field contains any of the following: script source code, file
  paths, environment variable values, usernames, or machine names — verifiable by static
  code review and integration test assertions against emitted event fields.
- **SC-004**: Execution count and latency data are emitted per-backend (as `mxc.backend`
  field) so the team can distinguish AppContainer, Sandbox, LXC, and WSLC adoption
  trends independently via consumer-side aggregation.
- **SC-005**: When an ETW trace session is not active, `wxc-exec` exit code and stdout/stderr
  output are identical to a run with telemetry disabled — verifiable by comparing outputs.
- **SC-006**: The TypeScript SDK and CLI correctly pass through the `telemetry` section
  from the caller-provided config to the Rust binary via the JSON config — verifiable
  by inspecting the JSON config passed to `wxc-exec`.
- **SC-007**: When telemetry is enabled, the total added wall-clock overhead to a `wxc-exec`
  run MUST NOT exceed 5 ms — verifiable by timing 100 identical runs with and without
  `experimental.telemetry.enabled: true` and comparing p95 latency.
- **SC-008**: On a run where `wxc-exec` completes in under 500 ms, all emitted ETW events
  are still written to the ETW buffer — verifiable by confirming events appear in the
  captured trace for short-lived executions (enabled by `unregister()` before exit).
- **SC-009**: (Manual) An end-to-end integration test confirms that telemetry events flow
  from `wxc-exec` through TraceLogging to the ETW subsystem — verifiable by a human tester
  starting an ETW trace session for the `Microsoft.MXC` provider, running `wxc-exec`, and
  confirming events appear in the decoded trace output.

## Scope

### In Scope

- TraceLogging ETW events (`MXC.Execution`, `MXC.Error`) for Windows execution backends
  (AppContainer, Sandbox, WSLC). Linux backends (LXC) are P2 (see Linux Support section).
- Adoption metrics as ETW event fields (execution count, outcome, latency per backend).
- Caller-delegated consent: the invoking agent (e.g., GitHub Copilot, Nanoclaw)
  is responsible for obtaining user consent. MXC does not implement consent
  prompts or persistent consent storage.
- Opt-in via `"experimental": { "telemetry": { "enabled": true } }` with `--experimental`.
- Opt-out via `"experimental": { "telemetry": { "enabled": false } }`.
- TypeScript SDK and CLI telemetry config propagation to the Rust binary.
- JSON configuration schema extension for the `experimental.telemetry` section.
- Privacy audit: static enforcement that no PII fields are captured in any event field.

### Out of Scope

- Replacing or removing existing `Logger` / ETW instrumentation.
- Building a custom telemetry dashboard or data pipeline.
- 1DS pipeline integration (TraceLogging emits to local ETW; remote collection is out of scope).
- Regional endpoint routing or EUDB compliance (these are concerns of any downstream
  ETW consumer, not of MXC itself).
- Changing existing exit codes, stdout format, or any user-visible behavior of `wxc-exec`.
- Telemetry for the build system or CI pipeline.
- Linux telemetry (P2 — the `tracelogging` crate compiles as no-ops on non-Windows;
  LTTng support may be added later).

## Assumptions

- MXC is typically invoked by a calling agent (e.g., GitHub Copilot, Nanoclaw)
  rather than directly by a human user. The calling agent is responsible
  for obtaining user consent. MXC does not implement consent prompts or
  persistent consent storage. Consent is entirely the agent's responsibility.
- Telemetry is an experimental feature gated behind the `--experimental` CLI flag.
  It is controlled by a two-level resolution: (1) `experimental.telemetry.enabled`
  in JSON config (explicit override), (2) default: off (telemetry requires
  explicit opt-in).
- The `tracelogging` Rust crate (v1.2+, from [microsoft/tracelogging](https://github.com/microsoft/tracelogging))
  is the telemetry backend. It provides `define_provider!` and `write_event!` macros that
  emit self-describing ETW events. No C/C++ FFI, git submodule, or CMake build is required.
  On non-Windows platforms (Linux), the crate compiles as no-ops.
- The TypeScript SDK and CLI pass the `experimental.telemetry` section from the
  caller-provided config through to the Rust binary. No TypeScript-side telemetry SDK is used.
- Linux telemetry is a P2 requirement. The `tracelogging` crate compiles as no-ops on Linux,
  so the code compiles cleanly but does not emit events. A future iteration may add
  LTTng tracepoint support using the same `microsoft/tracelogging` repo.
- No 1DS compatibility is required. Events are emitted to the local ETW subsystem.
  If a downstream 1DS UTC agent or other ETW consumer is present, it can collect events
  independently, but MXC does not directly integrate with 1DS endpoints.
- **Operational prerequisite — Windows Telemetry pipeline onboarding**: The
  `Microsoft.MXC` TraceLogging provider joins the Microsoft Telemetry provider
  group via `group_id("4f50731a-89cf-4782-b3e0-dce8c90476ba")` (the Rust equivalent
  of the C/C++ `TraceLoggingOptionGroup` macro with the well-known Microsoft
  Telemetry GUID). This tells the Windows **Connected User Experiences and Telemetry**
  component (CUET, also known as DiagTrack / `diagtrack.dll`) that this provider
  is a Microsoft first-party telemetry source.

  For events to flow from devices to Microsoft's backend, the following operational
  steps must be completed (these are not code changes):

  1. **Provider onboarding with the Windows Telemetry team**: Register the
     `Microsoft.MXC` provider with the Windows Telemetry onboarding process.
     This authorizes the provider GUID within the CUET pipeline and configures
     which events are collected. The CUET component uses **OneSettings** (a
     cloud-based configuration service) to control which providers and event
     keywords it listens to — a new provider is not collected by default.

  2. **Event schema registration**: Register the `MXC.Execution` and `MXC.Error`
     event schemas with the telemetry pipeline so events are correctly parsed
     and stored upon ingestion at `v10.events.data.microsoft.com`.

  3. **Data access and querying**: Set up access to the ingested data in
     **Kusto** (Azure Data Explorer) or the internal telemetry dashboarding
     tools to query and visualize the MXC telemetry events.

  Note: This is distinct from "1DS/Aria" — while 1DS and Aria are related
  Microsoft telemetry systems, the Windows diagnostic data pipeline
  (CUET/DiagTrack → `v10.events.data.microsoft.com` → Cosmos/Kusto) is the
  path for TraceLogging providers using the Microsoft Telemetry provider group.
  These steps are tracked separately from this feature spec and must be completed
  before telemetry data flows end-to-end in production.
- The failure reason category dimension on metrics is a bounded enum (e.g., config_error,
  policy_error, process_error, timeout) — not a free-form string — to prevent accidental PII.
- Malformed telemetry configuration is treated as `enabled: false` (safe default) rather than failing the run.
- The existing Cargo workspace structure is extended, not restructured. `wxc_common` gains
  a `telemetry/` module. No new crate is needed.
- The GitHub Actions CI pipeline requires no changes for TraceLogging support.
  The `tracelogging` crate is a standard Cargo dependency.


