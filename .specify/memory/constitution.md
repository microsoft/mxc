<!--
SYNC IMPACT REPORT
==================
Version change: N/A (unfilled template) → 1.0.0
Modified principles: N/A — initial concrete constitution; all sections newly authored
Added sections:
  - Core Principles (I–V)
  - Development Workflow
  - Clarification-First Policy
  - Governance
Removed sections: N/A
Templates requiring updates:
  ✅ .specify/templates/plan-template.md — Constitution Check gates filled with MXC-specific gates
  ✅ .specify/templates/tasks-template.md — Test task examples updated to Rust conventions,
       observability task type added to Phase N
  ⚠  .specify/templates/spec-template.md — No constitution-specific changes required
  ⚠  .specify/templates/checklist-template.md — No constitution-specific changes required
Follow-up TODOs:
  - None: all fields resolved from codebase context
-->

# MXC Constitution

## Core Principles

### I. Codebase Conventions (NON-NEGOTIABLE)

All contributions MUST conform to the existing codebase style and structure:

- Every Rust source file MUST begin with the Microsoft copyright header:
  `// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT License.`
- Rust code MUST pass `cargo fmt --all -- --check` without changes.
- Rust code MUST pass `cargo clippy --workspace --all-targets -- -D warnings`
  with zero warnings promoted to errors.
- New crates MUST be added to the workspace `Cargo.toml` members list and use
  `workspace = true` dependency references where dependencies already exist in the
  workspace manifest.
- Platform-specific code MUST be gated with `#[cfg(target_os = "...")]` following
  the existing `lib.rs` pattern; no platform-specific code in platform-agnostic modules.
- The existing module layout (one logical concern per file, named after the concern)
  MUST be followed for new files within existing crates.

**Rationale**: MXC is an in-progress project. Drift from existing conventions creates
maintenance cost, review friction, and CI failures that block other contributors.

### II. Test-First Development (NON-NEGOTIABLE)

TDD MUST be applied to all new Rust logic:

- Tests MUST be written and reviewed before implementation begins.
- Tests MUST demonstrably fail (Red) before implementation proceeds.
- Implementation proceeds only until tests pass (Green); then refactor.
- Unit tests live in inline `#[cfg(test)]` modules within the same `.rs` file as
  the code under test.
- Integration tests that exercise cross-crate behavior live in `tests/` directories
  within the relevant crate and are run via `cargo test`.
- The CI gate `cargo test --release` MUST pass for all supported targets before
  any PR may merge.

**Rationale**: The sandboxed execution domain requires high correctness confidence.
TDD surfaces design problems early and prevents regressions across the Windows and
Linux backends.

### III. Rust Best Practices

Idiomatic Rust MUST be used throughout the codebase:

- Prefer `Result<T, E>` over `panic!` or `unwrap()` in all library code; panics are
  only acceptable in tests and in unreachable branches with a `// SAFETY:` comment.
- Use `thiserror` for structured error enumerations in library crates; use `anyhow`
  only in binary entry points (`main.rs`).
- Use `serde` + `serde_json` for all JSON serialization following the existing
  `#[serde(default)]` / `#[serde(rename_all = "...")]` patterns in `models.rs`.
- Async code MUST use `tokio` (workspace dependency) and MUST NOT block the async
  executor with synchronous I/O.
- Unsafe code MUST be accompanied by a `// SAFETY:` comment explaining the
  invariants that make the block sound; minimize unsafe surface area.
- Edition 2021 MUST be used for all crates; the Rust stable toolchain is required.

**Rationale**: Consistent idiomatic patterns reduce cognitive load during review,
improve compiler-assisted safety, and maintain the existing workspace dependency
discipline.

### IV. Observability via OpenTelemetry (NON-NEGOTIABLE)

All new features MUST be instrumented with OpenTelemetry:

- Use the `opentelemetry` crate family together with the `tracing` crate and the
  `tracing-opentelemetry` bridge so spans propagate through the OTel pipeline.
- Every significant code path (container creation, policy application, script
  execution, error handling) MUST be wrapped in a named tracing span.
- Structured span attributes MUST be emitted for context-relevant fields (e.g.,
  `container.name`, `backend.type`, `request.id`, `exit_code`).
- Error paths MUST record the error as a span event (`tracing::error!` or
  `span.record_error(&err)`).
- Metrics (counters, histograms) MUST be emitted for execution throughput and
  latency at the crate boundary.
- Existing `Logger`/ETW instrumentation MUST remain functional; OTel is additive.

**Rationale**: MXC runs untrusted code in sandboxed environments; distributed
tracing and metrics are essential for diagnosing policy failures, latency regressions,
and security incidents in production.

### V. Security by Design (NON-NEGOTIABLE)

Security is the core product value of MXC; it MUST never be a secondary concern:

- Input validation MUST occur at every system boundary: JSON configuration parsing,
  CLI argument handling, and IPC message deserialization.
- Principle of least privilege MUST be applied to all container configurations and
  internal process permissions.
- Security vulnerabilities MUST NOT be reported via public GitHub issues; follow the
  Microsoft security reporting process documented in `SECURITY.md`.
- Dependency updates MUST be reviewed for known CVEs before merging.
- No new capability or network policy bypass may be added without documented
  security review and explicit approval.
- OWASP guidance (injection, broken access control, insecure defaults) MUST be
  considered during review of any code that processes external input.

**Rationale**: MXC is a sandboxed code execution host. A security failure directly
exposes the host system. Security correctness cannot be traded for convenience or speed.

## Development Workflow

The development process MUST follow these gates in order:

1. **Specification**: Feature spec written and reviewed (`/speckit.specify`).
2. **Planning**: Implementation plan with Constitution Check gate cleared (`/speckit.plan`).
3. **Clarification**: Ambiguities resolved before any code is written (`/speckit.clarify`).
4. **Tasks**: TDD-ordered task list authored (`/speckit.tasks`).
5. **Implementation**: Tests written → confirmed failing → implementation → green.
6. **CI gate**: All of the following MUST pass before a PR is opened:
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo test --release --target x86_64-pc-windows-msvc`
   - `cargo test --release --target aarch64-pc-windows-msvc` (where available)
7. **Review**: At least one code review required; security-impacting changes require
   dedicated security review.
8. **Merge**: Squash-merge to `main`; branch deleted after merge.

**Build**: Run `build.bat` from the repo root for a full release build including
the TypeScript SDK. Use `build.bat --debug` for debug builds.

## Clarification-First Policy

When intent, design, or requirements are unclear, MUST ask before implementing:

- Do NOT make assumptions about security policy behavior, container backend semantics,
  or platform-specific behavior without explicit confirmation.
- Ambiguous design decisions MUST be documented as open questions in the feature spec
  and resolved before the planning phase begins.
- If a task's scope is unclear mid-implementation, pause and seek clarification rather
  than guessing.

**Rationale**: Incorrect assumptions in a sandboxed execution environment can
introduce security vulnerabilities or silent policy bypasses that are hard to detect.

## Governance

- This constitution supersedes all other practices, conventions, and informal norms.
- **Amendment procedure**: Amend via `/speckit.constitution` with a clear description
  of the change and rationale. Update `LAST_AMENDED_DATE` and increment the version
  per the policy below. Propagate to all dependent templates.
- **Versioning policy**:
  - MAJOR: Backward-incompatible change (principle removed, redefined, or renamed).
  - MINOR: New principle or section added, or existing principle materially expanded.
  - PATCH: Clarifications, wording improvements, typo fixes, non-semantic refinements.
- **Compliance review**: Every PR description MUST include a "Constitution Check"
  asserting compliance with each of the five principles. Non-compliance MUST be
  explicitly justified and approved before merge.

**Version**: 1.0.0 | **Ratified**: 2026-03-25 | **Last Amended**: 2026-03-25
