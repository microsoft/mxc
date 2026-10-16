---
name: mxc-code-review
description: Review MXC pull requests and diffs for SDK breaking changes, CI gate regressions, useful SDK documentation, maintainable design, and containment.
---

# MXC code review

Read `AGENTS.md`, `.github/copilot-instructions.md`, matching language
instructions, and the affected subsystem docs. Follow the changed flow through
its callers, shared code, backends, and failure paths. Do not make edits during
review or stop after finding one working path.

## Check SDK compatibility first

- Compare changed public APIs with the existing supported version in Rust,
  .NET, and Node. Check removals, renames, signatures, types, import paths,
  serialization, defaults, errors, cancellation, and resource ownership.
  Look for source, binary, and behavioral breaks, not only compile failures.

- Report every confirmed breaking change to an existing supported SDK API in
  the **highest review category: P0 / critical**. Put these findings first and
  label them **SDK breaking change**. This is a maintainer compatibility alert;
  it does not imply a security vulnerability or universal runtime failure.

- Identify the affected SDK and version, the old and new behavior, and a
  concrete caller that breaks. Call it out even when the PR describes the
  change as intentional. Maintainers decide whether to accept it; the reviewer
  must not silently waive it or assume acceptance.

- Published SDK APIs require a new versioned surface for breaking changes.
  Check that the existing version and its references remain intact. Adding
  a new version while preserving the old one is not itself a breaking change.

## Check the design in context

- Does the change fit the existing design and remain understandable to the
  next maintainer, or does it merely get the requested feature working?

- Look for duplicated paths, feature-specific helper variants, narrow
  exceptions, and unnecessary abstractions. Prefer fixing the responsible
  shared component over adding another special case.

- Check responsibility boundaries. Parsing should decode contracts and retain
  field presence; backend-specific defaults, policy checks, and enforcement
  belong in the backend, not the shared parser.

- If a feature requires a broad rewrite or large deletion, call out the
  maintenance risk and recommend smaller, reviewable vertical slices with
  behavior coverage. Do not demand a rewrite for a local problem.

## Check MXC rules

- **Rust package boundaries:** Inspect `src/Cargo.toml` workspace members and
  changed Cargo dependencies. Internal engine, contract, shared-runtime,
  backend, build, and schema implementations belong as modules in `mxc-sdk`,
  not new workspace crates or publishable path dependencies. Required process
  boundaries use existing `[[bin]]` patterns; distinguish legitimate tools and
  FFI packages from unnecessary SDK implementation crates.

- **Dispatch and build:** `mxc_engine` owns backend routing. No dispatch or
  backend implementation dependencies in `mxc_common`, backend-selection
  matches in thin executors, or recursive Cargo invocation in `build.rs`.
  Keep platform/feature gates and build-time staging intact.

- **Containment and errors:** Unsupported policy fails closed before container
  creation. Preserve failure propagation, cancellation, cleanup, handle
  ownership, and panic containment across the C ABI. Check each changed
  execution surface, not only create-and-run.

- **Contracts:** Preserve optional-field presence and version-specific parsing.
  Do not edit released schemas or hand-edit generated artifacts. Development
  fields need the proper contract, adapter, regenerated artifacts, and tests;
  experimental authorization does not replace contract or host validation.

- **SDKs:** Compare affected Rust, .NET, and Node versioned references. Preserve
  field meanings, optional-field presence, and language-appropriate naming.
  Confirm .NET JSON source-generation registration and AOT smoke coverage.

- **Host compatibility:** New Windows backend features need concrete host
  prerequisites, runtime capability checks, actionable unsupported-feature
  errors, and a brief update to existing user guidance when requirements or
  behavior change. Document supported builds, limits, and remedies, not a
  backend implementation walkthrough. SDK/schema versions alone cannot prove
  host support. Telemetry requires MXC-owned consent and restrictive admin policy.

## Keep SDK documentation useful

SDK READMEs and versioned API references are consumer-facing entry points.
Review additions and removals against what a caller needs to install, choose,
use, and safely clean up an operation.

- Keep signatures, examples, defaults, prerequisites, limitations, and error
  remedies accurate and consistent with the supported API. Check affected
  links and examples when content is moved or removed.

- Flag changes that hide supported behavior, remove necessary usage guidance,
  contradict the API, or bury instructions under irrelevant implementation
  detail. Keep backend internals and contributor workflows in developer docs;
  link them only when they help the reader's task.

- Make additions and removals leave a coherent final document. Avoid agent
  reasoning, change diaries, discarded designs, and repetition. Do not demand
  more documentation merely because code changed, or report wording nits as
  defects.

## Check for weakened CI gates

Inspect removed or changed checks, including workflows, reusable jobs, build
scripts, test commands, and matrix configuration. Do not assume a green check
means the same validation still runs.

- Check trigger and path filters, job conditions and dependencies, platform
  and feature coverage, test discovery, exclusions, and skipped tests.
  Look for checks that disappear or stop covering the changed behavior.

- Check failure propagation. `continue-on-error`, ignored exit codes, removed
  assertions, and success-shaped fallbacks can make a failing build or test
  appear green. Trace the relevant command through its callers to the final
  check result.

- Flag removed or weakened validation that lets a concrete regression pass.
  Name the lost check, the affected path or platform, and what CI no longer
  detects. Do not accept disabling the failing check as a fix for the failure.

- Legitimate replacement or retirement is allowed. Verify equivalent coverage
  still runs and gates the result, or that the covered behavior is actually
  removed. An explanation alone does not establish equivalent coverage.

## Require behavior coverage

Feature changes need functional validation in the applicable CI suite.
Backend behavior needs coverage in the scheduled/nightly validation runs on
suitable hosts. Bug fixes need a regression scenario for the reported failure,
preferably shown to fail before the fix and pass afterward. Verify the scenario
is wired into CI and checks observable behavior through the relevant API or
backend, including affected interactions and failures.

Do not accept a collection of tiny unit tests as a substitute for that coverage.
Unit tests, including those at the bottom of `.rs` files, can support isolated
logic; passing tests that mirror new helpers do not establish that a feature
works in MXC. Prefer extending existing functional scenarios over test-count
growth. Follow the validation runbook and backend guide; report specific gaps,
not demands for unrelated tests. Documentation-only edits need no runtime tests.

## Write useful findings

Focus on high- and medium-severity defects; critical failures always qualify.
Leave out low-severity issues, style nits, speculative scenarios, and optional
refactoring. Apply the highest-priority SDK breaking-change rule above;
otherwise, do not inflate severity just to include a finding.

Review all affected paths before submitting, combine related findings, and
post one consolidated review. Do not drip-feed findings across rounds or
reopen resolved points without new evidence. New edits still need review for
material regressions, not unrelated cleanup.

Use plain language an everyday developer can act on. Give the severity,
file/line, triggering situation, incorrect behavior, and consequence. Include
enough detail to explain the issue without jargon, long essays, or wording so
short that the reader must guess. Do not include an agent's internal reasoning.

Keep comments and requested documentation focused on non-obvious reasons and
useful behavior, usage, and limits, not implementation diaries. Separate
paragraph-length list items with a blank line; keep short lists compact.
Report concrete defects and material maintenance risks, not speculative bugs
or style preferences. Distinguish missing test evidence from a confirmed
runtime failure.
