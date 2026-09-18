# Non-WSLC Version-Aware Stack Session Plan

Status: completed implementation record for the non-WSLC stack.

Date: September 18, 2026.

## Scope and ownership

This session owns only:

| Phase | Branch | PR | Current remote tip |
| --- | --- | --- | --- |
| Phase 12 | `user/gudge/version_specific_config_parsers_phase12` | #1184 | `11d09229` |
| Phase 13 core | `user/gudge/version_specific_config_parsers_phase13` | #1185 | `6fa9ba0d` |
| Phase 13 follow-ups | `user/gudge/version_specific_config_parsers_phase13_followups` | #1186 | `f89c574d` |

Use `D:\git\microsoft\mxc\mxc.skyblue`. It currently holds the Phase 12 branch.
Do not modify or push any `*_wslc_graduation*` branch.

## Final state

The stack is based on current `origin/main` `4bb804c0` and has the exact
one-commit chain:

```text
4bb804c0 <- 11d09229 (#1184) <- 6fa9ba0d (#1185) <- f89c574d (#1186)
```

Local and remote refs match. The Phase 13 worktrees were restored detached at
their parent commits, the Phase 12 worktree remains clean on its named branch,
and all review threads on #1184, #1185, and #1186 are resolved.

The finalized stack includes:

- Windows all-feature clippy failures in the IsolationSession SDK tests;
- inline MicroVM and Hyperlight E2E requests that still declared v0.9;
- Hyperlight migration and snapshot-warmup requests;
- Windows Sandbox and WSLC state-aware test defaults;
- remaining Node WSLC/MicroVM integration callers;
- permanent top-level WSLC provision payloads;
- the C# WSLC example's directional network shape;
- v0.10 playground requests for Windows Sandbox, MicroVM, and Hyperlight;
- version-dependent typed-SDK network compatibility;
- policy hashes based on effective enforcement rather than source
  attribution;
- registry-driven fixture diagnostics and controlled schema-generator failure
  for inconsistent metadata.

## Validation completed

- Rust formatting, workspace checks, all-feature Clippy, and workspace tests;
- MicroVM-enabled x64 E2E coverage;
- Node build, unit tests, and integration type-check;
- .NET tests;
- 82 versioning tests, exact codegen/parity gates, and validation of 363
  configurations against five exact registered schemas;
- focused playground, binding-request, Rust SDK doctest, policy-identity, and
  schema-generator regressions.

## Guardrails

- Do not alter the published v0.9 schema after #1184 is selected for merge.
- Do not import WSLC graduation changes from #1187.
- Do not dismiss CodeQL alerts as part of this stack; alerts already on main
  are not Phase 12 changes.
- A transient package-install failure may be rerun only after confirming the
  identical job succeeds on the parallel stack or the log shows infrastructure
  failure.
- Any later rewrite must rerun applicable verification before a
  `--force-with-lease` push.

## Completion

Completed on September 18, 2026: #1184, #1185, and #1186 are restacked,
verified, pushed, correctly based, and free of unresolved review threads.
