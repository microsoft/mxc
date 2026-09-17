# Non-WSLC Version-Aware Stack Session Plan

Status: active handoff for the non-WSLC stack.

Date: September 17, 2026.

## Scope and ownership

This session owns only:

| Phase | Branch | PR | Current remote tip |
| --- | --- | --- | --- |
| Phase 12 | `user/gudge/version_specific_config_parsers_phase12` | #1184 | `4d26fab7` |
| Phase 13 core | `user/gudge/version_specific_config_parsers_phase13` | #1185 | `82f62e94` |
| Phase 13 follow-ups | `user/gudge/version_specific_config_parsers_phase13_followups` | #1186 | `fc5d4514` |

Use `D:\git\microsoft\mxc\mxc.skyblue`. It currently holds the Phase 12 branch.
Do not modify or push any `*_wslc_graduation*` branch.

## Current Phase 12 state

#1184 is based on `ca1ada8a`. Current `origin/main` was `dd589b41` when this
handoff was written.

The current head includes fixes for:

- Windows all-feature clippy failures in the IsolationSession SDK tests;
- inline MicroVM and Hyperlight E2E requests that still declared v0.9;
- Hyperlight migration and snapshot-warmup requests;
- Windows Sandbox and WSLC state-aware test defaults;
- remaining Node WSLC/MicroVM integration callers;
- permanent top-level WSLC provision payloads;
- the C# WSLC example's directional network shape.

Copilot's six comments on #1184 have been addressed. CodeQL's aggregate check
became neutral after rebasing onto the main commit that already contains the
open alerts.

## Required sequence

1. Monitor #1184 until every required check is green. Treat neutral/skipped
   aggregate CodeQL as acceptable when both language analyses pass.
2. Inspect only newly failing jobs. Do not repeatedly report already-known
   failures.
3. If Phase 12 changes again:
   - make the smallest fix on the Phase 12 branch;
   - run the relevant failing job locally plus the Phase 12 regression gates;
   - preserve the single-commit PR shape with `git commit --amend`;
   - push with an explicit `--force-with-lease`;
   - wait for the new #1184 CI run.
4. Do not rebase #1185 or #1186 until #1184 is fully green.
5. Once #1184 is green, fetch `origin` and record the remote tips. Restack:

   ```powershell
   git rebase --onto `
     origin/user/gudge/version_specific_config_parsers_phase12 `
     57eea6c053597003e8cce65e1ecb5d1d1eca13fd `
     user/gudge/version_specific_config_parsers_phase13

   git rebase --onto `
     user/gudge/version_specific_config_parsers_phase13 `
     82f62e94bf66ba2183944ffa55147cda259c0ec2 `
     user/gudge/version_specific_config_parsers_phase13_followups
   ```

   Recompute the old-parent arguments if either remote Phase 13 tip changed.
6. Verify each rewritten endpoint. The minimum applicable ladder is:
   - `cargo fmt --all -- --check`
   - `cargo check --workspace --all-targets`
   - Windows all-feature release clippy
   - `cargo test --workspace`
   - Node build, unit tests, and integration type-check
   - .NET tests
   - versioning tests, exact codegen, and config validation
7. Confirm each PR remains exactly one commit above its base, contains the
   required trailers, and passes the base-sensitive contract-history gate.
8. Push #1185 and #1186 with explicit `--force-with-lease`.
9. Verify:

   ```text
   #1184: main <- phase12
   #1185: phase12 <- phase13
   #1186: phase13 <- phase13_followups
   ```

## Guardrails

- Do not alter the published v0.9 schema after #1184 is selected for merge.
- Do not import WSLC graduation changes from #1187.
- Do not dismiss CodeQL alerts as part of this stack; alerts already on main
  are not Phase 12 changes.
- A transient package-install failure may be rerun only after confirming the
  identical job succeeds on the parallel stack or the log shows infrastructure
  failure.
- If `origin/main` advances, do not rewrite a green Phase 12 automatically.
  First determine whether GitHub requires it to be current. Any Phase 12
  rewrite restarts the green-CI gate.

## Completion

This session is complete when #1184 is green and #1185/#1186 are restacked,
verified, pushed, and correctly based.
