# WSLC-Inclusive Version-Aware Stack Session Plan

Status: active handoff for the WSLC-inclusive stack.

Date: September 17, 2026.

## Scope and ownership

This session owns only:

| Phase | Branch | PR | Current remote tip |
| --- | --- | --- | --- |
| Phase 12 | `user/gudge/version_specific_config_parsers_phase12_wslc_graduation` | #1187 | `eb88b090` |
| Phase 13 core | `user/gudge/version_specific_config_parsers_phase13_wslc_graduation` | #1188 | `54496529` |
| Phase 13 follow-ups | `user/gudge/version_specific_config_parsers_phase13_wslc_graduation_followups` | #1189 | `1d76e9ce` |

Use a clean independent worktree, preferably
`D:\git\microsoft\mxc\mxc.cyan`, and attach the named WSLC branch there. Do not
modify or push the non-WSLC branches.

## Current Phase 12 state

#1187 is based on `ca1ada8a`. Current `origin/main` was `dd589b41` when this
handoff was written.

The current head includes fixes for:

- Windows all-feature clippy failures in the IsolationSession SDK tests;
- Hyperlight and MicroVM callers that still declared v0.9;
- permanent top-level `wslc.provision` in inline lifecycle requests;
- retaining all WSLC one-shot and lifecycle runtime fixtures on published
  v0.9;
- directional networking in the C# WSLC example;
- removal of stale documentation that still called graduated WSLC
  experimental.

Copilot's four comments on #1187 have been addressed. Exact schema validation
accepts all v0.9 WSLC fixtures, and representative v0.9 provision dry runs reach
the intended `policy_validation` and `malformed_request` paths.

## Required sequence

1. Monitor #1187 until every required check is green. Treat neutral/skipped
   aggregate CodeQL as acceptable when both language analyses pass.
2. Inspect only newly failing jobs. Do not repeatedly report already-known
   failures.
3. If Phase 12 changes again:
   - make the smallest fix on the WSLC Phase 12 branch;
   - validate the failing job and the WSLC feature-specific paths;
   - preserve the single-commit PR shape with `git commit --amend`;
   - push with an explicit `--force-with-lease`;
   - wait for the new #1187 CI run.
4. Do not rebase #1188 or #1189 until #1187 is fully green.
5. Once #1187 is green, fetch `origin` and record the remote tips. Restack:

   ```powershell
   git rebase --onto `
     origin/user/gudge/version_specific_config_parsers_phase12_wslc_graduation `
     ef52be43685d417c20b15a29d213ca79db43f105 `
     user/gudge/version_specific_config_parsers_phase13_wslc_graduation

   git rebase --onto `
     user/gudge/version_specific_config_parsers_phase13_wslc_graduation `
     544965294edb33f7c138bc90b6b478169f4cec15 `
     user/gudge/version_specific_config_parsers_phase13_wslc_graduation_followups
   ```

   Recompute the old-parent arguments if either remote Phase 13 tip changed.
6. Verify each rewritten endpoint. In addition to the standard Rust, Node,
   .NET, exact-codegen, and config-validation ladder, run:
   - WSLC-feature checks and clippy for `wxc`, `mxc_engine`, `mxc-sdk`, and
     `mxc_ffi`;
   - WSLC-feature unit tests for the engine, Rust SDK, and FFI;
   - exact v0.9 WSLC fixture validation and representative state-aware dry
     runs.
7. Confirm each PR remains exactly one commit above its base, contains the
   required trailers, and passes the base-sensitive contract-history gate.
8. Push #1188 and #1189 with explicit `--force-with-lease`.
9. Verify:

   ```text
   #1187: main <- phase12_wslc_graduation
   #1188: phase12_wslc_graduation <- phase13_wslc_graduation
   #1189: phase13_wslc_graduation <- phase13_wslc_graduation_followups
   ```

## Guardrails

- Do not modify the non-WSLC branches or PRs.
- Keep WSLC in published v0.9; do not copy the non-WSLC stack's v0.10 WSLC
  defaults into this stack.
- Preserve compile-time feature gates, platform probes, and runtime
  prerequisites even though runtime experimental authorization is removed.
- Live WSLC runtime E2E requires a suitable WSL2/WSLC host. Report it as
  unavailable rather than silently treating a skip as execution coverage.
- If `origin/main` advances, do not rewrite a green Phase 12 automatically.
  First determine whether GitHub requires it to be current. Any Phase 12
  rewrite restarts the green-CI gate.

## Completion

This session is complete when #1187 is green and #1188/#1189 are restacked,
verified, pushed, and correctly based.
