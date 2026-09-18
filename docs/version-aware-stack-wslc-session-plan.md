# WSLC-Inclusive Version-Aware Stack Session Plan

Status: active rebuild handoff for the WSLC-inclusive stack.

Date: September 18, 2026.

## Scope and ownership

This session owns only:

| Phase | Branch | PR | Current remote tip |
| --- | --- | --- | --- |
| Phase 12 | `user/gudge/version_specific_config_parsers_phase12_wslc_graduation` | #1187 | `d8cab425` |
| Phase 13 core | `user/gudge/version_specific_config_parsers_phase13_wslc_graduation` | #1188 | `54496529` |
| Phase 13 follow-ups | `user/gudge/version_specific_config_parsers_phase13_wslc_graduation_followups` | #1189 | `1d76e9ce` |

Use a clean independent worktree, preferably
`D:\git\microsoft\mxc\mxc.cyan`, and attach the named WSLC branch there. Do not
modify or push the non-WSLC branches.

## Current Phase 12 state

#1187 is one commit on `d20511e7`. Current `origin/main` is `4bb804c0`, which
adds #1211's LXC inbound-deny tests and documentation. GitHub reports #1187 as
`DIRTY`, so it must be rebased before the alternative stack is merge-ready.

The current head includes fixes for:

- Windows all-feature clippy failures in the IsolationSession SDK tests;
- Hyperlight and MicroVM callers that still declared v0.9;
- permanent top-level `wslc.provision` in inline lifecycle requests;
- retaining all WSLC one-shot and lifecycle runtime fixtures on published
  v0.9;
- directional networking in the C# WSLC example;
- removal of stale documentation that still called graduated WSLC
  experimental.

Two current Copilot comments remain on #1187:

- `docs/linux-wsl-roadmap-june-2026.md` incorrectly says Bubblewrap remains
  experimental;
- `sdk/node/tests/unit/wire-conformance.test.ts` allows `wslc` as a permanent
  public-only root key but documents only `appContainer`.

#1188 is not currently a clean one-commit child of #1187. Its configured PR
base is `d8cab425`, but head `54496529` has parent `ef52be43`, an older WSLC
publication commit. Git therefore sees two commits over the configured base.
#1189 remains one commit on current #1188 and must be replayed after #1188 is
rebuilt.

## Required sequence

1. Fetch `origin`, record all three remote tips for force-with-lease, and
   confirm `mxc.cyan` is clean on the #1187 branch.
2. Rebase #1187 onto `origin/main` `4bb804c0`, resolving the #1211 overlap by
   retaining the new LXC fixture for exact-schema validation while preserving
   deletion of obsolete rolling-corpus accounting.
3. Port the applicable Phase 12 fixes:
   - emit `0.10.0-alpha` from the playground raw builder used only by Windows
     Sandbox, MicroVM, and Hyperlight, and update its diagnostics and comments
     from v0.9 to v0.10;
   - remove the stale Bubblewrap experimental claim;
   - document both `appContainer` and `wslc` in the root-key conformance
     exception.
4. Validate #1187, amend its single commit, push with explicit
   `--force-with-lease`, resolve its review threads, and wait for required CI.
5. Rebuild #1188 by replaying only its Phase 13 commit onto rewritten #1187:

   ```powershell
   git rebase --onto `
     origin/user/gudge/version_specific_config_parsers_phase12_wslc_graduation `
     ef52be43685d417c20b15a29d213ca79db43f105 `
     user/gudge/version_specific_config_parsers_phase13_wslc_graduation
   ```

   Port the finalized Phase 13 corrections:
   - clear only `source_contract` for direct typed SDK requests and retain the
     exact adapter's v0.6/v0.7 `LegacyCompatible` selection;
   - exclude source attribution from policy hashes while including normalized
     network-enforcement compatibility;
   - document compatibility as version-dependent for both JSON and typed SDK
     inputs.
6. Rebuild #1189 on rewritten #1188:

   ```powershell
   git rebase --onto `
     user/gudge/version_specific_config_parsers_phase13_wslc_graduation `
     544965294edb33f7c138bc90b6b478169f4cec15 `
     user/gudge/version_specific_config_parsers_phase13_wslc_graduation_followups
   ```

   Port the finalized follow-up corrections:
   - run the specialized malformed-exec diagnostic check only when the
     registry exposes `ExecRequest`;
   - return a controlled error rather than panicking if registry metadata marks
     a legacy version renderable;
   - give non-renderable v0.6-v0.8 contracts no generated request roots;
   - retain parser-backed backend-name validation and the simplified probe
     checks.
7. Verify each rewritten endpoint. In addition to the standard Rust, Node,
   .NET, exact-codegen, and config-validation ladder, run:
   - WSLC-feature checks and clippy for `wxc`, `mxc_engine`, `mxc-sdk`, and
     `mxc_ffi`;
   - WSLC-feature unit tests for the engine, Rust SDK, and FFI;
   - exact v0.9 WSLC fixture validation and representative state-aware dry
     runs.
8. Confirm each PR remains exactly one commit above its base, contains the
   required trailers, and passes the base-sensitive contract-history gate.
9. Push #1188 and #1189 with explicit `--force-with-lease`.
10. Verify:

   ```text
   #1187: main <- phase12_wslc_graduation
   #1188: phase12_wslc_graduation <- phase13_wslc_graduation
   #1189: phase13_wslc_graduation <- phase13_wslc_graduation_followups
   ```

## Guardrails

- Do not modify the non-WSLC branches or PRs.
- Keep WSLC in published v0.9; do not copy the non-WSLC stack's v0.10 WSLC
  defaults into this stack.
- Keep the Node WSLC binding fixtures and Rust SDK WSLC example on v0.9 without
  runtime experimental authorization.
- Retain `WslcProvisionRequest` in the published v0.9 request-root metadata and
  do not describe WSLC normalization or runtime support as experimental.
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
