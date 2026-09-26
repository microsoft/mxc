# Version-aware SDK stack session handoff

Date: September 26, 2026

This document records the current state of the version-aware SDK pull-request
stack and the remaining work for a new Copilot session.

The canonical architecture and phase plan remains
[`version-aware-stack-plan.md`](version-aware-stack-plan.md). That plan now
includes a follow-up PR to give `mxc_ffi` typed and raw exact-JSON entry points
for both one-shot and state-aware operations.

## 1. Current pull-request stack

| PR | Branch | Base | Remote tip | Local tip | State |
| --- | --- | --- | --- | --- | --- |
| #1254 | `user/gudge/rust-sdk-direct-transport` | `main` | `ec46a4155` | `ec46a4155` | Merged |
| #1255 | `user/gudge/rust-sdk-operation-api` | `main` | `357ceea03` | `357ceea03` | Open; GitHub-rebased after #1254 merged |
| #1256 | `user/gudge/rust-sdk-operation-cli` | #1255 | `1e3a8b1bf` | `1e3a8b1bf` | Open; published and mergeable |
| #1269 | `user/gudge/rust-sdk-phase14a` | #1256 | `96b949518` | `00c26cb89` | Open; local restack not pushed |
| #1270 | `user/gudge/rust-sdk-phase14b` | #1269 | `032b73d74` | `ec49eb728` | Open; local restack not pushed |
| #1271 | `user/gudge/rust-sdk-phase14c` | #1270 | `0bd3ff636` | `f62146960` | Open; local restack not pushed |

The local parent chain is exact:

```text
main 8d6f41818
  -> #1255 357ceea03
  -> #1256 1e3a8b1bf
  -> #1269 00c26cb89
  -> #1270 ec49eb728
  -> #1271 f62146960
```

Do not reconstruct this chain from the remote #1269-#1271 tips; those remote
branches still contain the pre-restack history.

## 2. Worktree assignments

| Worktree | Current state |
| --- | --- |
| `mxc.root` | `main` |
| `mxc.cyan` | `user/gudge/rust-sdk-operation-cli` (#1256) |
| `mxc.green` | `user/gudge/rust-sdk-phase14a` (#1269) |
| `mxc.blue` | `user/gudge/rust-sdk-phase14b` (#1270) |
| `mxc.maroon` | `user/gudge/rust-sdk-phase14c` (#1271) |
| `mxc.yellow` | `user/gudge/version_specific_config_parsers_plan` |

All listed worktrees were clean at handoff creation.

## 3. Work completed in this session

### #1254

- Merged into `main`.
- Verified the recent human review replies:
  - current typed state-aware backends are Windows-hosted;
  - Node and .NET later gain analogous lifecycle APIs, but transport differs:
    `mxc_ffi` retains JSON/co-versioned entry points, Node remains
    executor-backed, and .NET uses the FFI lifecycle path.

### #1255

- GitHub rebased the branch after #1254 merged.
- Local branch was reset to the remote tip `357ceea03`.

### #1256

- Rebased onto current #1255.
- Resolved the shared E2E-helper conflict while preserving the newer
  cross-platform helper infrastructure.
- Migrated the IsolationSession, WSLC, WSLC streaming, and Windows Sandbox
  direct-executor helpers to:
  - remove `phase` and `sandboxId` from encoded JSON;
  - pass `--operation` and, for non-provision phases, `--sandbox-id`;
  - place routing/config arguments before a trailing workload separator.
- Amended and force-pushed `1e3a8b1bf`.
- Replied to and resolved review comment `4112971085`.

### #1269-#1271 local restack

- #1269 rebased cleanly onto #1256: `00c26cb89`.
- #1270 rebased onto #1269: `ec49eb728`.
  - Resolved the Windows Sandbox PowerShell conflict by retaining #1256 CLI
    routing and applying the #1270 `1.1.0-alpha` default.
- #1271 rebased onto #1270: `f62146960`.
  - Resolved policy, SDK, Node, and .NET conflicts against the newer base.
  - Removed two stale high-level version selectors found by Node integration
    type-checking.
- None of these three rewritten tips has been pushed.

## 4. Validation already completed

### #1256

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets --all-features`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test -p wxc -p wxc_common -p wxc_e2e_tests`
- Rebuilt `wxc-exec` and reran the state-aware E2E tests: 3 passed.
- PowerShell syntax checks for all three changed lifecycle scripts.
- Helper-level checks confirmed routing fields are removed from JSON without
  mutating the caller's request.

### #1269

- Versioning tests: 67 passed.
- Schema-version synchronization passed.
- The Linux Node failure was an unrelated flaky test. Its rerun completed
  successfully on attempt 2.

### #1270

- Full `mxc_config_contract` tests passed.
- Node unit tests passed: 359 tests.
- Contract codegen passed for three exact artifact sets.
- Config validation passed for 394 configs against six schemas.
- PowerShell syntax and `git diff --check` passed.

### #1271

- Rust format and targeted checks/tests for `mxc_engine`, `mxc-sdk`, and
  `mxc_ffi` passed.
- Node build and unit tests passed: 359 passed, 20 skipped.
- Node integration TypeScript compilation passed.
- .NET tests passed: 241 passed, 27 host-dependent skips.
- Versioning tests passed: 67.
- Schema/codegen/config, C# API and error-code parity, telemetry parity,
  Linux-timeout parity, PSEC codegen, build-script scanning, and C# bindings
  codegen passed.
- The optional Node integration runtime suite was not run because the maroon
  worktree lacks packaged `mxc_ffi.dll`, `wxc-exec.exe`, and
  `wxc-test-proxy.exe`.

## 5. Immediate publication work

Push the already validated local branches in order:

1. #1269: force-push `00c26cb89` over remote `96b949518`.
2. #1270: force-push `ec49eb728` over remote `032b73d74`.
3. Do not push #1271 until its open review comments are fixed.

Use explicit leases:

```text
--force-with-lease=refs/heads/<branch>:<recorded-remote-sha>
```

Never use bare `--force`.

## 6. Remaining #1271 review work

GitHub currently has 12 unresolved review threads on remote head `0bd3ff636`.
Several overlap and should be addressed as grouped changes on local
`f62146960`.

### 6.1 Rust fail-closed behavior

Comments:

- `4112698874`: production `SandboxPolicy` silently ignores removed `version`.
- `4112977220`: typed non-provision operations can still accept `wsb:` IDs.

Plan:

- Add `deny_unknown_fields` to production `SandboxPolicy`.
- Remove the test-only `version` field and migrate historical-version tests to
  raw exact-contract inputs.
- Add a regression proving old JSON containing `version` is rejected.
- Reject Windows Sandbox IDs at the typed SDK boundary before normalization for
  start, exec, stop, and deprovision.
- Preserve Windows Sandbox lifecycle only through raw exact `1.1.0-alpha`.

### 6.2 .NET fail-closed JSON migration

Comments:

- `4112977236`: `SandboxPolicy` ignores removed JSON members.
- `4112977250`: state-aware DTOs ignore removed legacy network members.

Plan:

- Apply unmapped-member rejection to high-level policy and state-aware DTOs.
- Add tests for old `version`, legacy one-shot networking, and legacy
  state-aware network properties.
- Confirm `JsonSerializer.Deserialize` raises `JsonException` instead of
  creating an empty/default v1 policy.

### 6.3 Duplicate Node coverage

Comments:

- `4112836582`: `v1-inprocess-run.test.ts` duplicates existing tests.
- `4113061605`: `package.json` runs both duplicate suites.

Plan:

- Delete `v1-inprocess-run.test.ts`.
- Remove it from the package test command.
- Retain the broader `inprocess-run.test.ts`, including its unique native-error
  and invocation-failure cases.

### 6.4 Node documentation

Comments:

- `4112836551`: backend selection still advertises high-level `vm`/`microvm`.
- `4112836570`: package example uses `version` and `allowOutbound`.
- `4113061564`: public examples in `index.ts` and `sandbox.ts` use removed
  properties.

Plan:

- Limit high-level examples to the `SandboxContainment` set.
- Move `vm`, `microvm`, and other development-only containments to raw
  `ContainerConfig` guidance.
- Remove `policy.version`.
- Replace legacy networking with directional egress/ingress examples.

### 6.5 .NET documentation

Comments:

- `4112836520`: README claims `SchemaVersions` exposes removed state-aware
  defaults.
- `4112977271`: README still documents `AllowOutbound`, `AllowedHosts`,
  `BlockedHosts`, and proxy members removed from high-level policy.

Plan:

- Document only public `SchemaVersions.Minimum`, `MaximumSupported`, and
  `LatestStable`.
- Remove obsolete high-level legacy-network guidance or clearly identify it as
  raw historical-contract behavior.
- Keep high-level examples directional and version-free.

### 6.6 Additional Rust SDK documentation

Comment:

- `4113061635`: the WSL Rust quick-start still initializes removed
  `SandboxPolicy.version`.

Plan:

- Replace it with `SandboxPolicy::default()` or an equivalent version-free
  initializer.
- Search all Rust SDK examples and doctests for caller-authored policy versions.

## 7. Required #1271 validation

After addressing the review comments:

1. `cargo fmt --all -- --check`
2. `cargo check --workspace --all-targets --all-features`
3. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
4. `cargo test --workspace`
5. Node build and unit tests
6. Node integration TypeScript compilation
7. .NET solution tests
8. Versioning, codegen, config-corpus, API parity, error-code parity, telemetry
   parity, and generated-binding checks
9. macOS-target compilation where locally available; otherwise rely on CI and
   state the limitation
10. `git diff --check`

Keep fixes as separate local commits for review. After approval, squash them
into the single #1271 commit, push with an explicit lease, then reply to and
resolve all 12 threads.

## 8. Flaky tests and tracking issues

| Test | Tracking |
| --- | --- |
| `publishes a worker result only after the anchor closes` | #1234, reopened |
| `lxc_bindings::tests::a_reused_container_does_not_inherit_an_earlier_runs_mounts` | #1292 |
| `reaps the detached anchor after repeated probes` | #1293 |

The #1269 Linux Node rerun for workflow `36275024031` completed successfully on
attempt 2.

## 9. Planned FFI follow-up PR

The planning branch contains commit `895fd58ef`, which adds a follow-up PR for
complete `mxc_ffi` ingress symmetry:

| Execution model | Typed FFI | Raw exact-JSON FFI |
| --- | --- | --- |
| One-shot | Required | Required |
| State-aware | Required | Required |

The typed paths must adapt directly into `CommonRequestIR` and checked
state-aware binding without serializing to JSON. Raw exact JSON remains for
configuration, replay, and compatibility. The PR must preserve ABI ownership,
error mapping, panic containment, streaming/attached semantics, and generated
binding parity.

## 10. Key architecture invariants

- `mxc_engine` remains the single execution engine.
- High-level SDK policy is version-free and targets stable exact `1.0.0`.
- Raw configuration remains explicitly exact-versioned.
- Production parsing dispatches through exact closed contracts into private
  `CommonRequestIR`.
- Typed high-level Rust requests adapt directly to `CommonRequestIR`; they do
  not serialize to JSON.
- Optional-field presence is preserved through parsing and binding.
- Unsupported policy fails closed before sandbox creation.
- Released schemas under `schemas/stable/` remain immutable.
- Development schemas and generated TypeScript wire types are regenerated,
  never hand-edited.
- Windows Sandbox lifecycle remains raw exact `1.1.0-alpha`; typed v1 lifecycle
  supports IsolationSession and WSLC.
- WSLc one-shot and lifecycle working directories are absolute in-container
  POSIX paths.
- History-rewriting pushes always use `--force-with-lease`.

## 11. Recommended next-session sequence

1. Read this handoff and `docs/version-aware-stack-plan.md`.
2. Verify current remote tips before pushing anything.
3. Push local #1269 and #1270 in order with explicit leases.
4. Implement the grouped #1271 review fixes as separate local commits.
5. Run the complete validation ladder and show the #1271 diff.
6. Squash #1271, force-push with lease, and resolve all review threads.
7. Monitor CI, rerunning only verified unrelated flaky failures.
8. Begin the planned symmetric typed/raw `mxc_ffi` follow-up only after the
   current stack is merged or otherwise stable.
