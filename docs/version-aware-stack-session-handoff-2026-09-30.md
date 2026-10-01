# Version-aware SDK stack session handoff

Date: September 30, 2026. Updated: October 1, 2026.

This document records the state of the v1 SDK and JSON-only FFI ingress
pull-request stack, the decisions behind it, and the remaining work, for a
new Copilot session. It supersedes
[`version-aware-stack-session-handoff-2026-09-26.md`](version-aware-stack-session-handoff-2026-09-26.md).

The canonical design is [`ffi-json-ingress-plan.md`](ffi-json-ingress-plan.md).
Its October 1 additions record the accepted public SDK API alignment in
section 7 and release-work ownership/exit criteria in section 8. These are
planned changes, not an assertion that all SDKs already expose the target API.
[`version-aware-stack-plan.md`](version-aware-stack-plan.md) describes the
earlier phases; its typed-FFI follow-up (§9.3, §9.5, Phase 14 exit criterion
16) is superseded by the JSON-only ingress plan.

## 1. Pull requests

October 1 afternoon snapshot: `main` is `46ce71d0d`. #1270, #1348, and #1271
have merged. The tips below are GitHub PR head tips, not merge commits.

| PR | Title | Branch | Base | Tip | State |
| --- | --- | --- | --- | --- | --- |
| #1348 | Reject a blank ProcessContainer proxy peer | `user/gudge/reject-blank-proxy-peer` | `main` | `ca559ebbc` | Merged October 1; merge `74ecd71fc` |
| #1271 | Make the v1 SDKs own their contract version | `user/gudge/rust-sdk-phase14c` | `main` | `73196bae7` | Merged October 1; merge `46ce71d0d` |
| #1355 | Move contract-mapped v1 SDK types into V1 namespaces | `user/gudge/sdk-v1-namespaces` | `main` | `ab229c28d` | Rebased/pushed; CI green; review required |
| #1349 (A) | Make exact versioned JSON the only FFI configuration ingress | `user/gudge/rust_ffi_json_ingress` | #1355 | `347738317` | Review required; conflicts with current #1355 |
| #1350 (B) | Switch Node to exact JSON FFI ingress | `user/gudge/node-json-ffi` | A | `aba5e0dc0` | Review required |
| #1351 (C) | Switch .NET to exact JSON FFI ingress | `user/gudge/dotnet-json-ffi` | B | `885b720dd` | Review required |
| #1352 (D) | Remove the binding request FFI exports | `user/gudge/remove-binding-json-ffi` | C | `1ee00e482` | Review required |
| #1353 (E0) | Move the SDK authoring types into mxc-sdk | `user/gudge/move-sdk-policy-types` | D | `e246be7d7` | Review required |

#1301, #1302, and #1303, the superseded typed-FFI pull requests, are closed.
GitHub stack #1257, which held #1271 and its closed successors, is unstacked.
None of #1349–#1353 is a draft.

Remaining merge order: #1355, A, B, C, D, E0. #1348 landed before #1271,
satisfying the blank `allowedProxyPeer` review dependency.

Commit shape:

- Every pull request in the stack is one commit, and each base is the pull
  request below it, so each diff contains only its own change.
- #1271 carries only the contract-version change and the documentation fixes
  from review. The V1 namespace move was split out into #1355 to stop review
  rounds on #1271 widening its scope.
- B and C are independent in content; they are stacked so D builds on both.
- Commit messages and pull-request descriptions do not mention other pull
  requests in the stack or closed pull requests.

#1271 was rebased and merged; #1355 is now based on that merge. A through E0
still need restacking onto the updated lower stack. Main's #1276 request-probe
APIs add a private .NET probe-ingress path that C, D, and E0 must include in
their migration; see the canonical plan's release item 1.

Local #1355 was rebased from `81ac3c7c9` to `8978cff6c` without conflicts and
with an unchanged patch. Its subsequently published tip is `ab229c28d`, with
the same tree as `8978cff6c`. A's local cyan tip is `64c537ca9`, distinct from
its published `347738317`; inspect local work before restacking or replacing
it.

Local backup branches (not pushed):

| Branch | Tip | Contents |
| --- | --- | --- |
| `user/gudge/rust-sdk-phase14c-backup-2026-09-30` | `483e0857f` | #1271 before the two-commit squash and V1 namespaces |
| `user/gudge/rust-sdk-phase14c-backup-pre-lf` | `618262c8a` | #1271 as two commits, before the LF restore and rebase |
| `user/gudge/rust-sdk-phase14c-backup-pre-split` | `6d3aa0a12` | #1271 as two commits, before the split into #1271 and #1355 |
| `user/gudge/rust_ffi_json_ingress-premerge-6commits` | `48e32ec12` | A as six commits, before the squash |
| `user/gudge/dotnet-json-ffi-premerge-5commits` | `eafb96ac3` | C as five commits, before the squash |
| `user/gudge/remove-binding-json-ffi-old` | `05c738ee2` | D before the rebase onto the V1 layout |

Other branches:

- `user/gudge/version_specific_config_parsers_plan` holds the plan documents.
  It is pushed and has no pull request.
- `user/gudge/remove-schema-0-6-to-0-8` (local only) removes schema 0.6.0,
  0.7.0, and 0.8.0 and raises the floor to 0.9.0-alpha. It is built on an
  old E0 (`c0f2a80e0`); see open item 7.
- `user/gudge/unify-experimental-backend-gate` and
  `user/gudge/rust_policy_types_without_serde` are folded into A and
  redundant.

## 2. Worktrees

| Worktree | Branch | Notes |
| --- | --- | --- |
| `mxc.root` | `main` | Behind `origin/main` |
| `mxc.green` | detached | Reusable; `74ecd71fc` |
| `mxc.scarlet` | detached | Reusable; `46ce71d0d`; merged local #1271 branch deleted |
| `mxc.magenta` | #1355 | |
| `mxc.cyan` | A (#1349) | Local `64c537ca9` differs from remote |
| `mxc.red` | B (#1350) | |
| `mxc.tan` | C (#1351) | |
| `mxc.maroon` | D (#1352) | |
| `mxc.crimson` | E0 (#1353) | |
| `mxc.yellow` | plan branch | |
| `mxc.orange` | `user/gudge/remove-schema-0-6-to-0-8` | |
| `mxc.blue` | detached | Reusable; `74ecd71fc` |
| `mxc.skyblue` | detached | Reusable; `74ecd71fc` |

Confirm `git branch --show-current` before resetting or rewriting a worktree;
a detached worktree once caused a stale branch to be pushed.

## 3. Decisions

1. **Experimental opt-in.** Backends are production or experimental
   (`ContainmentBackend::is_experimental`: MicroVM, Hyperlight, Windows
   Sandbox). The opt-in only permits selecting an experimental backend; it is
   ignored for production backends and is independent of the contract
   version. A missing opt-in is `backend_unavailable` on every one-shot and
   lifecycle entry point, checked before host-specific resolution.
2. **JSON-only FFI ingress.** Configuration crosses `mxc_ffi` only as exact
   versioned JSON (`mxc_run_json`, `mxc_spawn_json`, and the renamed
   `mxc_run_state_aware_json`, `mxc_exec_state_aware_json`,
   `mxc_exec_state_aware_attached_json`). Non-configuration controls are
   typed `i32` arguments, never JSON fields. D removes `mxc_run_request`,
   `mxc_spawn_request`, the private binding-request probe export, and the
   private binding request.
3. **V1 namespaces (#1355).** Contract-mapped SDK types live in
   `Microsoft.Mxc.Sdk.V1`, `mxc_sdk::v1`, and `@microsoft/mxc-sdk/v1`, and
   evolve additively across published 1.x contracts; a future v2 adds V2
   alongside. Errors, discovery, telemetry, process handles, and raw JSON APIs
   stay at the package roots. .NET discovery is `Microsoft.Mxc.Sdk.MxcPlatform`
   (`NativeVersion`, `GetAvailableBackends`, `GetPlatformSupport`). .NET
   source and tests mirror the namespace in `V1\` folders.
4. **Pinned SDK target.** .NET `SchemaVersions.SdkContract` is the literal
   `"1.0.0"` from `sdkMajorTargets["1"]`, not an alias of `LatestStable`.
   Node and Rust already pin 1.0.0.
5. **Node packaging.** The SDK has been ESM-only, with import-only exports,
   since its public release. In #1355 its `.` and `./v1` exports carry
   `types`, `import`, and `default` conditions so CommonJS `require()` works on
   Node 24, and `typesVersions` maps `v1` for `node10` module resolution.
6. **Shared goldens.** `tests/policy/sdk-v1/{input,expected,invalid}` is the
   cross-language contract: each SDK maps every input and must emit the
   expected exact 1.0.0 document. The README there lists the mapping rules
   (for example, `containerId` is always present and minted when unnamed).
7. **Builder normalization.** The Rust builder no longer writes host-specific
   sections for abstract `process` containment or adds network capabilities;
   the engine and ProcessContainer backend own both.
8. **Plain SDK types.** The Rust SDK policy types have no serde derives. E0
   moves the policy, containment, request, builder, and typed lifecycle types
   from `mxc_engine` into `mxc-sdk` (exposed only under `mxc_sdk::v1`); the
   engine exposes `spawn_execution_request(&ExecutionRequest)`. `mxc-sdk` now
   depends directly on `mxc_config_contract`.
9. **Stable lifecycle and Windows Sandbox.** The typed V1 lifecycle APIs
   support IsolationSession and WSLC and reject `wsb:` ids with
   `unsupported_containment` in every SDK. Windows Sandbox remains reachable
   through raw `1.1.0-alpha` JSON with the experimental opt-in; typed access
   returns in the experimental surfaces planned as PRs E and F.
10. **Public SDK alignment.** Use Container terminology across Rust, .NET,
    and Node, distinguish persistent `ContainerId` from live `MxcProcess` and
    `MxcPty`, and expose run/spawn/spawn-with-PTY for both one-shot and
    existing-container exec. Prefer `spawnInContainerWithPty`. The canonical
    plan section 7 records type names, asynchronous conventions, byte-output
    direction, PTY versus attached execution, ownership, and pending details.
11. **Public raw counterparts.** Every SDK needs the same capture/pipe/PTY
    family for complete caller-authored exact JSON, plus raw lifecycle phases.
    Keep these at package roots and do not route development documents through
    the stable mapper. Experimental authorization remains independent of
    contract version. Native JSON exports do not alone satisfy SDK access.
12. **PR scope.** #1355 owns namespace spelling/export boundaries, including
    `v1::container` if retaining the lifecycle module. Bulk API/type renames
    use a focused alignment follow-up after E0 where practical. The co-worker's
    Rust `MxcPty` and missing execution/output capabilities need coordinated
    functional follow-ups. E/F are not prerequisites for raw development use.

## 4. Review status

At the October 1 afternoon check, the latest head runs are green on #1355 and
A through E0; the merged #1348/#1271 heads also passed. A's conflict and the
older upper-stack runs mean this is not validation of a restacked composition.

The thread counts below are the earlier October 1 pre-restack snapshot; they
have not been re-counted for this planning update.

| PR | Threads | Unresolved |
| --- | --- | --- |
| #1348 | 5 | 0; approved by jsidewhite |
| #1271 | 50 | 0 |
| #1355 | 0 | 0 |
| #1349 (A) | 4 | 4 Copilot |
| #1350 (B) | 7 | 6 Copilot, 1 bbonaby (`bindings/one-shot.ts`) |
| #1351 (C) | 6 | 6 Copilot |
| #1352 (D) | 3 | 3 Copilot |
| #1353 (E0) | 5 | 4 Copilot |

The earlier unresolved threads on A through E0 have been analyzed for
release-work ownership in canonical plan section 8. That allocation does not
mean fixes or GitHub review replies have been completed.

#1271 history:

- Review rounds kept widening its scope, so it was split: the V1 namespace
  move became #1355, and #1271 kept the contract-version change plus the
  documentation fixes (version-free wording removed, the LXC guide uses
  `createConfigFromPolicy(policy, 'lxc')` and root `spawnSandboxFromConfig`,
  the Seatbelt paragraph corrected, and an `SdkContract` bullet added).
- Deferred threads, answered and resolved: migrating the playground renderer
  (no issue opened), a Rust V1 target constant (deferred to the 1.1
  promotion), and the Node blank `allowedProxyPeer` (handled by #1348).

CI fixes pushed on October 1:

- E0 had gated `EngineProvisionMetadata` with `cfg(target_os = "windows")`
  although the engine re-exports and uses it on every platform, which broke
  the Linux, macOS, and lint jobs. The enum is now ungated; only its Windows
  constructors stay gated.
- C's new C# path rule requires `csharpPath: null` for non-renderable
  contracts, but the versioning script tests' `contract()` helper left it
  `undefined`. The helper now defaults it to `null`, and a new test covers both
  C# rules.

## 5. Open items

1. **Blank proxy peer follow-up.** #1348 has merged. Restack the remaining
   work, remove the Rust builder's duplicate `allowedProxyPeer` check
   (`validate_common` in the builder), point its two tests at the shared
   parser error, and add `tests/policy/sdk-v1/invalid/blank-proxy-peer.json`.
   Put the builder/fixture correction in A and carry it into E0's move.
2. **Misplaced `mxc-sdk` tests.** Tests in `mxc-sdk` that parse 0.7.0-alpha or
   development-contract documents (`policy.rs` and
   `configs/process_container.rs`) test `wxc_common`'s parser and should move
   there, leaving `mxc-sdk` to use only `published::v1_0_0`.
3. **SDK coupling to internals.** `mxc-sdk` depends on `wxc_common` runtime
   types (`ExecutionRequest`, `SdkStateAwareInput`, `SandboxProcess`) and
   publicly re-exports output metadata types. A narrower engine-facing API
   would fix this; it is out of scope for this stack.
4. **Experimental SDK APIs.** PRs E (Node) and F (.NET) are not started. Their
   surfaces are `@microsoft/mxc-sdk/v1/experimental` and
   `Microsoft.Mxc.Sdk.V1.Experimental`.
5. **Playground.** `tests/playground` loads the SDK with `require()`. Its real
   build was not verified because `npm ci` there fails: the internal feed
   lacks `undici@6.29.0` (bumped by #1345). A scratch CommonJS project with
   `node10` resolution and a `require()` smoke test cover the changes. The
   playground is not built in CI.
6. **#1337 (crates.io release pipeline, not merged).** It overlaps this stack
   in `README.md`, `src/Cargo.lock`, `src/core/mxc-sdk/Cargo.toml`, and
   `src/core/mxc_engine/Cargo.toml`. It renames packages to `mxc-*` while
   keeping library names, so code does not change. Whichever lands second
   resolves those files (regenerate `Cargo.lock`). Whether to publish to
   crates.io is undecided.
7. **Schema 0.6–0.8 removal.** `user/gudge/remove-schema-0-6-to-0-8` needs
   rebasing onto the current E0, dropping its line-ending commit `2bd1c86f4`
   (made redundant by #1334), before deciding whether to open a pull request.
8. **Inherited platform lint failures.** `src/core/mxc-sdk/tests/sandbox.rs`
   imports `build_request` and `SandboxPolicy` unconditionally, but only the
   macOS and Windows tests use them; Linux all-target checks with warnings
   denied fail. macOS SDK all-target clippy also finds `let_and_return` in
   `tests/streaming.rs`. Both are present on merged main and the tree published
   as #1355. Resolve in a scoped cleanup rather than rewriting merged #1271.
   Windows affected-crate checks/lint, Node build/unit/typecheck, focused .NET
   contracts, parity/codegen, Rust docs, and prescribed macOS backend clippy
   passed during the local namespace rebase; this does not erase the two
   broader cross-check failures or cover real-host backend suites.
9. **Restack onto the published namespace tip.** #1271 has merged and #1355's
   rebase is published. Restack A through E0 after inspecting existing local
   work and include the request-probe migration. Revalidate rewritten tips
   before pushing; do not reuse old upper-stack CI as proof of the composition.
10. **Review threads.** Triage the unresolved threads on A–E0 (§4).
11. **Mechanical documentation checks.** Discussed but not designed: extract
    TypeScript, Rust, and C# snippets from the documentation and READMEs and
    type-check them, so stale examples like those found on #1271 fail CI.
12. **Release closeout items 1-6.** The numbered review work and PR allocation
    are in canonical plan section 8, with lower-case substep labels. These
    numbers are independent of this older handoff's open-item numbering.
13. **API alignment and PTY work.** Implement canonical plan section 7's
    cross-language names, six typed and six raw execution operations per SDK,
    raw lifecycle phases, and consistent output/ownership contracts. Coordinate
    the Rust `MxcPty` work; settle the listed facade, cancellation, byte-output,
    and capability details before API freeze. Namespace/ingress merges alone
    do not complete this additional stable v1 work.

## 6. Working notes

- Prefix any command that shells out to `gh` with `gh auth status | Out-Null;`
  in the same PowerShell invocation.
- The user denies UAC prompts. Never trigger elevation, and do not run
  `npm run test:integration` or `tests\scripts\*.ps1` backend suites.
- Before `npm run typecheck` in `sdk/node`, delete
  `sdk/node/tests/integration/node_modules/@microsoft/mxc-sdk` and run
  `npm install` there; the integration project keeps a stale copy of the SDK
  otherwise.
- Run `npm ci` in `scripts/versioning` if a gate script cannot find `ajv`.
- Local validation runs on Windows, so also run the cross-platform checks
  that CI runs on Linux and macOS, plus `npm test` in `scripts/versioning`:
  `cargo check --target x86_64-unknown-linux-gnu -p mxc_engine -p mxc-sdk
  -p mxc_ffi -p wxc_common --all-targets` with `RUSTFLAGS=-D warnings`, and
  `cargo clippy --target x86_64-apple-darwin -p mxc_darwin -p seatbelt_common
  --all-targets -- -D warnings`. LXC clippy for Linux cannot run on Windows
  because the `ring` build script needs a Linux C cross-compiler.
- To change commit messages without changing trees, rebuild the chain with
  `git commit-tree` and update each worktree branch with `git reset --keep`.
- Edit pull-request descriptions through `gh pr view --json body` and
  `gh pr edit --body-file`; PowerShell splits `-q .body` output into lines.
- Read and write files with explicit UTF-8 in Python and preserve each file's
  line endings.
- Use `--force-with-lease` against the expected remote tip for every rewrite,
  and ask before pushing to a pull request that is approved.
- After rewriting a lower pull request, restack the ones above it with
  `git rebase --onto <new base> <old base>` in order up the straight stack,
  and confirm trees or patch IDs where content should be unchanged.
- Validation ladder: `cargo fmt --all -- --check`, workspace `cargo check`
  and `clippy -D warnings` with all features, `cargo test --workspace` after
  rebuilding `wxc-exec`, `cargo doc` for `mxc-sdk` and `mxc_ffi` with
  `RUSTDOCFLAGS=-D warnings`, the `scripts/` gate scripts, Node build, tests,
  and typecheck, `dotnet test --solution Microsoft.Mxc.Sdk.slnx`, and
  `git diff --check`.
