# Version-aware SDK stack session handoff

Date: September 30, 2026. Updated: October 1, 2026.

This document records the state of the v1 SDK and JSON-only FFI ingress
pull-request stack, the decisions behind it, and the remaining work, for a
new Copilot session. It supersedes
[`version-aware-stack-session-handoff-2026-09-26.md`](version-aware-stack-session-handoff-2026-09-26.md).

The canonical design is [`ffi-json-ingress-plan.md`](ffi-json-ingress-plan.md).
[`version-aware-stack-plan.md`](version-aware-stack-plan.md) describes the
earlier phases; its typed-FFI follow-up (§9.3, §9.5, Phase 14 exit criterion
16) is superseded by the JSON-only ingress plan.

## 1. Pull requests

`main` was `0dd2ed756` when this document was updated. #1270 has merged.

| PR | Title | Branch | Base | Tip | State |
| --- | --- | --- | --- | --- | --- |
| #1348 | Reject a blank ProcessContainer proxy peer | `user/gudge/reject-blank-proxy-peer` | `main` | `76eb8cc02` | Approved; conflicts with `main` |
| #1271 | Make the v1 SDKs own their contract version | `user/gudge/rust-sdk-phase14c` | `main` | `439419111` | Review required; conflicts with `main` |
| #1355 | Move contract-mapped v1 SDK types into V1 namespaces | `user/gudge/sdk-v1-namespaces` | #1271 | `463a33cee` | Review required |
| #1349 (A) | Make exact versioned JSON the only FFI configuration ingress | `user/gudge/rust_ffi_json_ingress` | #1355 | `347738317` | Review required |
| #1350 (B) | Switch Node to exact JSON FFI ingress | `user/gudge/node-json-ffi` | A | `aba5e0dc0` | Review required |
| #1351 (C) | Switch .NET to exact JSON FFI ingress | `user/gudge/dotnet-json-ffi` | B | `885b720dd` | Review required |
| #1352 (D) | Remove the binding request FFI exports | `user/gudge/remove-binding-json-ffi` | C | `1ee00e482` | Review required |
| #1353 (E0) | Move the SDK authoring types into mxc-sdk | `user/gudge/move-sdk-policy-types` | D | `e246be7d7` | Review required |

#1301, #1302, and #1303, the superseded typed-FFI pull requests, are closed.
GitHub stack #1257, which held #1271 and its closed successors, is unstacked.
None of #1349–#1353 is a draft.

Merge order: #1348, #1271, #1355, A, B, C, D, E0. #1348 should land before
#1271 because #1271's reply on the Node blank `allowedProxyPeer` thread relies
on it.

Commit shape:

- Every pull request in the stack is one commit, and each base is the pull
  request below it, so each diff contains only its own change.
- #1271 carries only the contract-version change and the documentation fixes
  from review. The V1 namespace move was split out into #1355 to stop review
  rounds on #1271 widening its scope.
- B and C are independent in content; they are stacked so D builds on both.
- Commit messages and pull-request descriptions do not mention other pull
  requests in the stack or closed pull requests.

`main` has moved since the stack was rebased (`8505c7900`). #1271 conflicts in
`sdk/dotnet/Microsoft.Mxc.Sdk/MxcSandbox.cs`,
`sdk/dotnet/Microsoft.Mxc.Sdk.Tests/MxcSandboxTests.cs`, and
`sdk/node/package.json`, mostly from #1276 (Node and .NET request probe APIs).
#1348 conflicts in `docs/schema.md`.

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
| `mxc.green` | #1348 | |
| `mxc.scarlet` | #1271 | |
| `mxc.magenta` | #1355 | |
| `mxc.cyan` | A (#1349) | |
| `mxc.red` | B (#1350) | |
| `mxc.tan` | C (#1351) | |
| `mxc.maroon` | D (#1352) | |
| `mxc.crimson` | E0 (#1353) | |
| `mxc.yellow` | plan branch | |
| `mxc.orange` | `user/gudge/remove-schema-0-6-to-0-8` | |
| `mxc.blue` | detached | Reusable |
| `mxc.skyblue` | detached | Reusable |

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
   `mxc_spawn_request`, and the private binding request.
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

## 4. Review status

CI is green on every pull request in the stack and on #1348.

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

The unresolved threads on A–E0 are new since the previous update and have not
been triaged.

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

1. **Blank proxy peer follow-up.** After #1348 merges, rebase the stack onto
   `main`, remove the Rust builder's duplicate `allowedProxyPeer` check
   (`validate_common` in the builder), point its two tests at the shared
   parser error, and add `tests/policy/sdk-v1/invalid/blank-proxy-peer.json`.
   #1348 (`76eb8cc02`) is approved and needs a rebase to resolve a
   `docs/schema.md` conflict before it can merge.
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
8. **Linux unused import in #1271.** `src/core/mxc-sdk/tests/sandbox.rs`
   imports `build_request` and `SandboxPolicy` unconditionally, but only the
   macOS and Windows tests use them, so the file warns on Linux. CI does not
   compile it on Linux with warnings denied. Fixing it means gating the import
   with `cfg(any(target_os = "macos", target_os = "windows"))` in #1271 and
   restacking every pull request above it; awaiting a decision.
9. **Rebase onto `main`.** #1271 conflicts with `main` (see §1). Rebase it
   with `-X renormalize` if older commits predate #1334's LF normalization,
   then restack #1355 and A–E0.
10. **Review threads.** Triage the unresolved threads on A–E0 (§4).
11. **Mechanical documentation checks.** Discussed but not designed: extract
    TypeScript, Rust, and C# snippets from the documentation and READMEs and
    type-check them, so stale examples like those found on #1271 fail CI.

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
