# Version-aware SDK stack session handoff

Date: September 30, 2026

This document records the state of the v1 SDK and JSON-only FFI ingress
pull-request stack, the decisions behind it, and the remaining work, for a
new Copilot session. It supersedes
[`version-aware-stack-session-handoff-2026-09-26.md`](version-aware-stack-session-handoff-2026-09-26.md).

The canonical design is [`ffi-json-ingress-plan.md`](ffi-json-ingress-plan.md).
[`version-aware-stack-plan.md`](version-aware-stack-plan.md) describes the
earlier phases; its typed-FFI follow-up (§9.3, §9.5, Phase 14 exit criterion
16) is superseded by the JSON-only ingress plan.

## 1. Pull requests

`main` was `80f2d0553` when this document was written. #1270 has merged.

| PR | Title | Branch | Base | Tip | State |
| --- | --- | --- | --- | --- | --- |
| #1271 | Make the v1 SDKs own their contract version | `user/gudge/rust-sdk-phase14c` | `main` | `618262c8a` | Open, review required |
| #1348 | Reject a blank ProcessContainer proxy peer | `user/gudge/reject-blank-proxy-peer` | `main` | `422f64d02` | Open, review required |
| #1349 (A) | Make exact versioned JSON the only FFI configuration ingress | `user/gudge/rust_ffi_json_ingress` | #1271 | `c3bb09eca` | Draft |
| #1350 (B) | Switch Node to exact JSON FFI ingress | `user/gudge/node-json-ffi` | A | `5f974f72a` | Draft |
| #1351 (C) | Switch .NET to exact JSON FFI ingress | `user/gudge/dotnet-json-ffi` | A | `8d1b83565` | Draft |
| #1352 (D) | Remove the binding request FFI exports | `user/gudge/remove-binding-json-ffi` | A | `83eb247d4` | Draft; contains the B and C commits |
| #1353 (E0) | Move the SDK authoring types into mxc-sdk | `user/gudge/move-sdk-policy-types` | D | `c0f2a80e0` | Draft |

#1301, #1302, and #1303, the superseded typed-FFI pull requests, are closed.

Commit shape:

- #1271 has two commits: `6a7d0d4f3` (v1 SDKs own their contract version) and
  `618262c8a` (contract-mapped types move into V1 namespaces). It is rebased
  onto `main` `a4f74b9b5`.
- A, B, and C are each one commit. D is A, then C, then B, then the removal
  commit; only the last commit is new in #1352. E0 is one commit on D.
- #1352's description says it contains the #1350 and #1351 commits because
  GitHub allows one base branch.

Local backup branches (not pushed):

| Branch | Tip | Contents |
| --- | --- | --- |
| `user/gudge/rust-sdk-phase14c-backup-2026-09-30` | `483e0857f` | #1271 before the two-commit squash and V1 namespaces |
| `user/gudge/rust_ffi_json_ingress-premerge-6commits` | `48e32ec12` | A as six commits, before the squash |
| `user/gudge/dotnet-json-ffi-premerge-5commits` | `eafb96ac3` | C as five commits, before the squash |
| `user/gudge/remove-binding-json-ffi-old` | `05c738ee2` | D before the rebase onto the V1 layout |

Other branches:

- `user/gudge/version_specific_config_parsers_plan` holds the plan documents.
  It is pushed and has no pull request.
- `user/gudge/unify-experimental-backend-gate` is folded into A and redundant.
- `user/gudge/sdk-v1-namespaces` is squashed into #1271 and redundant.
- `user/gudge/rust_policy_types_without_serde` is folded into A and redundant.

## 2. Worktrees

| Worktree | Branch | Notes |
| --- | --- | --- |
| `mxc.root` | `main` | |
| `mxc.backup` | `main` | |
| `mxc.scarlet` | #1271 | |
| `mxc.cyan` | A (#1349) | |
| `mxc.red` | B (#1350) | |
| `mxc.tan` | C (#1351) | |
| `mxc.maroon` | D (#1352) | |
| `mxc.crimson` | E0 (#1353) | |
| `mxc.yellow` | plan branch | |
| `mxc.orange` | `user/gudge/rust_policy_types_without_serde` | Redundant; reusable |
| `mxc.magenta` | `user/gudge/sdk-v1-namespaces` | Redundant; reusable |
| `mxc.blue` | `user/gudge/unify-experimental-backend-gate` | Redundant; untracked `docs/sdk_public_api_surface.md` belongs to the user |
| `mxc.green` | detached | Untracked `review_pr1318.md` belongs to the user |
| `mxc.skyblue` | `user/gudge/rust-sdk-phase14b` | #1270's merged branch; reusable |

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
3. **V1 namespaces.** Contract-mapped SDK types live in
   `Microsoft.Mxc.Sdk.V1`, `mxc_sdk::v1`, and `@microsoft/mxc-sdk/v1`, and
   evolve additively across published 1.x contracts; a future v2 adds V2
   alongside. Errors, discovery, telemetry, process handles, and raw JSON APIs
   stay at the package roots. .NET discovery is `Microsoft.Mxc.Sdk.MxcPlatform`
   (`NativeVersion`, `GetAvailableBackends`, `GetPlatformSupport`). .NET
   source and tests mirror the namespace in `V1\` folders.
4. **Pinned SDK target.** .NET `SchemaVersions.SdkContract` is the literal
   `"1.0.0"` from `sdkMajorTargets["1"]`, not an alias of `LatestStable`.
   Node and Rust already pin 1.0.0.
5. **Node packaging.** The SDK is ESM-only. Its `.` and `./v1` exports carry
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

#1271:

- All Copilot threads are answered and resolved, including the latest two
  (`require()` of the ESM package, and pinning `SdkContract`).
- jsidewhite's thread on `V1/MxcLifecycle.cs` ("why is this PR also removing
  WindowsSandbox?") is open. The reply explains decision 9; leave it for the
  reviewer to resolve.
- The title and description describe the V1 namespaces; "version-free" no
  longer appears in the code or documentation.

#1349–#1353 are drafts with no review yet. #1348 awaits review.

## 5. Open items

1. **Blank proxy peer follow-up.** After #1348 merges, rebase the stack onto
   `main`, remove the Rust builder's duplicate `allowedProxyPeer` check
   (`validate_common` in the builder), point its two tests at the shared
   parser error, and add `tests/policy/sdk-v1/invalid/blank-proxy-peer.json`.
   #1348's head is now `422f64d02`: a later session reworked its tests to
   cover every registered contract from 0.8 onward, so they survive version
   promotion.
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
- Read and write files with explicit UTF-8 in Python and preserve each file's
  line endings.
- Use `--force-with-lease` against the expected remote tip for every rewrite,
  and ask before pushing to a pull request that is approved.
- After rewriting a lower pull request, restack the ones above it with
  `git rebase --onto <new base> <old base>`, rebuild D from A, C, B, and the
  removal commit, and confirm trees or patch IDs where content should be
  unchanged.
- Validation ladder: `cargo fmt --all -- --check`, workspace `cargo check`
  and `clippy -D warnings` with all features, `cargo test --workspace` after
  rebuilding `wxc-exec`, `cargo doc` for `mxc-sdk` and `mxc_ffi` with
  `RUSTDOCFLAGS=-D warnings`, the `scripts/` gate scripts, Node build, tests,
  and typecheck, `dotnet test --solution Microsoft.Mxc.Sdk.slnx`, and
  `git diff --check`.
