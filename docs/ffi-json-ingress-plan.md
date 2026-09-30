# FFI JSON-Only Ingress Plan

Status: adopted and implemented as draft pull requests #1349–#1353, stacked
on #1271. It replaces the typed-structure ingress in #1301, #1302, and #1303,
which are closed. §9.3, §9.5, and Phase 14 exit criterion 16 of
[`version-aware-stack-plan.md`](version-aware-stack-plan.md) are superseded by
this plan. The current state of each pull request is recorded in
[`version-aware-stack-session-handoff-2026-09-30.md`](version-aware-stack-session-handoff-2026-09-30.md).

Updated: September 30, 2026.

## 1. Decision

`mxc_ffi` accepts sandbox policy and configuration only as exact-versioned
JSON. Invocation controls that are not configuration, such as experimental
authorization, dry-run, and attached execution, remain typed C parameters.

SDKs continue to offer both typed high-level APIs and raw JSON APIs. Typed SDK
calls normalize to exact-versioned JSON before calling the FFI.

The in-process Rust SDK is unaffected: its typed APIs continue to adapt
directly into `CommonRequestIR` without JSON.

The FFI does not accept the private co-versioned binding JSON used by
`mxc_run_request` and `mxc_spawn_request`. Every JSON document crossing the FFI
is a published or development exact contract that the executor also accepts.

## 2. Rationale

- **One ingress contract.** The typed ABI, raw exact JSON, and private binding
  JSON collapse into one versioned, schema-validated contract.
- **Existing validation.** Exact contract parsing already rejects unknown
  fields, out-of-range integers, and version-inappropriate fields with
  path-aware diagnostics.
- **Fewer defects at the language boundary.** Review of the typed approach
  found silent integer wrapping in Node (#1302), an environment-flag
  regression in .NET (#1303), ignored backend sections for unselected
  containment, and unchecked native allocation arithmetic.
- **Cheaper evolution.** A new v1.x field requires a contract and schema
  change, not an ABI revision, struct extension, binding regeneration, and
  per-SDK marshaller updates.
- **Replayable requests.** Every SDK-originated request is a valid exact
  configuration that can be logged, hashed, stored, or replayed through
  `wxc-exec`.
- **Less unsafe code.** Approximately 1,000 lines of Rust pointer and length
  validation, and a comparable Koffi layout module, are removed.

Reviewer feedback on #1301 and #1303 recommended this direction.

## 3. Version selection

The SDK selects the exact contract version. Callers and the FFI do not.

### 3.1 Source of truth

`schemas/schema-version.json` defines `sdkMajorTargets`, which maps each SDK
major version to its latest published stable exact contract. SDK constants,
such as .NET `SchemaVersions.SdkContract` and Node `SDK_CONTRACT_VERSION`, are
checked against it by the schema-version synchronization gate.

The SDK and its native library ship in the same package. The SDK's target
contract is therefore always registered in the native library it loads, and
no runtime negotiation is required.

### 3.2 Mapping

```text
SDK high-level types
  -> SDK mapper typed against the target contract's generated wire types
  -> exact JSON with version = SDK target constant
  -> mxc_*_json(json, experimental = 0, ...)
  -> exact version dispatch -> contract adapter -> CommonRequestIR
```

Mappers are written against generated wire types for the exact target
contract. Wire types mirror one exact contract's JSON document one-to-one:
member names, optionality, enum strings, and request roots. They are
internal and distinct from the ergonomic, version-free public SDK types.

Both SDKs use one generation pipeline: the Rust contract types produce the
exact JSON Schema, and `mxc_schema_support` emits language-specific wire types
from that schema through `mxc_schema_gen`. Node already emits TypeScript under
`sdk/node/src/generated/`. PR C adds a C# emitter for .NET. Generated files are
committed and checked for drift by `check-contract-codegen`.

When `sdkMajorTargets` advances to the next minor contract, retargeting the
mapper to that contract's generated types exposes any omissions at compile
time. The v1.x compatibility gates guarantee that existing fields retain
their meaning.

### 3.3 Surfaces

The version is determined by the API the caller uses, never inferred from the
fields present in a request.

| Surface | Types | `version` | FFI `experimental` |
| --- | --- | --- | --- |
| Stable high-level API | Stable types only | SDK target, e.g. `1.0.0` | `0` |
| Experimental high-level API (PRs E and F) | Development-only types | Co-shipped development contract, e.g. `1.1.0-alpha` | `1` |
| Raw JSON API | Caller-authored JSON | Caller-authored, passed through unchanged | Caller option |

Rules:

- Backends are either production or experimental. `experimental = 1` means
  selecting an experimental backend, such as Windows Sandbox, MicroVM, or
  Hyperlight, is acceptable. Native rejects an experimental backend without
  it and ignores it for production backends.
- The opt-in is independent of the contract version. Development-contract
  fields for production backends do not require it, and published contracts
  accept it.
- Experimental authorization is never read from JSON.
- A sandbox identity is operated on only through the surface that created it.
  The stable API rejects development-only prefixes such as `wsb:`.
- Development types carry no compatibility promise. They are regenerated from
  each release's development contract.
- A new SDK major version targets the new major contract through the same
  table.

Until the experimental high-level APIs in PRs E and F land,
development-only features, including the Windows Sandbox lifecycle, are
available only through raw JSON APIs.

## 4. Pull-request stack

The stack is built on #1271, which also places the contract-mapped SDK types
in per-major V1 namespaces (§6, decision 4). #1301, #1302, and #1303 are closed.

| PR | Branch | Base | Replaces |
| --- | --- | --- | --- |
| A — FFI JSON ingress (#1349) | `user/gudge/rust_ffi_json_ingress` | #1271 | #1301 |
| B — Node (#1350) | `user/gudge/node-json-ffi` | A | #1302 |
| C — .NET (#1351) | `user/gudge/dotnet-json-ffi` | A | #1303 |
| D — Cleanup (#1352) | `user/gudge/remove-binding-json-ffi` | A, and contains B and C | — |
| E0 — SDK types into `mxc-sdk` (#1353) | `user/gudge/move-sdk-policy-types` | D | — |
| E — Node experimental API | not started | After B merges | — |
| F — .NET experimental API | not started | After C merges | — |

A lands first. B and C proceed in parallel, as do E and F. GitHub allows one
base branch, so D targets A and carries the B and C commits; only its last
commit is new. A and C are each a single squashed commit. When A changes, B,
C, D, and E0 are rebased onto it, and each pull request's diff is confirmed
to contain only its own commits before review.

### 4.1 A — FFI JSON ingress

1. Reuse the exact JSON one-shot work from #1301: engine and SDK
   `run_json`/`spawn_sandbox_json`, and FFI `mxc_run_json`/`mxc_spawn_json`.
   Omit the typed ABI entirely.
2. Add an `experimental` parameter to `mxc_run_json` and `mxc_spawn_json`.
   Nonzero means true, matching existing raw exports.
3. Rename the lifecycle JSON exports to verb-bearing names and remove the old
   names, rather than adding aliases:

   | Current | New |
   | --- | --- |
   | `mxc_state_aware` | `mxc_run_state_aware_json` |
   | `mxc_state_aware_exec` | `mxc_exec_state_aware_json` |
   | `mxc_state_aware_exec_attached` | `mxc_exec_state_aware_attached_json` |

   Result and free functions keep their names. Update .NET and Node call
   sites in the same change so every pull request builds.
4. Enforce the rule in §3.3 with one check shared by one-shot runner
   resolution and state-aware dispatch: `ContainmentBackend::is_experimental`
   classifies every backend, and a missing opt-in for an experimental backend
   is `backend_unavailable` on every entry point.
5. Keep each FFI JSON wrapper thin: argument conversion, then a single call to
   the corresponding `mxc_sdk::*_json` function.
6. Audit the Rust v1.0 policy builder for normalization beyond field mapping,
   including host-dependent defaults for abstract `process` containment,
   capabilities derived from network policy, container-identifier minting,
   and the WSLC experimental exemption in `request.rs`. Either move each
   behavior into the shared semantic path or specify it for SDK mappers.
7. Add shared golden fixtures under `tests/policy/` that pair a high-level
   policy description with the exact 1.0.0 request produced by the Rust
   builder. Rust tests assert equivalent normalized intent and validate each
   expected document against the registered schema. Include negative cases,
   such as a backend section that does not match the selected containment.
8. Correct the result-ownership documentation: callers free a result after
   every call that populated it, including failures.
9. Mark `mxc_run_request`, `mxc_spawn_request`, and `request.rs` deprecated.
10. Remove `Deserialize` and `Serialize` from the Rust SDK policy types. The
    deprecated binding request owns private copies until D removes it.
11. Document the ingress rule in the `mxc_ffi` crate documentation and a short
    paragraph in an existing SDK or versioning document. Do not add a separate
    FFI document.

### 4.2 B — Node

1. Build exact 1.0.0 one-shot JSON through `createConfigFromPolicy` for
   `spawnSandboxAsync` and native streaming, then call `mxc_run_json` or
   `mxc_spawn_json` with `experimental = 0`.
2. Keep state-aware envelopes as exact 1.0.0 JSON on the renamed exports.
3. Reject `wsb:` identities in the high-level lifecycle API with a clear
   error.
4. Remove the private binding request builder in `request.ts`.
5. Test output against the shared goldens, and test that out-of-range and
   non-integer numeric input is rejected as `malformed_request`.
6. Retain executor-backed `spawnSandbox` and `spawnSandboxFromConfig`
   behavior.

### 4.3 C — .NET

1. Add a C# wire-type emitter to `mxc_schema_support` beside the TypeScript
   emitter, and a C# output mode to `mxc_schema_gen`. It supports the patterns
   the exact schemas use: closed objects, string enums, one class per request
   root, and optional members emitted as nullable properties omitted when
   unset. Generate internal records for the SDK target contract under
   `sdk/dotnet/Microsoft.Mxc.Sdk/Generated/`, extend `check-contract-codegen`
   to detect drift, and document regeneration in `docs/schema-codegen.md`.
   This is a separate commit at the start of C.
2. Add one exact 1.0.0 one-shot writer in `Microsoft.Mxc.Sdk.V1` (it consumes
   V1 types) that populates the generated wire records and serializes them
   with System.Text.Json. It omits absent members
   rather than writing `null`, migrates legacy `CaptureDenials` to
   ProcessContainer containment, and treats `InheritDefaultEnvironment`
   without `Environment` as having no effect.
3. Reject undefined enum values, such as `(NetworkAction)42`, instead of
   mapping them to a default.
4. Call `mxc_run_json` and `mxc_spawn_json` with `experimental = 0`, and move
   lifecycle calls to the renamed exports.
5. Reject `wsb:` identities in `MxcLifecycle` with a clear error, consistent
   with `docs/versioning.md` and the state-aware lifecycle API documentation.
6. Retain the public API surface.
7. Test output against the shared goldens and validate it against the exact
   schema. Negative tests assert the exact error. Tests exercise public API
   methods as well as internal writers.
8. Update `scripts/check-dotnet-api-parity.js` to compare against the exact
   contract instead of the private binding request.

### 4.4 D — Cleanup

After B and C merge, remove `mxc_run_request`, `mxc_spawn_request`,
`request.rs`, and the binding-request golden fixtures, and update generated
binding inventories.

### 4.4.1 E0 — SDK authoring types into `mxc-sdk`

Move the Rust SDK's policy, containment, request, builder, and typed
lifecycle types from `mxc_engine` into `mxc-sdk`, exposed only under
`mxc_sdk::v1`. The engine accepts `ExecutionRequest` from either the SDK
builder or the JSON parser through `spawn_execution_request`, and no longer
exports SDK types. `mxc-sdk` depends directly on `mxc_config_contract`, whose
1.0.0 contract struct the builder fills.

### 4.5 E and F — Experimental typed SDK APIs

Each SDK adds a separate experimental high-level API for development-only
features, such as Windows Sandbox, MicroVM, and Hyperlight:

1. Place experimental types and entry points in a distinct surface under the
   V1 namespaces: `Microsoft.Mxc.Sdk.V1.Experimental` marked with
   `[Experimental]` in .NET, and `@microsoft/mxc-sdk/v1/experimental` in
   Node.
2. Map experimental types to the co-shipped development contract's wire
   types and stamp its exact version. PR F generates C# wire records for the
   development contract with the emitter added in PR C.
3. Always call the FFI with `experimental = 1`.
4. Return sandbox identities that are accepted only by the experimental
   lifecycle API. The stable API continues to reject them.
5. Document that experimental APIs and their types may change in any release.
6. Test mapping against development-contract goldens, rejection of
   experimental backends without the opt-in, and cross-surface identity
   rejection.

## 5. Validation

Each pull request runs the applicable ladder:

- `cargo fmt --all -- --check`;
- `cargo check --workspace --all-targets --all-features`;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`;
- `cargo test --workspace`, rebuilding `wxc-exec` before Windows E2E tests;
- Node build, unit tests, and integration type-checking;
- `dotnet test --solution Microsoft.Mxc.Sdk.slnx`;
- versioning, contract codegen, configuration corpus, API parity, error-code
  parity, telemetry parity, PSEC, and generated-binding checks;
- `git diff --check`.

Platform paths that cannot run locally are identified in each pull request.

## 6. Decisions

1. `experimental = 1` only permits selecting an experimental backend. It is
   ignored for production backends and is not tied to the contract version.
2. Experimental high-level SDK APIs are follow-on PRs E and F.
3. .NET wire types are generated by a C# emitter in the existing
   `mxc_schema_support` / `mxc_schema_gen` pipeline, added in PR C.
4. Contract-mapped SDK types live in per-major namespaces:
   `Microsoft.Mxc.Sdk.V1`, `mxc_sdk::v1`, and `@microsoft/mxc-sdk/v1`. They
   evolve additively as 1.x contracts are published, and a future v2 adds a
   V2 namespace alongside them. Version-independent APIs (errors, discovery,
   telemetry, process handles, raw JSON) stay at each package root; .NET
   discovery lives in `MxcPlatform`.
5. The SDK v1 goldens in `tests/policy/sdk-v1` are the cross-language
   contract: every SDK must emit each expected document for its input.
6. The Rust SDK's authoring types belong to `mxc-sdk`, not `mxc_engine`
   (E0).
