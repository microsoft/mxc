# FFI JSON-Only Ingress and SDK API Plan

Status: the JSON-only ingress foundation is adopted and implemented in
pull requests #1349–#1353, stacked on #1355; #1271 has merged. The SDK API
alignment and release closeout in sections 7 and 8 were agreed on October 1,
2026, and remain implementation work, not a claim that the target surface
already exists. This plan replaces the typed-structure ingress in
#1301, #1302, and #1303, which are closed. §9.3, §9.5, and Phase 14 exit
criterion 16 of
[`version-aware-stack-plan.md`](version-aware-stack-plan.md) are superseded by
this plan. Its stable-target and public SDK API decisions also take precedence
over conflicting historical SDK statements in that earlier phase plan.
The current state of each pull request is recorded in
[`version-aware-stack-session-handoff-2026-09-30.md`](version-aware-stack-session-handoff-2026-09-30.md).

Updated: October 2, 2026.

## 1. Decision

`mxc_ffi` accepts sandbox policy and configuration only as exact-versioned
JSON. Invocation controls that are not configuration, such as experimental
authorization, dry-run, and attached execution, remain typed C parameters.

Every SDK is to offer both typed high-level APIs and the raw JSON counterparts
in section 7. Node and .NET typed calls normalize to exact-versioned JSON
before calling the FFI. Completing the public raw family in every SDK is
separate from implementing the native JSON entry points.

The in-process Rust SDK is unaffected: its typed APIs continue to adapt
directly into `CommonRequestIR` without JSON.

In the completed design the FFI does not accept the private co-versioned
binding JSON used by `mxc_run_request`, `mxc_spawn_request`, or
`mxc_probe_sandbox_request_json_with_error`. The deprecated paths remain only
until their consumers migrate and D removes them. Every configuration document
crossing the final FFI is a published or development exact contract that the
executor also accepts.

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

The typed high-level SDK selects its exact contract version; callers do not
select a version on that path. Raw JSON callers explicitly select an exact
contract in their document. The FFI does not negotiate, infer, or replace it.

### 3.1 Source of truth

`schemas/schema-version.json` defines `sdkMajorTargets`, which maps each SDK
major version to its latest published stable exact contract within that same
major. SDK constants,
such as .NET `SchemaVersions.SdkContract` and Node `SDK_CONTRACT_VERSION`, are
checked against it by the schema-version synchronization gate.

The target is fixed by the installed SDK release, not looked up dynamically
at runtime and not an alias of the globally latest stable version. Opening a
development contract does not advance the stable typed target.

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

When `sdkMajorTargets` advances to the next published stable minor contract,
retargeting the mapper exposes shape and type mismatches at compile time.
Generated types do not detect every omitted optional field or semantic change;
shared mapping fixtures and compatibility checks must also establish that
existing fields retain their meaning.

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
- Stable typed lifecycle APIs support only identities representable by their
  target contract and reject development-only prefixes such as `wsb:`.
  Development-only requests and identities must not be routed through the
  stable mapper; use the raw or experimental surface that supports them.
- Development types carry no compatibility promise. They are regenerated from
  each release's development contract.
- A new SDK major version targets the new major contract through the same
  table.

The complete public raw family in section 7 is a release requirement.
Until the experimental high-level APIs in PRs E and F land,
development-only features, including the Windows Sandbox lifecycle, are
available only through raw JSON APIs.

## 4. Pull-request stack

The stack is built on the merged #1271, which makes the v1 SDKs own their
contract version, and #1355, which places contract-mapped SDK types in V1
namespaces (§6, decision 4). #1301, #1302, and #1303 are closed.

| PR | Branch | Base | Replaces |
| --- | --- | --- | --- |
| V1 namespaces (#1355) | `user/gudge/sdk-v1-namespaces` | `main` | — |
| A — FFI JSON ingress (#1349) | `user/gudge/rust_ffi_json_ingress` | #1355 | #1301 |
| B — Node (#1350) | `user/gudge/node-json-ffi` | A | #1302 |
| C — .NET (#1351) | `user/gudge/dotnet-json-ffi` | B | #1303 |
| D — Cleanup (#1352) | `user/gudge/remove-binding-json-ffi` | C | — |
| E0 — SDK types into `mxc-sdk` (#1353) | `user/gudge/move-sdk-policy-types` | D | — |
| E — Node experimental API | not started | After B merges | — |
| F — .NET experimental API | not started | After C merges | — |

The stack is a straight line, and each pull request is a single commit, so
each one's diff contains only its own change. B and C are independent in
content but are stacked so D can build on both. When a lower pull request
changes, every pull request above it is rebased in order.

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
10. Retain the existing SDK serde derives needed by the deprecated binding
    parser. Reuse its existing SDK policy/config types rather than introducing
    parallel `FilesystemSpec`, `NetworkSpec`, or UI models and conversions.
    Removing SDK serde support is deferred to D, after B/C migrate every
    private-parser consumer.
11. Document the ingress rule in the `mxc_ffi` crate documentation and a short
    paragraph in an existing SDK or versioning document. Do not add a separate
    FFI document.
12. Exclude experimental authorization from the policy-hash projection.
    Identical production enforcement must have the same policy identity with
    either authorization value. Extend failure-result ownership documentation
    to the lifecycle JSON entry points as well as one-shot execution.

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
7. Complete the mapper and integration-test corrections assigned to B in
   section 8. The existing names describe this migration stage; the public
   Container/run/spawn/PTY naming change is the separate section 7 follow-up.

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
9. Migrate `MxcSandbox.Probe` through the same exact writer as run/spawn and
   invoke `mxc_probe_request_json_with_error`. Test equivalent mapped requests
   across probe and execution. Do not retain a second private request format
   just because probing does not launch a workload.
10. Complete the C# emitter, mapper, and experimental-option corrections
    assigned to C in section 8. Public API alignment remains a separate
    follow-up rather than widening this transport migration.

### 4.4 D — Cleanup

After B and C merge, remove `mxc_run_request`, `mxc_spawn_request`,
`mxc_probe_sandbox_request_json_with_error`, `request.rs`, and the
binding-request golden fixtures, and update generated binding inventories.
Keep the exact-config probe. Give migrated real-host tests fresh container
identifiers and document both one-shot and lifecycle producers of shared
process handles, as detailed in section 8.

Only after removing those consumers and the private parser, remove
`Deserialize`/`Serialize` and serde attributes from SDK authoring types.
Versioned exact-contract types and test-only fixture input types keep their
serde support. A/B/C temporarily retain the existing authoring derives; they
do not define a new supported SDK JSON contract or require new mirror models.
The released stable SDK still has plain Rust authoring types.

This staging deliberately avoids removing a trait used by an existing call
path in A and then recreating its decoder with duplicate policy types. Existing
private adapters whose wire shapes differ from SDK types remain until the
parser is deleted; do not indiscriminately remove those earlier adapters.

### 4.4.1 E0 — SDK authoring types into `mxc-sdk`

Move the Rust SDK's policy, containment, request, builder, and typed
lifecycle types from `mxc_engine` into `mxc-sdk`, exposed only under
`mxc_sdk::v1`. The engine accepts `ExecutionRequest` from either the SDK
builder or the JSON parser through `spawn_execution_request`, and no longer
exports SDK types. `mxc-sdk` depends directly on `mxc_config_contract`, whose
1.0.0 contract struct the builder fills.

Preserve the typed Rust request-probe API through an SDK-owned adapter to the
engine's `ExecutionRequest`-based probe seam. Restore lifecycle equivalence
tests at the moved SDK conversion boundary rather than testing only
hand-constructed `SdkStateAwareInput`. Finish extensibility of the public Rust
input types before release; these changes belong to E0, not the namespace PR.

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
4. Support development-only identities on the experimental lifecycle API;
   stable typed APIs continue to reject them. Raw lifecycle counterparts may
   operate on them through an appropriate registered exact contract and
   explicit backend authorization.
5. Document that experimental APIs and their types may change in any release.
6. Test mapping against development-contract goldens, rejection of
   experimental backends without the opt-in, and cross-surface identity
   rejection.

### 4.6 Public API alignment and PTY follow-ups

Keep #1355 focused on namespace names and export boundaries. If retaining the
public Rust lifecycle grouping, use `mxc_sdk::v1::container`, not
`mxc_sdk::v1::sandbox`. Contract-mapped authoring types and typed entry points
belong under V1; version-independent process/PTY handles, output, outcomes,
errors, discovery, telemetry, and raw JSON APIs belong at the package roots.
The new lifecycle module name fits #1355; bulk type/function renames and
execution-mode changes do not.

Add a focused public API-alignment PR, preferably after E0 establishes Rust
SDK authoring ownership, for section 7's cross-language vocabulary and typed
and raw API names. It must preserve execution semantics when renaming and
explicitly implement missing modes rather than disguising them as renames.
Update the SDK READMEs, examples, API parity checks, and consumer tests with
the public surface. Do not scatter this naming redesign across A through E0.

Coordinate separate functional follow-ups with the co-worker implementing
Rust's `MxcPty`. Complete its ownership and terminal contract first, then the
engine/FFI support and language-appropriate Node and .NET wrappers. Missing
captured or pipe-backed exec paths and any byte-output ABI work are functional
changes too. Preserve the shared engine routing and panic/ownership contracts.

These follow-ups are additional stable v1 work, not PRs E/F. Experimental typed
convenience APIs can follow independently; raw development-contract access
must not depend on their completion. No PR numbers are assigned to the new
API-alignment or PTY follow-ups yet.

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
   telemetry, process/PTY handles, output, outcomes, raw JSON) stay at each
   package root; .NET discovery lives in `MxcPlatform`.
5. The SDK v1 goldens in `tests/policy/sdk-v1` are the cross-language
   contract: every SDK must emit each expected document for its input.
6. The Rust SDK's authoring types belong to `mxc-sdk`, not `mxc_engine`
   (E0). They retain legacy-parser serde support through A/B/C; D removes it
   after deleting private ingress, so E0 moves plain authoring types.
7. Public generic SDK names use `Container`, not `Sandbox`. Distinguish a
   container identity from its running processes and terminal connections;
   retain actual backend product names such as Windows Sandbox.
8. Typed and raw execution each have run, pipe-backed spawn, and PTY spawn
   counterparts for one-shot and existing-container workloads. Section 7
   specifies the target vocabulary, semantics, and remaining contract choices.
9. The existing ingress PRs and namespace PR do not by themselves finish the
   stable public API. Section 8's fixes and section 7's alignment/functional
   follow-ups must be covered by the release checkpoint.

## 7. Cross-language public SDK API alignment

This section records the agreed target design from October 1. Names and
execution modes are intentional public API decisions, not statements that all
three SDKs already implement them. Rust's authoring vocabulary and semantics
are the starting point, with idiomatic casing and asynchronous conventions in
.NET and Node.

### 7.1 Type vocabulary and placement

| Concept | Target public name | Placement |
| --- | --- | --- |
| Container restrictions | `ContainerPolicy` | V1 |
| Complete one-shot invocation | `ContainerRequest` | V1 |
| Opaque persistent-container identity | `ContainerId` | V1 |
| Existing-container workload invocation | `ExecRequest` | V1 |
| Provision-time authoring request | `ProvisionRequest` | V1 |
| Live process with ordinary pipes | `MxcProcess` | Package root |
| Live terminal-backed workload | `MxcPty` | Package root |
| Captured execution result | `Output` | Package root |
| Terminal process outcome | `WaitOutcome` | Package root |

Use the same conceptual names and meaning across languages, rather than
copying Rust implementation details blindly. In particular, the current Rust
`Sandbox` is a live process facade: its replacement is `MxcProcess`, not a
container object. The .NET typed entry-point class can be `MxcContainer` in
V1 without making its returned process another container.

Persistent `ContainerId`, an optional one-shot container name, and an OS
process ID are distinct concepts. Do not collapse them into one `id` type.
Backend identifiers, generated exact wire records, and ergonomic authoring
types also remain distinct even when related.

Public SDK terminology changes do not rename released JSON members such as
state-aware `sandboxId`, ID prefixes, or containment wire names. Map the new
authoring names onto the existing exact contracts. Do not edit published
schemas or rename a product such as Windows Sandbox to imply another backend.

### 7.2 Typed execution operations

| Operation | Rust | .NET | Node | Logical result |
| --- | --- | --- | --- | --- |
| One-shot capture | `run` | `Run` | `run` | `Output` |
| One-shot pipes | `spawn` | `Spawn` | `spawn` | `MxcProcess` |
| One-shot terminal | `spawn_with_pty` | `SpawnWithPty` | `spawnWithPty` | `MxcPty` |
| Existing-container capture | `run_in_container` | `RunInContainer` | `runInContainer` | `Output` |
| Existing-container pipes | `spawn_in_container` | `SpawnInContainer` | `spawnInContainer` | `MxcProcess` |
| Existing-container terminal | `spawn_in_container_with_pty` | `SpawnInContainerWithPty` | `spawnInContainerWithPty` | `MxcPty` |

Prefer `spawnInContainerWithPty` over `spawnWithPtyInContainer`: preserve the
base operation `spawnInContainer` and append the I/O modifier, just as
`spawnWithPty` extends `spawn`. Do not alternate between `spawnPty` and
`spawnWithPty`; the latter describes spawning a workload with a terminal, not
merely allocating a PTY.

One-shot APIs take the one-shot authoring request. Existing-container exec
APIs take `ContainerId` plus `ExecRequest` and invocation options. They must
not accept a complete replacement provision policy or implicitly provision,
start, stop, or deprovision the identified container.

The table specifies operation names, not a requirement to expose duplicate
aliases at multiple import paths. Settle exact Rust export paths and managed
facade placement while implementing the alignment.

### 7.3 Asynchronous behavior is a separate axis

`run` means capture and wait for completion; `spawn` means return a live
process; `spawnWithPty` means return a live terminal-backed process. None of
these distinctions is expressed by an `Async` suffix.

- .NET awaitable variants use `Async`, including `RunAsync`, `SpawnAsync`,
  `SpawnWithPtyAsync`, and `SpawnInContainerWithPtyAsync`. Synchronous variants
  may coexist where appropriate, with the same mode semantics.
- Node startup should be non-blocking. The target is Promise-based operations:
  `run` resolves to `Output` after completion; `spawn` and `spawnWithPty`
  resolve to their live handles when startup has succeeded, not at exit.
- Rust keeps idiomatic snake_case. Document whether each implementation is
  blocking or asynchronous; any asynchronous counterpart retains the same
  capture, pipe, and terminal distinctions.

Renaming Node's current `spawnSandbox` to `spawn` is not necessarily
mechanical: its executor/PTY behavior must first satisfy the new pipe-backed
contract. Likewise, the current buffered `spawnSandboxAsync` name must not
become the model for distinguishing capture from streaming.

### 7.4 First-class raw JSON counterparts

Every SDK must expose the corresponding raw family at its package root:

| Mode | Rust capture / pipes / PTY |
| --- | --- |
| One-shot | `run_json` / `spawn_json` / `spawn_with_pty_json` |
| Existing-container exec | `run_in_container_json` / `spawn_in_container_json` / `spawn_in_container_with_pty_json` |

| Mode | .NET capture / pipes / PTY |
| --- | --- |
| One-shot | `RunJson` / `SpawnJson` / `SpawnWithPtyJson` |
| Existing-container exec | `RunInContainerJson` / `SpawnInContainerJson` / `SpawnInContainerWithPtyJson` |

| Mode | Node capture / pipes / PTY |
| --- | --- |
| One-shot | `runJson` / `spawnJson` / `spawnWithPtyJson` |
| Existing-container exec | `runInContainerJson` / `spawnInContainerJson` / `spawnInContainerWithPtyJson` |

Awaitable .NET variants append `Async`, for example
`SpawnInContainerWithPtyJsonAsync`. Node uses the same Promise/startup rules as
the typed family. Resolve the root .NET raw facade without creating ambiguous
same-named root and V1 entry-point classes.

The raw counterparts return the same logical `Output`, `MxcProcess`, and
`MxcPty` types as their typed counterparts. This is a supported escape hatch
for development contracts and registered historical stable contracts, not a
stable-typed mapper with a version override.

Raw-input rules:

- **a.** Accept a complete exact-contract JSON document, normally as a string. The
   caller authors `version`; an existing-container exec document also authors
   its `phase`, `sandboxId`, and phase-specific fields.
- **b.** Require the exact version and request root to be registered in the native
   library actually loaded. Reject unsupported versions or roots; do not
   negotiate, select the latest version, or fall back to another contract.
- **c.** Pass the document through unchanged to native exact parsing. Do not stamp
   a stable version, insert SDK defaults, drop unknown fields, or parse and
   reserialize through stable wire types. This also avoids rounding numeric
   tokens merely because the Node high-level model uses JavaScript numbers.
- **d.** Do not route a development document through the stable mapper. Native
   parsing, normalization, backend validation, and runtime authorization
   remain authoritative.
- **e.** Keep experimental authorization, dry-run, and terminal invocation
   controls outside configuration JSON, as API/FFI arguments where supported
   by the entry point. Opening a development contract does not advance
   `sdkMajorTargets` or authorize an experimental backend. Production-backend
   development fields need no backend opt-in.
- **f.** Check the operation matches the entry point: one-shot calls reject lifecycle
   documents, and existing-container exec calls reject non-exec phases before
   allocating or launching resources.

Expose raw provision, start, stop, and deprovision operations as well, using
the same complete-document, version, authorization, and failure rules.
Preserve development-specific lifecycle response metadata as raw JSON or an
extensible envelope; do not force it into stable V1 metadata types. Native
JSON entry points alone do not satisfy this public SDK requirement, nor does
requiring a managed caller to launch the executor manually.

Provide phase-specific validation/dry-run routes where applicable. Validation
is not execution and must not produce an empty, success-shaped `Output` that
suggests a workload ran.

### 7.5 Process, PTY, and attached-console contracts

`spawn` returns language-appropriate owned stream objects: Rust reader/writer
interfaces, .NET streams, and Node readable/writable streams. Native OS pipe
handles are an advanced capability, not the portable public contract.
Document nullable/unavailable streams and reject unsupported requested modes
explicitly; do not manufacture a usable-looking handle or silently fall back.

The co-worker's `MxcPty` implementation must establish a shared contract before
the wrappers are built:

- **a.** Own a running terminal-backed workload and its terminal endpoints, with one
   lifecycle owner and reusable underlying process-control logic.
- **b.** Expose terminal input/output and initial dimensions plus resize.
- **c.** Define terminal output as the combined stream, not invented separate
   stdout/stderr pipes, and document its encoding and control-sequence behavior.
- **d.** Provide wait/outcome, termination, and disposal, including what closes
   endpoints and releases native resources on failed startup.
- **e.** Distinguish sending terminal input such as Ctrl-C from forcefully killing
   the process, according to the backend's supported terminal behavior.
- **f.** Work with caller-controlled endpoints without requiring the host process's
   own stdin/stdout to already be terminals.

PTY-backed spawn is not attached execution. The current Rust `exec_attached`
blocks, uses host stdio, and returns an outcome; renaming it to a PTY spawn
would not meet the new contract. An attached-console helper may instead relay
an owned `MxcPty` to the host console. A backend lacking PTY support must fail
explicitly before launching, not downgrade the request to pipes.

Terminal selection and options are invocation controls rather than a reason
to add PTY fields to an immutable policy contract. Any additional native
terminal exports must preserve the JSON-only configuration ingress rule.

### 7.6 Output, errors, and ownership

Captured one-shot and existing-container calls return the same result shape:
outcome, stdout, stderr, warnings, and output metadata. The target is
byte-preserving captured output with explicit text helpers. Rust already uses
byte vectors while .NET currently captures strings; inventory any FFI
pointer/length and binding work needed for parity rather than presenting this
as a type rename. Do not silently truncate binary output or replace decoding
failures without the documented caller-selected text policy.

A nonzero workload exit is an execution result, not an API failure.
Validation, startup, transport, capture, and wait failures remain explicit
errors with actionable context. Timeout remains distinguishable from ordinary
exit and carries captured partial output on run paths. Define one
cross-language cancellation and partial-output contract before freezing the
surface, rather than allowing three different interpretations.

Ownership rules:

- **a.** One-shot operations own their execution environment's cleanup under the
   request's supported lifecycle semantics.
- **b.** Existing-container exec operates within a caller-owned running container.
   Completing, timing out, cancelling, or disposing that exec must not
   implicitly stop or deprovision the container.
- **c.** State-aware termination scope is backend-specific. Do not promise whole
   process-tree cleanup where the native primitive reaches only the foreground
   process; document how remaining descendants are reclaimed.
- **d.** `run` drains stdout/stderr concurrently, defines stdin behavior, and returns
   after completion, output draining, and its owned cleanup. Define capture
   limits and behavior when descendants retain stream endpoints.
- **e.** `spawn` and PTY spawn define stream transfer, endpoint closure, wait,
   disposal, and cancellation responsibilities. Merely cancelling a host wait
   must not silently abandon an owned workload.
- **f.** Preserve warnings and metadata, including cleanup failures after exit.
   Common raw result wrappers must not discard development-specific metadata
   through stable-only deserialization.
- **g.** Every FFI result populated by a call is freed on success or failure.
   Handles from one-shot spawn and lifecycle exec use the same documented
   control/destructor contract.

The FFI remains co-versioned with its native library and generated bindings;
this SDK alignment does not promise an independently stable external C ABI.

### 7.7 Decisions to finish before API freeze

The vocabulary and execution-mode families above are the accepted direction.
The following details still require an explicit contract in their implementing
PRs:

- Exact Rust export paths and .NET typed/raw facade placement; avoid redundant
  aliases and ambiguous imports.
- `MxcPty` ownership, methods, resize/input behavior, backend capability matrix,
  and the required engine/FFI integration.
- Byte-output representation across the FFI, text decoding helpers, capture
  limits, and descendant-held-stream completion behavior.
- Post-start cancellation, termination/disposal guarantees, partial output,
  and the common outcome representation.
- Uniform handling of legacy experimental switches on stable typed APIs:
  remove/deprecate them or reject unsupported true values, rather than silently
  advertising an authorization option the stable surface cannot honor.
- Migration of existing public names and examples before 1.0; preserve mode
  semantics and do not publish aliases that misleadingly imply equivalence.

## 8. Release closeout and PR ownership

**October 2 staging update:** A adds exact ingress without removing the SDK
serde traits required by its still-active legacy callers. B/C migrate those
callers; D removes the private parser/exports and then SDK serde support.
This replaces A's earlier temporary mirror-policy model sequence. The end-state
JSON-only boundary, plain SDK types, and release criteria are unchanged.

The following numbered items retain the October 1 review's item numbers.
Lower-case suffixes identify substeps rather than new overall release items.
The allocation records where fixes belong; it does not claim they are done.

| Item | Required work | PR |
| --- | --- | --- |
| 1a | .NET probe uses the execution writer and exact-config probe; add mapping parity tests | #1351 (C) |
| 1b | Remove the private binding-request probe export/parser and refresh binding inventories | #1352 (D) |
| 1c | Preserve Rust typed probing via an SDK adapter to the engine's execution-request seam | #1353 (E0) |
| 2a | Node preserves explicit empty environments and explicit network capabilities when no directional policy owns them | #1350 (B) |
| 2b | .NET preserves environment order, validates keys, and does not mint a replacement for a supplied container name | #1351 (C) |
| 3 | Handle integral schema bounds including `0.0`, generate unsigned C# types faithfully, regenerate artifacts, remove lossy `ToInt64`, and test limits | #1351 (C) |
| 4a | Exclude experimental authorization from policy identity and test equivalent production hashes | #1349 (A) |
| 4b | Settle stable experimental-option behavior and truthful public documentation | #1350 (B), #1351 (C); corresponding Rust authoring changes in #1353 (E0) |
| 5 | Finish Rust input extensibility for `FilesystemSection`, `UiSection`, `WslcSection`, and related constructors/consumers before 1.0 | #1353 (E0) |
| 6a | Test the moved Rust lifecycle authoring conversions against exact JSON, not just hand-built internal input | #1353 (E0) |
| 6b | Narrow integration skip classification so real API failures do not masquerade as unavailable host runtimes | #1350 (B) |
| 6c | Mint distinct identifiers in migrated real-host FFI tests | #1352 (D) |
| 6d | Document freeing populated failure results and both producers of shared process handles | #1349 (A) for failure ownership; #1352 (D) for cleanup/handle documentation |

Shared golden and negative cases accompany the relevant B/C mapper fixes, with
Rust fixture-harness adjustments where needed. Cover absent versus empty
environment, caller order, duplicate/case-variant names where representable,
invalid keys, explicit capabilities, supplied identifiers, numeric boundaries,
and exact error behavior. Use one shared Node SDK target constant rather than
separate literals, and update examples that assume abstract `process` creates
a concrete `processContainer` section. Classify intermediate-state review
comments against the final stack instead of mistaking a planned B/C/D
migration for an extra architecture defect.

Additional work:

- #1348 has merged. In A's builder, remove the duplicate blank proxy-peer
  check, use the shared parser diagnostics, and add the shared invalid fixture.
  E0 carries the updated builder when moving authoring ownership.
- #1355 stays namespace/export-focused, including the generic `container`
  module spelling. Section 7's bulk naming and execution changes use the
  dedicated alignment/functional follow-ups.
- Track the Linux unused SDK test imports and macOS SDK test `let_and_return`
  warning already present on the merged base. Resolve them in a scoped
  baseline cleanup; do not call warnings-denied cross-platform verification
  green while those failures remain or attempt to amend merged #1271.
- Do not expand the stable release critical path to depend on E/F,
  historical-schema removal, crates.io publication, a playground rewrite, or
  deeper internal decoupling. Package-distribution changes still need their
  own release decision and validation.

### 8.1 Stable v1 release exit criteria

- **a.** Land the stable target, namespace, ingress, mapper, cleanup, and SDK
   ownership changes with applicable review and CI on the actual rewritten
   tips. Old upper-stack green runs do not verify a restacked composition.
- **b.** Close the numbered fixes above and the agreed stable API-alignment work.
   Merely merging A through E0 does not freeze the final public API.
- **c.** Verify all six typed and six raw execution entry points per SDK against
   their specified capture/pipe/PTY modes on each declared supporting backend.
   Unsupported combinations must refuse explicitly before execution.
- **d.** Verify raw lifecycle phases, supported historical exact versions,
   development-only fields, unregistered versions, unknown fields, phase
   mismatches, and experimental-backend authorization independently of version.
- **e.** Verify stream pressure, empty and binary output, timeout/cancellation,
   partial output, resize and terminal input, repeated wait/disposal,
   failed-startup cleanup, and persistence of caller-owned containers.
- **f.** Establish additive Rust, .NET, and Node consumer/API baselines before 1.0
   publication, including external Rust constructors, .NET async signatures,
   Node import/require and supported module-resolution consumers.
- **g.** Validate actual SDK packages with their matching native libraries, sidecars,
   generated bindings, registered SDK targets, and intended release versions,
   not only source-tree builds.
- **h.** Update SDK/backend documentation and examples with the implemented names
   and honest support matrix. Record unverified host coverage and open contract
   decisions explicitly; do not substitute skipped tests for supported-mode
   evidence.
