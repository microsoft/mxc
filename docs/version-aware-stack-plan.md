# Version-Aware Stack Plan

Status: Phase 12 and the exact-contract and runtime portions of Phase 13 are
complete. Phase 13c, which completes the missing direct typed Rust SDK path,
must land before Phase 14 starts. Phase 14 establishes the v1 SDK line and the
v1.0 exact contract.

Updated: September 22, 2026.

## 1. Stack status

The WSLC-inclusive exact-contract stack was selected and merged. The missing
Rust SDK transport work is the final pre-Phase 14 step:

| Phase | PR | Merge commit | Result |
| --- | --- | --- | --- |
| Phase 12 | #1187 | `c531de65` | Published v0.9 with stable WSLC support |
| Phase 13 core | #1188 | `be9c377d` | Removed the rolling configuration architecture |
| Phase 13 follow-ups | #1189 | `8ac67daf` | Hardened exact-contract infrastructure |
| Phase 13c | Planned | — | Complete direct typed Rust SDK transport before Phase 14 |

The alternative non-WSLC stack in #1184, #1185, and #1186 was completed and
verified but was not selected for merge.

The merged architecture now has:

- immutable exact published contracts for v0.6, v0.7, v0.8, and v0.9;
- one exact mutable development contract, v0.10;
- exact registered contracts as the external JSON trust boundary;
- version-specific adapters into private `CommonRequestIR`;
- shared semantic normalization into `ExecutionRequest`;
- no rolling whole-request parser, model, schema, TypeScript artifact, builder,
  or equivalence harness;
- registry-owned artifact-generation and request-root metadata;
- v0.6/v0.7 legacy network-enforcement compatibility and strict enforcement
  from v0.8 onward;
- source-contract attribution separated from effective runtime semantics.

The merged stack does not yet complete the SDK transport goal. State-aware
runtime dispatch is typed after parsing, but the public Rust state-aware API
still accepts serialized JSON. Node and .NET high-level state-aware APIs also
serialize JSON internally. Phase 13c must preserve the raw exact-JSON lane
while adding a direct typed lane for Rust SDK callers. Later binding work must
reuse that seam for .NET and evaluate the corresponding Node transport.

## 2. Versioning model

### 2.1 Exact configuration contracts

Raw configuration remains exact-versioned:

```text
raw JSON
  -> exact registered version
  -> exact request root
  -> version-specific adapter
  -> CommonRequestIR
  -> shared normalization
  -> ExecutionRequest
```

Config files, base64 configurations, raw SDK configuration APIs, and replay
tools must continue to declare an exact registered contract version.

There is no:

- missing-version fallback;
- supported-range dispatch;
- same-major parser fallback;
- latest-version fallback;
- deserialize-latest-and-reject-later path.

### 2.2 High-level SDK major lines

High-level SDK APIs target a major contract line rather than asking consumers
to select an exact configuration version.

High-level SDK version selection and SDK transport are separate concerns. A
package-owned exact target does not justify serializing a high-level request
to JSON and parsing it back. The two supported ingress lanes are:

```text
explicit raw configuration API
  -> exact JSON
  -> exact registered request root
  -> exact contract adapter
  -> CommonRequestIR
```

```text
trusted high-level SDK API
  -> typed SDK request
  -> direct SDK adapter
  -> CommonRequestIR
```

Both lanes then use the same semantic normalization into `ExecutionRequest`.
The raw lane remains available for configuration files, replay, automation,
and callers that intentionally use exact contracts. It is not the production
implementation path for a high-level Rust SDK call.

Within one SDK major line:

- a compatible minor SDK update must not require consumer code changes;
- existing code continues to express the same intent after upgrading;
- consumers change code only when they choose to use a newly added field,
  method, backend, or feature;
- each SDK release owns the exact minor contract emitted or constructed
  internally;
- an SDK always targets the latest minor contract available for its major
  line: SDK 1.0 targets `1.0.0`, SDK 1.1 targets `1.1.0`, and upgrading the
  package advances the exact contract without requiring existing source
  changes;
- raw configuration APIs continue to expose exact contract versions.

A new SDK major version may intentionally require consumer code changes.

The public type design must preserve source compatibility when minor releases
add capabilities. In particular:

- Rust public enums that may gain variants must not require exhaustive matching;
- TypeScript and .NET additions must avoid turning existing optional input into
  required input;
- existing methods and properties must retain their meaning;
- additions must not silently reinterpret existing policy;
- removed, renamed, or narrowed public API belongs in a new major version.

### 2.3 Runtime behavior

Contract versions select accepted JSON shape, not historical runtime
implementations. Backends consume current normalized runtime semantics and do
not parse or compare config-version strings.

Post-v1 compatibility tooling compares exact contracts at development and
publication time. It does not participate in runtime dispatch.

## 3. Pre-Phase 14 Rust SDK transport completion

Phase 13c corrects the missing caller-boundary work on the current v0.9/v0.10
contract line before any v1 contract or public-API transition begins.

### 3.1 Existing foundation

The work is partially complete:

| Area | Status | Existing implementation | Remaining Phase 13c work |
| --- | --- | --- | --- |
| One-shot caller transport | Complete for JSON elimination | `SandboxPolicy` plus `build_request` or `build_request_with_containment` constructs a typed `SandboxRequest`; `run` and `spawn_sandbox` consume it without serializing or parsing JSON | Preserve this invariant |
| One-shot normalization adapter | Partial | The builder constructs the selected exact contract as an in-memory Rust value and calls `load_one_shot_request_from_contract`; there is no JSON round trip | Add or confirm the intended borrowed SDK-to-`CommonRequestIR` adapter so high-level SDK construction does not depend on building an exact wire-contract value |
| Shared normalization seam | Complete | Exact-contract adapters produce private `CommonRequestIR`, which shared normalization converts into `ExecutionRequest` | Expose only the minimum crate-private construction seam needed by trusted SDK adapters |
| State-aware parsing and runtime representation | Complete after ingress | Exact JSON parsing produces `ParsedStateAwareRequest` with typed `StateAwareOperation`; successful requests retain neither source JSON nor raw backend payload | Preserve this typed runtime model |
| State-aware engine dispatch | Complete after parsing | `run_state_aware` and `exec_state_aware` accept `ParsedStateAwareRequest` and dispatch typed operations | Add construction entry points that do not require JSON parsing |
| Raw state-aware JSON API | Complete | `run_state_aware_json`, `exec_state_aware_json`, and attached-exec JSON entry points parse exact contracts and call the typed runtime dispatch | Retain and clearly identify these as raw exact-configuration APIs |
| High-level typed state-aware Rust API | Missing | Public Rust lifecycle calls accept `&str`; envelope calls return serialized JSON strings | Add typed request and response APIs for provision, start, exec, stop, and deprovision |
| Typed state-aware SDK adapter | Missing | State-aware `CommonRequestIR` is currently produced only by exact-contract adapters | Map borrowed typed SDK lifecycle requests directly into `CommonRequestIR` plus `StateAwareOperation` |
| Caller-boundary equivalence coverage | Missing | Existing tests prove exact JSON parsing and post-parse typed dispatch; one-shot tests cover the typed builder separately | Prove typed SDK and equivalent exact JSON inputs normalize to the same intent without routing production typed calls through JSON |

One-shot therefore already meets the immediate no-JSON transport objective.
Its remaining question is narrower: whether the current in-memory
exact-contract bridge is the intended long-term SDK adapter or should be
replaced by a dedicated borrowed SDK adapter. The target architecture favors
the dedicated adapter so SDK construction and exact wire-contract evolution
remain separate.

### 3.2 Required production path

The required production path is:

```text
typed Rust SDK request
  -> direct SDK adapter
  -> CommonRequestIR
  -> shared normalization
  -> ExecutionRequest
```

The raw path remains:

```text
exact JSON
  -> exact registered parser
  -> exact contract adapter
  -> CommonRequestIR
  -> shared normalization
  -> ExecutionRequest
```

### 3.3 Implementation sequence

#### 13c-a — Lock the SDK boundary

1. define typed public lifecycle request and response shapes for provision,
   start, exec, stop, and deprovision;
2. define which execution options remain method parameters rather than policy,
   including dry-run, experimental authorization, and stdio mode;
3. keep raw exact-JSON entry points, but give them explicit raw names and
   document that they are not the high-level implementation path;
4. add compile fixtures for the proposed typed API before implementing it.

#### 13c-b — Add the direct SDK normalization seam

1. add a crate-private borrowed SDK adapter into `CommonRequestIR`;
2. construct `StateAwareOperation` directly from typed lifecycle input;
3. normalize the pair through the existing `StateAwareInput` and shared
   semantic normalizer;
4. add typed engine construction entry points returning
   `ParsedStateAwareRequest`;
5. migrate the one-shot builder to the same direct SDK adapter, or explicitly
   prove and document why its current in-memory exact-contract bridge remains
   the chosen implementation.

#### 13c-c — Add typed lifecycle execution

1. add typed envelope-phase execution for provision, start, stop, deprovision,
   and dry-run;
2. add typed streaming and attached exec entry points;
3. return typed lifecycle envelopes and errors from high-level calls;
4. keep JSON response serialization solely in the raw JSON wrappers;
5. make raw wrappers parse exact JSON and delegate to the same typed engine
   execution functions used by the high-level APIs.

#### 13c-d — Prove equivalence and preserve behavior

1. create typed and exact-JSON pairs for every lifecycle operation;
2. compare their `CommonRequestIR`, `StateAwareOperation`, and normalized
   `ExecutionRequest` intent;
3. cover v0.9 and development v0.10 backends, presence semantics, experimental
   authorization, telemetry, dry-run, streaming exec, and attached exec;
4. preserve existing diagnostics for raw malformed or unsupported exact JSON;
5. prove high-level typed calls never invoke JSON serialization, JSON parsing,
   or an exact-contract adapter.

#### 13c-e — Migrate consumers and documentation

1. migrate Rust SDK tests and examples to the typed lifecycle surface;
2. retain focused tests for each raw JSON entry point;
3. update state-aware Rust and architecture documentation to show both lanes;
4. add an API-boundary regression that prevents the typed implementation from
   delegating to a raw JSON function;
5. record the completed seam for subsequent .NET FFI and Node transport work.

This step must preserve current v0.9/v0.10 contract behavior, runtime
semantics, diagnostics, feature gates, and raw API compatibility. It does not:

- create `1.0.0` or rename v0.10;
- remove v0.9 aliases or legacy high-level networking;
- redesign .NET, Node, or FFI transport;
- change the exact JSON trust boundary.

Phase 13c is complete when:

- typed Rust one-shot and state-aware calls reach `CommonRequestIR` without
  serializing or parsing JSON;
- the raw JSON lane remains explicit and exact-versioned;
- typed-versus-raw equivalence tests cover every lifecycle operation and
  representative backend-specific configuration;
- Rust SDK tests exercise the typed public lifecycle surface rather than using
  `run_state_aware_json` as the high-level API;
- no high-level Rust SDK implementation delegates to the raw JSON lane.

The implementation may be one pull request or a short stack covering the
engine seam, direct adapters, public lifecycle APIs, and equivalence tests.
All parts must merge before Phase 14 begins.

## 4. Phase 14 outcome

Phase 14 establishes:

- the v1 high-level SDK API line;
- preservation of the direct typed Rust SDK path established in Phase 13c;
- the typed SDK transport sequence for .NET and Node after the Rust path;
- directional-only high-level SDK networking;
- the exact published `1.0.0` contract;
- the exact mutable `1.1.0` development contract;
- canonical latest-minor SDK targeting for the v1 line;
- compatibility gates for future v1.x contract and SDK evolution.

The `-alpha` suffix ends at v1. Published v1 contracts use stable semantic
versions such as `1.0.0`; the registry status, not a prerelease suffix,
identifies whether a contract is mutable or published.

Phase 14 is the intentional public-API break boundary. It must not be combined
with unrelated backend redesign.

## 5. v1.0.0 contract boundary

The exact `1.0.0` contract starts from published `0.9.0-alpha`:

```text
published 0.9.0-alpha
          |
          | copy and remove compatibility aliases
          v
published 1.0.0
```

`1.0.0` is a conservative baseline:

- copy the published v0.9 accepted shape;
- change the exact version spelling to `1.0.0`;
- remove compatibility aliases, including `appContainer` and
  `macos_sandbox`, after completing an alias inventory;
- retain the exact-contract, adapter, and `CommonRequestIR` architecture;
- retain the v0.9 one-shot and state-aware request-root set;
- make only changes required for the approved v1 SDK boundary;
- do not introduce any v0.10-only field, request root, containment, alias, or
  test feature;
- do not add features merely to justify the major-version increment.

Published v0.9 has no experimental structures to carry into `1.0.0` or remove
from it.

The v1 high-level SDK policy exposes directional networking only. Legacy
network authoring remains available solely through the immutable v0.6-v0.8 raw
JSON contracts.

## 6. v0.10 becomes v1.1.0

The v0.10 development contract is not deleted and later reconstructed. Its
complete development lineage becomes the exact `1.1.0` development contract:

```text
development 0.10.0-alpha
             |
             | rename identity; preserve contract content
             v
development 1.1.0
```

The rename covers:

- the Rust development contract version;
- registry identity and metadata;
- schema and generated TypeScript artifact paths;
- fixture directories and version markers;
- adapters and parser dispatch;
- SDK exact-target constants;
- tests and documentation.

Every v0.10-only item is therefore a `1.1.0` addition relative to `1.0.0`:

| Item | v0.10 surface | `1.0.0` | `1.1.0` development |
| --- | --- | --- | --- |
| Abstract VM intent | `containment: "vm"` | Excluded | Included |
| Windows Sandbox one-shot | `containment: "windows_sandbox"` | Excluded | Included |
| Windows Sandbox idle timeout | `windowsSandbox.idleTimeoutMs` | Excluded | Included |
| Legacy Windows Sandbox timeout spelling | `windowsSandbox.idleTimeout` | Excluded | Included |
| Windows Sandbox daemon pipe override | `windowsSandbox.daemonPipeName` | Excluded | Included |
| Windows Sandbox state-aware provision | `WindowsSandboxProvisionRequest` | Excluded | Included |
| MicroVM containment | `containment: "microvm"` | Excluded | Included |
| Hyperlight containment | `containment: "hyperlight"` | Excluded | Included |
| Test feature plumbing | top-level `test` | Excluded | Included |

WSLC, IsolationSession, directional networking, and the common state-aware
phase roots are already part of v0.9 and therefore form part of the `1.0.0`
baseline.

## 7. Contract transition sequence

The transition preserves exactly one mutable development contract throughout.

### 7.1 Add and release `1.0.0`

While `0.10.0-alpha` remains the sole mutable development contract:

1. copy published v0.9 into a new published `1.0.0` contract module;
2. remove every inventoried compatibility alias;
3. add `1.0.0` registry identity, stable schema generation, stable TypeScript
   generation, fixtures, adapters, and parser dispatch;
4. apply the approved v1 high-level SDK changes;
5. set the v1 SDK exact target to `1.0.0`;
6. verify that no v0.10-only surface is reachable from a `1.0.0` request root;
7. verify the published Rust model regenerates the stable artifacts;
8. activate stable-schema and registry-history protection.

The implementation pull request is the release candidate. The merged
`1.0.0` identity is published from its first appearance in the registry; there
is no second mutable v1.0 contract alongside v0.10.

### 7.2 Release the v1.0 SDKs

At the release checkpoint:

1. high-level Rust, Node, and .NET APIs target the v1 major line;
2. their package-owned exact target is `1.0.0`;
3. high-level Rust one-shot and state-aware calls use typed requests and
   direct adapters rather than serialized JSON;
4. raw configuration APIs remain exact-versioned and explicitly named as raw
   JSON entry points;
5. the v1 SDKs and runtime are validated and released together;
6. no `1.1.0` SDK target is enabled before the v1.0 release is complete.

### 7.3 Rename v0.10 development to `1.1.0`

After the v1.0 release:

1. rename the existing v0.10 development identity to `1.1.0`;
2. rename its generated artifacts, fixtures, constants, tests, and
   documentation without removing and restoring feature content;
3. advance the v1 SDK exact target from `1.0.0` to `1.1.0`;
4. classify every `1.0.0` to `1.1.0` contract difference;
5. prove existing v1.0 SDK consumer source remains valid;
6. remove all remaining v0.10 identities and generated artifacts.

## 8. Canonical SDK exact targets

Add a canonical major-to-exact-contract mapping to
`schemas/schema-version.json`, conceptually:

```json
{
  "sdkMajorTargets": {
    "1": "1.0.0"
  }
}
```

At the v1.0 release commit the v1 target is `1.0.0`. When v1.1 development
opens, it advances to `1.1.0`.

Rust, Node, and .NET may expose language-appropriate internal constants, but
the existing schema-version synchronization gate must verify that all three
match the canonical mapping.

Applications select an SDK package version, not an exact wire version:

- SDK 1.0 emits or constructs `1.0.0`;
- SDK 1.1 emits or constructs `1.1.0`;
- upgrading the package advances the exact contract automatically;
- existing source continues to express the same intent;
- raw configuration APIs continue to accept explicit exact versions.

## 9. SDK work

### 9.1 Rust

Phase 13c establishes the direct typed Rust transport on the current contract
line. The v1 Rust high-level API preserves that path while it:

- removes caller selection of an exact config version;
- targets the v1 major line and its canonical latest minor;
- exposes directional network policy only;
- preserves exact-version selection in raw configuration APIs;
- provides typed one-shot and state-aware request types;
- adapts borrowed typed SDK input directly into `CommonRequestIR`;
- does not serialize high-level requests to JSON or invoke the exact JSON
  parser as an implementation step;
- retains separately named raw JSON state-aware entry points for callers that
  intentionally supply an exact contract;
- retains backend validation and current runtime semantics;
- uses non-exhaustive or otherwise additive public types where minor releases
  may add variants.

### 9.2 Node

Separate high-level policy from raw configuration:

```typescript
type SandboxPolicy = {
  // v1 high-level intent; no caller-selected exact config version
};

interface ContainerConfig {
  version: string;
  // exact raw configuration
}
```

High-level calls target the canonical v1 exact contract. Raw APIs such as
`spawnSandboxFromConfig`, config-file execution, and explicit
`ContainerConfig` construction continue to require exact versions.

New v1.x policy fields and backend options must be optional additions.

The current state-aware Node path builds an exact JSON envelope and sends it to
the executor. After the Rust direct-adapter seam is established, perform a
bounded Node transport design and implementation step. The default outcome is
a typed native transport for high-level calls while retaining explicit raw
JSON APIs. If the executor-backed architecture prevents that outcome, record
the constraint, approved boundary, owner, and follow-up instead of treating
JSON serialization as implicitly complete.

### 9.3 .NET and FFI

The v1 .NET high-level API:

- removes caller-selected exact config versions;
- exposes directional network policy only;
- targets the canonical latest v1 minor;
- keeps raw exact-configuration entry points versioned.

The private FFI request is a co-versioned binding contract, not an MXC
configuration contract. It must not recreate a public multi-version config
model.

The current .NET state-aware path serializes a `JsonObject` and passes UTF-8
JSON to `mxc_state_aware`. Replace that high-level path with a typed,
co-versioned FFI request that adapts into the same `CommonRequestIR` seam.
Explicit raw exact-configuration APIs may continue to pass JSON. Typed FFI is
required follow-up architecture work, not an independent performance
optimization.

### 9.4 Typed transport sequence

Implement typed transport in this order:

1. complete the typed engine entry points, direct Rust SDK adapters, typed
   state-aware APIs, and raw API separation in Phase 13c;
2. preserve that path through the v1 Rust API transition;
3. add a co-versioned typed FFI request and migrate .NET high-level lifecycle
   APIs;
4. complete the Node transport design and implement typed native transport
   unless an explicit reviewed architecture decision records why it must
   remain executor JSON;
5. keep typed and raw exact-JSON normalization equivalent through shared
   fixtures and tests.

Completing internal typed dispatch after JSON parsing does not satisfy this
work. Completion is measured at the caller boundary.

## 10. Legacy networking removal

Remove legacy network authoring from v1 high-level Rust, Node, and .NET policy
types:

- `allowOutbound`;
- `allowLocalNetwork`;
- `allowedHosts`;
- `blockedHosts`;
- legacy proxy placement;
- legacy authored-presence tracking;
- version-dependent `NetworkFormat` selection;
- compatibility converters used only by multi-version high-level policy.

Retain:

- directional egress policy;
- directional ingress policy;
- host-loopback posture;
- runtime proxy configuration at its current location;
- exact parsing of legacy syntax in immutable v0.6-v0.8 raw contracts.

## 11. v1.x compatibility gates

### 11.1 Exact-contract structural comparison

Compare adjacent exact contracts within one major line, beginning with
`1.0.0` to `1.1.0`. Use generated schemas plus registry request-root metadata,
not Rust source text.

| Change | Classification |
| --- | --- |
| Add optional field | Compatible |
| Add request root | Compatible, subject to SDK API review |
| Add containment/backend value | Contract-compatible, SDK review required |
| Relax a local constraint | Compatible with semantic review |
| Remove or rename field/root | Breaking |
| Make optional input required | Breaking |
| Remove enum value | Breaking |
| Narrow type, range, or pattern | Breaking |
| Open or close an object | Semantic review required |
| Change default or presence meaning | Semantic review required |
| Change adapter or runtime meaning | Semantic review required |

The gate rejects same-major structural breaks and requires an explicit
classification for every difference it cannot prove compatible.

### 11.2 Semantic review manifests

Add a checked-in manifest for every adjacent v1 minor transition, beginning
with:

```text
schemas/compatibility/1.0.0-to-1.1.0.json
```

The manifest records:

- every structurally additive or changed surface;
- its intended runtime meaning;
- whether existing policy behavior changes;
- the tests covering the change;
- explicit approval for each semantic-review classification.

CI fails when the contract changes without a corresponding classification.

### 11.3 SDK source-compatibility gates

Capture public API baselines when v1.0 is published:

- Rust: run `cargo-semver-checks` against the v1.0 baseline and compile
  representative v1.0 consumer fixtures;
- TypeScript: compile v1.0 consumer fixtures with `tsc --noEmit` against the
  current SDK and compare a generated public API report;
- .NET: run API compatibility against the v1.0 reference assembly and compile
  a representative v1.0 consumer project;
- FFI: retain generated-binding, status-code, and API parity gates.

### 11.4 Behavioral compatibility fixtures

Create a small corpus of high-level v1.0 policies representing established
consumer intent. Run them through the latest v1 SDK and verify:

- they still compile or deserialize;
- they normalize to the same `ExecutionRequest` intent;
- newly added optional fields remain absent unless requested;
- defaults and presence meaning have not changed;
- advancing the exact emitted version does not change existing behavior.

Compare normalized intent rather than serialized JSON bytes because the exact
version and additive wire shape are expected to advance.

For every typed SDK request represented in the corpus, construct the
equivalent exact JSON request and prove that both lanes produce equivalent
`CommonRequestIR` and normalized `ExecutionRequest` intent. This equivalence
test is a publication gate; production typed SDK calls must not use the JSON
lane to achieve equivalence.

## 12. File-level implementation inventory

Every implementation pull request must inspect and update the applicable
surfaces below.

### 12.1 Contract and registry

- `src/core/mxc_config_contract/src/registry.rs`;
- the published v0.9 module used as the `1.0.0` source;
- the mutable `src/core/mxc_config_contract/src/dev/` contract that changes
  identity from v0.10 to `1.1.0`;
- exact-contract adapters into `CommonRequestIR`;
- parser and state-aware request-root dispatch.

### 12.2 Canonical and generated artifacts

- `schemas/schema-version.json`;
- stable `1.0.0` schema;
- development `1.1.0` schema;
- generated `1.0.0` and `1.1.0` TypeScript wire oracles;
- schema and TypeScript codegen checks;
- stable-history protection.

### 12.3 Fixtures and tests

- exact request-root fixture directories;
- valid and invalid root fixtures;
- alias rejection fixtures for `1.0.0`;
- proof that v0.10-only fields and roots fail under `1.0.0`;
- `1.0.0` to `1.1.0` compatibility classifications;
- raw historical contract regression tests.

### 12.4 SDK and binding surfaces

- Rust `mxc-sdk` high-level policy and builders;
- typed Rust state-aware lifecycle request types and public APIs;
- direct Rust SDK adapters into `CommonRequestIR`;
- typed engine entry points that bypass exact JSON parsing;
- separately named raw JSON configuration and lifecycle entry points;
- Node public policy, raw `ContainerConfig`, state-aware API, README, and
  conformance tests;
- .NET policy and lifecycle APIs, README, reference assembly, and tests;
- co-versioned typed FFI request adaptation and generated-binding parity;
- Node typed-transport design and implementation record;
- SDK exact-target synchronization.

### 12.5 CI and documentation

- exact-contract codegen and fixture gates;
- schema-version synchronization;
- Rust, TypeScript, and .NET source-compatibility gates;
- `docs/versioning.md`;
- SDK documentation and migration guidance.

## 13. Suggested PR and release boundaries

| Step | Scope |
| --- | --- |
| 13c — Rust typed SDK transport | Before Phase 14, add typed engine entry points, direct Rust SDK adapters into `CommonRequestIR`, typed state-aware APIs, raw JSON API separation, and typed-versus-raw equivalence tests on the current v0.9/v0.10 line |
| 14a — Compatibility foundations | Canonical SDK-major target metadata, adjacent-contract comparator, semantic-review manifest format, and initial SDK API baseline tooling |
| 14b — Exact `1.0.0` contract | Create `1.0.0` from v0.9, remove aliases, add stable registry/schema/types/fixtures/adapters/parser dispatch, and prove v0.10-only surfaces are rejected |
| 14c — v1 SDK boundary | Apply the Rust, Node, .NET, and FFI high-level v1 API changes, preserve the direct Rust transport, remove high-level legacy network authoring, and target `1.0.0` |
| 14d — .NET and Node transport | Add typed co-versioned FFI and migrate .NET high-level lifecycle calls; complete the Node transport design and typed implementation or record an explicit reviewed constraint and follow-up |
| v1.0 release checkpoint | Complete validation and release the v1.0 SDKs and runtime while the canonical v1 target is `1.0.0` |
| 14e — Rename v0.10 to `1.1.0` | Rename the existing development contract and artifacts without reconstructing features, advance the canonical v1 SDK target, and remove v0.10 identities |
| 14f — Enforce v1.1 compatibility | Check `1.0.0` to `1.1.0`, add semantic classifications, compile v1.0 consumers against v1.1 SDKs, and run behavioral compatibility fixtures |
| 14g — Documentation and cleanup | Complete migration guidance, remove obsolete aliases and identities, and verify canonical documentation |

Phase 14 may not start until 13c is complete. Implement 14d after the Phase 13c
seam is stable and the v1 API boundary has consumed it. Merge the required
.NET and Node work before the v1.0 release checkpoint.

## 14. Validation

### 14.1 Phase 13c Rust transport

- typed one-shot and state-aware calls bypass JSON serialization and exact
  parsing;
- typed and exact-JSON inputs produce equivalent `CommonRequestIR` and
  `ExecutionRequest` intent;
- raw exact-JSON APIs retain diagnostics and compatibility;
- typed public API compile tests cover every lifecycle operation;
- default and applicable feature-gated Rust SDK, engine, and FFI suites pass.

### 14.2 Exact `1.0.0`

- exact stable `1.0.0` schema and TypeScript code generation;
- `1.0.0` request-root fixture validation;
- alias rejection fixtures;
- proof that every v0.10-only surface is rejected by `1.0.0`;
- adapter-to-`CommonRequestIR` and runtime normalization tests;
- raw legacy-contract regression tests;
- stable-schema immutability and published-registry history checks.

### 14.3 v1 SDK release

- typed Rust one-shot and state-aware calls reach `CommonRequestIR` without
  JSON serialization or exact JSON parsing;
- equivalent typed Rust and exact JSON requests produce equivalent
  `CommonRequestIR` and `ExecutionRequest` intent;
- raw Rust state-aware JSON APIs remain available but are explicitly separated
  from the high-level typed surface;
- .NET high-level lifecycle calls use the co-versioned typed FFI path;
- the Node transport decision and implementation status are explicit, tested,
  and not represented as typed merely because parsing produces typed runtime
  operations;
- Rust, Node, .NET, and FFI high-level semantic equivalence;
- directional-only SDK compile-time and runtime tests;
- canonical exact-target synchronization at `1.0.0`;
- API removal and migration diagnostics;
- package and schema version synchronization.

### 14.4 `1.1.0` development

- fixture and codegen coverage for every former v0.10 item;
- no v0.10 identity or artifact remains;
- canonical exact-target synchronization at `1.1.0`;
- `1.0.0` to `1.1.0` compatibility-classifier tests;
- semantic-review manifest completeness;
- SDK source-compatibility checks proving existing v1.0 consumers still build;
- behavioral fixtures proving existing intent is unchanged;
- explicit tests for every newly available optional field and backend.

## 15. Phase 14 exit criteria

Phase 14 is complete when:

1. high-level SDK APIs target the latest minor in the v1 major line without
   caller-selected exact config versions;
2. Phase 14 preserves the Phase 13c invariant that high-level Rust one-shot and
   state-aware APIs adapt typed input directly into `CommonRequestIR` without
   serializing or parsing JSON;
3. raw configuration and raw state-aware APIs still require exact registered
   versions and are clearly separated from high-level typed APIs;
4. typed Rust and exact JSON requests have publication-gated semantic
   equivalence without sharing the production ingress path;
5. .NET high-level state-aware calls use a typed co-versioned FFI request
   rather than UTF-8 JSON;
6. the Node typed-transport outcome is implemented or an explicit reviewed
   architecture decision records the remaining constraint and follow-up;
7. v1 high-level policy is directional-network-only;
8. published `1.0.0` derives from the v0.9 baseline with compatibility aliases
   removed;
9. `1.0.0` contains none of the v0.10-only items;
10. the former v0.10 development contract is now the sole mutable `1.1.0`
   contract;
11. SDK 1.0 targets `1.0.0` and SDK 1.1 targets `1.1.0`;
12. existing v1.0 SDK consumer source remains valid against the v1.1 SDK unless
   it opts into a new feature;
13. exact-contract, semantic, behavioral, and SDK compatibility gates protect
   future v1.x evolution;
14. no v0.10 identity or artifact remains;
15. no rolling parser, rolling SDK contract interpreter, runtime
    `VersionSemantics`, or same-major parser fallback is introduced.

## 16. Non-goals

Phase 14 does not:

- change immutable v0.6-v0.9 contracts;
- preserve v0.9 compatibility aliases in `1.0.0`;
- preserve legacy networking in the v1 high-level SDK;
- promote v0.10-only features into `1.0.0`;
- delete and later reconstruct the v0.10 development feature set;
- infer the oldest representable contract for execution;
- make runtime dispatch select parsers by compatible ranges;
- combine every historical config shape into one SDK policy union;
- redesign backend execution;
- remove explicit raw exact-JSON APIs;
- reject positional JSON arrays accepted by Serde struct deserialization.
