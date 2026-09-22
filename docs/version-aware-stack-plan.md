# Version-Aware Stack Plan

Status: Phase 12 and Phase 13 are complete. Phase 14, which establishes the
v1 SDK line and the v1.0 exact contract, is planned but not started.

Updated: September 22, 2026.

## 1. Completed stack

The WSLC-inclusive stack was selected and merged:

| Phase | PR | Merge commit | Result |
| --- | --- | --- | --- |
| Phase 12 | #1187 | `c531de65` | Published v0.9 with stable WSLC support |
| Phase 13 core | #1188 | `be9c377d` | Removed the rolling configuration architecture |
| Phase 13 follow-ups | #1189 | `8ac67daf` | Hardened exact-contract infrastructure |

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

## 3. Phase 14 outcome

Phase 14 establishes:

- the v1 high-level SDK API line;
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

## 4. v1.0.0 contract boundary

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

## 5. v0.10 becomes v1.1.0

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

## 6. Contract transition sequence

The transition preserves exactly one mutable development contract throughout.

### 6.1 Add and release `1.0.0`

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

### 6.2 Release the v1.0 SDKs

At the release checkpoint:

1. high-level Rust, Node, and .NET APIs target the v1 major line;
2. their package-owned exact target is `1.0.0`;
3. raw configuration APIs remain exact-versioned;
4. the v1 SDKs and runtime are validated and released together;
5. no `1.1.0` SDK target is enabled before the v1.0 release is complete.

### 6.3 Rename v0.10 development to `1.1.0`

After the v1.0 release:

1. rename the existing v0.10 development identity to `1.1.0`;
2. rename its generated artifacts, fixtures, constants, tests, and
   documentation without removing and restoring feature content;
3. advance the v1 SDK exact target from `1.0.0` to `1.1.0`;
4. classify every `1.0.0` to `1.1.0` contract difference;
5. prove existing v1.0 SDK consumer source remains valid;
6. remove all remaining v0.10 identities and generated artifacts.

## 7. Canonical SDK exact targets

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

## 8. SDK work

### 8.1 Rust

The v1 Rust high-level API:

- removes caller selection of an exact config version;
- targets the v1 major line and its canonical latest minor;
- exposes directional network policy only;
- preserves exact-version selection in raw configuration APIs;
- retains backend validation and current runtime semantics;
- uses non-exhaustive or otherwise additive public types where minor releases
  may add variants.

### 8.2 Node

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

### 8.3 .NET and FFI

The v1 .NET high-level API:

- removes caller-selected exact config versions;
- exposes directional network policy only;
- targets the canonical latest v1 minor;
- keeps raw exact-configuration entry points versioned.

The private FFI request is a co-versioned binding contract, not an MXC
configuration contract. It must not recreate a public multi-version config
model.

State-aware JSON transport may remain temporarily, but the SDK owns its exact
target version. Replacing that transport with typed FFI is independent
optimization work.

## 9. Legacy networking removal

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

## 10. v1.x compatibility gates

### 10.1 Exact-contract structural comparison

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

### 10.2 Semantic review manifests

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

### 10.3 SDK source-compatibility gates

Capture public API baselines when v1.0 is published:

- Rust: run `cargo-semver-checks` against the v1.0 baseline and compile
  representative v1.0 consumer fixtures;
- TypeScript: compile v1.0 consumer fixtures with `tsc --noEmit` against the
  current SDK and compare a generated public API report;
- .NET: run API compatibility against the v1.0 reference assembly and compile
  a representative v1.0 consumer project;
- FFI: retain generated-binding, status-code, and API parity gates.

### 10.4 Behavioral compatibility fixtures

Create a small corpus of high-level v1.0 policies representing established
consumer intent. Run them through the latest v1 SDK and verify:

- they still compile or deserialize;
- they normalize to the same `ExecutionRequest` intent;
- newly added optional fields remain absent unless requested;
- defaults and presence meaning have not changed;
- advancing the exact emitted version does not change existing behavior.

Compare normalized intent rather than serialized JSON bytes because the exact
version and additive wire shape are expected to advance.

## 11. File-level implementation inventory

Every implementation pull request must inspect and update the applicable
surfaces below.

### 11.1 Contract and registry

- `src/core/mxc_config_contract/src/registry.rs`;
- the published v0.9 module used as the `1.0.0` source;
- the mutable `src/core/mxc_config_contract/src/dev/` contract that changes
  identity from v0.10 to `1.1.0`;
- exact-contract adapters into `CommonRequestIR`;
- parser and state-aware request-root dispatch.

### 11.2 Canonical and generated artifacts

- `schemas/schema-version.json`;
- stable `1.0.0` schema;
- development `1.1.0` schema;
- generated `1.0.0` and `1.1.0` TypeScript wire oracles;
- schema and TypeScript codegen checks;
- stable-history protection.

### 11.3 Fixtures and tests

- exact request-root fixture directories;
- valid and invalid root fixtures;
- alias rejection fixtures for `1.0.0`;
- proof that v0.10-only fields and roots fail under `1.0.0`;
- `1.0.0` to `1.1.0` compatibility classifications;
- raw historical contract regression tests.

### 11.4 SDK and binding surfaces

- Rust `mxc-sdk` high-level policy and builders;
- Node public policy, raw `ContainerConfig`, state-aware API, README, and
  conformance tests;
- .NET policy and lifecycle APIs, README, reference assembly, and tests;
- FFI request adaptation and generated-binding parity;
- SDK exact-target synchronization.

### 11.5 CI and documentation

- exact-contract codegen and fixture gates;
- schema-version synchronization;
- Rust, TypeScript, and .NET source-compatibility gates;
- `docs/versioning.md`;
- SDK documentation and migration guidance.

## 12. Suggested PR and release boundaries

| Step | Scope |
| --- | --- |
| 14a — Compatibility foundations | Canonical SDK-major target metadata, adjacent-contract comparator, semantic-review manifest format, and initial SDK API baseline tooling |
| 14b — Exact `1.0.0` contract | Create `1.0.0` from v0.9, remove aliases, add stable registry/schema/types/fixtures/adapters/parser dispatch, and prove v0.10-only surfaces are rejected |
| 14c — v1 SDK boundary | Implement the Rust, Node, .NET, and FFI high-level v1 APIs, remove high-level legacy network authoring, and target `1.0.0` |
| v1.0 release checkpoint | Complete validation and release the v1.0 SDKs and runtime while the canonical v1 target is `1.0.0` |
| 14d — Rename v0.10 to `1.1.0` | Rename the existing development contract and artifacts without reconstructing features, advance the canonical v1 SDK target, and remove v0.10 identities |
| 14e — Enforce v1.1 compatibility | Check `1.0.0` to `1.1.0`, add semantic classifications, compile v1.0 consumers against v1.1 SDKs, and run behavioral compatibility fixtures |
| 14f — Documentation and cleanup | Complete migration guidance, remove obsolete aliases and identities, and verify canonical documentation |

If 14c is too large for one review, implement it as a short stacked series for
Rust, Node, and .NET/FFI. Review the stack as one API-boundary change and merge
all parts before the v1.0 release checkpoint.

## 13. Validation

### 13.1 Exact `1.0.0`

- exact stable `1.0.0` schema and TypeScript code generation;
- `1.0.0` request-root fixture validation;
- alias rejection fixtures;
- proof that every v0.10-only surface is rejected by `1.0.0`;
- adapter-to-`CommonRequestIR` and runtime normalization tests;
- raw legacy-contract regression tests;
- stable-schema immutability and published-registry history checks.

### 13.2 v1 SDK release

- Rust, Node, .NET, and FFI high-level equivalence;
- directional-only SDK compile-time and runtime tests;
- canonical exact-target synchronization at `1.0.0`;
- API removal and migration diagnostics;
- package and schema version synchronization.

### 13.3 `1.1.0` development

- fixture and codegen coverage for every former v0.10 item;
- no v0.10 identity or artifact remains;
- canonical exact-target synchronization at `1.1.0`;
- `1.0.0` to `1.1.0` compatibility-classifier tests;
- semantic-review manifest completeness;
- SDK source-compatibility checks proving existing v1.0 consumers still build;
- behavioral fixtures proving existing intent is unchanged;
- explicit tests for every newly available optional field and backend.

## 14. Phase 14 exit criteria

Phase 14 is complete when:

1. high-level SDK APIs target the latest minor in the v1 major line without
   caller-selected exact config versions;
2. raw configuration APIs still require exact registered versions;
3. v1 high-level policy is directional-network-only;
4. published `1.0.0` derives from the v0.9 baseline with compatibility aliases
   removed;
5. `1.0.0` contains none of the v0.10-only items;
6. the former v0.10 development contract is now the sole mutable `1.1.0`
   contract;
7. SDK 1.0 targets `1.0.0` and SDK 1.1 targets `1.1.0`;
8. existing v1.0 SDK consumer source remains valid against the v1.1 SDK unless
   it opts into a new feature;
9. exact-contract, semantic, behavioral, and SDK compatibility gates protect
   future v1.x evolution;
10. no v0.10 identity or artifact remains;
11. no rolling parser, rolling SDK contract interpreter, runtime
    `VersionSemantics`, or same-major parser fallback is introduced.

## 15. Non-goals

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
- reject positional JSON arrays accepted by Serde struct deserialization.
