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
- the SDK owns the exact minor contract emitted or constructed internally;
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
- the exact v1.0 development contract;
- the exact v1.1 development contract after v1.0 publication;
- compatibility gates for future v1.x contract and SDK evolution.

Phase 14 is the intentional public-API break boundary. It must not be combined
with unrelated backend redesign.

## 4. v1.0 contract boundary

The v1.0 exact contract starts from published v0.9:

```text
published v0.9
      |
      v
development v1.0
```

v1.0 must remain a conservative baseline:

- copy the published v0.9 accepted shape;
- change the exact version spelling to v1.0;
- retain the exact-contract, adapter, and `CommonRequestIR` architecture;
- make only changes required for the approved v1 SDK boundary;
- do not introduce any v0.10-only field, request root, containment, alias, or
  test feature;
- do not add features merely to justify the major-version increment.

The v1 high-level SDK policy exposes directional networking only. Legacy
network authoring remains available solely through the immutable v0.6-v0.8 raw
JSON contracts.

## 5. v0.10 disposition

The v0.10 development contract is not promoted into v1.0.

Every v0.10-only item is deferred to the v1.1 development contract:

| Item | v0.10 surface | v1.0 | v1.1 development |
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
phase roots are already part of v0.9 and therefore form part of the v1.0
baseline.

## 6. Contract transition sequence

The transition must preserve exactly one mutable development contract.

### 6.1 Establish the v1.0 candidate

1. Copy published v0.9 into a new exact v1.0 development module.
2. Add v1.0 registry identity, schema generation, TypeScript generation,
   fixtures, adapters, and parser dispatch.
3. Apply the approved v1 high-level SDK changes.
4. Remove the mutable v0.10 development identity and artifacts.
5. Verify that no v0.10-only surface is reachable from a v1.0 request root.
6. Validate v1.0 as the sole development contract.

### 6.2 Publish v1.0

Publication is mechanical:

1. mark v1.0 published in the registry;
2. move its exact schema and generated TypeScript contract to their stable
   locations;
3. verify the published Rust model regenerates the committed stable artifacts;
4. activate stable-schema and registry-history protection;
5. make no parser, adapter, SDK, or runtime redesign in the publication step.

### 6.3 Open v1.1 development

Immediately after v1.0 publication:

1. copy published v1.0 into the exact v1.1 development module;
2. add every item listed in [v0.10 disposition](#5-v010-disposition);
3. restore the associated adapters, fixtures, schemas, generated TypeScript
   types, SDK affordances, and backend routing under v1.1;
4. verify each addition is compatible with existing v1.0 consumers;
5. remove all remaining v0.10 identities and generated artifacts.

## 7. SDK work

### 7.1 Rust

The v1 Rust high-level API:

- removes caller selection of an exact config version;
- targets the v1 major line;
- exposes directional network policy only;
- preserves exact-version selection in raw configuration APIs;
- retains backend validation and current runtime semantics;
- uses non-exhaustive or otherwise additive public types where minor releases
  may add variants.

The package-owned exact contract target may advance from v1.0 to v1.1 without
requiring changes to existing consumer source.

### 7.2 Node

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

High-level calls target the package-owned v1 contract. Raw APIs such as
`spawnSandboxFromConfig`, config-file execution, and explicit
`ContainerConfig` construction continue to require exact versions.

New v1.x policy fields and backend options must be optional additions.

### 7.3 .NET and FFI

The v1 .NET high-level API:

- removes caller-selected exact config versions;
- exposes directional network policy only;
- targets the v1 major line;
- keeps raw exact-configuration entry points versioned.

The private FFI request is a co-versioned binding contract, not an MXC
configuration contract. It must not recreate a public multi-version config
model.

State-aware JSON transport may remain temporarily, but the SDK owns its exact
target version. Replacing that transport with typed FFI is independent
optimization work.

## 8. Legacy networking removal

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

## 9. v1.x compatibility gates

### 9.1 Exact-contract classification

The compatibility tool compares exact contracts within one major line:

| Change | Classification |
| --- | --- |
| Add optional field | Compatible |
| Add request root | Compatible, subject to SDK API review |
| Add containment/backend value | Compatible only if SDK public types remain source-compatible |
| Relax a local constraint | Compatible with semantic review |
| Remove or rename field/root | Breaking |
| Make optional input required | Breaking |
| Narrow type, range, pattern, or enum | Breaking |
| Change default or presence meaning | Semantic review required |
| Change adapter or runtime meaning | Semantic review required |

The gate must reject same-major structural breaks and require an explicit
decision for semantic changes.

### 9.2 SDK source-compatibility review

Contract compatibility alone is insufficient. Each minor release must also
check:

- Rust public API compatibility;
- TypeScript source compatibility;
- .NET public API and binary compatibility;
- FFI parity;
- unchanged behavior for existing high-level policy construction;
- raw exact-config conformance.

## 10. Validation

### v1.0 candidate

- exact v1.0 schema and TypeScript code generation;
- v1.0 request-root fixture validation;
- proof that every v0.10-only surface is rejected by v1.0;
- adapter-to-`CommonRequestIR` and runtime normalization tests;
- Rust, Node, .NET, and FFI high-level equivalence;
- directional-only SDK compile-time and runtime tests;
- raw legacy-contract regression tests;
- API removal and migration diagnostics.

### v1.0 publication

- stable-schema immutability checks;
- published-registry history checks;
- exact Rust-model-to-stable-artifact regeneration;
- schema-version and package-version synchronization;
- no mutable v1.0 development artifact remains.

### v1.1 development

- fixture and codegen coverage for every deferred v0.10 item;
- v1.0-to-v1.1 compatibility-classifier tests;
- SDK source-compatibility checks proving existing v1.0 consumers still build;
- explicit tests for every newly available optional field and backend;
- no v0.10 identity or artifact remains.

## 11. Phase 14 exit criteria

Phase 14 is complete when:

1. high-level SDK APIs target the v1 major line without caller-selected exact
   config versions;
2. raw configuration APIs still require exact registered versions;
3. v1 high-level policy is directional-network-only;
4. v1.0 is published from the v0.9 baseline;
5. v1.0 contains none of the v0.10-only items;
6. v1.1 is the sole mutable development contract;
7. every v0.10-only item is represented in v1.1 development;
8. existing v1.0 SDK consumer source remains valid against the v1.1 SDK unless
   it opts into a new feature;
9. exact-contract and SDK compatibility gates protect future v1.x evolution;
10. no rolling parser, rolling SDK contract interpreter, runtime
    `VersionSemantics`, or same-major parser fallback is introduced.

## 12. Non-goals

Phase 14 does not:

- change immutable v0.6-v0.9 contracts;
- preserve legacy networking in the v1 high-level SDK;
- promote v0.10-only features into v1.0;
- infer the oldest representable contract for execution;
- make runtime dispatch select parsers by compatible ranges;
- combine every historical config shape into one SDK policy union;
- redesign backend execution;
- reject positional JSON arrays accepted by Serde struct deserialization.
