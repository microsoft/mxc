# Version-Aware Stack Plan

Status: proposed implementation plan and decision record.

Date: September 14, 2026.

Base:
`origin/user/gudge/version_specific_config_parsers_phase10b` at `a6176ac9`
(`Complete the v0.9 directional networking cutover`).

## 1. Purpose

This plan replaces the former Phase 11 direction with a smaller stack that:

1. publishes the v0.9 exact configuration contract;
2. graduates IsolationSession from experimental status as part of v0.9;
3. reduces the number of parser, publication, SDK-builder, and migration types;
4. prevents the post-1.0 design from recreating a rolling parser or rolling
   SDK contract interpreter;
5. starts the v1.0 contract and SDK work, with v1.0 expected to remain close to
   v0.9 unless a deliberate breaking change is required.

The implementation uses three substantive pull requests. A later v1.0
publication pull request may be added if the v1.0 candidate needs a separate
validation period.

## 2. Core decisions

### 2.1 Configuration and SDK versions are separate axes

Configuration versions describe external JSON contracts:

- configuration files;
- command-line and base64 input;
- raw SDK configuration APIs;
- Node-to-executor JSON;
- schema validation and replay.

SDK package versions describe typed APIs:

- Rust `SandboxPolicy` and `SandboxRequest`;
- .NET policy and request classes;
- Node high-level policy and lifecycle APIs.

A direct typed SDK call does not select or infer a configuration contract.

### 2.2 Exact dispatch remains the JSON trust boundary

Every external JSON document must declare one exact registered version:

```text
raw JSON
  -> exact ContractVersion
  -> exact version-specific Request
  -> version-specific adapter
  -> shared normalization
```

There is no:

- missing-version fallback;
- supported-version range dispatch;
- same-major parser fallback;
- latest-version fallback;
- "deserialize latest and reject later fields" path.

A document declaring v1.0 must always be parsed through the frozen v1.0
contract, even after v1.1 and v1.2 exist.

### 2.3 Compatibility is a relationship between exact contracts

Post-1.0 compatibility tooling compares exact contract versions. It does not
change runtime parser selection.

Compatible minor-version evolution may add:

- optional fields;
- new request roots;
- explicitly extensible values.

Same-major releases may not:

- remove or rename fields or roots;
- make optional input required;
- narrow accepted values;
- change the meaning of existing input.

Defaults, presence semantics, adapter mapping, backend validation, and runtime
behavior require explicit semantic review.

### 2.4 The SDK is not a rolling configuration parser

The current typed SDK model describes current typed intent. It is not a union
of every historical JSON contract and does not use a `VersionSemantics` table
to reinterpret that intent as different config versions.

Historical exact JSON remains available through raw config APIs.

### 2.5 Only actual contract versions get contract types

The stack does not add a publication-specific projection of a development
contract.

Every request type belongs to:

- an actual published exact contract; or
- the one actual mutable development contract.

There is no parallel `PublicationProfile` request hierarchy.

## 3. Target architecture

```text
UNTRUSTED JSON                         DIRECT TYPED SDK

exact version probe                    package/API version
        |                                     |
        v                                     v
exact contract Request                  SandboxPolicy
        |                                     |
version-specific adapter                 SDK adapter
        |                                     |
        +----------------+--------------------+
                         |
                    ConfigInput
                         |
                  ExecutionRequest
                         |
                      backend
```

Node remains a JSON producer when it launches an executor:

```text
Node SandboxPolicy
  -> package-owned exact contract encoder
  -> versioned JSON
  -> executor exact parser
```

Raw Node configuration APIs continue to expose the exact version.

## 4. Pull request stack

```text
origin/...phase10b (a6176ac9)
        |
        +-- PR 1: Publish v0.9 and graduate IsolationSession
        |
        +-- PR 2: Collapse parser and runtime representations
        |
        `-- PR 3: Establish the v1 SDK and v1.0 contract candidate
                  |
                  `-- optional: mechanical v1.0 publication
```

These are the minimum sensible boundaries:

- PR 1 intentionally changes the published contract and product support.
- PR 2 is a behavior-preserving internal simplification protected by the v0.9
  freeze.
- PR 3 intentionally changes public SDK APIs and starts the v1 contract line.

Combining these boundaries would make it difficult to distinguish publication
errors, refactoring regressions, and intended v1 API changes.

## 5. PR 1: Publish v0.9 and graduate IsolationSession

### 5.1 Outcome

Before:

```text
published:    v0.6, v0.7, v0.8
development:  v0.9
```

After:

```text
published:    v0.6, v0.7, v0.8, v0.9
development:  v0.10
```

The lifecycle transition is atomic. No candidate status or parallel
publication contract is required.

### 5.2 Contract sequence

1. Copy the complete Phase 10b v0.9 development contract forward to v0.10.
2. Change the copied contract's exact version, generated schema path,
   TypeScript oracle, fixtures, adapter, and registry identity.
3. Finalize the actual v0.9 contract contents.
4. Copy the final actual v0.9 module into
   `published/v0_9_0_alpha`.
5. Mark v0.9 published and v0.10 development in the exact registry.
6. Generate and record v0.9 schema and behavior freeze evidence.

Publication must not transform or project the candidate shape. The exact v0.9
module tested before publication is the module that becomes published.

### 5.3 IsolationSession graduation

Published v0.9 includes:

- one-shot `isolation_session` containment;
- its required directional all-allow network posture;
- state-aware IsolationSession provision;
- shared state-aware start, exec, stop, and deprovision roots;
- permanent `isolationSession.provision.appId` placement;
- stable telemetry fields reachable from those roots.

Remove IsolationSession experimental authorization from:

- executor dispatch;
- `mxc_engine`;
- Rust SDK;
- FFI;
- .NET SDK;
- Node SDK;
- platform discovery;
- examples and documentation.

Selecting IsolationSession no longer requires:

```text
--experimental
SandboxRequest::set_experimental(true)
experimental: true
```

IsolationSession may remain compile-time feature-gated where required by the
build, but it is no longer a runtime experimental feature.

### 5.4 Permanent development field locations

Remove the JSON `experimental` wrapper from v0.9 and v0.10.

Development fields use their intended permanent locations:

```text
experimental.isolation_session -> isolationSession
experimental.windows_sandbox   -> windowsSandbox
experimental.wslc              -> wslc
experimental.test              -> test
```

Location, publication eligibility, and execution authorization are separate:

| Concern | Authority |
|---|---|
| JSON location and shape | Exact contract |
| Publication eligibility | Actual published contract contents |
| Runtime authorization | Engine/SDK execution gate |

For v0.9:

- include IsolationSession;
- include only other fields and roots that are independently approved for
  graduation;
- structurally reject ungraduated fields and containments;
- do not retain empty placeholders.

For v0.10:

- retain ungraduated development features at permanent locations;
- retain runtime authorization for features that remain experimental.

Unless separately decided, Windows Sandbox, WSLC, MicroVM, Hyperlight, and the
test feature do not graduate in v0.9.

### 5.5 Publication and freeze tooling

Retain the useful Phase 11a concepts:

- Rust registry as lifecycle source of truth;
- generated machine-readable registry;
- immutable schema digest;
- exact accepted/rejected fixtures;
- adapter-to-runtime snapshots;
- field-presence snapshots;
- builder/parser equivalence while builders remain;
- backend dispatch observations;
- base-ref-aware CI checks.

Do not add:

- `PublicationProfile`;
- publication `StateAwareBackend`;
- publication-specific `Containment`;
- publication-specific one-shot or state-aware request roots;
- a stable-candidate type family parallel to the v0.9 contract.

### 5.6 PR 1 exit criteria

- v0.9 is registered as published.
- v0.10 is the only mutable development contract.
- v0.9 accepts the intended stable one-shot surface.
- v0.9 accepts IsolationSession one-shot and state-aware requests.
- IsolationSession executes without experimental authorization.
- v0.9 rejects every ungraduated field, root, and containment.
- v0.10 retains ungraduated development features.
- repository configs using those features declare v0.10.
- published v0.6-v0.8 contracts and schemas are unchanged.
- v0.9 shape and adapter/runtime behavior are frozen.

## 6. PR 2: Collapse parser and runtime representations

### 6.1 Outcome

This PR is behavior-preserving against the newly published v0.9 contract.

It reduces the architecture to:

```text
exact Request
  -> exact adapter
  -> ConfigInput
  -> ExecutionRequest
```

State-aware input becomes:

```text
ExecutionRequest + StateAwareOperation
```

with no retained backend JSON or source text.

### 6.2 Repurpose the rolling wire model

Rename:

```text
wire::MxcConfig -> config_input::ConfigInput
```

Keep approximately the current fields and nested types. Do not introduce a
parallel normalization hierarchy.

Remove from `ConfigInput` and its nested types:

- `Deserialize`;
- `JsonSchema`;
- schema generation;
- external wire-contract documentation;
- version-range validation;
- production or test parser entry points.

Exact adapters construct `ConfigInput` after exact structural validation.
Direct SDK adapters construct the same type from current typed intent.

Rename:

```text
convert_wire_config -> convert_config_input
```

### 6.3 Delete rolling and migration implementations

Delete:

- rolling whole-request parser;
- rolling loader APIs;
- rolling policy-builder oracle;
- rolling `-dev` schema;
- rolling generated TypeScript `wire.ts`;
- `--legacy-wire` code generation;
- rolling-versus-exact executable comparisons;
- `legacy_payload_reference.rs`;
- `legacy_state_aware_request.rs`;
- `LegacyStateAwareWireInput`;
- `LegacyStateAwareRequest`;
- `LegacyMxcRequest`;
- successful-request source retention;
- dispatch-time backend JSON reparsing;
- obsolete divergence classifications.

Replace useful evidence with:

- direct exact acceptance/rejection fixtures;
- diagnostic regressions;
- exact adapter/runtime snapshots;
- independent state-aware dispatch expectations.

### 6.4 Retain typed state-aware operations

Retain:

- `StateAwareProvision`;
- `StateAwareOperation`;
- `ParsedStateAwareRequest`;
- `BoundStateAwareOperation<B>`;
- `BoundStateAwareRequest<B>`;
- backend-associated phase config types.

These types remove independent phase, containment, sandbox ID, raw payload, and
source-text authorities. They are shared across every config version and do
not grow per minor release.

### 6.5 Remove config-version-driven backend behavior

`ExecutionRequest::schema_version` currently serves two unrelated purposes:

- telemetry attribution;
- runtime behavior selection.

Replace source attribution with:

```rust
pub source_contract: Option<ContractVersion>,
```

Only diagnostics and telemetry may inspect it:

- exact JSON input sets `Some(version)`;
- direct typed SDK input sets `None`.

Represent execution behavior explicitly on existing normalized types. For
network compatibility, add a field such as:

```rust
pub strict_network_enforcement: bool,
```

Exact adapters set the effective behavior:

```text
v0.6/v0.7 -> compatibility posture where required
v0.8+     -> strict posture
direct SDK -> strict posture
```

Directional policy remains visible through existing normalized fields:

```text
network_egress
network_ingress
network_proxy
```

Delete:

- `supports_directional_network`;
- `directional_network_support`;
- `schema_enforces_network_strictly`;
- backend SemVer parsing;
- malformed-version fallback behavior inside backends.

### 6.6 De-wire runtime types

Retain but restrict:

- `ExecutionRequest`;
- `ContainerPolicy`;
- `IsolationSessionProvisionConfig`;
- `WslcProvisionConfig`;
- other backend runtime configuration types.

Remove unnecessary `Serialize`/`Deserialize` implementations and public
fields. These types are internal runtime models, not alternative wire
contracts.

### 6.7 PR 2 exit criteria

- exact v0.6-v0.10 parsing is unchanged;
- published v0.9 freeze evidence remains unchanged;
- no rolling whole-request parser is compiled in production or tests;
- `ConfigInput` cannot be deserialized externally;
- successful state-aware requests retain no raw JSON or source text;
- backends perform no config SemVer parsing;
- only exact contracts and adapters grow per config version.

## 7. PR 3: Establish the v1 SDK and v1.0 contract candidate

### 7.1 Outcome

This PR:

- removes config versions from direct typed SDK execution;
- makes the current SDK policy directional-only;
- deletes per-version SDK execution builders;
- creates the exact v1.0 development contract;
- adds the compatibility gates needed before a future v1.1.

This is the appropriate pull request for intentional public API breaks.

### 7.2 Rust SDK

Remove:

```rust
SandboxPolicy::version
```

The direct path becomes:

```text
SandboxPolicy
  -> ConfigInput
  -> ExecutionRequest
  -> SandboxRequest
```

Delete direct-execution use of:

```text
policy/exact/v0_6.rs
policy/exact/v0_7.rs
policy/exact/v0_8.rs
policy/exact/v0_9.rs
policy/exact/v0_10.rs
ExactOneShotContract
```

Do not retain historical config encoders speculatively. Add an explicit config
serialization feature later only if a concrete caller requires it.

### 7.3 Current SDK network model

The v1 typed SDK exposes current directional policy only.

Remove from current Rust, Node, and .NET high-level policy types:

- `allowOutbound`;
- `allowLocalNetwork`;
- `allowedHosts`;
- `blockedHosts`;
- legacy `proxy`;
- legacy authored-presence tracking;
- compatibility JSON converters used only by a multi-version SDK model;
- `NetworkFormat`;
- version-dependent format selection.

Legacy network syntax remains supported by the frozen v0.6-v0.8 exact JSON
contracts.

### 7.4 .NET and FFI

Remove:

- `.NET SandboxPolicy.Version`;
- FFI `RequestPolicy.version`;
- config-version validation from one-shot Run/Spawn;
- caller-selected config versions from high-level state-aware options.

One-shot becomes:

```text
.NET SandboxRequest
  -> private FFI RequestSpec
  -> ConfigInput
  -> ExecutionRequest
```

The FFI request is a co-versioned binding format, not an MXC configuration
contract.

State-aware .NET may continue to emit exact JSON initially. The high-level SDK
owns the emitted version; the caller does not select it. Replacing that JSON
transport with a typed FFI operation is separate optimization work.

### 7.5 Node

Separate high-level policy from raw config:

```typescript
type SandboxPolicy = {
  // no config version
};

interface ContainerConfig {
  version: string;
  // exact raw config
}
```

High-level calls target the package's bundled exact contract:

```text
spawnSandbox(policy)
  -> bundled exact JSON
  -> executor
```

Exact versions remain required for:

- raw `ContainerConfig`;
- `spawnSandboxFromConfig`;
- config files;
- explicit raw config construction.

Normal high-level execution does not infer the oldest representable contract.

### 7.6 v1.0 exact contract

Create v1.0 by copying the published v0.9 exact contract as the initial
development shape:

```text
published v0.9
       |
       v
development v1.0
```

Keep v1.0 close to v0.9. Differences must be deliberate, for example:

- exact version spelling;
- approved removal of obsolete compatibility aliases;
- removal of pre-v1 deprecated fields;
- final naming cleanup;
- changes required by the v1 SDK boundary.

Do not add changes merely to justify the major version.

The v1.0 adapter may share private conversion helpers with v0.9, but v1.0
retains its own exact request root and adapter entry point.

### 7.7 Post-1.0 compatibility gate

Add a classifier that compares exact contracts:

| Change | Classification |
|---|---|
| Add optional field | Structurally compatible |
| Add request root | Structurally compatible |
| Relax local constraint | Compatible with semantic review |
| Remove/rename field or root | Breaking |
| Make optional field required | Breaking |
| Narrow type, range, pattern, or enum | Breaking |
| Change default or presence meaning | Semantic review required |
| Change adapter/runtime meaning | Semantic review required |

Before v1.0 publication:

- same-major breaking changes must be rejected;
- semantic changes must require an explicit decision;
- adapter and normalization snapshots must be reviewed independently;
- the classifier must not participate in runtime dispatch.

Do not introduce:

- `VersionSemantics`;
- same-major parser fallback;
- latest-version parsing;
- automatic oldest-representable selection for execution;
- one SDK union containing every historical config shape.

### 7.8 PR 3 exit criteria

- direct Rust and one-shot .NET calls contain no config version;
- Node high-level calls hide their package-owned exact target;
- raw config APIs continue requiring exact versions;
- current SDK policies are directional-only;
- per-version SDK execution builders are removed;
- v1.0 exists as an exact development contract;
- v1.0 remains intentionally close to v0.9;
- compatibility tooling is ready for a future v1.1.

## 8. Optional v1.0 publication PR

If the v1.0 candidate needs a separate validation period, publication should
be a small mechanical pull request:

- mark v1.0 published;
- move its exact schema to stable;
- record schema and behavior digests;
- open the next development contract;
- update release documentation.

No parser, adapter, SDK, or runtime redesign belongs in this publication PR.

If the candidate evidence is already sufficient, this mechanical transition
may be included at the end of PR 3.

## 9. Type-growth result

After the three substantive pull requests, each config version adds only:

```text
exact contract type family
+ exact adapter
```

The shared types exist once:

```text
ConfigInput
ExecutionRequest
ContainerPolicy
StateAwareOperation
BoundStateAwareRequest<B>
SandboxPolicy per SDK language
```

Growth:

```text
v0.6 contract + adapter --+
v0.7 contract + adapter --+
v0.8 contract + adapter --+--> ConfigInput --> ExecutionRequest
v0.9 contract + adapter --+
v1.0 contract + adapter --+

Rust/.NET SDK ----------------^
Node exact JSON encoder -------^
```

The stack does not grow:

- publication request projections;
- per-version SDK builders;
- runtime version-semantics tables;
- rolling parser unions;
- per-version backend request models.

## 10. Types retained, removed, and not introduced

### Retained

- `ContractVersion`
- `ContractDescriptor`, `ContractStatus`, and `CONTRACTS`
- actual exact published and development request types
- exact version-specific adapters
- `ExecutionRequest`
- `ContainerPolicy`
- `SandboxPolicy`, `Containment`, and `SandboxRequest`
- `StateAwareProvision`
- `StateAwareOperation`
- `ParsedStateAwareRequest`
- `BoundStateAwareOperation<B>`
- `BoundStateAwareRequest<B>`
- raw Node `ContainerConfig`

### Repurposed

- `wire::MxcConfig` -> private `ConfigInput`
- nested `wire::*` types -> private normalization DTOs
- `ExecutionRequest::schema_version` -> source-only
  `Option<ContractVersion>`

### Removed

- rolling parser and loader
- rolling schema and TypeScript model
- rolling builder oracle
- complete legacy state-aware reference implementation
- raw backend payload and source retention
- publication projection types
- direct SDK config-version fields
- per-version direct SDK builders
- current SDK legacy network authoring types
- backend schema-version parsing helpers

### Not introduced

- `PublicationProfile`
- publication-specific request roots
- `VersionSemantics`
- `NormalizationInput` sub-type hierarchy
- automatic oldest-representable execution inference
- same-major runtime parser fallback

## 11. Validation strategy

### PR 1

- exact contract tests for v0.9 and v0.10;
- generated exact schema and TypeScript gates;
- IsolationSession one-shot and state-aware tests without experimental opt-in;
- negative tests proving ungraduated v0.9 surfaces are rejected;
- published-contract freeze checks;
- Rust, Node, .NET, and FFI parity.

### PR 2

- all published contract fixtures unchanged;
- adapter/runtime snapshot equality;
- exact diagnostic regression coverage;
- state-aware binding and dispatch tests;
- compile-time removal checks for rolling APIs;
- backend tests covering explicit strict/compatibility policy;
- no remaining rolling parser symbols or artifacts.

### PR 3

- Rust direct SDK equivalence against v1.0 exact JSON fixtures;
- .NET/FFI request equivalence;
- Node high-level emitted-config conformance;
- raw config exact-version validation;
- v1.0 contract fixtures and code generation;
- compatibility-classifier unit tests;
- API removal and migration diagnostics.

## 12. Completion criteria

The plan is complete when:

1. v0.9 is published and immutable.
2. IsolationSession is non-experimental on its published v0.9 surfaces.
3. v0.10 carries the remaining development features.
4. no rolling whole-request parser or builder survives.
5. successful state-aware requests retain no raw backend JSON.
6. direct SDK calls carry no config contract version.
7. backends do not interpret config version strings.
8. only exact contract types and adapters grow per config version.
9. v1.0 exists as an exact candidate close to v0.9.
10. future v1.x compatibility is enforced by publication tooling, not runtime
    parser fallback.
