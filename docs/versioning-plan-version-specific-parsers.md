# MXC Version-Specific Config Parsers

Status: implementation plan; Phases 1-4 merged in PRs #807, #816, #835, and
#838. Phase 4.1 and Phase 4.2 merged in PRs #907 and #912. Phase 5A and
Phase 5B are under review as GitHub stack #911 in PRs #909 and #910. Phase 5C
is in progress; Phase 5D remains to be implemented.

Base: `origin/main` at `692275b84eaa3f83cd8582dc774bc5f354f46ccf`
(2026-08-14)

## Goals

- Require every config to declare an exact registered version.
- Deserialize each published version through its own immutable Rust wire types.
- Support exact published contracts for `0.6.0-alpha` and `0.7.0-alpha`.
- Use the existing `0.8.0-alpha` version as the current mutable development
  contract.
- Keep `experimental` completely absent from published contracts.
- Make the development contract's `experimental` structure recursively closed,
  while allowing that entire unpublished contract to change freely.
- Preserve the existing source-aware Serde diagnostics, duplicate-field
  rejection, secret redaction, semantic validation, and backend behavior.
- Keep adapters from versioned wire types into the runtime model outside the
  immutable published modules.

## Non-goals

- Reproduce historical runtime bugs or security defaults.
- Make a declared version select backend behavior or weaker validation.
- Retrospectively claim that the old rolling parser enforced independent
  `0.6`, `0.7`, or `0.8` shapes.
- Introduce a JSON `Value` migration engine or a second schema-validation
  language in the runtime trust boundary.
- Edit the existing immutable `0.6` or `0.7` stable schema files.
- Reject positional JSON arrays that Serde can deserialize into structs. That
  object-root hardening is out of scope for this work in every phase.
- Introduce another development version as part of the initial parser
  conversion. `0.9.0-dev` is selected when `0.8.0-alpha` is published;
  `1.0.0` remains a later milestone.

## Contract reconstruction policy

The published schema defines each version's canonical field set and spellings.
The exact Rust contract additionally preserves an undocumented parser spelling
only when it was an explicit, lossless compatibility alias at that version:

1. The parser names the spelling in a Serde alias or dedicated match arm.
2. It maps to one canonical field or value without weakening validation.
3. It has a deprecation diagnostic or focused regression test.
4. It does not expose experimental or later-version functionality.

The compatibility matrix is:

| Versions | Compatibility spelling | Canonical spelling |
| --- | --- | --- |
| `0.6`, `0.7`, `0.8` | containment `appcontainer` | `processcontainer` |
| `0.6`, `0.7`, `0.8` | top-level `appContainer` | `processContainer` |
| `0.7`, `0.8` | containment `macos_sandbox` | `seatbelt` |
| `0.7`, `0.8` | top-level `macos_sandbox` | `seatbelt` |

`$schema` and `_comment` are normal declared fields beginning in `0.7`; their
incidental acceptance by the open `0.6` rolling parser does not backport them
into the exact `0.6` contract. Arbitrary unknown fields, parse-and-ignore
behavior, missing versions, experimental fields on published contracts, and
`experimental.macos_sandbox` after Seatbelt promotion are not preserved.

## Design note under discussion: experimental fields in published contracts

> **Status: recorded discussion, not part of the plan of record.**
>
> The goals, target contracts, and phases below still describe the earlier
> assumption that published contracts exclude `experimental`. Do not implement
> the alternative in this section until the requirement is ratified and the
> normative parts of this plan are updated.

A proposed requirement allows a published config contract (and therefore a
stable schema artifact) to include explicitly selected experimental fields.
The `experimental` object and every nested experimental object would remain
recursively closed. A later published version could promote a feature by moving
it from `experimental.<feature>` to a top-level `<feature>` field.

This separates three concepts that the current plan partly conflates:

| Concept | Meaning |
| --- | --- |
| Contract status | Whether a complete accepted JSON shape is mutable development work or an immutable published contract |
| Feature status | Whether a field is experimental or part of the top-level stable surface |
| Execution gate | Whether using the feature requires `--experimental` or another explicit opt-in |

Under this requirement, publishing would freeze the **entire accepted shape**,
including any experimental subtree included in that version. Published would
mean immutable syntax, not that every field in the contract is a mature
top-level feature.

For example:

```text
0.8.0-alpha accepts: experimental.foo
0.9.0-alpha accepts: foo
```

The two immutable contract modules would retain their respective paths while
their mutable adapters normalize both into the same canonical runtime field:

```text
v0.8 experimental.foo --\
                         +--> CanonicalRequest.foo
v0.9 foo ----------------/
```

This works naturally with exact version dispatch and avoids putting a
version-sensitive alias on one rolling wire type. The old path remains accepted
only while its published contract remains supported; the newer contract may
reject it and accept only the promoted top-level path.

### Impact if adopted

The following parts of the current plan would need revision:

- Remove the goal and target-contract rule that published contracts never
  contain `experimental`.
- Reconstruct each historical version from what that version actually
  published. The existing `0.6` and `0.7` stable schemas would still exclude
  `experimental`; a future `0.8` publication could include only the explicitly
  selected experimental fields intended for that contract.
- Allow published modules to define self-contained, recursively closed
  experimental types. Development would remain mutable, but would no longer be
  the only contract status allowed to contain experimental fields.
- Make shadow-parser expectations version-specific rather than treating
  `published version + experimental` as universally invalid.
- Classify corpus migrations by the first exact contract that defines each
  experimental field. Do not mechanically move every experimental config to
  the development version.
- Dispatch state-aware requests according to the selected contract if
  state-aware experimental shapes are ever included in a published version.
- Change publication tooling to freeze the complete selected contract rather
  than copying only a stable candidate surface. Experimental and state-aware
  types would be excluded or included deliberately per publication, not by a
  global rule.
- Generate schemas and SDK wire types that expose the exact experimental field
  set for each version.

Phase 1's exact version model, registry, and source-text probe would not change.
The per-version Rust contract and adapter architecture would also remain the
same.

### Cost and trade-off

An experimental field included in a published contract loses shape-level
mutability for that version. Adding, removing, renaming, or restructuring one
of its fields requires a new config version even though the feature remains
experimental. This is the principal cost of making experimental structures
closed and publishable.

The benefit is deterministic parsing: an experimental typo or unsupported
field is rejected rather than silently ignored, and a published version's
accepted JSON shape cannot change underneath its users.

### Decisions required before adoption

1. Does a published contract structurally accept its experimental fields even
   when `--experimental` is absent, with the flag controlling execution only?
2. If an experimental field is present without the execution opt-in, should MXC
   reject the request or preserve the current parse-and-ignore behavior?
3. Can state-aware request shapes be included in a published contract, or does
   this requirement initially apply only to one-shot experimental fields?
4. When a feature is promoted, does the new contract reject its old
   `experimental` path immediately, or provide a version-scoped transition
   spelling?
5. Which experimental fields, if any, should be selected for the first
   `0.8.0-alpha` published contract?

## Target contracts

| Status | Exact version | Contract |
| --- | --- | --- |
| Published | `0.6.0-alpha` | Stable one-shot config only |
| Published | `0.7.0-alpha` | Stable one-shot config only |
| Development | `0.8.0-alpha` | Mutable closed one-shot experimental and state-aware config |

Published request types do not contain:

- `experimental`
- `phase`
- `sandboxId`
- `correlationVector`
- experimental containment values such as `windows_sandbox`, `wslc`,
  `microvm`, `isolation_session`, or `hyperlight`
- the abstract `vm` intent while it resolves only to an experimental backend

The existing `schemas/stable/mxc-config.schema.0.5.0-alpha.json` experimental
section remains an unsupported historical artifact. No `0.5` runtime contract
will be added.

## Intended parse flow

```text
raw JSON source
    |
    v
probe required exact version (and later phase)
    |
    v
exact registry lookup
    |
    +-- 0.6.0-alpha --> published::v0_6_0_alpha::Request
    +-- 0.7.0-alpha --> published::v0_7_0_alpha::Request
    `-- 0.8.0-alpha --> dev one-shot or phase-specific state-aware request
    |
    v
typed adapter outside the immutable contract module
    |
    v
current internal wire/runtime normalization
    |
    v
existing semantic and cross-field validation
    |
    v
ExecutionRequest / ParsedStateAwareRequest
```

The request is deserialized directly from its source text. It is not converted
to `serde_json::Value` before structural validation.

### Entry-point-dependent command requirements

The published `Request` types represent complete JSON requests and retain the
schema requirement for `process.commandLine`. The existing CLI policy mode that
supplies the command separately remains supported, but it is an entry-point
concern rather than a relaxation of the published contract.

Before exact dispatch is enabled, the loader must provide an entry-point-aware,
typed path for `LoadOptions::allow_missing_command` that combines the CLI
command with the versioned policy before normal semantic validation. A
dedicated versioned policy root is acceptable; falling back to the rolling
version-insensitive parser is not. Phase 7 shadow dispatch must cover this path,
and Phase 9 cannot enable exact dispatch until its behavior matches the current
CLI override flow.

## Work plan

### Phase 1: Add the contract crate and exact version probe

Implemented by PR #807.

Add:

```text
src/core/mxc_config_contract/
  Cargo.toml
  src/
    lib.rs
    registry.rs
    version.rs
```

The crate depends only on Serde and `serde_json`, plus optional Schemars support
when schema generation is added. It must not depend on `wxc_common`,
`mxc_engine`, or any backend crate. This is intentionally a separate crate
rather than a module in an existing runtime crate so Cargo enforces the
dependency boundary. Any broader crates.io packaging work for the Rust SDK is a
separate concern.

Implement:

- `ContractVersion`
- exact string lookup
- published/development status metadata
- a source-text `VersionProbe`
- a structured probe error
- focused unit tests

This step has no production parser integration and no behavior change.

### Phase 2: Implement the `0.6.0-alpha` contract

Add a self-contained version directory from the documented stable `0.6` field
set:

```text
published/
  mod.rs
  v0_6_0_alpha/
    mod.rs
    primitives.rs
    network.rs
    request.rs
```

Substantial published contracts use directory modules so their internal
organization can grow without sharing field-bearing types across versions.

Requirements:

- exact version marker
- recursively closed objects
- no experimental or state-aware fields
- only documented `0.6` containment values and aliases
- explicit handling of required versus entry-point-dependent fields
- valid and invalid fixtures

This is the first complete vertical contract slice.

### Phase 3: Add the `0.6` adapter

Add:

```text
src/core/wxc_common/src/config_contract_adapters/
  mod.rs
  v0_6.rs
```

Convert the published request into the current internal `wire::MxcConfig`.
Published contract modules remain frozen; adapters may evolve as the internal
runtime model evolves.

The adapter must explicitly destructure every source field and explicitly fill
every internal field. Do not use a catch-all `..`.

Add wire-equivalence tests proving that representative `0.6` requests adapt to
the same `wire::MxcConfig` produced by the current deserializer.

### Phase 4: Add the `0.7.0-alpha` contract and adapter

Implemented by PR #838. PR #907 completed published-API rustdoc coverage; PR
#912 aligns positive adapter tests with the published schema's backend-section
constraints.

Create an independent self-contained module rather than sharing field-bearing
types.

The `0.7` contract adds the documented differences from `0.6`, including
annotations and the stable Seatbelt surface.

Add:

```text
src/core/wxc_common/src/config_contract_adapters/v0_7.rs
```

The adapter exhaustively maps `published::v0_7_0_alpha::Request` into the
current wire model, including annotations, stable Seatbelt configuration, and
version-specific compatibility aliases. Add expected-wire and current-wire
equivalence tests for representative `0.7` requests.

Add cross-version fixtures proving that fields and values are accepted only by
the versions that define them.

The historical `0.6` and `0.7` schema files remain byte-for-byte unchanged.
Document the bootstrap tightening where the typed contracts require an exact
version and reject unknown fields more consistently than those advisory files.

### Phase 5: Add the closed `0.8.0-alpha` development contract and adapters

Status:

- **Phase 5A** — one-shot development contract, under review in PR #909
- **Phase 5B** — one-shot development adapter, stacked on 5A in PR #910
- **Phase 5C** — phase discriminator and state-aware development contracts,
  complete and under review in PR #929
- **Phase 5D** — state-aware adapter and wire-equivalence tests, complete and
  under review in PR #941

Separate the mutable development contract into:

```text
dev/
  mod.rs
  primitives.rs
  network.rs
  stable.rs
  experimental.rs
  one_shot.rs
  state_aware/
    mod.rs
    phase.rs
    start.rs
    exec.rs
    stop.rs
    deprovision.rs
    provision/
      mod.rs
      windows_sandbox.rs
      isolation_session.rs
      wslc.rs
```

Add mutable development adapters outside the contract crate:

```text
src/core/wxc_common/src/config_contract_adapters/dev/
  common.rs
  mod.rs
  one_shot.rs
  one_shot_tests/
    mod.rs
    common.rs
    stable_candidate.rs
    experimental.rs
  state_aware.rs
  state_aware_tests/
    mod.rs
    common.rs
    start.rs
    exec.rs
    stop.rs
    deprovision.rs
    provision.rs
src/core/wxc_common/src/state_aware_wire.rs
```

The development adapter follows the mutable `dev` contract rather than an
immutable version name. Publication creates a separate frozen versioned adapter
for the promoted stable contract while `dev` advances to the next development
version.

The one-shot development request contains the stable candidate surface plus a
recursively closed one-shot experimental structure.

State-aware requests use separate root types per phase. Each phase type accepts
only the top-level and `experimental.<backend>.<phase>` fields valid for that
phase. The phase discriminator is read from source text before selecting the
concrete request type.

This typed path replaces permissive experimental acceptance and eventually
removes the need to mask the experimental source block before base parsing.

The adapters exhaustively map the one-shot request and each phase-specific
state-aware request into the current wire model. State-aware adaptation also
preserves raw experimental JSON and exact source text in a neutral
pre-normalization value. Add expected-wire and current-wire equivalence tests
for representative stable, experimental, and phase-specific development
requests.

#### Phase 5A: Closed one-shot development contract

Implemented in PR #909.

The exact one-shot root:

- requires `version: "0.8.0-alpha"` and a non-empty
  `process.commandLine`
- independently owns the mutable stable-candidate field-bearing types rather
  than reusing a published contract
- accepts stable containment selections and the development-only `vm`,
  `windows_sandbox`, `microvm`, `hyperlight`, `wslc`, and
  `isolation_session` selections
- includes the stable-candidate ProcessContainer `learningMode` and
  `captureDenials` fields, including `retainEtl`
- defines a recursively closed one-shot experimental subtree for TestFeature,
  telemetry, Windows Sandbox compatibility settings, and flat one-shot WSLC
  settings and port mappings
- excludes the state-aware `experimental.isolation_session` and
  `experimental.wslc.provision` shapes
- rejects the moved `experimental.seatbelt` and
  `experimental.macos_sandbox` paths; Seatbelt configuration and its
  compatibility alias are top-level

The one-shot containment enum is deliberately broader than the experimental
configuration subtree. Windows Sandbox, IsolationSession, and WSLC support
both one-shot and state-aware execution; MicroVM and Hyperlight are one-shot
only. IsolationSession has no one-shot backend-configuration object.

Contract tests cover field cardinality, null and duplicate rejection, recursive
closure, numeric boundaries, string-only enum encoding, compatibility aliases,
state-aware exclusions, and adjacent-version introduction boundaries. Valid
JSON fixtures remain semantically credible examples; structurally valid but
runtime-incompatible combinations belong in focused inline tests.

#### Phase 5B: One-shot development adapter

Implemented in PR #910.

The adapter exhaustively converts `dev::OneShotRequest` into the current
`wire::MxcConfig`. It explicitly destructures every source field and fills
every destination field without `..`. It preserves compatibility aliases,
non-zero WSLC port validation, both Windows Sandbox timeout spellings,
`captureDenials.retainEtl`, and explicit false values.

One-shot-only normalization fills the broader rolling wire model explicitly:

- `phase`, `sandboxId`, and `correlationVector` are absent
- `experimental.isolation_session` and the obsolete experimental Seatbelt
  field are absent
- `experimental.wslc.provision` is absent

Adapter tests are organized along the publication boundary:

- `stable_candidate.rs` covers mappings that will be copied into the frozen
  v0.8 adapter at publication
- `experimental.rs` covers development-only containment and experimental
  mappings that remain with mutable dev when it advances to v0.9
- `common.rs` contains only test mechanics, not contract-bearing fixtures

Both groups contain direct expected-wire assertions and current-wire
deserialization equivalence coverage. Published and development adapters do
not share test fixtures or conversion helpers.

#### Phase 5C: State-aware development contracts

The source-text phase probe and the closed `start`, `stop`, and `deprovision`
roots are implemented. The `exec` root and its structural tests are in
progress. Provision contracts and typed root selection remain.

The phase probe runs after the exact version probe. An absent phase selects
`dev::one_shot::Request`; a present valid phase selects the matching
state-aware root family. Duplicate, null, non-string, and unknown phase
declarations fail before root deserialization.

Serde's derived struct deserialization can accept positional JSON arrays.
Rejecting those arrays through map-only probes or request deserializers is
explicitly out of scope for this work and is not assigned to any phase.

Exact phase fields use private-macro-generated zero-sized string markers
(`StartPhase`, `ExecPhase`, `StopPhase`, `DeprovisionPhase`, and
`ProvisionPhase`) rather than the broad `Phase` enum. This makes a request with
the wrong valid phase fail structurally. The private `string_marker!` macro is
also used for exact provision containment markers; it adds no public `TryFrom`
surface.

Start, stop, and deprovision each own independent closed experimental wrapper
types. They currently contain only optional telemetry, but are not shared so a
future phase-specific field cannot accidentally widen the other contracts.
Their roots require `sandboxId`, optionally accept annotations and a relayed
correlation vector, and reject containment, process, policy, lifecycle,
one-shot backend sections, and backend-specific experimental payloads.

Exec follows the same envelope pattern but additionally requires the process
block and accepts the top-level network field used for WSLC's cooperative
per-exec proxy. It rejects containment, provision-time filesystem/UI policy,
lifecycle, one-shot backend sections, and backend-specific experimental
payloads.

Provision uses a second discrimination step. After `phase` selects the
provision family, probe the required exact `containment` value and deserialize
one of three backend-specific roots:

```text
phase == provision
    |
    +-- containment == windows_sandbox
    |       --> WindowsSandboxProvisionRequest
    +-- containment == isolation_session
    |       --> IsolationSessionProvisionRequest
    `-- containment == wslc
            --> WslcProvisionRequest
```

The public provision discriminator contains only concrete backends with
lifecycle implementations:

- `windows_sandbox`
- `isolation_session`
- `wslc`

Do not reuse the one-shot containment enum. In particular, do not accept the
abstract `vm` intent for state-aware provision unless abstract state-aware
backend selection is made an explicit requirement.

Each concrete provision root uses its own exact zero-sized containment marker,
not the broad provision discriminator enum. Therefore a Windows Sandbox root
cannot deserialize a request declaring `containment: "wslc"`, and no custom
cross-field `Deserialize` validation is required.

Expose the selected result as:

```rust
pub enum ProvisionRequest {
    WindowsSandbox(WindowsSandboxProvisionRequest),
    IsolationSession(IsolationSessionProvisionRequest),
    Wslc(WslcProvisionRequest),
}
```

The provision containment probe rejects missing, duplicate, null, non-string,
unknown, abstract, one-shot-only, and non-state-aware containment values.

The backend-specific provision roots encode their field matrices
structurally:

- Windows Sandbox accepts provision-time filesystem policy and no
  backend-specific provision payload (`ProvisionConfig = ()`)
- IsolationSession accepts the top-level network acknowledgment and optional
  `experimental.isolation_session.provision.appId`
- WSLC accepts provision-time filesystem and network policy plus optional
  `experimental.wslc.provision.image` and `imageTarPath`
- all three accept annotations and optional telemetry
- all three reject `sandboxId`, `correlationVector`, process, lifecycle,
  one-shot backend sections, foreign backend payloads, and fields belonging to
  another provision backend

Every experimental object and nested phase/backend object is recursively
closed. The contract crate defines its own backend payload types and retains
its dependency boundary; it does not import backend crates.

After all phase/backend roots exist, add a typed development request selector:

```rust
pub enum Request {
    OneShot(OneShotRequest),
    Provision(ProvisionRequest),
    Start(StartRequest),
    Exec(ExecRequest),
    Stop(StopRequest),
    Deprovision(DeprovisionRequest),
}
```

Selection is source-text driven: probe phase, use one-shot when absent, probe
containment only for provision, then deserialize exactly one closed root.

Contract tests use phase-specific files. Start, stop, and deprovision have
complete acceptance, required-field, type, null, duplicate, recursive-closure,
forbidden-field, annotation, correlation-vector, and telemetry matrices. Exec
uses the same baseline plus process and exec-time network coverage. Provision
tests must additionally prove containment discrimination, exact marker
enforcement, backend-key/phase-key closure, and rejection of foreign backend
fields.

#### Phase 5D: State-aware development adapter and wire equivalence

Implemented in PR #941.

The mutable state-aware adapter exhaustively maps every phase root into the
current `wire::MxcConfig` shape:

- `StartRequest`, `ExecRequest`, `StopRequest`, and `DeprovisionRequest`
- Windows Sandbox, IsolationSession, and WSLC provision requests
- annotations, correlation vectors, process and policy fields, telemetry, and
  backend-specific provision payloads

The development adapter exposes one crate-visible facade,
`dev::adapt_request`, returning `AdaptedWireRequest`. One-shot requests contain
their `wire::MxcConfig` directly. State-aware requests contain a neutral
`StateAwareWireInput` with:

- the adapted `wire::MxcConfig`
- the validated raw experimental JSON object
- the exact decoded source text needed for later positional diagnostics

Internal conversion modules and helpers remain private or `pub(super)`; Phase 7
consumes only the facade.

Direct expected-wire and current-wire-deserialization equivalence tests cover
every supported backend/phase combination, optional-field presence, explicit
false and empty values, telemetry, required envelope fields, and all provision
backend payloads. Focused facade tests begin with JSON source and prove request
selection, raw experimental preservation, and exact source-text preservation.

Comprehensive rolling-versus-exact final-model convergence, acceptance mismatch
classification, and diagnostic parity are explicitly deferred to Phase 7, where
both complete parser pipelines run together. Phase 5D does not modify the rolling
parser or normalize exact requests into `ParsedStateAwareRequest`.

### Phase 6: Add versioned development-schema codegen

Add the schema-generation foundation needed to evolve the closed development
contract safely:

- optional Schemars support on the contract crate
- custom schema implementations for contract primitives where derive output is
  insufficient
- `mxc_schema_gen schema --version 0.8.0-alpha`
- versioned TypeScript wire-oracle generation
- drift checks proving generated development artifacts match the Rust contract

This phase generates development artifacts only; it does not publish or freeze
`0.8.0-alpha`. It must land before substantial development-contract changes so
those changes update the Rust contract, JSON Schema, and TypeScript oracle
together.

### Phase 7: Add shadow exact-contract dispatch

Add a private exact-contract path in `config_parser` while retaining the current
path as authoritative.

The exact development path calls `dev::adapt_request`. One-shot results proceed
through the existing one-shot normalization. State-aware results supply their
neutral `StateAwareWireInput` to the shared normalizer introduced below.

Extract a behavior-preserving shared state-aware normalization seam from the
rolling parser when the exact path becomes its second caller. Both parser paths
produce the same neutral pre-normalization value and feed that shared function
to obtain `ParsedStateAwareRequest`; do not duplicate runtime normalization in
the shadow path.

For matching inputs:

1. Parse with the current parser.
2. Parse through the selected version contract.
3. Adapt both to the runtime model.
4. Assert semantic equivalence.

Semantic-equivalence tests belong here, where both complete parsing paths
exist. For valid inputs, Phase 3's wire-equivalence tests establish that the
same deterministic wire-to-runtime conversion receives the same value; Phase 7
adds end-to-end coverage for runtime results, acceptance differences, and
diagnostic behavior.

Cover every loader mode and representative one-shot/state-aware backend/phase
combination, including `allow_missing_command`, immutable post-provision policy,
telemetry, required envelope fields, and source-position diagnostics. Explicitly
classify intentional tightening and other known expected incompatibilities,
especially configs that declare `0.6.0-alpha` while carrying experimental
fields.

Shadow comparison uses the current legacy Network syntax for all versions. The
GA Network change is intentionally deferred until exact dispatch is
authoritative, because the rolling parser cannot accept the new `0.8.0-alpha`
shape without repeating the version-insensitive break introduced by PR #676.

### Phase 8: Migrate producers and the config corpus

Do not rely on the original base-commit counts; the corpus changes frequently.
Regenerate and check in an inventory report at the start of this phase,
covering configs, examples, SDK producers, state-aware envelopes, and schema
references.

The most recent focused audit (2026-08-11, `tests/configs` plus
`tests/examples`) found:

- 97 configs declaring `0.6.0-alpha`: 54 conformed to the exact stable
  contract, while 43 used experimental or later-version surfaces
- 55 unversioned configs: none conformed after temporary `0.6.0-alpha`
  injection; they were experimental, state-aware, or annotation-bearing

These counts are evidence that migration is required, not a frozen Phase 8
input.

Experimental and state-aware configs move to `0.8.0-alpha`. Stable configs are
classified and assigned an exact published version.

This migration retains the current legacy Network syntax. Development configs
that use Network policy receive a second, focused migration when Phase 10
changes the authoritative `0.8.0-alpha` contract to the GA shape.

Update Node, C#, Rust SDK, FFI, examples, tests, and `$schema` references.
State-aware producers must stop hard-coding `0.6.0-alpha`.

This step is primarily mechanical and is suitable for delegation.

### Phase 9: Enable exact dispatch

Replace the major/minor range check with exact registry dispatch.

Add `allow_development_contract` to parser load options. Initially, the
existing `--experimental` option authorizes parsing `0.8.0-alpha` as well as
enabling experimental execution.

Published versions reject `experimental` as an ordinary unknown field.
Development requests without opt-in receive a specific error. There is no
fallback to the latest version.

After parity tests pass, remove the direct version-insensitive wire
deserialization path.

Exact dispatch must be authoritative before the development Network contract
changes. This sequencing is what protects `0.6.0-alpha` and `0.7.0-alpha`
callers from the breaking-change failure mode that caused PR #676 to be
reverted.

### Phase 10: Reintroduce the GA network contract on the authoritative development version

Redo the work originally attempted by PR #676 and reverted by PR #707, but
apply it only to the now-authoritative version-specific `0.8.0-alpha` contract.
Do not replace or widen a rolling version-insensitive wire shape.

The `0.8.0-alpha` development contract adds:

- `network.egress` and `network.ingress`
- `NetworkEgress`, rule, destination, port, protocol, and ingress policy types
- destination `except` ranges and inclusive `endPort`
- `tcp`, `udp`, `icmp`, and `any` protocol values
- `processContainer.network.allowedPeers`
- the GA runtime location for network proxy configuration

The phase must be end-to-end and leave the tree green. It includes the
development contract, adapters from the legacy `0.6`/`0.7` network shapes,
canonical runtime models, semantic validation, backend enforcement, Rust and
TypeScript SDK surfaces, generated artifacts, fixtures, and applicable unit,
integration, and E2E tests. Do not merge a schema-only change that intentionally
breaks the parser, codegen, SDK, or test gates.

The published `0.6` and `0.7` contracts retain their immutable legacy Network
syntax and continue to parse through their exact contract modules. Their
adapters normalize legacy fields into the canonical runtime model. Migrations
must not silently drop DNS host rules, enforcement choices, local-network
intent, or proxy configuration; each legacy behavior must be translated,
rejected with a specific migration error, or retained through a documented
compatibility representation.

The GA fields are available only in the mutable `0.8.0-alpha` development
contract. Update the development schema, TypeScript oracle, SDK emitters, and
the `0.8.0-alpha` Network config corpus in this phase. Because exact dispatch is
already authoritative, these changes cannot alter the accepted syntax of
published `0.6.0-alpha` or `0.7.0-alpha` requests.

### Phase 11: Add publication and freeze checks

Extend `mxc_schema_gen` with the publication command:

```text
mxc_schema_gen publish --version 0.8.0-alpha --next-dev 0.9.0-dev
```

Publication copies only the development stable-candidate request;
experimental and state-aware types never enter a published contract. Generate
the lifecycle registry and version constants from the publication metadata.

Add CI checks that published Rust modules, stable generated schemas, registry
identities, and recorded digests cannot be modified or deleted. Reuse
`scripts/versioning/lib/git-base.js` for base-ref handling.

Replace `schemas/schema-version.json` and the regex-based version synchronization
logic once all consumers use the generated registry.

Do not extend the existing rolling-version synchronization gate to treat its
current min/stable/dev constants as the exact-contract registry. Exact contracts
are registered deliberately as their Rust modules are implemented; Phase 11
replaces the old synchronization mechanism with generated registry metadata.

## Suggested ownership

Good substantive Rust work to keep with the primary implementer:

- exact version probe and registry
- `0.6` contract
- typed adapters
- parser dispatch
- closed state-aware development types
- publication command

Good tasks to delegate:

- config inventory and version rewrites
- repetitive fixture scaffolding
- generated artifact regeneration
- SDK constants and documentation sweeps
- CI JavaScript updates

## Phase 1 detailed design

Phase 1 was implemented by PR #807. The detailed design remains here as the
record of the crate boundary and probe responsibilities.

### Phase 1 objective

Create a small independent crate that can answer:

> Given raw JSON request text, which exact registered MXC contract does it
> declare?

It must reject malformed declarations without knowing anything about the rest
of the config shape. It does not yet deserialize a version-specific request.

### Phase 1 step breakdown

Phase 1 is intentionally split into six small implementation steps. Each step
has a single responsibility and leaves the new crate in a buildable state.

#### Phase 1.0: Prepare the implementation branch

Start from the base commit named at the top of this document rather than the
older detached worktree on which this plan was authored.

Done when:

- `HEAD` is based on `origin/main` at or after `79c39c70`
- the worktree is clean except for this plan, if the plan is carried onto the
  implementation branch
- the repository Rust instructions have been read

No source files are changed in this step.

#### Phase 1.1: Scaffold the independent crate

Files:

```text
src/Cargo.toml
src/core/mxc_config_contract/Cargo.toml
src/core/mxc_config_contract/src/lib.rs
src/core/mxc_config_contract/src/version.rs
src/core/mxc_config_contract/src/registry.rs
```

Actions:

- add `core/mxc_config_contract` to the workspace
- add only the initial Serde dependencies
- add crate-level documentation stating that this crate defines input
  contracts and must not depend on runtime or backend crates

Done when:

```text
cargo check -p mxc_config_contract
```

passes without changing any existing crate's behavior.

Suggested commit boundary: `Add config contract crate scaffold`.

#### Phase 1.2: Implement the exact version value type

Primary file:

```text
src/core/mxc_config_contract/src/version.rs
```

Actions:

- add `ContractVersion`
- add `ContractVersion::ALL`
- add `as_str`
- add `parse_exact`
- optionally implement `Display` by delegating to `as_str`
- do not add a SemVer dependency or any normalization

Add table-driven tests covering every accepted and rejected spelling.

Done when:

- every registered string round-trips through `parse_exact` and `as_str`
- every unregistered spelling returns `None`
- the module has no knowledge of config shape or parser behavior

Suggested commit boundary: `Add exact config contract versions`.

#### Phase 1.3: Add lifecycle registry metadata

Primary file:

```text
src/core/mxc_config_contract/src/registry.rs
```

Actions:

- add `ContractStatus`
- add `ContractDescriptor`
- add the static `CONTRACTS` table
- add descriptor lookup
- add supported-version iteration
- classify `0.6` and `0.7` as published
- classify `0.8` as development

Add consistency tests proving:

- every `ContractVersion::ALL` entry has exactly one descriptor
- every descriptor refers to a value in `ALL`
- no version string appears twice
- descriptor lookup returns the correct status

Done when the version enum and lifecycle registry cannot silently drift.

Suggested commit boundary: `Add config contract registry metadata`.

#### Phase 1.4: Implement source-text version probing

Primary file:

```text
src/core/mxc_config_contract/src/version.rs
```

Actions:

- add the private borrowed `VersionProbe`
- add `VersionProbeError`
- add `probe_version`
- deserialize directly from `&str`
- retain the submitted unsupported version as structured data
- do not log or produce terminal-facing diagnostics in this crate

Add focused malformed-input tests. In particular, confirm that Serde rejects a
duplicate `version` key rather than accepting the last value.

Done when raw JSON can be mapped to an exact `ContractVersion` without parsing
or storing the rest of the config.

Suggested commit boundary: `Add exact contract version probe`.

#### Phase 1.5: Stabilize the initial public API

Primary file:

```text
src/core/mxc_config_contract/src/lib.rs
```

Actions:

- re-export only the types and functions intended for later parser integration
- keep `VersionProbe` private
- document that `probe_version` validates only the declaration, not the
  selected contract's shape
- document the exact-match behavior on `ContractVersion`

Done when a future consumer can use the crate without reaching into private
implementation details.

This step may be folded into Phase 1.4's commit if the API change is trivial.

#### Phase 1.6: Run the phase quality gate

Run:

```text
cargo fmt --all -- --check
cargo test -p mxc_config_contract
cargo clippy -p mxc_config_contract --all-targets -- -D warnings
```

Also confirm:

- `cargo tree -p mxc_config_contract` contains no MXC runtime or backend crate
- no existing parser, schema, SDK, config, or generated artifact changed
- `git diff --check` passes

Suggested commit boundary: normally none; fix issues in the commit that
introduced them.

### Cargo wiring

Add `core/mxc_config_contract` to the workspace members in `src/Cargo.toml`.
Declare the workspace path dependency when the first adapter, shadow-dispatch,
or code-generation consumer needs it. Phase 1 has no consumer and therefore
does not add the dependency preemptively.

Initial crate dependencies:

```toml
[dependencies]
serde.workspace = true
serde_json.workspace = true
```

Schemars is deferred until Phase 6, when versioned schema generation consumes
the contract types. Earlier phases validate deserialization behavior directly
and do not add schema-generation dependencies without a consumer.

### Public API

The initial `lib.rs` should expose only the version model and probe:

```rust
pub mod registry;
pub mod version;

pub use registry::{ContractDescriptor, ContractStatus, CONTRACTS};
pub use version::{probe_version, ContractVersion, VersionProbeError};
```

The `published` module begins with the first published request type in Phase 2.
The `dev` module is deferred until the development contract in Phase 5.

### Exact version model

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContractVersion {
    V0_6_0Alpha,
    V0_7_0Alpha,
    V0_8_0Alpha,
}
```

Required methods:

```rust
impl ContractVersion {
    pub const fn as_str(self) -> &'static str;
    pub fn parse_exact(value: &str) -> Option<Self>;
}
```

Do not implement fuzzy parsing. Do not normalize `0.6.0` into
`0.6.0-alpha`. Do not ignore patch or prerelease components.

An `ALL` array is useful for iteration and diagnostics:

```rust
pub const ALL: &[ContractVersion] = &[
    ContractVersion::V0_6_0Alpha,
    ContractVersion::V0_7_0Alpha,
    ContractVersion::V0_8_0Alpha,
];
```

### Registry metadata

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractStatus {
    Published,
    Development,
}

pub struct ContractDescriptor {
    pub version: ContractVersion,
    pub status: ContractStatus,
}
```

`CONTRACTS` is initially a static Rust table. Shape modules and generated
artifacts are added later. Publication tooling may eventually generate this
table from lifecycle metadata, but Phase 1 should not introduce a build script
or code generation.

The registry should provide:

```rust
pub fn descriptor(version: ContractVersion) -> &'static ContractDescriptor;
pub fn supported_version_strings() -> impl Iterator<Item = &'static str>;
```

### Source-text probe

Use a deliberately small borrowed Serde type:

```rust
#[derive(serde::Deserialize)]
#[serde(expecting = "a configuration object")]
struct VersionProbe<'a> {
    #[serde(borrow)]
    version: &'a str,
}
```

Do not add `deny_unknown_fields`: the probe must ignore every field except
`version`.

```rust
pub fn probe_version(json: &str) -> Result<ContractVersion, VersionProbeError>
```

Suggested error shape:

```rust
#[derive(Debug)]
pub enum VersionProbeError {
    InvalidDeclaration(serde_json::Error),
    UnsupportedVersion(String),
}
```

The contract crate returns structured data and does not log. It should avoid
embedding the submitted version in an unescaped terminal-facing diagnostic;
`wxc_common` remains responsible for safe rendered messages when integration
occurs.

`serde_json::from_str` supplies these properties automatically:

- missing `version` is rejected
- null and non-string versions are rejected
- duplicate `version` keys are rejected
- scalar and empty-array roots are rejected; populated positional arrays are
  outside this plan's scope
- trailing non-whitespace content is rejected

After deserialization, call `ContractVersion::parse_exact`.

### Phase 1 tests

Unit tests should cover:

1. Every registered exact version succeeds.
2. Additional unrelated fields are ignored by the probe.
3. Missing version fails.
4. Null, number, object, and array versions fail.
5. Duplicate version fields fail.
6. Scalar and empty-array roots fail; populated positional arrays are not
   covered.
7. Trailing JSON content fails.
8. `0.6.0`, `0.6.1-alpha`, `0.8.0-dev`, and `1.0.0-dev` are unsupported.
9. Registry descriptors report the expected published/development status.
10. `ALL`, `CONTRACTS`, `as_str`, and `parse_exact` remain mutually consistent.

Avoid pinning complete Serde error strings. Assert the error variant and only
stable, meaningful fragments where necessary.

### Phase 1 exit criteria

- The new crate builds independently.
- Exact version lookup is the only accepted lookup behavior.
- Raw source probing rejects malformed and duplicate declarations.
- No existing parser or SDK behavior has changed.
- No schema, generated SDK type, config file, or documentation migration has
  started.
