# MXC Version-Specific Config Parsers

Status: implementation plan; Phases 1-4 merged in PRs #807, #816, #835, and
#838. Phase 4.1 and Phase 4.2 merged in PRs #907 and #912. Phase 5 is complete
and under review as GitHub stack #948: Phase 5A merged in PR #909, Phase 5B in
PR #910, Phase 5C in PR #929, Phase 5D in PR #941, and the Phase 5A review
follow-up in PR #949. Phases 6-11 remain to be implemented; Phase 6 has a
detailed design below.

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

The CLI command override is therefore resolved **before** the parser runs, by
splicing the CLI command into the request source and then parsing one complete,
contract-conforming document. `LoadOptions::allow_missing_command`, the
`command_required` relaxation in `convert_wire_config`, and the post-parse
`apply_command_override` mutation of `ExecutionRequest::script_code` are all
removed by this rework. No versioned policy root, no relaxed twin of an exact
contract, and no fallback to the rolling version-insensitive parser is
introduced: every contract keeps `process` and a non-empty
`process.commandLine` required, which is also the shape Phase 6 generates and
Phase 11 publishes.

The rework must resolve one ordering obstacle. Converting CLI `argv` into a
command-line string is backend-specific
(`cmdline_from_argv_for_context(&cli.command, CommandLineContext::for_backend(..))`),
and today the context comes from the already-parsed request: `request.containment`
for one-shot, and `resolve_backend(&parsed)` — that is, the `sandboxId` prefix —
for state-aware exec. Injection therefore runs as a probe-driven pre-parse step
that reuses the exact-dispatch probes:

```text
raw JSON source
    |
    v
probe version, phase, and (provision) containment      [exact dispatch probes]
    |
    v
probe the command-line context                          [entry point only]
      one-shot        -> declared/default containment
      state-aware exec-> sandboxId prefix
    |
    v
convert argv -> command line, splice into process.commandLine
    |
    v
exact registry lookup and normal typed parse of the effective document
```

Required behavior:

- A CLI command is spliced only when one is supplied; the ordinary path parses
  the caller's bytes untouched.
- The splice **overwrites** `process.commandLine` and creates the `process`
  object when it is absent. Both cases exist today: `allow_missing_command`
  tolerates an empty `commandLine` and a wholly missing `process` block, and
  `apply_command_override` then replaces whatever was there. A fill-if-absent
  splice would newly reject a config carrying `"commandLine": ""` together with
  a CLI command.
- The existing precedence and diagnostics are preserved: an override that
  replaces a policy-supplied `process.commandLine` still logs the override, so
  the injection step must observe whether the field was already present.
- A CLI override remains valid only where it is valid today: one-shot requests
  and state-aware `exec`. Any other phase still fails with the current
  "CLI command override is only supported for state-aware exec requests" error.
- An empty or unconvertible CLI command is an entry-point error, not a parse
  error. This is a new failure site: today `has_cli_command` makes an empty
  converted command unreachable, so the rework needs an explicit error and a
  test rather than relying on the validator's empty-command check.
- The containment probe's raw-string-to-backend mapping lives outside the
  immutable contract modules, beside the adapters.
- The probe reproduces a mapping the parser also performs — including the
  absent-containment host default and the abstract `vm` intent — so the two can
  drift, and a drift would quote the command for one backend while another
  executes it. After the typed parse, assert that the context used for the
  splice matches the resolved containment and fail loudly on a mismatch. This
  assertion is part of the Phase 9 acceptance criteria.

Known trade-off: when a command is spliced, serde's source positions and the
state-aware `source_text` used for positional experimental diagnostics describe
the effective document rather than the caller's original bytes. This applies
only to the override path. This transform is an entry-point concern applied
exactly once to one field; it is not the general JSON `Value` migration engine
excluded by the non-goals. A `serde_json::Value` round-trip is the default
implementation. If positional fidelity on the override path proves to matter, a
textual splice that inserts the member into the existing `process` object keeps
every offset before the insertion point exact and bounds the drift to the text
after it.

Phase 7 shadow dispatch must cover this path, and Phase 9 cannot enable exact
dispatch until its behavior matches the current CLI override flow.

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

This rule applies to every adapter, published and development, and extends to
wildcard *field* bindings: an adapter must not bind a contract field to `_`.
Bind a marker field by its exact type pattern and match an enum field
exhaustively:

```rust
let contract::IsolationSessionNetwork {
    default_policy: contract::IsolationSessionNetworkDefaultPolicy,
    allow_local_network: contract::True,
} = value;
```

The reason is that a discarded field is usually paired with a hardcoded
destination value — a phase, a containment, or the IsolationSession
unrestricted-network acknowledgment. With `_`, widening the contract type
(`string_marker!` unit struct becomes an enum, `True` becomes a bool) still
compiles and the adapter silently keeps stamping the old value. The exact type
pattern turns that into a compile error at precisely the sites whose output the
change invalidates. The guarantee covers the contract type's *shape*, not the
set of spellings it accepts.

Write the marker pattern **qualified** (`contract::StartPhase`, not
`StartPhase`). A qualified path in pattern position can only resolve to a unit
struct, unit variant, or constant, so widening the type is `error[E0532]` at the
adapter line. An unqualified identifier that no longer resolves to a unit struct
is instead treated as a fresh binding, which downgrades the failure to
`unused_variables` and `non_snake_case` warnings — caught by the repository's
`cargo clippy -- -D warnings` gate, but no longer a compile error, and
suppressible with a leading underscore.

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

- **Phase 5A** — one-shot development contract, merged in PR #909
- **Phase 5B** — one-shot development adapter, complete and under review in
  PR #910, stacked on 5A
- **Phase 5C** — phase discriminator and state-aware development contracts,
  complete and under review in PR #929, stacked on 5B
- **Phase 5D** — state-aware adapter and wire-equivalence tests, complete and
  under review in PR #941, stacked on 5C
- **Phase 5A follow-up** — string enum contract coverage generated from each
  `string_enum!` declaration, addressing Phase 5A review feedback after #909
  merged. Complete and under review in PR #949, stacked on 5D. It rewrites the
  `string_enum!` macro in the `dev`, `published/v0_6_0_alpha`, and
  `published/v0_7_0_alpha` modules so canonical, alias, non-string, and
  externally tagged object coverage derives from the macro's own value table.
  Phase 6.2 extends those same macros, so it must build on this shape

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

Complete and under review in PR #909.

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

Complete and under review in PR #910.

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

Complete and under review in PR #929.

The source-text phase probe, the closed `start`, `exec`, `stop`, and
`deprovision` roots, the backend-specific provision roots, and typed root
selection are implemented.

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

Complete and under review in PR #941.

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

The detailed design is in the Phase 6 detailed design section below.

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

Remove the `#[cfg_attr(not(test), allow(dead_code))]` suppressions on the
adapter modules, on `state_aware_wire`, and on the Phase 7.3 exact path. This
is the first phase in which the router calls the exact path, so it is the first
phase in which any of that code is reachable in a production build. Removing
them earlier would produce dead-code warnings, since an uncalled exact path
leaves everything it calls dead too.

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

State-aware `0.8.0-alpha` requests carry the legacy Network shape in three
places, all introduced by Phase 5C/5D, and all of them change in this phase:

- the IsolationSession provision **unrestricted-network acknowledgment**, today
  encoded structurally as the exact markers `network.defaultPolicy: "allow"`
  plus `network.allowLocalNetwork: true` on
  `IsolationSessionProvisionRequest`. The GA equivalent must be defined
  deliberately — an acknowledgment that no longer has `defaultPolicy` or
  `allowLocalNetwork` to point at is not a mechanical rename — and the backend's
  `validate_provision_network_policy` must be updated with it.
- `ExecRequest.network`, the per-exec cooperative proxy path used by WSLC.
- `WslcProvisionRequest.network`, the provision-time WSLC network policy.

Decide explicitly, rather than mechanically porting, whether the IsolationSession
acknowledgment should remain expressed as network *policy values* at all. It is
an assertion about the caller's understanding, encoded as two fields MXC cannot
enforce; that is exactly why it needs a bespoke translation whenever the network
vocabulary changes. A dedicated field (for example `network.acknowledgeUnrestricted`
or a backend-level acknowledgment inside the ISO provision payload) would be
invariant across this change, would read honestly in the generated schema, and
would decouple the acknowledgment from `network_specified`. The cost is a corpus
and SDK migration plus documentation updates in `docs/isolation-session/`, since
the current spelling has shipped.

The state-aware development adapters (`config_contract_adapters::dev`) move with
them, including the hardcoded acknowledgment mapping in
`convert_isolation_session_network`.

The backends' presence-based gates must keep working. `network_specified` and
`ui_specified` exist because a default-deny policy is value-indistinguishable
from an absent one; the GA shape needs an equivalent notion of "the caller
supplied a network policy" or those backends lose the distinction that makes
their `policy_validation` errors correct.

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

Publication is not a byte-for-byte copy of every stable-candidate type. The
development one-shot `Containment` enum deliberately carries both
stable-candidate values (`process`, `processcontainer` + its `appcontainer`
alias, `lxc`, `bubblewrap`, `seatbelt` + its `macos_sandbox` alias) and
development-only values (`vm`, `windows_sandbox`, `microvm`, `hyperlight`,
`wslc`, `isolation_session`). Publishing `0.8.0-alpha` therefore emits a
`published/v0_8_0_alpha` module whose containment enum contains only the
stable-candidate values, and a frozen `config_contract_adapters::v0_8` adapter
mapping that narrower enum. The mutable `dev` contract keeps the full enum and
advances to the next development version.

The published adapter is **forked**, not updated: freezing copies the current dev
one-shot adapter into `v0_8`, and the `dev` adapter continues to evolve against
`0.9`. Phase 5B's split of the adapter tests into `stable_candidate.rs` (copied
at publication) and `experimental.rs` (retained by dev) exists for this fork.

The same fork applies to the `mxc_engine::policy` contract builder introduced by
the Phase 7 decision 3 resolution. Each supported version has its own builder
mapping `SandboxPolicy` onto that version's root, so publication freezes a
`v0_8` builder beside the frozen `v0_8` adapter while `dev`'s builder advances.
Publication is therefore a three-way fork — contract module, adapter, builder —
and all three must be copied together.

Keep the stable-candidate set machine-readable inside the contract crate rather
than in a comment or an external metadata file. Declare it beside the enum, for
example:

```rust
pub const STABLE_CANDIDATE_CONTAINMENTS: &[Containment] = &[ /* ... */ ];
```

with a test asserting every enum arm appears in exactly one of the
stable-candidate and development-only lists. This keeps a single flat enum — and
therefore good deserialization diagnostics — while making the narrowing
declarative. Do not split the enum into a stable type wrapped by a
development-only extension type: that degrades parse errors to "data did not
match any variant" for every misspelled containment.

Narrowing at publication has a recurring cost that must be planned for, not
discovered: at every publication, each config using a development-only
containment must be re-versioned to the new development version. A document
declaring `0.8.0-alpha` with `containment: "windows_sandbox"` becomes a hard
error the moment `0.8.0-alpha` is published. Phase 8's migration is therefore
not a one-off; a smaller version of it recurs at each publication. This is also
the strongest practical argument for the recorded design discussion on including
selected experimental fields in published contracts, and the two should be
decided together.

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

## Phase 6 detailed design

Phase 6 is the next phase to implement. It depends on the complete Phase 5
stack (PRs #909, #910, #929, #941, and the #949 follow-up) and should be
branched from #949, the current top of that stack, or from `main` once the
stack merges. Branching from #941 instead will conflict: #949 rewrites the
`string_enum!` macros and the enum declarations in `dev/` that Phase 6.1 and
Phase 6.2 both edit.

### Phase 6 objective

Make the mutable `0.8.0-alpha` contract's generated artifacts derive from
`mxc_config_contract::dev` rather than from the rolling `wxc_common::wire`
model, and gate them, so that every later change to the development contract
updates the Rust contract, the JSON Schema, and the TypeScript wire oracle in
one reviewable change.

Phase 6 **adds** a second generator alongside the existing one. It does not
publish or freeze `0.8.0-alpha`, does not retire the rolling artifacts, does
not repoint the corpus gate, and does not modify the parser or any runtime
behavior.

### Phase 6 relationship to adjacent phases

Phase 6 is independent of Phase 7 and the two may proceed in parallel. It must
land before Phase 10 and should land before Phase 8.

**The entry-point command splice fixes the generated shape.** Because the CLI
command override is resolved before the parser runs, every contract keeps
`process` and a non-empty `process.commandLine` required. Phase 6 therefore
generates exactly one shape per root. It must not emit a relaxed twin, an
`allow_missing_command` variant, or an optional-command policy root. The
practical consequence is that a policy document supplied to the CLI override
entry point is not itself contract-valid; only the effective spliced document
is. Record that in the codegen documentation so a future reader does not
"fix" the schema by relaxing the requirement.

This also repairs a limitation of the rolling schema that only the multi-root
composition can express. The rolling single-root schema has no root `required`
array at all, because one root had to cover one-shot and every state-aware
phase simultaneously. Of the 230 documents in the `tests/configs` plus
`tests/examples` corpus, 21 carry no `process` block, and all 21 are
state-aware. Splitting the schema by root restores `required: ["process"]`
exactly where the contract requires it and omits it exactly where the contract
does not.

**The adapter marker rule gets a second enforcement surface.** Phase 3's rule
that an adapter must bind marker fields by qualified type pattern rather than
`_` protects the adapters. The schema implementations in Phase 6.2 must be
emitted by the `string_enum!` and `string_marker!` macros themselves, so that
widening one of those types changes the deserializer and the generated const
together. Adapters then fail to compile and the artifact drift gate fails,
rather than either failing alone.

**Phase 10's network rework becomes reviewable.** The IsolationSession
unrestricted-network acknowledgment is encoded structurally as the exact
values `network.defaultPolicy: "allow"` and `network.allowLocalNetwork: true`
on the provision root. Once Phase 6 lands, that acknowledgment appears in a
generated schema and a generated TypeScript oracle as two constants attached
to a backend that cannot enforce either of them. Whichever way Phase 10
resolves the acknowledgment, it then produces a reviewable artifact diff and
cannot land as a Rust-only change. The same applies to `ExecRequest.network`
and `WslcProvisionRequest.network`.

**Phase 11 reuses the version dispatch.** The generator's `--version`
selection is exact and registry-driven from the outset, with published
versions reserved. Publication adds a `published/v0_8_0_alpha` arm rather
than reworking the command line. The enum schema emission must derive its
value set from the macro's own value table, never from a list written into
the generator, so that Phase 11's `STABLE_CANDIDATE_CONTAINMENTS` narrowing
yields the narrower published schema automatically.

### Phase 6 decisions required

Resolve these before implementation; each changes committed paths or output.

| # | Decision | Recommendation |
| --- | --- | --- |
| 1 | Path of the contract-generated schema, given that the rolling `schemas/dev/mxc-config.schema.0.8.0-dev.json` already exists | `schemas/dev/mxc-config.schema.0.8.0-alpha.json`, keyed by the exact registry version and visibly distinct from the rolling `-dev` artifact that Phase 9 deletes. Both gates tolerate the second file — `check-schema-versions.js` only tests existence of the `devSchemaFile` path and `validate-configs.js` resolves that same path; neither enumerates `schemas/dev/`. Nothing stops an author pointing `$schema` at the new file and being validated against a contract the parser does not enforce until Phase 9, so say so in the artifact banner |
| 2 | Path of the versioned TypeScript oracle | `sdk/node/src/generated/v0_8_0_alpha/wire.ts`; confirm it is neither re-exported nor listed in the package `files` array, otherwise place it under `sdk/node/tests/` |
| 3 | How eight concrete roots become one schema document | A single root with `oneOf` over the eight roots and a shared `definitions` block |
| 4 | Whether the schema advertises the compatibility aliases `appContainer` and `macos_sandbox` | Yes; the rolling schema omits them and `docs/schema-codegen.md` records that as a known reduction |
| 5 | Fate of the current `-- <path>` and `-- --ts <path>` argument forms | Replace them and update all call sites in the same commit; do not retain a hidden legacy form |
| 6 | Whether to accept the authoring-diagnostics cost of a bare `oneOf`, or discriminate with `if`/`then` | Decide deliberately; do not leave it implicit. `oneOf` is correct — every branch pins `version`, each state-aware root pins a distinct `phase`, each provision root pins a distinct `containment`, and every root is closed, so at most one branch can match. But the schema also serves editor validation through `$schema`, and a failing document under an eight-branch `oneOf` produces errors from all eight branches where the rolling single root produced one. Either discriminate on `phase` (and `containment`) with `if`/`then` so only the matching branch is evaluated, at the cost of a more verbose document, or keep `oneOf` and record the regression in `docs/schema-codegen.md` beside the other deliberate differences |

### Phase 6 step breakdown

#### Phase 6.0: Prepare the implementation branch

Base the branch on PR #949, the top of the Phase 5 stack, or on `main` once the
stack has merged. Do not base it on #941: #949 rewrites the `string_enum!`
macros and reformats the enum declarations this phase annotates.
Confirm `cargo test -p mxc_config_contract` is green before adding anything,
so a later failure is unambiguously attributable to this phase.

No source files are changed in this step.

#### Phase 6.1: Add optional Schemars support to the contract crate

Hoist `schemars` into `src/Cargo.toml` `[workspace.dependencies]`. It is
currently declared inline in `wxc_common`, against the repository convention,
and a second consumer makes the inline declaration a drift risk.

Add to the contract crate:

```toml
[features]
schema-gen = ["dep:schemars"]

[dependencies]
schemars = { workspace = true, optional = true }
```

Annotate every derive-`Deserialize` type under `dev/` with

```rust
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
```

covering `stable.rs`, `network.rs`, `experimental.rs`, `one_shot.rs`, and
`state_aware/`. Leave `published/` untouched; published schema generation is
Phase 11 work.

The behavioral unknown here has been settled empirically against Schemars 0.8,
by replicating `OptionalField<T>` in a scratch crate: a `#[serde(default)]`
field of a transparent custom wrapper is **omitted from `required`** and
**carries no null branch**. No `schemars(default)` attribute and no
required-field override are needed. The emitted document is draft-07 with a
`definitions` block, matching decision 3 and ajv 8's default dialect.

Two conditions make that result hold; treat them as requirements rather than
rediscovering them:

- `OptionalField<T>` must keep its `impl Default`. The Schemars derive
  evaluates the field default and fails to compile without it, with
  `no associated function or constant named 'default' found`.
- The hand-written `JsonSchema` impl must set `is_referenceable() -> false`.
  Otherwise the wrapper becomes its own named definition and the avoidance of
  the `anyOf: [T, null]` wrapper is lost.

Done when the crate builds cleanly with and without the feature, and the
default build carries no Schemars dependency.

Suggested commit boundary: `Add optional schema generation to the config
contract crate`.

#### Phase 6.2: Implement contract primitive schemas

Derived output is insufficient for five families of contract type. Each needs
a feature-gated hand-written implementation.

| Type | Emitted schema | Why the derive is insufficient |
| --- | --- | --- |
| `dev::primitives::True` | `{"type": "boolean", "enum": [true]}` | The hand-written `Deserialize` accepts only `true`; a derive would emit a plain boolean. This restores `const: true` for `network.proxy.builtinTestServer`, which the rolling schema widened |
| `dev::primitives::NonEmptyString` | `{"type": "string", "minLength": 1}` | A newtype with a validating `Deserialize` |
| `dev::primitives::OptionalField<T>` | transparent forward to `T`, not referenceable | Must not emit the `anyOf: [T, null]` wrapper the rolling schema uses; this contract rejects explicit `null` |
| `string_enum!` enums | `{"type": "string", "enum": [...]}` with per-variant descriptions | The macro generates a string-only deserializer with aliases; a derive would emit Rust variant names and drop every alias |
| `string_marker!` markers | a single-value string `enum` | Zero-sized types with no derive-visible shape; these are what make each state-aware root self-discriminating |

Emit the last two from inside the macros under `#[cfg(feature =
"schema-gen")]`. A variant or marker value must not be addable without
appearing in the generated artifact.

PR #949 already established this pattern for tests: it derives canonical,
alias, non-string, and externally tagged object coverage from `string_enum!`'s
own value table. Schema emission is the second consumer of that table, so
extend the post-#949 macro rather than reintroducing a parallel value list.
Only the `dev` copy of the macro needs schema emission in this phase; the
`published/v0_6_0_alpha` and `published/v0_7_0_alpha` copies are Phase 11 work,
and the macro is deliberately duplicated per contract module so published
contracts share no field-bearing machinery.

Suggested commit boundary: `Add contract primitive schema implementations`.

#### Phase 6.3: Compose the multi-root development schema

Add a feature-gated `dev::schema` module exposing one entry point that returns
an unrendered `serde_json::Value`.

Composition:

1. Create one Schemars generator for the whole run.
2. Request a subschema for each of the eight roots — `OneShotRequest`,
   `WindowsSandboxProvisionRequest`, `IsolationSessionProvisionRequest`,
   `WslcProvisionRequest`, `StartRequest`, `ExecRequest`, `StopRequest`, and
   `DeprovisionRequest` — so each yields a reference into one shared,
   deduplicated `definitions` block.
3. Take the definitions, then assemble the root by hand: a `oneOf` over the
   eight references, plus `title`, `description`, and a `$comment` naming the
   discriminators.

`oneOf` rather than `anyOf` is exactly right, and the contract earns it. Every
root pins `version` to a constant, each state-aware root pins `phase` to a
distinct constant, each provision root pins `containment` to a distinct
constant, and every root is closed. At most one branch can ever match.

Known hazard, and it is already live rather than hypothetical: Schemars derives
definition names from the bare Rust type name and silently overwrites a
collision. The current `dev` contract has 57 public types with two colliding
names:

| Name | Locations | Impact |
| --- | --- | --- |
| `Containment` | `one_shot.rs` and `state_aware/provision/containment.rs` | Damaging — two different enums with different value sets |
| `Request` | `one_shot.rs` and the selector enum in `request.rs` | Harmless today; the selector never derives `JsonSchema` |

Rename through `#[schemars(rename = "...")]` in this step, before the
composition is written. Phase 6.7's collision test then guards a known-good
state instead of discovering the defect afterwards.

Suggested commit boundary: `Generate the 0.8.0-alpha development contract
schema`.

#### Phase 6.4: Share rendering and the TypeScript emitter

Integer-format normalization, root key ordering, and `$id` injection are
private to `wxc_common::wire`, and the TypeScript emitter is
`wxc_common::ts_emit`. The contract crate must not depend on `wxc_common`, so
this shared machinery has to move.

Let the generator own rendering. The contract crate exposes only an unrendered
value; `mxc_schema_gen` gains a dependency on the contract crate alongside its
existing `wxc_common` dependency and performs normalization, `$id` injection,
root ordering, and TypeScript emission for both models. Two acceptable
placements:

- move the shared code into `mxc_schema_gen` and reduce the `wxc_common`
  `schema-gen` surface to an unrendered value, which removes
  `generate_config_schema_json` and `generate_sdk_types_ts` from that crate's
  public API; or
- add a dependency-light emitter crate depending only on `serde_json`,
  consumed by both, which keeps the `wxc_common` public API intact.

Prefer the second. The first deletes two public functions from `wxc_common` in
the same commit that must keep two generated artifacts byte-for-byte identical,
which is a wider blast radius than this step needs. Narrowing the `wxc_common`
`schema-gen` surface is a reasonable follow-up once the artifacts are gated.

Take `$id` from the registry rather than the hardcoded constant currently in
`wire.rs`.

The binding constraint either way: the legacy artifacts must remain
byte-for-byte identical, so `check-schema-codegen.js` and
`check-sdk-types-codegen.js` pass with no regeneration. Move the code
unchanged and resist tidying it; those two gates are the regression test for
this step, so run them immediately before and after.

Suggested commit boundary: `Share schema rendering between the wire model and
the contract crate`.

#### Phase 6.5: Rework the generator command line

Replace the positional and `--ts` argument handling with subcommands. `clap` is
already declared in `[workspace.dependencies]`, but `mxc_schema_gen`'s own
manifest currently lists exactly one dependency (`wxc_common`), so this step
adds both `clap` and the contract crate to that manifest.

```text
mxc_schema_gen schema   --version <exact> [--out <path>]
mxc_schema_gen types    --version <exact> [--out <path>]
mxc_schema_gen schema   --legacy-wire     [--out <path>]
mxc_schema_gen types    --legacy-wire     [--out <path>]
mxc_schema_gen versions [--json]
```

Requirements:

- `--version` accepts only exact registered spellings. A published version
  returns a specific "published contract generation is not implemented until
  Phase 11" error rather than panicking or silently falling back.
- `--legacy-wire` targets the rolling model and is removed in Phase 9.
- Omitting `--out` writes to standard output, preserving current behavior.
- `versions --json` emits the registry — version, status, and default artifact
  paths — so the CI gate never hardcodes a version list. This is the seed of
  the generated registry metadata Phase 11 needs.
- Preserve the existing convention that status goes to standard output and
  errors to standard error; the gates depend on it.

Suggested commit boundary: `Add versioned subcommands to the schema generator`.

#### Phase 6.6: Commit the generated development artifacts

Commit the schema and the TypeScript oracle at the paths chosen in decisions 1
and 2, each carrying a banner that names the exact regeneration command and
states that the TypeScript file is a drift oracle rather than public API.

Expect the TypeScript emitter to need extension. It currently handles enums,
closed and open objects, references, the `anyOf [T, null]` nullable wrapper,
arrays, and scalars. The new schema adds a root-level `oneOf` over object
references, which should emit as a discriminated union type alias, and
single-value string constants. Extend the emitter for exactly those two
constructs and keep its output deterministic.

Suggested commit boundary: `Add generated 0.8.0-alpha contract artifacts`.

#### Phase 6.7: Add the drift gate and schema tests

Add `scripts/versioning/check-contract-codegen.js`, mirroring the two existing
codegen gates:

1. Read the artifact list from `mxc_schema_gen versions --json`; do not
   hardcode versions in the gate.
2. For each development contract, regenerate the schema and the TypeScript
   oracle into a temporary directory, compare modulo line endings, and print
   the exact regeneration command on failure.
3. Using the `ajv` dependency already present in `scripts/versioning`, assert
   accept-side and reject-side behavior against the **reorganized per-root**
   fixture corpus described below.

**The existing fixtures cannot be used as they stand.** Everything under
`tests/v0_8_0_alpha/fixtures/` is one-shot-scoped: `fixtures.rs` feeds all of
it to `OneShotRequest`, so "invalid" means *invalid as a one-shot request*, not
invalid against the contract. Applied to the composed eight-root schema, the
naive assertion fails immediately. `fixtures/invalid/state_aware.json` is

```json
{ "version": "0.8.0-alpha", "phase": "exec",
  "sandboxId": "example:12345678",
  "process": { "commandLine": "echo state-aware" } }
```

which is a well-formed exec request and validates cleanly against the exec
branch. The risk is not the red build; it is the obvious "fix" of weakening the
schema until the fixture fails again.

The accept side is equally misleading. All twelve valid fixtures are one-shot,
so fixture validation covers **one of the eight roots**; the seven state-aware
roots have no fixture coverage at all, because their contract tests are inline
JSON in `state_aware/*.rs`.

Therefore reorganize the corpus into per-root directories
(`fixtures/<root>/{valid,invalid}/`) and assert per root: a valid fixture for
root R validates against R's branch, and an invalid one fails it. Cross-root
documents then state what they actually mean — `state_aware.json` is invalid as
one-shot and valid as exec. Promote representative inline state-aware JSON into
fixtures so the seven remaining roots gain coverage.

This reorganization is Phase 5 test debt that Phase 6 inherits. Budget it as
part of this step rather than discovering it while writing the gate.

Add the gate to the `Versioning Checks` workflow beside the existing codegen
steps.

Two deliberate non-changes: `validate-configs.js` stays pointed at the rolling
dev schema, because the corpus is still declared at `0.6.0-alpha` and carries
experimental fields until Phase 8; and `schemas/schema-version.json` with
`check-schema-versions.js` remain untouched, because `devSchemaFile` still
names the rolling artifact and Phase 11 replaces that mechanism outright.

Suggested commit boundary: `Gate the generated contract artifacts against
drift`.

#### Phase 6.8: Defer public SDK conformance

Do not add public-SDK conformance tests against the versioned oracle. The SDK
still emits rolling and `0.6.0-alpha` shapes, so binding it to the exact
contract is Phase 8 work. Phase 6 requires only that the generated file type
checks in the SDK build and that the drift gate covers it. Record the
deferral in the codegen documentation.

#### Phase 6.9: Update documentation

- `docs/schema-codegen.md` — add a versioned contract codegen section covering
  the two coexisting generators and when the rolling one retires, the
  multi-root composition, the primitive schema table, the deliberate
  differences from the rolling schema, and the entry-point splice consequence
  that a CLI-override policy document is not itself contract-valid.
- `docs/versioning.md` and `docs/authoring-a-new-feature.md` — update the
  regeneration commands and add the contract crate to the authoring checklist.
- `.github/copilot-instructions.md` — update the schema system section and the
  experimental feature checklist, as the repository's pull request template
  requires whenever codegen commands change.
- This plan — record the Phase 6 status and the resolutions of decisions 1
  through 5.

#### Phase 6.10: Run the phase quality gate

```text
cargo fmt --all -- --check
cargo clippy -p mxc_config_contract --all-targets --features schema-gen -- -D warnings
cargo clippy -p mxc_schema_gen --all-targets -- -D warnings
cargo test -p mxc_config_contract --features schema-gen
node scripts/versioning/check-schema-codegen.js
node scripts/versioning/check-sdk-types-codegen.js
node scripts/versioning/check-contract-codegen.js
node scripts/versioning/check-schema-versions.js
node scripts/versioning/validate-configs.js
cd sdk/node && npm run build && npm test
```

Also confirm that `cargo tree -p mxc_config_contract --features schema-gen`
contains no MXC runtime, engine, or backend crate.

### Deliberate differences from the rolling schema

Record each of these in `docs/schema-codegen.md`. They are improvements, not
drift, and a reviewer comparing the two artifacts will otherwise read them as
regressions.

| Difference | Reason |
| --- | --- |
| Eight roots under `oneOf` instead of one permissive root | The contract has eight concrete roots; a single root cannot express per-phase required fields |
| `required: ["process"]` on the one-shot and exec roots | The rolling schema has no root `required` array at all; the splice design fixes `process` as required |
| No `anyOf: [T, null]` wrappers | The contract rejects explicit `null`; the rolling wrapper misdescribes it |
| `const: true` on `network.proxy.builtinTestServer` | Restores a constraint the rolling schema widened to `boolean` |
| Compatibility aliases documented | The rolling schema omits `appContainer` and `macos_sandbox` |
| The experimental subtree is closed | The rolling schema leaves it open by design; the exact contract closes it recursively |

### Phase 6 tests

Feature-gated Rust tests in the contract crate should cover:

1. All eight roots appear in the root `oneOf`.
2. No duplicate definition names, since a collision is silently overwritten.
3. Every root pins `version` to the `0.8.0-alpha` constant.
4. The one-shot root has no `phase` property; each state-aware root pins
   `phase` to a single-value constant; each provision root pins `containment`
   to a single-value constant.
5. `NonEmptyString` emits `minLength: 1` and `True` emits a `true` constant.
6. The one-shot and exec roots require `process`, and `process.commandLine`
   carries `minLength: 1`, so no future relaxation reaches the artifact
   unnoticed.
7. `OptionalField` fields are absent from `required` and carry no null branch.
8. Every `string_enum!` value set contains its canonical spelling and every
   alias.
9. Recursive closure: every object definition reachable from any root,
   including every experimental object, sets `additionalProperties: false`.
   Assert this by walking the document, not by spot-checking; recursive
   closure is the contract's headline property. The walker must follow `$ref`
   into `definitions` rather than stopping at the eight roots, or the
   experimental subtree — the property this is meant to prove — goes
   unchecked.
10. Generation is deterministic across two runs. This holds by construction
    because Schemars 0.8 uses `BTreeMap` unless the `preserve_order` feature
    is enabled; record that reason so nobody enables the feature later without
    realizing it breaks the drift gate.
11. Definition names are unique, guarding the `Containment` and `Request`
    collisions renamed in Phase 6.3.
12. Authoring diagnostics are comprehensible: assert the validator output for
    one representative malformed document, so the cost recorded in decision 6
    is measured rather than assumed.

### Phase 6 exit criteria

- The contract crate builds with and without `schema-gen`, the default build
  carries no Schemars dependency, and the crate's dependency boundary is
  unchanged.
- The generator produces deterministic `0.8.0-alpha` artifacts from the
  contract crate, and reproduces the rolling artifacts byte-for-byte.
- Both committed `0.8.0-alpha` artifacts are gated and cannot drift.
- Every existing valid `0.8.0-alpha` fixture validates against the generated
  schema and every invalid fixture fails.
- The parser, the corpus gate, `schemas/schema-version.json`, the published
  contracts, and all runtime behavior are unchanged.

### Phase 6 risks

| Risk | Mitigation |
| --- | --- |
| ~~Schemars marks `OptionalField<T>` fields required, or wraps them nullable~~ | Settled empirically against Schemars 0.8: fields are omitted from `required` and carry no null branch, provided `OptionalField` keeps its `Default` impl and its `JsonSchema` impl sets `is_referenceable() -> false`. See Phase 6.1 |
| Moving the shared rendering perturbs the legacy artifacts | Move the code unchanged and run both existing codegen gates before and after Phase 6.4 |
| Definition name collisions across `dev` submodules silently overwrite | Two collisions already exist (`Containment`, `Request`); rename them in Phase 6.3 and guard with the Phase 6.7 uniqueness test |
| The one-shot-scoped fixture corpus makes the schema gate assert the wrong thing | Reorganize fixtures per root in Phase 6.7 before wiring the gate; see the worked `state_aware.json` case |
| Eight-branch `oneOf` degrades editor diagnostics | Resolve decision 6 explicitly, and measure it with the Phase 6 authoring-diagnostics test |
| The TypeScript emitter cannot express the root `oneOf` | Emit a discriminated union type alias; the drift gate and the SDK build cover it |
| The command line change lands without updating call sites | Only two script call sites and a handful of documentation references exist; update them all in the Phase 6.5 commit |

## Phase 7 detailed design

Phase 7 may proceed in parallel with Phase 6. It depends on the complete
Phase 5 stack and should be branched from PR #949, the current top of that
stack, or from `main` once the stack merges. Its only overlap with Phase 6 is
`wxc_common/src/lib.rs` and `Cargo.toml`; Phase 6 does not touch
`config_parser.rs` and Phase 7 does not modify the contract crate.

### Phase 7 objective

Run the exact-contract parser beside the rolling parser, prove the two agree
on the runtime model for every input the corpus and the test suite can supply,
and classify every input where they deliberately disagree.

Phase 7 changes no runtime behavior. The rolling parser stays authoritative;
Phase 9 flips that over. The deliverable is a classification: for each parser
mode and each representative request shape, either the two paths converge, or
the difference is recorded as intentional tightening with a reason.

**This is differential testing, not shadowing.** "Shadow dispatch" is a
misnomer inherited from the original phase name. Shadowing normally means
running both implementations in production against live traffic, to discover
inputs the test corpus lacks. MXC has no live traffic to shadow: it is a CLI
and a library whose inputs are the corpus, the fixtures, and SDK-generated
envelopes, all of which can be enumerated in tests. A production dual-run would
double the parse cost of every request and add a runtime failure mode in a
security-sensitive path, in exchange for inputs that do not exist. Decision 2
resolves this; the phase name is retained only for continuity with earlier
sections.

### How Phase 7 differs from the Phase 5 adapter tests

The Phase 5D adapters already ship an equivalence helper that looks like the
same idea:

```rust
let current: wire::MxcConfig = config_deserialize::from_str(json).unwrap();
let contract: contract::OneShotRequest = serde_json::from_str(json).unwrap();
assert_eq!(to_value(into_wire(contract)), to_value(current));
```

The technique is identical. What is compared is not. Four differences, and the
last one is a defect to repair rather than a gap to fill:

1. **Depth in the pipeline.** The Phase 5 helper stops at `wire::MxcConfig`.
   Everything that gives the runtime model its meaning happens afterwards, in
   `convert_wire_config` and the state-aware normalization: containment
   mapping, filesystem path validation and normalization, proxy conversion,
   backend-section validation, schema-version validation, and telemetry
   population. Identical wire values can still diverge, or be rejected, in that
   layer.
2. **Both sides `unwrap`, so the disagreement set is unreachable.** The helper
   can only assert over inputs both paths accept. Phase 7's actual deliverable
   is the opposite set: inputs one path accepts and the other rejects, and
   inputs both reject with different diagnostics.
3. **Inputs are author-chosen.** Every Phase 5 input is a JSON literal written
   alongside the adapter it exercises, so it proves the cases the author
   thought of. Phase 7 runs the corpus, the fixtures, and all six loader entry
   points, including base64 and file decode, `ParseError` routing, logging
   conventions, and the spliced command override.
4. **The state-aware comparison currently targets a shape the rolling pipeline
   never builds.** `state_aware_tests` compares against
   `config_deserialize::from_str::<wire::MxcConfig>(json)` — the plain,
   unmasked deserialization. But `convert_wire_state_aware` masks `experimental`
   out of the source, sets `cfg.experimental = None`, and clears `sandbox_id`,
   `correlation_vector`, and the one-shot sections before normalizing. Those
   tests therefore validate against a straw man and carry false confidence.
   Repair them in Phase 7.2, when the seam makes the real pre-normalization
   value available to compare against.

### Phase 7 parser surface

The loader has six public entry points, all in `wxc_common::config_parser`,
and they do not all carry the same information:

| Entry point | Input | Returns | Callers |
| --- | --- | --- | --- |
| `load_request` | file path or base64 | `ExecutionRequest` | `lxc`, `mxc_darwin`, `wxc --probe` |
| `load_request_with_options` | file path or base64 | `ExecutionRequest` | options-aware variant |
| `load_request_from_value` | `serde_json::Value` | `ExecutionRequest` | `mxc_engine::policy` (two sites) |
| `load_mxc_request` | file path or base64 | `MxcRequest` | fuzz targets |
| `load_mxc_request_with_options` | file path or base64 | `MxcRequest` | `wxc` (four sites) |
| `load_mxc_request_from_json` | decoded JSON text | `MxcRequest` | `mxc_engine::state_aware` |

`parse_mxc_request_json` is the shared core: it borrows a
`RequestDiscriminator`, routes on the presence of `phase`, and calls either
`convert_wire_config` or `convert_wire_state_aware`.

**`load_request_from_value` has no source text.** It takes an already-parsed
`serde_json::Value` built in process by `mxc_engine::policy`, and the exact
contract deserializes from source text by design — that is what preserves line
and column diagnostics and what the non-goals protect when they exclude a JSON
`Value` migration engine. This entry point therefore cannot be shadowed the
same way as the others, and Phase 9 cannot simply repoint it. Resolve it as
decision 3 below.

### Phase 7 decisions required

Resolve these before implementation; each changes the shape of the work.

| # | Decision | Recommendation |
| --- | --- | --- |
| 1 | Whether the raw experimental JSON or the typed contract payload is authoritative for state-aware backend configuration | **Resolved.** The contract is the structural authority and the backend config type is the semantic authority; dispatch keeps reading `experimental_raw`. See "Phase 7 decision 1 resolved" below |
| 2 | Where the shadow comparison runs | In a test-only harness, not in the production call path — that is, differential testing rather than true shadowing. Running both parsers in production doubles parse cost on every request and turns any equivalence bug into a runtime failure in a security-sensitive path. The usual justification for shadowing, discovering inputs the corpus lacks, does not apply: MXC has no live traffic, and its inputs are enumerable. Test-only does not mean the phase has no production diff: see "Phase 7 production surface" below |
| 3 | How `load_request_from_value` reaches an exact contract | **Resolved.** Construct the declared version's contract root directly in Rust and adapt it, rather than round-tripping JSON. See "Phase 7 decision 3 resolved" below |
| 4 | Whether the entry-point command splice lands in Phase 7 or Phase 9 | Phase 7. Shadow dispatch cannot cover a path that does not exist, and the splice is the prerequisite that lets every contract keep `process.commandLine` required. It changes the entry point, not parser semantics, so it can land while the rolling parser stays authoritative |
| 5 | How runtime-model equivalence is asserted | `ExecutionRequest` derives `Serialize` but not `PartialEq`, so compare `serde_json::to_value` of both sides, as the Phase 5D adapter tests already do for `wire::MxcConfig`. `ParsedStateAwareRequest` derives neither, so it needs a field-by-field comparator or a test-only `PartialEq`. Audit that no field is `skip_serializing`, or a difference will compare equal |
| 6 | When the script reaches `mxc_engine::policy` | **Resolved.** At build time. `build_request` and `build_request_with_containment` take the script as an argument, so the required `process.commandLine` is satisfied structurally. See "Phase 7 decision 3 resolved" below |
| 7 | Whether `SandboxRequest::set_script` survives decision 6 | **Resolved: remove it.** Keeping it as a post-build override would preserve mutation of an already-validated model, which is the pattern decision 6 exists to remove. Both `mxc_ffi` call sites already hold the command at build time, so neither needs it. `set_experimental` stays: it gates execution rather than altering the validated shape |

#### Phase 7 decision 1 resolved: split structural and semantic authority

**Resolution.** The exact contract is the **structural** authority for the
state-aware experimental subtree: recursive closure, unknown-field rejection,
and shape. Each backend's config type remains the **semantic** authority: what
a field means, its defaults, and its validation. Dispatch continues to read
`experimental_raw` through `deserialize_config<C>`.

This is option C of the three considered, adopted deliberately rather than by
accident, with the drift it implies closed by a test.

**Why not option B (typed payload authoritative at dispatch) now.** The stated
goal is to surface errors as early as possible, and option C already achieves
that. The contract root is recursively closed, so `appIdd` fails at
`dev::parse_request`, before dispatch and before any backend runs. Option B
adds no earliness whatsoever; its only gains are removing the redundant second
parse and the drift risk. Since the Phase 5 stack is already long, the
redundancy is a fair price for now.

**Why option B stays cheap later.** All three state-aware provision config
types already live in `wxc_common`, not in the backend crates:

| Backend | `ProvisionConfig` | Defined in |
| --- | --- | --- |
| IsolationSession | `models::IsolationSessionProvisionConfig` | `wxc_common::models` |
| WSLC | `wire::WslcProvisionPhase` | `wxc_common::wire` |
| Windows Sandbox | `()` | — |

So the contract type, the adapter, and the backend config type are all visible
in one crate, and the crate-boundary obstacle does not exist. Option B's cost
is confined to dispatch plumbing — `StatefulSandboxBackend::ProvisionConfig`,
the six `deserialize_config` call sites in `state_aware_dispatch.rs`, the three
backend impls, and `state_aware_request.rs`. It touches no contract module, no
adapter destructuring, no published contract, and no generated artifact. Option
C adds no coupling that B must later unpick, and Phase 11 never freezes
state-aware types, so no deadline forces the choice.

**Enforcement is not weakened by dropping the duplicate payload.** Validation
is a property of parsing, not of adaptation:

```rust
let request = contract::parse_request(json)?;   // enforcement happens here
adapt_request(request, json)                    // runs on an already-valid value
```

The contract types are the validator; the adapter output is the payload.
Emitting `experimental: None` from the state-aware adapter discards a redundant
copy of a value that has already served its purpose as a check.

**Required work, both small.**

1. Delete the double population. The state-aware adapter currently fills both
   `config.experimental` and `experimental_raw` with no stated precedence.
   Emit `experimental: None` so `experimental_raw` is unambiguously the value
   dispatch reads, which also matches the shape the rolling parser builds and
   is what makes the Phase 7.2 test repair possible. This removes the
   `convert_*_experimental` conversions from the state-aware path.
2. Add a parity test in `wxc_common`, which can see both definitions, asserting
   that each backend's `ProvisionConfig` round-trips through its contract
   counterpart. The asymmetry rule: the contract may be **stricter** than the
   backend, since that is the intended tightening, but the backend must never
   accept a shape the contract rejects without a recorded Phase 7.4
   classification entry. This mirrors the existing
   `check-dotnet-errorcode-parity.js` gate.

**Telemetry must move to the seam.** The adapter currently maps
`experimental.telemetry` into `wire::Experimental`. The rolling parser does not:
it sets `cfg.experimental = None`, then reads telemetry back out of
`experimental_raw` after `convert_wire_config` and writes it onto the domain
request. Once the exact adapter emits `experimental: None`, the shared seam must
own telemetry population for both paths, which it should anyway. Missing this
makes telemetry silently disappear on the exact path. Note that the seam and the
adapter are different layers: the adapter converts a contract type to
`wire::MxcConfig` and is exact-path only, while the seam converts
`StateAwareWireInput` to `ParsedStateAwareRequest` and is shared.

**Known live divergence, and the trigger to revisit.** The two authorities
already disagree: `models::IsolationSessionProvisionConfig` is
`#[serde(default)]` over `Option<String>` and documents that "a JSON `null` is a
second spelling of absent", while the contract's `OptionalField<String>` rejects
explicit `null`. The backend also ignores unknown fields where the contract
rejects them. Under this resolution the stricter authority wins by rejecting
first, so `"appId": null` becomes a parse error; record it in the Phase 7.4
classification.

What option C does not guarantee is that the value dispatch acts on is the one
the contract produced. That is a non-issue while the payloads are plain strings
with no normalization — `appId`, `image`, `imageTarPath`. The moment a payload
field gains defaulting or canonicalization, the two authorities could interpret
the same bytes differently, and that is the trigger to move to option B.

#### Phase 7 decision 3 resolved: build the declared version's contract root

**Resolution.** `mxc_engine::policy` constructs the contract root for the
version the policy declares, then reuses the existing per-version adapter to
reach `wire::MxcConfig` and the normal semantic validation. It does not
serialize to text, and it does not deserialize a synthesized `Value`. The
script becomes a build-time argument, so the root's required
`process.commandLine` is satisfied structurally.

**Why this path is different from every other entry point.** The `Value` this
caller passes today is entirely synthesized by `build_wire_config` from typed
Rust — `json!` literals over `SandboxPolicy`, `Containment`, and
`WslcSection`. No user-authored JSON text exists anywhere on this path, so
there are no source positions to preserve and nothing is lost by never
producing text. There is exactly one production caller, at `policy.rs:848`;
the other occurrence is in `mod tests`.

**Why not deserialize a synthesized `Value` into the version's root.** That
alternative needs no new construction API and keeps one builder, but it
reintroduces a version-insensitive builder: a single function emitting a union
shape whose correctness is delegated to a downstream check. That is
structurally the pattern this plan exists to remove, even though its failure
mode is milder. It also surfaces errors as JSON field names for combinations
the caller expressed as typed values, and it makes "`build_wire_config` never
emits an explicit `null`" a load-bearing property, because `OptionalField`
rejects `null`.

**What construction costs.** Less than it first appears. Every contract root
field is already `pub`, `NonEmptyString::new` is public, and the `True` and
`string_marker!` types are unit structs. The entire gap is that
`OptionalField<T>` has no way to build a present value, so this adds one impl:

```rust
impl<T> From<Option<T>> for OptionalField<T>
```

The contract crate thereby becomes bidirectional — an input contract that can
also be constructed. Record that as intentional rather than incidental. A
feature gate (`build`) would make the boundary louder at the cost of a CI
matrix entry; it is not required.

**What it buys.** Version expressibility becomes largely a compile-time
property rather than a runtime check. A `published::v0_6_0_alpha::Request` has
no `wslc` field, so a WSLC section under a `0.6.0-alpha` policy cannot be
written at all. The declared version stops being an assertion about the
document and becomes the thing that selects the type.

**Recurring cost, accepted.** One builder per supported version — three today,
plus one at each publication, frozen alongside the frozen adapter that Phase 11
forks. Phase 10 makes this unavoidable in any design: `0.8.0-alpha` gains
`network.egress` and `network.ingress` while `0.6` and `0.7` keep the legacy
shape, so construction must branch on version regardless. The only question is
whether that branching lives in the type system or in `json!` literals.

**Cross-version combinations need explicit errors.** A `Containment::Wslc`
under a `0.6.0-alpha` policy must fail with a message naming the requirement,
for example "wslc requires 0.8.0-alpha", produced at the version match arm.

**The script becomes a build-time argument.** This is the second consumer of
`allow_missing_command`, and the reason Phase 7.1 is not only a CLI concern.
Today the builder emits `"commandLine": ""`, parses, and the caller patches the
parsed model through `set_script` — the same parse-then-patch pattern the CLI
splice removes. Both FFI call sites already hold the command at that point:

```rust
let mut request = build_request(&policy, None)?;
request.set_script(command);
run(request) / spawn_sandbox(request)
```

Change surface: the `build_request` and `build_request_with_containment`
signatures in `mxc-sdk` and `mxc_engine::policy`, the removal of
`SandboxRequest::set_script`, the two `mxc_ffi` call sites (`lib.rs` and
`streaming.rs`), and the rustdoc examples in both crates. The C
ABI does **not** change — `mxc_run` and `mxc_spawn` already take the policy and
the command together — so the generated C# bindings, the csbindgen codegen
gate, and the `ErrorCode` parity gate are untouched. The Node SDK is unaffected
because it spawns binaries.

`set_script` is removed rather than retained as an override: keeping it would
preserve exactly the parse-then-patch pattern this decision eliminates, and no
caller needs it once the script is a build-time argument. `set_experimental`
stays, because it gates execution rather than altering the validated shape.

With this and the CLI splice in place, `allow_missing_command` has no consumers
and is deleted outright.

### Phase 7 production surface

Decision 2 keeps the comparison in tests, but the phase still carries a
production diff. Three changes land in non-test code:

| Change | Kind | Step |
| --- | --- | --- |
| Command splice replaces `allow_missing_command` at the CLI entry point | Behavior-visible, entry point only | 7.1 |
| Script becomes a build-time argument to `build_request`, removing the second `allow_missing_command` consumer | Behavior-visible, `mxc-sdk` and `mxc_ffi` | 7.1 |
| `normalize_state_aware` extracted from `convert_wire_state_aware` | Behavior-preserving refactor | 7.2 |
| Exact-contract path added, dead in production | Compiled but uncalled | 7.3 |
| `From<Option<T>> for OptionalField<T>` added to the contract crate | New construction surface | 7.3 |

Nothing else moves: no call site of the rolling parser changes, `wxc_common`
grows no public API, and no runtime behavior differs. The seam in particular
must be real production code rather than a test-only copy — a copy would
validate a fork of the logic rather than the logic the rolling parser runs.

### Phase 7 step breakdown

#### Phase 7.0: Prepare the implementation branch

Base on PR #949 or on `main` once the Phase 5 stack merges. Confirm
`cargo test -p wxc_common` is green first, so a later failure is attributable
to this phase. No source files change in this step.

#### Phase 7.1: Remove `allow_missing_command` from both of its consumers

`allow_missing_command` has two consumers, not one, and both follow the same
parse-then-patch pattern. Remove the flag, the `command_required` relaxation in
`convert_wire_config`, and both patch sites.

**The CLI.** Implement the design recorded under "Entry-point-dependent command
requirements": resolve the CLI command override before the parser runs by
splicing it into the request source, then parse one complete document. This
replaces the post-parse `apply_command_override` mutation of
`ExecutionRequest::script_code`.

The ordering obstacle is that `cmdline_from_argv_for_context` needs a
backend-specific `CommandLineContext`, which today comes from the parsed
request. Run the splice as a probe-driven pre-parse step, and after the typed
parse assert that the context used matches the resolved containment.

**The programmatic builder.** `mxc_engine::policy::build_request` and
`build_request_with_containment` take the script as an argument instead of
emitting `"commandLine": ""` and relying on the caller's later `set_script`.
See the decision 3 resolution for the change surface; the C ABI is unaffected.

Both halves stand alone, change only entry points, and are independently
reviewable. Land them first so the rest of the phase shadows the real shape.

Suggested commit boundary: one commit per consumer.

#### Phase 7.2: Extract the shared state-aware normalization seam

`convert_wire_state_aware` currently interleaves three concerns: recovering
`experimental_raw` and the masked base JSON, a series of validations that read
the raw block, and the normalization into `ParsedStateAwareRequest`.

Extract the third concern into a function over the neutral value both parsers
can produce:

```rust
fn normalize_state_aware(
    input: StateAwareWireInput,
    logger: &mut Logger,
) -> Result<ParsedStateAwareRequest, WxcError>
```

Keep this behavior-preserving: the rolling parser must produce byte-identical
results before and after, proven by the existing `wxc_common` tests. Do not
fold the exact path in yet.

Note which of the interleaved validations become structurally impossible for
exact input — the non-object `experimental` guard, the moved-to-stable
`seatbelt` / `macos_sandbox` check, the stray one-shot section rejection, and
the `containment`-on-non-provision rejection are all closed by the contract
roots. They stay in the seam for the rolling path; for exact input they are
unreachable, and the difference in the resulting *error message* is Phase 7.4
classification material.

Repair the Phase 5D state-aware equivalence tests in this step. They currently
compare against the unmasked `wire::MxcConfig` deserialization, which the
rolling state-aware pipeline never produces; once the seam exposes the real
pre-normalization value, point them at it.

Per the decision 1 resolution, the seam owns telemetry population for both
paths, and the state-aware adapter stops emitting `config.experimental`.

Suggested commit boundary: `Extract the shared state-aware normalization seam`.

#### Phase 7.3: Add the private exact-contract path

Add a private path in `config_parser` that probes the version, dispatches to
the exact registry, calls `dev::adapt_request`, and produces the same runtime
model:

- one-shot results feed the existing one-shot normalization
- state-aware results feed `normalize_state_aware` from Phase 7.2

Nothing calls this path in production. It exists for the harness in Phase 7.4
and becomes authoritative in Phase 9.

Write it as ordinary private production code carrying
`#[cfg_attr(not(test), allow(dead_code))]`, the idiom the adapter modules and
`state_aware_wire` already use. That attribute means dead in a production build
and genuinely reachable under `cargo test`, so the path is compiled, formatted,
and clippy-checked alongside everything else, and Phase 9's cutover is a routing
change rather than a code move. Do not place the path inside `#[cfg(test)]`:
that would force Phase 9 to move code into production at the moment it becomes
authoritative, so the validated code would not be literally the shipped code.

Keep the existing `#[cfg_attr(not(test), allow(dead_code))]` suppressions on the
adapter modules and on `state_aware_wire`. They are still required: an uncalled
exact path leaves everything it calls dead in production too. Phase 9 removes
all of them together when the router first calls the exact path.

This step also adds `impl<T> From<Option<T>> for OptionalField<T>` to the
contract crate and repoints `mxc_engine::policy` at the per-version contract
builders, per the decision 3 resolution. Unlike the parser path, that builder is
live in production immediately: it is not a shadow, it is the only way that
entry point reaches a request.

Suggested commit boundary: `Add the shadow exact-contract parser path`.

#### Phase 7.4: Build the equivalence harness and classify differences

Put the harness in an inline `#[cfg(test)]` module in `config_parser.rs`, the
crate's dominant convention and the only placement that keeps the exact path
private. An integration test under `src/core/wxc_common/tests/` can only reach
`pub` items, and making an unfinished parser part of `wxc_common`'s public API
to test it is not worth the corpus convenience; read the corpus from
`CARGO_MANIFEST_DIR` instead.

For each input, parse with both paths, adapt both to the runtime model, and
assert semantic equivalence by the mechanism chosen in decision 5.

Inputs must cover every loader mode, both request kinds, every state-aware
phase, every provision backend, `0.6`, `0.7`, and `0.8` declarations, the
command-splice path from Phase 7.1, immutable post-provision policy, telemetry,
required envelope fields, and source-position diagnostics.

Differences are not failures; unclassified differences are. Record each one in
a table with its input, both behaviors, and the reason. Expect at least:

- a `0.6.0-alpha` document carrying `experimental`, which the rolling parser
  accepts and the exact contract rejects as an unknown field
- explicit `null` on any optional field, which `OptionalField` rejects
- `"phase": null`, which the rolling parser treats as one-shot and the exact
  phase probe rejects as a malformed declaration
- `"appId": null` on an IsolationSession provision request, which
  `models::IsolationSessionProvisionConfig` documents as a second spelling of
  absent and the contract's `OptionalField` rejects
- an unknown field inside an experimental backend payload, which the backend
  config type ignores and the closed contract rejects
- curated policy diagnostics replaced by structural Serde errors, most visibly
  the IsolationSession `filesystem` and `ui` rejections, whose current messages
  explain *why* the backend cannot honor the policy
- any corpus document that is valid under one root and invalid under another

Suggested commit boundary: `Add rolling-versus-exact parser equivalence tests`.

#### Phase 7.5: Record the classification in this plan

Fold the difference table into the plan as the input to Phase 8's migration and
Phase 9's cutover. A difference that survives to Phase 9 unclassified is a
break MXC would be shipping without deciding to.

### Phase 7 tests

1. Rolling-path behavior is unchanged, proven by the existing `wxc_common`
   suite before and after the Phase 7.2 extraction.
2. Both paths converge for every representative one-shot request across `0.6`,
   `0.7`, and `0.8`.
3. Both paths converge for every state-aware phase and provision backend.
4. Both paths converge across every loader mode, including the spliced
   command-override path.
5. Every divergence is asserted explicitly and matches its classification.
6. Source-position diagnostics are compared, not just accept/reject outcomes.
7. The corpus parses through the exact path with its acceptance classified,
   which is the direct input to Phase 8.

### Phase 7 exit criteria

- The rolling parser is still authoritative and its behavior is unchanged.
- The exact path produces the same runtime model for every convergent input.
- Every divergence is classified with a recorded reason.
- `allow_missing_command` is gone and the command splice is covered by tests.
- Decisions 1 through 5 are resolved and recorded.

### Phase 7 risks

| Risk | Mitigation |
| --- | --- |
| The seam extraction silently changes rolling behavior | Extract without tidying; the existing suite is the regression test, run before and after |
| Shadow parsing lands in the production path | Resolve decision 2 first; keep the harness in tests |
| `serde_json::to_value` equivalence hides a difference in a skipped field | Audit `ExecutionRequest`'s `Serialize` for `skip_serializing`, or add a test-only `PartialEq` |
| The experimental authority question is deferred again | It is decision 1 and it gates Phase 7.2; after Phase 9 the asymmetry is permanent |
| `load_request_from_value` is discovered to have no exact path during Phase 9 | It is decision 3, resolved here rather than at cutover |
