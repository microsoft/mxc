# MXC Version-Specific Config Parsers

Status: implementation plan and decision record. Phases 1-6.5 are merged
through PRs #807, #816, #835, #838, #907, #912, #909, #910, #929, #941,
#949, #966, #968, and #1027. The legacy rolling-model v0.8 release shipped
from tag `v0.8.0`; Phase 6.5 reconstructed its exact Rust contract and
advanced exact development to `0.9.0-alpha`.

The implementation PR stack was published through Phase 9.5 as of 2026-09-08,
with seven PRs open at that checkpoint. Phase 10a and the atomic 10b-10d
cutover are now published on their implementation branches, with no PRs
opened for those branches yet. "Complete" below means
implemented, not merged or fully accepted; native Unix and live-backend
acceptance remain outstanding.

| Scope | PR | Published tip |
| --- | --- | --- |
| Phase 7a: command-before-parse integration | #969 | `aa6c12d3` |
| Phase 7.2: shared state-aware normalization | #1091 | `c3519b3d` |
| Phase 7.3: private exact parser and builders | #1096 | `b13c0bae` |
| Phase 7.4: differential equivalence harness | #1097 | `3b411771` |
| Phase 8: producer and corpus migration | #1099 | `92581c44` |
| Phase 9: authoritative exact dispatch | #1104 | `1116d233` |
| Phase 9.5: typed state-aware dispatch | #1123 | `2ae06e78` |
| Phase 10a: additive IsolationSession acknowledgment | Not opened | `16ed3c81` |
| Phases 10b-10d: directional-only v0.9 cutover | Not opened | `8722f343` |

The stack root was rebased onto `origin/main` at `29702c3a` on 2026-09-04.
Review fixes and subsequent restacks were published with explicit leases on
2026-09-05; #1096 and #1104 are each a single commit relative to their stack
bases. Phase 7.5 is maintained on this dedicated plan branch. Phase 9.5 was
published as a single commit in #1123 on 2026-09-08, with acceptance pending.
The rewritten Phase 9a/9b tips are `1116d233`/`2ae06e78`; Phase 10a was
squashed and restacked on that parent as `16ed3c81`. The atomic 10b-10d
implementation is published as `8722f343` on
`user/gudge/version_specific_config_parsers_phase10b`. Phase 11a is the next
unimplemented unit. The planned end state after Phases
10-11 publishes `0.9.0-alpha` and opens `0.10.0-alpha` development.

The phase descriptions retain the design and behavior at each intermediate
boundary. In particular, references to rolling production authority in Phase 7
or Phase 8 do not describe the completed Phase 9 implementation.

Original planning base: `origin/main` at
`692275b84eaa3f83cd8582dc774bc5f354f46ccf` (2026-08-14).

## 1. Goals, non-goals, and overall design

### Goals

- Require every config to declare an exact registered version.
- Deserialize each published version through its own JSON-shape-frozen Rust
  wire types.
- Support exact published contracts for `0.6.0-alpha`, `0.7.0-alpha`, and
  `0.8.0-alpha`.
- Use `0.9.0-alpha` as the current mutable development contract.
- Publish `0.9.0-alpha` as the first stable schema released through the exact
  contract publication path, with legacy Network fields removed, then advance
  development to `0.10.0-alpha`.
- Keep `experimental` completely absent from published contracts.
- Make the development contract's `experimental` structure recursively closed,
  while allowing that entire unpublished contract to change freely.
- Preserve the existing source-aware Serde diagnostics, duplicate-field
  rejection, secret redaction, semantic validation, and backend behavior.
- Keep adapters from versioned wire types into the runtime model outside the
  immutable published modules.

### Non-goals

- Reproduce historical runtime bugs or security defaults.
- Make a declared version select backend behavior or weaker validation.
- Retrospectively claim that the old rolling parser enforced independent
  `0.6`, `0.7`, or `0.8` shapes.
- Introduce a JSON `Value` migration engine or a second schema-validation
  language in the runtime trust boundary.
- Edit the existing immutable `0.6` or `0.7` stable schema files.
- Reject positional JSON arrays that Serde can deserialize into structs. That
  object-root hardening is out of scope for this work in every phase.
- Publish `0.10.0-alpha` or advance development beyond it; `1.0.0` remains a
  later milestone.

### Contract lifecycle and target state

The legacy rolling stack shipped config schema `0.8.0-alpha` under product tag
`v0.8.0`. Phase 6.5 reconstructed that immutable published contract and advanced
the exact development contract to `0.9.0-alpha`.

| Point in the work | Published exact contracts | Mutable exact development contract |
| --- | --- | --- |
| After Phase 6.5 | `0.6.0-alpha`, `0.7.0-alpha`, `0.8.0-alpha` | `0.9.0-alpha` |
| End state after Phase 11 | `0.6.0-alpha`, `0.7.0-alpha`, `0.8.0-alpha`, `0.9.0-alpha` | `0.10.0-alpha` |

Published request types contain only the stable one-shot surface. They exclude
`experimental`, `phase`, `sandboxId`, `correlationVector`, experimental
containments, and the abstract `vm` intent while it resolves only to an
experimental backend. The historical `0.5.0-alpha` schema remains unsupported;
no runtime contract is added for it.

#### Freeze model

Before Phase 11, a published contract is frozen with respect to its observable
JSON contract: field names and nesting, required and optional presence,
accepted canonical and compatibility spellings, enum values, null handling,
unknown-field rejection, and local value rules. Its Rust implementation may
still gain safe constructors, helper methods, traits, documentation, tests, or
internal refactoring needed to complete exact dispatch, provided those changes
do not alter that JSON behavior.

Phase 11 freezes both the JSON shape and the contract-to-runtime behavior:
exact dispatch, adapter normalization, field-presence semantics, typed builder
output, and contract-specific acceptance and rejection behavior. After that
point, observable semantic changes require a new contract version. Source code
is not byte-frozen: internal refactoring and security hardening remain allowed
when the freeze gates prove the published shape and behavior are unchanged.
Contract versions never select obsolete backend implementations or weaker
shared semantic validation.

### Contract reconstruction policy

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

### Two coexisting versioning models
Phase 9 makes exact dispatch authoritative on the implementation stack. Rolling
artifacts and compatibility metadata coexist with it until Phase 11 retires
their remaining consumers; they no longer authorize production requests.

#### The two models

| | Rolling (old stack) | Contract (new stack) |
| --- | --- | --- |
| Source of truth | `schemas/schema-version.json` | `mxc_config_contract::registry` |
| Shape authority | `wxc_common::wire` | per-version Rust modules |
| Version model | a range, `min` to `maxSupported` | an exact enum |
| Artifacts | `…0.9.0-dev.json`, `generated/wire.ts` | immutable published modules plus `…0.9.0-alpha.json` and `generated/v0_9_0_alpha/wire.ts` |
| Gates after cutover | `check-schema-versions`, `check-schema-codegen`, `check-sdk-types-codegen` for retained metadata/oracles | `check-contract-codegen`; `validate-configs` selects an exact schema per declared version |
| Enforced at runtime | yes through Phase 8 | yes beginning with Phase 9 |

#### Current resolution

- v0.8 shipped under the legacy rolling scheme and its tagged stable schema is
  immutable; the exact Rust module reconstructs that contract but does not
  regenerate the released artifact.
- Both rolling and exact development now use the v0.9 line, with `-dev` reserved
  for rolling artifacts and `-alpha` used by exact contracts.
- The exact codegen gate covers mutable development artifacts only.
- The Phase 9 implementation stack makes exact registry dispatch authoritative
  and retains rolling parsing only as a test oracle.
- Corpus validation selects an exact schema from each document's declaration;
  intentionally invalid fixtures are explicitly exempted, not treated as valid.
- Phase 11 still replaces duplicated version metadata and adds general
  published-contract freeze/digest enforcement. Its final cleanup also deletes
  the test-only rolling parser, rolling builders, and legacy payload-extraction
  references after replacing their coverage with exact-contract regression
  gates.

### Intended parse flow
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
    +-- 0.8.0-alpha --> published::v0_8_0_alpha::Request
    `-- 0.9.0-alpha --> dev one-shot or phase-specific state-aware request
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

#### Entry-point-dependent command requirements

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
- The containment inspection's raw-string-to-backend mapping lives outside the
  immutable contract modules, in `wxc_common::splice::CommandSource` beside
  the duplicate-preserving source edit.
- `CommandSource::one_shot_backend` deserializes the declared containment as
  `wire::Containment` and reuses the same `From` conversion as the parser —
  including the absent-containment host default and the abstract `vm` intent.
  The exhaustive `one_shot_backend_agrees_with_the_parser_for_every_spelling`
  test pins all accepted spellings plus the absent and explicit-null cases.
  This removes the independent mapping that would otherwise require a
  post-parse drift assertion; see the 7.1.1.4 note.

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

## 2. Phases 1-11

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
- **Phase 5B** — one-shot development adapter, merged in PR #910
- **Phase 5C** — phase discriminator and state-aware development contracts,
  merged in PR #929
- **Phase 5D** — state-aware adapter and wire-equivalence tests, merged in
  PR #941
- **Phase 5A follow-up** — string enum contract coverage generated from each
  `string_enum!` declaration, addressing Phase 5A review feedback after #909
  merged. Merged in PR #949. It
  rewrites the `string_enum!` macro in the `dev`, `published/v0_6_0_alpha`, and
  `published/v0_7_0_alpha` modules so canonical, alias, non-string, and
  externally tagged object coverage derives from the macro's own value table.
  Phase 6.2 extends those same macros, so it must build on this shape
- **Phase 5A remediation** — the `ProcessContainerCapability` validating
  newtype closing the Phase 6 review finding, merged in PR #966 after the
  follow-up. See "Phase 6 review finding: contract
  value-rule gaps"

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

Merged in PR #909.

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

Merged in PR #910.

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

Merged in PR #929.

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

Merged in PR #941.

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

The detailed design, the resolved decisions, and the implementation record are
in the Phase 6 detailed design section below. Phase 6 merged in PR #968.

### Phase 6.5: Reconstruct published v0.8 and advance exact development to v0.9

Merged in PR #1027.

The legacy rolling stack shipped v0.8 before exact dispatch was authoritative.
This phase bridges that release into the exact-contract model without changing
its tagged stable schema:

- reconstruct `published::v0_8_0_alpha` from the released stable one-shot
  surface using the v0.6/v0.7 bootstrap-tightening policy
- add an exhaustive frozen v0.8 adapter into the current rolling wire model
- preserve the tagged v0.8 schema byte-for-byte and do not generate a published
  v0.8 TypeScript oracle
- move the mutable exact contract, adapters, tests, fixtures, schema, and
  TypeScript oracle from v0.8 to `0.9.0-alpha`
- register v0.8 as published and v0.9 as development
- add directional-network adapter coverage and cross-version boundary tests
- update codegen and authoring documentation to distinguish immutable
  published artifacts from mutable development artifacts

Done when the published v0.8 contract and adapter are fully covered, the exact
v0.9 artifacts pass their drift gate, the tagged stable schema is unchanged,
and no production parser behavior changes. Appendix B records the final
implementation details.

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

Shadow comparison covers the shipped v0.8 legacy and directional Network
surfaces and the inherited v0.9 development surface. Any remaining removal of
legacy Network syntax happens only on the authoritative v0.9 exact contract;
published v0.6/v0.7/v0.8 syntax remains immutable.

### Phase 8: Migrate producers and the config corpus

Status: complete at `92581c44` on
`user/gudge/version_specific_config_parsers_phase8`, open as PR #1099 and
stacked on Phase 7.4 PR #1097.

Do not rely on the original base-commit counts; the corpus changes frequently.
Regenerate and check in an inventory report at the start of this phase,
covering configs, examples, SDK producers, state-aware envelopes, and schema
references.

An early focused audit (2026-08-11, `tests/configs` plus
`tests/examples`) found:

- 97 configs declaring `0.6.0-alpha`: 54 conformed to the exact stable
  contract, while 43 used experimental or later-version surfaces
- 55 unversioned configs: none conformed after temporary `0.6.0-alpha`
  injection; they were experimental, state-aware, or annotation-bearing

These counts are evidence that migration is required, not a frozen Phase 8
input.

Experimental and state-aware configs move to the `0.9.0-alpha` development
contract. Stable configs are classified and assigned an exact published
version (`0.6.0-alpha`, `0.7.0-alpha`, or `0.8.0-alpha`).

Published-version configs retain their version-specific Network syntax.
Development configs still using legacy Network fields migrate to the v0.9
stable-candidate directional shape in Phase 10.

Update Node, C#, Rust SDK, FFI, examples, tests, and `$schema` references.
State-aware producers must stop hard-coding `0.6.0-alpha`.

#### Phase 8 execution breakdown

The migration is selective. Do not replace every `0.6.0-alpha` occurrence:
stable one-shot tests and examples may legitimately exercise the minimum
published version. Change a declaration only when the document or producer
uses a shape that its declared exact contract cannot express.

| Item | File | Edit type | Work | Status |
| --- | --- | --- | --- | --- |
| 8a | `docs/version-specific-parser-migration-inventory.md` plus the corpus and producer directories below | Addition and audit | Regenerate the inventory from the Phase 7d tip. For each input record its request kind, current declaration, exact classification, target declaration, schema reference, and owning producer. Retain the report as the review and migration audit record | Complete in #1099 |
| 8b | `tests/configs/**/*.json`, `tests/examples/**/*.json`, `tests/policy/**/*.json` | JSON changes | Assign an exact version to all 55 documents with no declaration. Stable one-shot documents select the earliest published contract that expresses their shape; development containment, experimental, and state-aware documents select `0.9.0-alpha` | Complete in #1099 |
| 8c | The 45 explicitly inventoried development-containment documents | JSON changes | Replace their published declaration with `0.9.0-alpha`; do not change the containment or policy merely to fit an older contract | Complete in #1099 |
| 8d | The two explicitly inventoried published-experimental documents | JSON changes | Move them to `0.9.0-alpha` while preserving the experimental payload | Complete in #1099 |
| 8e | The 21 explicitly inventoried published state-aware documents | JSON changes | Move provision, start, exec, stop, and deprovision envelopes to `0.9.0-alpha` | Complete in #1099 |
| 8f | `tests/configs/wslc_destroy_on_exit_false.json`, `tests/configs/wslc_destroy_on_exit_true.json` | JSON changes | Migrate the two WSLC documents whose first exact rejection is `_comment`; preserve the annotation and record that containment becomes the next structural distinction | Complete in #1099 |
| 8g | `sdk/node/src/state-aware-helper.ts`, `sdk/node/tests/unit/state-aware.test.ts`, `sdk/node/tests/unit/state-aware-types.test.ts`, development-backend cases in `sdk/node/tests/unit/sandbox.test.ts`, and applicable Node examples/README sections | TypeScript, tests, and documentation | Change state-aware and development-only producers from `0.6.0-alpha` to `0.9.0-alpha`. Keep stable one-shot minimum-version and compatibility coverage on its published version | Complete in #1099 |
| 8h | `sdk/dotnet/Microsoft.Mxc.Sdk/SchemaVersions.cs`, `sdk/dotnet/Microsoft.Mxc.Sdk.Tests/MxcLifecycleTests.cs`, and `sdk/dotnet/README.md` | C#, tests, and documentation | Change `SchemaVersions.StateAware` and lifecycle producer expectations to `0.9.0-alpha`; do not change `SchemaVersions.Minimum` | Complete in #1099 |
| 8i | `src/core/mxc-sdk/examples/**/*.rs`, `src/core/mxc-sdk/tests/**/*.rs`, FFI request/state-aware tests under `src/ffi/mxc_ffi`, and `tests/policy/**/*.json` | Rust, tests, and JSON changes | Migrate state-aware and development-backend producers and fixtures while retaining published-version compatibility tests | Complete in #1099 |
| 8j | `$schema` members under `tests/configs` and `tests/examples`, SDK documentation links, and editor examples | JSON and documentation changes | Make every schema reference agree with its document's selected exact version. Do not add `$schema` solely to satisfy the parser; add or change it only where the document already carries or documents an editor schema reference | Complete in #1099 |
| 8k | `src/core/wxc_common/src/config_parser.rs`, `expected_corpus_divergences` and its differential corpus test | Test changes | Remove each declaration-only migration from the exact-stricter inventory. Keep the focused non-corpus divergence tests and the seven explicitly recorded development-contract tightenings below. Any unclassified, exact-looser, or runtime-model divergence must fail with its path and classification | Complete in #1099 |
| 8l | Rust workspace, `sdk/node`, `sdk/dotnet`, FFI, schema/versioning scripts, and corpus validators | Validation | Run the complete validation matrix below and repair producer expectations without weakening exact contracts or the differential harness | Complete in #1099 |
| 8m | `user/gudge/version_specific_config_parsers_phase8` | Commit and PR | Commit the mechanical migration as one reviewable change and open it against the Phase 7d branch used by PR #1097 | Complete at `92581c44` in #1099 |

Review follow-up completed the remaining producer paths: the three engine
state-aware test requests now declare `0.9.0-alpha`, and both WSLC test-script
helpers default an inline request's absent version on a clone. Explicit values
(including deliberately invalid versions), caller hashtables, and file-fixture
handling are preserved. The lifecycle guide distinguishes optional SDK config
versions from required wire declarations, uses the existing
`StateAwareSchemaVersion`, and labels post-graduation examples as hypothetical.
The WSLC SDK examples also use the development version.

#### Phase 8 authority and compatibility boundaries

- Production loaders remain on the rolling parser throughout this phase.
- Exact contract types, adapters, schemas, and runtime behavior do not change.
- Published v0.6/v0.7/v0.8 documents retain the Network syntax belonging to
  their published version.
- Development v0.9 documents retain their current Network syntax; the
  directional-only v0.9 change is separate work.
- Do not move a stable one-shot document to v0.9 merely because v0.9 can
  express it. Select the earliest published version that truthfully represents
  the document.
- Do not alter an invalid fixture into a valid policy. Give it the exact
  declaration for the shape whose invalid behavior it is intended to test.
- The 148 currently convergent accepted documents and nine convergent rejected
  documents remain regression inputs. The 125 exact-stricter corpus documents
  are the migration set. Version migration resolves 118 of those divergences;
  seven remain because the exact contract intentionally rejects structure that
  the rolling parser either ignores or defers to backend validation.

#### Phase 8 expected corpus result

After migration, the same 282-document corpus must produce:

| Result | Expected count |
| --- | ---: |
| Both parsers accept with equivalent runtime models | 266 |
| Both parsers reject | 9 |
| Rolling accepts and exact rejects | 7 |
| Rolling rejects and exact accepts | 0 |
| Both accept with different runtime models | 0 |

The exact counts are tied to the Phase 7d inventory. If the corpus changes
while Phase 8 is in progress, regenerate the report and explain the delta
rather than editing the expected counts until the test passes.

#### Phase 8 residual parser differences

**Adopted 2026-09-03.** Migration exposed seven differences that cannot be
removed without weakening the exact contract, changing rolling production
behavior, or changing what the owning backend tests exercise:

| Fixtures | Exact-contract difference | Disposition |
| --- | --- | --- |
| `isolation_session_configid_ignored.json`, `isolation_session_one_shot_stray_config_ignored.json` | The rolling parser ignores unknown one-shot `experimental.isolation_session` members; the recursively closed exact one-shot contract rejects them | Retain as classified rolling-compatibility inputs through Phase 8. At the Phase 9 cutover, change their expected behavior to structural rejection or retire the obsolete compatibility coverage |
| `isolation_session_state_aware_provision_rejected_denied.json`, `isolation_session_state_aware_provision_rejected_network.json`, `isolation_session_state_aware_provision_rejected_ui.json`, `isolation_session_state_aware_provision_with_filesystem.json` | The rolling parser accepts the envelope and lets IsolationSession return `policy_validation`; the exact backend-specific provision root forbids the unsupported policy structurally | Retain the parser divergence while preserving direct backend-policy coverage. After Phase 9, the public JSON surface rejects structurally; backend validation coverage must not depend on bypassing the exact contract |
| `wslc_state_aware_exec_rejected_filesystem.json` | The rolling parser defers immutable post-provision filesystem policy to WSLC validation; the exact exec root forbids `filesystem` structurally | Retain the parser divergence while preserving direct immutable-policy coverage. After Phase 9, expect structural JSON rejection and keep backend validation covered below the exact parser boundary |

These are all exact-stricter results. The executable inventory must name each
path and verify its expected structural diagnostic. A new residual path, an
exact-looser acceptance, or a runtime-model difference remains a test failure.

The current inventory pins the field paths for all seven residual rejections,
including `network.defaultPolicy` as a typed structural error. Phase 9 has
completed their public-surface cutover: the first two fixtures are renamed
`isolation_session_configid_rejected.json` and
`isolation_session_one_shot_stray_config_rejected.json`, and the backend suites
expect structural rejection while retaining direct backend-policy coverage.
The seven differences remain only as rolling-oracle characterization, not
unfinished migration work.

#### Phase 8 validation

Run, in order:

1. `cargo fmt --all -- --check`
2. `cargo check --workspace --all-targets`
3. `cargo clippy --workspace --all-targets -- -D warnings`
4. `cargo test --workspace`
5. Applicable Rust cross-target checks for files touched by the migration.
6. From `sdk/node`: `npm run build` and `npm test`.
7. From `sdk/dotnet`:
   `dotnet test --solution Microsoft.Mxc.Sdk.slnx`.
8. `node scripts/versioning/validate-configs.js`.
9. `node scripts/versioning/check-schema-versions.js`.
10. `node scripts/versioning/check-contract-codegen.js`.
11. `node scripts/versioning/check-sdk-types-codegen.js`.

No backend E2E run is required solely for version-declaration changes. Run the
applicable backend suite if migration changes any policy value or serialized
shape beyond `version` and `$schema`.

#### Phase 8 exit criteria

- Every valid complete request config, example, and SDK-produced envelope
  declares a registered version that can express its complete shape. Negative
  fixtures retain their intended invalidity; the three wrapper-only policy
  inputs recorded in the inventory remain non-request documents.
- State-aware and development-only producers emit `0.9.0-alpha`.
- Stable one-shot producers retain intentional published-version coverage.
- Every existing `$schema` reference matches the selected declaration.
- `expected_corpus_divergences` contains exactly the seven recorded
  development-contract tightenings and no declaration-only migration entries.
- The differential corpus test reports 266 equivalent accepts, nine shared
  rejections, seven classified exact-stricter results, and no unclassified,
  exact-looser, or runtime-model divergence.
- All applicable validation commands pass.
- No production parser routing, contract shape, adapter behavior, or backend
  policy behavior changes.

This step is primarily mechanical and is suitable for delegation.

### Phase 9: Enable exact dispatch

Status: complete at rewritten tip `1116d233` on
`user/gudge/version_specific_config_parsers_phase9a`, open as PR #1104 and
stacked on Phase 8 PR #1099.

Replace the major/minor range check with exact registry dispatch.

**Adopted 2026-09-03:** the declared exact version is sufficient authorization
to parse that registered contract. Do not add an
`allow_development_contract` parser option and do not make registry lifecycle
status an out-of-band parsing gate. A caller that declares `0.9.0-alpha` has
explicitly selected the mutable development contract.

Contract selection and feature execution remain separate concerns:

- `version` selects the exact JSON contract
- `--experimental` authorizes execution of functionality that remains
  experimental

A v0.9 request using only stable fields therefore parses and executes without
`--experimental`. A v0.9 request using an experimental containment or feature
parses through the closed development contract, then the existing execution
gate rejects it unless the caller supplied `--experimental`. Published
v0.6/v0.7/v0.8 versions reject `experimental` as an ordinary unknown field
because their frozen contracts do not define it. Missing and unregistered
versions fail exact probing; there is no fallback to the latest version.

After parity tests pass, remove the direct version-insensitive wire
deserialization path.

Remove the remaining `#[cfg_attr(not(test), allow(dead_code))]` suppressions on
the development adapter, `state_aware_wire`, and the Phase 7.3 exact path.
Published one-shot adapters are already referenced by the hidden construction
bridge, but no public production entry point calls that bridge before this
phase. Phase 9 is when the router first calls the exact parser path.

Exact dispatch must be authoritative before the v0.9 stable-candidate contract
removes legacy Network syntax. This sequencing protects all published
v0.6/v0.7/v0.8 callers from the version-insensitive breaking-change failure
mode that caused PR #676 to be reverted.

The implementation makes the exact parser authoritative for CLI, probe,
one-shot, state-aware, Rust SDK, and FFI request construction. Input sources
are still decoded once, and CLI command overrides are spliced into the source
before exact typed parsing. Stable top-level telemetry remains outside
`experimental`, and obsolete `experimental.telemetry` receives a focused
migration diagnostic. Public one-shot SDK version properties remain strings
with runtime exact-version validation; the existing state-aware-specific type
continues to name `0.9.0-alpha`. No general handwritten public version registry
or union is introduced. Registry-derived public metadata remains Phase 11
work. The rolling parser and rolling builders remain only as test oracles.

#### Phase 9 review follow-up completed

- All legacy rolling file/base64, value, and raw-JSON loaders are test-only,
  including the raw-JSON options helper. A compile-fail regression guards the
  former public raw loader's absence from production builds.
- `ParseError::Version` distinguishes unsupported versions and declaration
  data errors from genuine JSON syntax, EOF, and input-decoding failures.
  Version failures retain pre-discrimination stderr routing but audit as
  `schema_violation`; decode failures still audit as `malformed_json`.
  Engine conversion preserves the existing `malformed_request` wire code.
- Once the development phase probe succeeds, discriminator failures preserve
  the selected request kind. Duplicate `experimental` members on lifecycle
  requests produce the state-aware JSON envelope; one-shot failures retain
  stderr diagnostics. Neither path accepts the duplicate.
- Public-loader, CLI output-route, and actual audit-record regressions cover
  these boundaries. The diagnostic oracle records the new `Version` outcome
  separately rather than collapsing it into `Decode`.
- Codegen, schema-reference, contributor, and SDK guidance reflects exact
  registered-version selection. These changes do not replace the raw
  state-aware payload bridge, remove legacy networking, or add publication
  tooling.

No new telemetry initialization is performed for pre-request failures, and
the command-preparation compatibility boundary recorded under Phase 7a is
unchanged.

### Phase 9.5: Replace raw state-aware dispatch payloads

Status: implemented at rewritten tip `2ae06e78` on
`user/gudge/version_specific_config_parsers_phase9b`, published as PR #1123
stacked on Phase 9a PR #1104. Native Linux/macOS execution and successful live
lifecycle acceptance for all three Windows backends remain outstanding.
The six design decisions and acceptance gates below were agreed on 2026-09-05;
implementation does not by itself satisfy the full phase acceptance criteria.

Phase 9 makes exact contracts authoritative, which removes the rolling parser's
open experimental subtree from the production trust boundary. Phase 9.5 then
replaces the temporary `experimental_raw` bridge with a typed state-aware
backend payload before Phase 10 changes the v0.9 policy surface.

The exact contract remains the structural authority and backend configuration
types remain the semantic authority. The adapter between them becomes static:

```text
exact phase/backend request
    |
    v
neutral typed operation + normalized cross-cutting ExecutionRequest
    |
    v
mxc_engine: existing backend resolution and execution gates
    |
    v
checked binding to BoundStateAwareRequest<B>
    |
    v
generic dispatcher: StatefulSandboxBackend phase validation and execution
```

#### Adopted design: engine-side binding

**Adopted 2026-09-05:** use Option 1 from the Phase 9.5 design discussion.
Keep the generic lifecycle dispatcher and the backend trait's per-phase
configuration associated types. Bind the neutral parsed operation to the
selected backend in `mxc_engine`, rather than adding payload-extraction methods
to backend implementations or introducing a configuration-family trait.

The parser produces a closed neutral operation enum. Its variant is the single
source of truth for the phase: callers obtain `phase()` by matching the variant,
not from an independently writable `phase` field alongside a typed payload.
Provision identifies the selected backend even when its optional configuration
is absent; non-provision variants carry their required `sandbox_id`. The common
`ExecutionRequest`, including process, policy, and telemetry values, remains
outside the backend-specific payload. The JSON still declares `phase` and uses
the same exact contract roots; this is an internal representation change.

Keep construction controlled through the exact adapter and checked
constructors/binding helpers, with private fields and read-only accessors where
needed. Migrate existing callers and test fixtures that assemble the public
parsed-request struct directly. Construction establishes structural
relationships; it does not replace backend semantic validation, apply backend
defaults, or introduce earlier sandbox-ID content validation.

The engine keeps the existing routing authority: declared `containment` for
provision, and the `sandbox_id` prefix for every later phase. After the existing
backend-resolution and experimental/backend-availability gates, it consumes the
neutral request through a checked binding helper. A payload incompatible with
the selected backend is an explicit error, never an absent configuration or a
reason to select a different backend. Preserve existing error ordering and
response routing for externally supplied requests.

Successful binding produces `BoundStateAwareRequest<B>` (name illustrative).
Its operation enum carries `Option<B::ProvisionConfig>`,
`Option<B::StartConfig>`, `Option<B::ExecConfig>`, `Option<B::StopConfig>`, or
`Option<B::DeprovisionConfig>` as appropriate, together with the required
sandbox ID for non-provision operations. Its phase is likewise derived from
the operation variant. The generic dispatcher consumes this bound request,
borrows its configuration for validation, then moves it into the phase method.
Keep configuration presence intact and leave defaults and semantic validation
in the backend.

Both the relayed lifecycle dispatcher and the streaming-exec dispatcher take
bound requests. Their engine entry points reuse the same binding helpers;
streaming still requires the exec operation and retains its existing failure
behavior for other phases. Bindings and neutral types live in `wxc_common`
without backend-crate dependencies; `mxc_engine` selects the concrete backend
type at its existing feature-gated routing arms. Remove the configuration
associated types' `DeserializeOwned` bounds where no longer needed.

Binding is a mechanical typed conversion, not another parser. Do not serialize
payloads back through JSON, introduce type-erased configuration downcasts, or
add fallback deserialization. Test incompatible payload/backend combinations
at the binding boundary as well as successful delivery to both dispatch paths.

#### Adopted payload model: sparse operations and runtime-owned configuration

**Adopted 2026-09-05:** use Option B from the payload-model discussion.
Separate wire representations from runtime configuration, following the
one-shot adapter pattern, rather than retaining a runtime dependency on the
rolling WSLC wire type or moving/re-exporting that type as a shared definition.

Use a sparse neutral operation model. Provision carries a backend-tagged
payload with only the configuration each backend actually supports:

| Backend | Neutral provision payload |
| --- | --- |
| IsolationSession | `Option<models::IsolationSessionProvisionConfig>` |
| Windows Sandbox | No backend-specific configuration |
| WSLC | `Option<models::WslcProvisionConfig>` |

The backend tag remains present when its optional provision configuration is
absent. Start, exec, stop, and deprovision carry their required sandbox ID but
no backend-specific configuration today; exec process settings stay in the
common `ExecutionRequest`. Do not introduce fifteen configuration structs to
mirror the backend/phase test matrix. Binding these no-configuration operations
preserves the existing absent `Option<()>` argument rather than manufacturing
a present unit configuration from an empty `experimental` object.

Keep the existing IsolationSession runtime type. Add
`models::WslcProvisionConfig` in `wxc_common` with `image: Option<String>` and
`image_tar_path: Option<String>`, and change the WSLC backend's provision
associated type and configuration consumers to use it. Exact contract adapters
construct these runtime values directly, with exhaustive field mapping.

Retain `wire::WslcProvisionPhase` for rolling artifacts and the test oracle
where still needed, with an explicit wire-to-runtime conversion at that
boundary. The temporarily similar definitions have distinct responsibilities;
do not alias them together or serialize through JSON to convert them. Cover
the retained wire conversion and the exact adapter with independent expected
values and parity tests. This decision changes no contract or generated JSON
shape.

#### Adopted presence model: backend-observable distinctions

**Adopted 2026-09-05:** use Option A from the presence/defaulting discussion.
Preserve every configuration and field-presence distinction observable by the
backend using `Option<Config>` and the configuration's optional fields. Do not
retain additional metadata solely to distinguish otherwise equivalent absent
and empty outer JSON wrappers.

For IsolationSession provision, the required mapping is:

| Exact input | Runtime provision configuration |
| --- | --- |
| No provision member | `None` |
| `"provision": {}` | `Some(Config { app_id: None })` |
| `"provision": {"appId": ""}` | `Some(Config { app_id: Some("") })` |
| `"provision": {"appId": "example"}` | `Some(Config { app_id: Some("example") })` |
| `"provision": {"appId": null}` | Rejected by the exact contract; no runtime configuration |

For accepted IsolationSession and WSLC provision requests, an absent
`experimental` object, an empty one, or an allowed empty backend wrapper all
produce no provision configuration unless the `provision` member is present.
These outer-wrapper distinctions need not survive exact structural validation.
Do not collapse an absent provision configuration into a present empty one,
normalize away explicit empty strings, or reinterpret rejected `null` values
as absence.

An omitted WSLC `image` stays `None` through adaptation and binding; the backend
chooses its default image. Defaulting and semantic validation remain backend
responsibilities. Preserve the shared normalization seam's existing policy
presence information, including `network_specified` and `ui_specified`, so
post-provision inheritance is not replaced by a newly supplied default policy.

Use explicit expected-value cases for the exact and retained rolling adapters
and for binding, plus backend-level cases for default resolution. The runtime
does not need to retain original source text or wrapper-presence metadata to
enforce these invariants.

#### Adopted equivalence strategy: independent reference and observed behavior

**Adopted 2026-09-05:** use the combined three-layer approach from the
equivalence-harness discussion. Introduce its coverage before deleting
production raw handling; do not merely remove the existing `experimental_raw`
and `source_text` assertions or generate expected results through the new
adapter being tested.

1. Retain independent legacy payload extraction in dedicated test-only support.
   For inputs accepted by both paths, compare the old extraction's typed
   configuration values with the new exact adapter's runtime configuration.
   The WSLC reference can deserialize into `wire::WslcProvisionPhase` and inspect
   its fields directly; it must not obtain its expected values through the new
   production wire-to-runtime conversion. This reference does not preserve raw
   payload fields on production request types or keep
   `ParsedStateAwareRequest::deserialize_config` as a production API.
2. Add independently written expected-value cases for configuration absence,
   present empty configuration, explicit empty `appId`, supplied field values,
   and backend-owned defaulting. These establish the adopted presence contract
   and catch errors shared by the reference and new implementation. Exercise
   the retained rolling wire conversion separately as well as the exact adapter.
3. Use recording backend implementations to observe the common request and
   configuration delivered to validation and execution after engine-side
   binding. Cover both relayed lifecycle and streaming-exec dispatch so a
   correct adapter cannot mask a dropped or misrouted configuration later.

Replace transport-oriented snapshot fields with backend-observable state:
selected backend, operation, sandbox ID, configuration presence and values,
the common runtime request and its policy-presence flags, and telemetry.
Do not compare retained source text, raw experimental JSON, or equivalent
absent/empty outer wrappers that the adopted presence model deliberately drops.
Keep diagnostic coverage separate, preserving source-aware exact parse errors,
semantic errors, and their response routes without retaining source text on
successful runtime requests.

Legacy acceptance is not an authority for the exact contract. Value parity
applies to shared accepted inputs; existing classified acceptance/rejection
differences remain explicit tests. In particular, the legacy parser's
acceptance of `appId: null` must not turn that value into an accepted exact
request. The new coverage must be in place before the old production transport
and reparsing code are removed.

#### Adopted normalization split: shared conversion and separate wrappers

**Adopted 2026-09-05:** extract the existing common-field conversion into a
shared function, with a typed production wrapper and a separate test-only
legacy wrapper. Do not write a replacement policy normalizer or leave
test-only raw-JSON branches scattered through the production normalizer.

Replace `StateAwareWireInput` with a controlled input whose illustrative shape
is:

```rust
struct StateAwareInput {
    common: wire::MxcConfig,
    operation: StateAwareOperation,
}
```

The operation is the adopted phase/backend/configuration representation.
The common wire value carries the existing common-field representation, with
`phase`, `sandbox_id`, `containment`, and `experimental` unset and one-shot-only
sections absent. Exact adapters construct this shape explicitly; its checked
construction boundary rejects contradictory input instead of silently
discarding fields. This preserves the existing common-policy representation
for Phase 9.5 rather than introducing another domain-model migration.

Extract the shared conversion with an interface along these lines:

```rust
fn normalize_state_aware_common(
    common: wire::MxcConfig,
    context: NormalizationContext<'_>,
    logger: &mut Logger,
) -> Result<ExecutionRequest, WxcError>;
```

`NormalizationContext` is a temporary phase/provision-containment/sandbox-ID
view, derived from the operation in production, not another persistent or
independently writable routing authority. Preserve the existing conversion
sequence: remember supplied network policy; populate the temporary wire
containment context from the provision backend or existing sandbox-ID-prefix
lookup; derive the existing `require_process` and `state_aware_wslc_exec`
flags; call `convert_wire_config`; and retain the clearing of directional
network values for non-provision requests with no supplied network policy.
Telemetry and network/UI presence mapping remain in the existing conversion.
Do not add backend-availability checks, earlier ID validation, backend defaults,
or new policy rules here.

The production `normalize_state_aware` becomes a thin wrapper: derive the
context, invoke the shared conversion, and assemble the controlled parsed
request from its `ExecutionRequest` and operation.

Assign structural checks explicitly:

| Behavior | Owner after the split |
| --- | --- |
| Exact JSON shape validation | Existing exact contract deserialization |
| Focused obsolete-telemetry diagnostic | Existing exact-input boundary, preserving error ordering and routing |
| Legacy missing phase and non-provision containment checks | Test-only legacy wrapper |
| Legacy raw experimental backend-key and moved-section checks | Test-only legacy wrapper |
| Legacy stray one-shot section rejection | Test-only legacy wrapper |
| Common process, policy, and telemetry conversion | Shared common conversion |
| Typed payload/backend mismatch rejection | Engine-side binding |

Keep legacy structural checks in their existing order relative to one another
and common conversion. Legacy observations retain a separate test-only
representation and independent payload extraction: do not force legacy inputs
that exact contracts reject into the stricter production operation enum. The
legacy wrapper supplies its original, possibly incomplete phase/backend/ID
context to shared conversion where the old path did so, then constructs its
own observation for equivalence comparisons.

The concrete source changes are the input replacement in `state_aware_wire.rs`,
direct common-fields-plus-operation output from
`config_contract_adapters/dev/state_aware.rs`, removal of the source-text
argument and raw-extraction error path in `config_contract_adapters/dev/mod.rs`,
the shared conversion and separate wrappers in `config_parser.rs`, and removal
of production raw fields and phase-fragment reparsing in
`state_aware_request.rs`. Keep source-based diagnostics, discriminator probes,
and CLI command splicing wherever they still have consumers.

#### Adopted acceptance gates

**Adopted 2026-09-05:** require the following six gates rather than treating
"exhaustive parity" as an unspecified test obligation.

##### Gate 1: Configuration and binding matrix

Cover IsolationSession, Windows Sandbox, and WSLC across provision, start,
exec, stop, and deprovision using the adopted independent reference, explicit
expectations, and recording backends. Assert selected backend, operation,
sandbox ID, common request, and configuration delivered downstream.
Provision cases include absent configuration, present empty configuration,
individual fields, combined fields, and explicit empty `appId` where applicable.
Incompatible backend/payload combinations fail binding rather than becoming
`None`. This specifies coverage, not exactly fifteen test functions.

##### Gate 2: Execution-path behavior

| Path | Required observation |
| --- | --- |
| Normal lifecycle dispatch | Successful validation precedes the corresponding operation, which executes exactly once |
| Validation failure | No execution occurs |
| Dry run | Validation occurs; no lifecycle operation executes |
| Streaming exec | Uses the same binding rules and passes `ExecStdio::Piped` |
| Relayed exec | Passes `ExecStdio::Relayed` |
| Streaming request for another phase | Preserves the existing rejection behavior |

Preserve backend-specific streaming support: IsolationSession supports piped
execution; Windows Sandbox and WSLC refuse it before running the workload.
Recording backends establish ordering and arguments without live sandboxes;
real-backend tests cover backend-specific refusal and defaulting behavior.

##### Gate 3: Diagnostics and entry-point boundaries

Retain regression coverage for unknown fields, duplicates, rejected `null`,
wrong field types, missing required declarations, structural error paths and
source coordinates, backend semantic error codes and messages, existing
stderr/state-aware-envelope routing, the focused obsolete-telemetry migration
diagnostic, experimental opt-in, and unavailable-backend errors.
Exercise representative file, base64, and raw-JSON entry points plus CLI
command override, not only private adapter helpers. Preserve classified
legacy/exact acceptance differences instead of forcing their rejections to
match.

##### Gate 4: Platform and feature matrix

| Platform | Engine configuration | Compiled state-aware backends |
| --- | --- | --- |
| Windows | Default | Windows Sandbox |
| Windows | `isolation_session` | Windows Sandbox and IsolationSession |
| Windows | `wslc` | Windows Sandbox and WSLC |
| Windows | `isolation_session,wslc` | All three |
| Linux | Default | No Windows state-aware implementations; neutral types and unavailable-backend paths remain covered |
| macOS | Default | No Windows state-aware implementations; neutral types and unavailable-backend paths remain covered |

Run relevant compilation and targeted tests in each configuration, including
affected backend tests and existing Rust SDK/FFI state-aware boundary tests.
Exercise the feature configurations separately: a combined-feature build alone
does not cover the unavailable-backend branches. Neutral types and adapter tests
must remain usable without Windows backend dependencies. Retain applicable
repository formatting and lint gates; introduce no new testing framework.

Windows Sandbox is not an optional `mxc_engine` Cargo feature:
`windows_sandbox_lifecycle` is an unconditional Windows dependency. Compilation,
experimental execution opt-in, and host availability are separate gates.
Windows Sandbox participates in every Windows configuration's lifecycle,
binding, dry-run, validation-order, and piped-exec-refusal coverage. A host
without the Windows Sandbox OS feature cannot supply its live lifecycle
evidence, but that does not skip ordinary adapter, binding, or recording-backend
tests.

##### Gate 5: Production architecture and artifacts

Require evidence that successful production state-aware requests retain
neither raw backend JSON nor source text; both dispatch paths consume bound
typed requests; no production backend-payload reparsing or
typed-to-JSON-to-typed conversion remains; legacy extraction is test-only; and
the removed production deserialization API is no longer callable. Removing
only a method name is insufficient if a replacement hides the same reparsing.
Existing schema/type codegen gates stay clean: this phase changes no published
contract or generated JSON shape.

##### Gate 6: Live lifecycle evidence

Run the existing state-aware lifecycle suites for IsolationSession, Windows
Sandbox, and WSLC on suitable hosts or CI infrastructure, covering real
provision-through-teardown behavior beyond recording backends.
Local development need not have every backend's prerequisites, but a skipped
suite is not passing evidence. Record unsupported or unrun coverage explicitly
and obtain the required backend evidence on an appropriate host before
declaring Phase 9.5 complete.

#### Implementation and exit criteria

Implement:

- define a neutral typed payload representation covering every supported
  state-aware backend and phase
- adapt exact contract payloads directly into the backend-facing configuration
  types, preserving exhaustive field mapping
- introduce the runtime-owned WSLC provision configuration and migrate its
  backend consumers, retaining a separate rolling wire conversion where needed
- carry the typed payload on `ParsedStateAwareRequest` or its replacement
- update state-aware dispatch to consume the typed payload rather than calling
  `deserialize_config<C>` over raw JSON
- preserve structural source diagnostics at exact contract deserialization and
  semantic diagnostics at backend validation
- delete `experimental_raw`, the phase-fragment locator and reparsing path, and
  `source_text` where it has no remaining consumer
- retain telemetry as a cross-cutting value populated by the shared Phase 7.2
  normalization seam rather than embedding it in the backend payload
- extract the shared common-field conversion and separate typed production
  normalization from test-only legacy structural checks and observations
- replace transport-oriented equivalence assertions with the independent
  test-only reference, explicit expected values, and dispatch observations
- add exhaustive parity tests for IsolationSession, Windows Sandbox, and WSLC
  across every lifecycle phase
- satisfy all six acceptance gates, including separate feature configurations
  and live lifecycle evidence for all three backends

This phase changes no published contract and no user-visible JSON shape. It is
an internal representation and dispatch migration made safe by the Phase 9
cutover: production requests have already passed a closed exact contract, so
the rolling parser's lossless open-object preservation is no longer required.

Done when both dispatch paths consume bound typed requests, state-aware
dispatch receives no raw backend JSON, and no production backend-payload
reparsing remains (including `ParsedStateAwareRequest::deserialize_config`).
Removing the raw representation must change neither accepted exact requests
nor backend behavior, with all six acceptance gates satisfied.

### Phase 10: Finalize the v0.9 stable candidate

Phase 10a is squashed and restacked as `16ed3c81`. The atomic Phase 10b-10d
cutover is implemented and published as `8722f343`. Its exact contracts,
backend mapping, Rust/Node/C# authoring, generated artifacts, request corpus,
and documentation are updated together. The feature branch's
`docs/version-specific-parser-migration-inventory.md` records the actual local
verification and remaining native Unix/live-backend acceptance limitations.
Implementation completion is not a claim that those host-dependent gates ran.

Directional networking shipped in v0.8 through the rolling stack and is already
present in the exact v0.8 and v0.9 contracts. Phase 10 therefore does not
reintroduce that surface. It finalizes the authoritative v0.9 stable candidate
before publication:

- remove legacy Network syntax from v0.9 while leaving published
  v0.6/v0.7/v0.8 contracts immutable
- migrate v0.9 development configs, SDK emitters, and state-aware request
  surfaces to directional networking
- preserve adapters that translate each published legacy Network contract into
  the canonical runtime model
- resolve the IsolationSession unrestricted-network acknowledgment without
  pretending MXC enforces policy values that the backend cannot honor
- retain presence information equivalent to `network_specified` and
  `ui_specified`, so backend validation can distinguish omission from an
  explicit policy request

The IsolationSession acknowledgment requires a deliberate design. A dedicated
acknowledgment field, rather than borrowed Network policy values, would remain
stable across future Network vocabulary changes and describe caller intent
honestly. Any spelling change includes corpus, SDK, backend validation, and
documentation updates.

The removed v0.9 fields are `network.defaultPolicy`,
`network.enforcementMode`, `network.allowedHosts`, `network.blockedHosts`,
`network.allowLocalNetwork`, and `network.proxy`. Their behavior is represented
through directional egress/ingress, runtime proxy configuration, explicit
backend acknowledgments, or a specific migration error; it is never silently
dropped. Publication must fail if any of these legacy fields remains reachable
from a v0.9 one-shot or state-aware root.

The phase must be end-to-end and leave the tree green. It includes the v0.9
contract and adapters, published-version translations, canonical runtime
models, semantic validation, backend enforcement, Rust/TypeScript/C# SDK
surfaces, generated artifacts, fixtures, and applicable unit, integration, and
E2E tests. No published schema or contract may change.

### Phase 11: Add publication and freeze checks

The v0.8 release shipped through the legacy publication stack, and Phase 6.5
manually reconstructed its immutable Rust contract and adapter. Phase 11
publishes the completed v0.9 stable candidate through the exact-contract path
and opens v0.10 development:

```text
mxc_schema_gen publish --version 0.9.0-alpha --next-dev 0.10.0-alpha
```

Publication copies only the development stable-candidate request;
experimental and state-aware types never enter a published contract. Generate
the lifecycle registry and version constants from the publication metadata.
After publication, the registry marks v0.9 published and v0.10 development;
the mutable `dev` module and its schema, fixtures, adapters, and TypeScript
oracle all advance to `0.10.0-alpha`.

Publication is not a byte-for-byte copy of every stable-candidate type. A
development one-shot `Containment` enum may carry both
stable-candidate values (`process`, `processcontainer` + its `appcontainer`
alias, `lxc`, `bubblewrap`, `seatbelt` + its `macos_sandbox` alias) and
development-only values (`vm`, `windows_sandbox`, `microvm`, `hyperlight`,
`wslc`, `isolation_session`). Publication emits a versioned module containing
only stable-candidate values and a frozen adapter mapping that narrower enum.
The mutable `dev` contract keeps the full enum and advances.

The published adapter is **forked**, not updated: freezing copies the current dev
one-shot adapter into a versioned adapter, and the `dev` adapter continues to
evolve. Phase 5B's split of the adapter tests into `stable_candidate.rs` and
`experimental.rs` exists for this fork.

The same fork applies to the `mxc_engine::policy` contract builder introduced by
the Phase 7 decision 3 resolution. Each supported version has its own builder
mapping `SandboxPolicy` onto that version's root, so publication freezes a
versioned builder beside the frozen adapter while `dev`'s builder advances.
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
declaring `0.9.0-alpha` with `containment: "windows_sandbox"` must move to
`0.10.0-alpha` when v0.9 is published. Phase 8's migration is therefore not a
one-off; a smaller version recurs at each publication.

Add CI checks that published Rust modules, stable generated schemas, registry
identities, and recorded digests cannot be deleted or changed incompatibly.
The gates freeze observable shape and behavior rather than source bytes:
schema digests, acceptance and rejection fixtures, aliases and local value
rules, adapter/runtime snapshots, field-presence semantics, and
builder-versus-parser equivalence must remain unchanged. Published Rust source
may be refactored only when those gates prove equivalent behavior. Reuse
`scripts/versioning/lib/git-base.js` for base-ref handling.

Replace `schemas/schema-version.json` and the regex-based version synchronization
logic once all consumers use the generated registry.

Do not extend the existing rolling-version synchronization gate to treat its
current min/stable/dev constants as the exact-contract registry. Exact contracts
are registered deliberately as their Rust modules are implemented; Phase 11
replaces the old synchronization mechanism with generated registry metadata.

#### Final cleanup exit criteria (Phases 11b-11c)

**Adopted 2026-09-05:** complete rolling-parser retirement includes test builds,
not just production entry points. Phase 9 removes production authority;
Phase 9.5 deliberately retains a test-only legacy reference; Phase 11's final
cleanup removes that remaining implementation after its replacement evidence
is established.

Before deleting the rolling references, replace their coverage with explicit
exact-contract acceptance/rejection fixtures and diagnostic regressions,
adapter/runtime snapshots including field-presence semantics, versioned
builder-versus-parser equivalence, and backend dispatch observations. Expected
values must remain independent of the mapping under test. Preserve the
meaningful exact-contract regressions from the former divergence inventory;
do not delete coverage merely because the rolling comparison is going away.

The final tree must satisfy all of the following:

- No rolling whole-request parser, rolling loader, or rolling policy-builder
  oracle remains callable in production or test builds. Remove their obsolete
  test entry points and helpers rather than retaining a renamed or archived
  executable implementation.
- Remove the independent legacy payload-extraction reference retained by
  Phase 9.5, including its separate legacy request/observation machinery and
  any masking, source-retention, or structural-validation helpers used only
  by that reference. Keep the replacement exact expectations and dispatch
  coverage.
- No surviving test depends on executing the rolling parser or rolling
  builders. Replace obsolete differential assertions and classifications with
  direct exact-contract regressions where they still describe required
  behavior.
- Retire `--legacy-wire` generation, remaining rolling development artifacts
  and drift gates, and duplicated version metadata/synchronization after their
  consumers have migrated to exact artifacts and the generated registry.
  Historical published schemas and exact published contract modules remain
  immutable; they are not rolling-cleanup targets.
- Retain shared normalization, semantic validation, and internal conversion
  types still consumed by the exact path. Removing the obsolete parser does
  not require deleting `convert_wire_config`, the common state-aware
  normalization function, or every use of `wire::MxcConfig`. Remove a shared
  helper or type only when it has no remaining consumer.

Phase 11 is not complete while a rolling parser or builder survives solely as
a test oracle. The exact-contract regression and freeze gates must pass
without those implementations, and no production or test entry point may
fall back to rolling whole-request parsing.

### Suggested ownership
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

### Implementation PR plan

**Adopted 2026-09-02; status updated 2026-09-10.** The work uses ten reviewable
PRs rather than one PR per fine-grained work item or one very large PR per
major phase. Each PR must build and test green on its own; later PRs may be
stacked while review is in progress, but merge in the order below.

| Sequence / PR | Plan scope | Boundary | Status |
| --- | --- | --- | --- |
| 1 / #1091 | Phase 7.2 | Extract the shared state-aware normalization seam and repair the state-aware adapter tests | Complete at `c3519b3d` |
| 2 / #1096 | Phase 7.3 | Add the private exact parser path and test-only versioned policy builders | Complete at `b13c0bae` |
| 3 / #1097 | Phase 7.4 | Add the differential harness and its executable file-level divergence inventory | Complete at `3b411771` |
| 4 / #1099 | Phase 8 | Migrate producers, SDK envelopes, configs, examples, and schema references | Complete at `92581c44` |
| 5 / #1104 | Phase 9 | Make exact registry dispatch authoritative and retire version-insensitive deserialization | Complete at `1116d233` |
| 6 / #1123 | Phase 9.5 | Replace `experimental_raw` with typed state-aware backend payloads | Implemented at `2ae06e78`; acceptance pending |
| 7 | Phase 10a | Add the IsolationSession acknowledgment and scoped runtime preparation without removing legacy v0.9 input yet | Implemented at `16ed3c81`; native/live acceptance pending; PR not opened |
| 8 | Phases 10b-10d | Perform the atomic v0.9 directional-only cutover, backend and SDK migration, corpus rewrite, gates, and documentation | Implemented at `8722f343`; native/live acceptance pending; PR not opened |
| 9 | Phase 11a | Add publication, freeze, digest, and generated-registry tooling before changing lifecycle state | Not started |
| 10 | Phases 11b-11c | Publish v0.9, open v0.10 development, migrate development-only configs, and retire rolling artifacts, metadata, and test-only parser/builder oracles | Not started |

Phase 10's internal subphases are detailed in Appendix C. Phase 11a is
deliberately additive so publication mechanics can be reviewed before they
rewrite the contract lifecycle; the final publication and rolling-stack cleanup
remain together so no intermediate tree has conflicting version authorities.
That cleanup includes deleting the Phase 9.5 legacy payload reference and all
remaining rolling parser/builder oracles after their exact-contract replacement
coverage is established.
Phase 7.5 is maintained on the dedicated plan branch rather than adding this
planning document to an implementation PR.

## 3. Detailed implementation plans and records

### Phase 1 detailed design
Phase 1 was implemented by PR #807. The detailed design remains here as the
record of the crate boundary and probe responsibilities.

#### Phase 1 objective

Create a small independent crate that can answer:

> Given raw JSON request text, which exact registered MXC contract does it
> declare?

It must reject malformed declarations without knowing anything about the rest
of the config shape. It does not yet deserialize a version-specific request.

#### Phase 1 step breakdown

Phase 1 is intentionally split into six small implementation steps. Each step
has a single responsibility and leaves the new crate in a buildable state.

##### Phase 1.0: Prepare the implementation branch

Start from the base commit named at the top of this document rather than the
older detached worktree on which this plan was authored.

Done when:

- `HEAD` is based on `origin/main` at or after `79c39c70`
- the worktree is clean except for this plan, if the plan is carried onto the
  implementation branch
- the repository Rust instructions have been read

No source files are changed in this step.

##### Phase 1.1: Scaffold the independent crate

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

##### Phase 1.2: Implement the exact version value type

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

##### Phase 1.3: Add lifecycle registry metadata

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

##### Phase 1.4: Implement source-text version probing

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

##### Phase 1.5: Stabilize the initial public API

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

##### Phase 1.6: Run the phase quality gate

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

#### Cargo wiring

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

#### Public API

The initial `lib.rs` should expose only the version model and probe:

```rust
pub mod registry;
pub mod version;

pub use registry::{ContractDescriptor, ContractStatus, CONTRACTS};
pub use version::{probe_version, ContractVersion, VersionProbeError};
```

The `published` module begins with the first published request type in Phase 2.
The `dev` module is deferred until the development contract in Phase 5.

#### Exact version model

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

#### Registry metadata

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

#### Source-text probe

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

#### Phase 1 tests

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

#### Phase 1 exit criteria

- The new crate builds independently.
- Exact version lookup is the only accepted lookup behavior.
- Raw source probing rejects malformed and duplicate declarations.
- No existing parser or SDK behavior has changed.
- No schema, generated SDK type, config file, or documentation migration has
  started.

### Phase 6 detailed design
Phase 6 merged in PR #968 after review and CI.

It adds versioned development-contract schema and TypeScript generation without
changing parser dispatch, corpus validation, or runtime behavior.

#### Phase 6 objective

Make the mutable `0.8.0-alpha` contract's generated artifacts derive from
`mxc_config_contract::dev` rather than from the rolling `wxc_common::wire`
model, and gate them, so that every later change to the development contract
updates the Rust contract, the JSON Schema, and the TypeScript wire oracle in
one reviewable change.

Phase 6 **adds** a second generator alongside the existing one. It does not
publish or freeze `0.8.0-alpha`, does not retire the rolling artifacts, does
not repoint the corpus gate, and does not modify the parser or any runtime
behavior.

#### Phase 6 relationship to adjacent phases

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

**Phase 10's v0.9 Network cleanup becomes reviewable.** The IsolationSession
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
versions reserved. Phase 11 adds `published/v0_9_0_alpha`, advances `dev` to
v0.10, and leaves the command-line shape unchanged. The enum schema emission
must derive its value set from the macro's own value table, never from a list
written into the generator, so publication narrowing yields the stable
containment set automatically.

#### Phase 6 decisions resolved

All six decisions were resolved during implementation.

| # | Decision | Resolution |
| --- | --- | --- |
| 1 | Path of the contract-generated schema | `schemas/dev/mxc-config.schema.0.8.0-alpha.json` |
| 2 | Path of the versioned TypeScript oracle | `sdk/node/src/generated/v0_8_0_alpha/wire.ts`, not exported |
| 3 | How eight concrete roots become one schema document | Nested `if`/`then` phase and containment discrimination over one shared `definitions` table, rather than a bare root `oneOf` |
| 4 | Whether the schema advertises the compatibility aliases | Yes. `appContainer` and `macos_sandbox` are advertised, and each is mutually exclusive with its canonical property |
| 5 | Fate of the positional and `--ts` argument forms | Replaced by `schema`, `types`, and `versions` subcommands; rolling generation moves to `--legacy-wire` |
| 6 | Whether to accept the authoring-diagnostics cost of a bare `oneOf` | Not accepted. Nested `if`/`then` was selected specifically to keep editor diagnostics focused on the declared phase and backend |

Decisions 3 and 6 resolved together: the diagnostics concern raised by decision
6 is what selected the `if`/`then` composition in decision 3, so the plan's
original `oneOf` recommendation was deliberately not taken.

#### Phase 6 as implemented

- `mxc_config_contract` gained optional `schema-gen` support and carries no
  Schemars dependency in its default build.
- Constrained primitives, `string_enum!`, and `string_marker!` carry
  hand-written schema implementations matching their deserialization behavior.
- `mxc_schema_support` is the dependency-light shared renderer and TypeScript
  emitter, taking the second of the two placements this section offered.
- Exact artifact paths and schema identifiers live in the contract registry.
- `mxc_schema_gen versions --json` drives the development artifact gate.
- `check-contract-codegen.js` regenerates both exact artifacts, asserts the
  dispatched root set exactly matches fixture coverage, requires valid and
  invalid fixtures for every root, and checks focused authoring diagnostics.
- The exact schema records in its own banner that it is not authoritative until
  Phase 9.
- Integer normalization preserves signed and unsigned minimum and maximum
  bounds after Schemars-specific formats are removed.
- The TypeScript emitter handles named scalar definitions, literal constants,
  conditional root unions, externally tagged object unions, and mutually
  exclusive aliases.

The fixture reorganization this section required was carried out: the gate
demands valid and invalid fixtures per root, which is what makes the
one-shot-scoped corpus problem recorded in Phase 6.7 impossible to reintroduce.

#### Phase 6 step breakdown

Steps 6.0 through 6.10 are all implemented. The text below is retained as the
design record and as the review checklist that PR #968 was reviewed against.

##### Phase 6.0: Prepare the implementation branch

Base the branch on PR #966, the top of the Phase 5 stack, or on `main` once the
stack has merged. Do not base it on anything below #949: that pull request
rewrites the `string_enum!` macros and reformats the enum declarations this
phase annotates.
Confirm `cargo test -p mxc_config_contract` is green before adding anything,
so a later failure is unambiguously attributable to this phase.

No source files are changed in this step.

##### Phase 6.1: Add optional Schemars support to the contract crate

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

##### Phase 6.2: Implement contract primitive schemas

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

##### Phase 6.3: Compose the multi-root development schema

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

##### Phase 6.4: Share rendering and the TypeScript emitter

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

##### Phase 6 step 6.5: Rework the generator command line

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
- `--legacy-wire` targets the rolling model. It remains an oracle-generation
  path through Phase 9 and retires with the remaining rolling artifacts and
  metadata consumers in Phase 11.
- Omitting `--out` writes to standard output, preserving current behavior.
- `versions --json` emits the registry — version, status, and default artifact
  paths — so the CI gate never hardcodes a version list. This is the seed of
  the generated registry metadata Phase 11 needs.
- Preserve the existing convention that status goes to standard output and
  errors to standard error; the gates depend on it.

Suggested commit boundary: `Add versioned subcommands to the schema generator`.

##### Phase 6.6: Commit the generated development artifacts

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

##### Phase 6.7: Add the drift gate and schema tests

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

##### Phase 6.8: Defer public SDK conformance

Do not add public-SDK conformance tests against the versioned oracle. The SDK
still emits rolling and `0.6.0-alpha` shapes, so binding it to the exact
contract is Phase 8 work. Phase 6 requires only that the generated file type
checks in the SDK build and that the drift gate covers it. Record the
deferral in the codegen documentation.

##### Phase 6.9: Update documentation

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

##### Phase 6.10: Run the phase quality gate

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

#### Deliberate differences from the rolling schema

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

#### Phase 6 tests

Feature-gated Rust tests in the contract crate should cover:

1. All eight roots are reachable through the root discrimination. Written
   against a bare `oneOf`; decision 3 selected nested `if`/`then`, so this
   asserts over the conditional structure instead.
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

#### Phase 6 exit criteria

Every exit criterion below is reported satisfied on the implementation branch.
The rolling and exact generated artifact families coexist and are independently
gated. Parser dispatch, corpus validation, `schemas/schema-version.json`, the
published contracts, and runtime behavior are unchanged.

Review and CI confirmed the implementation before PR #968 merged.

- The contract crate builds with and without `schema-gen`, the default build
  carries no Schemars dependency, and the crate's dependency boundary is
  unchanged.
- The generator produces deterministic `0.8.0-alpha` artifacts from the
  contract crate, and reproduces the rolling artifacts byte-for-byte.
- Both committed `0.8.0-alpha` artifacts are gated and cannot drift.
- Every valid `0.8.0-alpha` fixture validates against the generated schema and
  every invalid fixture fails, per root.
- The parser, the corpus gate, `schemas/schema-version.json`, the published
  contracts, and all runtime behavior are unchanged.


#### Phase 6 review finding: contract value-rule gaps

An adversarial review of the Phase 6 branch raised, at Medium severity on the
security axis, that the exact contract accepts `processContainer.capabilities`
entries the rolling parser rejects: entries containing a comma, which is
BaseContainer's wire delimiter, and the reserved `learningModeLogging` and
`permissiveLearningMode` names, which relax deny-by-default containment. All
three contracts type the field as a bare `Vec<String>`.

**The finding is correct. Its stated severity rests on a premise that does not
hold.** The review reasoned that "the guard would disappear when exact dispatch
replaces [the rolling parser] unless the validation is carried forward". That
is true only if `convert_wire_config` stops running. It does not: the exact
path is contract to `dev::adapt_request` to `wire::MxcConfig` to the same
`convert_wire_config`, and Phase 9 removes the version-insensitive
*deserialization*, not the wire-to-domain conversion. The capability rules
therefore survive the cutover by construction rather than by anyone remembering
to port them.

That reclassifies the finding from a latent security regression to an instance
of the structural-versus-semantic split ratified in Phase 7 decision 1: the
contract is the structural authority, and `convert_wire_config` remains the
semantic authority for value rules and cross-field interplay.

**A separate regression, which the review did not name, is worth fixing on its
own.** The rolling schema documents the rule in the field's `description`:

> Each array entry must contain exactly one capability name; commas are
> rejected because BaseContainer uses commas as its wire delimiter.
> `learningModeLogging` and `permissiveLearningMode` are reserved and rejected
> here; use `learningMode`, `--audit`, or the dedicated denial capture
> configuration instead.

The exact schema reduces this to "Optional AppContainer capability names."
Neither artifact *enforces* the rule, so enforcement parity is unchanged, but
the rolling one told the author and the exact one does not. The contract's doc
comments were written fresh rather than carried over from the wire model, and
the loss propagates into both the generated schema and the TypeScript oracle.

The four generated artifacts line up as follows. No schema in any version
enforces the rule; only the rolling development schema documents it:

| Schema | Enforces | Documents |
| --- | --- | --- |
| stable `0.6.0-alpha` | no | no — "AppContainer capabilities (e.g., 'internetClient', 'registryRead')." |
| stable `0.7.0-alpha` | no | no — same wording, under `processContainer`; the `appContainer` alias carries no `capabilities` at all |
| rolling `0.8.0-dev` | no | yes — the full prose above |
| exact `0.8.0-alpha` | no | no — reverts to the older stable wording |

Two consequences. The regression is specifically against the rolling
development schema, not against the published ones. And a caller reading a
published schema has never been told the rule, which is an argument for fixing
the prose regardless of what is decided about enforcement.

Remediation, in order:

1. Port the descriptive prose from `wxc_common::wire` into the contract doc
   comments, and audit the other fields for the same loss. Zero risk, restores
   authoring guidance in both generated artifacts, and requires no design
   decision.
2. Decide whether to model the rule as a validating newtype on the development
   contract. Two constraints the review does not mention: the published `0.6`
   and `0.7` contracts are immutable, so the fix cannot be applied uniformly
   across versions; and it places the rule in two implementations, so it needs
   a shared constant and a parity test, or it will drift — the failure mode
   this plan exists to prevent. **Resolved: the newtype landed in PR #966.**
   `dev::stable::ProcessContainerCapability` rejects comma-bearing entries and
   the two reserved names case-insensitively at deserialization, with invalid
   fixtures for each rejected class. The drift risk this item warns about is
   now live and unclosed: the rule exists in the contract newtype and in
   `convert_wire_config`, and neither a shared constant nor a parity test has
   been added yet.
3. Treat the finding as a class rather than an instance, and cover it in
   Phase 7.4 by running the harness over the corpus's invalid documents. See
   the "exact looser than rolling" direction recorded there.

**Disposition.** The updated review marks this finding "Verified; fix in this
branch" and concludes the Phase 6 branch is "not ready to merge as-is", with
three other in-branch fixes: a gate check that selects whichever invalid exec
fixture sorts first, manual Rust fixture registration against automatic
JavaScript discovery, and roughly 826 lines of incidental line-ending churn.
No merge-blocking High finding survived verification.

The plan's position on severity stands: the fix is worth making as defense in
depth rather than because the guard would otherwise vanish. Nothing structurally
enforces that the exact path keeps routing through `convert_wire_config`, and if
the adapters ever produced `ExecutionRequest` directly the rule would disappear
silently. That is a better reason to move it into the contract than the one the
review gives, and it reaches the same conclusion.

If the newtype lands, record the resulting asymmetry deliberately: development
`0.8` would reject these values at parse time while published `0.6` and `0.7`
continue to reject them at conversion. That is defensible, since immutability
leaves no alternative, but it should be a recorded choice rather than a
consequence nobody decided.

**Recorded, as of PR #966.** The asymmetry above is now the accepted state:
`0.8.0-alpha` rejects a comma-bearing or reserved capability during
deserialization, with a contract-level message, while `0.6.0-alpha` and
`0.7.0-alpha` accept it structurally and reject it later in
`convert_wire_config` with that function's message. Two consequences follow for
the remaining phases. Phase 7.4 must classify the differing *diagnostic* for
these inputs across versions, not only the accept/reject outcome, since all
three versions still reject. Phase 6.5 freezes the newtype into
`published/v0_8_0_alpha`, deliberately preserving that diagnostic asymmetry
across published contracts.

**Where the fix landed.** Remediation moved out of the Phase 6 branch and into
the Phase 5 stack, as `user/gudge/version_specific_config_parsers_phase5a_2`
stacked on #949. This is the better placement: the defect is in the Phase 5
contract, not in Phase 6's generation of artifacts from it, and fixing it
upstream means the Phase 6 schema and TypeScript oracle inherit the constraint
on regeneration. The duplicate Phase 6 implementation was dropped when that
branch rebased onto the merged stack.

**Related finding, deliberately not addressed.** The review also records, at
Medium severity and out of scope, that the exact parser accepts positional-array
roots the generated schema declares impossible. This plan's non-goals already
exclude that hardening from every phase, and it remains excluded. Note only that
the generated schema now states `"type": "object"` on every root, so the split
between what the schema forbids and what `parse_request` accepts is visible in a
shipped artifact — a stronger argument for revisiting the non-goal than existed
when it was written, but not one being acted on yet.

#### Phase 6 risks

| Risk | Mitigation |
| --- | --- |
| ~~Schemars marks `OptionalField<T>` fields required, or wraps them nullable~~ | Settled empirically against Schemars 0.8: fields are omitted from `required` and carry no null branch, provided `OptionalField` keeps its `Default` impl and its `JsonSchema` impl sets `is_referenceable() -> false`. See Phase 6.1 |
| Moving the shared rendering perturbs the legacy artifacts | Move the code unchanged and run both existing codegen gates before and after Phase 6.4 |
| Definition name collisions across `dev` submodules silently overwrite | Two collisions already exist (`Containment`, `Request`); rename them in Phase 6.3 and guard with the Phase 6.7 uniqueness test |
| The one-shot-scoped fixture corpus makes the schema gate assert the wrong thing | Reorganize fixtures per root in Phase 6.7 before wiring the gate; see the worked `state_aware.json` case |
| Eight-branch `oneOf` degrades editor diagnostics | Resolve decision 6 explicitly, and measure it with the Phase 6 authoring-diagnostics test |
| The TypeScript emitter cannot express the root `oneOf` | Emit a discriminated union type alias; the drift gate and the SDK build cover it |
| The command line change lands without updating call sites | Only two script call sites and a handful of documentation references exist; update them all in the generator CLI commit |

### Phase 7 detailed design
Phase 7 is independent of Phase 6 and the two proceeded in parallel. It depends
on the complete Phase 5 stack and should be branched from PR #966, the current
top of that stack, or from `main` once the stack merges. Its only overlap with
Phase 6 is `wxc_common/src/lib.rs` and `Cargo.toml`; Phase 6 does not touch
`config_parser.rs` and Phase 7 does not modify the contract crate — except for
the one construction impl required by the decision 3 resolution, which Phase 6
also does not touch.

Phase 6 merged first, so later exact-contract branches build on its generated
artifact and drift-gate foundation.

#### Phase 7 objective

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

#### How Phase 7 differs from the Phase 5 adapter tests

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

#### Phase 7 parser surface

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

#### Phase 7 decisions required

Resolve these before implementation; each changes the shape of the work.

| # | Decision | Recommendation |
| --- | --- | --- |
| 1 | Whether the raw experimental JSON or the typed contract payload is authoritative for state-aware backend configuration | **Resolved.** The contract is the structural authority and the backend config type is the semantic authority. Dispatch keeps reading `experimental_raw` through Phase 9; Phase 9.5 replaces the bridge with a typed payload. See "Phase 7 decision 1 resolved" below |
| 2 | Where the shadow comparison runs | In a test-only harness, not in the production call path — that is, differential testing rather than true shadowing. Running both parsers in production doubles parse cost on every request and turns any equivalence bug into a runtime failure in a security-sensitive path. The usual justification for shadowing, discovering inputs the corpus lacks, does not apply: MXC has no live traffic, and its inputs are enumerable. Test-only does not mean the phase has no production diff: see "Phase 7 production surface" below |
| 3 | How `load_request_from_value` reaches an exact contract | **Resolved.** Add a test-only builder that constructs the declared version's contract root directly and adapts it for differential validation. Keep the existing rolling builder authoritative in production until Phase 9 cuts every public surface over together. See "Phase 7 decision 3 resolved" below |
| 4 | Whether the entry-point command splice lands in Phase 7 or Phase 9 | Phase 7. Shadow dispatch cannot cover a path that does not exist, and the splice is the prerequisite that lets every contract keep `process.commandLine` required. It changes the entry point, not parser semantics, so it can land while the rolling parser stays authoritative |
| 5 | How runtime-model equivalence is asserted | `ExecutionRequest` derives `Serialize` but not `PartialEq`, so compare `serde_json::to_value` of both sides, as the Phase 5D adapter tests already do for `wire::MxcConfig`. `ParsedStateAwareRequest` derives neither, so it needs a field-by-field comparator or a test-only `PartialEq`. Audit that no field is `skip_serializing`, or a difference will compare equal |
| 6 | When the script reaches `mxc_engine::policy` | **Resolved.** At build time. `build_request` and `build_request_with_containment` take the script as an argument, so the required `process.commandLine` is satisfied structurally. See "Phase 7 decision 3 resolved" below |
| 7 | Whether `SandboxRequest::set_script` survives decision 6 | **Resolved: remove it.** Keeping it as a post-build override would preserve mutation of an already-validated model, which is the pattern decision 6 exists to remove. Both `mxc_ffi` call sites already hold the command at build time, so neither needs it. `set_experimental` stays: it gates execution rather than altering the validated shape |

##### Phase 7 decision 1 resolved: split structural and semantic authority

**Resolution.** The exact contract is the **structural** authority for the
state-aware experimental subtree: recursive closure, unknown-field rejection,
and shape. Each backend's config type remains the **semantic** authority: what
a field means, its defaults, and its validation. Dispatch continues to read
`experimental_raw` through `deserialize_config<C>`.

This is option C of the three considered, adopted deliberately rather than by
accident, with the drift it implies closed by a test.

**Why not option B (typed payload authoritative at dispatch) now.** The stated
goal is to surface errors as early as possible, and option C already achieves
that. The contract root is recursively closed, so `appIdd` fails during
concrete-root deserialization, before dispatch and before any backend runs.
The exact parser uses the path-aware helper in `wxc_common` for that step. Option B
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
in one crate, and the crate-boundary obstacle does not exist. The Phase 9.5
engine-side binding decision supersedes the earlier dispatch-only scope
estimate: implementation also covers the neutral adapter/normalization
boundary, engine routing, controlled request construction, and the equivalence
harness. It changes no published contract or user-visible JSON shape. Option C
adds no coupling that B must later unpick. Phase 9.5 is now the explicit
retirement point: exact dispatch is authoritative first, then the raw bridge is
removed before the v0.9 stable-candidate cleanup.

**Enforcement is not weakened by dropping the duplicate payload.** Validation
is a property of parsing, not of adaptation:

```rust
let phase = mxc_config_contract::dev::probe_phase(json).map_err(exact_phase_error)?;
let request = deserialize_development_request(json, phase)?;
adapt_request(request, json) // runs on an already-validated contract value
```

The contract types are the validator; the adapter output is the payload.
Emitting `experimental: None` from the state-aware adapter discards a redundant
copy of a value that has already served its purpose as a check.

**Required work, both small.**

1. Resolve the double population at the neutral boundary. The state-aware
   adapter's internal phase converters retain their exhaustive
   contract-to-`wire::Experimental` mappings and direct mapping tests as staging
   for the typed payload migration in Phase 9.5. Before returning
   `StateAwareWireInput`, the adapter clears `config.experimental`, so
   `experimental_raw` is unambiguously the value dispatch reads and the exact
   input matches the rolling parser's canonical shape.
2. Add a parity test in `wxc_common`, which can see both definitions, asserting
   that each backend's `ProvisionConfig` round-trips through its contract
   counterpart. The asymmetry rule: the contract may be **stricter** than the
   backend, since that is the intended tightening, but the backend must never
   accept a shape the contract rejects without a recorded Phase 7.4
   classification entry. This mirrors the existing
   `check-dotnet-errorcode-parity.js` gate.

**Telemetry belongs to the seam.** After telemetry's promotion to the stable
top-level surface, the neutral representation carries it in `config.telemetry`.
Shared normalization populates the domain request from that field for both
parser paths. Clearing `config.experimental` affects the redundant backend
payload, not telemetry; `experimental_raw` is not a telemetry source, and
obsolete `experimental.telemetry` is rejected. This supersedes the earlier
experimental-telemetry mapping design. Phase 9.5 must keep telemetry
cross-cutting rather than moving it into a backend payload.

**Known live divergence, and the trigger to revisit.** The two authorities
already disagree: `models::IsolationSessionProvisionConfig` is
`#[serde(default)]` over `Option<String>` and documents that "a JSON `null` is a
second spelling of absent", while the contract's `OptionalField<String>` rejects
explicit `null`. The backend also ignores unknown fields where the contract
rejects them. Under this resolution the stricter authority wins by rejecting
first, so `"appId": null` becomes a parse error; record it in the Phase 7.4
classification.

What option C does not guarantee is that the value dispatch acts on is the one
the contract produced. That is tolerable while the payloads are plain strings
with no normalization — `appId`, `image`, `imageTarPath` — and while the
differential harness guards the two interpretations. Phase 9.5 moves to option
B before Phase 10 evolves the v0.9 surface, rather than waiting for a future
defaulting or canonicalization change to expose the drift.

##### Phase 7 decision 3 resolved: prepare direct exact construction without early cutover

**Resolution.** A test-only `mxc_engine::policy::exact` builder constructs the
contract root for the version the policy declares, then reuses the existing
per-version adapter to reach `wire::MxcConfig` and the normal semantic
validation. It does not serialize to text or deserialize a synthesized
`Value`. Production `build_request` continues to synthesize rolling wire JSON
and call the same rolling parser as the executor until Phase 9 cuts the Rust
SDK, FFI, executor, Node SDK, and state-aware surfaces over together. The
script remains a build-time argument on both paths, so the required
`process.commandLine` is satisfied before either parser runs.

**Why keep this exact counterpart.** The production `Value` is entirely
synthesized by `build_wire_config` from typed Rust — `json!` literals over
`SandboxPolicy`, `Containment`, and `WslcSection`. No user-authored JSON text
exists on that path, so a direct typed exact builder is the intended Phase 9
replacement. Keeping it test-only in Phase 7 allows parity work without giving
SDK callers a different structural contract from `wxc-exec` or state-aware
callers.

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
`OptionalField<T>` has no way to build a present value, so each independent
contract primitive module adds one explicit constructor:

```rust
impl<T> OptionalField<T> {
    pub fn present(value: T) -> Self;
}
```

The contract crate thereby becomes bidirectional — an input contract that can
also be constructed. `Default` continues to represent omission, while
`present` makes member presence explicit; no implicit `From<Option<T>>` or
`From<T>` conversion is added. Record that as intentional rather than
incidental. A feature gate (`build`) would make the boundary louder at the
cost of a CI matrix entry; it is not required.

**What it buys.** The harness can prove that version expressibility will become
largely a compile-time property at cutover. A
`published::v0_6_0_alpha::Request` has no `wslc` field, so the exact builder
cannot write a WSLC section under a `0.6.0-alpha` policy. Phase 9 promotes this
tested path only after the rolling-versus-exact classifications are complete.

**Recurring cost, accepted.** One builder per supported version — published
v0.6/v0.7/v0.8 plus mutable v0.9, then another mutable builder when publication
opens v0.10. Phase 10 makes this unavoidable: published versions retain their
legacy-compatible shapes while the v0.9 stable candidate removes old Network
fields, so construction must branch on version. The only question is whether
that branching lives in the type system or in `json!` literals.

**Cross-version combinations need explicit errors.** A `Containment::Wslc`
under a `0.6.0-alpha` policy must fail with a message naming the requirement,
for example "wslc requires 0.9.0-alpha", produced at the version match arm.

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

#### Phase 7 production surface

Decision 2 keeps the comparison in tests, but the phase still carries a
production diff. Its entry-point, staging, and comparison changes are:

| Change | Kind | Step |
| --- | --- | --- |
| Command splice replaces `allow_missing_command` at the CLI entry point | Behavior-visible, entry point only | 7.1 |
| Script becomes a build-time argument to `build_request`, removing the second `allow_missing_command` consumer | Behavior-visible, `mxc-sdk` and `mxc_ffi` | 7.1 |
| `normalize_state_aware` extracted from `convert_wire_state_aware` | Behavior-preserving refactor | 7.2 |
| Exact-contract JSON parser added, dead in production | Compiled but uncalled | 7.3 |
| `OptionalField::present` added to each contract primitive module | New explicit construction surface | 7.3 |
| Hidden typed one-shot contract bridge added for `mxc_engine` | Workspace-internal cross-crate API | 7.3 |
| Per-version exact policy builders added beside rolling JSON synthesis | Test-only differential infrastructure | 7.3 |

No public production call site moves: the Rust SDK and FFI continue through
the rolling builder, and user-authored JSON continues through the rolling
parser. The exact builder parity tests pin the runtime model before the common
Phase 9 cutover.
`wxc_common` adds only a `#[doc(hidden)]` exact one-shot
contract enum and normalization function because Rust has no friend-crate
visibility and `mxc_engine` must cross the crate boundary without exposing the
adapter modules or adding implicit public conversions. The bridge and parser
path are compiled production staging code, while `mxc_engine` invokes the
bridge only from its test-only exact builders until Phase 9.

#### Phase 7 status

Phase 7.1 is renamed **Phase 7a** and is complete on
`user/gudge/version_specific_config_parsers_phase7a`. Its six development
commits, plus a follow-up covering the unconvertible-command entry-point error,
were squashed into a single commit rebased onto `main` after the Phase 5 stack
landed. The pre-squash history is retained locally on
`user/gudge/version_specific_config_parsers_phase7_prerebase`. The result is
open as PR #969.

After adversarial review, convergence work restarted from the pre-expansion
commit `3a295c00` on
`user/gudge/version_specific_config_parsers_phase7a_redux`. The follow-up
commits applied the compatibility boundary below, consolidated backend
inspection with the raw source edit, restored cross-platform and public-surface
coverage, and updated the user and architecture documentation. They were
squashed on 2026-09-02 as `499fcda8`, then rebased onto `origin/main` at
`878936a4` and verified again. The presquash history is retained on
`backup/version_specific_config_parsers_phase7a_redux_presquash-993a651a`.
The stack was most recently rebased onto `origin/main` at `29702c3a` and the
local and remote `user/gudge/version_specific_config_parsers_phase7a` refs were
moved to `aa6c12d3` with `--force-with-lease`, so PR #969 points to the
validated converged implementation.

The squashed commit covers the steps the plan broke out separately:

| Step | Content |
| --- | --- |
| 7.1.1.0 | characterization tests |
| 7.1.1.1 | pre-parse probes (`wxc_common::probe`) |
| 7.1.1.2 | splice (`wxc_common::splice`) |
| 7.1.1.3 | override pipeline, loader wiring, and deletion |
| 7.1.1.4 | superseded; see the 7.1.1.4 note |
| 7.1.2 | build-time command |

`allow_missing_command` and `SandboxRequest::set_script` no longer exist. Both
consumers resolved on the same principle: the command is present before the
request is parsed or built, never patched into it afterwards. The 7.1.1.0
characterization tests passed unchanged across the refactor, which is the
evidence that the CLI behavior was preserved.

##### Phase 7a compatibility boundary

**Adopted 2026-09-02.** Phase 7a preserves behavior for valid requests and for
the ordinary path without a trailing CLI command. When a valid trailing command
is supplied, MXC must resolve the request's quoting context, splice the command
before parsing, and feed the resulting complete document through the normal
typed parser. Successful requests must retain the same resolved command,
containment, policy, and state-aware error-routing behavior as the previous
post-parse override path.

Exact historical precedence between independently invalid inputs is not a
compatibility requirement. In particular, when both command preparation and an
unrelated policy field are invalid, Phase 7a may report the command-preparation
error before the typed policy error. The selected ordering must be deterministic
and covered by tests, but Phase 7a does not perform a synthetic splice or a
second typed parse solely to reproduce which invalid-input diagnostic happened
to win before this rework.

This boundary distinguishes semantic compatibility from diagnostic identity:
ordinary typed validation remains authoritative for the effective document,
while failures that prevent construction of that document are entry-point
errors. Any resulting difference for multiply-invalid input is recorded as an
intentional Phase 7 classification rather than repaired with another parser
path.

Diagnostics produced after a successful splice describe the effective document
that the typed parser consumed. Replacing or inserting `process.commandLine`
may therefore shift a later same-line column relative to the caller's original
bytes. Phase 7a tests this behavior against an explicitly spliced document; it
does not retain an edit map or translate locations back to the original source.

Command preparation also precedes construction of the typed request that owns
the top-level telemetry configuration. A failure to resolve, render, or
splice the trailing command is consequently a pre-request failure and does not
initialize policy-configured telemetry. This is an accepted entry-point
classification, not a reason to add a partial telemetry parser or a synthetic
typed-validation pass.

The programmatic builder migration remains part of Phase 7a. CLI loading and
`mxc_engine::policy` were the only two consumers of the missing-command
relaxation; requiring the script in `build_request` and
`build_request_with_containment` removes the second consumer and prevents the
same parse-then-patch pattern from surviving through the Rust SDK and FFI. The
two entry-point changes are therefore reviewed and landed atomically.

The trailing-command path retains separate phase-probe, raw command-source, and
authoritative parser passes. Each owns a different contract: phase and output
routing, duplicate-preserving backend selection and source editing, and typed
structural plus semantic validation. Phase 7a consolidates backend selection
with the raw edit pass but does not couple these remaining responsibilities
without representative evidence that their startup cost is material. Further
pass coalescing requires a benchmark against realistic large policies and must
preserve the no-command parser path unchanged.

Two lessons worth carrying into the remaining steps. First, `cargo doc` belongs
in this phase's quality gate: `-D warnings` lives in `RUSTFLAGS` and rustdoc
reads `RUSTDOCFLAGS`, so deleting a documented item breaks intra-doc links that
no other gate reports. Second, the repository has 11 pre-existing broken
intra-doc links, so compare against a baseline rather than requiring zero.

Phases 7.2 through 7.5 are complete. The parser-parity remediation that paused
the work merged in PR #966; see "Phase 6 review finding: contract value-rule
gaps".

#### Phase 7 step breakdown

##### Phase 7.0: Prepare the implementation branch

Base on PR #949 or on `main` once the Phase 5 stack merges. Confirm
`cargo test -p wxc_common` is green first, so a later failure is attributable
to this phase. No source files change in this step.

##### Phase 7.1: Remove `allow_missing_command` from both of its consumers

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


###### Phase 7.1.1: The CLI consumer

Grounding facts, verified against the branch: there is exactly one production
call site (`wxc/src/main.rs:973` on the Phase 7 worktree); everything from line 1366 onward is
`mod tests`. There is one post-parse mutation to remove
(`apply_command_override`, `main.rs:243`, mutating `script_code` at line 256). `lxc` and `mxc_darwin` are
unaffected — they call `load_request`, where the flag is always false, and they
never mutate `script_code`.

**7.1.1.0 — Characterize the current behavior.** Pin the four behaviors below
with tests before changing anything. See "Phase 7.1.1.0 tests" for the list and
placement.

- An override replaces a policy-supplied `commandLine` **and logs**
  `Overriding policy process.commandLine with CLI command: {cmd}`.
- An override is accepted for one-shot and for state-aware **exec only**; any
  other phase errors with "CLI command override is only supported for
  state-aware exec requests".
- Error routing differs by request kind: one-shot and decode failures print a
  stderr diagnostic, state-aware failures print a JSON error envelope on
  stdout.
- Quoting is backend-specific across all three `CommandLineContext` values.

**7.1.1.1 — Add pre-parse probes in `wxc_common`.** Three source-text probes,
each reusing existing machinery rather than introducing a second mapping:

| Probe | Reuses | Purpose |
| --- | --- | --- |
| `phase` | the existing `RequestDiscriminator` | one-shot versus state-aware, and which error convention applies |
| `containment` | `wire::Containment` deserialization, then `From<wire::Containment> for ContainmentBackend` | the one-shot quoting context |
| `sandboxId` | `parse_sandbox_id_prefix` and `backend_from_prefix` | the state-aware exec quoting context |

Do not hand-roll the containment-to-backend mapping. `map_wire_containment` is
`Some(c) => c.into()` with `None => Process.into()`, and the `From` impl already
resolves the abstract `process` and `vm` intents per host, including the
`appcontainer` and `macos_sandbox` aliases. Reusing both is what removes the
drift risk that would otherwise justify the post-parse assertion.

**7.1.1.2 — Implement the splice.** A function over decoded JSON text that
overwrites `process.commandLine`, creating the `process` object when absent —
both cases exist today — and reports whether the field was previously present
and non-empty so the override log still fires exactly when it does now. A
`serde_json::Value` round-trip is the agreed implementation. A non-object
`process` must error rather than panic.

**Refined as implemented.** `splice_command` returns `Option<Spliced>` and
*declines* rather than erroring: a document it cannot transform — a non-object
root, a non-object `process`, or unparseable JSON — is one the parser rejects
anyway, so returning the source unchanged lets that input keep the parser's own
message and output routing instead of inheriting a differently routed
entry-point diagnostic. The same passthrough covers an unreadable `phase` or
`containment` declaration. This is a strictly better answer than the plan's, and
the requirement it was written to enforce — never panic — still holds.

**7.1.1.3 — Change `LoadOptions`.** Replace `allow_missing_command: bool` with
the CLI command, and perform decode, probe, splice, and parse inside
`load_mxc_request_with_options`. The loader is the right home: it already owns
`decode_request_input_without_logging` and the `ParseError` routing, so placing
the splice in the driver would duplicate the decode step and re-derive the error
conventions. Route splice failures by the probed phase, so a state-aware failure
still produces an envelope. An empty or unconvertible command becomes an
entry-point error — a genuinely new failure site, since `has_cli_command` makes
it unreachable today.

**7.1.1.4 — Assert the context after parsing.** Compare the context used for the
splice against the resolved containment and fail loudly on a mismatch. This is
the Phase 9 acceptance criterion recorded under "Entry-point-dependent command
requirements".

**Superseded as implemented.** Phase 7a carries no runtime assertion. The drift
it guards against is closed at the source instead:
`CommandSource::one_shot_backend` deserializes `wire::Containment` and reuses
the same `From` conversion the parser uses, and
`one_shot_backend_agrees_with_the_parser_for_every_spelling` pins it against
`map_wire_containment` for all twelve accepted spellings, including the
absent-containment host default and the explicit-null case. That is the outcome
7.1.1.1 predicted when it required command preparation to reuse existing
machinery rather than hand-roll a second mapping. The Phase 9 acceptance
criterion is therefore restated: the requirement is that the splice context and
the resolved containment cannot diverge, satisfied by shared code plus an
exhaustive test rather than by a post-parse comparison. Reinstate the runtime
assertion only if a future change gives command preparation its own mapping.

**7.1.1.5 — Wire the driver and delete the old path.** Pass the CLI command
through `LoadOptions`; delete `apply_command_override`, the
`has_command_override` plumbing, and the `command_override_context_for_state_aware`
call in the state-aware branch. `command_override_from_cli`'s argv conversion
moves into the loader rather than dying. In `config_parser`, delete
`allow_missing_command`, the `command_required` computation, and the parameter
from `convert_wire_config` and `convert_wire_state_aware`.

`load_request_from_value`'s third parameter belongs to Phase 7.1.2. Either land
both halves together, or leave that one parameter in place until 7.1.2 removes
it.

**7.1.1.6 — Tests and verification.** Splice-path equivalents of the existing
`allow_missing_command` tests, plus the matrix in "Phase 7.1.1.0 tests" re-run
against the new implementation. Then the standard ladder: `cargo fmt --all --
--check`, `cargo check --workspace --all-targets`, `cargo clippy -p wxc_common
-p wxc --all-targets -- -D warnings`, `cargo test -p wxc_common -p wxc`, and a
manual smoke run with and without a policy command.

Two hazards worth stating. Error routing is behavior, not cosmetics: probing
`phase` before splicing is what preserves the envelope-on-stdout convention for
state-aware requests. And the ordering is fixed — probe phase, probe context,
convert argv, splice, parse — because obtaining the command string before the
backend is known is the defect this design exists to prevent.

##### Phase 7.2: Extract the shared state-aware normalization seam

Status: complete on
`user/gudge/version_specific_config_parsers_phase7b` at `c3519b3d`; open as
PR #1091, stacked on Phase 7a PR #969.

Before Phase 7.2, `convert_wire_state_aware` interleaved three concerns: recovering
`experimental_raw` and the masked base JSON, a series of validations that read
the raw block, and the normalization into `ParsedStateAwareRequest`.

The phase extracts the third concern into a function over the neutral value
both parsers can produce:

```rust
fn normalize_state_aware(
    input: StateAwareWireInput,
    logger: &mut Logger,
) -> Result<ParsedStateAwareRequest, WxcError>
```

The extraction is behavior-preserving: the rolling parser produces the same
results before and after, proven by the existing `wxc_common` tests. The exact
path is not folded in yet.

The interleaved validations that become structurally impossible for
exact input — the non-object `experimental` guard, the moved-to-stable
`seatbelt` / `macos_sandbox` check, the stray one-shot section rejection, and
the `containment`-on-non-provision rejection are all closed by the contract
roots. They stay in the seam for the rolling path; for exact input they are
unreachable, and the difference in the resulting *error message* is Phase 7.4
classification material.

The Phase 5D state-aware equivalence tests now compare against the real rolling
pre-normalization value rather than the unmasked `wire::MxcConfig`
deserialization that the state-aware pipeline never produces.

Per the decision 1 resolution, the seam owns telemetry population for both
paths. The state-aware adapter clears `config.experimental` at the neutral
boundary while retaining its tested internal mappings for Phase 9.5.

Suggested commit boundary: `Extract the shared state-aware normalization seam`.

The implementation:

- characterizes every state-aware phase, all three provision backends, raw
  experimental and source retention, telemetry, and post-provision Network
  presence before the refactor
- adds `parse_rolling_state_aware_wire_input` as the rolling source adapter and
  `normalize_state_aware` as the shared validation and runtime-normalization
  seam
- keeps rolling-only validation messages stable and moves cross-cutting
  telemetry population into the seam
- makes `experimental_raw` the sole payload presented to normalization while
  retaining the exact adapters' tested `wire::Experimental` mappings as
  compile-time staging for the typed Phase 9.5 payload
- replaces the Phase 5D plain-wire comparison with complete
  `StateAwareWireInput` equivalence across every phase and provision backend
- adds contract/backend parity tests for IsolationSession and WSLC provision
  payloads and records the known exact-stricter `null` and unknown-field cases;
  Windows Sandbox remains a unit provision payload
- confirms dispatch continues to deserialize backend phase config from
  `experimental_raw`, which remains the temporary transport until Phase 9.5

The full Rust workspace format, compile, clippy, and test gates pass on the
branch.

##### Phase 7.3: Add the private exact-contract path

Status: complete on
`user/gudge/version_specific_config_parsers_phase7c` at `b13c0bae`, stacked on
the Phase 7.2 branch and open as PR #1096. The initial development commits were
squashed on 2026-09-03; the diagnostic follow-up was folded into the current
single commit on 2026-09-05. Original history is retained locally on
`backup/version_specific_config_parsers_phase7c_presquash-764a9850`.

The implementation adds a private path in `config_parser` that probes the
version, dispatches to the exact registry, calls the applicable adapter, and
produces the same runtime model:

- one-shot results feed the existing one-shot normalization
- state-aware results feed `normalize_state_aware` from Phase 7.2

The selected concrete development roots, like published roots, deserialize
directly from source through `config_deserialize::from_str` in `wxc_common`.
The exact parser path does not delegate typed development deserialization to the
contract crate's plain-Serde convenience parser. Review follow-up covers
nested paths and whole-document locations for all registered one-shot versions
and all eight development roots, plus escaping and secret-path redaction;
the contract crate remains independent of runtime crates.

Nothing calls the exact JSON parser path in production. It exists for the
harness in Phase 7.4 and becomes authoritative in Phase 9.

The exact JSON parser is ordinary private production code carrying
`#[cfg_attr(not(test), allow(dead_code))]`, the idiom the adapter modules and
`state_aware_wire` already use. That attribute means dead in a production build
and genuinely reachable under `cargo test`, so the path is compiled, formatted,
and clippy-checked alongside everything else, and Phase 9's cutover is a routing
change rather than a code move. Do not place the path inside `#[cfg(test)]`:
that would force Phase 9 to move code into production at the moment it becomes
authoritative, so the validated code would not be literally the shipped code.

The hidden one-shot bridge references the published adapters, so the
v0.6/v0.7/v0.8 adapter modules no longer carry dead-code suppressions even
though no public production entry point calls the bridge yet. The development
adapter retains its module-level suppression because its state-aware mappings
remain staging code. `state_aware_wire` and the exact JSON parser retain their
suppressions until Phase 9 makes exact dispatch authoritative.

This step also adds explicit `OptionalField::present` construction to each
independent contract primitive module plus a narrow `#[doc(hidden)]`
one-shot-contract bridge in `wxc_common`, and repoints `mxc_engine::policy` at
test-only per-version contract builders, per the decision 3 resolution.
Production `build_request` remains on `build_wire_config` and
`load_request_from_value`. Adapter modules and `into_wire` functions remain
crate-private; no public `From` conversion from contract requests to
`wire::MxcConfig` is added.

The test-only direct builders live under `mxc_engine::policy::exact`: `mod.rs`
owns version selection and shared preparation, while `v0_6.rs`, `v0_7.rs`,
`v0_8.rs`, and `v0_9.rs` own contract-specific construction and mapping. The
rolling `serde_json::Value` builder remains the production path and the parity
oracle. Safe `NonEmptyString::new` and `NonEmptyVec::new` constructors are
exposed where typed construction needs them; this changes Rust implementation
surface without changing a published JSON shape.

The Phase 7c development sequence was:

| Step | Content |
| --- | --- |
| 7c-a | Explicit construction primitives and hidden exact one-shot bridge |
| 7c-b | Private exact-contract parser and version dispatch |
| 7c-c | Comprehensive exact parser coverage |
| 7c-d | Test-only per-version Rust policy builders and rolling parity oracle |
| 7c-e | SDK, authoring, versioning, and architecture documentation |

The original squashed commit was `f790ec76`; the current published single
commit is `b13c0bae` (`Add private exact contract parsing`).
The earlier exact-production variant is retained locally on
`backup/version_specific_config_parsers_phase7c_exact-production-27717182`.

The full Rust workspace format, compile, clippy, and test gates pass. The
`aarch64-apple-darwin` cross-target check passes for `mxc_engine` and
`mxc-sdk`; cross-target clippy reaches an unrelated existing
`clippy::let_and_return` warning in `mxc-sdk/tests/streaming.rs`.

##### Phase 7.4: Build the equivalence harness and classify differences

Status: complete at `3b411771` on
`user/gudge/version_specific_config_parsers_phase7d`, open as PR #1097 and
stacked on Phase 7.3 PR #1096.

Put the harness in an inline `#[cfg(test)]` module in `config_parser.rs`, the
crate's dominant convention and the only placement that keeps the exact path
private. An integration test under `src/core/wxc_common/tests/` can only reach
`pub` items, and making an unfinished parser part of `wxc_common`'s public API
to test it is not worth the corpus convenience; read the corpus from
`CARGO_MANIFEST_DIR` instead.

For each input, parse with both paths, adapt both to the runtime model, and
assert semantic equivalence by the mechanism chosen in decision 5.

Inputs must cover every loader mode, both request kinds, every state-aware
phase, every provision backend, published `0.6`/`0.7`/`0.8` declarations, the
`0.9` development declaration, the command-splice path from Phase 7.1,
immutable post-provision policy, telemetry, required envelope fields, and
source-position diagnostics.

Differences are not failures; unclassified differences are. Record each one in
a table with its input, both behaviors, and the reason.

Differences come in two directions, and they are not equally safe.

**Exact stricter than rolling** — the expected direction, and the point of the
work. Each is an intentional tightening to classify and, where it affects the
corpus, to migrate in Phase 8:

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
- a stray `sandboxId` on a provision request, which the rolling parser lifts
  regardless of phase and the provision roots reject
- `{"process": {"commandLine": 42}}` combined with a CLI command override,
  which the rolling parser rejects and the splice makes parseable by
  overwriting the field
- curated policy diagnostics replaced by structural Serde errors, most visibly
  the IsolationSession `filesystem` and `ui` rejections, whose current messages
  explain *why* the backend cannot honor the policy
- any corpus document that is valid under one root and invalid under another

**Exact looser than rolling** — the dangerous direction, and the one the
harness exists to find. The contract accepts a document that `convert_wire_config`
rejects on a value rule the contract does not express. The Phase 6 review found
the first instance:

- `processContainer.capabilities` entries containing a comma, or naming the
  reserved `learningModeLogging` / `permissiveLearningMode` capabilities. The
  contract types all three versions as a bare `Vec<String>`; the rolling parser
  rejects both, case-insensitively for the reserved names

This class is not confined to that field. `convert_wire_config` also enforces
filesystem path rules, proxy and enforcement-mode combinations, backend-section
constraints, and `captureDenials` output-path validation, none of which any
contract expresses. Run the harness over the corpus's **invalid** documents,
not only the valid ones, and assert that both paths reject the same inputs.

Suggested commit boundary: `Add rolling-versus-exact parser equivalence tests`.

##### Phase 7.5: Record the classification in this plan

Status: complete on `user/gudge/version_specific_config_parsers_plan`.

The harness examines all JSON documents under `tests/configs`,
`tests/examples`, and `tests/policy`. The executable file-level inventory lives
in `config_parser::tests::expected_corpus_divergences`: every divergent path is
named, and a new or changed divergence fails until its classification is
updated deliberately.

The pre-migration Phase 7d inventory contains 282 documents. The following
tables record that baseline; Phase 8 above records the completed migration.

| Result | Count |
| --- | ---: |
| Both parsers accept with equivalent runtime models | 148 |
| Both parsers reject | 9 |
| Rolling accepts and exact rejects | 125 |
| Rolling rejects and exact accepts | 0 |
| Both accept with different runtime models | 0 |

The 125 exact-stricter corpus results are:

| Classification | Count | Rolling behavior | Exact behavior | Disposition |
| --- | ---: | --- | --- | --- |
| Missing version | 55 | Accepts the legacy omitted declaration | Rejects the missing exact declaration | Assign a registered version based on the document's request shape |
| Published comment rejected first | 2 | Accepts the annotation | Rejects `_comment` before reaching the development-only containment | Migrate with the owning WSLC documents and preserve the first-error classification |
| Development containment under a published version | 45 | Accepts the rolling containment enum | Rejects the unknown published containment value | Move the documents to the development contract |
| Experimental content under a published version | 2 | Accepts the rolling experimental extension | Rejects the unknown published field | Move the documents to the development contract |
| State-aware request under a published version | 21 | Accepts the rolling state-aware shape | Rejects `phase` because published roots are one-shot | Move the documents to the development contract |

The focused non-corpus cases classify structural and diagnostic differences:

| Input | Rolling behavior | Exact behavior | Classification | Disposition |
| --- | --- | --- | --- | --- |
| Published v0.6 request with `experimental` | Accepts | Rejects the unknown field | Exact stricter | Intentional published-root closure |
| Explicit `containerId: null` | Accepts as absent | Rejects the explicit null | Exact stricter | Preserve omission-versus-null distinction |
| IsolationSession `appId: null` | Accepts as absent | Rejects the explicit null | Exact stricter | Migrate the compatibility spelling to omission |
| Unknown IsolationSession provision member | Ignores the member | Rejects the closed payload | Exact stricter | Intentional recursive closure |
| `sandboxId` on provision | Accepts and lifts the value | Rejects the field on the provision root | Exact stricter | Intentional phase-specific root shape |
| Network policy on start, stop, or deprovision | Retains the supplied policy for semantic rejection | Rejects the field structurally | Exact stricter | Intentional immutable-policy shape |
| IsolationSession filesystem or UI policy | Retains the supplied policy for later backend validation | Rejects the field structurally | Exact stricter with later diagnostic change | Structural rejection is correct; the public request no longer reaches the backend's curated explanation |
| `phase: null` | Rejects as a missing phase | Rejects as an invalid declaration | Diagnostic only | Both reject; retain the routing distinction |
| Malformed JSON after a readable version | Reports JSON syntax | Reports version-probe failure | Diagnostic only | Both reject; retain the attribution difference |
| Invalid v0.8 or v0.9 capability name | Rejects during semantic conversion | Rejects during contract construction | Diagnostic only | Both reject the same value rule |
| Numeric `process.commandLine` with a CLI command | Leaves the invalid value for typed rejection | Leaves the invalid value for typed rejection | Convergent rejection | Preserve the command-splice behavior |

The exact path also preserves every sampled rolling value-rule rejection:

| Value rule | Covered inputs |
| --- | --- |
| Capability syntax and reserved names | Comma-separated names and case-insensitive `learningModeLogging` / `permissiveLearningMode` variants across v0.6-v0.9 |
| Filesystem paths | Whitespace-only, quoted, and embedded-NUL paths |
| Proxy and enforcement compatibility | Proxy combined with capabilities-only enforcement |
| Backend section compatibility | A ProcessContainer section supplied with LXC containment |
| Denial capture output | Relative `captureDenials.outputPath` |

No exact-looser acceptance or accepted-model difference was found. The runtime
snapshot compares the serialized `ExecutionRequest`, proxy internals, all five
policy fields omitted from serialization, the serde-skipped
`telemetry.requested_sandbox_kind`, and every field on
`ParsedStateAwareRequest`. Logger snapshots retain both primary output and
warnings, so the comparison does not depend on model serialization alone.

Review follow-up closes the distinction between retaining a snapshot field
and actually asserting it. Each of the 14 curated divergence cases declares a
full `DiagnosticExpectation` for every rejecting side: route, category, path,
line, column, and required message fragments. Logger expectations constrain
channel, order, count, and stable fragments on both accepted and rejected
sides. Negative mutation cases exercise those checks; positive cases permit
nonessential wording changes. This is not byte-for-byte error-message freezing
or a requirement that intentionally different parser outcomes become equal.

The snapshot also distinguishes `OneShotMalformed` from `OneShot`, even when
their rendered messages are identical. Phase 9 adds the separate `Version`
outcome for pre-discrimination declaration failures and updates the affected
expectations at that cutover boundary; the Phase 7 staging behavior is not
retroactively changed.

#### Phase 7 tests

Status: satisfied by the Phase 7a-7d test suites.

1. Rolling-path behavior is unchanged, proven by the existing `wxc_common`
   suite before and after the Phase 7.2 extraction.
2. Both paths converge for every representative one-shot request across
   published `0.6`/`0.7`/`0.8` and development `0.9`.
3. Both paths converge for every state-aware phase and provision backend.
4. Both paths converge across every loader mode, including the spliced
   command-override path.
5. Every divergence is asserted explicitly and matches its classification.
6. Source-position diagnostics are compared, not just accept/reject outcomes.
7. The corpus parses through the exact path with its acceptance classified,
   which is the direct input to Phase 8.

#### Phase 7 exit criteria

Status: satisfied at the Phase 7 boundary; Phase 9 later changes production
authority without retiring the differential oracle.

- The rolling parser is still authoritative and its behavior is unchanged.
- The exact path produces the same runtime model for every convergent input.
- Every divergence is classified with a recorded reason.
- `allow_missing_command` is gone and the command splice is covered by tests.
- Decisions 1 through 5 are resolved and recorded.

#### Phase 7 risks

| Risk | Mitigation |
| --- | --- |
| The seam extraction silently changes rolling behavior | Extract without tidying; the existing suite is the regression test, run before and after |
| Shadow parsing lands in the production path | Resolve decision 2 first; keep the harness in tests |
| `serde_json::to_value` equivalence hides a difference in a skipped field | Audit `ExecutionRequest`'s `Serialize` for `skip_serializing`, or add a test-only `PartialEq` |
| The experimental authority question is deferred again | It is decision 1 and it gates Phase 7.2; after Phase 9 the asymmetry is permanent |
| `load_request_from_value` is discovered to have no exact path during Phase 9 | It is decision 3, resolved here rather than at cutover |

The harness resolves the comparison risks: it explicitly snapshots every
skipped runtime field, keeps production routing on the rolling parser, covers
the hidden exact bridge, and fails on any unclassified or exact-looser result.

#### Phase 7.1.1.0 tests

**File:** `src/core/wxc/src/main.rs`, inside the existing `mod tests`, which
begins at line 1366 on the Phase 7 worktree branch. Add them beside the current
CLI command-override tests, which occupy lines 1527 to 1808. That module is the
only place where the CLI parsing helpers and the loader are both visible, and it
already provides `parse_cli` (1375), `encoded_policy` (1381), and
`test_logger` (1385).

**Write them through a helper, not against the current call shape.** Today the
behavior is split across two calls that the refactor merges into one:

```rust
let command_override = command_override_from_cli(&cli, context)?;
let opts = LoadOptions { is_base64: true, allow_missing_command: command_override.is_some() };
let mut request = load_mxc_request_with_options(&encoded_policy(policy), &mut logger, opts)?;
apply_command_override(&mut request, command_override.as_deref(), &mut logger);
```

Tests written against that shape must be rewritten in the same commit that
changes the behavior, which defeats the point of writing them first. Introduce
one helper — resolve a CLI argv plus a policy document into the final
`ExecutionRequest` and the logger buffer — and have every test assert only on
those two outputs. The refactor then edits the helper body and leaves the
assertions untouched.

**Existing coverage, verified.** Already present and worth keeping:
`cli_command_overrides_policy_command_line_in_resolved_request` (the override
plus its log line), `windows_sandbox_cli_command_uses_cmd_context`,
`isolation_session_cli_command_quotes_shell_metacharacters`,
`wslc_cli_command_uses_posix_shell_quoting`, the five argv-capture tests, and
`state_aware_command_override_only_applies_to_exec_phase`. The quoting tests
survive the refactor unchanged, because `command_override_from_cli` and
`cmdline_from_argv_for_context` both survive it.

**Gaps to close before refactoring.**

The shared helper:

```rust
fn resolve_with_cli(argv: &[&str], policy: &str) -> (Result<ExecutionRequest, ParseError>, String);
```

| # | Proposed test name | What it pins | Status |
| --- | --- | --- | --- |
| 1 | `cli_command_overrides_policy_command_line_in_resolved_request` | Override replaces a policy command and logs the override line | Exists at 1676; move onto the helper |
| 2 | `cli_command_fills_absent_policy_command_line_without_override_log` | Override supplies a command the policy omits, and the log does **not** fire | New. The `if !script_code.is_empty()` branch in `apply_command_override` is unasserted |
| 3 | `policy_command_line_survives_without_cli_command` | The no-override path leaves `script_code` untouched | New. Nothing pins it end to end |
| 4 | `state_aware_exec_cli_command_reaches_script_code` | Exec accepts an override and the command lands in the request | New. Only the rejection case is covered |
| 5 | `state_aware_non_exec_cli_command_error_routes_to_envelope` | Non-exec rejection **and** its envelope routing | New, highest value. The existing test at 1808 calls `command_override_context_for_state_aware` on a hand-built request; routing is decided in `main()` and is untestable there |
| 6a | `cli_command_quoting_for_windows_create_process_in_resolved_request` | Final `script_code` under `WindowsCreateProcess` | New. The test at 1668 asserts the intermediate conversion |
| 6b | `cli_command_quoting_for_command_processor_in_resolved_request` | Final `script_code` under `WindowsCommandProcessor` | New; complements 1780 |
| 6c | `cli_command_quoting_for_posix_shell_in_resolved_request` | Final `script_code` under `PosixShell` | New; complements 1798 |
| 7a | `empty_cli_command_is_an_entry_point_error` | An empty converted command fails at the entry point | New. Unreachable today through `has_cli_command`; 7.1.1.3 makes it reachable |
| 7b | `non_object_process_section_is_rejected` | A non-object `process` errors rather than panicking | New; the splice must not assume an object |
| 7c | `malformed_policy_json_is_rejected_before_splicing` | Decode failure precedes any splice attempt | New |

Tests 6a through 6c are deliberately separate from the three existing
context tests: those assert the string `command_override_from_cli` produces,
while these assert what reaches `script_code` after the whole pipeline. The
existing ones survive the refactor untouched; these are what prove the splice
preserves quoting.

Test 5 is the highest value of these. Error routing is the behavior most likely
to regress silently, because 7.1.1.3 moves that decision from `main()` into the
loader, and `main()` cannot be called from a test.

The three `allow_missing_command` tests in `config_parser.rs` (lines 1604,
1623, and 1636) characterize the loader half and are replaced, not preserved, by
7.1.1.6.

Line references in this section are against the Phase 7 worktree branch. That
branch predates the rebased #949 tip, so the numbers shift once it is rebased,
though the override machinery itself is identical in both.

## 4. Decisions adopted along the way

### Decision summary

| Decision | Adopted result |
| --- | --- |
| Published contract contents | Published contracts contain stable one-shot fields only; experimental and state-aware structures remain on the mutable development line |
| Legacy v0.8 release | Treat tag `v0.8.0` and stable schema blob `78791e8ad9adcd8b96a632fc1d9471153a9fe20b` as immutable; reconstruct Rust types without regenerating the released schema |
| Version progression | Phase 6.5 moves exact development to `0.9.0-alpha`; Phase 11 publishes v0.9 and opens `0.10.0-alpha` development |
| v0.9 Network surface | Remove legacy Network fields from every v0.9 one-shot and state-aware root before publication; published v0.6/v0.7/v0.8 contracts retain their immutable syntax |
| Phase 10a acknowledgment location | Backend-specific under `experimental.isolation_session`: directly on the one-shot section and inside `provision` for state-aware requests |
| Phase 10a acknowledgment value | `acknowledgeUnrestrictedNetwork` is an optional true-only marker; omission does not acknowledge unrestricted networking, and the legacy acknowledgment remains available during 10a |
| Phase 10a acknowledgment coexistence | Accept legacy-only, acknowledgment-only, and both consistent forms during 10a; reject an explicit empty network section, incompatible restrictions/proxies, or neither form |
| Phase 10a acknowledgment validation | Preserve existing boundaries: conditional acknowledgment presence is structural for state-aware provision; one-shot retains its common/backend-policy failure path; invalid supplied values remain structural errors |
| Phase 10a runtime representation | Keep the common policy model and pass typed acknowledgment separately through backend-specific runtime configuration; distinguish authored policy from implicit defaults using existing presence information |
| Phase 10a SDK compatibility | Preserve shared SDK APIs while permitting documented source changes confined to IsolationSession's experimental API; design its post-cutover acknowledgment API in 10a so 10b-10d does not reshape it again |
| Phase 10a SDK construction | Add explicit acknowledgment to existing pre-build authoring/configuration surfaces, preserve original network omission, and avoid post-normalization repair setters or unrelated backend-support expansion |
| Phase 10a policy identity | Preserve existing hashes; acknowledgment-bearing requests add an explicit scoped acknowledgment/presence projection, with intentionally distinct identities for legacy-only, new-only, and combined forms |
| Contract authority | Versioned Rust types own structure and local value rules; shared conversion and validators own cross-field and backend semantics |
| Differential validation | Compare rolling and exact paths in tests rather than dual-running both parsers in production |
| Programmatic policy construction | Prepare direct typed exact builders under tests in Phase 7, keep rolling construction authoritative, and promote the exact builders with the common Phase 9 cutover |
| Command overrides | Resolve and splice the command before exact parsing so every effective request satisfies the required process shape |
| State-aware backend payload transport | Preserve `experimental_raw` through exact-dispatch cutover, then replace it with typed payloads in Phase 9.5 |
| Phase 9.5 typed dispatch | Engine-side checked binding to `BoundStateAwareRequest<B>`; derive phase from the operation variant, control construction, and retain containment/sandbox-ID routing plus backend-owned defaults and validation |
| Phase 9.5 payload model | Sparse operations with runtime-owned provision configuration; retain IsolationSession's domain type, add `models::WslcProvisionConfig`, and adapt the separate exact/rolling wire types explicitly |
| Phase 9.5 presence/defaulting | Preserve backend-observable configuration/field presence and existing policy-presence flags; discard otherwise equivalent outer-wrapper distinctions and leave default resolution in the backend |
| Phase 9.5 equivalence evidence | Before raw-transport deletion, combine independent test-only legacy extraction, explicit expected values, and recording-backend dispatch observations; compare behavior rather than source/raw representation and retain exact rejection boundaries |
| Phase 9.5 normalization | Preserve common wire-backed conversion behind typed production and separate test-only legacy wrappers; derive production context from the operation and keep exact diagnostics, legacy check ordering, telemetry, and policy-presence behavior |
| Phase 9.5 acceptance | Require configuration/binding, execution-path, diagnostic/entry-point, platform/feature, production/artifact, and live lifecycle gates; Windows Sandbox is compiled in every Windows configuration and skipped live suites are not passing evidence |
| Freeze model | Published JSON shapes are fixed now; Phase 11 freezes contract-to-runtime behavior as well, while permitting behavior-equivalent source refactoring and security hardening |
| Publication mechanics | Future publication freezes contract, adapter, and policy builder behavior together and adds artifact, fixture, and equivalence checks |

### Publication and version-transition decision record

The current forward sequence is Phase 8 migration, Phase 9 exact dispatch,
Phase 9.5 typed state-aware payload migration, Phase 10 removal of legacy v0.9
Network fields and stable-candidate completion, then Phase 11 publication of
`0.9.0-alpha` with `0.10.0-alpha` opened for development.

The historical sequence that established the v0.8/v0.9 starting point was
agreed 2026-08-20, after PR #961 shipped directional networking on the rolling
model ahead of this work:

The order is:

1. PRs #961 and #962 land: directional networking and its backend validation,
   on the rolling wire model, version-gated to `0.8`. **Done.**
2. Port the same fields into `mxc_config_contract::dev` and its adapters —
   `network.egress`, `network.ingress`, and
   `processContainer.network.allowedProxyPeer`. **This is a prerequisite, not
   an option:** publishing a `0.8.0-alpha` contract that cannot express a
   feature the same version ships to customers would be incoherent. **Done, in
   PR #968 rather than separately:** a review of that pull request identified
   the same gap, so the port landed there alongside a `NonEmptyVec` primitive
   that restores the shipped schema's `minItems` constraint on a rule's `to`
   and `ports`.
3. Land Phase 6, so exact development artifacts derive from the contract crate.
   **Done in PR #968.**
4. Publish `0.8.0-alpha`. **Done by the legacy rolling stack in PR #996 and
   released under annotated tag `v0.8.0` at `7dac1a95`.** The tagged stable
   schema is immutable blob `78791e8ad9adcd8b96a632fc1d9471153a9fe20b`;
   Phase 6.5 reconstructs the exact Rust contract but does not regenerate or
   rewrite that artifact.
5. Move remaining rolling and exact development work to `0.9.0-alpha`.
   **Rolling development moved in PR #996; exact development moved in Phase
   6.5, PR #1027.** The contract artifact suffix is `-alpha`; `-dev` remains
   reserved for the rolling family being retired.

#### Published `0.8.0-alpha` scope: stable candidate only

**Decided 2026-08-20: neither state-aware nor experimental enters stable
`0.8.0-alpha`.** The original target-contract rule therefore stands unchanged,
and design-note decision 5 is answered "none" while its question 3 is answered
"no". `published::v0_8_0_alpha` is the stable-candidate one-shot surface only:
no `experimental`, no `phase`, no `sandboxId`, no `correlationVector`, and the
containment enum narrowed to `process`, `processcontainer` with its
`appcontainer` alias, `lxc`, `bubblewrap`, and `seatbelt` with its
`macos_sandbox` alias.

The directional network fields ported in step 2 are unaffected: `network.egress`,
`network.ingress`, and `processContainer.network.allowedProxyPeer` are all
stable-surface fields, so they publish with the rest of the one-shot contract.

The corpus cost is small and entirely predictable. Of the thirty configs
declaring `0.8.0-alpha` today, twenty-four are stable-candidate only and stay;
six move to `0.9.0-alpha`, and they are the same six documents — every one is a
WSLC config that uses both the development-only `wslc` containment and an
`experimental` block:

```text
wslc_denied_dotdot_alias.json        wslc_most_specific_denied_parent.json
wslc_denied_masking.json             wslc_port_mapping_multiple.json
wslc_filesystem_object.json          wslc_port_mapping_tcp.json
```

No corpus config declares `0.8.0-alpha` together with a `phase`, so excluding
state-aware costs nothing in the corpus. It does, however, decide where
state-aware lives: with no published version to declare, state-aware requests
move from the `0.6.0-alpha` they hard-code today onto `0.9.0-alpha`, so the
lifecycle ships only against a development contract until it is promoted. That
is the intended consequence of the Phase 11 rule, recorded here as a choice.

#### Resolved schedule consequences

- The released schema version remains the literal `0.8.0-alpha`; product
  release tag `v0.8.0` does not change the config-version spelling.
- `schemas/schema-version.json` and the rolling parser/SDK moved to the v0.9
  development line in PR #996.
- The exact registry marks v0.8 published and v0.9 development.
- `ProcessContainerCapability` is frozen into the v0.8 Rust contract as a
  deliberate parse-time tightening; v0.6/v0.7 retain conversion-time rejection.
- Per-version policy-builder forking remains deferred until that builder exists.
- State-aware producer migration to v0.9 remains Phase 8 work.
- Phase 10 retains only work not already shipped by the rolling v0.8 networking
  implementation, notably the IsolationSession acknowledgment redesign and
  published-version translation.

## 5. Appendices

### Appendix A: Experimental fields in published contracts

> **Status: recorded discussion, not part of the plan of record.**
>
> The plan of record excludes `experimental` from published contracts,
> including the planned v0.9 publication. Do not implement the alternative in
> this section until the requirement is ratified and the normative plan is
> updated.
>
> **Update, 2026-08-20.** The revised publication sequence brought this
> forward, and it was decided against: stable `0.8.0-alpha` contains neither
> experimental nor state-aware fields, answering decision 5 as "none" and
> question 3 as "no". This section remains a recorded discussion for a future
> publication. See the decision record in section 4.

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
version N accepts:   experimental.foo
version N+1 accepts: foo
```

The two immutable contract modules would retain their respective paths while
their mutable adapters normalize both into the same canonical runtime field:

```text
vN experimental.foo --\
                       +--> CanonicalRequest.foo
vN+1 foo --------------/
```

This works naturally with exact version dispatch and avoids putting a
version-sensitive alias on one rolling wire type. The old path remains accepted
only while its published contract remains supported; the newer contract may
reject it and accept only the promoted top-level path.

#### Impact if adopted

The following parts of the current plan would need revision:

- Remove the goal and target-contract rule that published contracts never
  contain `experimental`.
- Reconstruct each historical version from what that version actually
  published. Existing v0.6/v0.7/v0.8 contracts remain unchanged; a future
  publication could include only explicitly selected experimental fields.
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

#### Cost and trade-off

An experimental field included in a published contract loses shape-level
mutability for that version. Adding, removing, renaming, or restructuring one
of its fields requires a new config version even though the feature remains
experimental. This is the principal cost of making experimental structures
closed and publishable.

The benefit is deterministic parsing: an experimental typo or unsupported
field is rejected rather than silently ignored, and a published version's
accepted JSON shape cannot change underneath its users.

#### Decisions required before adoption

1. Does a published contract structurally accept its experimental fields even
   when `--experimental` is absent, with the flag controlling execution only?
2. If an experimental field is present without the execution opt-in, should MXC
   reject the request or preserve the current parse-and-ignore behavior?
3. Can state-aware request shapes be included in a published contract, or does
   this requirement initially apply only to one-shot experimental fields?
4. When a feature is promoted, does the new contract reject its old
   `experimental` path immediately, or provide a version-scoped transition
   spelling?
5. Which experimental fields, if any, should be selected for the next
   publication?

### Appendix B: Phase 6.5 implementation record

#### Phase 6.5 final implementation

Phase 6.5 merged in PR #1027. It:

- reconstructs `published/v0_8_0_alpha` from the tagged stable schema using the
  same policy as v0.6/v0.7: exact required version, closed objects, explicit
  null rejection, string-only enums, local value constraints, and preservation
  only of explicit compatibility aliases
- adds the frozen `config_contract_adapters::v0_8` adapter without changing the
  tagged stable schema or generating a published TypeScript oracle
- renames the mutable development contract to `0.9.0-alpha`, moving its tests,
  fixtures, and adapters to the v0.9 line
- registers v0.8 as published and v0.9 as development, and commits the generated
  v0.9 exact schema and TypeScript oracle
- covers cross-version boundaries and the published adapter's directional
  conversion, including `egress`, `ingress`, `runtimeConfig`, and
  `allowedProxyPeer`
- preserves the released v0.8 schema byte-for-byte and keeps
  `mxc_schema_gen`/`check-contract-codegen.js` scoped to mutable development
  artifacts

Two consequences of the rebase are worth recording, because both were found by
a failing test rather than by inspection. The 0.8 test suite inherited from
#968 assumed `0.8` was still the development contract, so it listed
`"experimental": {}` as an acceptable empty optional object; under publication
that document must be rejected. And the adapter and one-shot tests added to
#968 for `runtimeConfig` carried `0.8.0-alpha` version markers into the renamed
`0.9` suites, where the exact version marker rejects them. Both are the same
class of error: a version-specific test moving between contracts without its
version string moving with it.

#### Phase 6.5 completion status

Merged in PR #1027 as commit `bae778e1`.

| Area | Final state |
| --- | --- |
| v0.8 release identity | Annotated tag `v0.8.0` resolves to `7dac1a95`; stable schema blob `78791e8ad9adcd8b96a632fc1d9471153a9fe20b` is preserved byte-for-byte |
| Published v0.8 contract | Reconstructed with the v0.6/v0.7 bootstrap-tightening policy and explicit compatibility aliases; no experimental or state-aware surface |
| Published v0.8 adapter | Exhaustive stable one-shot mapping, including legacy and directional network families, runtime proxy configuration, and ProcessContainer proxy identity |
| Development rollover | Exact development contract, adapters, fixtures, schema, and TypeScript oracle moved to `0.9.0-alpha` |
| Generated artifacts | Only rolling `0.9.0-dev` and exact development `0.9.0-alpha` artifacts are regenerated; published v0.8 artifacts are immutable |
| Cross-version coverage | Directional networking and runtime configuration are introduced at v0.8; experimental containment and state-aware roots are introduced at v0.9 |
| Published contract coverage | All v0.8 fixtures are discovered automatically; version, null, command, LXC, proxy, capability, alias, enum, experimental, and state-aware boundaries are covered |
| Review remediation | Stable-schema rewrite, obsolete v0.8 TypeScript generation, validation-claim drift, documentation errors, fixture omissions, and the v0.8 capability boundary assertion are resolved |

General published-contract digest/freeze automation remains part of Phase 11
rather than Phase 6.5 work.

#### The adapter's no-wildcard rule is enforced by the compiler

Phase 3 requires adapters to destructure every contract field explicitly, with
no catch-all `..`. Mutation testing during Phase 6.5 showed this rule is
stronger than the plan claims, and worth stating precisely:

- **A dropped field cannot compile.** Removing a field's mapping leaves its
  binding unused, and the crate denies warnings, so `unused variable: except`
  fails the build.
- **A swapped field usually cannot compile either.** Mapping `allow` from the
  `deny` binding produces `use of moved value: deny`.
- **A misrouted *value* compiles and must be caught by tests.** Changing
  `NetworkAction::Deny => wire::NetworkAction::Allow` builds cleanly; it failed
  four adapter tests, and `NetworkProtocol::Udp => Tcp` failed three.

So adapter tests are not guarding against omission — the compiler already does
that. They guard against a mapping that points at the wrong value, which is
exactly what the wire-equivalence comparison detects best. Write them for enum
arms and for fields whose types are interchangeable, and do not pad them with
presence assertions the build already guarantees.

### Appendix C: Phase 10 detailed implementation plan

Phase 10 removes the legacy Network vocabulary from v0.9 only. Directional
networking already shipped through the rolling v0.8 stack and is present in the
published v0.8 and development v0.9 exact contracts; this phase makes that
directional representation the sole v0.9 surface while preserving every
published v0.6/v0.7/v0.8 contract.

The removed v0.9 fields are:

```text
network.defaultPolicy
network.enforcementMode
network.allowedHosts
network.blockedHosts
network.allowLocalNetwork
network.proxy
```

Their behavior must move to directional egress and ingress, runtime proxy
configuration, ProcessContainer proxy-peer identity, the dedicated
IsolationSession acknowledgment, or an explicit migration error. No adapter,
builder, SDK, or backend may silently discard a removed field.

| # | Work item | Primary files or surfaces | Change | Completion condition |
| --- | --- | --- | --- | --- |
| 1 | Require authoritative exact dispatch | Phase 9 parser router | Dependency | Declared v0.6/v0.7/v0.8 requests already dispatch through their immutable contracts before v0.9 removes syntax |
| 2 | Design the IsolationSession acknowledgment | Contract, SDKs, backend validation, docs | Addition and change | A dedicated field and type honestly acknowledge unrestricted networking without borrowing unenforceable Network policy values |
| 3 | Remove legacy fields from the v0.9 one-shot contract | `mxc_config_contract::dev::network`, `dev::one_shot` | Deletion and change | No v0.9 one-shot request can structurally express any removed field |
| 4 | Remove legacy fields from v0.9 state-aware roots | `dev::state_aware::exec`, WSLC provision, IsolationSession provision | Deletion and change | Exec and provision expose only directional policy, runtime proxy, or the dedicated acknowledgment |
| 5 | Replace the current IsolationSession marker pair | IsolationSession provision contract | Deletion and addition | The exact `defaultPolicy=allow` plus `allowLocalNetwork=true` pair is gone and the acknowledgment is required instead |
| 6 | Regenerate exact v0.9 artifacts | Exact development schema and generated TypeScript oracle | Generated change | Both artifacts expose no legacy v0.9 fields and include the acknowledgment |
| 7 | Add a recursive publication guard | Contract schema tests and `check-contract-codegen.js` | Test addition | Publication fails if a removed field remains reachable from any v0.9 request root |
| 8 | Update v0.9 development adapters | Development common, one-shot, and state-aware adapters | Change and deletion | Directional fields, runtime proxy, and acknowledgment map exhaustively into the canonical runtime representation |
| 9 | Preserve published-version adapters | v0.6, v0.7, and v0.8 adapters | Change only when runtime types require it | Published legacy syntax remains accepted and translates without loss |
| 10 | Finalize the canonical runtime network model | `wxc_common::models`, wire compatibility types, network parser | Change and deletion | Backend-facing policy is independent of whether input used published legacy or v0.9 directional syntax |
| 11 | Preserve field-presence information | `ContainerPolicy`, adapters, normalization | Change and tests | Network, network-mode, runtime-proxy, and UI presence remain distinguishable from explicit defaults |
| 12 | Add explicit migration diagnostics | Exact parser and contract error rendering | Addition | Removed v0.9 fields produce actionable migration errors where practical |
| 13 | Move proxy configuration to its v0.9 location | Contract, adapters, runtime configuration, SDKs | Change and deletion | Cooperative runtime proxy behavior uses `runtimeConfig.networkProxy`; `network.proxy` is unreachable in v0.9 |
| 14 | Update IsolationSession validation | Shared policy validation plus one-shot and state-aware runners | Change | Provision and one-shot consume the acknowledgment; later phases reject redeclaration |
| 15 | Update WSLC policy handling | WSLC backend, state-aware normalization and dispatch, SDKs | Change | Provision uses directional posture and exec uses runtime proxy without restating immutable network mode |
| 16 | Update ProcessContainer policy mapping | AppContainer and BaseContainer configuration and validation | Change | Directional egress, ingress, host loopback, runtime proxy, and peer identity remain correctly lowered |
| 17 | Update Seatbelt, Bubblewrap, and LXC translations | Backend policy builders and validators | Change | Each backend receives canonical directional policy while published legacy inputs retain behavior through adapters |
| 18 | Update per-version Rust policy builders | Test-only builders introduced in Phase 7.3 | Change and addition | Published builders emit their frozen syntax and the v0.9 builder emits directional-only syntax |
| 19 | Update the Node SDK surface | Public types, one-shot builder, state-aware types, helpers, tests | Change and deletion | v0.9 emitters cannot generate legacy fields and expose runtime proxy plus acknowledgment |
| 20 | Update the C# SDK surface | Policy POCOs, lifecycle types, converters, tests | Change and deletion | C# emits the same v0.9 shape and acknowledgment as Rust and Node |
| 21 | Confirm FFI behavior | Rust FFI and managed parity gates | Tests and possible change | No ABI change occurs unless required; JSON crossing FFI follows the selected exact version builder |
| 22 | Migrate every v0.9 configuration | Configs, examples, exact fixtures, state-aware envelopes | Change | No document declaring v0.9 uses legacy Network syntax |
| 23 | Update invalid and migration fixtures | Contract fixtures and parser tests | Addition and change | Every removed field is rejected on each applicable v0.9 root while published acceptance remains pinned |
| 24 | Add adapter and runtime equivalence tests | Versioned adapters and parser tests | Addition | Equivalent published-legacy and v0.9-directional policies normalize to equivalent runtime behavior |
| 25 | Update backend unit and integration tests | Rust backend crates | Addition and change | Every backend proves directional enforcement, presence handling, proxy behavior, and acknowledgment validation |
| 26 | Update SDK tests | Node and C# unit and integration suites | Addition and change | Serialization and lifecycle tests prove SDKs emit no legacy v0.9 fields |
| 27 | Update applicable E2E tests | Backend validation scripts and `wxc_e2e_tests` | Change | Representative one-shot and state-aware v0.9 directional requests execute on each applicable platform |
| 28 | Update documentation | Schema, networking specification, backend docs, SDK READMEs, examples, this plan | Change and deletion | All v0.9 guidance is directional-only and explains acknowledgment and migration |
| 29 | Run codegen and versioning gates | Contract and SDK generation scripts | Execution | Exact artifacts match Rust and published artifacts remain immutable |
| 30 | Run the cross-platform quality gate | Rust, Node, C#, backend and E2E suites | Execution | Format, compile, lint, unit, SDK, contract, and applicable platform tests all pass |

#### Phase 10 delivery subphases

The work remains conceptually divided into four subphases, but the adopted PR
plan uses two PRs to limit review latency without creating an inconsistent
intermediate contract.

| Subphase | Scope | PR boundary |
| --- | --- | --- |
| 10a | Add the dedicated IsolationSession acknowledgment and scoped runtime preparation additively while legacy v0.9 input remains accepted | Implemented on the phase10a branch; PR pending |
| 10b | Remove legacy fields from the v0.9 contract, update generated artifacts, adapters, policy builders, and migration diagnostics | Implemented in `8722f343` |
| 10c | Update backend validation and enforcement plus Rust, Node, C#, and FFI producer surfaces | Implemented in `8722f343` |
| 10d | Migrate the corpus, add publication guards, update documentation, and run the cross-platform quality gate | Implemented in `8722f343`; native/live acceptance pending |

PR 7 is deliberately additive and leaves all existing requests valid. PR 8 is
the atomic cutover: contract removal, producer migration, generated artifacts,
backend behavior, tests, and documentation land together so no merged tree
declares v0.9 fields that its SDKs still emit or removes fields its corpus still
uses.

#### Phase 10b implementation decision: WSLC directional posture

The user approved explicit unrestricted bridged networking for exact v0.9
after the implementation inventory confirmed that WSLC has no independent
ingress or host-loopback restriction primitive.

| Mode | Egress default | Ingress default | Host loopback |
| --- | --- | --- | --- |
| Isolated | deny | deny | deny |
| Bridged, unrestricted | allow | allow | allow |

Reject mixed postures and per-host rules rather than implying enforcement
that the SDK cannot supply. In particular, egress allow with omitted ingress
is not a shorthand for unrestricted networking: omitted directional values
default to deny, so all three allows must be explicit for a bridged request.
An allow declaration does not create port forwarding or guarantee reachability
through NAT. Published v0.6/v0.7/v0.8 contracts and their legacy runtime
behavior remain unchanged.

State-aware runtime-proxy-only exec requests inherit the provisioned posture
and must not synthesize a network-mode change. The runtime URL must remain
guest-routable; do not apply another backend's host-loopback-only endpoint rule
to WSLC.

#### Phase 10b implementation decision: NanVix network limits

The user approved constrained v0.9 NanVix networking after review found that
the old host-network flag and IPv4 filter do not implement arbitrary
directional policies. Support isolated deny/deny/deny and explicitly
unrestricted allow/allow/allow; reject mixed postures and directional egress
rules with a clear unsupported-policy error. The host-network switch includes
bind/listen capabilities, and the legacy allowlist has implicit DNS exceptions,
so advertising full directional filtering would be misleading.

Wire the validated mode to actual host-network enablement, not only capability
flags. Keep positive network fixtures working with their explicit unrestricted
declarations and retain negative isolation coverage. Unsupported filtering
gets explicit rejection coverage. The legacy filter implementation remains for
compatibility/reference; published contracts are not changed or down-versioned
to hide the new v0.9 boundary.

#### Phase 10a design decisions

The eight decisions below are adopted. Concrete implementation details must
stay within these boundaries; a material departure requires an explicit
revision rather than silently reopening the design.

##### Decision 1: acknowledgment location

**Adopted 2026-09-08:** use Option A, the backend-specific experimental
location:

| Surface | Acknowledgment path |
| --- | --- |
| One-shot | `experimental.isolation_session.acknowledgeUnrestrictedNetwork` |
| State-aware provision | `experimental.isolation_session.provision.acknowledgeUnrestrictedNetwork` |

The field name and value type are adopted in Decision 2 below. Add a closed
IsolationSession section to the one-shot experimental contract and keep it
distinct from the state-aware provision shape, so `appId` remains
provision-only. Later lifecycle phases do not accept the acknowledgment.

Do not introduce a shared acknowledgment section or place the field in
`network`. Keeping it under `experimental` also keeps it outside published
stable contracts while IsolationSession remains experimental. This decision
does not settle coexistence rules, runtime representation, SDK compatibility,
or policy hashing.

##### Decision 2: acknowledgment name and value

**Adopted 2026-09-08:** use Option A, the affirmative action spelling
`acknowledgeUnrestrictedNetwork` with a true-only value:

```json
{
  "acknowledgeUnrestrictedNetwork": true
}
```

This object fragment belongs at the backend-specific locations chosen in
Decision 1; it is not a new top-level request section. Model the wire field
with the existing contract `True` marker, wrapped in `OptionalField` during
10a. When supplied, only the JSON boolean `true` is valid; reject `false`,
`null`, string spellings, and numeric values structurally.

This is acknowledgment, not a Boolean network on/off control. Omission does
not implicitly acknowledge unrestricted networking; it leaves the existing
legacy acknowledgment path available during the additive phase. A supplied
acknowledgment never overrides an authored restriction. Coexistence is adopted
in Decision 3 below; Decision 4 specifies conditional-requirement enforcement
and diagnostics.

##### Decision 3: transitional coexistence

**Adopted 2026-09-08:** use Option A, accepting consistent redundancy while
preserving the distinction between an absent and an explicitly empty network
section.

Assuming the rest of the request is valid, apply this matrix during 10a:

| Acknowledgment input | Result |
| --- | --- |
| Existing valid legacy acknowledgment only | Accept unchanged |
| New true-only acknowledgment with no network section | Accept |
| New acknowledgment plus the consistent legacy acknowledgment | Accept |
| New acknowledgment plus `network: {}` | Reject |
| New acknowledgment plus incompatible network restrictions or proxy configuration | Reject |
| Neither acknowledgment form | Reject |

"Legacy acknowledgment" means a form already accepted on the relevant
surface. Do not widen the closed state-aware provision network shape merely
because the one-shot surface accepts additional semantically neutral legacy
fields. Invalid acknowledgment values remain structural errors under
Decision 2, even when the legacy acknowledgment is also present.

Consistent redundancy lets a caller add the acknowledgment before removing
legacy fields, but only on an executor that supports the new field; it does
not make that field acceptable to older closed exact contracts.
Do not treat an explicit empty network section as an omitted section or erase
an authored restriction to make a request pass. SDK default synthesis must not
be confused with the caller's original omission.

This decision defines acceptance and rejection, not the layer or diagnostic
used for each rejection; those are adopted in Decision 4 below.

##### Decision 4: validation ownership and diagnostics

**Adopted 2026-09-08:** use Option A for 10a, preserving the existing validation
boundaries rather than moving acknowledgment enforcement wholesale to an
earlier or later layer.

For state-aware IsolationSession provision, the exact contract conditionally
requires the legacy acknowledgment or the new field. Supplying neither
remains a structural `malformed_request` failure with source-aware diagnostics.
Enforce the condition in the exact contract's typed validation/construction,
not only in the CLI, and keep generated schema acceptance aligned. The
requirement is at least one valid form, not exactly one: Decision 3 permits
consistent redundancy.

For one-shot execution, validate the new field's shape during exact parsing,
but keep acknowledgment/policy enforcement in the existing common/backend
validation path. Checks already performed before dispatch stay there;
remaining backend-policy checks retain their established order and reporting.
Do not change error categories or stdout/stderr routing for existing inputs
as an incidental consequence of adding the alternative acknowledgment.
Diagnostic wording may explain the new alternative.

Invalid supplied acknowledgment values remain structural failures on both
surfaces under Decision 2. Preserve source paths and coordinates where source
text is available, and do not reintroduce successful-request source retention
or raw-payload reparsing. Typed builders must enforce the same chosen
requirements rather than bypassing checks that happen only during Serde input.

Backend guards remain for lower-level callers. Broader migration of static
backend-policy checks into exact contracts is deferred, not implicitly included
in this choice; it can be reconsidered separately.

##### Decision 5: runtime representation and preparation scope

**Adopted 2026-09-08:** use Option A, keeping the existing common policy model
and passing the typed acknowledgment separately to IsolationSession policy
validation.

Carry acknowledgment in the backend-specific runtime configuration for
one-shot execution or state-aware provision. Both paths supply it explicitly
to the shared IsolationSession validator. Preserve the current legacy
acknowledgment path and accept the new form only under the absence/conflict
rules adopted in Decision 3, at the validation boundaries adopted in Decision 4.

Use existing presence information to distinguish authored policy from
parser-generated defaults. In particular, an acknowledgment-only v0.9 request
can contain implicit directional deny defaults in `ContainerPolicy` despite
having no authored network section. Do not manufacture legacy `allow` fields
to satisfy the old validator, clear an explicit policy to make the new form
pass, or treat `network: {}` as omission. Runtime proxy and other independently
supplied network settings must not be overlooked merely because the `network`
section was absent.

Common normalization and other backends retain their existing behavior.
There is no new general network-policy model or separately stored normalized
IsolationSession intent view in 10a. Runtime preparation is limited to typed
acknowledgment transport and correct presence handling; the broader
network-model migration stays in the atomic 10b-10d change.

The generic policy fields alone do not describe effective IsolationSession
networking for the new form: the backend and acknowledgment must also be
considered. Policy-identity projection and old/new hash behavior are explicitly
adopted in Decision 8, not an accidental consequence of serializing these
defaults or adding the acknowledgment field.

##### Decision 6: SDK compatibility boundary

**Adopted 2026-09-08:** use Option B. Preserve shared SDK source compatibility,
but permit narrowly scoped, documented source changes to IsolationSession's
experimental API. This permits a break where useful; it does not require one.

The planning assumption is that the two Phase 10 PRs merge at roughly the
same time. Design the intended post-cutover acknowledgment API in 10a rather
than introducing a temporary SDK shape that must change again in 10b-10d.
Coordinate SDK release/adoption across those PRs while keeping each PR valid
at its own boundary: existing valid native JSON requests remain accepted in
10a, and the second PR performs the planned legacy-wire removal.

The source-compatibility exception applies to code depending on
IsolationSession-specific experimental types or members, including explicit
pattern matches mentioning that backend variant. It does not authorize
breaking shared `SandboxPolicy` or network types, adding mandatory parameters
to general build/spawn/provision APIs, or changing the WSLC and Windows Sandbox
APIs merely to carry IsolationSession's acknowledgment.

Identify the affected SDK symbols and document their migrations. The SDK
construction strategy is adopted in Decision 7 below. Choosing an experimental
backend must not implicitly supply acknowledgment, and this source-compatibility
choice does not override the accepted wire rules, validation boundaries, or
backend behavior.

Schema-version rollover remains a separate concern: this choice does not make
an explicit v0.9 IsolationSession request valid after Phase 11 publishes the
stable-only v0.9 contract and moves experimental requests to v0.10 development.

##### Decision 7: SDK entry points and omission handling

**Adopted 2026-09-08:** use Option A, extending existing authoring/configuration
surfaces so acknowledgment is explicit before serialization and normalization.
Keep general execution/lifecycle entry points and shared SDK usage intact,
using the scoped IsolationSession API freedom adopted in Decision 6.

| Surface | 10a construction path |
| --- | --- |
| Node state-aware | Expose acknowledgment in IsolationSession provision options without requiring the legacy network pair for the new form |
| Node one-shot | Expose the backend-specific acknowledgment on the explicit configuration path used by `spawnSandboxFromConfig` |
| C# state-aware | Allow acknowledgment-only `IsolationSessionProvisionOptions` to be constructed before envelope generation |
| Rust state-aware | Carry the new field through the existing JSON entry point; no public signature change is required just to express it |
| Native one-shot | Accept the new backend-specific field through the exact contract and adapter |

The current public Rust and C# one-shot run/spawn APIs do not support
IsolationSession. Do not add that capability incidentally in 10a. The new typed
SDK acknowledgment form should target the intended post-cutover API, rather
than requiring a temporary legacy-network argument. Native legacy-request
acceptance during 10a remains governed by Decision 3.

Builders must retain authored presence until the acknowledgment-aware emission
decision. With acknowledgment and an originally omitted network section, omit
the network key entirely: do not emit `null`, `{}`, or a synthesized deny.
Explicit empty sections, restrictions, proxies, and consistent legacy
acknowledgment data still follow Decisions 3 and 4; do not erase supplied policy
to make a request pass.

Setting a property on unprocessed options is permitted. Do not add an
acknowledgment repair setter to an already-normalized request, where the
distinction between original omission and authored defaults may be lost.
Small factories may wrap the normal construction path where they improve a
language's ergonomics, but no parallel generation pipeline or new mandatory
builder framework is required.

The resulting SDK output must continue to satisfy the exact contract, generated
wire-type conformance, and end-to-end omission/presence cases. Policy-identity
projection is adopted in Decision 8 below.

##### Decision 8: policy identity and hashing

**Adopted 2026-09-08:** use Option A, preserving existing hashes while
explicitly distinguishing acknowledgment-bearing requests and the relevant
presence information. This maintains existing audit/telemetry plumbing; it is
not a new hashing system, runtime policy model, or authorization mechanism.

Keep existing legacy-request and other-backend identities unchanged. When the
new acknowledgment is present, add an explicit IsolationSession-scoped
projection for the acknowledgment and the source-presence facts needed to
distinguish authored policy from implicit defaults. These include
`network_specified`, `network_mode_specified`, and
`runtime_network_proxy_specified`; classify meaningful presence information
explicitly rather than relying only on blanket policy serialization.
Do not remove `serde(skip)` from common-policy flags and thereby change every
backend's hash.

In particular, an omitted network section, `network: {}`, and an explicitly
authored directional deny can have the same normalized policy values but
different acknowledgment semantics. For requests that reach hashing, the
new projection must not collapse acknowledgment-only input with an authored
empty or restrictive policy merely because those presence flags were skipped
by the existing serialization.

With all other projected inputs held constant, legacy-only, new-only, and
both-consistent acknowledgment forms intentionally have distinct identities.
Preserve existing non-acknowledgment distinctions, including absent versus
present-empty state-aware provision configuration and `appId` presence/values.
No equality is promised across schema versions, phases, or differing container
names, working directories, timeouts, or other identity-bearing input.

Describe the result as policy/acknowledgment configuration identity, not a
guarantee that every behaviorally equivalent spelling hashes identically.
Hashing may precede backend validation and can describe an attempt that is
subsequently rejected. It must not decide authorization, invoke backend
validation early, change diagnostic ordering, or canonicalize away an authored
restriction. Credentials and sandbox IDs remain excluded.

Apply this only in the hash projection: do not mutate the runtime request,
synthesize legacy wire grants, introduce a stored normalized network-intent
view, or perform a general identity-contract migration. Add regressions for
unchanged legacy hashes, distinct new/combined forms, relevant presence
differences, and continued exclusion of secret-bearing data and sandbox IDs.
