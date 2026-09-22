# Schema codegen

MXC generates artifacts from exact registered configuration contracts:

| Artifact family | Rust source | Purpose |
| --- | --- | --- |
| Exact `0.9.0-alpha` | `src/core/mxc_config_contract/src/published/v0_9_0_alpha/` | Authoritative closed published contract and versioned TypeScript oracle |
| Exact `0.10.0-alpha` | `src/core/mxc_config_contract/src/dev/` | Authoritative closed development contract and versioned TypeScript oracle |

Published schemas under `schemas/stable/` are immutable release artifacts.
`mxc_schema_gen` renders published v0.9 into temporary output so
`check-contract-codegen.js` can compare the enforcing Rust model with the
committed stable schema and TypeScript oracle. The gate also compares
pre-existing stable schemas with the merge base and validates their registry
identities.

## Sources of truth

`src/core/mxc_config_contract/src/dev/` defines the exact mutable
`0.10.0-alpha` contract. Its one-shot and seven state-aware request roots are
independent closed Rust types. Constrained primitives and the `string_enum!`
and `string_marker!` macros implement `JsonSchema` so deserialization and
generated constants cannot drift.

`src/core/mxc_config_contract/src/published/v0_9_0_alpha/` defines the exact
published v0.9 contract, including IsolationSession and WSLC one-shot and
state-aware roots. It remains renderable for verification; generation does
not make the stable artifact mutable.

`mxc_schema_support` owns shared integer normalization, deterministic root
rendering, and TypeScript emission. `mxc_schema_gen` uses those helpers for
every renderable exact contract.

`wxc_common::common_request_ir::CommonRequestIR` is the internal whole-request
normalization boundary that replaced the former deserializable
`wire::MxcConfig` root. Exact contract adapters assemble it, and it may contain
reusable nested DTOs from `wire.rs`, but it has no JSON deserialization or
schema-generation surface of its own.

## Generating

Development-contract artifacts:

```text
cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schema --version 0.10.0-alpha --out schemas/dev/mxc-config.schema.0.10.0-alpha.json
cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- types --version 0.10.0-alpha --out sdk/node/src/generated/v0_10_0_alpha/wire.ts
```

Published v0.9 verification artifacts:

```text
cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schema --version 0.9.0-alpha --out <temporary-schema>
cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- types --version 0.9.0-alpha --out <temporary-types>
```

`mxc_schema_gen versions --json` emits registry-driven lifecycle and artifact
metadata, including whether an exact model is renderable and the fixture
directory/schema-definition pair for every request root. Versioning gates use
that metadata for artifact regeneration, root validation, fixture discovery,
and state-aware backend-version checks rather than maintaining separate
per-version root tables. Published v0.9 and development v0.10 dispatch to their
own exact models. Older published versions without renderable exact models
return an explicit error; no version falls back to another model.

The exact contract crate gates Schemars behind `schema-gen`, so normal builds
do not carry it. The exact `OptionalField<T>` schema is transparent and
non-referenceable: omitted fields remain optional while explicit `null` stays
rejected.

## Exact multi-root schema

The exact schema uses one shared `definitions` table and nested `if`/`then`
dispatch:

1. absence of `phase` selects one-shot;
2. a present `phase` selects provision, start, exec, stop, or deprovision;
3. provision additionally selects a backend-specific root by `containment`
   (Windows Sandbox, IsolationSession, or WSLC in v0.10; IsolationSession or
   WSLC in published v0.9).

This structure evaluates only the relevant branch and gives more focused
editor diagnostics than a bare request-root union. One-shot and exec require
`process`; the other lifecycle roots do not. Every reachable object has
`additionalProperties: false`.

Each exact schema is both the authoring contract and the runtime contract for
its registered version. Repository config validation obtains schema paths from
`mxc_schema_gen versions --json` and selects the exact schema named by each
document's declared version.

The CLI command-override entry point splices `process.commandLine` before exact
parsing. Therefore the exact contract and schema require `process` and a
non-empty `process.commandLine`; a pre-splice policy document is not itself
contract-valid, and no relaxed schema twin is generated.

### Adding a state-aware provision containment

1. Define and export the closed provision request and containment marker under
   `src/core/mxc_config_contract/src/dev/state_aware/provision/`.
2. Add its subschema and containment discriminator to `provision_dispatch()` in
   `dev/schema.rs`, then include the root in `ROOT_NAMES`.
3. Add the root's `ContractRequestRoot` entry to the version's `request_roots`
   metadata in `src/core/mxc_config_contract/src/registry.rs`, and create
   matching valid and invalid fixture directories under
   `tests/v0_10_0_alpha/fixtures/`.
4. Regenerate the exact schema and versioned TypeScript oracle.
5. Wire the request through the exact-contract adapter and state-aware runtime
   dispatcher.

## CI gates

- `check-contract-codegen.js` discovers renderable exact artifacts through
  `mxc_schema_gen versions --json`, regenerates v0.9 and v0.10 schema and
  TypeScript outputs, validates each version's expected roots and fixture
  corpus, and protects stable schema history and published registry identities.
- `validate-configs.js` validates the repository config corpus against exact
  registered schemas discovered from the same registry command.
- `wire-conformance.test.ts` checks the Node one-shot public-to-raw v0.10
  mapping against the exact generated v0.10 oracle.
- `wire-conformance-state-aware.test.ts` checks backend-specific state-aware
  public types against the exact v0.9 and v0.10 oracles.
- `check-schema-versions.js` and `check-version-sync.js` enforce schema and
  product version synchronization.

The generated TypeScript files are drift oracles, not public SDK exports. The
public SDK types remain hand-written and are checked at TypeScript compile time.
