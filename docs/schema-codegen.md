# Schema codegen

MXC configuration contracts are authored in Rust. Published contracts live
under `src/core/mxc_config_contract/src/published/`; the one mutable
development contract lives under `src/core/mxc_config_contract/src/dev/`.
JSON Schema, TypeScript wire types, and machine-readable lifecycle metadata are
generated from those Rust sources.

The neutral `wxc_common::wire` types are adapter/runtime normalization types.
They are not a request contract, are never a whole-request deserialization
target, and do not generate artifacts.

## Generated artifacts

| Artifact | Rust source | Gate |
| --- | --- | --- |
| `schemas/dev/mxc-config.schema.0.10.0-alpha.json` | Exact development contract | `check-contract-codegen.js` |
| `sdk/node/src/generated/v0_10_0_alpha/wire.ts` | Exact development schema | `check-contract-codegen.js` and Node conformance tests |
| `schemas/contract-registry.generated.json` | `mxc_config_contract::registry::CONTRACTS` | `check-contract-freeze.js` |

Published schemas under `schemas/stable/` are immutable. Their normalized
SHA-256 digests and associated Rust/adapter/builder/fixture paths are frozen in
the Rust registry.

## Regenerating the development artifacts

From the repository root:

```text
cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schema --version 0.10.0-alpha --out schemas/dev/mxc-config.schema.0.10.0-alpha.json
cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- types --version 0.10.0-alpha --out sdk/node/src/generated/v0_10_0_alpha/wire.ts
cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- registry
```

`schema` and `types` require an exact registered development version. Published
contract generation is refused so a released artifact cannot be overwritten by
ordinary codegen. There is no rolling or versionless generation mode.

## Publication

Preview publication without writing:

```text
cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- publish --version 0.10.0-alpha --next-dev 0.11.0-alpha --dry-run
```

The publication profile is Rust-authored beside the development contract. It
selects the one-shot root and any state-aware backends that have graduated.
Fields or backends that still require experimental authorization are excluded.

After review, run the command without `--dry-run`. It writes only the proposed
stable schema and reports its normalized SHA-256. The publication change must
then:

1. Copy the selected contract into an immutable published Rust module.
2. Freeze its adapter, builder, and independent fixtures.
3. Record the published status and schema digest in `registry::CONTRACTS`.
4. Add the next exact development version and regenerate its schema/types.
5. Regenerate `schemas/contract-registry.generated.json`.

## Validation

```text
node scripts/versioning/check-contract-codegen.js
node scripts/versioning/check-contract-freeze.js --base-ref <integration-ref>
node scripts/versioning/validate-configs.js
```

`check-contract-codegen.js` regenerates every registered development artifact
and compares it with the committed file. `check-contract-freeze.js` verifies
published identities, fixtures, digests, and generated registry metadata
against the merge base. `validate-configs.js` reads accepted versions and
schema paths directly from the generated registry.

The Node SDK's one-shot and state-aware conformance tests import the exact
versioned TypeScript artifact. A Rust contract change that is not reflected in
the handwritten SDK types therefore fails TypeScript compilation.
