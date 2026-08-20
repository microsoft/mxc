# Schema codegen

MXC currently has two generated schema families during the transition to exact
version-specific parsing:

| Artifact family | Rust source | Purpose |
| --- | --- | --- |
| Rolling legacy | `src/core/wxc_common/src/wire.rs` | Current parser, corpus validation, and public SDK conformance until exact dispatch is enabled |
| Exact `0.8.0-alpha` | `src/core/mxc_config_contract/src/dev/` | Closed mutable development contract and versioned TypeScript drift oracle |

Neither family is hand-authored. Phase 9 retires the rolling generator after
exact dispatch becomes authoritative.

## Sources of truth

`src/core/wxc_common/src/wire.rs` defines the wire model (`MxcConfig` and its
nested types) currently used by the parser. Its `experimental` block remains
permissive during the transition.

`src/core/mxc_config_contract/src/dev/` defines the exact mutable
`0.8.0-alpha` contract. Its one-shot and seven state-aware request roots are
independent closed Rust types. Constrained primitives and the `string_enum!`
and `string_marker!` macros implement `JsonSchema` so deserialization and
generated constants cannot drift.

`mxc_schema_support` owns shared integer normalization, deterministic root
rendering, and TypeScript emission without depending on either model.

## Generating

Rolling artifacts:

```text
cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schema --legacy-wire --out schemas/dev/mxc-config.schema.0.8.0-dev.json
cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- types --legacy-wire --out sdk/node/src/generated/wire.ts
```

Exact development-contract artifacts:

```text
cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schema --version 0.8.0-alpha --out schemas/dev/mxc-config.schema.0.8.0-alpha.json
cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- types --version 0.8.0-alpha --out sdk/node/src/generated/v0_8_0_alpha/wire.ts
```

`mxc_schema_gen versions --json` emits registry-driven lifecycle and artifact
metadata. Published version generation deliberately returns a Phase 11 error;
it never falls back to another model.

Both Rust model crates gate Schemars behind `schema-gen`, so normal builds do
not carry it. The exact `OptionalField<T>` schema is transparent and
non-referenceable: omitted fields remain optional while explicit `null` stays
rejected.

## Exact multi-root schema

The exact schema uses one shared `definitions` table and nested `if`/`then`
dispatch:

1. absence of `phase` selects one-shot;
2. a present `phase` selects provision, start, exec, stop, or deprovision;
3. provision additionally selects Windows Sandbox, IsolationSession, or WSLC
   by `containment`.

This structure evaluates only the relevant branch and gives substantially more
focused editor diagnostics than a bare eight-branch `oneOf`. One-shot and exec
require `process`; the other lifecycle roots do not. Every reachable object,
including all experimental objects, has `additionalProperties: false`.

The exact schema is available for authoring before runtime enforcement. Until
Phase 9, a document can validate against
`mxc-config.schema.0.8.0-alpha.json` even though the production parser still
uses the rolling wire model. The generated schema banner records this.

The CLI command-override entry point splices `process.commandLine` before exact
parsing. Therefore the exact contract and schema correctly require `process`
and a non-empty `process.commandLine`; a pre-splice policy document is not
itself contract-valid, and no relaxed schema twin is generated.

## CI gates (`Versioning Checks` job)

- **`check-schema-codegen.js`** — regenerates the schema and fails if the
  rolling committed schema differs.
- **`check-sdk-types-codegen.js`** — regenerates the rolling TypeScript oracle.
- **`check-contract-codegen.js`** — discovers development artifacts through
  `mxc_schema_gen versions --json`, regenerates both exact artifacts, validates
  valid and invalid fixtures for every concrete root with AJV, and checks a
  malformed exec request produces focused `if`/`then` diagnostics.
- **`validate-configs.js`** — validates the `tests/examples` + `tests/configs`
  corpus against the rolling schema until Phase 8 migrates it.
- **`check-schema-versions.js`** / **`check-version-sync.js`** — version-constant
  and product-version sync.

Public SDK conformance remains attached to the rolling
`sdk/node/src/generated/wire.ts` until Phase 8. The versioned
`v0_8_0_alpha/wire.ts` file must compile, but is not exported and is not yet
compared to the hand-written public SDK types.

## Deliberate exact-versus-rolling differences

| Difference | Reason |
| --- | --- |
| Eight discriminated roots instead of one permissive root | Expresses phase-specific fields and requirements |
| `process` required on one-shot and exec | Matches exact contracts and the pre-parse command splice |
| No nullable wrappers for optional fields | Exact contracts reject explicit `null` |
| `builtinTestServer` is the literal `true` | Matches its constrained deserializer |
| `appContainer` and `macos_sandbox` aliases are advertised | Exact contracts preserve these compatibility spellings |
| Experimental objects are recursively closed | Typos and unsupported fields are contract errors |

## What the rolling schema does NOT contain

Cross-field constraints — the single-backend-section rule and phase-scoping that
the hand-written schema expressed with top-level `allOf` — are **not** in the
generated schema. They are enforced by the parser (`wxc_common::config_parser`),
which is the trust boundary. The schema is an editor/CI convenience, never the
gate; the parser rejects a backend/containment mismatch regardless of what the
schema says.

## Rolling-schema equivalence to the previous hand-written schema

The generated schema replaced a hand-maintained one. Because the schema is a
convenience and not the trust boundary, equivalence is judged **behaviorally**,
not by diffing the JSON line-by-line (the encodings differ: the hand schema
inlined every object, while schemars emits a `definitions` block with `$ref`
indirection and wraps optionals as `anyOf: [{ $ref }, { "type": "null" }]`, so
the file roughly doubled in size with no change in meaning). Three lenses:

1. **Accept side** — every config in the `tests/examples` + `tests/configs`
   corpus must still validate. The `validate-configs.js` gate enforces this.
2. **Reject side** — the *effective* per-property constraints (allowed keys,
   enum value sets, `additionalProperties` open/closed, `required`) after
   resolving `$ref`s.
3. **Delegation** — constraints a JSON Schema expresses awkwardly are
   deliberately moved to the parser.

Comparing the generated schema against the prior hand-written one on lens (2):

- **Enums are identical** on every canonical path (`containment`,
  `network.defaultPolicy`, `network.enforcementMode`, `ui.clipboard`,
  `processContainer.ui.isolation`, `seatbelt.launchMethod`, port `protocol`).
- **The generated schema is stricter:** it closes the stable nested objects
  (`process`, `network`, `filesystem`, `lifecycle`, `ui`, `lxc`, `fallback`,
  `processContainer`/`.ui`, `seatbelt`) with
  `additionalProperties: false`, matching the wire model's `deny_unknown_fields`.
  The hand schema left several of these open, so the generated one catches
  nested typos the old one silently accepted.
- **The generated schema is more complete:** it documents surface the hand
  schema omitted — `processContainer.learningMode`,
  `experimental.windows_sandbox.idleTimeout` (legacy alias),
  `experimental.seatbelt` (pre-promotion alias), and the per-phase
  `isolation_session.provision` nesting.

Two reductions are intentional, each compensated by the parser:

| Dropped from the schema | Why it's safe |
| --- | --- |
| Top-level `allOf` cross-field rules (single-backend-section; `appContainer` alias note) | Semantic rules the parser enforces at runtime; the editor no longer pre-flags them, but a backend/containment mismatch is still rejected. |
| `appContainer` alias path is undocumented; `network.proxy.builtinTestServer` widened from `const: true` to `boolean` | The serde alias still parses, and `convert_wire_proxy` still rejects `builtinTestServer: false`. |

Root metadata (`$id`, `title`, `description`) is preserved: `title` comes from a
`#[schemars(title = …)]` attribute on `MxcConfig`, `description` from its doc
comment, and `$id` is injected in the post-process step of
`generate_config_schema_json` (schemars does not emit one).

Net: the generated schema is **equivalent-or-stricter** on values and structure,
**more complete** in coverage, and **less expressive only** on the cross-field
rules — gaps consciously owned by the parser. The equivalence is not a
one-time review: the codegen gate regenerates the schema from the types on every
CI run, and the corpus gate pins the accept-side behavior.

## Generated SDK types (drift oracle, Rust emitter)

The SDK's wire TypeScript types are generated too — by a **Rust emitter**, with
no third-party generator. `mxc_schema_gen types` walks the generated schema
value and `mxc_schema_support` emits the selected oracle. The rolling file is
**not public API** — it is a drift oracle. The unit test
`sdk/node/tests/unit/wire-conformance.test.ts` asserts (at `tsc` time) that the
hand-written public types in `sdk/node/src/types.ts` still conform to it, and
`check-sdk-types-codegen.js` is a CI gate (running the emitter and diffing the
committed file) that fails on drift. So a wire-model change ripples to all three
surfaces — Rust ⇄ schema ⇄ TS — and a forgotten SDK update fails CI instead of
drifting silently. The emitter handles only the JSON Schema constructs the MXC
schema uses (enums, closed/open objects, `$ref`, `anyOf [T, null]`, arrays,
named scalars, externally tagged object unions, and mutually exclusive aliases);
extending the wire model with a new construct may require teaching the emitter
about it.

The conformance check covers both SDK surfaces: `wire-conformance.test.ts` pins
the one-shot public types in `sdk/node/src/types.ts`, and
`wire-conformance-state-aware.test.ts` pins the state-aware lifecycle types in
`sdk/node/src/state-aware-types.ts` (the `Phase` enum and each phase's own wire
field set — provision is compared against its wire type, and the phases that
take no wire object must expose no backend-specific field) against the same
generated wire defs. Both share the
assertion helpers in `sdk/node/tests/unit/conformance-helpers.ts` and check
drift in both directions (public→wire and wire→public) so a new wire field the
SDK forgets to expose also fails the build. The state-aware file additionally
pins the derived key sets to their expected contents, so a mistake in the
derivation fails loudly instead of quietly making the assertions vacuous.

### Why a hand-written emitter (alternatives considered)

The generated `wire.ts` is a **drift oracle, not the public API**. The public
SDK types (`sdk/node/src/types.ts`, `sdk/node/src/state-aware-types.ts`) stay
hand-written, and the conformance test asserts they match the oracle. Two other
approaches were evaluated and rejected:

- **Generate the public API directly (generate-and-replace).** The public types
  are a *curated* surface a raw generator can't reproduce: JSDoc, the branded
  `SandboxId<C>`, and
  a per-call-phase organization that deliberately does **not** map 1:1 to the
  wire defs. Replacing them from a generator would either ship an un-ergonomic
  API or get hand-massaged anyway, and would churn the public surface (and its
  review diffs) on every wire tweak. The oracle gives identical, CI-enforced,
  bidirectional drift safety without coupling the public ergonomics to generator
  output.
- **A third-party schema→TS generator (e.g. `json-schema-to-typescript`).** It
  pulls ~15 transitive npm dependencies onto the public `MxcDependencies` feed,
  where new transitive packages 401 until manually seeded — a recurring CI/
  supply-chain cost. The in-repo emitter is a few hundred lines, has **zero
  dependencies**, and handles exactly the constructs our schema uses, giving
  exact control over the output so the conformance comparison stays precise.

Either alternative could revisit the "devs run a script and check in" workflow,
but that workflow already exists here (`mxc_schema_gen types`, enforced by the
codegen gate) — only the *oracle* is generated, not the curated public types. A
larger move (e.g. describing the config in a FlatBuffers IDL to emit both Rust
and TS) would replace the JSON config contract itself and trade away
human-authorable config files and `$schema` editor validation; out of scope
here.

## Roadmap

- The rolling wire model and the exact development contract generate separate
  committed artifacts, each guarded by codegen gates.
- The parser deserializes directly into the wire model and the `Raw*` structs
  are gone, so the schema source and the trust boundary share one definition of
  the wire shape and cannot drift.
- The rolling SDK TypeScript wire types are generated from the same wire model
  (`sdk/node/src/generated/wire.ts`, via `mxc_schema_support`),
  guarded by a conformance test plus the `check-sdk-types-codegen.js` gate, and
  the hand-maintained `*-strict.json` stable view has been retired.
