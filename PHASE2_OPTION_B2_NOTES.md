# Phase 2 — Option B2: dedicated well-typed wire model

**Approach:** a new `wxc_common::wire` module defines a dedicated, well-typed
wire model (`MxcConfig` + nested types) that is the single source of truth for
the config shape. Real `enum`s for closed value sets, `#[serde(rename_all =
"camelCase")]`, `#[serde(deny_unknown_fields)]`, and `///` doc-comments. In a
full integration these types replace the `Raw*` structs as the parse target;
here they sit behind the `schema-gen` feature for comparison.

## How to regenerate
```
cargo run -p mxc_schema_gen -- schemas/dev/mxc-config.schema.0.8.0-dev.generated.json
```

## Result (generated schema)
- ~961 lines.
- **`title: "MxcConfig"`**, definitions named `Containment`, `Process`,
  `Filesystem`, … — clean public names, no internal identifiers leaked.
- **`containment` is a real closed value set** (a `Containment` enum: `process`,
  `processcontainer`, `vm`, … each documented).
- **root + every nested object `additionalProperties: false`** (19 closed
  objects) — the schema enforces the closed contract on its own, matching the
  parser.
- **115 descriptions** — one per field/type, straight from doc-comments.
- **19 enums** — every closed value set (network policy, clipboard, isolation
  level, protocol, …) is constrained.

## Pros
- **Faithful, strict schema** — enums, closed objects, descriptions. As good as
  (or better than) the hand-authored schema, with zero hand-authored JSON.
- **Clean published contract** — public type names, no `Raw*` leakage.
- **Schema concerns isolated** from the permissive parse layer; the model reads
  as documentation of the wire format.
- The model is independently useful (could become the parse target, and the SDK
  TS types generate from this schema).

## Cons
- **Duplicates the wire shape** — until it *replaces* `Raw*` as the parse target,
  there are two definitions (the new model + the existing `Raw*`). Full
  integration means rewiring deserialization + the `Raw* → domain` conversion to
  go through these types, and keeping them in sync until then.
- **More code to write up front** (~400 lines of typed model vs ~18 derive
  lines).
- Cross-field rules (single-backend `allOf`, phase-scoping) still live in the
  parser, not the generated schema (same as B1 — acceptable; parser is the
  boundary).

## Verdict vs B1
B2 produces a schema essentially at parity with today's hand-curated one
(enums, closed objects, 115 vs 85 descriptions) with no hand-authored JSON,
at the cost of writing+maintaining a dedicated model and eventually rewiring the
parse target. B1 is a far smaller diff but yields a materially looser schema
(stringly containment, all-nullable, open root, leaked `Raw*` names).
