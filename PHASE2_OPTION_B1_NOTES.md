# Phase 2 — Option B1: decorate the existing `Raw*` structs

**Approach:** add cfg-gated `#[derive(schemars::JsonSchema)]` to the existing
permissive `Raw*` deserialization structs in `wxc_common` (behind a
`schema-gen` feature, off by default), plus a `mxc_schema_gen` bin that emits
the schema. No new types; the wire types *are* the parse structs.

## How to regenerate
```
cargo run -p mxc_schema_gen -- schemas/dev/mxc-config.schema.0.8.0-dev.generated.json
```

## Result (generated schema)
- ~704 lines.
- **`containment` → `{"type":["string","null"]}`** — no enum (the `Raw` field is
  `Option<String>`). Loose.
- **67 nullable unions** — every field is `Option`, so everything serializes as
  `["T","null"]` with `default:null`. Loose.
- **Internal type names leak** — `"title": "RawConfig"`, definitions named
  `RawExperimental`, `RawFilesystem`, … (the public contract exposes our
  internal Rust identifiers).
- **5 descriptions only** — schemars pulls these from `///` doc-comments, and the
  `Raw` structs have almost none. To get the hand schema's 85 descriptions we'd
  have to write doc-comments on every `Raw` field.
- **root `additionalProperties` undefined (open)** — `Raw` has no
  `deny_unknown_fields`; the closed-root guarantee lives only in the parser
  (`reject_unknown_top_level_fields`), not the generated schema.

## Pros
- **Zero duplication.** One definition of the wire shape; the schema is a pure
  by-product, provably ≤ the parser's accepted shape.
- **Smallest diff.** ~18 one-line `cfg_attr` derives + 1 generator fn + 1 bin.
- Production parse path unchanged (feature off by default).

## Cons
- **Loose schema.** Stringly `containment`, all-nullable, open root — materially
  weaker than today's curated schema as an editor/CI artifact.
- **Leaks internal identifiers** (`RawConfig`, `Raw*`) into the published schema.
- **Couples schema concerns into the hot parse structs** (cfg_attr noise; serde
  vs schemars attribute interplay; `#[serde(flatten)]` `IgnoredAny` had to be
  `schemars(skip)`).
- Getting descriptions/enums to parity means heavily re-decorating the `Raw`
  layer — at which point it's no longer "just decorate what's there."
