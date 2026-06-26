# MXC Versioning Design

## Core Concepts

### Policy = Intent

The policy (filesystem, network) expresses **what** the user wants — "block network, allow these paths." It does not specify how the OS enforces it, nor which container type to use.

### Policy Version = Config Schema Version

The `version` field in SandboxPolicy must match the MXC config
JSON version: they are the same version, tied 1:1.

When a consumer specifies a SandboxPolicy version (e.g.,
`0.4.0`), MXC creates the corresponding configuration using the
`0.4.0` schema.

```typescript
// sdk/src/types.ts
const policy: SandboxPolicy = {
  version: "0.4.0-alpha",
  filesystem: { ... },
  network: { ... },
  timeoutMs: 30000,
};
```

The config JSON carries this same version:

```json
{
  "version": "0.4.0-alpha",
  "process": { ... },
  "filesystem": { ... },
  "network": { ... }
}
```

### Versioning follows Semver

Per [semver.org](https://semver.org/):
- **Patch** (x.y.Z) — bug fixes only
- **Minor** (x.Y.0) — new features, backward compatible
- **Major** (X.0.0) — breaking changes

## Schema Shipping Model

```
mxc/schemas/
├── stable/
│   ├── mxc-config.schema.0.4.0-alpha.json
│   ├── mxc-config.schema.0.5.0-alpha.json
│   ├── mxc-config.schema.0.6.0-alpha.json
│   └── mxc-config.schema.0.7.0-alpha.json  (shipped — current stable)
└── dev/
    └── mxc-config.schema.0.8.0-dev.json    (current — work in progress)
```

The dev schema file (`mxc-config.schema.X.Y.Z-dev.json`) must define the `experimental`
section structure so that editors can validate experimental configs.

### Trust boundary vs schema defaults

Schemas in `stable/` are immutable: they document the input shape that was
promised at release. They are **not** authoritative for runtime security
defaults. `wxc-exec` is the trust boundary and may apply stricter defaults
than a stable schema declares when a security issue requires it.

For example, an older stable schema may declare
`network.defaultPolicy` defaulting to `"allow"`. The runtime may treat an
absent `network.defaultPolicy` as `block` regardless of the declared schema
version when the old default is a security bug. The older stable schema is
left unchanged so the release contract stays auditable; newer schemas
document the corrected default. Consumers that need the legacy behavior
must set the field explicitly.

### Shipped vs Experimental

Each experimental feature is a typed property under `experimental` — the same
pattern as stable features (`filesystem`, `network`) under the top-level
config. This gives editors full autocomplete and validation for experimental
configs. Today, the `--experimental` flag is a global toggle that enables all
experimental features; per-feature gating (e.g., `--experimental compartments`)
is under consideration.

**Rules:**
- **Stable section** (top) — shipped, stable, supported. Always executed.
- **Experimental section** — an object containing experimental features as
  typed properties, only applied when the experimental flag is enabled (see
  below). Each feature defines its own schema. As long as experimental code
  doesn't break what is shipped, developers are free to iterate.
- **Promotion:** When an experimental feature is ready to ship, move it from
  `experimental` to the top-level section and bump the minor version.

### Experimental Flag

The experimental flag must be supported at every layer of the stack:

**1. `wxc-exec.exe` / `lxc-exec` (Rust binaries):**
```bash
wxc-exec.exe config.json --experimental
lxc-exec config.json --experimental
# Flag order does not matter — these are equivalent:
wxc-exec.exe --experimental config.json
```

The parser **always** parses and preserves the `experimental` section regardless
of the flag; parsing is flag-independent. The `--experimental` flag only sets
`request.experimental_enabled`:
- When set, the runners apply the parsed experimental features alongside the
  stable features
- When unset, `experimental_enabled` is false and the runners **ignore** the
  parsed experimental section — no error, the features are just not applied

**2. SDK (`@microsoft/mxc-sdk`):**
```typescript
// With policy:
const pty = spawnSandbox("python app.py", policy, {
  experimental: true,
  debug: false
});

// Or with config:
const config = createConfigFromPolicy(policy, "process");
config.process!.commandLine = "python app.py";
const pty = spawnSandboxFromConfig(config, {
  experimental: true,
  debug: false,
});
```

The SDK passes `--experimental` to the underlying binary when this option is set.

### Forking Code for Experimental Features

Developers adding experimental features follow this pattern. For a detailed
step-by-step guide, see [Authoring a New Feature](authoring-a-new-feature.md).

**In `wire.rs` (the parse + schema source of truth):**
```rust
pub struct MxcConfig {
    // ... stable fields ...
    pub experimental: Option<Experimental>,
}

// The `experimental` block is intentionally permissive (no deny_unknown_fields)
// so in-flux feature shapes stay forward-compatible.
pub struct Experimental {
    pub compartments: Option<Compartments>,
    pub gpu_isolation: Option<GpuIsolation>,
    // ... add new experimental features here ...
}
```

After editing `wire.rs`, regenerate the schema
(`cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schemas/dev/mxc-config.schema.0.8.0-dev.json`)
— do not hand-edit the generated schema.

**In `models.rs`:**
```rust
pub struct ExperimentalConfig {
    pub compartments: Option<CompartmentsConfig>,
    pub gpu_isolation: Option<GpuIsolationConfig>,
}

pub struct ExecutionRequest {
    // ... stable fields ...
    pub experimental_enabled: bool,  // set by --experimental flag
    pub experimental: ExperimentalConfig,
}
```

**In `config_parser.rs`:** map the wire `Experimental` field to the domain
`ExperimentalConfig` inside `convert_wire_config` (there is no `Raw*` struct).

**In the runner (e.g., `appcontainer.rs`):**
```rust
fn run(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
    // ... normal execution ...

    // Experimental features only applied when flag is set
    if request.experimental_enabled {
        if let Some(ref compartments) = request.experimental.compartments {
            self.apply_compartments(compartments, logger);
        }
        if let Some(ref gpu) = request.experimental.gpu_isolation {
            self.apply_gpu_isolation(gpu, logger);
        }
    }
}
```

**Promotion process:** When an experimental feature is ready to ship:
1. Move the field from the wire `Experimental` struct to top-level `MxcConfig`
   (e.g., `experimental.gpuIsolation` → top-level `gpuIsolation`), then
   regenerate the schema with `mxc_schema_gen`
2. Move the struct from `ExperimentalConfig` to `ExecutionRequest`
3. Map the now-top-level wire field in `convert_wire_config`; add
   `deny_unknown_fields` to the wire struct so the promoted stable surface is
   closed
4. Remove the `if request.experimental_enabled` guard
5. Bump the minor version
6. Add a parser error for configs still referencing the feature under
   `experimental`: `"<feature> has moved to the stable section"`.
   This error should persist for at least one release cycle so users have
   time to migrate, then it can be relaxed to the standard "unknown field"
   behavior.
7. If the feature is a containment backend with a per-backend config
   section, update the single-backend-section enforcement when it graduates
   from experimental to top-level:

   - In `wxc_common::config_parser`, rename the matching entry in
     `present_backend_sections` and `owned_backend_section` from
     `experimental.<name>` to `<name>`.

   The single-backend-section rule is a cross-field constraint enforced by the
   parser (the trust boundary), **not** by the JSON schema — the generated
   schema intentionally omits the old top-level `allOf` `if/then` clauses. So
   there is no schema edit for this step; the parser change is sufficient.

   The rule itself is unchanged: a backend section requires `containment` to be
   set, and the value must be either the concrete backend name or any abstract
   intent that resolves to it on at least one platform (for example,
   `processContainer` accepts both `processcontainer` and `process`).

## Data Flow

```
User writes SandboxPolicy (policy + environment, versioned)
        │
        ▼
Config JSON (version: "0.4.0-alpha")
        │
        ▼
MXC parses → validates schema version
        │       → if --experimental, includes experimental section
        │
        ▼
MXC calls OS: EnumerateSandboxSpecVersionInfo()
        │        → returns supported tech language versions
        │           e.g., [1.4.5, 2.0.0]
        │
        ▼
MXC translates policy → flat buffer
        │  (based on the tech language version the OS supports)
        │
        ▼
MXC calls OS: CreateProcessInSandbox(flatbuffer)
        │
        ▼
Process runs in sandbox
```

## Wire Model vs Runtime Model

MXC deliberately keeps **two** Rust representations of a config with a mapping at
the parse boundary, rather than one shared type:

- **Wire model** (`wxc_common::wire::MxcConfig`) — a faithful 1:1 mirror of the
  config JSON: every field `Option`, `camelCase`, `experimental` carried as a raw
  `serde_json::Value`, no invariants enforced. It is the parser's deserialization
  target **and** the single source of truth the JSON schema (via schemars) and the
  SDK TypeScript types are generated from.
- **Runtime / domain model** (`models::ExecutionRequest` and friends) — the
  validated, defaults-applied, invariant-rich model the backends consume:
  abstract containment resolved to a concrete backend, `process.commandLine`
  reshaped to `script_code`, enums resolved to domain enums, required fields no
  longer `Option`.

The parser (`config_parser`) is the one validate/normalize boundary between them;
trivial enum/struct conversions are `From` impls beside the domain type, and the
larger reshaping lives in `convert_wire_config`.

### Why two layers (pros)

- **One validate/normalize boundary.** Defaults, invariant enforcement,
  abstract→concrete backend resolution, and field reshaping all happen in exactly
  one place; backends receive a type whose invariants already hold.
- **Parse, don't validate.** The domain type makes illegal states
  unrepresentable (required fields non-`Option`, enums resolved, containment
  always concrete), so a backend never re-checks "is this set / known?".
- **The wire model stays a pure schema/DTO source.** Being exactly the JSON shape
  is what makes schemars-from-types and SDK TS codegen clean — and it is what the
  per-field stability attributes (stable/experimental/deprecated, for the
  stable-vs-dev schema views and the promotion guard) hang on. A merged type would
  entangle schema-generation concerns with runtime fields.
- **Decoupled evolution.** The wire format can change (rename, alias, restructure
  `experimental`) without touching backend code, and vice-versa; the blast radius
  of either is bounded by the parser.
- **Backends don't couple to JSON quirks** — camelCase renames, deprecated-spelling
  serde aliases, the raw-`Value` experimental block, `$schema`/`_comment`
  passthrough — none leak into runner code.

### Costs (cons)

- **Boilerplate.** Two definitions plus a mapping for each object; adding a field
  touches the wire struct, the domain struct, and the parser (`From` impls only
  soften the trivial cases).
- **Internal drift risk.** The two Rust types can fall out of sync. This is
  mitigated by destructuring wire structs without `..` in conversions (a new wire
  field then fails to compile until mapped), but that is a convention, not a
  guarantee everywhere.
- **Indirection.** Tracing one field means hopping wire struct → mapping → domain
  struct → runner.

### Why the split is the right call for MXC

It earns its keep because of three load-bearing facts: (a) the wire model is
*also* the schema + SDK codegen source, a job that wants a pure JSON-shaped type;
(b) there is genuine wire↔runtime impedance (containment resolution, field
reshaping, defaults, deprecated-spelling aliases) that must live somewhere, and
concentrating it in the parser beats scattering it across backends; (c) the
per-field stability attributes need the wire model as a distinct annotatable
layer. For a config that was a thin pass-through, a single layer would be the
better call — here it is not.

The real costs (boilerplate, internal drift) are addressable **without merging**
— e.g. a derive/macro for the trivial wire→domain `From` impls, or a compile-time
totality check on the mapping — which captures most of the single-layer ergonomics
while preserving the separation the schema/SDK codegen and stability-attribute work
depend on. No planned phase merges the two models; 2B already reduced three layers
(`Raw*` → … → domain) to two (wire → domain), and a single layer is explicitly not
on the roadmap.

## Version Negotiation

```
1. User sends SandboxPolicy with version "0.4.0-alpha"

2. MXC validates: is "0.4.0-alpha" ≤ SUPPORTED_VERSION?
   Yes → continue
   No  → error: "upgrade wxc-exec"

3. MXC calls: EnumerateSandboxSpecVersionInfo(HIGHEST_MAJOR)
   OS returns: [
     { version: "1.4.5", isAvailable: true },
     { version: "2.0.0", isAvailable: true }
   ]

4. MXC selects the best tech language version for the
   features in the policy

5. MXC translates policy → flat buffer targeting that
   tech language version

6. MXC calls: CreateProcessInSandbox(flatbuffer)
   OS returns: success or error with disposition
```

## OS APIs

```c
// Query what the OS supports
HRESULT EnumerateSandboxSpecVersionInfo(
    UINT32 highestMajor,
    SANDBOX_VERSION_INFO** versions,
    UINT32* count
);

// Execute with the translated policy
HRESULT CreateProcessInSandbox(
    BYTE* flatbuffer,
    UINT32 flatbufferSize,
    PROCESS_INFORMATION* processInfo
);
```

## Error Contract

MXC ↔ OS needs a defined error contract:
- Which feature failed
- Whether it's a version mismatch or runtime unavailability (e.g., Hyper-V off)
- What the user should do (upgrade OS, enable feature, etc.)
- Security policy is deterministic — no relaxation, no fuzzy fallback

## Experimental Features — Clarifications

**Shipping model:** The shipped schema contains **only** non-experimental 
features. Experimental features exist solely for internal development and 
testing — they are never shipped to end users. The `--experimental` flag is a 
development tool, not a production feature.

**Global flag:** The `--experimental` flag is a single global toggle. When enabled,
all experimental features in the config are active. There is no per-feature
enable/disable mechanism — simplicity over granularity.

**Migration after promotion:** When an experimental feature is promoted to the
stable section (moved from `experimental.X` to top-level `X` in a stable
schema), configs that still reference it under `experimental` will receive
an error: "feature X has moved to the stable section." The parser will not
silently fall back — explicit migration is required.

## Deprecation Aliases

When a wire value is renamed (e.g. `appcontainer` → `processcontainer` in
[#268](https://github.com/microsoft/mxc/pull/268)), the legacy spelling enters a
deprecation window where both forms are accepted on the wire.

**Policy:** deprecation aliases are **version-agnostic**. The native parser
accepts the legacy form regardless of `config.version`, and the SDK validator
mirrors that behavior. We do *not* gate alias acceptance on schema version (i.e.
"`appcontainer` only allowed for `0.4.0-alpha`/`0.5.0-alpha`") because:

1. **Two layers must agree.** Schema-version gating would mean a config accepted
   by the binary could be rejected by the SDK validator (or vice versa) based
   on a string in `config.version`. That class of "works through one entry point
   but not another" bug is exactly what [#390](https://github.com/microsoft/mxc/issues/390)
   surfaced.
2. **Authors don't always control `config.version`.** Configs flowing from
   external sources (governance services, third-party tooling) may legitimately
   declare `0.6.0-alpha` while still using legacy vocabulary their generator
   has not yet been updated for.
3. **The deprecation window is short.** The stated intent at rename time is
   removal in a future minor release; gating buys little and costs review
   complexity in every layer that re-checks containment.

**Observability.** Legacy *value* aliases are mapped to their canonical form by
serde (`#[serde(alias = "...")]`) during deserialization, so the Rust parser no
longer emits a per-value deprecation hint for them — serde normalizes the alias
before any parser code runs, and the wire model is the trust boundary. Aliases
are still accepted; they are simply silent in the native parser. The TypeScript
SDK validator may still surface a deprecation hint via `diagLog` where it
inspects the raw config before serialization. (Earlier revisions emitted a
`Logger` line from the hand-written parser for each legacy value; that path was
removed when the parser was rewired onto the wire model.)

**Removal.** When an alias is removed in a future release, the change goes
through the same promotion-style migration: a single release that turns the
silent accept-and-warn into an explicit `unsupported_containment` error.
Document the removal in the schema bump that drops it.

## Open Questions

1. **Experimental features on the OS side:** Does
   `EnumerateSandboxSpecVersionInfo` distinguish between stable and experimental
   OS capabilities? If the OS itself has experimental features, how does MXC
   discover and target them?

2. **Security of the experimental flag:** Should `--experimental` require
   additional privilege or be restricted to debug builds? A malicious caller could
   pass `--experimental` to enable a feature that weakens the sandbox boundary.

3. **Conflicting experimental features:** If two experimental features have
   conflicting requirements (e.g., one denies a namespace, another relaxes it),
   how are conflicts resolved? First-wins, last-wins, or error?

4. **Per-feature vs global experimental flag:** Should `--experimental` be a
   global toggle (all experimental features on/off), or per-feature
   (`--experimental compartments --experimental gpu-isolation`)? Per-feature
   gives more control but adds complexity to the executor and SDK interfaces.

5. **Shipping experimental features to customers:** Should experimental features
   be shippable to specific customers (e.g., Anthropic, Nemoclaw), or strictly
   internal development only? If shippable, the security and stability
   requirements for experimental features increase significantly. What is the
   delivery mechanism — private npm package drop, feature-flagged public release,
   or a separate experimental binary?

6. **Multiple dev schemas for multiple major versions:** When multiple major
   versions are alive simultaneously (e.g., v1 shipped on OS 26100, v2 shipped
   on OS 27000, v3 in development), promoting a feature may require adding it
   to multiple schemas. For example, if "compartments" is additive, it should
   be added to both `dev/1.vnext.json` and `dev/2.vnext.json` as a minor bump
   for each. If it's breaking, it goes only into `dev/3.vnext.json`. The `dev/`
   folder and promotion process need to support this multi-schema model. Today
   we are pre-1.0 with only one major version, so a single dev schema suffices.

7. **Experimental features modifying stable behavior:** Experimental features
   may need to modify stable behavior. How do we reason about
   and test this?
