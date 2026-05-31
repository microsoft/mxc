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
│   └── mxc-config.schema.0.6.0-alpha.json  (shipped — current stable)
└── dev/
    └── mxc-config.schema.0.7.0-dev.json    (current — work in progress)
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

When `--experimental` is passed:
- The parser reads the `experimental` section from the config JSON
- Features from the experimental section are applied alongside the stable features
- Without the flag, the `experimental` section is **silently ignored** — no error,
  just skipped

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

**In `config_parser.rs`:**
```rust
struct RawConfig {
    // ... stable fields ...
    experimental: Option<RawExperimental>,
}

struct RawExperimental {
    compartments: Option<RawCompartments>,
    #[serde(rename = "gpuIsolation")]
    gpu_isolation: Option<RawGpuIsolation>,
    // ... add new experimental features here ...
}
```

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
1. Move the property from `experimental` to a top-level property in the schema
   (e.g., `experimental.gpuIsolation` → `gpuIsolation`)
2. Move the struct from `ExperimentalConfig` to `ExecutionRequest`
3. Move the field from `RawExperimental` to `RawConfig`
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
   - In the JSON schema's top-level `allOf`, rekey the matching `if/then`
     clause so it checks the new top-level section instead of
     `experimental.<name>`.

   Concretely, if `wslc` graduates the clause changes from

   ```json
   {
     "if": {
       "required": ["experimental"],
       "properties": { "experimental": { "required": ["wslc"] } }
     },
     "then": {
       "required": ["containment"],
       "properties": { "containment": { "enum": ["wslc"] } }
     }
   }
   ```

   to

   ```json
   {
     "if": { "required": ["wslc"] },
     "then": {
       "required": ["containment"],
       "properties": { "containment": { "enum": ["wslc"] } }
     }
   }
   ```

   The `then` branch is unchanged: a backend section requires `containment`
   to be set, and the value must be either the concrete backend name or any
   abstract intent that resolves to it on at least one platform (for
   example, `processContainer` accepts both `processcontainer` and `process`).

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

**Observability.** Each legacy-value encounter emits a one-line deprecation hint
via the existing diagnostic channel (Rust: `Logger`; TypeScript SDK: `diagLog`,
dedup'd per legacy value per process). The hint names the canonical replacement.
No throw, no stderr write — the deprecation is observable only to callers who
opt into the diagnostic stream.

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
