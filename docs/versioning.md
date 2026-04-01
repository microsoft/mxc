# MXC Versioning Design

## Core Concepts

### Policy = Intent

The policy (filesystem, network) expresses **what** the user wants — "block network, allow these paths." It does not specify how the OS enforces it, nor which container type to use.

### Policy Version = Config Schema Version

We are introducing a `version` field in the SandboxPolicy. This version must match the MXC config JSON version — they are the same version, tied 1:1.

When a consumer specifies a SandboxPolicy version (e.g., `0.4.0`), MXC creates
the corresponding `WxcConfiguration` using the `0.4.0` schema. If a different
version is specified (e.g., `0.5.0`), MXC uses the `0.5.0` schema. All schemas
for a major version are packaged together in the SDK.

```typescript
// sdk/src/types.ts
// NOTE: SandboxPolicy is subject to significant evolution as the schema matures.
SandboxPolicy {
  version: "0.4.0-alpha",       // must match MXC config schema version
  filesystem: { ... },           // policy (intent)
  network: { ... },              // policy (intent)
}
```

The config JSON (`WxcConfiguration`) carries this same version:

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
│   ├── schema.0.3.0-alpha.json      (shipped — historical)
│   └── schema.0.4.0-alpha.json      (shipped — current stable)
└── dev/
    └── mxc-config.schema.json       (current — includes experimental section definition)
```

The dev schema file (`mxc-config.schema.json`) must define the `experimental`
section structure so that editors can validate experimental configs. Stable
schemas in `stable/` do not include the experimental section.

### Shipped vs Experimental

The current config schema has two sections:

```json
{
  "version": "0.4.0-alpha",
  "process": { ... },
  "filesystem": { ... },
  "network": { ... },
  "appContainer": { ... },
  "lxc": { ... },

  "experimental": [
    {
      "name": "compartments",
      "config": { ... }
    },
    {
      "name": "gpu-isolation",
      "config": { ... }
    }
  ]
}
```

Each experimental feature has a `name` (used for identification and future
per-feature gating — see Open Questions) and a freeform `config` object that
the feature developer defines. The `name` must be unique across all experimental
features. Today, the `--experimental` flag is a global toggle that enables all
experimental features; per-feature gating (e.g., `--experimental compartments`)
is under consideration.

**Rules:**
- **Generic section** (top) — shipped, stable, supported. Always executed.
- **Experimental section** (bottom) — an array of named features, only executed
  when the experimental flag is enabled (see below). Developers can put any
  keys or nested keys they want inside a feature's `config` and are responsible
  for adding the parsing code for their
  experimental feature. As long as their experimental code doesn't break what
  is shipped, they are free to iterate as much as they want.
- **Promotion:** When an experimental feature is ready to ship, move it from
  `experimental` to the generic section and bump the minor version.

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
const pty = spawnSandbox("python app.py", policy, {
  experimental: true,
  debug: false
});
```

The SDK passes `--experimental` to the underlying binary when this option is set.

### Forking Code for Experimental Features

Developers adding experimental features follow this pattern:

**In `config_parser.rs`:**
```rust
struct RawConfig {
    // ... stable fields ...
    experimental: Option<RawExperimental>,
}

struct RawExperimental {
    compartments: Option<RawCompartments>,
    gpu_isolation: Option<RawGpuIsolation>,
    // ... add new experimental fields here ...
}
```

**In `CodexRequest` (models.rs):**
```rust
pub struct CodexRequest {
    // ... stable fields ...
    pub experimental_enabled: bool,  // set by --experimental flag
    pub experimental: ExperimentalConfig,
}
```

**In the runner (e.g., `appcontainer.rs`):**
```rust
fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
    // ... normal execution ...

    // Experimental features only applied when flag is set
    if request.experimental_enabled {
        if let Some(compartments) = &request.experimental.compartments {
            self.apply_compartments(compartments, logger);
        }
    }
}
```

**Promotion process:** When an experimental feature is ready to ship:
1. Move the field from `RawExperimental` to the stable section of `RawConfig`
2. Move the field from `ExperimentalConfig` to `CodexRequest`
3. Remove the `if request.experimental_enabled` guard — the feature now always
   applies
4. Update the schema: move from `experimental` section to generic section
5. Bump the minor version

## Data Flow

```
User writes SandboxPolicy (intent, versioned)
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

**Shipping model:** The shipped schema contains **only** non-experimental features.
Experimental features exist solely for internal development and testing — they are
never shipped to end users. The `--experimental` flag is a development tool, not
a production feature.

**Global flag:** The `--experimental` flag is a single global toggle. When enabled,
all experimental features in the config are active. There is no per-feature
enable/disable mechanism — simplicity over granularity.

**Migration after promotion:** When an experimental feature is promoted to the
stable section, configs that still reference it under `experimental` will receive
an error: "feature X has moved to the stable section." The parser will not
silently fall back — explicit migration is required.

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
   gives more control but adds complexity to the CLI and SDK interfaces.

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
   may need to modify stable behavior (e.g., "AppContainer as Medium IL"
   changes how the stable appcontainer feature works). How do we reason about
   and test this?
