# MXC Versioning Design

## Core Concepts

### Policy = Intent

The policy (filesystem, network, lifecycle) expresses **what** the user wants — "block network, allow these paths, destroy on exit." It does not specify how the OS enforces it, nor which container type to use. The container selection is a separate concern handled by MXC based on the `containment` field.

### Policy Version = Config Schema Version

The SandboxPolicy carries a `version` field that versions **both** the policy format and its semantics together — tied 1:1.

```typescript
// sdk/src/types.ts
SandboxPolicy {
  version: "0.4.0-alpha",       // versions policy format + semantics
  filesystem: { ... },           // policy (intent)
  network: { ... },              // policy (intent)
}
```

The config JSON (`WxcConfiguration`) carries this version through to the binary:

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

## Two Independent Version Streams

| Stream | Owner | What it versions | Format |
|---|---|---|---|
| **MXC Policy/Config** | MXC team | SandboxPolicy + config format | Semver (e.g., 0.4.0-alpha) |
| **OS Tech Language** | OS team | What the OS can enforce (sandbox spec) | Version info (e.g., 1.4.5, 2.0.0) |

MXC is responsible for mapping policy intent onto the OS tech language version.
They are **not** lock-stepped.

## Schema Shipping Model

```
mxc/schemas/
├── schema.0.3.0-alpha.json      (shipped — historical)
├── schema.0.4.0-alpha.json      (shipped — current stable)
└── mxc-config.schema.json       (current — includes experimental section)
```

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

  "experimental": {
    "compartments": { ... },
    "gpuIsolation": { ... },
    "threadInjectionPrevention": { ... }
  }
}
```

**Rules:**
- **Generic section** (top) — shipped, stable, supported. Always executed.
- **Experimental section** (bottom) — only executed when the experimental flag
  is enabled (see below).
- **Promotion:** When an experimental feature is ready to ship, move it from
  `experimental` to the generic section and bump the minor version.

### Experimental Flag

The experimental flag must be supported at every layer of the stack:

**1. `wxc-exec.exe` / `lxc-exec` (Rust binaries):**
```bash
wxc-exec.exe --experimental config.json
lxc-exec --experimental config.json
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

**3. CLI (`mxc-cli`):**
```bash
npm start run config.json --experimental
```

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

1. **Experimental + stable interaction:** Can experimental features modify or
   override the behavior of stable features? Or must they be fully isolated?
   (e.g., experimental compartments changing how `network.defaultPolicy` is
   enforced)

2. **Experimental features on the OS side:** Does
   `EnumerateSandboxSpecVersionInfo` distinguish between stable and experimental
   OS capabilities? If the OS itself has experimental features, how does MXC
   discover and target them?

3. **Security of the experimental flag:** Should `--experimental` require
   additional privilege or be restricted to debug builds? A malicious caller could
   pass `--experimental` to enable a feature that weakens the sandbox boundary.

4. **Telemetry / diagnostics:** When something fails with `--experimental`
   enabled, how do we distinguish between experimental feature bugs and stable
   feature regressions? Should experimental execution be tagged differently in
   logs?

5. **Conflicting experimental features:** If two experimental features have
   conflicting requirements (e.g., one denies a namespace, another relaxes it),
   how are conflicts resolved? First-wins, last-wins, or error?
