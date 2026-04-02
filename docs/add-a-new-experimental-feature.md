# Adding a New Experimental Feature

> **Do not modify stable schemas.** Files in `schemas/stable/` are immutable
> release artifacts. All experimental work happens in `schemas/dev/` only.
> Stable schemas are updated solely during the promotion process when an
> experimental feature ships.

This guide walks MXC developers through adding a new experimental feature
end-to-end. We assume an experimental feature `compartments` already exists in
the codebase, and we are adding a second experimental feature called
`gpuIsolation`.

## Prerequisites

Read the [Versioning Design](versioning.md) doc for context on how experimental
features fit into the MXC schema and shipping model.

## Overview

Adding an experimental feature touches these files:

| File | What to change |
|------|----------------|
| `schemas/dev/mxc-config.schema.json` | Add `gpuIsolation` as a feature under `experimental` |
| `src/wxc_common/src/models.rs` | Add `GpuIsolationConfig` struct, add field to `ExperimentalConfig` |
| `src/wxc_common/src/config_parser.rs` | Add `gpuIsolation` field to `RawExperimental` |
| Runner (`appcontainer.rs` or `lxc_runner.rs`) | Feature logic, guarded behind `experimental_enabled` |
| `test_configs/` | Test config exercising your feature |

## Step 1: Update the schema

In `schemas/dev/mxc-config.schema.json`, the `experimental` section already
exists with `compartments` as a feature. Add `gpuIsolation` as a new
feature with its own typed schema:

```json
"experimental": {
  "type": "object",
  "description": "Experimental features. Only active when --experimental is passed.",
  "properties": {
    "compartments": {
      "type": "object",
      "description": "Network compartment isolation (experimental).",
      "properties": {
        "namespace": {
          "type": "string",
          "description": "Compartment namespace identifier."
        },
        "isolationLevel": {
          "type": "integer",
          "minimum": 1,
          "description": "Isolation level (1 = shared network, 2 = separate stack, 3 = full isolation)."
        }
      }
    },
    "gpuIsolation": {
      "type": "object",
      "description": "GPU device isolation (experimental).",
      "properties": {
        "deviceIndex": {
          "type": "integer",
          "minimum": 0,
          "description": "GPU device index to assign to the container."
        },
        "memoryLimitMb": {
          "type": "integer",
          "minimum": 0,
          "description": "GPU memory limit in megabytes. 0 = no limit."
        },
        "allowCuda": {
          "type": "boolean",
          "default": false,
          "description": "Allow CUDA runtime access inside the container."
        }
      },
      "required": ["deviceIndex", "memoryLimitMb"]
    }
  }
}
```

Each experimental feature is its own typed property under `experimental` —
the same pattern as stable features (`filesystem`, `network`) under the
top-level config. This gives editors full autocomplete and validation.

## Step 2: Add the model struct

In `src/wxc_common/src/models.rs`, `ExperimentalConfig` already exists with
`compartments`. Add your `GpuIsolationConfig` struct and a field for it:

```rust
/// GPU isolation settings (experimental).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GpuIsolationConfig {
    pub device_index: u32,
    pub memory_limit_mb: u32,
    pub allow_cuda: bool,
}
```

Add it to the existing `ExperimentalConfig`:

```rust
pub struct ExperimentalConfig {
    pub compartments: Option<CompartmentsConfig>,
    pub gpu_isolation: Option<GpuIsolationConfig>,   // ← add this
}
```

## Step 3: Parse the experimental section

In `src/wxc_common/src/config_parser.rs`, the `RawExperimental` struct already
exists with `compartments`. Add `gpu_isolation`:

```rust
#[derive(Deserialize, Default)]
struct RawExperimental {
    compartments: Option<RawCompartments>,          // existing
    #[serde(rename = "gpuIsolation")]
    gpu_isolation: Option<RawGpuIsolation>,         // ← add this
}

#[derive(Deserialize)]
struct RawGpuIsolation {
    #[serde(rename = "deviceIndex")]
    device_index: u32,
    #[serde(rename = "memoryLimitMb")]
    memory_limit_mb: u32,
    #[serde(rename = "allowCuda")]
    allow_cuda: Option<bool>,
}
```

In `convert_raw_config()`, map it directly — no name matching needed. Each
feature should own its parsing via a constructor:

```rust
let mut experimental = ExperimentalConfig::default();

if let Some(raw_exp) = raw.experimental {
    if let Some(c) = raw_exp.compartments {
        experimental.compartments = Some(CompartmentsConfig::from_raw(c)?);
    }
    if let Some(g) = raw_exp.gpu_isolation {
        experimental.gpu_isolation = Some(GpuIsolationConfig::from_raw(g)?);
    }
}
```

Each feature implements its own `from_raw()` constructor to keep
`convert_raw_config()` clean:

```rust
impl GpuIsolationConfig {
    fn from_raw(raw: RawGpuIsolation) -> Result<Self, String> {
        Ok(Self {
            device_index: raw.device_index,
            memory_limit_mb: raw.memory_limit_mb,
            allow_cuda: raw.allow_cuda.unwrap_or(false),
        })
    }
}
```

Add tests to verify:
- `gpuIsolation` config parses correctly
- Missing optional fields use defaults
- Unknown fields under `experimental` are ignored (forward compatibility)

Also ensure that `convert_raw_config()` populates `CodexRequest.experimental`:

```rust
Ok(CodexRequest {
    // ... existing fields ...
    experimental,   // ← include the parsed experimental config
})
```

## Step 4: Implement the feature in the runner

> The `--experimental` CLI flag and `experimental_enabled` field on
> `CodexRequest` already exist from when `compartments` was added. No changes
> needed in `main.rs`.

The full flow is:

```
main.rs: cli.experimental → request.experimental_enabled = true
main.rs: runner.run(&request, &mut logger)
  → runner checks request.experimental_enabled
    → reads request.experimental.gpu_isolation
      → applies the feature
```

In the appropriate runner (`appcontainer.rs`, `lxc_runner.rs`, etc.), guard
your feature behind `experimental_enabled`:

```rust
fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
    // ... normal execution (filesystem, network, etc.) ...

    if request.experimental_enabled {
        // existing experimental feature
        if let Some(ref compartments) = request.experimental.compartments {
            self.apply_compartments(compartments, logger)?;
        }

        // new experimental feature
        if let Some(ref gpu) = request.experimental.gpu_isolation {
            self.apply_gpu_isolation(gpu, logger)?;
        }
    }

    // ... execute the script ...
}
```

**Important:** Your experimental code must not break the stable code path. When
`experimental_enabled` is false, behavior must be identical to before your
change.

## Step 5: Add a test config

Create a test config that exercises your feature:

```json
{
  "version": "0.4.0-alpha",
  "containment": "appcontainer",
  "process": {
    "commandLine": "cmd.exe /c echo gpu isolation test"
  },
  "experimental": {
    "gpuIsolation": {
      "deviceIndex": 0,
      "memoryLimitMb": 1024,
      "allowCuda": true
    }
  }
}
```

Run it with and without the flag to verify:

```bash
# With flag — experimental feature is active
wxc-exec.exe test_configs/experimental_gpu_isolation.json --experimental --debug

# Without flag — experimental section silently ignored, normal execution
wxc-exec.exe test_configs/experimental_gpu_isolation.json --debug
```

Verify three things:
1. **With `--experimental`:** debug output shows your feature was applied
   (e.g., "Applying GPU isolation: device 0, 1024MB limit")
2. **Without `--experimental`:** no trace of your feature in the output,
   process executes normally
3. **Stable features unaffected:** filesystem, network, and other policies
   still work exactly as before in both modes

## Step 6: Update the SDK (if needed)

If your feature should be accessible from the TypeScript SDK, add
`experimental` to the `SandboxSpawnOptions` interface in `sdk/src/sandbox.ts`:

```typescript
export interface SandboxSpawnOptions {
  debug?: boolean;
  experimental?: boolean;
}
```

The SDK passes `--experimental` to the underlying binary when this is set.

## Promoting to Stable

When your experimental feature is ready to ship:

1. Move the property from `experimental` to a top-level property in the schema
   (e.g., `experimental.gpuIsolation` → `gpuIsolation`)
2. Move the struct from `ExperimentalConfig` to `CodexRequest`
3. Move the field from `RawExperimental` to `RawConfig`
4. Remove the `if request.experimental_enabled` guard
5. Bump the minor version
6. Add a parser error for configs still referencing the feature under
   `experimental`: `"gpuIsolation has moved to the stable section"`.
   This error should persist for at least one release cycle so users have
   time to migrate, then it can be relaxed to the standard "unknown field"
   behavior.

## Checklist

- [ ] Schema updated in `schemas/dev/mxc-config.schema.json`
- [ ] Model struct added to `models.rs`
- [ ] Parsing added to `config_parser.rs` with unit tests
- [ ] `--experimental` flag wired through (if not already)
- [ ] Feature logic guarded behind `experimental_enabled` in the runner
- [ ] Test config created and verified with and without `--experimental`
- [ ] Stable code path is unaffected (all existing tests pass)
- [ ] SDK updated if feature is SDK-accessible
