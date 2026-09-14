# Version-Specific Parser Phase 9A / origin/main Architecture Analysis

## Scope

This analysis uses `origin/main` at `43d579bf`, committed on September 13,
2026. The parser-relevant parent is `9c2097e4`, which merged authoritative exact
contract dispatch in #1104.

The requested filename calls this Phase 9A analysis. The actual `origin/main`
baseline contains the completed Phase 9 exact-dispatch change, but predates the
typed state-aware payload work represented by Phase 9b.

## Current architecture

One-shot JSON is exact at the trust boundary:

```text
JSON
  -> ContractVersion::parse_exact
  -> published v0.6/v0.7/v0.8 or dev v0.9 Request
  -> version-specific adapter
  -> wire::MxcConfig
  -> convert_wire_config
  -> ExecutionRequest
```

The Rust SDK also uses exact contracts, despite not using JSON:

```text
SandboxPolicy { version }
  -> policy/exact/v0_6 | v0_7 | v0_8 | v0_9
  -> ExactOneShotContract
  -> version-specific adapter
  -> wire::MxcConfig
  -> ExecutionRequest
```

State-aware parsing is not yet fully typed. `ParsedStateAwareRequest` retains:

- `ExecutionRequest`;
- an independent `Phase`;
- optional containment;
- optional sandbox ID;
- raw `experimental` JSON;
- the complete source string.

The dispatcher later calls `deserialize_config<C>` against the retained
backend/phase fragment. This reparses backend payloads and permits phase,
containment, and payload authority to remain separate.

## What has already been achieved

The most important parser goal is already complete:

- every supported JSON document declares an exact registered version;
- the selected version chooses a frozen Rust request type;
- unsupported or missing versions do not fall back to a latest parser;
- published JSON shapes are independent;
- adapters, not published modules, absorb runtime evolution.

This is the correct boundary to preserve.

## Remaining type and representation costs

`origin/main` has three principal representations:

```text
exact Request
    |
    v
wire::MxcConfig
    |
    v
ExecutionRequest
```

For state-aware requests it also retains:

```text
StateAwareWireInput
ParsedStateAwareRequest
raw experimental Value
complete source text
backend phase config C
```

The Rust SDK adds per-version builder modules even though it never serializes
canonical config JSON.

The type growth pressure is therefore:

```text
Per version:
  exact Request family
  exact adapter
  exact SDK builder

Shared:
  rolling wire model
  runtime model
  SDK policy model
```

## Preferred architecture from this baseline

Starting here produces the simplest implementation:

```text
UNTRUSTED JSON                     TRUSTED SDK

exact Request                     SandboxPolicy
     |                                 |
exact adapter                      SDK adapter
     |                                 |
     +---------------+-----------------+
                     |
                ConfigInput
                     |
              ExecutionRequest
```

Do not introduce a new normalization type hierarchy. Rename and repurpose
`wire::MxcConfig` as `ConfigInput`:

- exact adapters continue constructing it;
- the SDK constructs it directly;
- `convert_wire_config` becomes `convert_config_input`;
- Serde and schema generation are removed;
- it is no longer an external or rolling contract.

Its existing nested types can continue to represent process, filesystem,
network, UI, lifecycle, telemetry, and backend configuration before final
normalization.

## State-aware correction

Phase 9b's central typed-operation idea should still be added:

```text
exact state-aware root
  -> ConfigInput + StateAwareOperation
  -> ExecutionRequest + StateAwareOperation
  -> checked backend binding
  -> dispatch
```

The essential additions are:

- `StateAwareProvision`
- `StateAwareOperation`
- a revised `ParsedStateAwareRequest` containing only
  `ExecutionRequest + StateAwareOperation`
- optionally `BoundStateAwareRequest<B>` for checked backend binding

These types replace more state than they add:

- independent phase;
- independent containment;
- independent sandbox ID;
- raw backend JSON;
- retained complete source;
- dispatch-time reparsing.

Migration reference implementations may exist temporarily, but should be
deleted in the same overall convergence effort rather than becoming a
long-lived second parser.

## Direct SDK versioning

Config minor versions are not needed for ordinary in-process Rust execution.
The direct SDK should use:

```rust
pub struct SandboxPolicy {
    pub filesystem: Option<FilesystemSection>,
    pub network: Option<NetworkSection>,
    pub ui: Option<UiSection>,
    pub timeout_ms: Option<u32>,
}
```

`SandboxPolicy.version` should be removed at the next SDK breaking boundary.
The SDK package version governs the typed surface.

The per-version `policy/exact/v0_*` builders should be:

- deleted if Rust does not expose historical config serialization; or
- moved behind an explicit config-export API.

They should not remain in the ordinary execution path.

Node remains different because it invokes an executor through exact JSON.
Raw `ContainerConfig.version` remains required. The high-level Node
`SandboxPolicy` can omit the version and let the package target its bundled
exact contract.

## Backend version interpretation

`ExecutionRequest::schema_version` should stop selecting backend behavior.

Use existing runtime fields where possible:

- directional policy is represented by `network_egress` and
  `network_ingress`;
- add a boolean such as `strict_network_enforcement` where v0.6/v0.7
  compatibility differs from v0.8+ behavior;
- retain `Option<ContractVersion>` only for source attribution and telemetry.

No general `VersionSemantics` type is required.

## Type-growth diagram

Current:

```text
v0.6: contract + adapter + SDK builder --+
v0.7: contract + adapter + SDK builder --+--> wire::MxcConfig
v0.8: contract + adapter + SDK builder --+          |
v0.9: contract + adapter + SDK builder --+          v
                                              ExecutionRequest
```

Preferred:

```text
v0.6: contract + adapter --+
v0.7: contract + adapter --+
v0.8: contract + adapter --+--> ConfigInput --> ExecutionRequest
v0.9: contract + adapter --+         ^
                                      |
                               one SandboxPolicy
```

Only exact external contracts grow per version.

## Types to retain

- `ContractVersion`
- `ContractDescriptor`, `ContractStatus`, and `CONTRACTS`
- exact published and development request types
- version-specific adapters
- `ExecutionRequest`
- `ContainerPolicy`
- `SandboxPolicy`, `Containment`, and `SandboxRequest`
- `MxcRequest`
- `Phase`
- Node raw `ContainerConfig`

## Types to add

- `StateAwareProvision`
- `StateAwareOperation`
- optionally `BoundStateAwareRequest<B>`

No other major input hierarchy is needed.

## Types to repurpose

- `wire::MxcConfig` -> private `ConfigInput`
- nested `wire::*` types -> private normalization DTOs
- `convert_wire_config` -> `convert_config_input`

## Types to delete

- raw fields on the current `ParsedStateAwareRequest`
- `StateAwareWireInput` after typed adaptation
- dispatch-time `deserialize_config<C>`
- retained state-aware source text and raw `experimental` payload
- rolling `MxcConfig` deserializer and schema generator
- rolling generated schema and TypeScript model
- direct SDK `SandboxPolicy.version`
- per-version direct SDK builders unless required for explicit serialization
- backend version-string helpers
- `ExactOneShotContract` once it no longer serves SDK construction

## Recommended implementation sequence

1. Add typed `StateAwareOperation` and remove raw state-aware payload retention.
2. Rename `wire::MxcConfig` to `ConfigInput` and remove its parser authority.
3. Delete rolling parser and code-generation consumers.
4. Map direct Rust and one-shot FFI policies directly into `ConfigInput`.
5. Remove config versions from high-level direct SDK calls.
6. Replace backend version comparisons with explicit normalized behavior.
7. Publish later contracts by freezing actual exact candidate modules, without
   introducing a parallel publication contract family.

This baseline offers the clearest opportunity to finish the parser migration
while adding only the typed state-aware operation types that eliminate real
duplicate state.
