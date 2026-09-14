# Version-Specific Parser Phase 10b Architecture Analysis

## Scope and ancestry

This analysis uses
`origin/user/gudge/version_specific_config_parsers_phase10b` at `a6176ac9`,
committed on September 13, 2026. Its direct parent is the remote Phase 10a
branch at `a8556c61`.

Phase 10b completes the v0.9 directional-networking cutover across the exact
contract, adapters, runtime models, Rust/Node/.NET SDK authoring, fixtures, and
backend validation.

## What becomes simpler

The v0.9 exact contract no longer accepts legacy network fields. The
IsolationSession two-form transition collapses to one directional type:

```text
Network
  -> NetworkEgress
  -> NetworkIngress
  -> rules, peers, ports, and actions
```

Cooperative proxy configuration moves to
`runtimeConfig.networkProxy`.

Old contracts retain their frozen legacy syntax. The mutable v0.9 contract no
longer carries the Phase 10a legacy/directional union.

This is the correct use of version-specific parsing:

```text
v0.6-v0.8 exact contracts -> legacy syntax
v0.9 exact contract       -> directional syntax
```

No rolling JSON parser needs to understand both as one evolving shape.

## What remains complex

The direct Rust SDK `NetworkSection` still contains both:

- legacy fields such as `allow_outbound`, `allow_local_network`,
  `allowed_hosts`, `blocked_hosts`, and `proxy`;
- directional `egress`, `ingress`, and runtime configuration;
- authored-presence tracking;
- a custom deserializer;
- version-dependent `select_network_format`.

The .NET SDK similarly adds custom JSON converters so one high-level policy
type can preserve legacy presence while authoring the new shape.

The Node high-level `SandboxPolicy` also spans legacy and directional fields.

Therefore Phase 10b simplifies the exact contract while increasing the
complexity of shared SDK models that attempt to author several historical
contracts.

## Type growth in this phase

Phase 10b changes 64 files with approximately 2,147 insertions and 983
deletions.

Notable additions include:

- directional `Network`, `NetworkEgress`, `NetworkIngress`, `NetworkRule`,
  `NetworkPeer`, and `NetworkPort` exact contract types;
- Rust SDK `NetworkSection` custom-deserialization support;
- SDK `NetworkFormat`;
- .NET `NetworkPolicyJsonConverter`;
- .NET `StateAwareNetworkPolicyJsonConverter`;
- Node directional network interfaces;
- frozen network snapshot types used by migration tests.

Some of these are permanent current policy types. Others exist only because a
single SDK model is asked to represent both old and new config contracts.

## Current data flow

JSON:

```text
exact v0.6/v0.7/v0.8/v0.9 Request
  -> version-specific adapter
  -> wire::MxcConfig
  -> shared normalization
  -> ExecutionRequest
```

Direct Rust SDK:

```text
SandboxPolicy { version, rolling NetworkSection }
  -> select_network_format(version, policy)
  -> exact version-specific SDK builder
  -> exact contract Request
  -> exact adapter
  -> wire::MxcConfig
  -> ExecutionRequest
```

State-aware runtime:

```text
exact phase root
  -> wire::MxcConfig + StateAwareOperation
  -> ParsedStateAwareRequest
  -> checked backend binding
```

The JSON path is exact. The SDK authoring model remains rolling.

## Architectural conclusion

Phase 10b is the best point in the stack to separate:

- historical exact JSON shapes;
- the current typed SDK policy;
- canonical runtime policy.

The direct SDK should no longer preserve old JSON authoring fields merely
because it can target old config versions.

Preferred direct path:

```text
current directional SandboxPolicy
  -> ConfigInput
  -> ExecutionRequest
```

Preferred external path:

```text
legacy exact Request ------+
                           +--> ConfigInput --> ExecutionRequest
directional exact Request -+
```

Old syntax remains available through old exact config contracts, not through
the current SDK policy type.

## Repurpose the existing wire model

As in the earlier-phase analyses, avoid introducing a new normalization type
hierarchy. Rename `wire::MxcConfig` to `ConfigInput` and retain its nested
types as private normalization DTOs.

After the rolling parser is deleted, `ConfigInput` is not a rolling contract:

- it has no `Deserialize`;
- it has no `JsonSchema`;
- no caller can submit it;
- exact adapters resolve version-specific structure before constructing it;
- the SDK constructs current semantics directly.

## Direct SDK network type

Replace the rolling Rust `NetworkSection` with a current directional policy:

```rust
pub struct NetworkSection {
    pub egress: Option<NetworkEgressSection>,
    pub ingress: Option<NetworkIngressSection>,
    pub runtime_config: Option<RuntimeConfigSection>,
}
```

Remove from the current SDK type:

- `allow_outbound`
- `allow_local_network`
- `allowed_hosts`
- `blocked_hosts`
- legacy `proxy`
- `legacy_fields_specified`
- custom legacy-presence deserialization
- `NetworkFormat`
- `select_network_format`

Equivalent legacy authoring remains in exact v0.6-v0.8 request modules.

The same simplification applies to Node and .NET high-level policy types at
their next breaking SDK boundary.

## Runtime version removal

Backends currently use `ExecutionRequest::schema_version` to distinguish
pre-v0.8 compatibility behavior from strict v0.8+ behavior.

Do not replace that with a general semantic-version interpreter. Add one
explicit normalized field to `ContainerPolicy`, for example:

```rust
pub strict_network_enforcement: bool,
```

Exact adapters set it:

```text
v0.6/v0.7 -> false where compatibility requires it
v0.8+     -> true
SDK       -> true
```

Directional policy remains visible through `network_egress` and
`network_ingress`.

`ExecutionRequest` may retain `Option<ContractVersion>` only for telemetry
source attribution.

## Minor versions

Phase 10b demonstrates the appropriate value of config minor versions:

- v0.8 can continue accepting legacy syntax;
- v0.9 can reject it and require directional syntax;
- exact diagnostics identify the requested contract;
- old documents remain stable.

This value ends after adaptation. Backend execution and direct SDK calls need
effective normalized policy, not config minor-version inference.

## Types to retain

- exact v0.6-v0.9 contract network types in their own modules
- version-specific adapters
- `ExecutionRequest`
- `ContainerPolicy`
- directional runtime network types
- `StateAwareOperation`, `StateAwareProvision`, and typed binding
- current directional SDK network types
- exact Node raw config types

## Types to repurpose

- `wire::MxcConfig` -> private `ConfigInput`
- nested `wire::Network` and related types -> private adapter input DTOs
- `schema_version` -> typed optional source-contract metadata, telemetry only

## Types to delete

- current SDK legacy network fields
- `NetworkFormat`
- `select_network_format`
- `select_rolling_network_format`
- SDK custom deserializers used only to preserve historical authoring presence
- .NET converters whose only purpose is one model spanning old and new config
  shapes
- Node high-level legacy network authoring fields
- frozen rolling network snapshot/reference types after exact regressions
  replace them
- rolling parser, schema, and generated wire model
- per-version direct SDK builders unless explicit config export requires them
- backend schema-version parsing helpers

## Types to avoid introducing

- `VersionSemantics`
- an SDK union that accumulates each future minor's fields
- per-version runtime network types
- publication-specific network projection types
- automatic oldest-representable inference in ordinary execution

## Growth diagram

Current Phase 10b:

```text
EXACT CONTRACTS

v0.6 legacy types ----+
v0.7 legacy types ----+
v0.8 mixed-era types -+--> wire::MxcConfig --> ExecutionRequest
v0.9 directional -----+

SDK MODEL

legacy fields
+ directional fields
+ presence tracking
+ custom deserializer
+ version selector
+ per-version builders
```

Preferred:

```text
EXTERNAL

v0.6 legacy contract ----+
v0.7 legacy contract ----+
v0.8 exact contract -----+--> ConfigInput --> ExecutionRequest
v0.9 directional --------+

DIRECT SDK

one current directional SandboxPolicy ------^
```

Future growth is then:

```text
per version: exact contract + adapter
shared:      one SDK policy + one ConfigInput + one runtime model
```

## Recommended implementation sequence

1. Preserve the completed v0.9 directional-only exact contract.
2. Keep the Phase 9b typed state-aware operation and binding model.
3. Delete Phase 10a's transitional two-form network types.
4. Split current SDK policy from historical config authoring.
5. Repurpose `wire::MxcConfig` as non-wire `ConfigInput`.
6. Remove rolling parser and reference models.
7. Remove config versions from direct SDK execution.
8. Replace backend version checks with explicit normalized behavior.
9. Publish actual exact candidate modules rather than publication projections.

Phase 10b leaves the external contract boundary in a good state. The next
simplification should remove historical syntax and version inference from
shared SDK and backend types rather than layering publication machinery on top
of them.
