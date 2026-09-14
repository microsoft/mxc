# Version-Specific Parser Phase 10a Architecture Analysis

## Scope and ancestry

This analysis uses
`origin/user/gudge/version_specific_config_parsers_phase10a` at `a8556c61`,
committed on September 12, 2026.

Its direct parent is the remote Phase 9b commit `36786cae`, so the remote
branches form the intended Phase 9b -> Phase 10a stack.

## What Phase 10a changes

Phase 10a adds an additive transition for IsolationSession networking. The
v0.9 development contract accepts either:

```json
{
  "defaultPolicy": "allow",
  "allowLocalNetwork": true
}
```

or:

```json
{
  "egress": { "default": "allow" },
  "ingress": {
    "default": "allow",
    "hostLoopback": "allow"
  }
}
```

The two forms are exact alternatives. Partial, mixed, rule-bearing,
proxy-bearing, restrictive, empty, null, and omitted forms are rejected.

## Type growth introduced by the transition

The Rust exact development contract adds:

- `IsolationSessionNetworkAllow`
- `IsolationSessionLegacyNetworkAllow`
- `IsolationSessionLegacyNetwork`
- `IsolationSessionNetworkEgress`
- `IsolationSessionNetworkIngress`
- `IsolationSessionDirectionalNetwork`
- `IsolationSessionNetwork`
- private `IsolationSessionNetworkFields`
- `InvalidIsolationSessionNetwork`

The Node SDK adds equivalent legacy and directional interfaces and a union.
The generated TypeScript exact wire oracle gains the corresponding types.

The transition also adds a frozen legacy provision snapshot in parser tests so
the independent baseline does not silently learn directional fields from a
live runtime type.

The phase changes 21 files with approximately 787 insertions and 106
deletions. Most of the net growth represents two simultaneously accepted
spellings.

## Architectural significance

This is intentionally transitional type growth:

```text
                    IsolationSessionNetwork
                    /                     \
          legacy unrestricted       directional unrestricted
```

It is justified only while both spellings are accepted. It should collapse at
the directional-only cutover:

```text
IsolationSessionNetwork {
    egress: all-allow,
    ingress: all-allow + host-loopback-allow,
}
```

Phase 10a does not change the preferred parser or SDK architecture. It changes
one exact contract shape and its SDK authoring representation.

## Current data flow

The Phase 9b typed state-aware flow remains:

```text
exact IsolationSession provision request
  -> exact IsolationSessionNetwork union
  -> exact state-aware adapter
  -> canonical ContainerPolicy network fields
  -> StateAwareOperation::Provision
  -> checked IsolationSession binding
  -> backend validation
```

The backend does not need to retain which spelling was used after
normalization. Both forms mean the same unrestricted runtime posture.

## Type-growth assessment

At this point there are three separate network descriptions:

1. exact contract legacy and directional types;
2. SDK legacy and directional authoring types;
3. canonical runtime `ContainerPolicy` network fields.

That is acceptable for a short migration but should not become the post-1.0
minor-version strategy.

If every minor added a new alternative while retaining all prior alternatives
inside one SDK model, growth would look like:

```text
SDK NetworkPolicy
  = V1.0 form
  | V1.1 form
  | V1.2 form
  | V1.3 form
  | ...
```

That is a rolling parser/producer model expressed as a union.

## Lower-type-count target from Phase 10a

Preserve exact alternatives only at the external contract boundary:

```text
legacy exact input ------+
                         +--> canonical ConfigInput network
directional exact input -+             |
                                       v
                                ContainerPolicy
```

The direct SDK should expose only the current directional policy. Historical
legacy authoring should exist only in:

- frozen v0.6-v0.8 exact contracts;
- explicit legacy config serialization, if required;
- migration diagnostics.

It should not remain a permanent member of a current typed SDK
`NetworkSection`.

## Minor config versions

Phase 10a demonstrates the value of an exact external version:

- an older exact contract can retain the legacy shape;
- the development contract can admit the directional shape;
- diagnostics can distinguish unsupported and mixed forms;
- the runtime receives one truthful canonical posture.

It does not demonstrate value for carrying the config version into backend
execution. Once normalized, both accepted forms have identical runtime
meaning.

## Types to retain

- Phase 9b's `StateAwareProvision`, `StateAwareOperation`,
  `ParsedStateAwareRequest`, and checked binding
- exact v0.9 network types while the additive transition exists
- canonical runtime network policy types
- Node/.NET directional authoring types
- exact contract adapters

## Types to delete at the cutover

- `IsolationSessionLegacyNetworkAllow`
- `IsolationSessionLegacyNetwork`
- the legacy arm of `IsolationSessionNetwork`
- private union-deserialization staging used only for the two-form transition
- `InvalidIsolationSessionNetwork` if ordinary closed directional structs
  provide sufficient diagnostics
- Node legacy IsolationSession network interface
- .NET legacy IsolationSession network authoring properties
- frozen legacy provision snapshot after replacement exact regressions exist
- compatibility helpers that only recognize the temporary alternative

## Types to avoid introducing

- a permanent SDK union of all historical network contract shapes
- per-minor runtime network types
- backend logic that branches on schema version
- a general `VersionSemantics` table describing which network form each
  version accepts

## Growth diagram

During Phase 10a:

```text
Exact contract:

IsolationSessionNetwork
  +-- LegacyNetwork
  |     +-- LegacyAllow marker
  |     `-- True marker
  |
  `-- DirectionalNetwork
        +-- Egress
        +-- Ingress
        `-- Allow marker

SDK:

LegacyNetwork interface | DirectionalNetwork interface

Runtime:

one canonical ContainerPolicy network posture
```

After the cutover:

```text
Exact current contract --> DirectionalNetwork --+
                                                 +--> one runtime posture
Current SDK -----------> DirectionalNetwork -----+

Old exact contracts retain their own legacy types independently.
```

## Recommended implementation sequence

1. Keep Phase 10a strictly additive and temporary.
2. Complete backend and SDK evidence for the directional representation.
3. Cut v0.9 over to directional-only input.
4. Delete all two-form union and legacy-transition types from the mutable
   contract and current SDKs.
5. Leave legacy network types only inside frozen older exact contracts.
6. Continue with the Phase 9b plan to remove rolling parser/reference
   machinery.
7. Do not generalize this migration union into the post-1.0 minor-version
   model.

Phase 10a temporarily increases types, but it need not change the final
architecture if its legacy arm is removed promptly.
