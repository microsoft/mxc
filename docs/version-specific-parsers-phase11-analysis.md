# Version-Specific Parser Phase 11 Architecture Analysis

## Scope

This analysis is based on the latest available remote Phase 11 branch,
`origin/user/gudge/version_specific_config_parsers_phase11a` at `fc187205`,
committed on September 13, 2026:

```text
36786cae  Use typed payloads for state-aware dispatch
a8556c61  Accept directional networking for IsolationSession
a6176ac9  Complete the v0.9 directional networking cutover
6052b3a7  Add exact contract publication tooling
fc187205  Add state-aware publication profiles
```

As of September 14, 2026, `origin` has no
`origin/user/gudge/version_specific_config_parsers_phase11b` or
`origin/user/gudge/version_specific_config_parsers_phase11c` ref. On the
remote Phase 11a branch, v0.9 remains the mutable development contract. The
experimental-wrapper removal, v0.9 publication, and v0.10 development
transition are still proposed later phases rather than part of this analysis
baseline.

## Conclusion

Remote Phase 11a does not restore a rolling JSON parser. Exact JSON dispatch
remains correct:

```text
JSON
  -> exact ContractVersion
  -> exact version-specific request type
  -> exact adapter
  -> wire::MxcConfig
  -> ExecutionRequest
```

The architectural concern is instead that the publication and proposed
post-1.0 SDK designs add parallel descriptions of each contract:

- an exact contract type family;
- an exact adapter;
- an exact SDK builder;
- a publication projection type family for the active development version;
- proposed representability and `VersionSemantics` descriptions.

That prevents parser rollback, but it does not produce a smaller or simpler
system.

## Current type growth

Phase 11 adds `dev/publication.rs`, including:

- `PublicationProfile`;
- `StateAwareBackend`;
- a publication-specific `Containment`;
- `OneShotRequest`;
- three backend-specific provision requests;
- `StartRequest`, `ExecRequest`, `StopRequest`, and
  `DeprovisionRequest`.

These types project a stable subset from the mutable development contract.
The planned publication step would then copy that projected shape into another
complete published v0.9 exact type family. That published family does not yet
exist on the remote Phase 11a branch.

The resulting growth is:

```text
                         SHARED RUNTIME
                 +--------------------------+
                 | rolling SDK SandboxPolicy|
                 | wire::MxcConfig          |
                 | ExecutionRequest         |
                 +------------^-------------+
                              |
        +---------------------+---------------------+
        |                     |                     |
+-------+--------+    +-------+--------+    +-------+--------+
| Contract 1.0  |    | Contract 1.1  |    | Contract 1.2  |
| request types |    | request types |    | request types |
| adapter       |    | adapter       |    | adapter       |
| SDK builder   |    | SDK builder   |    | SDK builder   |
+----------------+    +----------------+    +----------------+

Active development additionally has:

+--------------------------------------+
| development contract                 |
| publication projection contract      |
| development adapter and SDK builder  |
+--------------------------------------+
```

Symbolically:

```text
N * (contract + adapter + SDK builder)
+ publication projection
+ rolling normalization model
+ runtime model
+ SDK model
```

## Minor versions after 1.0

Minor config versions remain valuable for external serialized documents:

- config files;
- command-line and base64 input;
- Node-to-executor JSON;
- schema validation;
- replay and compatibility with older executors.

They add little value to a direct typed SDK call:

```text
SandboxPolicy
  -> ExecutionRequest
  -> backend
```

For that path the SDK package version already determines the available typed
surface. Carrying a config minor version means interpreting a current SDK
object as if it had arrived through a historical JSON contract.

The proposed post-1.0 rules correctly state that a 1.0 document must continue
to use the frozen 1.0 parser and cannot contain a field introduced in 1.2.
That invariant should remain. The risky parts are:

- one SDK object model spanning several config minors;
- automatic selection of the oldest representable contract;
- direct SDK normalization through a hand-maintained `VersionSemantics`
  description;
- demoting exact SDK builders to temporary test oracles.

Those choices create a rolling producer and a second description of every
contract even though the JSON parser remains exact.

## Lower-type-count alternative

Starting from `origin/main`, the lower-type-count design is:

```text
UNTRUSTED JSON                     TRUSTED SDK

exact contract Request            SandboxPolicy
          |                            |
version-specific adapter          SDK adapter
          |                            |
          +----------+-----------------+
                     |
                ConfigInput
                     |
              ExecutionRequest
                     |
                  backend
```

`ConfigInput` should be the current `wire::MxcConfig` repurposed:

- rename it;
- remove `Deserialize`;
- remove `JsonSchema`;
- remove its status as a wire contract;
- keep its existing nested process, filesystem, network, UI, lifecycle, and
  backend-section types as private normalization DTOs.

This avoids introducing separate `NormalizationInput`, `ProcessInput`,
`FilesystemInput`, `NetworkInput`, `UiInput`, and `ContainmentInput` families.

## Publication without projection types

The candidate contract itself should equal the published contract:

```text
Before publication

published:    v0.6, v0.7, v0.8
candidate:    v0.9 final shape
development:  v0.10 full development shape

After publication

published:    v0.6, v0.7, v0.8, v0.9
development:  v0.10
```

The publication sequence should be:

1. Copy the full mutable v0.9 development contract forward to v0.10.
2. Move all non-graduated fields and roots to v0.10.
3. Test the remaining actual v0.9 candidate.
4. Freeze that module unchanged as published v0.9.
5. Record its schema and behavior digests.

This removes the need for a publication-specific view of the same version.

## Types to retain

- `ContractVersion`
- `ContractDescriptor`, `ContractStatus`, and `CONTRACTS`
- every actual published and development exact request type
- exact contract adapters
- `ExecutionRequest`
- `ContainerPolicy`
- `SandboxPolicy`, `Containment`, and `SandboxRequest`
- `StateAwareOperation` and `StateAwareProvision`
- `ParsedStateAwareRequest`
- `BoundStateAwareRequest<B>` where checked generic binding remains useful
- raw Node `ContainerConfig`, including its exact `version`

## Types to repurpose

- `wire::MxcConfig` -> private `ConfigInput`
- nested `wire::*` types -> private normalization DTOs
- per-version SDK builders -> explicit config encoders, but only if historical
  config serialization is a demonstrated requirement
- `ContractDescriptor::builder_path` -> `encoder_path`, if encoders survive

## Types to delete

- `PublicationProfile`
- publication `StateAwareBackend`
- all request and nested types in `dev/publication.rs`
- rolling whole-request parser and loader
- rolling schema and generated TypeScript wire model
- legacy state-aware payload/reference implementations
- `ExecutionRequest::schema_version` after runtime behavior is made explicit
- backend SemVer helpers such as `supports_directional_network` and
  `schema_enforces_network_strictly`
- direct SDK `SandboxPolicy.version`
- state-aware high-level SDK version options
- FFI `RequestPolicy.version`
- per-version SDK builder modules if no historical serialization API requires
  them

`VersionSemantics` should not be introduced.

## Backend version removal

`ExecutionRequest::schema_version` currently controls both telemetry and some
Bubblewrap/LXC behavior. Replace those responsibilities separately:

- retain `Option<ContractVersion>` only as source attribution for JSON input;
- add an explicit field such as
  `ContainerPolicy::strict_network_enforcement`;
- derive directional policy from the existing normalized
  `network_egress`/`network_ingress` fields.

Backends then consume explicit runtime policy rather than parsing config
version strings.

## Recommended direction

Keep Phase 11's exact registry, immutable published modules, behavior freeze,
and digest checks. Do not retain the publication projection family as the
long-term publication mechanism, and do not implement post-1.0 compatibility
as a shared rolling SDK model plus `VersionSemantics`.

The only unavoidable per-version growth should be:

```text
exact external contract types + exact adapter
```

SDK construction, normalization, and backend execution should remain shared.
