# Version-Specific Parser Phase 9b Architecture Analysis

## Scope and ancestry

This analysis uses the remote branch
`origin/user/gudge/version_specific_config_parsers_phase9b` at `36786cae`,
committed on September 12, 2026.

Its history is:

```text
4ba1f344  Migrate development requests to version-specific parsers
9c2097e4  Enable authoritative exact contract dispatch
36786cae  Use typed payloads for state-aware dispatch
```

This is the exact Phase 9b commit used as the parent of the remote Phase 10a
branch.

## What Phase 9b changes

Phase 9b replaces state-aware raw backend JSON and dispatch-time reparsing with
typed operations.

The normalized request changes from:

```text
ExecutionRequest
+ independent Phase
+ optional containment
+ optional sandboxId
+ raw experimental JSON
+ complete source text
```

to:

```text
ParsedStateAwareRequest {
    request: ExecutionRequest,
    operation: StateAwareOperation,
}
```

`StateAwareOperation` owns the phase and routing information:

```text
Provision(StateAwareProvision)
Start { sandbox_id }
Exec { sandbox_id }
Stop { sandbox_id }
Deprovision { sandbox_id }
```

`StateAwareProvision` owns backend-specific provision input:

```text
IsolationSession(Option<IsolationSessionProvisionConfig>)
WindowsSandbox
Wslc(Option<WslcProvisionConfig>)
```

This makes phase/payload contradictions unrepresentable after adaptation.

## Essential new types

The following additions carry architectural value:

- `StateAwareProvision`
- `StateAwareOperation`
- the revised `ParsedStateAwareRequest`
- `BoundStateAwareOperation<B>`
- `BoundStateAwareRequest<B>`
- runtime-owned `WslcProvisionConfig`

`BoundStateAwareRequest<B>` ensures that:

- the resolved backend matches the typed payload;
- sandbox ID prefix routing agrees with the backend;
- only that backend's associated phase config types can reach dispatch;
- lifecycle and streaming exec use the same checked binding.

These types add a small typed state machine but delete several independent
authorities and raw representations.

## Temporary type growth

The commit also adds a substantial independent reference implementation:

- `legacy_payload_reference.rs`
- `legacy_state_aware_request.rs`
- `LegacyStateAwareWireInput`
- `LegacyStateAwareRequest`
- `LegacyMxcRequest`
- frozen snapshot structs and recording test types

The commit changes 25 core files with approximately 3,739 insertions and 3,034
deletions. Much of the added surface is evidence for migration rather than the
target runtime design.

This distinction is important:

```text
Permanent:
  StateAwareOperation
  StateAwareProvision
  ParsedStateAwareRequest
  checked binding

Temporary:
  complete legacy state-aware parser
  raw-payload reference
  duplicate observation machinery
```

Phase 9b is a net simplification only if the temporary family is later removed.

## Architecture at this phase

```text
JSON
  -> exact contract request
  -> exact adapter
       +-- common fields -> wire::MxcConfig
       `-- backend payload -> StateAwareOperation
  -> normalize common fields
  -> ParsedStateAwareRequest
  -> bind_<backend>
  -> BoundStateAwareRequest<B>
  -> dispatch
```

The exact parser is authoritative. The rolling parser and the independent
legacy state-aware path remain only as test/reference machinery.

The direct Rust SDK still takes a config version and constructs an exact
contract before returning to `wire::MxcConfig`.

## Type-growth assessment

Phase 9b does not itself create per-version state-aware operation families.
`StateAwareOperation` is version-neutral and therefore scales well.

The growth problem remains elsewhere:

```text
Per config version:
  exact request family
  exact adapter
  exact SDK builder

Shared:
  wire::MxcConfig
  ExecutionRequest
  StateAwareOperation
  BoundStateAwareRequest<B>

Migration-only:
  complete legacy state-aware reference family
```

The typed operation and binding types are shared and should not be copied for
v1.0, v1.1, and v1.2.

## Lower-type-count target from Phase 9b

Retain Phase 9b's typed state-aware work, but collapse the remaining parser
layers:

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
          +----------+-----------+
          |                      |
   ExecutionRequest       StateAwareOperation
          |                      |
          +----------+-----------+
                     |
       BoundStateAwareRequest<B>
                     |
                  backend
```

`ConfigInput` should be the current `wire::MxcConfig` renamed and stripped of
Serde/schema authority. No parallel normalization input family is required.

## Minor config versions

Minor config versions continue to govern exact external JSON. They should not
govern direct typed SDK execution.

The Phase 9b operation types demonstrate why: once a request has become
`ExecutionRequest + StateAwareOperation`, the backend requires effective typed
values, not knowledge of which JSON minor introduced them.

The direct SDK should therefore:

- remove `SandboxPolicy.version`;
- construct current `ConfigInput` directly;
- use package SemVer for typed API evolution;
- target exact config versions only in explicit serialization APIs.

Node and state-aware .NET still emit canonical JSON at this phase, so their
transport helpers continue to stamp an exact version. That does not require
the backend-facing typed operation to retain it.

## Types to retain

- exact contract request types and adapters
- `ExecutionRequest`
- `ContainerPolicy`
- `StateAwareProvision`
- `StateAwareOperation`
- revised `ParsedStateAwareRequest`
- `BoundStateAwareOperation<B>`
- `BoundStateAwareRequest<B>`
- `StatefulSandboxBackend` associated config types
- `WslcProvisionConfig`
- SDK per-backend/per-phase authoring types

## Types to repurpose

- `wire::MxcConfig` -> private `ConfigInput`
- `StateAwareInput` -> either rename to a short-lived adapter result or replace
  with a tuple of `ConfigInput + StateAwareOperation`
- `ExactOneShotContract` -> parser-internal only until it can be removed

## Types to delete

- `LegacyStateAwareWireInput`
- `LegacyStateAwareRequest`
- `LegacyMxcRequest`
- `legacy_payload_reference.rs`
- `legacy_state_aware_request.rs`
- frozen legacy snapshot structs once direct exact fixtures replace them
- rolling whole-request parser and builders
- raw state-aware source retention
- dispatch-time backend JSON reparsing
- direct SDK `SandboxPolicy.version`
- per-version direct SDK builder modules when no explicit serializer needs them

## Types to avoid introducing

- version-specific `StateAwareOperationV1_0`, `StateAwareOperationV1_1`, etc.
- per-version bound request families
- a shared rolling SDK model interpreted by `VersionSemantics`
- publication-specific copies of every state-aware root

## Growth diagram

Current Phase 9b:

```text
v0.6 contract + adapter + SDK builder --+
v0.7 contract + adapter + SDK builder --+
v0.8 contract + adapter + SDK builder --+--> wire::MxcConfig
v0.9 contract + adapter + SDK builder --+          |
                                                   +--> ExecutionRequest
                                                   +--> StateAwareOperation

Temporary side branch:
  complete legacy state-aware parser/reference family
```

Preferred:

```text
v0.6 contract + adapter --+
v0.7 contract + adapter --+
v0.8 contract + adapter --+--> ConfigInput --> ExecutionRequest
v0.9 contract + adapter --+         |
                                    `--> StateAwareOperation

SandboxPolicy ----------------------^
```

## Recommended implementation sequence

1. Keep the typed operation and checked binding introduced by Phase 9b.
2. Replace legacy reference comparisons with direct exact fixtures and
   independent expected observations.
3. Delete the complete legacy state-aware implementation.
4. Repurpose `wire::MxcConfig` as private `ConfigInput`.
5. Retire rolling deserialization and code generation.
6. Remove config versions from direct SDK construction.
7. Keep all state-aware runtime types version-neutral.

Phase 9b contains the most valuable structural simplification in the stack.
Its permanent typed operation model should survive; its duplicate migration
implementation should not.
