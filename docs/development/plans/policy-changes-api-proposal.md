<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Proposal: typed creation-policy change notifications

> **Audience:** MXC developers
>
> **Status:** Deferred proposal; not implemented or exposed by the SDKs.

## Motivation

Caller-authorized policy mutation returns plain warning text beginning
`Sandbox configuration updated due to IT policy`. Reapplying cached
restrictions is silent unless Windows requires another correction.
These messages are suitable for a person or agent, but their wording and
serialized field values are not a stable parsing contract.

A consuming application such as Copilot could benefit from a typed description
of applied restrictions: render a concise, localized notification, distinguish
filesystem and network changes, or recognize a restriction already explained
to the user without parsing diagnostic sentences. A separate read-only API
could make that possible without exposing the complete effective request or
native administrative-policy diagnostics.

## Candidate API

The proposed accessor belongs to a successfully created live process:

| SDK | Candidate accessor | Result |
|---|---|---|
| Rust | `MxcProcess::policy_changes()` | `Vec<PolicyChange>` |
| Node | `MxcProcess.policyChanges` | `readonly PolicyChange[]` |
| .NET | `MxcProcess.PolicyChanges` | `IReadOnlyList<PolicyChange>` |
| Internal C adapter | `mxc_sandbox_policy_changes_json` | Owned JSON array, released with `mxc_string_free` |

All SDK operations and types would remain within supported versioned entry
points. A caller would read the records after `spawn`, then stream or capture
output and wait using the ordinary process APIs. This proposal does not add a
field to the published Rust `ExecutionResult` or change captured result layouts.
Availability directly from captured execution would need its own compatibility
design.

Candidate record kinds:

| Kind | Proposed data |
|---|---|
| `filesystemAccessRestricted` | Literal path, `previousAccess`, and resulting `access`: `none`, `read`, or `readWrite` |
| `capabilityRemoved` | Removed Windows capability identifier |
| `networkRestricted` | Category: `outbound`, `inbound`, `hostLoopback`, or `proxy`; not a complete rule diff |
| `denialCaptureChanged` | Resulting recording mode: `off`, `enforced`, or `permissive` |

Rust could express these as a non-exhaustive enum, TypeScript as a discriminated
union, and .NET as an SDK-owned closed hierarchy. Serialized records would use
a camelCase `kind` discriminator and camelCase fields and enum values.

An illustrative proposed record:

```json
{
  "kind": "filesystemAccessRestricted",
  "path": "C:\\work\\private",
  "previousAccess": "readWrite",
  "access": "none"
}
```

## Semantics and boundaries

Records would describe restrictions actually applied to the current request
for successful creation, not attempted changes from a failed negotiation.
Strict creation or a creation with no effective permission change would return
an empty collection. Exact duplicate-path removal or a diagnostic-output
filename change alone would not be an effective-permission record.

The candidate semantics include restrictions reapplied from the private cache
even when no warning is emitted. This could support a persistent UI indicator
without causing repeated warning notifications. Notification history and
deduplication would belong to the consumer, not MXC's cache or launch authority.
Stable record identities and a cache-origin marker are not part of this
candidate and would need justification if consumers require them.

The accessor is not a pre-execution approval callback: the workload has already
been launched when `spawn` returns. Records cannot authorize a later launch,
change the authored request, disclose the administrator's full permission
ceiling, or replace Windows validation. Mutation authorization stays in the
existing default-off creation options. No caller-owned mutation context or
new request JSON field is proposed.

## Requirements before adoption

- Derive records from the actual original and applied permissions, not warning
  text or a replayed whole-policy snapshot. Define coverage for synthesized
  capabilities and changes that affect several permission categories.
- Avoid a full grant-list scan for every path, including unchanged policies.
  Compute only relevant differences or use an indexed comparison, and keep
  nonessential metadata work outside the serialized negotiation window.
- Define record availability across wait, output capture, disposal and native
  handle release. Node must retain any promised records before freeing the
  handle; all adapters must preserve exact ownership and cleanup behavior.
- Treat unavailable native metadata support distinctly from a supported empty
  result. Map missing exports to actionable SDK errors rather than unhandled
  platform exceptions or a misleading empty collection.
- Define enum/discriminator evolution and malformed-data handling consistently
  across SDKs. Register .NET serialization roots and include reflection-disabled
  and Native AOT round-trip checks.
- Review record privacy and volume bounds. Paths and capability names are
  application data, not permission grants or trusted UI instructions.

Adoption requires an explicit SDK contract decision and corresponding
implementation, references and tests. The current implementation remains
text-only; see the
[creation-policy guide](../guides/process-container-adding-os-features.md#opt-in-creation-policy-mutation)
for supported behavior.
