<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Network Format Normalization Refactor Plan

> **Status:** Design proposal
>
> **Last updated:** September 28, 2026

## 1. Purpose

Resolve the legacy-versus-directional network format at the exact-contract
adapter boundary instead of inferring it later in `network_parser`.

The exact contract already determines which network shapes can reach common
normalization:

| Contract | Accepted network shape |
| --- | --- |
| `0.6.0-alpha` | Legacy only |
| `0.7.0-alpha` | Legacy only |
| `0.8.0-alpha` | Transitional additive shape: legacy or directional, but not both |
| `0.9.0-alpha` | Directional only |
| `1.0.0` | Directional only |
| `1.1.0-alpha` / eventual `1.1.0` | Directional only |

The current `select_network_format` function nevertheless receives
`NetworkEnforcementCompatibility`, checks the fields again, and emits a
version-specific error. This preserves behavior introduced before exact
contracts became the production trust boundary, but it leaves a
version-derived format decision below that boundary.

This refactor will make the adapter output explicit:

```rust
pub(crate) enum NormalizedNetworkInput {
    Legacy(LegacyNetworkInput),
    Directional(DirectionalNetworkInput),
}
```

Common normalization will apply the selected variant directly. It will not
compare versions, inspect a version-derived capability to select a format, or
ask whether directional networking is supported.

## 2. Goals

1. Resolve network format exactly once, while adapting an exact contract into
   `CommonRequestIR`.
2. Preserve all accepted inputs, rejected inputs, defaults, and enforcement
   behavior for every registered contract.
3. Keep the special `0.8.0-alpha` additive contract behavior:
   a. legacy fields select the legacy path;
   b. directional fields select the directional path;
   c. omitted or empty network configuration selects directional defaults;
   d. mixed legacy and directional fields are rejected;
   e. empty `runtimeConfig` or `processContainer.network` sections do not make
      an otherwise legacy request mixed.
4. Delete `select_network_format` and the now-unreachable
   `directional_network_version_error`.
5. Keep published exact contracts and stable schemas unchanged.

## 3. Non-goals

1. Do not change the JSON shape of any exact contract.
2. Do not regenerate or edit stable schemas or generated SDK wire types.
3. Do not change legacy v0.6/v0.7 network behavior.
4. Do not change directional defaults or enforcement for v0.8 and later.
5. Do not accept legacy network fields in v0.9, v1.0, or v1.1.
6. Do not remove `NetworkEnforcementCompatibility` from `ExecutionRequest` in
   this change.

`NetworkEnforcementCompatibility` currently affects Bubblewrap and NanVix
backend behavior and is included in policy identity. Removing it safely
requires a separate audit showing that every enforcement distinction has been
materialized in the normalized policy and that policy-hash compatibility has
been addressed. This plan removes the flag only from network-format selection.

## 4. Current behavior

The current flow is:

```text
exact contract
  -> version-specific adapter
  -> CommonRequestIR {
       network,
       runtime_config,
       process_container.network,
       network_enforcement_compatibility,
     }
  -> normalize_common_request_ir
  -> parse_network_policy
  -> select_network_format
  -> apply_legacy_network | apply_directional_network
```

`select_network_format`:

1. Detects legacy and directional fields.
2. Rejects mixed fields.
3. Rejects directional sections when compatibility is not `Strict`.
4. Uses compatibility to choose defaults when the network block is empty or
   omitted.

Under exact-contract parsing, step 3 is unreachable:

- v0.6/v0.7 contracts cannot deserialize directional fields or sections;
- v0.8 accepts directional fields;
- v0.9 and later contain only directional network fields.

The ambiguous empty/omitted case is also known at the adapter boundary:
v0.6/v0.7 mean legacy, while v0.8 and later mean directional.

## 5. Target model

Add private normalization-input types alongside `CommonRequestIR`:

```rust
pub(crate) enum NormalizedNetworkInput {
    Legacy(LegacyNetworkInput),
    Directional(DirectionalNetworkInput),
}

pub(crate) struct LegacyNetworkInput {
    pub(crate) network: Option<wire::Network>,
}

pub(crate) struct DirectionalNetworkInput {
    pub(crate) network: Option<wire::Network>,
    pub(crate) runtime: Option<wire::RuntimeConfig>,
    pub(crate) process_container: Option<wire::ProcessContainerNetwork>,
}
```

The exact field types may be narrowed further during implementation. The
important invariants are:

- `Legacy` cannot carry effective directional fields.
- `Directional` cannot carry effective legacy fields.
- `CommonRequestIR` contains one selected network variant, not three unrelated
  sections plus a later format-selection flag.
- Empty transitional sections that have no semantic effect are normalized
  away when v0.8 selects `Legacy`.

Move `processContainer.network` out of the general process-container DTO during
adaptation and into `NormalizedNetworkInput`. Other process-container fields
remain in `CommonRequestIR.process_container`.

## 6. Exact-contract adapter mapping

### 6.1 v0.6 and v0.7

The adapters always construct:

```rust
NormalizedNetworkInput::Legacy(...)
```

Their exact contracts have no directional fields, `runtimeConfig`, or
`processContainer.network`, so no runtime classification is needed.

### 6.2 v0.8

The v0.8 adapter uses one shared classifier over the converted v0.8 network
sections:

| Legacy fields | Effective directional fields | Result |
| --- | --- | --- |
| Present | Present | Existing mixed-format error |
| Present | Absent | `Legacy` |
| Absent | Present | `Directional` |
| Absent | Absent | `Directional` |

“Effective directional fields” retains the current definition:

- `network.egress` or `network.ingress` is present;
- `runtimeConfig.networkProxy` is present;
- `processContainer.network.allowedProxyPeer` is nonempty.

The mere presence of an empty `runtimeConfig` or
`processContainer.network` object does not make a legacy request mixed.

The classifier should return `Result<NormalizedNetworkInput, WxcError>`.
Make the adapter path fallible rather than encoding a known-invalid mixed
state in `CommonRequestIR`. Use a shared helper so one-shot and any future
typed v0.8 entry points cannot drift.

### 6.3 v0.9, v1.0, and v1.1

These adapters always construct:

```rust
NormalizedNetworkInput::Directional(...)
```

Their exact `Network` types contain only `egress` and `ingress` and use
`deny_unknown_fields`. Legacy fields are therefore rejected at exact
deserialization and never enter `CommonRequestIR`.

Apply the same rule to both one-shot and state-aware adapters. Specialized
state-aware provision network types continue to adapt directly into the
directional variant.

### 6.4 Typed SDK input

Typed SDK construction that does not originate from external JSON constructs
the directional variant explicitly. Typed one-shot SDK builders that first
construct an exact contract inherit the mapping from that contract's adapter.

No typed input should infer its format by populating a compatibility enum.

## 7. Implementation steps

1. Introduce the normalized network input.

   a. Add `NormalizedNetworkInput`, `LegacyNetworkInput`, and
      `DirectionalNetworkInput` as private common-normalization types.

   b. Replace the separate network normalization fields in `CommonRequestIR`
      with one `network: NormalizedNetworkInput` field.

   c. Keep source-contract attribution and
      `NetworkEnforcementCompatibility` separate from this field.

2. Make exact adapters select the variant.

   a. Update v0.6 and v0.7 adapters to construct `Legacy`.

   b. Add the shared fallible v0.8 classifier and preserve the existing mixed
      error text.

   c. Update v0.9, v1.0, and development adapters to construct `Directional`
      without field-based format detection.

   d. Split `processContainer.network` from other process-container data during
      adaptation so network normalization has one owner.

   e. Update adapter entry points and parser dispatch to propagate a fallible
      v0.8 adaptation result without changing error routing.

3. Simplify common normalization.

   a. Pass `NormalizedNetworkInput` directly to `parse_network_policy`.

   b. Match on `Legacy` or `Directional` and call the corresponding apply
      function.

   c. Delete `NetworkSections`, or retain it only as the payload of
      `DirectionalNetworkInput` if that avoids unnecessary churn.

   d. Delete `select_network_format`.

   e. Delete `directional_network_version_error`.

   f. Remove `NetworkEnforcementCompatibility` from
      `parse_network_policy`'s parameters.

4. Preserve runtime compatibility behavior.

   a. Continue assigning `LegacyCompatible` for v0.6/v0.7 and `Strict` for
      v0.8 and later while the field remains part of `ExecutionRequest`.

   b. Verify Bubblewrap and NanVix receive the same value as before.

   c. Keep the existing policy-identity projection unchanged so equivalent
      requests retain their policy hashes.

   d. Record removal of the runtime compatibility field as separate follow-up
      work, not as an opportunistic part of this refactor.

5. Update architectural documentation.

   a. Update `docs/versioning.md` to state that exact adapters select the
      normalized network variant.

   b. Document v0.8 as the sole transitional classifier.

   c. State that shared normalization applies a selected semantic variant and
      does not use contract provenance to choose a format.

## 8. Test plan

### 8.1 Adapter tests

1. v0.6 and v0.7 adapters produce `Legacy` for:
   a. omitted network;
   b. an empty network object where accepted;
   c. each supported legacy field.

2. v0.8 produces:
   a. `Legacy` for legacy fields;
   b. `Legacy` for legacy fields plus empty directional sections;
   c. `Directional` for egress;
   d. `Directional` for ingress;
   e. `Directional` for `runtimeConfig.networkProxy`;
   f. `Directional` for a nonempty
      `processContainer.network.allowedProxyPeer`;
   g. `Directional` for omitted or empty network configuration;
   h. the existing error for every legacy/directional mixed combination.

3. v0.9, v1.0, and development adapters always produce `Directional`.

### 8.2 Exact-contract tests

1. Preserve tests proving v0.7 rejects:
   a. egress and ingress;
   b. `runtimeConfig`;
   c. `processContainer.network`.

2. Add or retain tests proving v0.9, v1.0, and development contracts reject:
   a. `defaultPolicy`;
   b. `enforcementMode`;
   c. `allowLocalNetwork`;
   d. `allowedHosts`;
   e. `blockedHosts`;
   f. legacy `network.proxy`.

3. Verify these failures occur during exact deserialization, before common
   normalization.

### 8.3 Runtime regression tests

1. Preserve v0.6/v0.7 legacy defaults and backend command generation.
2. Preserve v0.8 legacy behavior when legacy fields select that path.
3. Preserve directional deny defaults for omitted/empty v0.8+ network input.
4. Preserve proxy and `allowedProxyPeer` validation.
5. Preserve one-shot and state-aware behavior.
6. Verify equivalent before/after requests produce identical policy hashes.
7. Verify Bubblewrap and NanVix compatibility-routing tests remain unchanged.

## 9. Validation

Run from `src\`:

```text
cargo fmt --all -- --check
cargo test -p wxc_common
cargo test -p bwrap_common
cargo test -p nanvix_runner
cargo clippy --workspace --all-targets -- -D warnings
```

Use narrower test filters during development, but run the full commands above
before considering the refactor complete. No schema or SDK code-generation
command should produce a diff.

## 10. Acceptance criteria

The refactor is complete when:

1. Every exact adapter constructs an explicit `NormalizedNetworkInput`.
2. Only the v0.8 adapter performs field-based format classification.
3. v0.9, v1.0, and v1.1 exact contracts cannot reach a legacy network path.
4. `select_network_format` and `directional_network_version_error` no longer
   exist.
5. `parse_network_policy` does not receive contract version or
   `NetworkEnforcementCompatibility`.
6. All existing accepted and rejected requests retain their behavior and
   diagnostic routing.
7. Stable schemas and generated SDK artifacts are unchanged.
8. Policy hashes for equivalent requests are unchanged.
9. The targeted Rust tests and workspace lint pass.

## 11. Follow-up: retire runtime network compatibility

After this refactor, audit every production use of
`ExecutionRequest.network_enforcement_compatibility`.

The follow-up may remove that field only if:

1. Every backend distinction is derivable from explicit normalized policy
   state rather than contract history.
2. v0.6/v0.7 behavior remains representable without a provenance flag.
3. Policy identity continues to distinguish policies with different effective
   enforcement, without unnecessarily changing existing hashes.
4. Direct typed requests and exact JSON requests resolve to identical runtime
   semantics when their effective policies are identical.

This follow-up is deliberately separate because it affects backend routing and
policy identity, while the primary refactor changes only where network format
is resolved.
