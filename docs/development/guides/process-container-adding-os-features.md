# Process Container: Adding OS Features

> **Audience:** MXC developers

This guide covers adding new OS-level features that flow through MXC's Windows
process container pipeline.

Supported networking uses directional egress/ingress,
`runtimeConfig.networkProxy`, and ProcessContainer proxy-peer identity. Retired
networking fields are rejected by every registered contract. Backend
selection depends on host capability and requested policy, not schema version.

For which policy aspects this backend can enforce on each Windows 11 release,
see [Windows OS-version policy support](../../backends/process-container/os-version-support.md).

## Prerequisites

1. Read the [supported configuration schema](../../schema.md) for policy and
   request fields.
2. Read [authoring-a-new-feature.md](authoring-a-new-feature.md), especially
   Step 1 (feature spec) and Step 2 (OS changes).
3. Submit a feature spec so reviewers understand the end-to-end flow.

## Architecture recap

For native Windows ProcessContainer, the executor flow is:

```text
MXC request JSON
  -> wxc-exec: version-specific parsing and request binding
    -> mxc_engine: native ProcessContainer eligibility
      -> BaseContainerRunner: builds a PSEC FlatBuffer
        -> CreateProcessSecurityEnvironment (processmodel.dll)
          -> CreateProcessW with PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT
            -> OS applies restrictions
```

The PSEC FlatBuffer is the contract between MXC and the OS process security
environment. New features must flow from the versioned config contract into the
runtime model and then into that FlatBuffer. Policy preparation accepts
creation-policy observations separately from request JSON.

## Structured creation-policy failures and separate preparation

Strict creation performs one native creation attempt and executes only the
supplied request. A policy refusal can return owned `PolicyFailures` from that
attempt. Applications merge observations explicitly, then use V1.Dev
`prepare_policy_json` to obtain a candidate request and structured changes.
Preparation never calls `CreateProcessSecurityEnvironment` (CPSE), starts a
trace or executes a workload. The application inspects and accepts, edits or
rejects the candidate before submitting ordinary request JSON through strict
creation. The [Rust Dev reference](../../api-reference/rust/v1/dev.md#separate-policy-preparation)
documents the API, limits and candidate shape, and the
[compiled caller example](../../../src/mxc-sdk/examples/policy_feedback.rs)
shows consumption. The [.NET](../../api-reference/dotnet/v1/dev.md) and
[Node](../../api-reference/node/v1/dev.md) V1.Dev references document the
corresponding preparation APIs.

When the optional allocation-returning
`Experimental_GetLastProcessSecurityEnvironmentPolicyResult` getter is present
and support flags include `EXPERIMENTAL_PSE_SUPPORT_POLICY_RESULT` (`0x10`), MXC
adds the internal capture flag (`0x2`) to
`CreateProcessSecurityEnvironment` (CPSE).
This enables diagnostic capture only. It does not change the request. Only a
CPSE policy refusal (`HRESULT 0x800704EC`)
queries the getter; retrieval occurs synchronously on the failing native thread
before cleanup, callbacks or another creation can replace its snapshot.
Successful creation and unrelated failures do not query it.

The copied `PSEP` contract is in
`external/windows-sdk/ExperimentalProcessSecurityEnvironmentPolicyResult.fbs`.
Its Rust bindings and the PSEC bindings use the same regeneration gate
(`scripts/versioning/check-psec-codegen.js`).
The native decoder validates the identifier, requested V1/minimum reader
versions, FlatBuffer structure, and 128 KiB/64-detail/32,768-resource-unit
limits.
Resource arrays contain UTF-16 units without terminators, with one additional
accounting unit per resource. Allocations are independently owned and freed with
`CoTaskMemFree`, including unexpected non-null getter failure outputs.

Native observations retain their numeric codes, flags, resources and observed
values. Backend-specific data travels through `MxcError.details`, the public
SDK error, owned C error JSON, and the language adapters. Specific failures
never become error or warning text. The generic native operation/status remain
authoritative; missing or invalid diagnostics never imply approval.

On another policy refusal, the error contains the fresh batch; the caller
uses `PolicyFailures::merged_with` to retain distinct whole batches.
Batches are non-exhaustive: merged observations are not
the entire administrative policy. A later observation describes the reduced
request Windows evaluated, so preparation derives current restrictive
constraints without rewriting the stored observed values. Unknown, incomplete,
contradictory or unsafe instructions fail explicitly. Already-satisfied known
restrictions are harmless; compatible strengthening is applied conservatively.

Maintainer rules for preparation:

- Reuse the conservative backend reduction path. Supported edits
  remove capabilities and their network/capture producers, lower only matching
  existing writable path spellings to read-only, add safe deny exceptions, and
  remove exact duplicates to meet path budgets. Preserve restrictive exceptions
  and enumeration-only paths.

- Proxy removal must not activate direct-network permissions that were
  ineffective in proxy mode.

- Filesystem probes use the bounded existing probe facility and the current
  creator's context; do not guess at aliases, ambiguous spellings or
  unsupported root cases.

- Treat observations as untrusted data that can be reused across requests or
  creators. Every edit must remain restrictive relative to this call's request,
  and the selected native tier must enforce it.

- Project only required authoring edits into the original JSON so it keeps its
  contract version, metadata, optional-field presence, unrelated grants and
  current runtime proxy, certificate and capture settings. Capture changes use
  the dedicated `learningMode`/`captureDenials` fields; never insert reserved
  capability names into the authored capability array.

- Reparse the candidate through the original contract and check it against the
  prospective PSEC and effective policy. Return no partial candidate or
  truncated changes. Preparation owns no live environment, process or trace
  handles.

The application owns retries, persistence and acceptance. Neither preparation
nor acceptance is approval by Windows, which reevaluates every strict creation.
Successful creation uses the ordinary launch/capture and cleanup path and
returns normal results or handles. Each creation call makes one native creation
attempt and executes only the supplied request. MXC keeps no observations
between calls.

The Windows CLI uses strict creation and emits the current native observations
in its error envelope. A caller can save an accepted candidate's `requestJson`
as a normal MXC configuration and submit it through the usual CLI invocation.
The CLI does not prepare, merge or persist observations.
Its diagnostic records share stderr with workload output;
JSON shape is not authentication. Prefer direct SDK errors for an automated
retry controller.

The scheduled ProcessContainer SDK test
`dev_json_processcontainer_policy_feedback_restricts_current_request` and the
injected native/backend tests are described in the
[CI validation runbook](../build-and-test/ci-validation-infrastructure.md).

## Step-by-step

### 1. Update the OS PSEC schema and implementation

The source-of-truth schema and processmodel implementation live in the internal
Windows OS source tree. Add the new contract field, regenerate the OS bindings,
and implement the corresponding enforcement.

### 2. Update MXC's PSEC schema copy

Once the OS change is available on the target build, update:

```text
external/windows-sdk/ProcessSecurityEnvironment.fbs
```

Then regenerate the Rust bindings in:

```text
src/mxc-sdk/src/core/process_security_environment_spec/
```

### 3. Flow the policy through MXC

Update the exact development config contract, normalized wire model, runtime
model, and parser mapping. Follow
[authoring-a-new-feature.md](authoring-a-new-feature.md) and regenerate the
development schemas and generated SDK wire types rather than editing generated
artifacts by hand.

### 4. Build the PSEC specification

Update the helpers under
`src/mxc-sdk/src/backends/process_container/common/base_container_helpers.rs` to encode
the runtime policy into the PSEC FlatBuffer. Update
`BaseContainerRunner::can_backend_service_request()` so the native runner
is constructed only when the single request-level decision reports that the
runtime OS can enforce the complete request.

If PSEC cannot represent or enforce the request, reject it before creating a
container and return an actionable error. Do not fall back to AppContainer,
filesystem brokering, or host-DACL mutation, or silently omit a restriction.

### 5. Test end-to-end

Use a Windows build containing the processmodel change.

1. Add focused parsing and PSEC-construction tests.
2. Run `wxc-exec` with a config that enables the new field and verify the OS
   enforcement.
3. Exercise the corresponding SDK policy and verify the complete
   policy-to-OS flow.
4. Verify omission applies the intended secure default.
5. Verify an unsupported host rejects the request before container creation
   with an actionable error and without weakening policy.
6. Wire functional coverage into scheduled backend validation. For networking,
   extend `tests/scripts/run_base_container_network_tests.ps1`, including
   positive and negative controls.

## Summary of files to touch

| Layer | Repo | File |
|-------|------|------|
| OS schema and enforcement | Microsoft Windows OS source (internal) | processmodel PSEC contract and implementation |
| MXC FlatBuffer copy | mxc | `external/windows-sdk/ProcessSecurityEnvironment.fbs` |
| MXC generated bindings | mxc | `src/mxc-sdk/src/core/process_security_environment_spec/` |
| MXC specification builder | mxc | `src/mxc-sdk/src/backends/process_container/common/base_container_helpers.rs` |
| MXC executor and capability selection | mxc | `src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs` |
| MXC Config schema | mxc | `schemas/dev/mxc-config.schema.*.json` |
| MXC SDK mapping | mxc | `sdk/node/src/v1/container.ts` |
| MXC SDK types | mxc | `sdk/node/src/v1/types.ts` |
