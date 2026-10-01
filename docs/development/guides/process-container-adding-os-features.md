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
runtime model and then into that FlatBuffer.

## Policy-denied creation diagnostics

If security-environment creation returns `ERROR_ACCESS_DISABLED_BY_POLICY`
(`HRESULT 0x800704EC`, Win32 error 1260), MXC explains that an IT-managed
policy blocked the requested sandbox and recommends reviewing its requested
permissions or contacting the system administrator. This guidance is automatic
for ordinary creation and creation used by denial capture. It does not require
experimental authorization, alter the request, or retry creation.

The native operation/status and existing failure category are preserved.
Ordinary access-denied errors (`0x80070005`) and failures from capture-trace
APIs are not reclassified as sandbox-creation policy refusals. Existing
process-launch policy guidance remains applicable if the later launch fails.

### Detailed policy errors

On a selected BaseContainer path, default creation calls
`CreateProcessSecurityEnvironment` (CPSE) once. When the optional getter is
present and `QueryProcessSecurityEnvironmentSupport` advertises
`EXPERIMENTAL_PSE_SUPPORT_POLICY_RESULT` (`0x10`), MXC adds
`EXPERIMENTAL_PROCESS_SECURITY_ENVIRONMENT_FLAG_CAPTURE_POLICY_RESULT` (`0x2`)
to the native creation flags. This internal diagnostic opt-in applies to ordinary
creation, with or without denial capture. It does not
authorize mutation, change permissions or start a trace. Existing creation
flags are preserved; hosts without advertised support receive no added flag.

Only if creation returns
`HRESULT 0x800704EC`, MXC calls the optional
`Experimental_GetLastProcessSecurityEnvironmentPolicyResult` export from the same System32
`processmodel.dll`. Retrieval happens synchronously on the failing native thread,
before cleanup, logging, callbacks or another creation attempt can replace that
thread's snapshot. No new configuration field or experimental authorization is
needed; default tier selection, request validation and preparation order are unchanged.
Support is checked before creation using the existing immutable support cache,
never between a refusal and retrieval. If the optional support query fails,
MXC still calls creation with its original flags. A resulting policy refusal
includes the query failure as unavailable-diagnostic context, while successful
creation and other creation failures keep their original result.

A policy refusal can include a bounded batch of constraints in the existing
error message. A recognized outcome starts with
`Sandbox creation failed: blocked by IT policy.` or
`Sandbox creation failed: IT policy evaluation failed.`
Each detail includes class, reason, action, resource/value kinds, and requested
and required values. Known discriminators use readable names without numeric
enum tags; raw flags are not printed. Meaningful path counts and unknown
discriminator values remain available. Complete resource strings are quoted
and control characters escaped; missing, invalid, or truncated resource text is
identified explicitly. CPSE's original operation, HRESULT and failure category
remain authoritative; the native failure context follows the detailed guidance.
The getter's HRESULT describes retrieval, not creation. Refusal outcomes are
`unknown` (0), `blocked` (1) and `evaluationFailed` (2); the OS retains only the
last two. Successful creations and non-policy failures are not queried.

The getter takes the requested contract version, a byte-count output, and a
buffer-pointer output. MXC requests V1 and receives an independent allocation
containing a `PSEP` FlatBuffer, described by
`external/windows-sdk/ExperimentalProcessSecurityEnvironmentPolicyResult.fbs`.
Its Rust bindings are generated with the pinned compiler and schema provenance
used by the PSEC specification bindings. Normal builds use the checked-in
generated modules. PSEP is the source of truth for result versions, limits and
flags; the decoder uses its generated definitions.

MXC verifies the `PSEP` identifier, FlatBuffer structure, exact requested
version and `minimum_reader_version` before interpreting details. It bounds
the allocation to 128 KiB, details to 64, and the total resource budget to
32,768 UTF-16 units including the OS's accounting unit per resource.
Resource vectors contain UTF-16 code units without terminating NULs. Embedded
NULs, unpaired surrogates, missing complete resources, and unknown remedies
cannot authorize a repair. The public flags are
`HasActionableDetails` (`0x1`), `ResourceComplete` (`0x2`), and
`ResourceUnavailable` (`0x4`). The contract has capability-removal,
filesystem-access and path-count remedies.
There are no UI, Win32k, integrity-level, bitmask or boolean detail codes.
Use matching OS and MXC builds for this experimental contract. V1 tables are
append-only; a newer producer must project the explicitly requested V1 format.
MXC resolves only the experimental export.

Retrieval copies the cached snapshot without another RPC, policy evaluation
or creation attempt. It does not consume the snapshot. MXC owns the returned
allocation with a `CoTaskMemFree` guard, including malformed data or unexpected
non-null failure outputs. Diagnostic text and private repair hints are copied
before the allocation is released; later creation attempts cannot invalidate
them. The batch is non-exhaustive even when it is not full. An unconditional
denial or non-actionable failure may have no details. The added policy text is bounded to
256 KiB; every returned fixed detail is retained, while resource-text
truncation is marked as incomplete.
Every creation attempt clears the thread's previous snapshot, including an
attempt without the capture flag. Capture is best effort; enabling it does
not guarantee that a refusal payload is available.

#### Guidance in MXC request terms

When the returned detail has understood discriminators, actionable flags and
any required complete resource, MXC uses the effective request to explain which
configuration settings requested the permission. This applies to both ordinary
and capture-enabled creation, including run-to-completion and streaming SDK
calls. The guidance accompanies the original native detail and does not edit
the request.

| Native constraint | MXC guidance |
|---|---|
| Remove `internetClient` | Set `network.egress.default` to `deny` and remove the `network.egress.allow` rules that request egress. When native denial capture records network decisions, also omit `processContainer.captureDenials`: direct-mode capture requests this capability even with deny-default egress and capture mode `block`. The message identifies the effective sources. |
| Remove `privateNetworkClientServer` | Set `network.ingress.default` to `deny`. A configured ProcessContainer proxy requires this capability, so also omit `runtimeConfig.networkProxy` and its `processContainer.network.allowedProxyPeer` setting rather than leaving an invalid proxy request. |
| Remove `networkLoopback` | Set `network.ingress.hostLoopback` to `deny`. This setting can supply the effective capability without an authored capability-list entry. An identity-less proxy needs host-loopback access; omit it or deliberately choose a supported identity-scoped deployment. |
| Remove an explicitly requested capability | Remove the matching `processContainer.capabilities` entry when it remains effective. Supported request parsing supplies deny-default directional network policy even when `network` is omitted; PSEC construction filters its owned network-capability entries. MXC does not attribute those filtered entries as sources. |
| Remove `permissiveLearningMode` | Change `processContainer.captureDenials.mode` from `allow` to `block`, or omit capture; also disable audit if used. When normalization does not retain the specific audit entry point, the message says so rather than inventing one. Reserved learning-mode capabilities are controlled by their dedicated settings, not the capability list. |
| Restrict filesystem access | Review `filesystem.readwritePaths` or `filesystem.readonlyPaths`, including covering ancestors and aliases. Narrow/remove a grant, move an RW grant to RO, or add the indicated RO/deny exception while checking more-specific grants. Keep existing restrictive exceptions. |
| Reduce path count | Reduce the combined entries in `filesystem.readwritePaths`, `filesystem.readonlyPaths` and `filesystem.deniedPaths` to the returned maximum. `processContainer.filesystem.enumeratePaths` is not counted by this native remedy. Do not satisfy the budget by broadening grants or dropping restrictive exceptions. |

Use the corresponding typed V1 SDK request properties when calling an SDK;
the field paths in the message are MXC configuration paths. Multiple settings
can request the same capability: changing only an explicit list entry may not
remove the effective permission. Narrower network destinations or a proxy do
not make a policy-forbidden network capability acceptable.
Capture attribution uses the trace sources selected when MXC built the PSEC
request. Legacy access-only capture and proxy capture do not synthesize this
extra internet capability, so they do not receive that revision advice.

Unknown outcomes, flags, codes, contradictory values, unavailable/invalid
resource text, or a permission with no known request source do not produce a
guessed configuration edit. Filesystem resources remain comparison witnesses:
aliases and more-specific rules can change which authored grant is responsible.
Never use a displayed resource marked truncated as a configuration path.
The suggested revision is not a replacement policy or a promise that the next
call will succeed.

MXC never applies these actions, changes the submitted policy, or retries a
policy refusal. A caller may feed the message to an LLM or present it to a user,
then deliberately submit another acceptable request. Another request can expose
further conflicts. A path is a diagnostic witness, not a pinned filesystem
object or a complete administrative ceiling. Unknown or incomplete details are
not instructions to guess a repair.

If the getter export or advertised capture support is absent, MXC returns the
basic CPSE error unchanged.
Diagnostic capture is best effort: `ERROR_NOT_FOUND` means no cached snapshot
is available, and other getter failures are appended as unavailable-diagnostic
context without replacing the CPSE error. A failed getter is never decoded,
and MXC does not retry creation to obtain details. Support flags describe API
availability, not whether policy governs this caller.

Successful creation is determined by CPSE's HRESULT and a non-null owned
environment; no diagnostic getter is called. Success and capture output
shapes are unchanged. Failed creations retain their existing failure category
and exit behavior; policy details are text, not a new public report or error
field. The Rust, C, Node, and .NET error layouts are unchanged.

Read the ordinary SDK error's message. Do not parse this diagnostic prose as a
stable machine-readable contract, infer an exemption from absent details, or
blindly retry later launch/wait failures. Resource values can be sensitive;
forward them only to an appropriate recipient. Mixed CLI guest output is not
an authenticated source for automated decisions.

#### Validation requirements

Use a matching governed Windows host to validate creation refusals and the
versioned, allocation-returning PSEP getter. Cover ordinary and capture-enabled
creation, original error retention, diagnostic capture availability, and
returned-allocation ownership. Injected decoder and runner tests complement
this native proof; they do not establish OS interoperability or enforcement.
Follow the [validation runbook](../build-and-test/ci-validation-infrastructure.md)
for functional test selection, capable hosts and positive execution checks.

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
