# Process Container: Adding OS Features

This guide covers adding new OS-level features that flow through MXC's Windows
process container pipeline.

Exact v0.9 networking uses directional egress/ingress,
`runtimeConfig.networkProxy`, and ProcessContainer proxy-peer identity. Legacy
networking fields remain available under their published contracts. Backend
selection depends on host capability and requested policy, not schema version.

For which policy aspects this backend can enforce on each Windows 11 release,
see [Windows OS-version policy support](./os-version-support.md).

## Prerequisites

1. Read the [Sandbox Policy spec](../sandbox-policy/0.7.0/policy.md) to
   understand how `SandboxPolicy` maps to `ContainerConfig`.
2. Read [authoring-a-new-feature.md](../authoring-a-new-feature.md), especially
   Step 1 (feature spec) and Step 2 (OS changes).
3. Submit a feature spec so reviewers understand the end-to-end flow.

## Architecture recap

For the BaseContainer tier, the flow is:

```text
SandboxPolicy
  -> SDK: createConfigFromPolicy() -> ContainerConfig JSON
    -> wxc-exec: parses ContainerConfig
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

## Creation-policy results

Creation-policy reporting is explicitly opt-in. Requests omitting
`processContainer.policyEnforcement` retain legacy creation, preparation order,
error presentation, capture output, and probe JSON. The legacy OS API still
enforces administrative policy; omitting the controls is not an exemption.

For an explicit section, on hosts advertising `PSE_SUPPORT_POLICY_RESULT`
(`0x10`) through
`QueryProcessSecurityEnvironmentSupport` and exporting
`CreateProcessSecurityEnvironment2`, MXC captures the native V1 policy result
and its bounded array of action details.
An empty section or omitted `mode` selects pass-through: a policy refusal is
returned without changing the request. The HRESULT and policy outcome are
independent; provisioning can fail
after policy has passed. `NoApplicablePolicy` is an evaluated outcome, not a
substitute for an unavailable API.

The mutable `0.10.0-alpha` contract adds:

```json
{
  "processContainer": {
    "policyEnforcement": {
      "mode": "pass-through"
    }
  }
}
```

`mode` accepts only `pass-through`, and an empty section selects that mode.
No experimental execution authorization is required. Mutation and `maxAttempts`
are not supported inputs and are rejected before creation, including on hosts
without CPSE2. Published contracts do not accept this development-only section.

If CPSE2 is unavailable, or ordinary tier selection chooses AppContainer, these
reporting controls are ignored. Existing sandbox
restrictions and tier selection are unchanged. Explicitly configured controls
then report `unavailable` or `notApplicable`, not a fictitious policy success.
With an explicit section, the read-only probe exposes
`probes.baseContainerPolicyResultsAvailable`.
It requires the base security-environment contract, its required exports, a
successful support query containing `0x10`, and the CPSE2 export from the System32
`processmodel.dll`. It does not require discovery of the newer named API-set
group, attempt creation, inspect the caller's agentic tag, or evaluate policy.
`baseContainerCreate2ExportPresent`, `baseContainerSupportFlags`, and
`baseContainerSupportQueryHresult` expose the underlying probe evidence.
A runtime query failure is an error, not proof that the capability is absent.
A real policy refusal never triggers legacy creation or a weaker-tier retry.
Capability absence before a CPSE2 call produces an empty attempt journal. If
the initial CPSE2 call returns decision-free `E_NOTIMPL`, its unknown-outcome
attempt remains in the unavailable report before legacy creation. That response
must have no details and zero pooled resource counts. Neither case claims policy
evaluation succeeded.

Pass-through never changes the request or retries a policy refusal. The caller
can inspect the native decision and decide whether to author a different request.
Capture starts against the already-created environment without another creation;
the workload, trace startup, and later process-launch failures are never retried.

Reports appear at `error.details.policyEnforcement` on creation failures and
`outputMetadata.policyEnforcement` on success. They include raw native codes and
recognized names, HRESULTs, complete resource text when available, termination
reason, unchanged requested/effective policy hashes, and the creation attempt.
MXC reports use `reportVersion: 1`. Each `attempts[n].result` has one `outcome`
and a `details` array;
class/reason/action/resource/value fields belong to `details[m]`. The native
result version is 1. Detail counts are bounded by 64 and resources share
a 32,768-UTF-16-character pool; offsets and written/required counts are reported.
The subset is not an inventory of every policy conflict. Success and
non-actionable refusals may have no details. Unknown codes and flags survive;
incomplete resource text is never presented as a complete resource.
Native 64-bit requested/required detail values are decimal strings on the JSON wire.
Pass-through has at most one CPSE2 attempt and no setting changes. Native resource
text is bounded. The report vocabulary can describe other modes, but this
request contract does not authorize them.

Native live handles expose creation reports after spawn; denial-capture outputs
arrive after completion. Report-bearing buffered APIs retain diagnostics on
wait failure and timeout: Rust callers use `run_with_report()` or
`wait_with_output_and_report()`, not the legacy capture-only methods.
Live callers can inspect handle reports even when waiting fails,
before disposing the handle. `environmentCreated` refers to a CPSE environment,
not to whether an AppContainer workload ran when controls were ignored.
For explicit reporting, buffered wait failures also retain available capture
outputs under `error.details.outputMetadata`. Combined timeout/teardown
diagnostics remain in buffered warnings even when no ETL was sealed; Node
timeout exceptions retain those warnings in `details.warnings`. The CLI keeps
the underlying timeout/teardown message alongside its timeout classification.
Live report-enabled handles retain teardown failures in their warnings even
when the legacy wait API classifies the result only as a timeout.

For explicit reporting, the CLI emits a `type: "policyEnforcement"` diagnostic
record and enriches its error envelope. These stderr records are newline-delimited
even when prior
human or guest output did not end with a newline; readers should ignore blank
lines between records. Legacy Node PTY/ChildProcess APIs retain that protocol and their
existing return types. Mixed guest output is not an authenticated control channel:
use typed SDK results/errors, not terminal-output scraping, for automated retries.
Dry runs do not create an environment or claim that OS policy was evaluated.

### Caller compatibility

Node `spawnSandboxAsync` retains its three-field result and return type,
including when legacy denial capture is enabled. The additive
`spawnSandboxAsyncWithReport` exposes `outputMetadata`; native policy reporting
still requires explicit controls.
The Node error constructors and public .NET exception constructor are unchanged;
new absent .NET diagnostic properties are omitted from default JSON serialization.

Rust `Output` and the two-field `SandboxOutputMetadata` retain their public
construction and destructuring shapes. `Sandbox::wait_with_output()` returns
the original I/O error, preserving `raw_os_error()` and custom payload downcasts.
Use `run_with_report()` for a `ReportedOutput`, or
`Sandbox::policy_enforcement_report()` on a live handle. The additive
`wait_with_output_and_report()` returns `OutputError` on failure; its
`io_error()`, `output_metadata()`, and `policy_enforcement_report()` accessors
retain the original error and available diagnostics without wrapping a legacy
`std::io::Error`. Choosing these APIs alone does not enable policy reporting:
the request must still contain the controls.

The C ABI is co-versioned with its bindings. `MxcErrorDetail` adds one owned
JSON pointer, changing its size and embedded result layouts. Deploy matching
SDK, binding, and native artifacts from the same build together; replacing
only the native DLL or relying solely on the package version is not supported.
The shared runtime response DTO is internal plumbing, not the public Rust
SDK's preserved capture DTO.

The CPSE2 V1 contract uses a 48/40-byte native header and 56-byte detail stride.

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
src/core/generated/process_security_environment_specification/
```

### 3. Flow the policy through MXC

Update the exact development config contract, normalized wire model, runtime
model, and parser mapping. Follow
[authoring-a-new-feature.md](../authoring-a-new-feature.md) and regenerate the
development schemas and generated SDK wire types rather than editing generated
artifacts by hand.

### 4. Build the PSEC specification

Update the helpers under
`src/backends/process_container/common/src/base_container_helpers.rs` to encode
the runtime policy into the PSEC FlatBuffer. Update
`BaseContainerRunner::can_backend_service_request()` so the BaseContainer tier
is selected only when the single request-level decision reports that the
runtime OS can enforce the complete request.

If PSEC cannot represent the request, selection must continue to an
AppContainer tier that can fully enforce it. Never silently omit a requested
restriction.

### 5. Test end-to-end

Use a Windows build containing the processmodel change.

1. Add focused parsing and PSEC-construction tests.
2. Run `wxc-exec` with a config that enables the new field and verify the OS
   enforcement.
3. Exercise the corresponding SDK policy and verify the complete
   policy-to-OS flow.
4. Verify omission applies the intended secure default.
5. Verify an unsupported host selects a compatible AppContainer tier or returns
   an actionable error without weakening policy.

## Summary of files to touch

| Layer | Repo | File |
|-------|------|------|
| OS schema and enforcement | Microsoft Windows OS source (internal) | processmodel PSEC contract and implementation |
| MXC FlatBuffer copy | mxc | `external/windows-sdk/ProcessSecurityEnvironment.fbs` |
| MXC generated bindings | mxc | `src/core/generated/process_security_environment_specification/` |
| MXC specification builder | mxc | `src/backends/process_container/common/src/base_container_helpers.rs` |
| MXC executor and capability selection | mxc | `src/backends/process_container/common/src/base_container_runner.rs` |
| MXC Config schema | mxc | `schemas/dev/mxc-config.schema.*.json` |
| MXC SDK mapping | mxc | `sdk/node/src/sandbox.ts` |
| MXC SDK types | mxc | `sdk/node/src/types.ts` |
