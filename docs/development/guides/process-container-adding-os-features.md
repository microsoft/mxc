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

### Detailed policy errors

On a selected BaseContainer path, MXC calls
`CreateProcessSecurityEnvironment` (CPSE) once. Only if it returns
`HRESULT 0x800704EC`, MXC calls the optional
`GetLastProcessSecurityEnvironmentPolicyResult` export from the same System32
`processmodel.dll`. Retrieval happens synchronously on the failing native thread,
before cleanup, logging, callbacks or another creation attempt can replace that
thread's snapshot. No new configuration field or experimental authorization is
needed; tier selection, request validation and preparation order are unchanged.

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

The native V1 contract has a 48/40-byte header and a 48-byte detail stride.
Each detail carries `ResourceCharsWritten`; only the aggregate header carries
`ResourceCharsRequired`. The public flags are `HasActionableDetails` (`0x1`),
`ResourceComplete` (`0x2`), and `ResourceUnavailable` (`0x4`). The current
contract has capability-removal, filesystem-access and path-count remedies.
There are no UI, Win32k, integrity-level, bitmask or boolean detail codes.
This unpublished native contract was revised in place; use matching OS and
MXC builds. MXC does not decode the preceding prototype layout.
MXC allocates its maximum 64 details and 32,768 UTF-16 resource characters once,
after the policy refusal. Retrieval copies the cached snapshot without another
RPC, policy evaluation or creation attempt. It does not consume the snapshot.
The returned batch is non-exhaustive, even when it is not full. An unconditional denial or
non-actionable failure may have no details. The added policy text is bounded to
256 KiB; every returned fixed detail is retained, while resource-text
truncation is marked as incomplete.

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

If the getter export is absent, MXC returns the basic CPSE error unchanged.
Diagnostic capture is best effort: `ERROR_NOT_FOUND` means no cached snapshot
is available, and other getter failures are appended as unavailable-diagnostic
context without replacing the CPSE error. A failed getter does not populate the
arrays, including `ERROR_INSUFFICIENT_BUFFER`, so MXC never decodes them on
failure or retries creation to obtain details. Support flag
`PSE_SUPPORT_POLICY_RESULT` (`0x10`) advertises the getter contract, but MXC does
not need an extra support query to attempt optional retrieval after a refusal.

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

#### Validation scope

After rebasing onto upstream `525d0f25`, validation on October 15, 2026 passed
70 CLI, Node and .NET cases plus 11 direct native snapshot checks on
`ge-uxip-261014-Desktop`. Requests used the stable `1.0.0` contract and typed
V1 SDK APIs. Coverage includes the internet capability synthesized by
network-decision capture, other effective capability sources, proxy
dependencies, permissive capture, restrictive filesystem revisions, path-count
limits, default denial and caller-authored compliant requests.
Managed `Run`, `RunAsync`, `Spawn` and `SpawnAsync`, and Node `run` and `spawn`,
retained the original refusal and MXC guidance. The native probe verified the
48-byte detail layout, same-thread ownership, non-consuming retrieval,
short-buffer behavior and snapshot clearing.

The VM's existing Node 26.8.1 was used. Administrative policy and owned workloads
were restored; the OS, policy tools and runtimes were not replaced. Runtime
evidence is x64 only, not x86, ARM64, non-Windows or interactive UI coverage.
Focused local checks passed 194 Rust SDK, one FFI, 131 Node and five .NET tests,
plus formatting, Clippy and native builds.

A separate upstream native proxy host-to-container ingress test timed out
with socket error 10060 on both the rebased basic-error baseline and the
diagnostics build, on the local host and this VM. It is retained as a failed
broader networking check, not counted as a pass; this update does not change
that proxy implementation. The successful matrix above validates creation
refusals and their feedback, not positive proxy-ingress reachability.

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
| MXC generated bindings | mxc | `src/mxc-sdk/src/core/process_security_environment_spec/` |
| MXC specification builder | mxc | `src/mxc-sdk/src/backends/process_container/common/base_container_helpers.rs` |
| MXC executor and capability selection | mxc | `src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs` |
| MXC Config schema | mxc | `schemas/dev/mxc-config.schema.*.json` |
| MXC SDK mapping | mxc | `sdk/node/src/sandbox.ts` |
| MXC SDK types | mxc | `sdk/node/src/types.ts` |
