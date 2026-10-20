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
environment. New policy fields must flow from the versioned config contract into
the runtime model and then into that FlatBuffer. Invocation-only authorization,
such as creation-policy mutation, is supplied by the caller outside request JSON.

## Policy-denied creation diagnostics

If security-environment creation returns `ERROR_ACCESS_DISABLED_BY_POLICY`
(`HRESULT 0x800704EC`, Win32 error 1260), MXC explains that an IT-managed
policy blocked the requested sandbox and recommends reviewing its requested
permissions or contacting the system administrator. This guidance is automatic
for ordinary creation and creation used by denial capture. It does not require
experimental authorization. Default creation neither changes the effective
request nor retries creation; explicit mutation APIs are described below.

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
to the native creation flags. This internal diagnostic opt-in applies to strict
and mutation-enabled creation, with or without denial capture. It does not
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

Default creation never applies these actions or retries a policy refusal.
A caller may feed the message to an LLM or present it to a user,
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

### Opt-in creation-policy mutation

Callers can explicitly authorize MXC to apply restrictive corrections before
launching a workload. Creation stays strict unless its invocation opts in.
Authorization is per invocation, never read from request JSON or granted by an
administrative policy, and does not imply experimental-backend authorization.

| Caller | Opt-in creation operation | Mutation text |
|---|---|---|
| Rust V1.1 revision | `v1_1::run` / `spawn` with `RunOptions.mutate_policy` / `SpawnOptions.mutate_policy` | `ExecutionResult.warnings`, `MxcProcess::warnings()` |
| Node V1 | `run` / `spawn` with `options.mutatePolicy` | `ExecutionResult.warnings`, `MxcProcess.warnings` |
| .NET V1 | `MxcContainer.Run[Async]` / `Spawn[Async]` with `options.MutatePolicy` | `ExecutionResult.Warnings`, `MxcProcess.Warnings` |
| Windows CLI | `wxc-exec --mutate-policy config.json` | stderr warnings |
| Internal C adapter | `mxc_run_with_policy_mutation_json`, `mxc_spawn_with_policy_mutation_json` | Existing run-result warnings / process warning getter |

All mutation options default to `false`. Rust's scoped `v1_1` revision preserves
published V1 option literals and reuses V1 request/result types and the `1.0.0`
request contract. It does not bump SDK package versions or introduce a new
configuration schema. Node and .NET retain their V1 entry points and add the
control to creation options. .NET cancellation behavior is unchanged.

The CLI keeps `--mutate-policy` separate from `config.json`: the file states the
requested permissions, while the caller separately authorizes MXC to revise
them for this invocation. SDK operation options express the same distinction.

The dedicated C exports retain existing argument and result layouts;
`experimental` remains only experimental-backend authorization. Older native
libraries without those exports reject opted-in calls, not strict calls; there
is no silent strict fallback. No structured creation-change API is exposed.

Only a serviceable native Windows ProcessContainer/BaseContainer path supports
mutation. Missing backend support or an unsupported request is not repaired by
switching tiers or weakening validation. PTY and container lifecycle operations
have no mutation option. The CLI rejects combining `--mutate-policy` with audit,
probe, dry-run, lifecycle or setup/management modes.

After a refusal, the same synchronous getter supplies ordinary diagnostic text
and private owned hints. A repair batch requires `blocked` outcome 1, valid
header/storage/counts, and only understood, actionable details with complete
resources where required. Evaluation failure, unknown codes/flags, malformed or
incomplete resources, contradictory constraints, or an unmatched request source
cannot authorize a guessed correction. MXC never parses diagnostic prose to
decide a repair.

Supported corrections are deliberately narrower than the advisory guidance:

| Constraint | Automatic restrictive change |
|---|---|
| Forbidden capability | Remove matching effective entries and all understood enabling network/capture settings. Deny egress and remove allow rules for `internetClient`; omit network-decision capture when it still needs that capability. Deny private ingress or host loopback as appropriate. When a proxy must be disabled, deny direct egress, private ingress and host loopback before leaving proxy mode; retain deny rules and omit capture if it would introduce direct-egress capability. |
| Forbidden permissive learning | Change capture from `allow` to `block`, or disable the corresponding learning behavior. If logging itself is forbidden, omit capture/logging. |
| Read-only ceiling | Lower only an existing exact writable path spelling to read-only. Do not introduce a new grant from a native witness or downgrade an unrelated ancestor. |
| No-access ceiling | Add a deny exception and remove only coincident grant entries, preserving existing restrictive exceptions and checking that effective access never increases. Further conflicts may appear on reevaluation. |
| Path-count ceiling | Remove exact duplicate entries within RW, RO and deny lists. Never discard distinct grants/deny exceptions or combine them into broader grants to meet the limit. Enumeration-only paths are not counted. |

Filesystem repairs require absolute literal DOS/UNC names and successful,
unaliased canonical resolution of every relevant path, including absent tails.
Ambiguous/device/wildcard paths, unresolved aliases and writable volume/share
roots are rejected. Enumeration-only paths are preserved verbatim and do not
gate filesystem repairs: they are neither data-access comparison points nor
entries in the native path-count budget. Normal backend validation still
checks that the requested enumeration policy can be enforced. Access is checked
at old/new grant and deny boundaries so removing an exception cannot reopen
access. These checks do not pin filesystem objects or disclose the complete ceiling.

Proxy and direct networking use different PSEC policy forms, so capability-set
inclusion alone is not a monotonicity proof. Opted-in normalized requests must
satisfy the same proxy/posture compatibility rules as parsed creation requests
before CPSE is called. Removing a proxy never activates previously ineffective
direct-network allowances. Selected-tier checks also apply to explicitly forced
test tiers; forcing AppContainer does not override mutation's native-only rule.

MXC applies a whole batch atomically to a private request clone and revalidates
it for the selected native tier. It makes at most eight CPSE attempts including
the first, stops on repeated specifications/refusals or no supported progress,
and bounds mutation notes to 1 MiB. Only creation is retried, before any workload
launch. Dependent capture paths, environment and stdio are prepared from the
effective request. The successful security-environment owner is reused for
optional trace start and process creation; it is not created again. RAII closes
unsuccessful or abandoned owners.

Successful calls return ordinary output/handles plus mutation descriptions,
not a replacement policy. New corrections use warning text beginning
`Sandbox configuration updated due to IT policy`, for example:

```text
Sandbox configuration updated due to IT policy: filesystem.deniedPaths: [] -> ["C:\\Users\\AdminUser\\Desktop\\denied"]
```

Descriptions contain JSON-serialized before/after field values. Only newly
negotiated corrections are reported; applying remembered restrictions alone
emits no mutation warning. Other policy or operational warnings remain
independent of mutation notifications.

A later workload failure is not a repair instruction
and never causes replay. Failed negotiation preserves the authoritative native
error and appends why mutation stopped and any earlier attempted corrections.
Caller objects and policy files are never rewritten. Mutation notes quote
configuration values as data; they and diagnostic errors are text for a person
or agent, not a stable structured parsing contract. A valid revision may expose
another constraint or still leave the workload unable to run.

#### In-process reuse

The native retry loop automatically remembers successful restrictive
corrections for opted-in creation. No caller-owned context, extra SDK option,
C handle or request field is required. Strict creation does not read or apply
this cache.

Entries are partitioned by the creator's process/effective token identities
and modification identifiers. They retain supported narrowing hints, not whole
permission-policy snapshots. Before reuse, the ordinary repair logic checks
the hint's relevant current inputs and reapplies the narrowing to a fresh
request clone. Already-satisfied restrictions need no edit. Unsupported or
inapplicable hints are not guessed.

Unrelated current fields are neither replayed from old state nor compared as
whole-policy cache identity. A new credential-CA filename, proxy endpoint,
unrelated grant, command, environment, container identity, timeout or diagnostic
output path does not invalidate an otherwise applicable narrowing edit. Those
values remain the current request's values unless the supported repair itself
must restrict them. No proxy credentials or unrelated permissions are retained.

A hit supplies validated narrowing edits, not an approval. Backend validation
and Windows creation run again every time. Further refusals can tighten that
entry; failed negotiation leaves its successful contents intact. Learning
commits when native environment creation succeeds, even if later trace startup
or workload execution fails. Cache access and negotiation are serialized in
the loaded native module; the lock is released before workload launch/wait.

The cache retains at most 16 entries and 4 MiB of owned narrowing-hint
state, with the ordinary per-creation attempt and text limits. Eviction,
process exit, native-library unload or a different key causes fresh negotiation
from the caller's request. It is an optimization, not durable policy storage.
Node keeps the mutation native module loaded between opted-in calls; policy
state itself remains entirely in MXC.

If Windows accepts the remembered restrictions, the cache hit is silent. If it
requires further narrowing, MXC reports only the newly negotiated corrections
and retains the combined hints after successful environment creation. A failed
negotiation does not replace a successful entry. Cache identity/retention
failures are reported without bypassing ordinary negotiation. An interrupted
cache is cleared before reuse. No disk persistence is used; invocation options
and ordinary results are unchanged by reuse.
Effective-policy audit identity is recorded independently of mutation warnings,
including when remembered restrictions are applied silently.

Typed notifications are recorded separately in the
[deferred policy-changes API proposal](../plans/policy-changes-api-proposal.md).
That proposal is not part of the supported SDK or native adapter surface.

#### Prior diagnostics-only validation (October 15, 2026)

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
