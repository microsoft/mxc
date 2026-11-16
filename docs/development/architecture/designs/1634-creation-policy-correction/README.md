# Feature design: caller-owned Windows policy preparation

> **Audience:** MXC developers

- **Status:** Accepted
- **Issue:** [#1634](https://github.com/microsoft/mxc/issues/1634)
- **Contributor:** @rossnichols
- **Implementation PRs:** None submitted.

Return structured native creation-policy failures and provide a separate
operation that prepares a candidate restricted request without creating a
container. The application inspects, accepts, edits or rejects that candidate,
then submits its chosen JSON through ordinary strict creation. The application
owns storage, merging and retry limits; MXC owns interpreting supported
observations and proving each proposed change restrictive.
Public declarations and caller examples are in the [API proposal](api.md).
An [exploratory implementation](https://github.com/microsoft/mxc/commit/90ce226f6b0e779abc8dfb541fe5dfb71d5697ae)
illustrates the accepted contract; implementation delivery remains separate.

## Problem and scope

An application or coding agent can request a container that Windows
administrative policy refuses. It needs machine-readable reasons without
parsing error text, and control over whether a reduced request still serves
its task. MXC must not decide to retry or retain restrictions for that caller.

Two usage scenarios:

1. **Inspect a strict refusal.** A request grants read-write access to
   `C:\work\repo`, but the creator has a read-only ceiling there. Creation fails
   without launching the command. Its ordinary error retains high-level
   managed-policy guidance, native operation and HRESULT; structured details
   identify the observation. The caller can stop or author a different request
   and submit it strictly. No request object or file changes.

2. **Prepare, inspect and choose.** A strict call returns observations A.
   Preparation takes a request and A and returns a candidate plus its exact
   changes, including lowering the matching writable grant to read-only.
   Preparation creates no container. The application can reject the candidate
   without executing anything, edit it, or accept and submit it through strict
   creation. If that attempt returns B, the application can merge A+B and
   prepare again. It can also reuse observations with another request or
   creator; every candidate is checked afresh and Windows evaluates creation
   in the current creator's context.

A restrictive change can still make a task impossible. Supplying observations
requests a proposal, not execution or acceptance. Applications may automate
acceptance using their own rules, or author a different request directly.

Non-goals: transformation inside creation; automatic retries; MXC-owned
storage or a creator-scoped cache; policy approval tokens; successful-creation
change reports; policy details in ordinary error/warning text; bypassing policy
or switching containment; changing workload code; or redesigning stdin, PTY
or lifecycle operations.

## Proposed behavior

### Strict creation and structured refusal

- Creation is always strict. It receives only the caller-selected request,
  never observations, and does not edit that request or apply remembered
  restrictions.
- On native `CreateProcessSecurityEnvironment` policy refusal, preserve the
  error category, operation and HRESULT. The ordinary message retains
  high-level IT-managed-policy, permission-review and administrator guidance.
  Specific capabilities, paths, failure-class/reason/action codes and observed
  values belong only in structured details, never error, debug/console or
  warning text.
- Resolve the optional
  `Experimental_GetLastProcessSecurityEnvironmentPolicyResult` from the same
  System32 `processmodel.dll` used for creation. Request V1 PSEP capture only
  when the getter exists and Windows advertises capture support. This is
  separate from preparation, denial tracing and experimental-backend
  authorization.
- For the policy-refusal HRESULT, retrieve the snapshot synchronously on the
  failing native thread before cleanup/callbacks can replace it. Do not query
  it for success or unrelated failures. Validate the identifier, bounds,
  versions and resources, copy owned observations and free every native output
  with `CoTaskMemFree`, including unexpected non-null failure output.
- Expose available observations as `Error.details.policyFailures` and typed
  V1.Dev extraction/storage helpers. Unavailable diagnostics do not replace the
  authoritative native error or become a guessed failure.

### Separate preparation and caller acceptance

V1.Dev preparation takes complete MXC request JSON, required `PolicyFailures`,
and separate extensible `PolicyPreparationOptions`. No creation option or
request JSON field carries observations. See [api.md](api.md).

1. Parse the request through its registered authoring contract and select the
   ordinary backend. Validate observation shape, format and input limits.
   Preparation requires a serviceable native Windows ProcessContainer
   create-and-run path; never ignore unsupported input or obtain a fallback.
2. Build a fresh private request, including current certificate/proxy inputs
   and permissions derived from capture. Apply only recognized restrictive
   constraints, retaining unrelated grants and restrictive exceptions.
3. Project required changes into the original authoring JSON. Preserve its
   contract, metadata and optional-field presence, including supported section
   aliases. Reparse the candidate and verify its prospective effective policy
   and PSEC against the restricted request. Pin `process.cwd` if reductions
   would otherwise change the original inferred working directory.
4. Return `PreparedPolicyRequest`: complete candidate request JSON and ordered
   changes. Each change has an operation, JSON Pointer, and required before
   and after JSON values. Arrays may be reported as one replacement. Unsafe
   projection fails explicitly; no partial candidate or truncated report.

Preparation may query host support and perform bounded filesystem probes.
It does not call `CreateProcessSecurityEnvironment`, start a trace, create a
container or execute a workload.

The application separately inspects, accepts, edits or rejects the candidate.
Ordinary strict creation of the chosen JSON makes at most one native creation
attempt. A further refusal contains fresh observations from that attempt, not
caller history. Success returns the normal result/process and warnings,
without a policy-correction report or warning text.

| Recognized constraint | Permitted restrictive application |
| --- | --- |
| Forbidden effective capability | Remove the capability and every understood enabling network/capture setting. Removing a proxy must not activate direct-network allowances that were ineffective in proxy mode. |
| Forbidden permissive learning or logging | Disable the behavior, or change capture from allow to block when that satisfies the constraint. |
| Read-only filesystem ceiling | Lower an existing matching writable path to read-only; do not introduce a grant from a diagnostic witness or downgrade an unrelated ancestor. |
| No-access filesystem ceiling | Add a safe deny exception and remove only coincident grants, preserving other restrictive exceptions. |
| Path-count ceiling | Remove exact duplicate entries only; never discard distinct restrictive rules or broaden a grant. |

Unknown versions/outcomes/actions/flags, evaluation failures, contradictory
constraints within one native batch, incomplete resources, unsafe aliases,
malformed paths and unresolved safety checks cannot authorize application.
Enumeration-only paths retain their separate semantics. Preserve the workload,
environment and original inferred working directory. Recheck all combined
constraints so one reduction cannot reintroduce a previously removed permission.

### Caller-owned observations and bounds

`PolicyFailures` is an owned value containing native batches, not the complete
administrative policy. SDK merge helpers return a new bounded history in
first-seen order, deduplicating identical whole batches without changing either
input. Keep batch boundaries, detail order, native versions, unknown codes/flag
bits, observed values and resource presence. Preparation combines compatible
ceilings conservatively; it never rewrites historical observations as
current-request facts.

| Bound | Preparation observations | JSON storage and merge |
| --- | ---: | ---: |
| UTF-8 bytes | 4 MiB | 4.5 MiB |
| Native batches | 64 | 65 |
| Total details | 1,024 | 1,088 |
| Resource accounting units | 262,144 | 294,912 |

Each batch has at most 64 details and 32,768 resource accounting units.
Each present resource counts its UTF-16 array length plus one, including an
empty array. A fresh native result is separately bounded to 128 KiB.
The larger storage bounds allow one final native batch beyond preparation
input limits. An over-limit merge fails while both inputs remain intact; it
never silently truncates or substitutes a smaller history.
`policyFeedbackError: { code, reason }` marks unsafe application or overflow;
automatic callers stop on its presence, including unknown codes. Parsing
stored observations does not establish preparation eligibility.

When fresh diagnostics cannot be obtained, an error can carry
`policyResultUnavailable`; the application already owns earlier observations.
Repeated observations or an unchanged candidate are not progress. The
application decides its budget and stops on terminal markers, unsupported
outcomes or unrelated errors. An eight-creation-call budget in an example is
application policy, not an MXC retry limit.

Preparation accepts at most 8 MiB of request UTF-8 and returns at most 32 MiB
of complete result JSON with 4,096 changes. A stored candidate can exceed the
8 MiB input limit when the entire result fits. Restoring a prepared result
validates storage shape and bounds, not acceptance or current policy.

MXC retains no observations between calls. Caller-owned storage can cross
processes and creators because observations are untrusted advisory data, not
cached approval. Every proposed edit is proved against the current request
and Windows reevaluates creation. Stale observations may remain stricter than
current policy; the application chooses its inputs and accepted request.

## Execution and container lifecycle support

| Operation | Planned behavior |
| --- | --- |
| V1.Dev policy preparation | Prepare a native Windows create-and-run request without creation or execution; return owned candidate and changes. |
| Dev captured create-and-run | Strict creation of caller-chosen JSON; fresh structured refusal where available. Ordinary output/timeout results remain. |
| Dev creation with live pipes | Same strict creation semantics and normal process/stream ownership. Writable stdin is unchanged. |
| Typed V1 creation | Existing signatures/options remain. Generic error details may carry native refusal data; typed extraction/preparation belongs to V1.Dev. |
| Creation with a PTY | Existing behavior remains; no preparation control or observation input on PTY creation. No broader structured terminal channel is promised. |
| Provision, start, execute in an existing container, stop, deprovision | Unchanged; preparation rejects these request phases. No persistent ProcessContainer lifecycle is added. |
| Probe, discovery, dry-run validation | Unchanged; preparation is a distinct operation, not dry-run creation or policy approval. |
| Denial capture | Existing native trace prerequisites remain; preparation accounts for capture-derived permissions but starts no trace. |
| CLI, including audit/setup/management | Ordinary strict behavior and existing error transport; no observation-input or preparation command is proposed. |

No persistent container or negotiation-session ID is introduced.
Create-and-run owns execution and teardown; returned live handles retain their
normal caller disposal/stream/wait responsibilities.

## Backend applicability and availability

This table concerns the feature, not whether a backend can otherwise run.

| Backend | Planned support | Required host features and how they are checked | What the probe/availability API reports |
| --- | --- | --- | --- |
| ProcessContainer | Yes, native Windows path only | Existing PSEC/request-version checks. Resolve the optional getter and advertised capture support for fresh diagnostics; denial capture retains separate checks. | Existing serviceability/request-error results, not policy approval or guaranteed diagnostic availability. |
| WSLC | No; different creation/enforcement system | Preparation rejects this backend; no new host checks. Ordinary execution remains unchanged. | Unchanged backend availability. |
| LXC | No; no Windows policy result | Same. | Unchanged. |
| Bubblewrap | No; no Windows policy result | Same. | Unchanged. |
| Seatbelt | No; no Windows policy result | Same. | Unchanged. |
| IsolationSession | No; persistent lifecycle is outside this proposal | Same. | Unchanged. |
| Windows Sandbox | No; VM lifecycle is outside this proposal | Same. | Unchanged. |
| MicroVM | No; not the native ProcessContainer path | Same. | Unchanged. |
| Hyperlight | No; not the native ProcessContainer path | Same. | Unchanged. |
| VM containment intent | Not applicable; selects a concrete backend | Existing routing does not authorize preparation on that backend. | Existing resolved-backend result. |

ProcessContainer can be available while fresh refusal reporting is unavailable.
An otherwise valid native creation still works without the optional getter.
MXC can depend on the Windows policy-result API when runtime detection finds
the getter and advertised reporting support. Runtime capability detection is
the support requirement; no minimum Windows build is inferred from a request
or SDK version.
Preparation of supplied observations remains subject to request/serviceability
and safety checks; it does not require obtaining a fresh refusal first.
Creation errors cannot return history they were not given. API availability
does not establish that the current creator is subject to administrative policy.

No new public feature probe, backend, or experimental-backend status change
is proposed. Unsupported preparation fails explicitly, without creating a
container, selecting fallback or weakening permissions.

## Contracts, APIs, and compatibility

- **MXC request fields/defaults change: No.** Observations are preparation
  arguments outside request JSON. Candidates use existing authoring fields;
  published contracts/generated request schemas remain unchanged.
- **Public APIs change: Yes, additive.** V1.Dev owns preparation,
  observations, candidates, changes and storage/merge helpers. Existing V1
  creation signatures/options, including V1.Dev, remain supported.
  See [api.md](api.md).
- **Rust creation source break: No.** Keep `JsonOptions { experimental: bool }`
  lifetime-free and exhaustive. Only new preparation options/results and
  observation types are non-exhaustive; a new SDK major is unnecessary for
  this additive feature.
- **Runtime behavior changes:** refusal errors gain structured details while
  retaining high-level policy guidance, category, operation and native status.
  Preparation only proposes edits. The caller selects the JSON for a
  separate strict creation call. There is no automatic retry or hidden reuse.
- PSEC requests, PSEP native results, MXC feedback `formatVersion` and MXC
  request `version` are separate contracts. Pin/generate the experimental
  native schema through the existing provenance gate; do not change released
  request schemas to carry feedback.
- Native library and adapters are co-versioned. Change structured-error/
  preparation transport, generated C# bindings, Node layouts and freeing
  contracts together; do not promise arbitrary old/new FFI interoperability.
  SDK releases follow the [versioning policy](../../versioning.md); Windows
  API availability is detected at runtime as described above.

## Design and security

`mxc_engine` remains the single router. SDKs/FFI transport observations,
candidate JSON and structured error details. The ProcessContainer backend
owns host checks and restrictive permission derivation; the engine projects
and verifies authoring JSON through existing contract parsing. Shared DTOs
stay passive. Binaries delegate routing; no new implementation crate or
parallel launch path is needed.

```mermaid
sequenceDiagram
    participant App as Application
    participant MXC
    participant Windows
    App->>MXC: Strict creation(request JSON)
    MXC->>Windows: One native creation attempt
    alt Policy refusal
        Windows-->>MXC: Native failure and optional observations
        MXC-->>App: Error with fresh structured observations
        App->>App: Inspect and optionally merge/store observations
        App->>MXC: Prepare(request JSON, observations, preparation options)
        MXC->>MXC: Restrict, project and verify; no creation
        MXC-->>App: Candidate request JSON and exact changes
        App->>App: Accept, edit or reject
        opt Caller chooses another creation
            App->>MXC: Strict creation(chosen request JSON)
            MXC->>Windows: One native creation attempt
            Windows-->>MXC: Current-policy result
            MXC-->>App: Ordinary result/process or fresh error
        end
    else Creation succeeds
        Windows-->>MXC: Owned environment
        MXC-->>App: Normal execution result or live process
    end
```

Feedback is not an authorization token from Windows. Resource text is a
comparison witness, not a pinned object or complete policy ceiling. Reuse
normal filesystem probes and literal-path/alias/root checks; preserve
restrictive exceptions and prove effective access cannot increase. Probes
retain their bounded waits/workers, but synchronous native creation/getter
calls do not acquire a new end-to-end cancellation/deadline guarantee.

Observations can contain sensitive paths/capability names. Do not render them
into ordinary error, debug/console or warning text. The application controls
storage and access to explicit structured serialization. This feature adds
no telemetry consent or data collection.

The main alternative is diagnostics-only operation with caller-authored
changes. That remains available without preparation. Shared transformation
logic avoids duplicating subtle permission-reduction rules in applications,
while a separate preparation operation keeps acceptance independent of
execution. Combining transformation and creation would prevent inspection of
the actual candidate before execution and is not proposed.

## Resource ownership and failure recovery

Windows owns policy evaluation/enforcement. MXC independently owns/frees each
native result buffer and owns environments, traces, jobs, pipes and processes
until transfer through the existing runner. SDK extractors copy feedback before
native memory is freed. The caller owns stored observations and returned live
handles. No host policy/ACL change, remote service state or stored approval is
created by preparation.

| Failure stage | Recovery and caller-visible outcome |
| --- | --- |
| Invalid/unsafe preparation input or projection | Fail without native creation; discard private edits and return no partial candidate. Caller request/observations remain intact. Structured terminal context where applicable; no workload. |
| Caller rejects a candidate | No creation or execution. The caller owns candidate/observation storage and may discard or edit it. |
| Native policy refusal | Free failed outputs and return the original failure plus fresh observations or unavailable-diagnostic context. Do not retry or merge caller history internally. |
| Storage/merge or preparation limit exceeded | Fail explicitly. Merge leaves both inputs intact; preparation returns no truncated report or partial candidate. Storage allowance is not preparation eligibility. |
| Trace, pipe/job preparation or launch after environment success | Normal cleanup releases owned resources; preserve the primary failure. No feedback-driven relaunch. |
| Workload timeout, wait failure or caller disposal | Existing termination/wait/cleanup behavior and output semantics remain; never interpret as a safe policy retry. |
| Cancellation or creator exit | Existing SDK cancellation contracts apply; dispose late unclaimed handles. Caller storage is independent and survives only when the caller persists it. |
| Cleanup also fails | Preserve the primary error and observable cleanup context through existing errors/warnings, without policy specifics. Do not invent a successful close result or recovery ID. |

Each later creation uses a fresh environment and current Windows evaluation;
preparation results own no native handles or partial container. There is no
partially mutated persistent container to resume. Callers use normal process disposal
and existing artifact/operational cleanup; the native close API exposes no
additional close status. See [SDK differences](api.md#inputs-results-and-sdk-differences).

## Acceptance criteria and validation plan

These are implementation acceptance requirements, not results from this
documentation-only PR. Unit/injected tests complement native enforcement.
Use trusted instrumentation for exact creation/trace/launch counts; absence
of workload markers alone cannot prove that no transient environment was created.

| Scenario | Input/action and exact assertion |
| --- | --- |
| Strict policy refusal | Inject a native policy refusal with captured observations: one refusal, unchanged request, high-level policy guidance/status, fresh structured details and zero workload markers. |
| Caller A -> prepare -> B -> merge -> prepare -> success | Inject successive native refusal/success outcomes through separate creation, preparation and acceptance calls. Assert zero preparation creation/trace/launch counts, at most one native attempt per creation, complete caller-owned merging, unchanged input and only the accepted workload launches. |
| Preparation, rejection and explicit acceptance | Use nonempty restrictions; compare original/candidate JSON and every reported edit independently. Reject once with no execution, then accept and submit only the chosen JSON through strict run/spawn. A stale approval must not accept another changed candidate. |
| Public SDK and changed-request reuse | Extend Rust `dev_json_processcontainer_policy_feedback_restricts_current_request`, .NET `DevJson_CapturesOutputAndStreamsInput`, and Node `V1.Dev prepares filesystem ceilings for caller-accepted strict creation`: cross real bindings, deny restricted writes, allow an unrelated writable control, preserve cwd/stdin/output and round-trip storage. |
| Different creator and stale observations | Prepare a fresh request using stored observations from another creator/current policy: verify restrictive applicability, then reevaluate Windows during creation. No creator-cache key or approval reuse. |
| Native decode/ownership/support | Cover absent getter/unadvertised or failed support, failed getter, malformed/bounded versions/resources and unexpected native outputs: preserve original failure and free every allocation once. |
| Restriction interactions | Decode submitted PSEC for current CA/proxy/capture inputs, stronger/repeated/satisfied constraints, intra-batch contradictions, deny/alias/root/enumeration rules and duplicate-only path budgets. Assert no access increase or permission reintroduction. |
| Unknown data, limits and terminal state | Preserve unknown codes/flags, full u64 values and absent/empty/malformed resources. Over-limit merging leaves inputs intact; unsafe or over-limit preparation returns no partial result. Missing fresh data cannot invent progress. |
| Errors, cleanup and cancellation | Policy details never appear in ordinary error/debug/console/warning text. Unrelated launch/wait/cleanup failures retain normal semantics and never relaunch. Verify disposed/late handles and subsequent fresh creation. |
| Unsupported surfaces and compatibility | Preparation rejects another backend or non-create-and-run phase, including empty observations. Existing Rust Dev literals/lifetime-free storage and all creation/stdin/PTY/lifecycle signatures remain usable. Strict old-host creation remains available. |
| Cross-SDK storage/ABI/AOT | Public extraction/merging, required before/after JSON values, null-versus-absence operations, JSON Pointers and limits survive storage and owned native transport. Source-generated .NET net8.0/net10.0 and AOT roots must not fall back to reflection. |

Run the public preparation and strict-creation cases in the existing scheduled
`process` suite in
`scripts/ci/run_backend_validation_tests.ps1`, reached through
`Validation.Tests.Scheduled.yml` and `Validation.Tests.Matrix.Job.yml`, with
architecture-matched SDK bundles from
`scripts/ci/build-windows-sdk-test-bundle.ps1`. Require discovered, positive,
non-skipped native/public-SDK results on suitable Windows x64/ARM64 hosts.

Use supplied observations for public preparation tests and injected native
outcomes for refusal capture, getter failures and exact native-attempt counts.
The public cases must still check actual filesystem enforcement, caller
acceptance, cwd/stdin and unchanged input through the real SDK/native bindings.
Existing CI gates remain unchanged.
See the [validation runbook](../../../build-and-test/ci-validation-infrastructure.md).

## Delivery and documentation

After this accepted feature/API spec is merged:

1. Deliver native capture/ownership, structured error transport and owned
   observation storage, with refusal and unknown-data coverage.
2. Deliver restrictive derivation and authoring JSON projection through the
   separate preparation API, then public Dev candidate/change storage and
   caller-controlled acceptance examples. Keep strict creation unchanged.
3. Wire public-SDK acceptance into the scheduled suite and document runtime
   host-capability detection before delivery.

Each implementation slice must preserve strict callers and be buildable.
MXC request-contract publication and experimental-backend authorization do
not change. Update ProcessContainer guidance and the validation runbook;
SDK references/examples are listed in
[api.md](api.md#validation-and-documentation). Keep #1634 open through agreed
implementation, validation and documentation.

## Open questions

None.

## Review checklist

- [x] The issue has maintainer-applied `feature-accepted`; scope and contributor are agreed.
- [x] One or two meaningful usage examples, non-goals, defaults, and failure behavior are clear.
- [x] Every backend is considered, with explicit capability checks and probe/availability behavior.
- [x] Execution modes and container lifecycle support are explicit; exclusions are explained.
- [x] Resource ownership, partial failures, failed cleanup, and subsequent container creation are addressed.
- [x] Security, contract/API compatibility, and any breaking changes are addressed.
- [x] A separate API proposal is linked when public APIs change.
- [x] Acceptance criteria and the CI plan cover observable behavior.
- [x] Delivery and documentation changes are scoped; material questions are resolved.
- [x] Answers are concise; diagrams explain the design without repeating the text.
- [x] Maintainers have approved the spec and its status is Accepted before merge.
