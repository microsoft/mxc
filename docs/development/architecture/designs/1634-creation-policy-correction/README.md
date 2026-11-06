# Feature design: caller-owned Windows creation-policy feedback

> **Audience:** MXC developers

- **Status:** Proposed
- **Issue:** [#1634](https://github.com/microsoft/mxc/issues/1634)
- **Contributor:** @rossnichols
- **Implementation PRs:** None submitted; maintainer scope acceptance and spec approval remain pending.

Return structured native creation-policy failures and optionally accept them
on a caller-selected later creation. The application owns storage, retry
limits and the decision to accept restrictions. MXC owns interpreting supported
native observations and proving each applied change restrictive.
Public declarations and caller examples are in the [API proposal](api.md).
An [exploratory implementation](https://github.com/microsoft/mxc/commit/6e04aa415e6e1f1bf901bfb76b7ebdc957bc6083)
illustrates the contract; it is not API, release or implementation-PR approval.

## Problem and scope

An application or coding agent can request a container that Windows
administrative policy refuses. It needs machine-readable reasons without
parsing error text, and control over whether a reduced request still serves
its task. MXC must not decide to retry or retain restrictions for that caller.

Two usage scenarios:

1. **Inspect a strict refusal.** A request grants read-write access to
   `C:\work\repo`, but the creator has a read-only ceiling there. Creation fails
   without launching the command. Its ordinary error retains policy-specific
   high-level guidance, native operation and HRESULT; structured details
   identify the observation. The caller can stop or author a different request
   and submit it strictly. No request object or file changes.

2. **Resubmit and reuse observations.** A first call returns failure A. The
   application decides that its restrictions are acceptable, stores A, and
   makes a new call with the original request plus A. MXC applies supported
   safe restrictions and attempts creation once. A further refusal returns
   cumulative A+B; a later caller-selected call can succeed. Stored feedback
   can also be supplied with a changed request or another creator; MXC checks
   that request afresh and Windows evaluates its current creator.

Supplying feedback is explicit permission to apply its supported restrictive
constraints, not proof that the resulting behavior meets the application's
needs. A restrictive change can still make a task impossible. Callers that
require direct control can inspect the failures, edit their own request and
omit feedback instead.

Non-goals: automatic retries; MXC-owned storage or a creator-scoped cache;
policy approval tokens; successful-creation change reports; policy details
in ordinary error/warning text; bypassing policy or switching containment;
changing workload code; or redesigning stdin, PTY or lifecycle operations.

## Proposed behavior

### Strict creation and structured refusal

- Omitted feedback means strict creation. Do not apply a remembered restriction
  or edit the caller's MXC request JSON.
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
  separate from feedback authorization, denial tracing and experimental-backend
  authorization.
- For the policy-refusal HRESULT, retrieve the snapshot synchronously on the
  failing native thread before cleanup/callbacks can replace it. Do not query
  it for success or unrelated failures. Validate the identifier, bounds,
  versions and resources, copy owned observations and free every native output
  with `CoTaskMemFree`, including unexpected non-null failure output.
- Expose available observations as `Error.details.policyFailures` and typed
  V1.Dev extraction/storage helpers. Unavailable diagnostics do not replace the
  authoritative native error or become a guessed failure.

### Caller-selected resubmission

Feedback is an invocation option, not an MXC request JSON field or a blanket
boolean mutation mode. It is supported only by V1.Dev JSON creation APIs and
the corresponding Windows CLI input described in [api.md](api.md).

For each supplied value:

1. Parse the unchanged request through its registered contract and select the
   ordinary backend. Validate feedback shape, format and limits. Explicit
   feedback requires the serviceable native Windows ProcessContainer path;
   never ignore it or obtain a fallback backend.
2. Prepare a fresh request, including current certificate/proxy inputs and
   permissions derived from capture. Apply only recognized constraints to a
   private copy, retaining unrelated grants and restrictive exceptions.
3. Revalidate and rebuild derived state. Make at most one native creation
   attempt. Invalid feedback or an unsafe required change fails before that
   attempt. Only successful creation can launch the workload, at most once.
4. On refusal, return the cumulative observations. On success, use the normal
   output/process path with its existing warnings and ownership. Do not add a
   policy-correction warning or a successful-creation report.

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

### Cumulative observations and bounds

`PolicyFailures` is an owned value containing distinct native batches, not the
complete administrative policy. A further refusal returns all known supplied
observations plus the new batch, deduplicating identical whole batches. Keep
batch boundaries, order, native versions, unknown codes/flag bits, observed
values and resource presence. Combine compatible ceilings conservatively for
application; do not rewrite historical observations as current-request facts.

| Bound | Invocation feedback | JSON storage |
| --- | ---: | ---: |
| UTF-8 bytes | 4 MiB | 4.5 MiB |
| Native batches | 64 | 65 |
| Total details | 1,024 | 1,088 |
| Resource accounting units | 262,144 | 294,912 |

Each batch has at most 64 details and 32,768 resource accounting units.
Each present resource counts its UTF-16 array length plus one, including an
empty array. A fresh native result is separately bounded to 128 KiB.
The larger storage bounds retain one final native batch in full, never a
truncated report. `policyFeedbackError: { code, reason }` marks unsafe
application or overflow; automatic callers stop on its presence, including
unknown codes. Parsing stored feedback does not establish replay eligibility.

When fresh diagnostics cannot be obtained, retain supplied observations and
add structured `policyResultUnavailable` context. An unchanged cumulative
snapshot is not progress. The application decides its budget and stops on
terminal markers, unsupported outcomes or unrelated errors. An eight-call
budget in an example is application policy, not an MXC retry limit.

MXC retains no observations between calls. Caller-owned storage can cross
processes and creators because feedback is untrusted advisory data, not cached
approval. Every edit is proved against the current request and Windows
reevaluates creation. Stale feedback may remain stricter than current policy;
the application decides whether to omit it.

## Execution and container lifecycle support

| Operation | Planned behavior |
| --- | --- |
| Dev captured create-and-run | Structured refusal and optional supplied feedback; ordinary output/timeout results remain. |
| Dev creation with live pipes | Same creation semantics; prepare streams/capture from the effective request and transfer the normal process handle. Existing stdin behavior is unchanged. |
| Typed V1 creation | No feedback option in this proposal. Generic error details may carry a native refusal; typed extraction belongs to V1.Dev. |
| Creation with a PTY | No feedback option; reject an attempted shared-options feedback value. Existing PTY behavior remains. |
| Provision, start, execute in an existing container, stop, deprovision | Unchanged; supplied creation feedback is rejected. No persistent ProcessContainer lifecycle is added. |
| Probe, discovery, dry-run validation | No feedback application or creation retry; supplied feedback is rejected. |
| Denial capture | Existing native trace prerequisites remain; safe application accounts for capture-derived permissions. |
| Audit/setup/management CLI modes | No feedback input; reject conflicting CLI combinations. |

No persistent container or negotiation-session ID is introduced.
Create-and-run owns execution and teardown; returned live handles retain their
normal caller disposal/stream/wait responsibilities.

## Backend applicability and availability

This table concerns the feature, not whether a backend can otherwise run.

| Backend | Planned support | Required host features and how they are checked | What the probe/availability API reports |
| --- | --- | --- | --- |
| ProcessContainer | Yes, native Windows path only | Existing PSEC/request-version checks. Resolve the optional getter and advertised capture support for fresh diagnostics; denial capture retains separate checks. | Existing serviceability/request-error results, not policy approval or guaranteed diagnostic availability. |
| WSLC | No; different creation/enforcement system | Reject supplied feedback before creation; no new host checks. | Unchanged backend availability. |
| LXC | No; no Windows policy result | Same. | Unchanged. |
| Bubblewrap | No; no Windows policy result | Same. | Unchanged. |
| Seatbelt | No; no Windows policy result | Same. | Unchanged. |
| IsolationSession | No; persistent lifecycle is outside this proposal | Same. | Unchanged. |
| Windows Sandbox | No; VM lifecycle is outside this proposal | Same. | Unchanged. |
| MicroVM | No; not the native ProcessContainer path | Same. | Unchanged. |
| Hyperlight | No; not the native ProcessContainer path | Same. | Unchanged. |
| VM containment intent | Not applicable; selects a concrete backend | Existing routing does not authorize feedback on that backend. | Existing resolved-backend result. |

ProcessContainer can be available while fresh refusal reporting is unavailable.
An otherwise valid native creation still works without the optional getter.
Supplied observations remain subject to normal request/serviceability and
safety checks; a refusal without a usable fresh result retains prior feedback
with unavailable-diagnostic context. Do not infer governance or a minimum
Windows build from a schema version or export/support bit.

No new public feature probe, backend, or experimental-backend status change
is proposed. Unsupported policy and unsupported feedback paths fail explicitly
before creation, without fallback or permission weakening.

## Contracts, APIs, and compatibility

- **MXC request fields/defaults change: No.** Feedback is outside the request
  JSON; published contracts/generated request schemas remain unchanged.
- **Public APIs change: Yes.** V1.Dev owns the typed observations,
  extraction/storage helpers and creation option. Stable typed V1 creation
  signatures/options remain unchanged. See [api.md](api.md).
- **Rust Dev source break: Yes, intentional.** Extending `JsonOptions` and
  making it non-exhaustive breaks existing Dev struct literals. Construct with
  `Default`; feedback DTOs are also non-exhaustive. This is an explicit
  Dev-only compatibility exception for maintainer approval, not a claim that
  all existing Rust Dev callers still compile.
- **Runtime behavior changes:** refusal errors gain structured details while
  retaining high-level policy guidance, category, operation and native status.
  Only supplying feedback authorizes restrictive application on a later call.
  There is no automatic retry or hidden reuse.
- PSEC requests, PSEP native results, MXC feedback `formatVersion` and MXC
  request `version` are separate contracts. Pin/generate the experimental
  native schema through the existing provenance gate; do not change released
  request schemas to carry feedback.
- Native library and adapters are co-versioned. Change structured-error/
  feedback transport, generated C# bindings, Node layouts and freeing
  contracts together; do not promise arbitrary old/new FFI interoperability.
  SDK release version and OS-contract shipping eligibility require maintainer
  agreement under the [versioning policy](../../versioning.md).

## Design and security

`mxc_engine` remains the single router. SDKs/FFI transport caller-owned feedback
and structured error details; the ProcessContainer backend owns preparation,
validation and restrictive application. Shared DTOs stay passive. Binaries
delegate routing, and no new implementation crate or parallel launch path is
needed.

```mermaid
sequenceDiagram
    participant App as Application
    participant MXC
    participant Windows
    App->>MXC: Creation(request JSON, optional prior feedback)
    MXC->>MXC: Validate; safely restrict a private request if supplied
    MXC->>Windows: One native creation attempt
    alt Policy refusal
        Windows-->>MXC: Native failure and optional observations
        MXC-->>App: Error with cumulative structured feedback
        App->>App: Inspect, store, decide whether to make a new call
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

The main alternative is diagnostics-only operation with caller-edited request
JSON. That remains available by omitting feedback. The proposed feedback
option keeps native permission interpretation and safety checks in MXC while
leaving every resubmission and task-appropriateness decision with the caller;
the authorization boundary remains a review question below.

## Resource ownership and failure recovery

Windows owns policy evaluation/enforcement. MXC independently owns/frees each
native result buffer and owns environments, traces, jobs, pipes and processes
until transfer through the existing runner. SDK extractors copy feedback before
native memory is freed. The caller owns stored observations and returned live
handles. No host policy/ACL change, remote service state or stored approval is
created by feedback application.

| Failure stage | Recovery and caller-visible outcome |
| --- | --- |
| Invalid/unsafe supplied feedback | Fail before native creation; discard private edits. Preserve inspectable observations and structured terminal context where applicable. No workload. |
| Native policy refusal | Free failed outputs and return the original failure plus cumulative observations or unavailable-diagnostic context. Do not retry internally. |
| Cumulative limit exceeded | Preserve the complete bounded terminal report, mark it terminal, and stop replay; never silently truncate or replace it with only the newest batch. |
| Trace, pipe/job preparation or launch after environment success | Normal cleanup releases owned resources; preserve the primary failure. No feedback-driven relaunch. |
| Workload timeout, wait failure or caller disposal | Existing termination/wait/cleanup behavior and output semantics remain; never interpret as a safe policy retry. |
| Cancellation or creator exit | Existing SDK cancellation contracts apply; dispose late unclaimed handles. Caller storage is independent and survives only when the caller persists it. |
| Cleanup also fails | Preserve the primary error and observable cleanup context through existing errors/warnings, without policy specifics. Do not invent a successful close result or recovery ID. |

Each later creation uses a fresh environment and current Windows evaluation;
feedback owns no native handles or partial container. There is no partially
mutated persistent container to resume. Callers use normal process disposal
and existing artifact/operational cleanup; the native close API exposes no
additional close status. See [SDK differences](api.md#inputs-results-and-sdk-differences).

## Acceptance criteria and validation plan

These are implementation acceptance requirements, not results from this
documentation-only PR. Unit/injected tests complement native enforcement.

| Scenario | Input/action and exact assertion |
| --- | --- |
| Strict governed refusal, proposed public-SDK test | Govern the actual creator, request a forbidden grant and omit feedback: one refusal, unchanged request, high-level policy guidance/status, structured details and zero workload markers. |
| Caller A -> A+B -> success, proposed governed test | Make three distinct public creation calls with caller-owned cumulative feedback. Assert one native attempt per call, no automatic retry, complete stored observations, unchanged input and only one workload launch. |
| Explicit replay and changed-request reuse | Introduce/extend the prototype's `dev_json_processcontainer_policy_feedback_restricts_current_request`: enforce read-only access, keep an unrelated writable control/current inputs and original working directory, round-trip storage and reuse with another request. |
| Different creator and stale feedback | Supply stored observations from a different creator/current policy: reevaluate Windows policy, retain only restrictive applicability, and allow the caller to omit stale restrictions. No creator-cache key or approval reuse. |
| Native decode/ownership/support | Cover absent getter/unadvertised or failed support, failed getter, malformed/bounded versions/resources and unexpected native outputs: preserve original failure and free every allocation once. |
| Restriction interactions | Decode submitted PSEC for current CA/proxy/capture inputs, stronger/repeated/satisfied constraints, intra-batch contradictions, deny/alias/root/enumeration rules and duplicate-only path budgets. Assert no access increase or permission reintroduction. |
| Unknown data, limits and terminal state | Preserve unknown codes/flags, full u64 values and absent/empty/malformed resources. Input overflow fails before creation; terminal overflow retains all known batches. Missing fresh data cannot invent progress. |
| Errors, cleanup and cancellation | Policy details never appear in ordinary error/debug/console/warning text. Unrelated launch/wait/cleanup failures retain normal semantics and never relaunch. Verify disposed/late handles and subsequent fresh creation. |
| Unsupported surfaces | Feedback on another backend, PTY/lifecycle/validation or conflicting CLI mode rejects before creation, including an explicitly supplied empty feedback value. Strict old-host creation remains available. |
| Cross-SDK storage/ABI/AOT | Public extraction, owned copies and serialization preserve batch boundaries/types and native status. Update co-versioned bindings; source-generated .NET net8.0/net10.0 and AOT roots must not fall back to reflection. |

Use the existing scheduled `process` suite in
`scripts/ci/run_backend_validation_tests.ps1`, reached through
`Validation.Tests.Scheduled.yml` and `Validation.Tests.Matrix.Job.yml`, with
architecture-matched SDK bundles from
`scripts/ci/build-windows-sdk-test-bundle.ps1`. Require discovered, positive,
non-skipped native/public-SDK results on suitable Windows x64/ARM64 hosts.

Explicit-feedback replay coverage does not install administrative policy and
does not prove fresh governed refusal capture. Required governed cases need
a maintained fixture that verifies the creator is actually governed and
restores exact policy/security state. Fixture ownership, matching host images
and scheduled jobs remain prerequisites for functional acceptance. Manual
prototype runs are not scheduled-CI coverage.

No CI gate is removed or weakened. Use injected faults for ownership cases
unsafe to induce on production hosts, with real-host positive controls.
See the [validation runbook](../../../build-and-test/ci-validation-infrastructure.md).

## Delivery and documentation

After maintainer acceptance and approval/merge of this feature/API spec:

1. Deliver native capture/ownership, structured error transport and owned
   observation storage, with refusal and unknown-data coverage.
2. Deliver safe caller-supplied feedback application through the ordinary
   backend path, public Dev APIs and CLI, with no internal retry/cache.
3. Wire governed/public-SDK acceptance into the scheduled suite and document
   supported host capabilities and release constraints before delivery.

Each implementation slice must preserve strict callers and be buildable.
MXC request-contract publication and experimental-backend authorization do
not change. Update ProcessContainer guidance and the validation runbook;
SDK references/examples are listed in
[api.md](api.md#validation-and-documentation). Keep #1634 open through agreed
implementation, validation and documentation.

## Open questions

- **Scope acceptance:** maintainers must apply `feature-accepted` and approve
  the design/API; those approvals have not been recorded.
- **Feedback authorization:** is supplying observations sufficient explicit
  permission for MXC's supported restrictive edits, or should the supported
  feature require caller-edited request JSON only? This proposal chooses the
  feedback option while preserving strict diagnostics-only use.
- **Dev compatibility and release:** approve the explicit Rust V1.Dev source
  break/non-exhaustive types and decide supported SDK/OS-contract shipping
  criteria. No new request version or experimental flag substitutes for that
  decision.
- **Governed CI:** agree on maintained setup/restore, matching x64/ARM64 images
  and required scheduled jobs before functional acceptance.

## Review checklist

- [ ] The issue has maintainer-applied `feature-accepted`; scope and contributor are agreed.
- [x] One or two meaningful usage examples, non-goals, defaults, and failure behavior are clear.
- [x] Every backend is considered, with explicit capability checks and probe/availability behavior.
- [x] Execution modes and container lifecycle support are explicit; exclusions are explained.
- [x] Resource ownership, partial failures, failed cleanup, and subsequent container creation are addressed.
- [x] Security, contract/API compatibility, and any breaking changes are addressed.
- [x] A separate API proposal is linked when public APIs change.
- [x] Acceptance criteria and the CI plan cover observable behavior.
- [ ] Delivery and documentation changes are scoped; material questions are resolved.
- [x] Answers are concise; diagrams explain the design without repeating the text.
- [ ] Maintainers have approved the spec and its status is Accepted before merge.
