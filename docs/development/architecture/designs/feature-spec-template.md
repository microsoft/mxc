# Feature design: feature name

> **Audience:** MXC developers

<!--
Copy to <issue-number>-<feature-name>/README.md under this directory.
For example: 1234-container-export/README.md.
Keep supporting API proposals, diagrams, and other files in that folder.
Use these questions to guide the design discussion, not as a request for a
finished design before review. Mark open questions for discussion.
Short bullets and yes/no answers are welcome when sufficient; explain
decisions, changed behavior, and risks. For irrelevant sections, write
"Not applicable" and a short reason. Link existing context rather than
repeating it. The same guidance applies to human and AI-assisted drafts.
Keep Status as Proposed until a maintainer approves the design.
Then change it to Accepted before merge.
Follow the acceptance and spec-review process in:
https://github.com/microsoft/mxc/blob/main/docs/development/guides/authoring-a-new-feature.md
-->

- **Status:** Proposed
- **Issue:** Link the tracking issue.
- **Contributor:** GitHub username(s), for example `@username`.
- **Implementation PRs:** Not started.

## Problem and scope

- Who has the problem, and what can they not do today?
- How does this feature solve that problem?
- Give two distinct usage examples with concrete inputs, expected outcomes,
  and cleanup where needed. If only one meaningful scenario exists, give one
  and say so; do not invent a second.
- What will this feature not cover?

## Proposed behavior

- What does the caller provide, and what result do they receive?
- Which execution, container lifecycle, discovery, or validation operations
  change? Mark the others unchanged.
- What are the defaults? What happens when a value is omitted or empty?
- What happens on unsupported requests, errors, or cancellation?

## Execution and container lifecycle support

- How will the feature work with run-to-completion execution and buffered
  output, live stdio streaming (stdin/stdout/stderr), and interactive PTY
  sessions? State support and explain any limitations or exclusions for each
  affected backend, both for create-and-run execution and execution in an
  existing container.
- Will container lifecycle operations be supported: provision, start, execute,
  stop, and deprovision? Describe supported operations, valid call order,
  and what state persists between calls. Explain any unsupported operations
  or operations that do nothing.
- How does create-and-run execution relate to those lifecycle operations?
  Explain any differences in behavior or cleanup.

## Backend applicability and availability

Use one row per existing or proposed backend. State planned support as
Yes, No, or Not applicable. Explain No or Not applicable briefly.

| Backend | Planned support | Required host features and how they are checked | What the probe/availability API reports |
| --- | --- | --- | --- |
| Name | Yes / No / Not applicable; reason | OS/build, capabilities, and runtime checks | Available / unavailable / cannot determine; result or error |

- Can the backend run but lack support for this feature? If yes, how is that detected?
- Does this add an experimental backend or change an existing backend's
  experimental status? If yes, describe the change.
- How are requests rejected when their policy cannot be enforced?

## Contracts, APIs, and compatibility

An MXC request contract defines the JSON fields and values accepted for a
request version. Its JSON schema is generated from Rust types. Policy fields
request permissions or restrictions, such as `network.egress.default` for
outbound network access. Public SDK inputs are separate types that may map
to these fields. See
[MXC request JSON](https://github.com/microsoft/mxc/blob/main/docs/schema.md#mxc-request-json).

- Do MXC request fields or their defaults change? Yes/No. If yes, name each
  field, its allowed values, what happens when it is omitted, and the affected
  request versions. Do not edit published request contracts.
- Do public APIs change? Yes/No. If yes, create a separate `api.md` using the
  [API proposal](https://github.com/microsoft/mxc/blob/main/docs/development/architecture/designs/api-spec-template.md)
  template in the feature folder and link it here.
  Split proposals only for distinct API areas; review them in the same spec PR.
- Does this break existing callers or change their behavior? Yes/No.
  If yes, identify the break and the new version or migration needed.
  Keep supported published API versions working.

## Design and security

- Which existing components change, and what will each one do?
- Show the main interactions or data flow with a small Mermaid diagram when
  it is clearer than text. Prefer sequence, data-flow, or state diagrams.
  Do not draw every function.
- Does this change isolation, permissions, trust, or resource ownership?
  Yes/No. If yes, explain the change, enforcement, and cleanup.
- Is a large refactor or new crate proposed? Yes/No. If yes, explain why.
  Internal engine and backend code must stay in `mxc-sdk` modules.
- What is the main alternative, and why was it not chosen?

Report vulnerabilities through
[SECURITY.md](https://github.com/microsoft/mxc/blob/main/SECURITY.md), not a public spec.

## Resource ownership and failure recovery

The **MXC backend adapter** may rely on a runtime, OS service, cloud service,
or device to create and manage containers. Name the systems involved and
distinguish their responsibilities from MXC's and the caller's. Cover both
local and remote state and resources where applicable.

- Who owns container state and resources at each lifecycle stage, and who
  releases them? Include processes, storage, mounts, network configuration,
  and temporary files where applicable.
- If an operation fails, times out, or is cancelled partway through, what state
  remains? What cleanup does MXC attempt, and what cleanup or recovery mechanism
  do those systems provide? Address caller or MXC process exit, loss of
  connectivity, and an unavailable service or device where applicable.
- If cleanup also fails, what can remain on the host, in the cloud service,
  or on the device? How does the caller learn
  about both the original failure and the cleanup failure, identify leftover
  resources, and retry cleanup or remove them manually?
- What happens on the next attempt to create a container of the same backend
  type after cleanup failed? Explain whether creation proceeds independently,
  retries cleanup, or fails with an actionable error. How are leftover state,
  identifiers, and shared resources kept from affecting the new container?
- For an existing container left partially changed, can the caller retry the
  operation or continue using it? Explain how its state is determined and
  when it must be stopped or deprovisioned.

## Acceptance criteria and validation plan

A **host** is the machine running MXC: name its OS/build, architecture, and
required features. A **CI suite** is a group of automated tests: name the
test script or test group and the workflow/job that runs it.

- What observable results prove the feature works? List pass/fail conditions.
- Which functional or regression tests will check them? Name the SDK operations,
  backends, hosts, and CI suites that will run them.
- How will tests cover unsupported hosts, probes, policy interactions,
  omitted/empty values, errors, and cleanup? Mark cases that do not apply.
- Which scenarios cover the claimed execution modes and lifecycle operations,
  partial failures, cleanup failure, and a subsequent container creation?
  Include any recovery steps and leftover resources the tests will check.
- Are any CI checks being removed or replaced? Yes/No. If yes, explain how
  coverage is preserved. List anything that cannot be tested.

For each distinct scenario, state the input or action and the exact result
the test will assert. Name the test to extend, or mark it as a proposed test
and explain how it will run in CI. Full test code is not needed in the spec.
Report actual test results in the implementation PR.

Use the
[validation runbook](https://github.com/microsoft/mxc/blob/main/docs/development/build-and-test/ci-validation-infrastructure.md)
to find the relevant backend suite and CI hosts.

## Delivery and documentation

- Which schema, backend, and SDK PRs are needed, and in what order?
  List contract publication and experimental authorization changes separately.
- Which consumer guides, API references, and examples need updates?
  Keep implementation details in developer docs.
- Link API proposals and other supporting documents in this folder.

## Open questions

What decisions remain, and who will resolve them? Write "None" if there are none.
Resolve questions that affect the design before approval.

## Review checklist

- [ ] The issue has maintainer-applied `feature-accepted`; scope and contributor are agreed.
- [ ] One or two meaningful usage examples, non-goals, defaults, and failure behavior are clear.
- [ ] Every backend is considered, with explicit capability checks and probe/availability behavior.
- [ ] Execution modes and container lifecycle support are explicit; exclusions are explained.
- [ ] Resource ownership, partial failures, failed cleanup, and subsequent container creation are addressed.
- [ ] Security, contract/API compatibility, and any breaking changes are addressed.
- [ ] A separate API proposal is linked when public APIs change.
- [ ] Acceptance criteria and the CI plan cover observable behavior.
- [ ] Delivery and documentation changes are scoped; material questions are resolved.
- [ ] Answers are concise; diagrams explain the design without repeating the text.
- [ ] Maintainers have approved the spec and its status is Accepted before merge.
