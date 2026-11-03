# Adding a new feature

> **Audience:** MXC developers

This is the feature workflow for executor binaries and the Rust, .NET, and
Node SDKs. For general contribution, build, and PR guidance, see
[CONTRIBUTING.md](../../../CONTRIBUTING.md).
Maintainer responsibilities are in [MAINTAINERS.md](../../../MAINTAINERS.md).

You are welcome to start with a problem or a rough idea. A complete design is
not needed to begin the conversation. The goal is to shape a useful feature
together and settle important design questions before you invest in implementation.

| Where you are | Start here |
| --- | --- |
| You have a feature idea | [Open or find an issue](#1-start-with-a-github-issue). |
| Maintainers accepted the issue | [Agree on the design](#2-agree-on-the-design). |
| Your issue is accepted and any required spec is approved and merged | [Choose the implementation layers](#choose-the-layers-to-change). |

## 1. Start with a GitHub issue

Find or open an issue describing the problem and desired behavior. Share your
use case and, if you would like to contribute, say so. Maintainers will help
discuss scope, related work, and whether a spec is needed before you write one.

A maintainer records the agreed scope and contributor with `feature-accepted`.
This gives design work a shared starting point; it is not a release commitment
or a completed design review. If the next step is unclear, ask in the issue.

Use the issue to discuss scope or contributor changes. If the agreed direction
needs to change, maintainers will explain why and work through the options with
you before more effort goes into the affected work.

For security reports, follow [SECURITY.md](../../../SECURITY.md), not a public issue.

## 2. Agree on the design

### When a spec is required

An approved and merged spec PR is required for:

- Request schema or policy changes, including defaults and enforcement.
- New or changed public APIs.
- New backends.
- Large refactors or new crates.

These requirements also apply when the change is filed as a bug fix or task.
Ordinary bug fixes and documentation corrections do not automatically need a
spec. Small features outside these categories can use an approach agreed in
the issue once scope is accepted. For other changes, maintainers will explain
if a spec is needed and which questions it should resolve.

### Write the spec

After acceptance, submit a documentation-only PR using the
[feature spec template](../architecture/designs/feature-spec-template.md).
Create `docs/development/architecture/designs/<issue-number>-<feature-name>/`
and put the design in `README.md`. For example:

```text
docs/development/architecture/designs/1234-container-export/
    README.md
    api.md
```

For public API changes:

- Create `api.md` in the feature folder using the
  [API proposal template](../architecture/designs/api-spec-template.md).
  Keep it separate from the feature design spec in `README.md`.
- Start with one proposal covering Rust, .NET, and Node. Split only for distinct
  API areas, not automatically per SDK.
- Review both documents in the same documentation-only PR. Link the issue in
  each document and link `api.md` and supporting files from `README.md`.

For feature design specs, API proposals, and implementation PRs, follow the
[PR review-history guidance](../../../CONTRIBUTING.md#preserve-pr-review-history):
preserve published commits and add follow-up commits during review.

Use the templates to explain the problem, solution, backend support, host
capability checks, compatibility, and validation plan. Consider every backend;
explain exclusions rather than extending capabilities just to match SDKs.
The repository's architecture rules also apply to the proposed design.

The templates are discussion aids. Open questions are welcome in a draft;
review is where we work through them together. To keep human and AI-assisted
drafts easy to review:

- Use short bullets, signatures, and examples, not long background sections.
- Yes/no answers are enough for simple questions; explain decisions and risks.
- Write "Not applicable" with a short reason for irrelevant sections.
- Give two distinct usage examples when available. If only one meaningful
  scenario exists, give one and say so. Do not repeat equivalent SDK examples.
- Link shared details instead of repeating them or adding summaries.
- Use Mermaid for diagrams. Prefer sequence, data-flow, or state diagrams.
  Show important behavior or ownership, not every function.
  Do not repeat the diagram in prose.

### Complete design review together

Design and applicable API review form one approval stage. After a maintainer
approves your design, change its status from **Proposed** to **Accepted**
before merge.

Review and merge the required design spec and API proposal before implementing.
This gives contributors and reviewers a stable plan for the work.
Maintainers record the review decisions with labels on the tracking issue:

| Label | What it means |
| --- | --- |
| `feature-accepted` | Contributors and maintainers have agreed on scope and who plans to contribute. |
| `design-approved` | The required design spec is approved and merged. |
| `api-approved` | The applicable API proposal is approved and merged. |

If your feature has no public API changes, API approval is not required.
Labels do not replace review and merge.

If implementation reveals a need for a material design or API change, bring
it back to the discussion and update the spec together. Complete review and
merge of the revision before implementing the affected changes. Work that
still follows the agreed design can continue.

## 3. Implement the accepted design

With scope agreed and any required spec approved and merged, you are ready to
implement and open an implementation PR, including a draft. Link the issue
and merged spec so reviewers can follow the shared plan. A draft implementation
PR is a useful place to collaborate as the work takes shape.

### Choose the layers to change

- **Request contract and schema:** Rust contract types define the JSON fields
  and values accepted for a request version. A request field is a named input,
  such as `process.commandLine` or `network.egress.default`. JSON schemas are
  generated from the contract types; do not edit generated files by hand.
- **Policy:** the restrictions or permissions a caller requests, such as
  allowed network access. The backend must enforce them.
- **Public SDK types:** the Rust, .NET, and Node types callers use to make
  requests. They are distinct from generated contract types.

For example, a new network restriction may need a request field, backend
enforcement, and public SDK support. Adding a field or SDK property alone does
not implement the restriction. An SDK-only helper may need neither a new
request field nor backend changes.

| Does your feature change...? | What to do next |
| --- | --- |
| Accepted request fields or values | Update the development Rust contract, adapter, and fixtures; regenerate artifacts. Start with [contract sources and codegen](../build-and-test/schema-codegen.md#sources-of-truth). |
| Policy defaults, restrictions, or host support | Update validation, enforcement, capability checks, and functional tests. Start with the [affected backend guide](../../backends/). |
| Public SDK inputs, operations, or results | Update public types, request/result mapping, examples, and SDK tests. Start with the [versioned API references](../../api-reference/README.md). |
| Published request versions, SDK contract targets, or experimental authorization | Follow the [versioning design](../architecture/versioning.md). Publication does not grant runtime authorization or prove host support. |

Several rows may apply. Follow each relevant path. SDKs must not expose a
field just because it exists in a development contract.

The published v1 SDKs never authorize experimental features: their operations
always pass the native entry points' `experimental` argument as off. Exercise an
experimental feature through `wxc-exec --experimental`, and expose it in the
SDKs' typed request types only when it is promoted to a published contract.

For request format details, read [MXC request JSON](../../schema.md#mxc-request-json).
For language-specific work, use the SDK READMEs:
[Rust](../../../src/mxc-sdk/README.md), [.NET](../../../sdk/dotnet/README.md),
and [Node](../../../sdk/node/README.md). Windows OS changes may also need the
[ProcessContainer OS-work guide](process-container-adding-os-features.md).

### Plan the implementation PRs

Use separate implementation PRs in this order, skipping stages that do not
apply. These are dependencies, not deadlines or additional approval stages:

1. **Request contract:** update development-contract types, adapters, and fixtures,
   then regenerate artifacts in a separate PR. Keep unsupported requests rejected.
   A parsed field must not silently enable unenforced policy.
2. **Backend behavior:** implement and functionally validate each claimed
   backend. A backend-specific feature needs only that backend; preserve
   rejection elsewhere. Split large changes into working, reviewable slices.
3. **Public SDK/API:** provide equivalent feature and operation support in Rust,
   .NET, and Node through idiomatic APIs. Backend support may differ.
   Add SDK support only after the intended backend behavior and functional
   coverage are ready. Use the versioned API agreed in the proposal.
   This work may span multiple PRs.

### Find the existing path

Trace a similar feature before adding code. All three SDKs call the engine
within the caller's process: Rust through Rust APIs, and Node and .NET through
the C ABI exposed by `mxc_ffi`. Executor binaries are separate engine clients,
not SDK implementations.

| Area | Where to start |
| --- | --- |
| Contracts and adapters | `src/mxc-sdk/src/core/mxc_contract/` and `src/mxc-sdk/src/core/mxc_common/config_contract_adapters/` |
| Routing and authorization | `src/mxc-sdk/src/core/mxc_engine/` |
| Backend enforcement | `src/mxc-sdk/src/backends/` |
| Rust SDK | `src/mxc-sdk/src/` |
| .NET SDK | `sdk/dotnet/Microsoft.Mxc.Sdk/` |
| Node SDK | `sdk/node/src/` |
| Native C ABI | `src/ffi/mxc_ffi/` |
| Executor binaries | `src/tools/` |

Follow the [repository architecture](../architecture/repository-architecture.md)
and [repository rules](../../../.github/copilot-instructions.md) for ownership,
routing, and module boundaries.

### Validate behavior and SDK access

Follow the [validation runbook](../build-and-test/ci-validation-infrastructure.md)
for suitable hosts and CI wiring, and the
[contributor test commands](../../../CONTRIBUTING.md#testing).

The **host** is the machine running MXC; identify its OS/build, architecture,
and required features. The **CI suite** is the automated test group; identify
the test script or group and the workflow/job that runs it. Your spec needs
concrete scenarios and expected results, not full test implementations.

- Test enforcement, unsupported requests, relevant policy interactions, errors,
  and cleanup. Unit or request-construction tests do not replace functional tests.
- Before SDK exposure, use development-contract fixtures and native test entry
  points to validate backend behavior.
- Test each affected public SDK path, not only the executor. Cover request
  mapping, results, discovery, cancellation, and resource ownership as applicable.
- Run backend scenarios in the applicable scheduled/nightly CI suite. Include
  .NET source-generated JSON and AOT smoke coverage when its serialization changes.
- Record actual results and anything not run; do not present plans as results.

| Coverage | Existing test area |
| --- | --- |
| Rust contracts, native behavior, and SDK APIs | `src/mxc-sdk/tests/` |
| .NET API and mapping tests | `sdk/dotnet/Microsoft.Mxc.Sdk.Tests/` |
| .NET JSON/AOT checks | `sdk/dotnet/Microsoft.Mxc.Sdk.AotSmokeTest/` |
| Node mapping and integration tests | `sdk/node/tests/unit/` and `sdk/node/tests/integration/` |
| Host-dependent backend validation | `tests/scripts/` |

Update the affected backend guide, SDK README, versioned API references, and
examples. Describe supported behavior and usage, not implementation history.

## Finish the feature

Keep the issue open until all agreed implementation, functional validation,
and documentation are complete. Spec and intermediate PRs use non-closing
references such as `Refs #<issue-number>`. Do not use closing keywords in their
PR descriptions or commit messages, or link them as closing the feature issue.
Only the final implementation PR may close it when all work is complete;
otherwise, leave it for a maintainer to close afterward.
