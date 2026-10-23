# API proposal: feature name

> **Audience:** MXC developers

<!--
Copy to api.md in the feature design spec's folder.
For example: 1234-container-export/api.md. Link it from the feature's README.md.
Split proposals only for distinct API areas, not automatically per SDK.
Review the feature design spec and API proposals in the same PR.
Describe only API changes; link shared details from the feature design spec.
Use these questions to explore the API together. Mark open questions for
discussion; they do not need to be settled before opening a draft.
Short bullets, signatures, and yes/no answers are welcome when sufficient;
explain changed behavior, decisions, and risks. For irrelevant sections,
write "Not applicable" and a short reason. Link shared context rather than
repeating it. The same guidance applies to human and AI-assisted drafts.
Follow the acceptance and spec-review process in:
https://github.com/microsoft/mxc/blob/main/docs/development/guides/authoring-a-new-feature.md
-->

- **Issue:** Link the tracking issue.
- **Feature design spec:** Link the feature's `README.md`.

## Caller scenario

- What task will the caller complete? Reuse the feature design spec's scenarios.
- Show a short example for Rust, .NET, and Node: call, result, and cleanup.
  If an SDK needs no API change, show how its existing API supports the feature.
- Show a second example only where it uses the API differently. One is enough
  if there is only one meaningful scenario; say so.
- Would a diagram make the call order, state changes, or ownership clearer?
  If yes, use a small Mermaid diagram. Prefer sequence, data-flow, or state
  diagrams. Link a diagram from the feature design spec instead if it already
  shows the behavior.

## Proposed signatures and types

For each SDK (Rust, .NET, and Node):

- Name the API version and entry point: Rust module path, .NET namespace,
  or Node import path.
- Does the change fit an existing supported API version? Yes/No. If no, explain why.
- If a new version is needed, name it and identify the breaking change.

Example entry-point formats: Rust `mxc_sdk::v<N>`, .NET
`Microsoft.Mxc.Sdk.V<N>`, Node `@microsoft/mxc-sdk/v<N>`.
Replace `<N>` with the proposed API major version.

Show only the proposed signatures, types, fields, and imports. For each operation:

- What are the inputs, their order, and the result type?
- Is it synchronous or asynchronous? How does the caller cancel it?

Do not include implementation bodies.

## Inputs, results, and SDK differences

For each new or changed input, name it and answer:

- What does it control? What values are allowed? For measurements, specify
  the unit, such as seconds or bytes.
- Is it required? Yes/No. If not, what default applies?
- Can the caller leave it out, pass an empty value, or pass null?
  Describe the behavior or error for each case. If an SDK input type cannot
  represent a case, say so.
- Which values are rejected, and with what error?

For each new or changed result:

- What does it report?
- What does the caller receive on failure, timeout, or cancellation?
- Must the caller close or release anything? Yes/No. If yes, show how.

Does any behavior differ between Rust, .NET, and Node? Yes/No.
If yes, list the differences and why they are needed.

Provide equivalent feature and operation support across Rust, .NET, and Node.
Use each language's naming conventions and idiomatic types and syntax.
Follow existing SDK patterns rather than forcing identical spelling or
construction across Rust, .NET, and Node.

Put workload and policy settings in request types; put per-call controls in
operation options.

## Backend support and discovery

- Which backends support the API? Link the feature design spec's backend table.
  Backend support may differ; that is separate from SDK feature parity.
- Do discovery, capability, or availability APIs change? Yes/No. If yes, show
  results for supported hosts, unsupported hosts, and when support cannot be determined.
- What happens if a backend is available but cannot enforce the requested policy?

## Compatibility and request mapping

MXC request fields are named inputs in the versioned request format, such as
`process.commandLine` or `network.egress.default`. See
[MXC request JSON](https://github.com/microsoft/mxc/blob/main/docs/schema.md#mxc-request-json)
for the format and field reference.

- Will existing callers still compile and behave the same? Yes/No.
  Identify source, binary, or behavior breaks prominently. Put breaking changes
  in a new API version; keep published versions working.
- Does this API use existing MXC request fields, or require new or changed
  fields? List the field names and request version. If it uses no request
  fields, say so.
- For optional inputs, explain how the SDK preserves "not provided" versus
  an explicitly supplied value.
- Which backend, host, or option combinations are unsupported, and what error
  will the caller receive? Reject restrictions the backend cannot enforce;
  do not silently ignore them.

## Validation and documentation

- Which tests will check request mapping, execution, discovery, errors, and cleanup
  through each SDK? Link the feature design spec's validation plan and name
  any SDK-specific tests to add or extend.
- Which versioned API references and examples need updates?

## Review checklist

- [ ] Examples demonstrate a useful caller task and correct ownership.
- [ ] Concrete versioned entry points are named; any new API version is justified.
- [ ] Defaults, optional values, errors, and cancellation are explicit.
- [ ] Rust, .NET, and Node offer equivalent feature support through idiomatic APIs.
- [ ] SDK behavior differences are intentional and documented; naming and syntax follow each language's conventions.
- [ ] Backend support, capability probes, and availability results are clear.
- [ ] Compatibility and request mapping are addressed; breaking changes are prominent.
- [ ] Public API validation and consumer documentation updates are planned.
- [ ] Answers and examples are concise; shared design details are linked, not repeated.
