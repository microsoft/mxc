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

Describe how callers use the feature through Rust, .NET, and Node here.
Keep backend support, execution-mode support, lifecycle behavior, resource
ownership, and recovery decisions in the feature design spec. Link the
relevant sections rather than repeating their answers.

## Caller scenario

- Link the feature design spec's usage scenarios; do not restate the problem
  or expected feature behavior.
- Show a short example for Rust, .NET, and Node: call, result, and cleanup.
  If an SDK needs no API change, show how its existing API supports the feature.
- Show a second example only where it uses the API differently. One is enough
  if there is only one meaningful scenario; say so.
- Would a diagram make the call order, state changes, or ownership clearer?
  If yes, use a small Mermaid diagram. Prefer sequence, data-flow, or state
  diagrams showing the SDK calls. Link an existing feature design diagram
  instead if it already shows what the caller needs.

## Proposed signatures and types

### Design guidance

Apply these rules to the declarations and examples in this proposal; they
do not need a separate written response.

- Let callers perform the same tasks through Rust, .NET, and Node, such as
  creating a container, running a command, or stopping a container.
  Explain any necessary SDK differences in **Inputs, results, and SDK
  differences** below.
- Follow each SDK's existing naming, types, and construction patterns.
  The SDKs do not need identical spelling or syntax.
- Put command, environment, and containment policy settings in request types.
  Put controls for an individual API call, such as cancellation, in that
  function's options type or SDK-standard cancellation parameter.

### Declarations to include

For each SDK (Rust, .NET, and Node):

- Name the API version and entry point: Rust module path, .NET namespace,
  or Node import path.
- Does the change fit an existing supported API version? Yes/No. If no, explain why.
- If a new version is needed, name it and identify the breaking change.

Example entry-point formats: Rust `mxc_sdk::v<N>`, .NET
`Microsoft.Mxc.Sdk.V<N>`, Node `@microsoft/mxc-sdk/v<N>`.
Replace `<N>` with the proposed API major version.

Show the proposed API shape in a code block for each SDK, not just a prose
description or table. For each public API function or method added or changed:

- Write its signature, including parameter names, types, order, optional
  parameters or defaults, and return type.
- Include declarations for new or changed request, options, and result types,
  with their public fields or variants, plus any required imports.
- Make synchronous or asynchronous behavior clear. Show cancellation in the
  signature or options type when supported; otherwise say it is not supported.

For example, a hypothetical Node API might be declared as:

```typescript
export interface ContainerStatusOptions {
  signal?: AbortSignal;
}

export declare function getContainerStatus(
  containerId: ContainerId,
  options?: ContainerStatusOptions,
): Promise<ContainerStatus>;
```

This illustrates the declaration format, not an existing or required API.
A complete proposal would also show any new or changed `ContainerId` and
`ContainerStatus` declarations. Use the equivalent declaration syntax for
Rust and .NET. Do not include implementation bodies; caller usage examples
belong in **Caller scenario** above.

## Inputs, results, and SDK differences

Use short bullets or a table to explain the declarations above.
For inputs that map to MXC request fields, link the feature design spec's
allowed values and defaults. Describe only SDK-specific details here, such
as how optional or null values are represented and passed to the engine.
For each new or changed input, name it and answer:

- What does it control? What values are allowed? For measurements, specify
  the unit, such as seconds or bytes.
- Is it required? Yes/No. If not, what default applies?
- Can the caller leave it out, pass an empty value, or pass null?
  Describe the behavior or error for each case. If the declared type does not
  allow a case, mark it "Not applicable" and explain briefly. For example,
  a required Rust `bool` cannot be omitted, empty, or null.
- Which values are rejected, and with what error?

For each new or changed result:

- What value does the function return, and what does each returned field or
  enum variant mean? For example, does an exit code describe the command's
  outcome or the success of container cleanup?
- What does the caller receive on failure, timeout, or cancellation?
- Must the caller close or release anything? Yes/No. If yes, show how.
- How does the SDK expose the recovery behavior defined in the feature design
  spec? Name the error types or fields and any container or session IDs the
  caller receives. Show the SDK calls needed to check state, retry, or clean
  up in **Caller scenario**; link manual recovery steps from the feature spec
  rather than repeating them.
- If discovery, capability, or availability APIs change, what functions and
  result types expose the feature spec's support decisions? Include their
  declarations above and explain how results distinguish supported,
  unsupported, and undetermined support.

Does any behavior differ between Rust, .NET, and Node? Write "No" if not.
Otherwise, use bullets or a table here to name the affected functions or
types, describe each SDK's behavior, and explain why the difference is needed.

## Compatibility and request mapping

MXC request fields are named inputs in the versioned request format, such as
`process.commandLine` or `network.egress.default`. See
[MXC request JSON](https://github.com/microsoft/mxc/blob/main/docs/schema.md#mxc-request-json)
for the format and field reference.

- Will existing callers still compile and behave the same? Yes/No.
  Identify source, binary, or behavior breaks prominently. Put breaking changes
  in a new API version; keep published versions working. Link runtime behavior
  changes from the feature design spec and explain their effect on SDK callers.
- Map SDK inputs to MXC request fields using bullets or a table: SDK field,
  request field, and request version. Link contract changes from the feature
  design spec rather than defining them again. If the API uses no request
  fields, say so.
- For optional inputs, explain how the SDK preserves "not provided" versus
  an explicitly supplied value.
- Link the feature design spec's backend and execution-mode support decisions.
  Name the SDK errors for unsupported combinations or unenforceable policy
  in **Inputs, results, and SDK differences**; do not redefine support here.

## Validation and documentation

- Link the feature design spec's validation plan. Name additional SDK-specific
  tests for declarations, request mapping, error conversion, and caller-owned
  resource disposal. Keep shared functional scenarios and CI hosts in that plan.
- Which versioned API references and SDK examples need updates? Link this list
  from the feature design spec's documentation plan.

## Review checklist

- [ ] Examples demonstrate a useful caller task and correct ownership.
- [ ] Concrete versioned entry points are named; any new API version is justified.
- [ ] Defaults, optional values, errors, and cancellation are explicit.
- [ ] Rust, .NET, and Node offer equivalent feature support through idiomatic APIs.
- [ ] SDK behavior differences are intentional and documented; naming and syntax follow each language's conventions.
- [ ] Backend and execution-mode support decisions are linked; SDK discovery results and errors reflect them.
- [ ] Compatibility and request mapping are addressed; breaking changes are prominent.
- [ ] Public API validation and consumer documentation updates are planned.
- [ ] Answers and examples are concise; shared design details are linked, not repeated.
