# API proposal: report why the probe finds isolation sessions unavailable

> **Audience:** MXC developers

- **Issue:** [#1684](https://github.com/microsoft/mxc/issues/1684)
- **Feature design spec:** [README.md](README.md)

## Caller scenario

Each SDK reads the field the same way, so each has one example of
[scenario 2](README.md#problem-and-scope). The probe creates nothing, so there
is nothing to clean up.

Rust:

```rust
use mxc_sdk::v1;

let output = v1::probe(None)?;
if let Some(reason) = &output.probes.isolation_session_unavailable_reason {
    eprintln!("isolation sessions unavailable: {reason}");
}
```

.NET:

```csharp
using Microsoft.Mxc.Sdk.V1;

ProbeOutput output = MxcContainer.Probe();
if (output.Probes.IsolationSessionUnavailableReason is { } reason)
{
    Console.Error.WriteLine($"isolation sessions unavailable: {reason}");
}
```

Node:

```typescript
import { probe } from '@microsoft/mxc-sdk/v1';

const reason = probe().probes.isolationSessionUnavailableReason;
if (reason !== undefined) {
  console.error(`isolation sessions unavailable: ${reason}`);
}
```

## Proposed signatures and types

The change fits V1: it adds one optional field to an existing result type. The
probe functions do not change. They stay synchronous and take no cancellation.

Rust, `mxc_sdk::v1`:

```rust
pub struct ProbeFacts {
    // Existing fields are unchanged.
    pub isolation_session_available: bool,
    pub isolation_session_unavailable_reason: Option<String>,
}
```

.NET, `Microsoft.Mxc.Sdk.V1`:

```csharp
public sealed class ProbeFacts
{
    // Existing members are unchanged.
    public bool IsolationSessionAvailable { get; init; }
    public string? IsolationSessionUnavailableReason { get; init; }
}
```

Node, `@microsoft/mxc-sdk/v1`:

```typescript
export interface ProbeFacts {
  // Existing fields are unchanged.
  isolationSessionAvailable: boolean;
  isolationSessionUnavailableReason?: string;
}
```

## Inputs, results, and SDK differences

- Inputs: none.
- `isolationSessionUnavailableReason` is one line of text that says why
  isolation sessions are unavailable. Its cases are in
  [Proposed behavior](README.md#proposed-behavior).
- The reason is text for people and logs. Its wording can change, so programs
  should not parse it.
- It is present only when `isolationSessionAvailable` is false and MXC was
  built with the `isolation_session` feature: the `mxc-sdk` crate feature in
  Rust, or the native library that .NET and Node load. Otherwise Rust returns
  `None`, .NET returns `null`, and Node omits the property.
- The .NET and Node parsers reject an explicit null or a non-string value as
  malformed probe output. .NET throws `JsonException`; Node throws `Error`.
- Nothing to release.
- SDK differences: only .NET and Node parse probe JSON, so only they reject
  malformed values. Rust reads the field from its own types.

## Compatibility and request mapping

- **Rust source compatibility.** `ProbeFacts` has no private fields and is not
  `#[non_exhaustive]`, so the new field breaks Rust code that builds it with a
  struct literal or destructures it without `..`. Whether that is acceptable in
  V1 is [open question 1](README.md#open-questions).
- **Mixed versions.** An older .NET or Node SDK paired with a newer native
  library rejects probe output that contains the field, so every probe call
  fails on hosts without isolation sessions. The NuGet and npm packages load
  their own native library unless `MXC_FFI_DIR` points elsewhere.
- .NET and Node callers otherwise compile and behave as before.
- Request fields: none; the field is probe output only.
- Support decisions:
  [Backend applicability and availability](README.md#backend-applicability-and-availability).

## Validation and documentation

- Tests: the [validation plan](README.md#acceptance-criteria-and-validation-plan).
  The .NET and Node unit tests and the .NET AOT smoke test parse the field
  when present and absent, and reject null and non-string values.
- Documentation:
  - `ProbeFacts` in `docs/api-reference/rust/v1/types.md`,
    `docs/api-reference/dotnet/v1/types.md` and
    `docs/api-reference/node/v1/types.md`.
  - The probe paragraph in `src/mxc-sdk/README.md`, `sdk/dotnet/README.md` and
    `sdk/node/README.md`.
  - An Added entry in `sdk/dotnet/CHANGELOG.md` and `sdk/node/CHANGELOG.md`.

## Review checklist

- [x] Examples demonstrate a useful caller task and correct ownership.
- [x] Concrete versioned entry points are named; any new API version is justified.
- [x] Defaults, optional values, errors, and cancellation are explicit.
- [x] Rust, .NET, and Node offer equivalent feature support through idiomatic APIs.
- [x] SDK behavior differences are intentional and documented; naming and syntax follow each language's conventions.
- [x] Backend and execution-mode support decisions are linked; SDK discovery results and errors reflect them.
- [x] Compatibility and request mapping are addressed; breaking changes are prominent.
- [x] Public API validation and consumer documentation updates are planned.
- [x] Answers and examples are concise; shared design details are linked, not repeated.
