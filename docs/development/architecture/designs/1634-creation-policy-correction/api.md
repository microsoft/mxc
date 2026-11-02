# API proposal: caller-authorized creation-policy correction

> **Audience:** MXC developers

- **Issue:** [#1634](https://github.com/microsoft/mxc/issues/1634)
- **Feature design spec:** [README.md](README.md), status Proposed

This draft keeps existing V1 requests/results and adds per-invocation
authorization. The Rust namespace choice is proposed, not approved.
[Backend/mode support](README.md#backend-applicability-and-availability) and
[ownership/recovery](README.md#resource-ownership-and-failure-recovery) are
defined in the feature design rather than redefined here.

## Caller scenario

See the feature's [two scenarios](README.md#problem-and-scope).
Ordinary V1 creation remains strict and needs no new API:
`v1::run(request, options)`, `MxcContainer.Run(request, options)` and
`run(request, options)` retain their existing errors and results, with richer
refusal text when the host supplies it.

The examples below accept an existing typed ProcessContainer request. The
application supplies the command, filesystem/network settings and timeout;
the option does not belong in that request.

### Captured creation with restrictive correction

Rust, proposed `mxc_sdk::v1_1`:

```rust
use mxc_sdk::v1_1::{self, ContainerRequest, Error, ExecutionResult, RunOptions};

fn run_with_correction(request: ContainerRequest) -> Result<ExecutionResult, Error> {
    let mut options = RunOptions::default();
    options.mutate_policy = true;
    let result = v1_1::run(request, options)?;
    for warning in &result.warnings {
        eprintln!("{warning}");
    }
    Ok(result)
}
```

.NET, `Microsoft.Mxc.Sdk.V1`:

```csharp
using Microsoft.Mxc.Sdk.V1;
using System;
using System.Threading;
using System.Threading.Tasks;

static async Task<ExecutionResult> RunWithCorrection(
    ContainerRequest request, CancellationToken cancellationToken)
{
    var result = await MxcContainer.RunAsync(
        request, new RunOptions { MutatePolicy = true }, cancellationToken);
    foreach (var warning in result.Warnings)
        Console.Error.WriteLine(warning);
    return result;
}
```

Node, `@microsoft/mxc-sdk/v1`:

```typescript
import { run, type ContainerRequest } from '@microsoft/mxc-sdk/v1';

async function runWithCorrection(request: ContainerRequest) {
  const result = await run(request, { mutatePolicy: true });
  for (const warning of result.warnings ?? []) console.error(warning);
  return result;
}
```

Captured operations own and release their native resources before returning;
the result needs no disposal. A creation failure returns/throws the ordinary
SDK error, not a successful result containing corrections.

### Live stdin and correction in the same invocation

This is a distinct API use: the returned process and a taken stdin stream
belong to the caller. Each example closes stdin before waiting. Untaken output
is drained by the existing wait operation; code that takes output streams
must read them concurrently. See the [feature sequence](README.md#design-and-security).

```rust
use mxc_sdk::v1_1::{self, ContainerRequest, SpawnOptions};
use std::io::{self, Write};

fn send_input(request: ContainerRequest) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SpawnOptions::default();
    options.stdin = true;
    options.mutate_policy = true;
    let mut process = v1_1::spawn(request, options)?;
    {
        let mut input = process
            .take_stdin()
            .ok_or_else(|| io::Error::other("stdin was not provided"))?;
        input.write_all(b"hello\n")?;
    }
    for warning in process.warnings() {
        eprintln!("{warning}");
    }
    let _outcome = process.wait()?;
    Ok(())
}
```

The Rust process is dropped on every return path, including a write/wait error.

```csharp
using Microsoft.Mxc.Sdk.V1;
using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

static async Task SendInput(ContainerRequest request, CancellationToken cancellationToken)
{
    using var process = await MxcContainer.SpawnWithStdinAsync(
        request, new SpawnOptions { MutatePolicy = true }, cancellationToken);
    using (var input = process.StandardInput
        ?? throw new InvalidOperationException("stdin was not provided"))
    {
        await input.WriteAsync(Encoding.UTF8.GetBytes("hello\n"), cancellationToken);
    }
    foreach (var warning in process.Warnings)
        Console.Error.WriteLine(warning);
    await process.WaitAsync(cancellationToken);
}
```

```typescript
import { spawnWithStdin, type ContainerRequest } from '@microsoft/mxc-sdk/v1';

async function sendInput(request: ContainerRequest) {
  const process = await spawnWithStdin(request, { mutatePolicy: true });
  try {
    const input = process.standardInput;
    if (input === null) throw new Error('stdin was not provided');
    input.end('hello\n');
    for (const warning of process.warnings) console.error(warning);
    return await process.wait();
  } finally {
    process.dispose();
  }
}
```

## Proposed signatures and types

Request, process, result, telemetry and error types below are the existing V1
types. This proposal adds no structured correction result or public cache.

### Rust

Proposed entry point: `mxc_sdk::v1_1`, re-exporting the listed V1 types.
Adding a field to V1's exhaustively constructible options would break existing
struct literals. Keep V1 types/functions intact; use non-exhaustive new options.
These are synchronous declarations, not new async/cancellation APIs.

```rust
pub use crate::v1::{
    ContainerRequest, Error, ExecutionResult, MxcProcess, TelemetryConfig,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RunOptions {
    pub telemetry: Option<TelemetryConfig>,
    pub mutate_policy: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpawnOptions {
    pub telemetry: Option<TelemetryConfig>,
    pub stdin: bool,
    pub mutate_policy: bool,
}

pub fn run(request: ContainerRequest, options: RunOptions) -> Result<ExecutionResult, Error>;
pub fn spawn(request: ContainerRequest, options: SpawnOptions) -> Result<MxcProcess, Error>;
```

The declarations show public shapes, not Rust implementation bodies.
`ContainerRequest`, result/process ownership and telemetry consent semantics
are unchanged. Both booleans default to `false`; telemetry defaults to `None`.
`stdin` composes with correction rather than selecting a competing API.

### .NET

Entry point: `Microsoft.Mxc.Sdk.V1`. The additive property fits the existing
sealed, mutable option classes; signatures and trailing cancellation parameters
remain unchanged. Existing constructors and compiled callers remain valid.

```csharp
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Mxc.Sdk.V1;

public sealed class RunOptions
{
    public TelemetryConfig? Telemetry { get; set; }
    public bool MutatePolicy { get; set; }
}

public sealed class SpawnOptions
{
    public TelemetryConfig? Telemetry { get; set; }
    public bool MutatePolicy { get; set; }
}

public static class MxcContainer
{
    public static ExecutionResult Run(ContainerRequest request, RunOptions? options = null);
    public static Task<ExecutionResult> RunAsync(
        ContainerRequest request, RunOptions? options = null,
        CancellationToken cancellationToken = default);
    public static MxcProcess Spawn(ContainerRequest request, SpawnOptions? options = null);
    public static Task<MxcProcess> SpawnAsync(
        ContainerRequest request, SpawnOptions? options = null,
        CancellationToken cancellationToken = default);
    public static MxcProcess SpawnWithStdin(ContainerRequest request, SpawnOptions? options = null);
    public static Task<MxcProcess> SpawnWithStdinAsync(
        ContainerRequest request, SpawnOptions? options = null,
        CancellationToken cancellationToken = default);
}
```

These are signature declarations, not compilable class implementations.
No property is added to PTY or lifecycle option classes.

### Node

Entry point: `@microsoft/mxc-sdk/v1`. Optional properties fit existing V1
interfaces and calls; all operations remain asynchronous.

```typescript
import type {
  ContainerRequest, ExecutionResult, MxcProcess, TelemetryConfig,
} from '@microsoft/mxc-sdk/v1';

export interface RunOptions {
  telemetry?: TelemetryConfig;
  mutatePolicy?: boolean;
}

export interface SpawnOptions {
  telemetry?: TelemetryConfig;
  mutatePolicy?: boolean;
}

export declare function run(
  request: ContainerRequest, options?: RunOptions,
): Promise<ExecutionResult>;
export declare function spawn(
  request: ContainerRequest, options?: SpawnOptions,
): Promise<MxcProcess>;
export declare function spawnWithStdin(
  request: ContainerRequest, options?: SpawnOptions,
): Promise<MxcProcess>;
```

No new `AbortSignal` or mutation option for PTY/lifecycle/Dev APIs is proposed.

## Inputs, results, and SDK differences

| Input | Meaning, omission and rejection |
| --- | --- |
| Rust `mutate_policy` | `bool`; `Default` supplies `false`. Literal omission is handled through the non-exhaustive options' default construction. Null/empty/non-booleans cannot be expressed. |
| .NET `MutatePolicy` | `bool`, default `false`. Null options use defaults; the property itself is non-nullable. A JSON `null`/non-boolean property value is invalid when options are serialized/deserialized. |
| Node `mutatePolicy` | Optional boolean. Absent/`undefined`/`false` are strict; `{}` is valid strict options. `null`, strings and numbers for the property produce `MxcError` with `malformed_request` before native execution. A null options object is not allowed. |
| Rust `stdin` | Optional through default construction, default `false`; requests the existing writable-input behavior in the combined creation operation. It grants no mutation support to another backend. |
| `telemetry` / `Telemetry` | Existing optional per-call preference, unchanged; omission does not authorize collection. |

Proposed error mapping uses existing categories:

| Situation | Caller receives |
| --- | --- |
| Creation or exhausted/unsafe negotiation | Rust `Error`; .NET `MxcException`; Node `MxcError`, retaining native failure context/category. Any earlier attempted corrections are ordinary error text. |
| Wrong-backend mutation | Existing `unsupported_containment`; no fallback. |
| Unsupported native host or required PSEC/capture capability | Existing `backend_unavailable`; no attempt to weaken the policy. Missing optional refusal details alone do not prevent an otherwise successful unchanged creation. |
| Invalid invocation combination or unenforceable policy | Existing validation error; the new options do not redefine structural request parsing. |
| Older native library without the opt-in entry points | Explicit SDK error for the requested operation, never silent use of a strict entry point instead. Strict callers remain compatible. |
| Workload exit or timeout after creation | Existing `ExecutionResult`/wait outcome and partial-output behavior; never a new correction attempt. |

No result type or field is added. Successful `run` returns existing output,
exit/timeout status and warnings. Successful `spawn` returns the existing live
process; correction strings use Rust `warnings()`, .NET `Warnings`, or Node
`warnings`. Only newly negotiated corrections warn; the quiet-reuse and
failure semantics are in [Proposed behavior](README.md#proposed-behavior).

Necessary SDK/runtime differences:

- Rust consumes the typed request; default/new option construction must not
  break V1 exhaustive literals. Drop releases a live handle. Creation has no
  cancellation token; existing workload timeouts/kill/wait remain.
- .NET options are nullable reference objects. Async cancellation continues to
  cancel awaiting a blocking native operation, not promise cancellation of
  native negotiation/execution; use the existing request timeout and live
  process kill/disposal. Dispose a late unclaimed spawn result through the
  existing async wrapper. Successful learning can precede cancellation.
- Node promises have no new per-call cancellation signal. Existing timeout
  and returned-process `kill()`/`dispose()` remain. Keep the loaded mutation
  native module alive across calls so native in-process reuse can work; retain
  no caller-owned request cache.

Callers still own live-process and taken-stream cleanup. No new container ID,
session handle or check-state/retry-cleanup operation is returned; see
[failure recovery](README.md#resource-ownership-and-failure-recovery).
Probes/discovery signatures/results are unchanged. They report advisory backend
serviceability, not policy approval or guaranteed diagnostic availability.

## Compatibility and request mapping

- **Existing callers still compile: Yes.** Preserve Rust V1 options/functions,
  existing .NET signatures and optional Node calls. The new Rust module is an
  additive proposal; there is no removal or migration requirement for V1.
- **Behavior is preserved:** strict creation remains strict and retains error
  categories, but message text gains useful diagnostic details. Text is not
  a stable parsing contract. Explicit opt-in authorizes the feature's specified
  runtime difference.
- **Request mapping:** `mutate_policy` / `MutatePolicy` / `mutatePolicy` maps to
  a native invocation control, not an MXC JSON field. There is no request
  version change. Omitted and explicit `false` intentionally authorize the
  same behavior; optional request-policy fields retain their existing presence
  semantics.
- Native adapters need additive opt-in entry points or equivalent explicitly
  versioned dispatch without changing existing C layouts/exports. Preserve panic
  containment, error/result/string frees and default export selection.
- Ship new feature/API behavior in at least a minor SDK release under the
  existing [Semver rules](../../versioning.md#versioning-follows-semver).
  The scoped Rust API name does not select a new MXC request contract or
  determine the package release version.

**API-placement decision requested:** this draft proposes `v1_1` to preserve
existing Rust option literals while composing stdin and mutation in extensible
options. An alternative is additive creation operations with new extensible
options under `v1`, preserving every old signature. The existing
[Rust](../../../../api-reference/rust/v1/api.md#choosing-a-launch-operation),
[.NET](../../../../api-reference/dotnet/v1/api.md#choosing-a-launch-operation)
and [Node](../../../../api-reference/node/v1/api.md#choosing-a-launch-operation)
writable-stdin additions provide an additive-operation precedent.
Maintainers must settle this before approval; this PR does not rename the
candidate or treat a choice as already approved.

V1.Dev has a different purpose: caller-authored MXC request JSON with an
explicit registered version and separate experimental-backend authorization.
See the current [Rust](../../../../api-reference/rust/v1/dev.md),
[.NET](../../../../api-reference/dotnet/v1/dev.md) and
[Node](../../../../api-reference/node/v1/dev.md) references. Mutation is
invocation authorization that must compose with typed requests, not a new
request-JSON field or implicit experimental permission.

## Validation and documentation

The shared [validation plan](README.md#acceptance-criteria-and-validation-plan)
defines capable hosts, scheduled governed cases and cleanup oracles.
SDK-specific additions:

- Rust compile/source-compatibility examples for old V1 struct literals and
  new non-exhaustive construction; strict/opt-in captured and combined-stdin
  public calls; existing wait/drop behavior.
- Node unit mapping/export-selection/missing-export and invalid-option tests;
  integration cases for captured/streaming/stdin outcomes, warning copies,
  current request preservation and dispose-on-failure.
- .NET sync/async/default/null options, cancellation/late-result disposal and
  native error conversion. Keep both option types in `MxcJsonContext`, use
  `MxcJson` and extend Native AOT smoke serialize/deserialize coverage for
  omitted/false/true authorization and telemetry. No reflection fallback.
- All SDKs require actual governed public-API execution, not just
  option-serialization tests. Byte-only request hashes are not proof that
  emitted retry/reuse permissions remain correct.

Consumer updates: all three SDK READMEs; Rust V1/V1.1 creation and type
references if this shape is approved; .NET/Node V1 operation/type references;
the API index; and captured/streaming-stdin examples. Keep backend internals
in the linked feature/backend guides and clearly label host prerequisites,
text stability, supported modes, default strictness and cleanup.

## Review checklist

- [x] Examples demonstrate a useful caller task and correct ownership.
- [ ] Concrete versioned entry points are named; any new API version is justified.
- [x] Defaults, optional values, errors, and cancellation are explicit.
- [x] Rust, .NET, and Node offer equivalent feature support through idiomatic APIs.
- [x] SDK behavior differences are intentional and documented; naming and syntax follow each language's conventions.
- [x] Backend and execution-mode support decisions are linked; SDK discovery results and errors reflect them.
- [x] Compatibility and request mapping are addressed; breaking changes are prominent.
- [x] Public API validation and consumer documentation updates are planned.
- [x] Answers and examples are concise; shared design details are linked, not repeated.
