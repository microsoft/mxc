# API proposal: caller-owned creation-policy feedback

> **Audience:** MXC developers

- **Issue:** [#1634](https://github.com/microsoft/mxc/issues/1634)
- **Feature design spec:** [README.md](README.md), status Proposed

Use `mxc_sdk::v1::dev`, `Microsoft.Mxc.Sdk.V1.Dev` and
`@microsoft/mxc-sdk/v1/dev`. Each accepts complete MXC request JSON and optional
caller-owned `PolicyFailures` for a new creation call. The application owns
inspection, storage, retry limits and stopping decisions.
[Backend/mode support](README.md#backend-applicability-and-availability) and
[ownership/recovery](README.md#resource-ownership-and-failure-recovery) are
defined in the feature design.

## Caller scenario

See the feature's [two scenarios](README.md#problem-and-scope) and
[call sequence](README.md#design-and-security). The examples use caller-authored
request JSON with a registered version. Feedback belongs in invocation options,
not that JSON. Successful calls return the ordinary result or process; there
is no successful-creation correction report or policy warning text.

### Rust: application-owned bounded loop

`run_with_feedback` below is application code, not an MXC API. It illustrates
an application-selected eight-call budget. The caller decides whether the
supported restrictions are acceptable before using such a loop.

```rust
use mxc_sdk::v1::{
    dev::{self, JsonOptions, PolicyFailureResult, PolicyFailures},
    Error, ExecutionResult,
};

fn run_with_feedback(
    config: &str,
    feedback: &mut Option<PolicyFailures>,
) -> Result<ExecutionResult, Error> {
    let mut remaining = 8;
    loop {
        remaining -= 1;
        let mut options = JsonOptions::default();
        options.policy_failures = feedback.as_ref();
        match dev::run_json(config, options) {
            Ok(output) => return Ok(output),
            Err(error) => {
                let Some(next) = PolicyFailures::from_error(&error)? else {
                    return Err(error);
                };
                let progress = feedback.as_ref() != Some(&next);
                let blocked = next
                    .results
                    .last()
                    .is_some_and(|result| result.outcome == PolicyFailureResult::OUTCOME_BLOCKED);
                let terminal = error
                    .details
                    .as_deref()
                    .is_some_and(|details| details.get("policyFeedbackError").is_some());
                let policy_refusal = error.operation.as_deref()
                    == Some("CreateProcessSecurityEnvironment")
                    && error.native_code.as_deref()
                        == Some(PolicyFailures::NATIVE_CODE_POLICY_BLOCKED);
                // Replace, rather than append, the complete returned observations.
                *feedback = Some(next);
                if remaining == 0 || !progress || !blocked || terminal || !policy_refusal {
                    return Err(error);
                }
            }
        }
    }
}
```

Persist `feedback.to_json()` after the helper returns, including terminal
failure, and restore with `PolicyFailures::from_json`. Persist application
stop/budget state separately when it must survive a restart: feedback storage
does not include companion diagnostics from the original error.
The [complete prototype example](https://github.com/microsoft/mxc/blob/6e04aa415e6e1f1bf901bfb76b7ebdc957bc6083/src/mxc-sdk/examples/policy_feedback.rs)
shows file storage and workload output/exit handling.

### .NET and Node: store observations for a later selected call

These examples assume the application has inspected a failed call and decided
that a later creation may apply its restrictions. They are not automatic retry
controllers. Preserve terminal/stopping decisions separately before scheduling
another invocation.

```csharp
using Microsoft.Mxc.Sdk.V1;
using System.Threading;
using System.Threading.Tasks;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;

static string? StoreFeedback(MxcException error) =>
    Dev.PolicyFailures.FromException(error)?.ToJson();

static Task<ExecutionResult> CreateFromStoredFeedback(
    string requestJson, string storedJson, CancellationToken cancellationToken) =>
    Dev.MxcContainer.RunJsonAsync(
        requestJson,
        new Dev.JsonOptions { PolicyFailures = Dev.PolicyFailures.FromJson(storedJson) },
        cancellationToken);
```

```typescript
import {
  parsePolicyFailures, policyFailuresFromError, runJson, serializePolicyFailures,
} from '@microsoft/mxc-sdk/v1/dev';

function storeFeedback(error: unknown): string | undefined {
  const feedback = policyFailuresFromError(error);
  return feedback === undefined ? undefined : serializePolicyFailures(feedback);
}

async function createFromStoredFeedback(requestJson: string, storedJson: string) {
  return runJson(requestJson, { policyFailures: parsePolicyFailures(storedJson) });
}
```

The saved value can be supplied with a different request or creator, subject
to the feature's current-request safety checks and fresh Windows evaluation.
Captured results need no disposal. A `spawn_json` / `SpawnJson` / `spawnJson`
result instead transfers the existing live process/stream ownership to the
caller; dispose/drop it through the normal SDK API. No stdin redesign or new
PTY/lifecycle control is proposed.

## Proposed signatures and types

All additions below are V1.Dev-only except the generic structured-error
extension. They do not add feedback options to stable typed V1 creation.

### Rust

Entry point: `mxc_sdk::v1::dev`. Retain the operation names and synchronous
behavior; use existing `mxc_sdk::v1::{Error, ExecutionResult, MxcProcess}`.
The public feedback structs implement `Debug`, `Clone`, `PartialEq`, `Eq`,
`Default` and Serde serialization/deserialization.

```rust
#[non_exhaustive]
pub struct JsonOptions<'a> {
    pub experimental: bool,
    pub policy_failures: Option<&'a PolicyFailures>,
}

pub fn run_json(json: &str, options: JsonOptions<'_>) -> Result<ExecutionResult, Error>;
pub fn spawn_json(json: &str, options: JsonOptions<'_>) -> Result<MxcProcess, Error>;

#[non_exhaustive]
pub struct PolicyFailures {
    pub format_version: u32,
    pub results: Vec<PolicyFailureResult>,
}

impl PolicyFailures {
    pub const NATIVE_CODE_POLICY_BLOCKED: &str = "0x800704EC";
    pub fn from_error(error: &Error) -> Result<Option<Self>, Error>;
    pub fn from_json(json: &str) -> Result<Self, Error>;
    pub fn to_json(&self) -> Result<String, Error>;
}

#[non_exhaustive]
pub struct PolicyFailureResult {
    pub version: u32,
    pub minimum_reader_version: u32,
    pub outcome: u32,
    pub details: Vec<PolicyFailureDetail>,
}

#[non_exhaustive]
pub struct PolicyFailureDetail {
    pub failure_class: u32,
    pub failure_reason: u32,
    pub required_action: u32,
    pub resource_kind: u32,
    pub value_kind: u32,
    pub flags: u32,
    pub requested_value: u64,
    pub required_value: u64,
    pub resource: Option<Vec<u16>>,
}

impl PolicyFailureDetail {
    pub fn resource_text(&self) -> Result<Option<String>, std::string::FromUtf16Error>;
}
```

These are declaration shapes, not implementation bodies. Construct
non-exhaustive options/DTOs with `Default` and set fields. Options borrow
feedback for the call; error extraction returns an owned value. Defaults are
`experimental = false`, no feedback, format/native versions1, unknown outcome0
and empty results/details. There is no cancellation token addition.

### .NET

Entry point: `Microsoft.Mxc.Sdk.V1.Dev`; result/process/error types belong to
`Microsoft.Mxc.Sdk.V1`. Methods and trailing cancellation parameters retain
their existing shapes.

```csharp
public sealed class JsonOptions
{
    public bool Experimental { get; set; }
    public PolicyFailures? PolicyFailures { get; set; }
}

// Microsoft.Mxc.Sdk.V1.Dev.MxcContainer
ExecutionResult RunJson(string json, JsonOptions? options = null);
Task<ExecutionResult> RunJsonAsync(string json, JsonOptions? options = null,
    CancellationToken cancellationToken = default);
MxcProcess SpawnJson(string json, JsonOptions? options = null);
Task<MxcProcess> SpawnJsonAsync(string json, JsonOptions? options = null,
    CancellationToken cancellationToken = default);

public sealed class PolicyFailures
{
    public uint FormatVersion { get; init; } = 1;
    public PolicyFailureResult[] Results { get; init; } = [];
    public string ToJson();
    public static PolicyFailures FromJson(string json);
    public static PolicyFailures? FromException(MxcException exception);
}

public sealed class PolicyFailureResult
{
    public uint Version { get; init; } = 1;
    public uint MinimumReaderVersion { get; init; } = 1;
    public uint Outcome { get; init; }
    public PolicyFailureDetail[] Details { get; init; } = [];
}

public sealed class PolicyFailureDetail
{
    public uint FailureClass { get; init; }
    public uint FailureReason { get; init; }
    public uint RequiredAction { get; init; }
    public uint ResourceKind { get; init; }
    public uint ValueKind { get; init; }
    public uint Flags { get; init; }
    public ulong RequestedValue { get; init; }
    public ulong RequiredValue { get; init; }
    public ushort[]? Resource { get; init; }
    public string? GetResourceText();
}
```

These are signatures, not compilable class implementations. Source-generated
`MxcJson` helpers/roots handle all serialized DTOs/options without reflection;
public storage helpers work with Native AOT. The sealed SDK-owned models keep
numeric fields open rather than defining closed enums.

### Node

Entry point: `@microsoft/mxc-sdk/v1/dev`. Operations remain asynchronous.
`JsonOptions` continues to hold `experimental?: boolean`;
only `CreationJsonOptions` accepts feedback.

```typescript
import type { ExecutionResult, MxcProcess } from '@microsoft/mxc-sdk/v1';

export interface JsonOptions {
  experimental?: boolean;
}
export interface CreationJsonOptions extends JsonOptions {
  policyFailures?: PolicyFailures;
}

export declare function runJson(
  json: string, options?: CreationJsonOptions,
): Promise<ExecutionResult>;
export declare function spawnJson(
  json: string, options?: CreationJsonOptions,
): Promise<MxcProcess>;

export interface PolicyFailures {
  formatVersion: number;
  results: PolicyFailureResult[];
}
export interface PolicyFailureResult {
  version: number;
  minimumReaderVersion: number;
  outcome: number;
  details: PolicyFailureDetail[];
}
export interface PolicyFailureDetail {
  failureClass: number;
  failureReason: number;
  requiredAction: number;
  resourceKind: number;
  valueKind: number;
  flags: number;
  requestedValue: string;
  requiredValue: string;
  resource?: number[];
}

export declare function policyFailuresFromError(error: unknown): PolicyFailures | undefined;
export declare function parsePolicyFailures(json: string): PolicyFailures;
export declare function serializePolicyFailures(value: PolicyFailures): string;
export declare function policyFailureResourceText(detail: PolicyFailureDetail): string | undefined;
```

### Named values, not closed numeric types

Rust uses associated constants; .NET uses public static constant classes and
Node exports frozen objects with the same PascalCase members. The DTO fields
remain primitive so unknown values/bits survive inspection and storage.

| Meaning | Rust owner and prefix | .NET/Node group and known members |
| --- | --- | --- |
| Outcome | `PolicyFailureResult::OUTCOME_` | `PolicyFailureOutcomes`: `Unknown=0`, `Blocked=1`, `EvaluationFailed=2` |
| Class | `PolicyFailureDetail::CLASS_` | `PolicyFailureClasses`: `None=0`, `Network=1`, `Filesystem=2`, `EnforcementMode=3` |
| Reason | `PolicyFailureDetail::REASON_` | `PolicyFailureReasons`: `None=0`, `CapabilityNotAllowed=1`, `AccessExceedsCeiling=2`, `DenyRequired=3`, `RequestPathLimit=4` |
| Action | `PolicyFailureDetail::ACTION_` | `PolicyFailureActions`: `None=0`, `RemoveCapability=1`, `RestrictFilesystemAccess=2`, `ReducePathCount=3` |
| Resource | `PolicyFailureDetail::RESOURCE_KIND_` | `PolicyFailureResourceKinds`: `None=0`, `Path=1`, `Capability=2` |
| Value | `PolicyFailureDetail::VALUE_KIND_` | `PolicyFailureValueKinds`: `None=0`, `Access=1`, `PathCount=2` |
| Access value | `PolicyFailureDetail::ACCESS_` | `PolicyFailureAccessValues`: `None=0`, `ReadOnly=1`, `ReadWrite=2` |
| Flag bits | `PolicyFailureDetail::FLAG_` | `PolicyFailureFlags`: `None=0`, `HasActionableDetails=1`, `ResourceComplete=2`, `ResourceUnavailable=4` |

Rust suffixes use upper snake case, for example `OUTCOME_BLOCKED`,
`REASON_CAPABILITY_NOT_ALLOWED`, `ACCESS_READ_ONLY`. Constant types are
`u32` / `uint` / `number`, except access values: `u64` / `ulong` / decimal
`string` (`'0'`, `'1'`, `'2'`) to match each SDK's fields. Access constants
apply only when the value kind is Access; inspect/combine flag bits as a mask.

`PolicyFailures::NATIVE_CODE_POLICY_BLOCKED` and .NET/Node
`PolicyFailureNativeCodes.PolicyBlocked` name the existing native-code string
`"0x800704EC"`: `HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY)`.
A known outcome, flag or HRESULT alone is not sufficient reason to retry.

### Windows CLI

`wxc-exec --policy-failures PATH` reads the inner feedback JSON from a
caller-owned file, separately from the request JSON. Omission is strict.
Invalid/unreadable input is an explicit error. The CLI attempts creation once,
emits available cumulative feedback in the structured error envelope, and
neither persists observations nor retries for the application.

Existing stdin semantics remain unchanged. Reject feedback with PTY,
validation, management or other unsupported modes. Diagnostic records share
stderr with workload output; JSON shape does not authenticate their origin.
Prefer direct SDK errors rather than scraping that stream for an automated
controller.

## Inputs, results, and SDK differences

### Invocation inputs

| Input | Meaning, omission and rejection |
| --- | --- |
| Rust `policy_failures` | Optional borrowed feedback; `None` is strict. `Some(empty_feedback)` is an explicit supplied value and still requires the supported creation path. |
| .NET `PolicyFailures` | Nullable feedback; null options/property mean no feedback. A present empty result collection is explicit feedback, not absence. |
| Node `policyFailures` | Omitted/`undefined` means no feedback. `null`, `{}`, invalid shapes and numeric representations reject with `MxcError(malformed_request)`; a valid empty feedback object is explicit input. |
| `experimental` / `Experimental` | Existing experimental-backend authorization, unchanged; it does not select a request version, authorize feedback on another backend or grant administrative approval. |

The shared [feedback bounds](README.md#cumulative-observations-and-bounds)
apply. Feedback on unsupported operations is rejected, including a shared
Node options object carrying the property. No operation silently ignores it.
No stdin, telemetry, timeout or lifecycle option is moved or redesigned.

### Error extension and storage JSON

The ordinary error retains its native category, operation and status.
Structured data uses Rust `Error.details: Option<Box<serde_json::Value>>`,
.NET `MxcException.Details: JsonElement?` and Node
`MxcError.details?: Record<string, unknown>`. Typed feedback access is Dev-only.
Other backend details remain independent and intact.

This is an illustrative complete `details` object, not the value to store:

```json
{
  "policyFailures": {
    "formatVersion": 1,
    "results": [{
      "version": 1,
      "minimumReaderVersion": 1,
      "outcome": 1,
      "details": [{
        "failureClass": 2,
        "failureReason": 2,
        "requiredAction": 2,
        "resourceKind": 1,
        "valueKind": 1,
        "flags": 3,
        "requestedValue": "2",
        "requiredValue": "1",
        "resource": [67, 58, 92, 119, 111, 114, 107]
      }]
    }]
  }
}
```

The detail observes read-write access to `C:\work` exceeding a read-only
ceiling. It does not enumerate the complete administrative policy.

- Store the inner `policyFailures` value beginning `{ formatVersion, results }`,
  not the whole error extension. Supply the restored value as the creation
  option. The feedback format, native batch versions and request JSON version
  are independent.
- Field names are camelCase. All fields are required except `resource`.
  Format version1 is supported; unknown object fields are rejected.
  Versions/codes/flags are unsigned32 JSON numbers. Unknown numeric values
  remain inspectable but do not authorize an unknown remedy.
- `requestedValue` / `requiredValue` are unsigned64 decimal JSON strings, up to
  `"18446744073709551615"`. Rust/.NET expose integers; Node keeps strings.
  Do not convert through JavaScript `Number`. Requested values describe the
  native batch's evaluated request, not a subsequent invocation.
- `resource` holds unsigned16 UTF-16 units without a terminator. Omitted/null
  resources normalize to absence and serialize as omitted; empty arrays remain
  present. Malformed UTF-16 remains inspectable. Text helpers decode strictly:
  Rust returns `FromUtf16Error`, .NET throws `DecoderFallbackException`, Node
  throws `MxcError(malformed_request)`. Decoded text alone is not actionable.
- Optional companion `policyFeedbackError` is always an object with string
  `code` and `reason`; current codes are `unsafeReplay` and
  `feedbackLimitExceeded`. Stop automatic retries on its presence, including
  unknown codes, not by matching text.
- Optional companion `policyResultUnavailable` is a diagnostic string. Known
  supplied observations remain when fresh native data is unavailable; no new
  approval or failure is invented.

Extractors return an owned value, or None/null/undefined when absent.
Malformed present data is an error, not absence. Invalid stored feedback is
Rust `Error(MalformedRequest)`, .NET `JsonException`, or Node
`MxcError(malformed_request)`. Malformed native error data remains an explicit
SDK error. Valid storage parsing does not prove that creation will accept it.
Companion diagnostics and application stop/budget state are not retained by
feedback serialization.

### Results, failures and runtime differences

| Situation | Caller receives |
| --- | --- |
| Native policy refusal | Ordinary error plus available cumulative structured failures, preserving high-level policy guidance/native operation/status. |
| Unsafe/unsupported feedback or exceeded input limit | Existing validation/unsupported error before creation; structured terminal context where applicable. No guessed edit, fallback or workload. |
| Wrong backend | Rust `UnsupportedContainment`; Node/.NET corresponding existing unsupported-containment category. |
| Unsupported operation | Rust `UnsupportedPhase`; .NET `MxcException(MalformedRequest)`; Node `MxcError(malformed_request)`. |
| Native environment succeeds | Existing `ExecutionResult` or process handle and ordinary warnings; no policy-correction report/text. |
| Launch/wait/read/cancellation/cleanup failure | Existing error and ownership semantics; supplied observations do not make a workload retry safe. |

Rust exposes byte-preserving captured output and synchronous calls; .NET/Node
capture exposes existing lossy UTF-8 text. Rust drops a process; .NET/Node
dispose it through their normal APIs. Creation attempts remain distinct from
workload exit/timeout results.

.NET cancellation tokens remain last. Canceling an async wait does not promise
cancellation of blocking native creation; existing wrappers dispose late
unclaimed spawn results. Node has no new `AbortSignal`; Rust has no new token.
Do not treat cancellation as a policy refusal or automatically create again.
Probes/discovery remain advisory backend serviceability, not policy approval.

## Compatibility and request mapping

**Breaking change: Rust V1.Dev only.** Adding `policy_failures` and
`#[non_exhaustive]` to Dev `JsonOptions` breaks existing exhaustive Dev struct
literals. Use the existing Dev entry point for incubation; callers construct
with `Default` and set fields. New feedback DTOs are non-exhaustive for future
additions. Maintainer approval is still required before shipping.

Stable typed V1 options/functions are preserved. .NET adds an optional property
to sealed Dev options; Node adds an optional property on creation options.
Existing no-feedback calls remain strict. Error prose is not a structured
control channel: policy specifics are exclusively structured, while useful
high-level text and native status remain.

Feedback maps to a native invocation option, not an MXC request field.
No request contract version, default, generated request schema or policy
field's optional-presence behavior changes. Native PSEP meanings and the
feedback storage contract are separately versioned.

Native library/adapters remain co-versioned. Error-detail/feedback transport
must preserve owned copies and complete/idempotent frees, regenerate C#
bindings, update Node layouts and contain every panic across the C ABI.
Do not claim compatibility between mismatched native libraries/bindings.
No new request version or experimental flag is a compatibility workaround.

## Validation and documentation

The shared [validation plan](README.md#acceptance-criteria-and-validation-plan)
defines capable hosts, scheduled governed cases and cleanup oracles.
SDK-specific coverage must include:

- Rust non-exhaustive construction, the explicit Dev literal break, public
  captured/live creation, caller-owned accumulation/storage and unchanged
  request/output/ownership semantics.
- Node Dev exports, open numeric fields, named constants, null/presence/
  malformed data, owned error copies and standard/fatal console rendering
  without policy details; public creation forwarding and disposal.
- .NET sync/async/default/null options, native-memory independence, cancellation/
  late-result disposal, source-generated serialization/storage and net8.0/
  net10.0 Native AOT roots for DTOs/options. Static constant groups are not
  serialized DTOs and require no reflection path.
- Cross-SDK fixed JSON encodings, unknown code/flag retention, full unsigned64
  values, UTF-16 resource distinctions, terminal overflow and companion-state
  handling. Compare named values with the authoritative native schema.

No runtime tests are claimed for this documentation PR. Prototype references
for review are the [Rust](https://github.com/microsoft/mxc/blob/6e04aa415e6e1f1bf901bfb76b7ebdc957bc6083/docs/api-reference/rust/v1/dev.md),
[.NET](https://github.com/microsoft/mxc/blob/6e04aa415e6e1f1bf901bfb76b7ebdc957bc6083/docs/api-reference/dotnet/v1/dev.md)
and [Node](https://github.com/microsoft/mxc/blob/6e04aa415e6e1f1bf901bfb76b7ebdc957bc6083/docs/api-reference/node/v1/dev.md)
Dev contracts. They illustrate the proposed API, not release approval.

Consumer updates belong in all three SDK READMEs and versioned V1.Dev
signature/type references, the API index, and caller-owned storage/resubmission
examples. Keep stable typed V1 references intact; document host prerequisites,
strict defaults, structured-only specifics, limits and normal process cleanup.

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
