# API proposal: caller-owned policy preparation

> **Audience:** MXC developers

- **Issue:** [#1634](https://github.com/microsoft/mxc/issues/1634)
- **Feature design spec:** [README.md](README.md), status Accepted

Use `mxc_sdk::v1::dev`, `Microsoft.Mxc.Sdk.V1.Dev` and
`@microsoft/mxc-sdk/v1/dev`. A new preparation operation takes complete MXC
request JSON and caller-owned `PolicyFailures`, returning a candidate request
and structured changes without creating a container. Existing creation APIs
accept only the caller-chosen JSON and their unchanged options. The application
owns inspection, acceptance, storage, merging, retry limits and stopping decisions.
[Backend/mode support](README.md#backend-applicability-and-availability) and
[ownership/recovery](README.md#resource-ownership-and-failure-recovery) are
defined in the feature design.

## Caller scenario

See the feature's [two scenarios](README.md#problem-and-scope) and
[call sequence](README.md#design-and-security). The examples use caller-authored
request JSON with a registered version. Observations are required preparation
arguments, not creation options or request JSON fields. Preparation returns
`PreparedPolicyRequest`; a separate accepted creation returns the ordinary
result or process, without a policy-correction report or warning text.

### Rust: prepare, inspect and optionally execute

`execute_approved` is application code, not an MXC API. Its callback inspects
the actual candidate and changes before deciding whether to create a container.

```rust
use mxc_sdk::v1::{
    dev::{self, JsonOptions, PolicyFailures, PreparedPolicyRequest},
    Error, ExecutionResult,
};

fn execute_approved(
    request_json: &str,
    failures: &PolicyFailures,
    accept: impl FnOnce(&PreparedPolicyRequest) -> bool,
) -> Result<Option<ExecutionResult>, Error> {
    // Preparation proposes changes without creating a container or workload.
    let prepared = dev::prepare_policy_json(request_json, failures, Default::default())?;
    if !accept(&prepared) {
        return Ok(None);
    }
    // Creation receives only the caller-approved JSON, never observations.
    dev::run_json(&prepared.request_json, JsonOptions { experimental: false }).map(Some)
}
```

Extract owned observations using `PolicyFailures::from_error`; store them with
`to_json` and restore with `from_json`. Combine earlier and fresh observations
using `prior.merged_with(&current)`, which leaves both inputs intact. Store
candidate/change data separately with `PreparedPolicyRequest::to_json`.
Approval decisions, original companion diagnostics and retry budgets are
application state, not part of either storage value.

The [complete example](../../../../../src/mxc-sdk/examples/policy_feedback.rs)
shows bounded caller-controlled retries, storage, exact reviewed-candidate
acceptance and output/exit handling. It accepts an unchanged candidate without
an approval file; changed candidates require the exact reviewed result.

### .NET and Node: restore, prepare and choose

These application helpers accept stored observations and an explicit candidate
review callback. They do not automatically retry or treat stored data as approval.

```csharp
using System;
using Microsoft.Mxc.Sdk.V1;
using System.Threading;
using System.Threading.Tasks;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;

static async Task<ExecutionResult?> ExecuteApprovedAsync(
    string requestJson,
    string storedJson,
    Func<Dev.PreparedPolicyRequest, bool> accept,
    CancellationToken cancellationToken)
{
    var failures = Dev.PolicyFailures.FromJson(storedJson);
    var prepared = await Dev.MxcContainer.PreparePolicyJsonAsync(
        requestJson, failures, cancellationToken: cancellationToken);
    if (!accept(prepared))
        return null;
    return await Dev.MxcContainer.RunJsonAsync(
        prepared.RequestJson, cancellationToken: cancellationToken);
}
```

```typescript
import {
  parsePolicyFailures, preparePolicyJson, runJson,
} from '@microsoft/mxc-sdk/v1/dev';
import type { PreparedPolicyRequest } from '@microsoft/mxc-sdk/v1/dev';
import type { ExecutionResult } from '@microsoft/mxc-sdk/v1';

async function executeApproved(
  requestJson: string,
  storedJson: string,
  accept: (candidate: PreparedPolicyRequest) => boolean | Promise<boolean>,
): Promise<ExecutionResult | undefined> {
  const prepared = await preparePolicyJson(requestJson, parsePolicyFailures(storedJson));
  if (!(await accept(prepared))) return undefined;
  return runJson(prepared.requestJson);
}
```

The saved observations can prepare a different request or be reused by another
creator, subject to current-request safety checks and fresh Windows evaluation
on creation. .NET uses `FromException`/`MergedWith` for extraction/merging;
Node uses `policyFailuresFromError`/`mergePolicyFailures`. Both provide
separate candidate/result storage helpers.
Captured results need no disposal. A `spawn_json` / `SpawnJson` / `spawnJson`
result instead transfers the existing live process/stream ownership to the
caller; dispose/drop it through the normal SDK API. No stdin redesign or new
PTY/lifecycle control is proposed.

## Proposed signatures and types

All additions below are V1.Dev-only except the generic structured-error
extension. Existing V1 creation APIs, including V1.Dev, take no observations.

### Rust

Entry point: `mxc_sdk::v1::dev`. Retain the operation names and synchronous
behavior; use existing `mxc_sdk::v1::{Error, ExecutionResult, MxcProcess}`.
The public feedback structs implement `Debug`, `Clone`, `PartialEq`, `Eq`,
`Default` and Serde serialization/deserialization.

```rust
pub struct JsonOptions {
    pub experimental: bool,
}

pub fn run_json(json: &str, options: JsonOptions) -> Result<ExecutionResult, Error>;
pub fn spawn_json(json: &str, options: JsonOptions) -> Result<MxcProcess, Error>;

#[non_exhaustive]
pub struct PolicyPreparationOptions {
    pub experimental: bool,
}
pub fn prepare_policy_json(
    json: &str,
    failures: &PolicyFailures,
    options: PolicyPreparationOptions,
) -> Result<PreparedPolicyRequest, Error>;

#[non_exhaustive]
pub struct PreparedPolicyRequest {
    pub request_json: String,
    pub changes: Vec<PolicyChange>,
}
impl PreparedPolicyRequest {
    pub fn from_json(json: &str) -> Result<Self, Error>;
    pub fn to_json(&self) -> Result<String, Error>;
}

#[non_exhaustive]
pub struct PolicyChange {
    pub operation: PolicyChangeOperation,
    pub path: String,
    pub before: serde_json::Value,
    pub after: serde_json::Value,
}
#[non_exhaustive]
pub enum PolicyChangeOperation { Add, Remove, Replace }

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
    pub fn merged_with(&self, other: &Self) -> Result<Self, Error>;
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

These are declaration shapes, not implementation bodies. Existing
`JsonOptions { experimental: false }` literals and `Vec<JsonOptions>` remain
valid. Construct the new non-exhaustive `PolicyPreparationOptions` with
`Default` and set fields. Preparation borrows observations for the call and
returns owned candidate/change data. Defaults are experimental authorization
off, observation format/native versions 1, unknown outcome 0 and empty
results/details. There is no cancellation token addition.

### .NET

Entry point: `Microsoft.Mxc.Sdk.V1.Dev`; result/process/error types belong to
`Microsoft.Mxc.Sdk.V1`. Methods and trailing cancellation parameters retain
their existing shapes.

```csharp
using Microsoft.Mxc.Sdk.V1;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

public sealed class JsonOptions
{
    public bool Experimental { get; set; }
}
public sealed class PolicyPreparationOptions
{
    public bool Experimental { get; set; }
}

// Microsoft.Mxc.Sdk.V1.Dev.MxcContainer
PreparedPolicyRequest PreparePolicyJson(string json, PolicyFailures failures,
    PolicyPreparationOptions? options = null);
Task<PreparedPolicyRequest> PreparePolicyJsonAsync(string json, PolicyFailures failures,
    PolicyPreparationOptions? options = null, CancellationToken cancellationToken = default);
ExecutionResult RunJson(string json, JsonOptions? options = null);
Task<ExecutionResult> RunJsonAsync(string json, JsonOptions? options = null,
    CancellationToken cancellationToken = default);
MxcProcess SpawnJson(string json, JsonOptions? options = null);
Task<MxcProcess> SpawnJsonAsync(string json, JsonOptions? options = null,
    CancellationToken cancellationToken = default);

public enum PolicyChangeOperation { Add, Remove, Replace }
public sealed class PolicyChange
{
    public PolicyChangeOperation Operation { get; init; }
    public string Path { get; init; }
    public JsonElement Before { get; init; }
    public JsonElement After { get; init; }
}
public sealed class PreparedPolicyRequest
{
    public string RequestJson { get; init; }
    public PolicyChange[] Changes { get; init; }
    public string ToJson();
    public static PreparedPolicyRequest FromJson(string json);
}

public sealed class PolicyFailures
{
    public uint FormatVersion { get; init; } = 1;
    public PolicyFailureResult[] Results { get; init; } = [];
    public string ToJson();
    public static PolicyFailures FromJson(string json);
    public static PolicyFailures? FromException(MxcException exception);
    public PolicyFailures MergedWith(PolicyFailures other);
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

`JsonElement` belongs to `System.Text.Json`; the SDK owns result values
independently of source documents and native buffers.
These are signatures, not compilable class implementations. Source-generated
`MxcJson` helpers/roots handle all serialized DTOs/options without reflection;
public storage helpers work with Native AOT. The sealed SDK-owned models keep
numeric fields open rather than defining closed enums.

### Node

Entry point: `@microsoft/mxc-sdk/v1/dev`. Operations remain asynchronous.
`JsonOptions` continues to hold only `experimental?: boolean`.
Preparation uses a separate options interface and required observations.

```typescript
import type { ExecutionResult, MxcProcess } from '@microsoft/mxc-sdk/v1';

export interface JsonOptions {
  experimental?: boolean;
}
export interface PolicyPreparationOptions {
  experimental?: boolean;
}

export declare function runJson(
  json: string, options?: JsonOptions,
): Promise<ExecutionResult>;
export declare function spawnJson(
  json: string, options?: JsonOptions,
): Promise<MxcProcess>;

export type JsonPointer = string;
export type JsonValue =
  | null | boolean | number | string
  | JsonValue[] | { [key: string]: JsonValue };
export type PolicyPreparationChange =
  | { operation: 'add'; path: JsonPointer; before: null; after: JsonValue }
  | { operation: 'remove'; path: JsonPointer; before: JsonValue; after: null }
  | { operation: 'replace'; path: JsonPointer; before: JsonValue; after: JsonValue };
export interface PreparedPolicyRequest {
  requestJson: string;
  changes: PolicyPreparationChange[];
}
export declare function preparePolicyJson(
  requestJson: string, failures: PolicyFailures, options?: PolicyPreparationOptions,
): Promise<PreparedPolicyRequest>;
export declare function parsePreparedPolicyRequest(json: string): PreparedPolicyRequest;
export declare function serializePreparedPolicyRequest(value: PreparedPolicyRequest): string;

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
export declare function mergePolicyFailures(older: PolicyFailures, newer: PolicyFailures): PolicyFailures;
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

The CLI retains strict creation and its existing error transport. No
observation-input or preparation command is proposed. Use the SDK preparation
API and ordinary strict creation for an application-controlled workflow.
Existing stdin, PTY, validation and management behavior remains unchanged.
Diagnostic records share stderr with workload output; JSON shape does not
authenticate their origin. Prefer direct SDK errors rather than scraping that
stream for an automated controller.

## Inputs, results, and SDK differences

### Preparation inputs

| Input | Meaning, omission and rejection |
| --- | --- |
| Request JSON | Required complete create-and-run request in a registered contract, bounded to 8 MiB UTF-8. Empty, malformed or unsupported input fails without a candidate or creation. The original string remains unchanged. |
| `failures` | Required owned observation value, borrowed for the Rust call. A valid empty result collection still requires the supported preparation path; it is not an omitted input or authorization to create. Missing/malformed data is rejected, not silently ignored. |
| `PolicyPreparationOptions` | Separate extensible type. Rust requires a value, normally `Default`; .NET accepts null/omitted options and Node accepts omitted options. Experimental authorization defaults off. |
| `experimental` / `Experimental` | Existing experimental-backend authorization; it neither selects a request version nor grants administrative approval. Supply it separately to subsequent strict creation when required. |

The shared [observation bounds](README.md#caller-owned-observations-and-bounds)
apply. Creation, PTY, lifecycle and validation options do not accept
observations. No stdin, telemetry, timeout or lifecycle option is moved or
redesigned.

### Prepared request and exact changes

The result storage JSON has only `requestJson` and `changes`:

```json
{
  "requestJson": "{\"version\":\"1.0.0\",\"process\":{\"commandLine\":\"cmd.exe /c exit 0\"},\"processContainer\":{\"capabilities\":[]}}",
  "changes": [{
    "operation": "replace",
    "path": "/processContainer/capabilities",
    "before": ["registryRead"],
    "after": []
  }]
}
```

`requestJson` is the complete candidate in the original authoring contract,
not an internal runtime configuration. Required edits preserve metadata,
unrelated settings and optional-field presence; formatting/property order can
change. The native engine reparses it and checks the prospective effective
policy and PSEC. If reducing access changes inferred cwd, the candidate adds
`process.cwd` to retain the original launch directory.

Every change requires `operation`, `path`, `before` and `after`. Operations
are the strings `add`, `remove` and `replace`, including .NET enum
serialization. Paths are RFC 6901 JSON Pointers: `~0` escapes `~`, `~1`
escapes `/`, and the empty pointer identifies the root. Changes are ordered;
whole arrays may be replaced.

`before` and `after` have the same underlying type: JSON values, including
actual JSON null. Add uses `before: null` for an absent original location;
Remove uses `after: null` for an absent candidate location. Replace treats
null as a present JSON null. Add/Remove can also add/remove a real null value;
the operation distinguishes absence without an extra wrapper.

Preparation returns at most 32 MiB of complete result JSON with 4,096 changes.
A stored candidate can exceed 8 MiB when the whole result fits. Unsafe or
over-limit preparation returns no partial candidate or truncated changes.
Storage helpers validate shape and bounds, not caller approval, correspondence
to a particular original request, or current backend policy. The report is
not a generic patch-execution API or an approval token.

Rust uses `serde_json::Value`, .NET uses owned `JsonElement`, and Node uses
JSON-compatible values. Node numeric change values use JavaScript `number`
precision, while `requestJson` retains candidate JSON text. Observation u64
values remain lossless decimal strings. .NET preparation storage uses compact
escaping, not HTML-safe output; escape separately when embedding it in HTML.

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
  not the whole error extension. Supply restored observations to preparation,
  never creation. Observation format, native batch versions and request JSON
  version are independent.
- Field names are camelCase. All fields are required except `resource`.
  Format version 1 is supported; unknown object fields are rejected.
  Versions/codes/flags are unsigned 32-bit JSON numbers. Unknown numeric values
  remain inspectable but do not authorize an unknown remedy.
- `requestedValue` / `requiredValue` are unsigned 64-bit decimal JSON strings, up to
  `"18446744073709551615"`. Rust/.NET expose integers; Node keeps strings.
  Do not convert through JavaScript `Number`. Requested values describe the
  native batch's evaluated request, not a subsequent invocation.
- `resource` holds unsigned 16-bit UTF-16 units without a terminator. Omitted/null
  resources normalize to absence and serialize as omitted; empty arrays remain
  present. Malformed UTF-16 remains inspectable. Text helpers decode strictly:
  Rust returns `FromUtf16Error`, .NET throws `DecoderFallbackException`, Node
  throws `MxcError(malformed_request)`. Decoded text alone is not actionable.
- Optional companion `policyFeedbackError` is always an object with string
  `code` and `reason`; current codes are `unsafeReplay` and
  `feedbackLimitExceeded`. Stop automatic retries on its presence, including
  unknown codes, not by matching text.
- Optional companion `policyResultUnavailable` is a diagnostic string.
  Earlier observations remain in caller storage when fresh native data is
  unavailable; strict creation neither receives nor returns that history.
  No new approval or failure is invented.

Extractors return an owned value, or None/null/undefined when absent.
Malformed present data is an error, not absence. Invalid stored feedback is
Rust `Error(MalformedRequest)`, .NET `JsonException`, or Node
`MxcError(malformed_request)`. Malformed native error data remains an explicit
SDK error. Valid storage parsing does not prove preparation eligibility.
Merge helpers preserve first-seen order and whole-batch boundaries, deduplicate
identical batches, and return an owned history without changing inputs.
Invalid or over-limit merging fails without truncation. Companion diagnostics
and application stop/budget state are not retained by observation serialization.

### Results, failures and runtime differences

| Situation | Caller receives |
| --- | --- |
| Native policy refusal | Ordinary error plus fresh structured failures where available, preserving high-level policy guidance/native operation/status. |
| Preparation succeeds | Owned candidate request and exact changes, no container/process handle. The caller can inspect, accept, edit, reject or store it. |
| Unsafe/unsupported preparation or exceeded input/result limit | Existing validation/unsupported error; structured terminal context where applicable. No guessed edit, partial candidate, fallback or workload. |
| Wrong backend | Rust `UnsupportedContainment`; Node/.NET corresponding existing unsupported-containment category. |
| Invalid request phase | Existing request parsing/phase error; preparation produces no candidate or creation. |
| Native environment succeeds | Existing `ExecutionResult` or process handle and ordinary warnings; no policy-correction report/text. |
| Launch/wait/read/cancellation/cleanup failure | Existing error and ownership semantics; stored observations do not make a workload retry safe. |

Rust exposes byte-preserving captured output and synchronous calls; .NET/Node
capture exposes existing lossy UTF-8 text. Rust drops a process; .NET/Node
dispose it through their normal APIs. Creation attempts remain distinct from
workload exit/timeout results.

.NET cancellation tokens remain last. Canceling an async preparation/run wait
stops awaiting, not the blocking native operation; existing wrappers dispose
late unclaimed spawn results. Node preparation uses Koffi's worker pool for
native filesystem work. Node has no new `AbortSignal`; Rust has no new token.
Do not treat cancellation as a policy refusal or automatically create again.
Probes/discovery remain advisory backend serviceability, not policy approval.

## Compatibility and request mapping

**Additive V1.Dev API; no creation compatibility exception.** Preserve existing
Rust `JsonOptions` fields, exhaustive struct literals and lifetime-free
signatures/storage. New preparation options, results/change types and
observations are non-exhaustive. .NET uses separate sealed preparation options
and result classes; Node uses a separate options interface and discriminated
change union. No V2 surface is required for this feature.

Existing V1 options/functions, including V1.Dev creation, remain supported and
strict. Error prose is not a structured control channel: policy specifics are
exclusively structured, while useful high-level text and native status remain.

Observations and preparation options are separate API arguments, not MXC
request fields. The candidate uses the original contract's permanent fields.
No request contract version, default, generated request schema or policy-field
presence rule changes. Native PSEP meanings and observation storage are
separately versioned.

Native library/adapters remain co-versioned. Error-detail/preparation transport
must preserve owned copies and complete/idempotent frees, regenerate C#
bindings, update Node layouts and contain every panic across the C ABI.
Do not claim compatibility between mismatched native libraries/bindings.
No new request version or experimental flag is a compatibility workaround.

## Validation and documentation

The shared [validation plan](README.md#acceptance-criteria-and-validation-plan)
defines capable hosts, public-SDK functional cases and cleanup oracles.
SDK-specific coverage must include:

- Rust existing Dev struct literals and lifetime-free options storage, new
  non-exhaustive preparation options/results, public preparation followed by
  strict captured/live creation, and caller-owned merging/storage.
- Node Dev exports, open numeric fields, named constants, null/presence/
  malformed data, owned error copies and standard/fatal console rendering
  without policy details; real nonempty preparation arguments crossing the
  C binding, caller-selected creation and disposal.
- .NET sync/async/default/null options, native-memory independence, cancellation/
  late-result disposal, source-generated serialization/storage and net8.0/
  net10.0 Native AOT roots for DTOs/options. Static constant groups are not
  serialized DTOs and require no reflection path.
- Cross-SDK fixed JSON encodings, exact required before/after values,
  null/absence operations, JSON Pointers, unknown code/flag retention, full
  unsigned64 observation values, UTF-16 distinctions, all-or-nothing limits
  and companion-state handling. Compare named values with the native schema.

The [Rust](../../../../api-reference/rust/v1/dev.md),
[.NET](../../../../api-reference/dotnet/v1/dev.md)
and [Node](../../../../api-reference/node/v1/dev.md) V1.Dev references
document the implemented API.

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
