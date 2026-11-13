# Node V1.Dev MXC request JSON API and policy preparation

> **Audience:** MXC consumers

Public subpath: `@microsoft/mxc-sdk/v1/dev`. Operations accept complete MXC
request JSON with a caller-declared contract version and return Promises.
MXC validates the unchanged document against its declared contract and
checks policy and backend availability.

`JsonOptions` contains optional `experimental?: boolean` authorization,
independent of the authored JSON version. `runJson` and `spawnJson` perform
strict creation and accept only this options shape. `PtyJsonOptions` also
contains optional `size?: MxcPtySize` (24 rows by 80 columns by default).
Execution returns the existing V1 result or process types. Lifecycle and
validation return the complete native response JSON string. Phase-specific
methods reject a different phase before native dispatch.

```typescript
export interface JsonOptions {
  experimental?: boolean;
}
export interface PtyJsonOptions extends JsonOptions {
  size?: MxcPtySize;
}

export function runJson(json: string, options?: JsonOptions): Promise<ExecutionResult>;
export function spawnJson(json: string, options?: JsonOptions): Promise<MxcProcess>;
export function spawnWithPtyJson(json: string, options?: PtyJsonOptions): Promise<MxcPtyProcess>;

export function runInContainerJson(json: string, options?: JsonOptions): Promise<ExecutionResult>;
export function spawnInContainerJson(json: string, options?: JsonOptions): Promise<MxcProcess>;
export function spawnInContainerWithPtyJson(
  json: string, options?: PtyJsonOptions
): Promise<MxcPtyProcess>;

export function provisionContainerJson(json: string, options?: JsonOptions): Promise<string>;
export function startContainerJson(json: string, options?: JsonOptions): Promise<string>;
export function stopContainerJson(json: string, options?: JsonOptions): Promise<string>;
export function deprovisionContainerJson(json: string, options?: JsonOptions): Promise<string>;
export function validateProvisionJson(json: string, options?: JsonOptions): Promise<string>;
export function validateStartJson(json: string, options?: JsonOptions): Promise<string>;
export function validateStopJson(json: string, options?: JsonOptions): Promise<string>;
export function validateDeprovisionJson(json: string, options?: JsonOptions): Promise<string>;
export function validateProcessJson(json: string, options?: JsonOptions): Promise<string>;
```

Captured stdout and stderr are lossy UTF-8 text. Callers own pipe and PTY
handles. Existing-container execution leaves the container caller-owned.
On timeout, in-container capture returns partial text without waiting for
output streams to close. Read failures reject promptly, and cleanup
preserves the original read or wait error.

On Windows, ProcessContainer `spawnWithPtyJson` uses `wxc-exec`;
`0.9.0-alpha` requests support the `appcontainer` alias. Its Promise resolves
at executor startup, before policy validation. Later failures appear in
combined terminal output and the exit code. Structured warnings and output
metadata are unavailable on this route. The executor enforces
`process.timeout`, but `wait().timedOut` is `false`: the terminal channel
reports only an exit code.

## Separate policy preparation

A supported Windows ProcessContainer creation refusal can include structured
observations in `MxcError.details.policyFailures`. Extract an owned copy with
`policyFailuresFromError`. Creation attempts remain strict and report their
own observations; the application combines earlier and newer batches with
`mergePolicyFailures` when needed.

`preparePolicyJson(requestJson, failures, options?)` validates the observations
and asks the native backend to prepare supported restrictive changes. It
creates no container and leaves the original request string and observations
unchanged.
Native filesystem work runs on Koffi's worker pool rather than blocking the
Node event loop. The result contains the candidate MXC request JSON and its
ordered edits. The application inspects and accepts the candidate before
passing `prepared.requestJson` to `runJson` or `spawnJson`.

Preparation has a separate extensible `PolicyPreparationOptions` interface.
Its `experimental` authorization is independent of the request's declared
contract version and must also be supplied to subsequent creation when
required. Observations are untrusted data, not policy approval. Unknown native
codes remain inspectable and do not authorize guessed changes. Unsupported
actions and unsafe edits fail explicitly. Windows reevaluates the current
creator's policy during strict creation.

Preparation accepts create-and-run requests for every backend and OS. With
empty observations it returns the request unchanged with no changes.
As with creation, experimental backends require `experimental: true`; without
it, preparation throws `MxcError` (`backend_unavailable`).
Observations are specific to the backend that reported them; native Windows
ProcessContainer is currently the only backend that reports and applies them.
Non-empty observations for any other backend throw `MxcError`
(`unsupported_containment`) rather than being ignored.

`preparePolicyJson` is the only operation that takes observations; creation,
lifecycle, validation, and PTY options accept only the properties shown above,
and any other property throws `MxcError` (`malformed_request`). The SDK keeps
no observations between calls and creates no workload during preparation.
Ordinary warnings are reported in the result or process `warnings` property.

```typescript
export interface PolicyPreparationOptions {
  experimental?: boolean;
}
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

export function preparePolicyJson(
  requestJson: string, failures: PolicyFailures, options?: PolicyPreparationOptions
): Promise<PreparedPolicyRequest>;
export function parsePreparedPolicyRequest(json: string): PreparedPolicyRequest;
export function serializePreparedPolicyRequest(value: PreparedPolicyRequest): string;
```

`path` is an RFC 6901 JSON Pointer, not a filesystem path. The empty string
identifies the root; `~0` escapes `~` and `~1` escapes `/`.
Both `before` and `after` are required JSON values, including when null.
For `add`, `before: null` is an absent-value placeholder. For `remove`,
`after: null` is the placeholder. `operation` distinguishes those placeholders
from replacing, adding, or removing a real JSON null. Numbers must be finite;
undefined values, non-JSON objects, and malformed Unicode are rejected.
Numeric change values use JavaScript `number` precision; the candidate
`requestJson` retains its JSON text, while the observations' unsigned 64-bit
values remain lossless decimal strings.

Preparation accepts at most 8 MiB of input request UTF-8 and returns at most
32 MiB of result JSON containing at most 4096 changes. The candidate request
may exceed 8 MiB when the complete result fits within 32 MiB. Candidate storage
helpers enforce the result size, edit count, and documented fields. Invalid
stored results throw `MxcError` with `code: 'malformed_request'`; malformed
native results reject preparation with `code: 'backend_error'`. Diagnostics do
not echo the supplied request, observations, or result JSON.

### Models and storage helpers

All types and helpers below are exported only from
`@microsoft/mxc-sdk/v1/dev`.

```typescript
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
  resource?: string;
}

export function parsePolicyFailures(json: string): PolicyFailures;
export function serializePolicyFailures(value: PolicyFailures): string;
export function mergePolicyFailures(older: PolicyFailures, newer: PolicyFailures): PolicyFailures;
export function policyFailuresFromError(error: unknown): PolicyFailures | undefined;
```

`formatVersion` identifies observation JSON, independently of native batch
versions and the MXC request JSON's `version`. The supported values are
`PolicyFailureVersions.Format`, `PolicyFailureVersions.Result` and
`PolicyFailureVersions.MinimumReader`. Native versions, outcomes, detail
codes, and flags are unsigned 32-bit numbers; unrecognized values are
preserved. Each result is one native refusal batch, and its details may not
describe every restriction.
`requestedValue` and `requiredValue` are unsigned 64-bit decimal strings,
including values such as `"18446744073709551615"` that cannot be represented
exactly by a JavaScript `number`. Requested values describe the request Windows
evaluated, not necessarily a later request.

The Dev subpath also exports frozen value groups. Use names such as
`result.outcome === PolicyFailureOutcomes.Blocked` and
`detail.failureReason === PolicyFailureReasons.CapabilityNotAllowed`.
Fields remain `number` or decimal `string`, not closed unions, so unknown
values survive storage. These names do not establish that preparation is safe.

`PolicyFailureNativeCodes.PolicyBlocked` is the string `'0x800704EC'` for
`MxcError.nativeCode`: `HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY)`.
The status alone is not a retry decision; also inspect the native operation,
structured outcome, progress, and application stop conditions.

| Exported object | Read-only members |
|---|---|
| `PolicyFailureVersions` | `Format: 1`, `Result: 1`, `MinimumReader: 1` |
| `PolicyFailureOutcomes` | `Unknown: 0`, `Blocked: 1`, `EvaluationFailed: 2` |
| `PolicyFailureClasses` | `None: 0`, `Network: 1`, `Filesystem: 2`, `EnforcementMode: 3` |
| `PolicyFailureReasons` | `None: 0`, `CapabilityNotAllowed: 1`, `AccessExceedsCeiling: 2`, `DenyRequired: 3`, `RequestPathLimit: 4` |
| `PolicyFailureActions` | `None: 0`, `RemoveCapability: 1`, `RestrictFilesystemAccess: 2`, `ReducePathCount: 3` |
| `PolicyFailureResourceKinds` | `None: 0`, `Path: 1`, `Capability: 2` |
| `PolicyFailureValueKinds` | `None: 0`, `Access: 1`, `PathCount: 2` |
| `PolicyFailureAccessValues` | `None: '0'`, `ReadOnly: '1'`, `ReadWrite: '2'`; for requested/required values when `valueKind` is `PolicyFailureValueKinds.Access` |
| `PolicyFailureFlags` | `None: 0`, `HasActionableDetails: 1`, `ResourceComplete: 2`, `ResourceUnavailable: 4`; combine or inspect as a bitmask |

Only `PolicyFailureAccessValues` uses strings, matching the lossless
`requestedValue` and `requiredValue` fields. The other groups contain numbers.

`resource` is the native resource text without a terminator; `''` remains
distinct from an omitted resource. When a native resource is not valid UTF-16,
such as one containing an unpaired surrogate, the text is omitted,
`PolicyFailureFlags.ResourceUnavailable` is set and
`PolicyFailureFlags.ResourceComplete` is cleared. That detail is never actionable.
Storage helpers reject a `resource` with an unpaired surrogate. Resource text
does not establish that a resource is complete, actionable, or safe to use as
a path. Readers normalize explicit `null` to absence, and serialized output
omits absent fields.

Storage helpers validate the documented shape and reject unknown fields and
invalid numeric representations with `MxcError` (`malformed_request`).
`policyFailuresFromError` returns an owned copy of
`MxcError.details.policyFailures`, or `undefined` if the error is not an
`MxcError` or has no observations. A present malformed report throws rather than
being treated as absent. Other error details, including `ffiStatus`, remain
available on the original error. Policy-failure specifics remain structured:
the SDK does not render them into `message`, `toString()`, `stack`, or warning
strings. High-level IT-managed-policy guidance, `operation`, and `nativeCode`
(including HRESULTs) remain available on policy refusals.

`details` can contain policy resource paths. `console.log` and `util.inspect`
use the SDK's custom inspector and omit `details`, even with `getters` enabled.
`JSON.stringify(error)`, object copies, `util.inspect` with both
`customInspect: false` and `getters: true`, and Node's uncaught-error printer
when `util.inspect.defaultOptions.getters` is enabled include it.
Filter `details` before logging or serializing an error.

Store the extracted `policyFailures` value, not the whole `error.details`
object. Its JSON starts with
`{ formatVersion: PolicyFailureVersions.Format, results: [...] }`. Storage
helpers do not preserve companion diagnostics or retry budgets. Persist
application stopping decisions separately if needed across restarts.

```typescript
import {
  parsePolicyFailures,
  policyFailuresFromError,
  mergePolicyFailures,
  preparePolicyJson,
  runJson,
  serializePolicyFailures,
} from '@microsoft/mxc-sdk/v1/dev';

// requestJson, error, earlierFailures, and acceptPolicyChange belong to the application.
const latest = policyFailuresFromError(error);
if (latest !== undefined) {
  const merged = earlierFailures === undefined
    ? latest : mergePolicyFailures(earlierFailures, latest);
  const storedJson = serializePolicyFailures(merged);
  // Persist storedJson using application-owned storage.

  // On an application-selected later preparation:
  const restored = parsePolicyFailures(storedJson);
  const prepared = await preparePolicyJson(requestJson, restored);
  if (await acceptPolicyChange(prepared)) {
    const result = await runJson(prepared.requestJson);
  }
}
```

### Owned merging and limits

`mergePolicyFailures(older, newer)` validates both inputs, deduplicates
identical complete native batches, and returns an owned report in first-seen
order: earlier observations precede fresh ones. Detail order remains part of
batch identity; individual details are not deduplicated. Optional resource
presence remains significant after the documented null normalization, and
decimal strings compare by their unsigned 64-bit numeric value. The output
retains the first batch's values. Invalid inputs or an over-limit merged
report throw `MxcError` with `code: 'malformed_request'` and leave both
inputs unchanged; observations are never truncated.

Native preparation validates at most 4 MiB of observation JSON, 64 results,
1024 total details, and 262144 total resource accounting units.
Each result allows at most 64 details and 32768 resource accounting units.
Every present resource counts its array length plus one accounting unit,
including an empty array.

Storage and merge helpers allow one final bounded native batch beyond the
preparation input limits: at most 4.5 MiB JSON, 65 results,
1088 details, and 294912 resource accounting units. The per-result limits
remain unchanged. A report accepted for storage or merging can still exceed
native preparation limits. Persist application stopping decisions separately;
observation storage is not a retry budget or policy approval.
