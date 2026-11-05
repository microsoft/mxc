# Node V1.Dev exact-JSON API

> **Audience:** MXC consumers

Public subpath: `@microsoft/mxc-sdk/v1/dev`. Operations accept complete MXC
request JSON with a caller-declared contract version and return Promises.
MXC validates the unchanged document against its declared contract and
checks policy and backend availability.

`JsonOptions` contains optional `experimental?: boolean` authorization,
independent of the authored JSON version. `CreationJsonOptions` additionally
contains optional `policyFailures?: PolicyFailures` for `runJson` and
`spawnJson`. `PtyJsonOptions` additionally
contains optional `size?: MxcPtySize` (24 rows by 80 columns by default).
Execution returns the existing V1 result or process types. Lifecycle and
validation return the complete native response JSON string. Phase-specific
methods reject a different phase before native dispatch.

```typescript
export interface JsonOptions {
  experimental?: boolean;
}
export interface CreationJsonOptions extends JsonOptions {
  policyFailures?: PolicyFailures;
}
export interface PtyJsonOptions extends JsonOptions {
  size?: MxcPtySize;
}

export function runJson(json: string, options?: CreationJsonOptions): Promise<ExecutionResult>;
export function spawnJson(json: string, options?: CreationJsonOptions): Promise<MxcProcess>;
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

## Caller-owned creation-policy feedback

On supported Windows ProcessContainer creation, `runJson` and `spawnJson`
accept prior creation-policy observations through `options.policyFailures`.
The request JSON remains unchanged. The native backend validates the feedback,
applies only supported safe restrictions, and attempts creation once.
The application owns storage, inspection, and the decision to make another
call. The SDK does not retry or retain feedback between invocations.
Ordinary warnings remain in the existing result/process `warnings` property;
successful creation does not produce a correction report.

Feedback is untrusted data, not approval of a policy change. Unknown native
codes remain inspectable and do not authorize a guessed correction. Backend
and host restrictions remain native; supplying feedback does not enable an
unsupported backend or operation. Lifecycle, validation, and PTY methods
explicitly reject `policyFailures`, including when a shared options object
carries that property. Typed V1 options are unchanged.

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
  resource?: number[];
}

export function parsePolicyFailures(json: string): PolicyFailures;
export function serializePolicyFailures(value: PolicyFailures): string;
export function policyFailuresFromError(error: unknown): PolicyFailures | undefined;
export function policyFailureResourceText(detail: PolicyFailureDetail): string | undefined;
```

`formatVersion` is `1` for feedback JSON, independently of native batch versions
and the MXC request JSON's `version`. Native versions, outcomes, detail codes,
and flags are unsigned 32-bit numbers; unrecognized values are preserved. Each result is one
native refusal batch, and its details may not describe every restriction.
`requestedValue` and `requiredValue` are unsigned 64-bit decimal strings,
including values such as `"18446744073709551615"` that cannot be represented
exactly by a JavaScript `number`. Requested values describe the request Windows
evaluated, not necessarily a later request.

The Dev subpath also exports frozen value groups. Use names such as
`result.outcome === PolicyFailureOutcomes.Blocked` and
`detail.failureReason === PolicyFailureReasons.CapabilityNotAllowed`.
Fields remain `number` or decimal `string`, not closed unions, so unknown
values survive storage. These names do not establish that replay is safe.

`PolicyFailureNativeCodes.PolicyBlocked` is the string `'0x800704EC'` for
`MxcError.nativeCode`: `HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY)`.
The status alone is not a retry decision; also inspect the native operation,
structured outcome, progress, and application stop conditions.

| Exported object | Read-only members |
|---|---|
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

`resource` contains the native UTF-16 code units, each between 0 and 65535,
without a terminator. Omitted resources, empty arrays, and malformed UTF-16
are distinct and survive JSON storage. `policyFailureResourceText` returns
`undefined` for an omitted resource and `''` for an empty one, and throws
`MxcError` with `code: 'malformed_request'` for unpaired surrogates instead of
replacing them. Decoded text does not establish that a resource is complete,
actionable, or safe to use as a path.
Readers normalize explicit `resource: null` to absence, and serialized output
omits it. An empty array remains present.

Storage helpers validate the documented shape and reject unknown fields and
invalid numeric representations with `MxcError` (`malformed_request`).
`policyFailuresFromError` returns an owned copy of
`MxcError.details.policyFailures`, or `undefined` if the error is not an
`MxcError` or has no feedback. A present malformed report throws rather than
being treated as absent. Other error details, including `ffiStatus`, remain
available on the original error. Policy-failure specifics remain structured:
the SDK does not render them into `message`, `toString()`, `stack`, or warning
strings. High-level IT-managed-policy guidance, `operation`, and `nativeCode`
(including HRESULTs) remain available on policy refusals.

Store and replay the extracted `policyFailures` value, not the whole
`error.details` object. Its JSON starts with `{ formatVersion: 1, results: [...] }`.
Storage helpers do not preserve companion diagnostics or retry budgets;
persist application stopping decisions separately if they must survive a restart.

```typescript
import {
  parsePolicyFailures,
  policyFailuresFromError,
  runJson,
  serializePolicyFailures,
} from '@microsoft/mxc-sdk/v1/dev';

// The application receives requestJson and owns the failed call's error.
const feedback = policyFailuresFromError(error);
if (feedback !== undefined) {
  const storedJson = serializePolicyFailures(feedback);
  // Persist storedJson using application-owned storage.

  // On an application-selected later attempt:
  const restored = parsePolicyFailures(storedJson);
  const result = await runJson(requestJson, { policyFailures: restored });
}
```

### Cumulative feedback and limits

On another policy refusal, `error.details.policyFailures` contains the supplied
observations plus the new native batch, deduplicating identical complete
batches. When cumulative feedback exceeds reapplication limits, the full report
remains inspectable and storable. `error.details.policyFeedbackError` is an
object with string `code` and `reason` fields; current codes are `unsafeReplay`
and `feedbackLimitExceeded`. Stop automatic retries on its presence, including
unknown codes, rather than matching diagnostic text. A terminal report cannot
be reapplied unchanged. If a refusal yields no
fresh usable native result, prior feedback remains available and
`error.details.policyResultUnavailable` explains retrieval.

Native creation validates at most 4 MiB of feedback JSON, 64 results,
1024 cumulative details, and 262144 cumulative resource accounting units.
Each result allows at most 64 details and 32768 resource accounting units.
Every present resource counts its array length plus one accounting unit,
including an empty array.

Storage helpers allow one final bounded native batch beyond the cumulative
input limits: at most 4.5 MiB JSON, 65 results, 1088 details, and 294912 resource
accounting units. The per-result limits remain unchanged. Accepting a report
for storage does not mean native creation will accept it for reapplication.
