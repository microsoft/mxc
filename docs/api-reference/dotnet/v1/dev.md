# .NET V1.Dev MXC request JSON API

> **Audience:** MXC consumers

Public namespace: `Microsoft.Mxc.Sdk.V1.Dev`. Methods accept complete MXC
request JSON containing the contract `version`, `phase`, and container ID
where applicable. MXC validates the unchanged document against its declared
contract; unregistered versions and unknown fields are rejected.
Phase-specific methods require the matching JSON `phase`.

Use `JsonOptions` for non-PTY calls and `PtyJsonOptions` for PTY calls.
Both define `Experimental`, independently of the JSON version; PTY options
also define `MxcPtySize? Size` (24 rows by 80 columns by default).
`JsonOptions.PolicyFailures` supplies caller-owned creation-policy feedback
only to `RunJson`, `SpawnJson`, and their async forms. Other operations
reject supplied feedback, including an empty value. PTY options do not
accept feedback.
Execution returns V1 result and process types. Lifecycle and validation
return complete response JSON strings, including backend metadata. When
importing both namespaces, qualify the Dev facade, for example with
`using Dev = Microsoft.Mxc.Sdk.V1.Dev;`.

```csharp
// Microsoft.Mxc.Sdk.V1.Dev.MxcContainer
ExecutionResult RunJson(string json, JsonOptions? options = null);
Task<ExecutionResult> RunJsonAsync(string json, JsonOptions? options = null,
    CancellationToken cancellationToken = default);
MxcProcess SpawnJson(string json, JsonOptions? options = null);
Task<MxcProcess> SpawnJsonAsync(string json, JsonOptions? options = null,
    CancellationToken cancellationToken = default);
MxcPtyProcess SpawnWithPtyJson(string json, PtyJsonOptions? options = null);

// Microsoft.Mxc.Sdk.V1.Dev.MxcLifecycle
ExecutionResult RunInContainerJson(string json, JsonOptions? options = null);
Task<ExecutionResult> RunInContainerJsonAsync(string json, JsonOptions? options = null,
    CancellationToken cancellationToken = default);
MxcProcess SpawnInContainerJson(string json, JsonOptions? options = null);
Task<MxcProcess> SpawnInContainerJsonAsync(string json, JsonOptions? options = null,
    CancellationToken cancellationToken = default);
MxcPtyProcess SpawnInContainerWithPtyJson(string json, PtyJsonOptions? options = null);

string ProvisionContainerJson(string json, JsonOptions? options = null);
Task<string> ProvisionContainerJsonAsync(string json, JsonOptions? options = null);
string StartContainerJson(string json, JsonOptions? options = null);
Task<string> StartContainerJsonAsync(string json, JsonOptions? options = null);
string StopContainerJson(string json, JsonOptions? options = null);
Task<string> StopContainerJsonAsync(string json, JsonOptions? options = null);
string DeprovisionContainerJson(string json, JsonOptions? options = null);
Task<string> DeprovisionContainerJsonAsync(string json, JsonOptions? options = null);

string ValidateProvisionJson(string json, JsonOptions? options = null);
Task<string> ValidateProvisionJsonAsync(string json, JsonOptions? options = null);
string ValidateStartJson(string json, JsonOptions? options = null);
Task<string> ValidateStartJsonAsync(string json, JsonOptions? options = null);
string ValidateStopJson(string json, JsonOptions? options = null);
Task<string> ValidateStopJsonAsync(string json, JsonOptions? options = null);
string ValidateDeprovisionJson(string json, JsonOptions? options = null);
Task<string> ValidateDeprovisionJsonAsync(string json, JsonOptions? options = null);
string ValidateProcessJson(string json, JsonOptions? options = null);
Task<string> ValidateProcessJsonAsync(string json, JsonOptions? options = null);
```

PTY methods are synchronous. Async run/spawn methods accept cancellation
tokens. Canceling `RunJsonAsync` stops awaiting, not native execution;
canceling `RunInContainerJsonAsync` disposes its owned process. Async
lifecycle management and validation calls run off the caller's thread
without cancellation tokens.

Captured output is lossy UTF-8 text. Callers own and dispose live handles;
existing-container execution leaves the container caller-owned.
A descendant holding an output pipe open can delay captured execution
completion after a workload timeout.

## Caller-owned creation-policy feedback

Windows ProcessContainer accepts optional prior observations separately from
MXC request JSON. The native backend validates this untrusted data and applies
only supported restrictive changes, then makes one creation attempt.
Applications own storage and the decision to make another call. Feedback
is not a policy approval, and an observation does not establish that its
resource is complete or that a suggested change is safe.

All types below belong to `Microsoft.Mxc.Sdk.V1.Dev`:

```csharp
public sealed class JsonOptions
{
    public bool Experimental { get; set; }
    public PolicyFailures? PolicyFailures { get; set; }
}

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

`FormatVersion` identifies the MXC storage format independently of native
`Version` and `MinimumReaderVersion`. Format version 1 is supported.
Native versions, numeric discriminators, outcomes, and flags retain unknown
`uint` values for inspection. Known native outcomes are 0 (unknown),
1 (blocked), and 2 (evaluation failed). `RequestedValue` describes the
request Windows evaluated, which need not be the request supplied on a
later call.

Use the public constant groups for comparisons, for example
`result.Outcome == PolicyFailureOutcomes.Blocked` or
`detail.FailureReason == PolicyFailureReasons.CapabilityNotAllowed`.
Properties remain `uint` or `ulong`, not closed enums; JSON keeps the numeric
encodings below and unknown values remain inspectable. Names do not authorize
replay.

`PolicyFailureNativeCodes.PolicyBlocked` is the `const string` `"0x800704EC"`
for `MxcException.NativeCode`: `HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY)`.
The status alone is not a retry decision; also inspect the native operation,
structured outcome, progress, and application stop conditions.

| Static class | Public constants |
|---|---|
| `PolicyFailureOutcomes` (`uint`) | `Unknown = 0`, `Blocked = 1`, `EvaluationFailed = 2` |
| `PolicyFailureClasses` (`uint`) | `None = 0`, `Network = 1`, `Filesystem = 2`, `EnforcementMode = 3` |
| `PolicyFailureReasons` (`uint`) | `None = 0`, `CapabilityNotAllowed = 1`, `AccessExceedsCeiling = 2`, `DenyRequired = 3`, `RequestPathLimit = 4` |
| `PolicyFailureActions` (`uint`) | `None = 0`, `RemoveCapability = 1`, `RestrictFilesystemAccess = 2`, `ReducePathCount = 3` |
| `PolicyFailureResourceKinds` (`uint`) | `None = 0`, `Path = 1`, `Capability = 2` |
| `PolicyFailureValueKinds` (`uint`) | `None = 0`, `Access = 1`, `PathCount = 2` |
| `PolicyFailureAccessValues` (`ulong`) | `None = 0`, `ReadOnly = 1`, `ReadWrite = 2`; for requested/required values when `ValueKind` is `PolicyFailureValueKinds.Access` |
| `PolicyFailureFlags` (`uint`) | `None = 0`, `HasActionableDetails = 1`, `ResourceComplete = 2`, `ResourceUnavailable = 4`; combine or inspect as a bitmask |

`ToJson` and `FromJson` use source-generated serialization without reflection
and are supported by Native AOT. JSON field names are camelCase.
`requestedValue` and `requiredValue` are decimal strings, preserving the
entire `ulong` range. Other numeric fields are JSON numbers. Resource data
is an optional array of UTF-16 code units without a terminator. Omitted
resources, empty arrays, and malformed UTF-16 remain distinguishable.
JSON readers normalize `resource: null` to absence, and serialization omits it.
`GetResourceText()` returns null for an absent resource and throws
`DecoderFallbackException` for malformed UTF-16; it does not replace
invalid units, include resource bytes in decoder diagnostics, or establish
that the text is actionable.

`PolicyFailures.FromException(error)` extracts `error.Details.policyFailures`.
It returns null when the property is absent. Invalid present feedback,
invalid stored shapes, unknown fields, unsupported format versions, and
storage-limit violations throw `JsonException`. The original error and its
other details remain available. Validation diagnostics do not echo supplied
JSON or attach parser exceptions containing it. Native failures preserve their original
`Code`, `Operation`, `NativeCode`, and generic message. Policy-specific
resources, capabilities, and requested or required values remain structured;
they are not converted into exception text, stacks, or warnings.
Policy refusals retain high-level IT-managed-policy guidance.

Persist `PolicyFailures.ToJson()`, not the complete `Details` object, and pass
the restored value through `JsonOptions.PolicyFailures`. Companion diagnostics
and retry budgets are application control state and need separate persistence
if stopping decisions must survive a restart. Parsing stored feedback is not
proof that it can be replayed. Feedback `formatVersion`, native batch versions,
and MXC request JSON `version` identify separate contracts.

On a further policy refusal, returned feedback includes prior observations
and the new native batch. Identical complete batches are deduplicated by
the native backend. A terminal report remains available in full even when
it exceeds invocation limits. `Details.policyFeedbackError` is an object with
string `code` and `reason` fields; current codes are `unsafeReplay` and
`feedbackLimitExceeded`. Stop automatic retries on its presence, including
unknown codes, without matching diagnostic text. If a refusal produces no usable
new native result, prior feedback remains available with
`Details.policyResultUnavailable`.

| Limit | Native invocation | JSON storage helpers |
|---|---:|---:|
| UTF-8 bytes | 4 MiB | 4.5 MiB |
| Results | 64 | 65 |
| Cumulative details | 1024 | 1088 |
| Cumulative resource accounting units | 262144 | 294912 |

Both paths allow at most 64 details and 32768 resource accounting units per
result. Each present resource counts its array length plus one unit.
The larger storage bounds preserve a terminal report containing one extra
native batch; that report cannot necessarily be reapplied unchanged. Native
validation owns the stricter invocation limits and all remediation decisions.

Successful calls retain the existing `ExecutionResult` or `MxcProcess`,
warnings, stdin, cancellation, and ownership semantics. Feedback is available
on errors rather than as an additional success report. Typed V1 creation
options, lifecycle operations, validation, and PTY execution do not support
applying feedback.
