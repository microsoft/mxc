# .NET V1.Dev MXC request JSON API and policy preparation

> **Audience:** MXC consumers

Public namespace: `Microsoft.Mxc.Sdk.V1.Dev`. Methods accept complete MXC
request JSON containing the contract `version`, `phase`, and container ID
where applicable. MXC validates the unchanged document against its declared
contract; unregistered versions and unknown fields are rejected.
Phase-specific methods require the matching JSON `phase`.

Use `JsonOptions` for non-PTY calls and `PtyJsonOptions` for PTY calls.
Both define `Experimental`, independently of the JSON version; PTY options
also define `MxcPtySize? Size` (24 rows by 80 columns by default).
Creation methods execute the supplied request strictly. `PreparePolicyJson`
and its async form take observations separately and use
`PolicyPreparationOptions`, which defines only `Experimental`. Preparation
does not create a container; callers decide whether to accept its proposed
changes.
Execution returns V1 result and process types. Lifecycle and validation
return complete response JSON strings, including backend metadata. When
importing both namespaces, qualify the Dev facade, for example with
`using Dev = Microsoft.Mxc.Sdk.V1.Dev;`.

```csharp
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

PTY methods are synchronous. Async preparation, run, and spawn methods accept
cancellation tokens. Canceling `RunJsonAsync` stops awaiting, not native
execution; canceling `PreparePolicyJsonAsync` similarly stops awaiting, not
preparation.
Canceling `RunInContainerJsonAsync` disposes its owned process. Async
lifecycle management and validation calls run off the caller's thread
without cancellation tokens.

Captured output is lossy UTF-8 text. Callers own and dispose live handles;
existing-container execution leaves the container caller-owned.
A descendant holding an output pipe open can delay captured execution
completion after a workload timeout.

## Policy preparation and caller-owned observations

`PreparePolicyJson(json, failures, options)` validates untrusted creation-policy
observations against the current MXC creation request and proposes only
supported restrictive changes. It creates no container and returns complete
prepared request JSON plus a change report. Unsupported phases, actions, and
unsafe changes fail explicitly.

Preparation accepts create-and-run requests for every backend and OS. With
empty observations it returns the request unchanged with no changes.
As with creation, experimental backends require `Experimental = true`; without
it, preparation throws `MxcException` with `BackendUnavailable`.
Observations are specific to the backend that reported them; native Windows
ProcessContainer is currently the only backend that reports and applies them.
Non-empty observations for any other backend throw `MxcException` with
`UnsupportedContainment` rather than being ignored.

Applications own storage, acceptance of the proposed changes, and the decision
to make another strict creation call. Observations are not policy approval and
do not establish that a resource is complete or that a change is safe. The
creation backend reevaluates the current creator's policy on every attempt.
Each creation call makes one native creation attempt and executes only the
supplied request. MXC keeps no observations between calls.

All types below belong to `Microsoft.Mxc.Sdk.V1.Dev`:

```csharp
public sealed class JsonOptions
{
    public bool Experimental { get; set; }
}

public sealed class PolicyPreparationOptions
{
    public bool Experimental { get; set; }
}

public enum PolicyChangeOperation
{
    Add,
    Remove,
    Replace,
}

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
    public uint FormatVersion { get; init; } = PolicyFailureVersions.Format;
    public PolicyFailureResult[] Results { get; init; } = [];

    public string ToJson();
    public static PolicyFailures FromJson(string json);
    public static PolicyFailures? FromException(MxcException exception);
    public PolicyFailures MergedWith(PolicyFailures other);
}

public sealed class PolicyFailureResult
{
    public uint Version { get; init; } = PolicyFailureVersions.Result;
    public uint MinimumReaderVersion { get; init; } = PolicyFailureVersions.MinimumReader;
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
    public string? Resource { get; init; }
}
```

### Prepared request and change report

The result JSON is
`{ "requestJson": "...", "changes": [{ "operation": "replace", "path": "/example", "before": null, "after": true }] }`.
`requestJson` contains complete MXC request JSON. `path` is an RFC 6901 JSON
Pointer; `~0` escapes `~` and `~1` escapes `/`. Changes retain their order.
The enum uses the named lowercase JSON strings `add`, `remove`, and `replace`,
not numeric enum values.

Both `before` and `after` are required JSON values, represented by non-nullable
`JsonElement` properties. Add uses JSON null for the absent original value;
Remove uses JSON null for the absent prepared value. Replace can have an actual
JSON null on either side. The operation distinguishes absence from replacing
an actual JSON null value. The SDK owns the JSON elements independently of
native memory and any source `JsonDocument`.

`PreparedPolicyRequest.ToJson` and `FromJson` use source-generated serialization
and validate shapes, required fields, operations, JSON Pointers, and limits.
Malformed data throws `JsonException` without echoing input or attaching parser
exceptions. Storage validation is not backend-policy validation or caller
acceptance. Native preparation failures set the `MxcException` `Code`,
`Operation`, `NativeCode`, and `Message` fields.

Preparation storage JSON uses compact escaping and is not intended for direct
embedding in HTML; escape it for HTML separately. Storage checks embedded
`RequestJson` syntax, object shape, encoding, and depth without normalizing its
text. The native engine validates the declared request contract, including
arbitrary `_comment` JSON. Duplicate members inside that annotation remain in
the request text; duplicate preparation-envelope properties are rejected.

| Preparation limit | Maximum |
|---|---:|
| Preparation input MXC request UTF-8 bytes | 8 MiB |
| Prepared result UTF-8 bytes, including the change report | 32 MiB |
| Changes | 4096 |

Preparation may expand the candidate request beyond the 8 MiB input bound.
The complete stored result, including its request JSON and changes, must fit
within 32 MiB.

The native operation owns remediation decisions and the stricter observation
input bounds listed below. The async method uses the same safe blocking-call
wrapper as captured execution. Its cancellation token comes last.

For example, after the application has saved observations from a refused call:

```csharp
using Microsoft.Mxc.Sdk.V1;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;

Dev.PolicyFailures failures = Dev.PolicyFailures.FromJson(
    await File.ReadAllTextAsync("policy-failures.json"));
Dev.PreparedPolicyRequest prepared = await Dev.MxcContainer.PreparePolicyJsonAsync(
    requestJson, failures, cancellationToken: cancellationToken);
await File.WriteAllTextAsync("prepared-request.json", prepared.ToJson(), cancellationToken);

// The application must review and accept the changes before executing RequestJson.
Console.WriteLine("Review prepared-request.json. Type 'accept' to execute its request.");
if (Console.ReadLine() == "accept")
{
    ExecutionResult result = await Dev.MxcContainer.RunJsonAsync(
        prepared.RequestJson, cancellationToken: cancellationToken);
}
```

### Observations and storage

`FormatVersion` identifies the MXC storage format independently of native
`Version` and `MinimumReaderVersion`. The supported values are
`PolicyFailureVersions.Format`, `PolicyFailureVersions.Result` and
`PolicyFailureVersions.MinimumReader`.
Native versions, numeric discriminators, outcomes, and flags retain unknown
`uint` values for inspection. `RequestedValue` describes the
request Windows evaluated, which need not be the request supplied on a
later call.

Use the public constant groups for comparisons, for example
`result.Outcome == PolicyFailureOutcomes.Blocked` or
`detail.FailureReason == PolicyFailureReasons.CapabilityNotAllowed`.
Properties remain `uint` or `ulong`, not closed enums; JSON keeps the numeric
encodings below and unknown values remain inspectable. Names do not authorize
replay.

`PolicyFailureNativeCodes.PolicyBlocked` is the `const string` `"0x800704EC"`
for `MxcException.NativeCode`:
`HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY)`. The status alone is not
a retry decision; also inspect the native operation,
structured outcome, progress, and application stop conditions.

| Static class | Public constants |
|---|---|
| `PolicyFailureVersions` (`uint`) | `Format = 1`, `Result = 1`, `MinimumReader = 1` |
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
entire `ulong` range. Other numeric fields are JSON numbers. `Resource` is
the optional native resource text without a terminator; an empty string
remains distinct from null. When a native resource is not valid UTF-16, such
as one containing an unpaired surrogate, the text is omitted,
`PolicyFailureFlags.ResourceUnavailable` is set and
`PolicyFailureFlags.ResourceComplete` is cleared. That detail is never actionable.
Storage helpers reject a `Resource` with an unpaired surrogate.
JSON readers normalize `null` to absence, and
serialization omits absent fields. Resource text alone does not establish
that a change is safe.

`PolicyFailures.FromException(error)` extracts `error.Details.policyFailures`.
It returns null when the property is absent. If present observations are
invalid, contain unknown fields, use an unsupported format version, or exceed
storage limits, it throws a new `MxcException` with `Code == BackendError` and
the message `native policy failures are malformed`. `FromJson` reports these
problems in stored observations with `JsonException`. The original error and
its other details remain available. Validation diagnostics do not echo
supplied JSON or attach parser exceptions containing it. Native failures
preserve their original `Code`, `Operation`, `NativeCode`, and generic message.
Policy-specific resources, capabilities, and requested or required values
remain structured and are not converted into exception text, stacks, or
warnings.
Policy refusals retain high-level IT-managed-policy guidance.

Persist `PolicyFailures.ToJson()`, not the complete `Details` object, and pass
the restored value to preparation. Companion diagnostics and retry budgets
are application control state and need separate persistence if stopping
decisions must survive a restart. Parsing stored observations is not proof
that they can be used to prepare a request. Observation `formatVersion`,
native batch versions, and MXC request JSON `version` identify separate
contracts.

A creation refusal reports that attempt's observations, not observations passed
to an earlier preparation call. Use `prior.MergedWith(current)` to combine them.
The helper validates both storage inputs and appends distinct complete native
batches in first-observed order, preserving detail order and resource presence.
It returns owned arrays, including resource arrays, without changing either
input. A malformed input or a complete merge exceeding storage limits throws
`JsonException`; neither report is truncated. Keep the original reports
separately on that failure and stop rather than guessing which details to
discard.

| Observation limit | Native preparation input | JSON storage helpers |
|---|---:|---:|
| UTF-8 bytes | 4 MiB | 4.5 MiB |
| Results | 64 | 65 |
| Total details | 1024 | 1088 |
| Total resource accounting units | 262144 | 294912 |

Both paths allow at most 64 details and 32768 resource accounting units per
result. Each present resource counts its array length plus one unit.
Storage may preserve accumulated observations that exceed preparation input
bounds; successful storage does not imply that preparation accepts them.
Native validation owns the stricter input limits and all remediation decisions.

Successful creation returns the usual `ExecutionResult` or `MxcProcess`, with
the same warnings, stdin, cancellation, and ownership semantics. Observations
remain structured on errors.
