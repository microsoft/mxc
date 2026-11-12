# .NET V1.Dev exact-JSON API

> **Audience:** MXC consumers

Public namespace: `Microsoft.Mxc.Sdk.V1.Dev`. Methods accept complete MXC
request JSON containing the contract `version`, `phase`, and container ID
where applicable. MXC validates the unchanged document against its declared
contract; unregistered versions and unknown fields are rejected.
Phase-specific methods require the matching JSON `phase`.

Use `JsonOptions` for non-PTY calls and `PtyJsonOptions` for PTY calls.
Both define `Experimental`, independently of the JSON version; PTY options
also define `MxcPtySize? Size` (24 rows by 80 columns by default).
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
Captured existing-container execution closes unused stdin automatically.
With live execution, close any stdin stream you take when the workload needs EOF.
A descendant holding an output pipe open can delay captured execution
completion after a workload timeout.

For W365 execution, `process.timeout` is sent unchanged to the service.
The native backend allows a further 30 seconds for transport and output drain;
the SDK does not attempt a local kill at the guest runtime limit.
A service exit code of 124 is preserved with `TimedOut == false`, since it
can also be a program's exit code. Exhausting the native deadline raises
an error with unknown remote outcome, rather than returning partial success.
