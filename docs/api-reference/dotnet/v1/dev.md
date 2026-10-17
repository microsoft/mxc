# .NET V1.Dev exact-JSON API

Public namespace: `Microsoft.Mxc.Sdk.V1.Dev`. All methods accept one complete
caller-authored exact-version JSON string; they do not stamp a version, parse
through typed V1, or take a duplicate container ID. Native exact parsing
rejects unregistered versions and unknown fields. Phase-specific methods
check the JSON phase before calling native code.

`JsonOptions.Experimental` authorizes an experimental backend independently
of the JSON version. `PtyJsonOptions` is a separate option type for PTY
operations with its own `Experimental` and optional `MxcPtySize? Size`
(24 rows by 80 columns by default). Non-PTY operations accept only
`JsonOptions`. Return types are the existing V1 execution and process types;
lifecycle and validation results are complete native response JSON strings,
without narrowing through typed V1 metadata. When importing both typed and
dev namespaces, qualify the dev facade (for example,
`using Dev = Microsoft.Mxc.Sdk.V1.Dev;`).

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

PTY entry points are synchronous only. Only the four async run/spawn methods
take cancellation tokens, matching their existing typed V1 counterparts.
One-shot `RunJsonAsync` cancellation stops awaiting, not native execution;
`RunInContainerJsonAsync` disposes its owned process on cancellation. Async
lifecycle operations run off the caller's thread but have no cancellation
token. Captured output is returned as lossy UTF-8 text; live handles retain
the existing V1 stream and disposal contract.
Timed-out in-container capture closes its readers and returns partial text
without deprovisioning the caller-owned container.
