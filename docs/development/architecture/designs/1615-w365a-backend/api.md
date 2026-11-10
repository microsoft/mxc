# API proposal: experimental W365A SDK access

> **Audience:** MXC developers

- **Status:** Proposed
- **Issue:** [#1615](https://github.com/microsoft/mxc/issues/1615)
- **Feature design spec:** [Windows 365 for Agents backend](README.md).

The initial scope includes the complete lifecycle through existing Rust, .NET
and Node V1.Dev JSON APIs, with captured execution and pipe-backed spawn.
SDK calls run in-process with experimental opt-in on each call.
**The SDK is optional:** `wxc-exec` supports the same lifecycle with synchronous
stdio relay; callers need not mix interfaces.

Invocation signatures and result types are unchanged. The only public API
additions are optional Rust/.NET error details; Node's existing member is
preserved. These are proposed capabilities, not working W365 examples.
Typed W365 configuration and contract publication remain out of scope.

**Implementation boundary:** Phase 2 implements checkout and terminal release
through the Windows executor's existing lifecycle interface. The backend is
included and tested through the engine on Windows, Linux and macOS; lifecycle
CLI support for Linux and macOS is deferred to separate work.
All Dev SDK W365 JSON calls remain explicitly unavailable
until cross-SDK structured error metadata and SDK fixtures are ready.
Start/readiness and exec are also deferred. The examples in this proposal are
not runnable Phase 2 SDK examples. See the
[backend guide](../../../../backends/w365agents/w365agents-backend.md).

## Caller scenario

All examples implement the same [internal Windows build scenario](README.md#usage-scenario).
The [support table](README.md#execution-and-container-lifecycle-support) and
[sequence diagram](README.md#design-and-security) apply to SDK and executor calls.

The application constructs this provision document in memory as `provisionJson`
(`provision_json` in Rust). Replace the synthetic GUIDs with the authorized
pool and human-user object IDs:

```json
{
  "version": "1.1.0-alpha",
  "phase": "provision",
  "containment": "w365_agents",
  "w365Agents": {
    "provision": {
      "poolId": "11111111-1111-1111-1111-111111111111",
      "userType": "HumanUser",
      "userObjectId": "22222222-2222-2222-2222-222222222222"
    }
  }
}
```

The caller supplies/renews W365 service configuration and resource-specific tokens
through the [documented environment variables](README.md#routing-and-phase-settings).
Keep tokens out of source, command-line arguments and persisted request files;
the SDK does not acquire or refresh them.
The project and `build.cmd` already exist in `C:\work\project` on the Cloud PC,
for example after an earlier exec retrieved the source. Local `request` helpers
are application JSON builders, not new SDK APIs.

### Multiple commands on one checked-out Cloud PC

1. Provision once; immediately persist the response's `result.sandboxId` and
   account/deployment context. Pass the opaque ID unchanged.
2. Start once with that ID and wait for readiness.
3. Execute sequential commands with the same ID, inspecting each outcome before
   continuing. Files persist subject to service expiration/reset, but each command
   is a new process, not a persistent shell; specify its working directory and environment.
4. Explicitly deprovision in final cleanup, including after readiness/exec failure.
   Stop is an alternative terminal release, not suspension or stop/start reuse.

Persistence is omitted from the snippets. They stop on nonzero exits/timeouts,
which are command results; SDK failures raise errors. They also retain a rejected
checkout's `details.sandboxId` for release without start/exec, and report primary
and cleanup failures separately. Without a valid ID, do not invent one or retry
checkout automatically. Retain IDs after failed/uncertain release; acceptance
does not prove reset/sanitization. See [errors and recovery](#errors-and-recovery).

### Rust

Within an application function returning `Result<(), Box<dyn std::error::Error>>`:

```rust
use mxc_sdk::v1::{dev, Error, WaitResult};
use serde_json::{json, Value};
use std::io::{self, Write};

fn request(phase: &str, id: &str, command: Option<&str>) -> String {
    let mut value = json!({
        "version": "1.1.0-alpha", "phase": phase, "sandboxId": id
    });
    if let Some(command) = command {
        value["process"] = json!({
            "commandLine": command, "cwd": "C:\\work\\project", "timeout": 300000
        });
    }
    value.to_string()
}

let options = dev::JsonOptions { experimental: true };
let mut sandbox_id: Option<String> = None;
let primary = (|| -> Result<(), Box<dyn std::error::Error>> {
    let response = dev::provision_container_json(provision_json, options)
        .map_err(|error: Error| {
            sandbox_id = error.details.as_ref()
                .and_then(|details| details.get("sandboxId"))
                .and_then(Value::as_str).map(str::to_owned);
            error
        })?;
    let response: Value = serde_json::from_str(&response)?;
    let id = response["result"]["sandboxId"].as_str()
        .ok_or("provision returned no sandboxId")?.to_owned();
    sandbox_id = Some(id.clone());
    dev::start_container_json(&request("start", &id, None), options)?;
    for command in ["cmd.exe /c build.cmd", "cmd.exe /c dir output"] {
        let result = dev::run_in_container_json(&request("exec", &id, Some(command)), options)?;
        io::stdout().write_all(&result.stdout)?;
        io::stderr().write_all(&result.stderr)?;
        eprintln!("command outcome: {:?}", result.outcome);
        if result.outcome != WaitResult::Exited(0) { break; }
    }
    Ok(())
})();
let cleanup = sandbox_id.as_ref().map(|id| {
    dev::deprovision_container_json(&request("deprovision", id, None), options)
});
eprintln!("container={sandbox_id:?}; work={primary:?}; release={cleanup:?}");
primary?;
if let Some(release) = cleanup { release?; }
```

### .NET

Within an async application method:

```csharp
using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Mxc.Sdk.V1;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;

static string Request(string phase, string id, string? command = null)
{
    var value = new JsonObject
    {
        ["version"] = "1.1.0-alpha", ["phase"] = phase, ["sandboxId"] = id,
    };
    if (command is not null)
        value["process"] = new JsonObject
        {
            ["commandLine"] = command, ["cwd"] = @"C:\work\project", ["timeout"] = 300000,
        };
    return value.ToJsonString();
}

var options = new Dev.JsonOptions { Experimental = true };
string? sandboxId = null;
Exception? primary = null;
try
{
    var response = await Dev.MxcLifecycle.ProvisionContainerJsonAsync(provisionJson, options);
    using var document = JsonDocument.Parse(response);
    sandboxId = document.RootElement.GetProperty("result").GetProperty("sandboxId")
        .GetString() ?? throw new InvalidDataException("provision returned no sandboxId");
    await Dev.MxcLifecycle.StartContainerJsonAsync(Request("start", sandboxId), options);
    foreach (var command in new[] { "cmd.exe /c build.cmd", "cmd.exe /c dir output" })
    {
        var result = await Dev.MxcLifecycle.RunInContainerJsonAsync(
            Request("exec", sandboxId, command), options);
        Console.Write(result.Stdout);
        Console.Error.Write(result.Stderr);
        Console.WriteLine($"command exit={result.ExitCode}; timedOut={result.TimedOut}");
        if (result.ExitCode != 0 || result.TimedOut) break;
    }
}
catch (Exception error)
{
    primary = error;
    if (sandboxId is null && error is MxcException sdkError
        && sdkError.Details is JsonElement details
        && details.TryGetProperty("sandboxId", out var id)
        && id.ValueKind == JsonValueKind.String)
        sandboxId = id.GetString();
    throw;
}
finally
{
    if (sandboxId is not null)
    {
        try
        {
            await Dev.MxcLifecycle.DeprovisionContainerJsonAsync(
                Request("deprovision", sandboxId), options);
        }
        catch (Exception cleanup)
        {
            if (primary is not null)
                throw new AggregateException($"Release still needed for {sandboxId}", primary, cleanup);
            throw;
        }
    }
}
```

### Node

```typescript
import { MxcError } from '@microsoft/mxc-sdk/v1';
import {
  provisionContainerJson, startContainerJson,
  runInContainerJson, deprovisionContainerJson,
} from '@microsoft/mxc-sdk/v1/dev';

function request(phase: 'start' | 'exec' | 'deprovision', id: string, command?: string): string {
  return JSON.stringify({
    version: '1.1.0-alpha', phase, sandboxId: id,
    ...(phase === 'exec' ? { process: {
      commandLine: command, cwd: 'C:\\work\\project', timeout: 300000,
    } } : {}),
  });
}

const options = { experimental: true };
let sandboxId: string | undefined;
let primary: unknown;
try {
  const response = JSON.parse(await provisionContainerJson(provisionJson, options));
  if (typeof response?.result?.sandboxId !== 'string')
    throw new Error('provision returned no sandboxId');
  const id: string = response.result.sandboxId;
  sandboxId = id;
  await startContainerJson(request('start', id), options);
  for (const command of ['cmd.exe /c build.cmd', 'cmd.exe /c dir output']) {
    const result = await runInContainerJson(request('exec', id, command), options);
    console.log({ stdout: result.stdout, stderr: result.stderr,
      exitCode: result.exitCode, timedOut: result.timedOut });
    if (result.exitCode !== 0 || result.timedOut) break;
  }
} catch (error) {
  primary = error;
  if (sandboxId === undefined && error instanceof MxcError
      && typeof error.details?.sandboxId === 'string')
    sandboxId = error.details.sandboxId;
  throw error;
} finally {
  if (sandboxId !== undefined) {
    try {
      await deprovisionContainerJson(request('deprovision', sandboxId), options);
    } catch (cleanup) {
      throw new AggregateError(
        primary === undefined ? [cleanup] : [primary, cleanup],
        `Release still needed for ${sandboxId}`,
      );
    }
  }
}
```

### Spawn instead of capture

Within the same checkout and cleanup scope, replace a captured run with the
corresponding spawn call when the application needs live I/O:

| SDK | Existing spawn call |
| --- | --- |
| Rust | `dev::spawn_in_container_json(&request("exec", &id, Some(command)), options)?` |
| .NET | `await Dev.MxcLifecycle.SpawnInContainerJsonAsync(Request("exec", sandboxId, command), options)` |
| Node | `await spawnInContainerJson(request('exec', id, command), options)` from `@microsoft/mxc-sdk/v1/dev` |

Each returns an `MxcProcess`. Drain its stdout and stderr concurrently, write
stdin as needed and close it for EOF, then wait for the outcome. Dispose/drop
the process and streams on success or failure before final Cloud PC release.
Rust uses `take_stdin`/`take_stdout`/`take_stderr` and `wait`; .NET uses
`StandardInput`/`StandardOutput`/`StandardError`, `WaitAsync` and `Dispose`;
Node uses `standardInput`/`standardOutput`/`standardError`, `wait` and `dispose`.
Capture owns this local cleanup; spawned handles transfer it to the caller.
Neither path automatically releases the Cloud PC.

## Proposed signatures and types

Lifecycle/execution signatures, options and results are unchanged; their
declarations are in the versioned Dev references linked below. Only error
metadata changes. Rust's error is non-exhaustive, .NET gains a read-only
optional property, and Node retains its existing member; no new API major
version is needed.

### Rust

Use [`mxc_sdk::v1::dev`](../../../../api-reference/rust/v1/dev.md);
results/errors belong to `mxc_sdk::v1`. Add to its non-exhaustive `Error`:

```rust
pub details: Option<serde_json::Value>
```

### .NET

Use [`Microsoft.Mxc.Sdk.V1.Dev.MxcLifecycle`](../../../../api-reference/dotnet/v1/dev.md);
results/errors belong to `Microsoft.Mxc.Sdk.V1`. Add to its `MxcException`,
using `System.Text.Json.JsonElement`:

```csharp
public JsonElement? Details { get; }
```

The SDK owns a clone independent of parsing-document/native-buffer lifetime.

### Node

Use [`@microsoft/mxc-sdk/v1/dev`](../../../../api-reference/node/v1/dev.md);
results/errors belong to `@microsoft/mxc-sdk/v1`. Retain `MxcError`'s existing member:

```typescript
readonly details?: Record<string, unknown>;
```

## Inputs, results, and SDK differences

Pass a complete `1.1.0-alpha` JSON string with `phase`, provision containment
or later `sandboxId`, and that phase's settings/process inputs. Empty/null/missing
JSON is invalid; field validation follows the [request](README.md#routing-and-phase-settings)
and [process](README.md#process-inputs-and-results) rules.

| SDK | Invocation controls |
| --- | --- |
| Rust | Synchronous calls; required `JsonOptions` value, whose default sets `experimental: false`; no cancellation parameter. Spawn does not wait for command completion. |
| .NET | Sync and async calls; optional/null options use `Experimental: false`. Async execution accepts a trailing `CancellationToken`; lifecycle management has none. |
| Node | Promises; optional options default to `experimental: false`. Explicit options must be an object; no `AbortSignal`. |

| Result | SDK behavior |
| --- | --- |
| Provision/start/stop/deprovision | Complete native response JSON string, including provision's existing `result.sandboxId` and backend metadata. |
| Captured exec | `ExecutionResult`: outcome, separate stdout/stderr, warnings and available output metadata. SDK owns transient process cleanup. |
| Spawned exec | Caller-owned `MxcProcess`; launch or later I/O/wait can fail. Dispose it separately from Cloud PC release. |
| Nonzero guest exit | Normal command result, including a real EXIT of -1; not a synthetic transport failure. |
| Unsupported request | Existing SDK error codes: `backend_unavailable` for missing experimental authorization, `policy_validation` for unenforceable policy, or the existing phase/mode refusal. No fallback to a different backend or executor. |

Rust capture returns bytes and `outcome: WaitResult`; .NET/Node return lossy
UTF-8 strings and exit-code/timeout properties. Spawned streams preserve bytes.
Full capture memory grows with output size; use incremental spawn reads for
large/continuous output.

### Errors and recovery

Existing error types/fields remain. Backend-defined `details` objects preserve
unknown fields; absence is Rust `None`, .NET null or Node undefined, not proof
that a remote operation had no effect. Preserve `details.code`,
`possiblySucceeded`, HTTP/request context and rejected-checkout cleanup IDs
(`poolId`, `sessionId`, `sandboxId`) as defined in the
[identity](README.md#container-identity) and [recovery](README.md#resource-ownership-and-failure-recovery)
sections. Never fabricate a missing ID.

Carry details through lifecycle, exec launch, I/O/wait and capture, retaining
internal `MxcError` until the SDK boundary without an engine dependency in
`mxc_common`. Rust `std::io::Error` retains the SDK `Error` as its typed inner
error (`get_ref`/`downcast_ref`); Dev capture converts it back without loss.
Native transport preserves details for .NET/Node.

Failed capture returns an error, not partial success; already-read spawned output
remains the caller's. Kill reports unsupported remote termination. Local
cancellation/disposal or executor termination does not prove remote exit or
release the Cloud PC. Do not replay commands after transport loss.
Local deadlines/disconnects must not produce `TimedOut: true` or
`WaitResult::TimedOut` without evidence of remote timeout termination.

## Compatibility and request mapping

Existing callers retain source compatibility and behavior, including error
constructors, result types and SDK contract targets. Native transport uses
compatible additive versioned exports/accessors as needed, never in-place
C ABI struct enlargement. Matching SDK and native artifact versions are
required; missing capability fails explicitly rather than dropping metadata.

The SDK passes authored JSON unchanged: no stable-V1 stamping, removed fields,
new W365 defaults or loss of omitted-versus-empty values. Experimental opt-in
is separate invocation authorization, not JSON policy; .NET cancellation is
local invocation control. Typed V1 configuration cannot select W365A.
Discovery APIs remain unchanged and W365A is
[not locally detected](README.md#backend-applicability-and-availability).

## Validation and documentation

Use the [shared validation plan](README.md#acceptance-criteria-and-validation-plan)
for lifecycle/capture/spawn/recovery scenarios, CI jobs, artifacts and live-test
deferral. Rust Dev/stream-adapter/FFI, Node unit/integration and .NET tests must
invoke real in-process Dev paths against the service fixture, not merely check
JSON construction. Run executor examples separately.

Add cross-SDK error-conversion and native-buffer-lifetime checks; retain
ABI/other-backend regressions. Any serialized .NET error DTOs must use
`MxcJsonContext`/`MxcJson` and extend `Microsoft.Mxc.Sdk.AotSmokeTest`, without
reflection-dependent serialization.

Implementation documentation updates:

- SDK READMEs: [Rust](../../../../../src/mxc-sdk/README.md),
  [.NET](../../../../../sdk/dotnet/README.md), and
  [Node](../../../../../sdk/node/README.md): experimental Dev access,
  compatible native dependencies, capture/spawn and explicit release.
- Versioned Dev references linked above: W365 lifecycle/execution support,
  timeout/cancellation limits and recovery examples.
- Versioned V1 type/error references for
  [Rust](../../../../api-reference/rust/v1/types.md),
  [.NET](../../../../api-reference/dotnet/v1/types.md), and
  [Node](../../../../api-reference/node/v1/types.md): additive error details
  and their ownership/mapping, without adding typed W365 configuration.

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
