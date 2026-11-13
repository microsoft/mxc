# Windows 365 for Agents: native lifecycle and execution

> **Audience:** MXC consumers and developers

**Access:** The current MXC integration is in development and only available in
an approved tenant. Work is underway to make it widely available.
You need an authorized W365 pool, identity and service credentials; MXC does
not set up tenant access or any of the required resources. For an overview, see
[Windows 365 for Agents overview](https://learn.microsoft.com/en-us/windows-365/agents/introduction-windows-365-for-agents).

W365 supports **explicit container lifecycle operations only**, not
create-and-run execution. Check out a Cloud PC with `provision`, wait for
readiness with `start`, run commands with `exec`, then explicitly release it
with `stop` or `deprovision`. Execution can use captured output or live pipes.
Repeated commands use the same reservation; completing or disposing an
execution does not release it.

Use the Rust, .NET or Node V1.Dev JSON SDK APIs on Windows, Linux or macOS.
Windows also supports `wxc-exec` lifecycle commands; `lxc-exec` and
`mxc-exec-mac` do not expose them. Commands always run on the remote Windows
Cloud PC.

Every operation requires experimental opt-in. Typed W365 SDK authoring APIs,
PTY and placement sessions are unavailable. Local probes do not check W365
availability.

## Configuration and contract

Use the `1.1.0-alpha` development contract. Provision accepts only these
settings under `w365Agents.provision`:

| Field | Meaning |
| --- | --- |
| `poolId` | Required hyphenated ASCII GUID of the authorized pool. |
| `userType` | Optional: `Local`, `HumanUser`, or `Agentic`. |
| `userObjectId` | Optional hyphenated ASCII GUID. |

Omitted identity fields are left to the service; MXC does not infer a user or
select `Local`. Supply `w365Agents.provision` only for provision operations.
Per-call endpoint, token and lifecycle timeout overrides are not supported.
Local filesystem, network, UI, clipboard and proxy policies are rejected before
service work because MXC cannot enforce them on the Cloud PC.

Supply configuration in the **caller environment**:

| Variable | Requirement |
| --- | --- |
| `W365A_CONTROLPLANE_URL` | Control-plane ASCII DNS hostname only, without scheme, port or path. HTTPS uses port 443. |
| `W365A_CP_TOKEN` | Nonempty resource-specific bearer token, without whitespace or control characters. |
| `W365A_DP_SUFFIX` | Bare ASCII data-plane DNS suffix, for example `northeurope.remotinginterface.regional.cloudinferenceplatform-int.azure.com`. MXC prefixes the reservation's pool GUID. Required for start/exec only. |
| `W365A_DP_TOKEN` | Nonempty resource-specific data-plane bearer token with the same character constraints. Required for start/exec only; no control-plane token fallback. |

For example, with an approved token already in `$controlPlaneToken`:

```powershell
$env:W365A_CONTROLPLANE_URL = 'northeurope.sessionmanagement.regional.cloudinferenceplatform.azure.com'
$env:W365A_CP_TOKEN = $controlPlaneToken
```

Set the variables before launching the caller. Use the endpoints authorized for
your pool; the hostname above is only an example. Never put tokens in request
JSON, command-line arguments, shell history or logs.

The caller must acquire and renew tokens, including before cleanup. Each call
rereads the environment. Checkout has a 45-second client budget; release has
30 seconds.

HTTP proxy configuration is not supported.

Linux builds require OpenSSL headers and `pkg-config` (`libssl-dev pkg-config`
on Debian/Ubuntu, `openssl-devel pkgconf-pkg-config` on Fedora), including
target-architecture packages for cross-builds. Deployed Linux hosts need
matching OpenSSL shared libraries and CA certificates.

### Readiness and process execution

Start waits up to 120 seconds for `Ready`, polling once per second.
Failures leave the reservation caller-owned. Exec setup has a separate
30-second connection budget. The serialized command payload is limited to
65,536 bytes.

`process.commandLine` is a **Windows executable command line**, not a shell
script. For shell operators, supply `cmd.exe /c ...` or an explicit interpreter.
`powershell.exe` means Windows PowerShell, not `pwsh.exe`. `cwd` is a guest
path; omitted/empty uses the service's default working directory.

Omitted `process.env` inherits the guest environment, never the caller's.
Supplied entries require `inheritDefaultEnv: true`; environment replacement is
unsupported. Entries use `NAME=value`, with the last duplicate winning; a
missing `=` means an empty value. Empty names and NUL characters are rejected.

`process.timeout` is the service runtime limit in milliseconds, up to 600,000.
Omitted/zero selects the service default (normally 300,000 ms) with no local
MXC command deadline. For positive values, MXC allows another 30 seconds for
transport/output drain. Expiry returns `exec_client_timeout` with unknown remote
outcome, not a synthetic exit or partial success.

.NET and Node pass `process.timeout` unchanged to the service but do not start a
separate SDK timeout timer for W365. Such a timer would disconnect at the runtime
limit, before the native backend's output-drain allowance finishes. The timeout
is therefore enforced by the service, not ignored. Service exit codes are
preserved, including 124 with .NET
`TimedOut == false` or Node `timedOut: false`: code 124 alone cannot distinguish
a timeout from a program's own result.

With live execution, close owned stdin writers for EOF and drain stdout/stderr
concurrently. Each stream has an 8 MiB pending-output queue in addition to pump
and pipe buffers. An unread stream can overflow and fail with `output_truncated`,
preserving its queued prefix. Dropping a reader discards later output for that
stream but does not clear an existing overflow. Retained readers can drain queued
output after completion, even after a failed wait and process disposal.

The executor and live example allow five seconds to drain host output after
completion; undelivered output fails with `host_output_undelivered`. A blocked
stderr, including one sharing an undrained stdout pipe, prevents a final
diagnostic response rather than blocking exit. Capture buffers the full output in
memory and fails rather than returning successful partial output.

Disposal stops local I/O, not necessarily the remote command. Kill reports
`remote_termination_unsupported`. Neither releases the reservation; do not
automatically replay commands after a disconnect or timeout.

## Reservation ownership and error recovery

Retain the returned `result.sandboxId` (`w365:{poolId}:{sessionId}`) and pass it
unchanged to later operations. MXC does not keep a local reservation registry.

Checkout can fail after allocating a session. Retain any cleanup ID from
`error.details.sandboxId` or the SDK error message and explicitly release it.
If no ID was returned, give the service operator the `clientRequestId`, any
service `requestId` and `possiblySucceeded` value for reconciliation. Do not
repeat checkout automatically. SDK messages are diagnostic text, not a parsing API.

Stop and deprovision are terminal release alternatives, not suspension.
`result.metadata.releaseRequested: true` means release was accepted or the
session was already absent; it does not confirm reset, sanitization or reusable
capacity. If release fails or is uncertain, retain the same ID for an explicit
retry with renewed credentials. A new checkout does not clean up an earlier one.

## Dev SDK lifecycle and execution

These APIs provide the W365 lifecycle flow on Windows, Linux and macOS without
launching an MXC executor. Supply the documented environment variables before
invoking an SDK. Use a complete development-contract request, including `phase`:

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

Replace the synthetic GUIDs with authorized values. Pass this JSON string to
the existing Dev API; each returns the complete response JSON:

| SDK | Provision call |
| --- | --- |
| Rust | `dev::provision_container_json(provision_json, dev::JsonOptions { experimental: true })` through `mxc_sdk::v1::dev`. |
| .NET | `Dev.MxcLifecycle.ProvisionContainerJson(provisionJson, new Dev.JsonOptions { Experimental = true })` with `using Dev = Microsoft.Mxc.Sdk.V1.Dev;`. |
| Node | `await provisionContainerJson(provisionJson, { experimental: true })` from `@microsoft/mxc-sdk/v1/dev`. |

Retain `result.sandboxId` immediately. To release without start or exec,
pass `{"version":"1.1.0-alpha","phase":"deprovision","sandboxId":"<retained-id>"}`
to the corresponding `deprovision_container_json`, `DeprovisionContainerJson`
or `deprovisionContainerJson` API with experimental authorization.
The stop APIs are terminal release alternatives. Validation APIs perform
local checks without allocating or releasing a session.

After provision, call the corresponding Dev start API with
`{"version":"1.1.0-alpha","phase":"start","sandboxId":"<retained-id>"}`.
Start returns only after status is `Ready`; a status failure leaves the
reservation caller-owned. Supply the documented data-plane environment first.
For execution, use the same ID in a development request with `phase: "exec"`
and `process.commandLine`, for example `cmd.exe /c echo hello`.

| SDK | Capture | Live pipes |
| --- | --- | --- |
| Rust V1.Dev | `run_in_container_json(exec_json, options)` | `spawn_in_container_json(exec_json, options)` |
| .NET V1.Dev.MxcLifecycle | `RunInContainerJsonAsync(execJson, options)` | `SpawnInContainerJsonAsync(execJson, options)` |
| Node V1.Dev | `await runInContainerJson(execJson, options)` | `await spawnInContainerJson(execJson, options)` |

Capture closes unused stdin and drains both output streams. Rust capture preserves
bytes; Node/.NET capture decode UTF-8. All live streams preserve bytes.
Node/.NET asynchronous process failures report `BackendError` without remote
diagnostic details. Rust wait/kill errors retain the backend message but not
structured details; native executor responses retain structured details.

## Optional live validation: explicit invocation only

The CLI commands below use Windows `wxc-exec`. On Linux/macOS, use the
Dev SDK lifecycle flow above instead.

Use an authorized pool and identity, the environment variables above and a
normal build without `test-support`. Do not reuse another caller's reservation.

Save this as `provision.json`, replacing the synthetic pool GUID:

```json
{
  "version": "1.1.0-alpha",
  "containment": "w365_agents",
  "w365Agents": {
    "provision": {
      "poolId": "11111111-1111-1111-1111-111111111111",
      "userType": "Local"
    }
  }
}
```

Run **once**, capturing stdout and the exit status:

```text
wxc-exec.exe --config provision.json --operation provision --experimental
```

Retain `result.sandboxId`, or follow the error recovery guidance above if
checkout fails.

Save `{"version":"1.1.0-alpha"}` as `release.json` for the remaining lifecycle
commands.

### Run commands on the same reservation

After the single Local provision above, retain its ID as `$id`. Supply both
data-plane environment variables through the caller's approved credential
mechanism and run readiness explicitly:

```powershell
.\wxc-exec.exe --config release.json --operation start --container-id $id --experimental
```

If readiness succeeds, save this as `exec-write.json` with **the same ID** and
an existing guest working directory:

```json
{
  "version": "1.1.0-alpha",
  "phase": "exec",
  "sandboxId": "w365:11111111-1111-1111-1111-111111111111:22222222-2222-2222-2222-222222222222",
  "process": {
    "commandLine": "cmd.exe /c \"echo mxc-phase3>mxc-phase3.txt & type mxc-phase3.txt\"",
    "cwd": "C:\\approved-existing-work-directory",
    "timeout": 30000
  }
}
```

Build the Dev SDK execution example **without test-support** from `src\`:

```powershell
cargo build --locked -p mxc-sdk --example w365_execution
.\target\debug\examples\w365_execution.exe --experimental live exec-write.json
.\target\debug\examples\w365_execution.exe --experimental capture exec-read.json
```

For `exec-read.json`, keep the ID/cwd unchanged and use
`cmd.exe /c type mxc-phase3.txt`. The first invocation streams output and forwards
stdin; the second captures output and closes stdin immediately. Both return the
guest exit code. The marker demonstrates state retained between commands;
service expiration/reset can still lose guest state.

Always release after the test, including after readiness or exec failure.
With valid credentials, pass the retained ID unchanged:

```powershell
.\wxc-exec.exe --config release.json --operation deprovision --container-id $id --experimental
```

Report execution and cleanup failures separately and retain the ID until release
is accepted.

## Offline functional fixtures

The `w365_lifecycle` integration target tests lifecycle recovery, readiness,
binary I/O, backpressure, timeouts and cleanup against loopback TLS services.
It needs no live tenant. Separate .NET and Node fixtures cover Dev JSON APIs.
For CI hosts and job wiring, see the
[validation runbook](../../development/build-and-test/ci-validation-infrastructure.md#offline-tls-fixtures).

From `src\` on Windows:

```powershell
# Requires openssl on PATH, or MXC_W365_TEST_OPENSSL set to its executable path.
cargo build --locked -p wxc --features test-support --target-dir target\w365-fixture
cargo build --locked -p mxc-sdk --example w365_execution --features test-support --target-dir target\w365-fixture
$env:MXC_W365_TEST_EXECUTOR = (Resolve-Path target\w365-fixture\debug\wxc-exec.exe).Path
cargo test --locked -p mxc-sdk --test w365_lifecycle --features test-support --target-dir target\w365-fixture -- --include-ignored
```

Keep fixture artifacts separate from shipping builds. Fresh-executor tests are
ignored unless explicitly included as above. Linux/macOS jobs build the execution
example but do not require a fixture executor. Windows/macOS fixtures require
the OpenSSL CLI on `PATH` or selected by `MXC_W365_TEST_OPENSSL`.
Test certificate and deadline overrides work only in `test-support` builds;
shipping builds ignore them.
