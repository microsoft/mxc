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
| `poolId` | Optional hyphenated ASCII GUID. When supplied, use only that pool; otherwise try the signed-in user's assigned pools in list order. Explicit null and empty values are invalid. |
| `userType` | Optional: `Local` or `HumanUser`. `Agentic` is parsed but rejected because its auxiliary authentication is unsupported. |
| `userObjectId` | Required non-nil hyphenated ASCII GUID for API 3.0 checkout. |

MXC does not infer a user or select `Local`. Supply `w365Agents.provision` only for provision operations.
Per-call endpoint, token and lifecycle timeout overrides are not supported.
Local filesystem, network, UI, clipboard and proxy policies are rejected before
service work because MXC cannot enforce them on the Cloud PC.

Supply configuration in the **caller environment**:

| Variable | Requirement |
| --- | --- |
| `W365A_GRAPH_TOKEN` | Separate caller-supplied Graph bearer token, required only for provision. Use a token for the selected Graph environment. |
| `W365A_GRAPH_ENVIRONMENT` | `public` (default) or `canary`. Selects a fixed Graph deployment, not an arbitrary URL. |
| `W365A_CP_TOKEN` | Nonempty resource-specific control-plane bearer token, without whitespace or control characters. Required for provision and release; also used for start/exec when `W365A_DP_TOKEN` is absent. |
| `W365A_DP_TOKEN` | Optional data-plane bearer token for start/exec, overriding `W365A_CP_TOKEN`. An explicitly set empty or invalid value fails validation rather than falling back. |

For example, with an approved token already in `$controlPlaneToken`:

```powershell
$env:W365A_CP_TOKEN = $controlPlaneToken
$env:W365A_GRAPH_TOKEN = $graphToken
```

Set the variables before launching the caller. Never put tokens in request
JSON, command-line arguments, shell history or logs.

The caller must acquire and renew tokens, including before cleanup. Each call
rereads only the credentials it needs. Listing assigned pools has a 30-second
budget across pages; each pool-resource fetch has a separate 30-second budget.
Each pool checkout has a 45-second budget, and release has 30 seconds. Checkout
sends API 3.0 JSON `userObjectId` and optional `sessionKind` (`local` or `human`).
`Created` completes using the same session ID and client request ID inside that
checkout budget; it never triggers a replacement allocation.

### Endpoint discovery and local routing

When `poolId` is supplied, provision fetches its resource directly without
listing assigned pools. When it is omitted, MXC first lists
`/beta/me/cloudPcPools` on `graph.microsoft.com`, or
`/testprodbeta_cpc_sh/me/cloudPcPools` on `canary.graph.microsoft.com`, following
pagination only within that collection. Malformed or duplicate pool IDs fail
before checkout. An empty list returns `no_assigned_pools`, not a CP fallback.

For each candidate, MXC fetches `/beta/deviceManagement/virtualEndpoint/cloudPcPools/{poolId}`
on public Graph, or
`/testprodbeta_cpc_sh/deviceManagement/virtualEndpoint/cloudPcPools/{poolId}`
on Canary, and reads `poolUrl` from that resource, not the list entry. The
resource's `id` must match the candidate pool. Listing and resource fetches use
the same Graph token; the caller must authorize the endpoints used.
Authentication, transport, HTTP (including resource GET 404), malformed-response
and pagination failures are errors, not fallback conditions. No administrative
pool-list fallback is used.

MXC reads `sessionUsage.availableSessionsCount` from each fetched pool resource.
Checkout is attempted only when this Int32 count is greater than zero;
nonpositive counts skip that pool without a checkout request. Automatic
selection continues to the next assigned pool. An explicitly selected pool
with no capacity, or an assigned-pool list with no available capacity, returns
`no_available_sessions`. Missing or malformed usage metadata is a discovery
error, not assumed capacity. Availability is a snapshot, not a reservation;
checkout can still fail after a positive count.

Graph is the only source of checkout endpoints. MXC uses `poolUrl`'s destination,
path and existing query as returned, appending `api-version=3.0` for checkout
and same-ID completion. It does not rewrite pool IDs, regions or hosts, or impose
a service host or path pattern. URLs require HTTPS port 443, an ASCII DNS host,
and no credentials or fragment. For a pool with capacity, missing, null, empty
or invalid `poolUrl` fails before checkout; there is no endpoint environment
fallback. MXC saves the selected pool identity and complete checkout URL for
later lifecycle calls. Authentication query parameters are rejected.

Without a supplied `poolId`, MXC fetches each candidate's details and attempts
checkout in list order, stopping at the first successful checkout whose routing
was saved. It advances only after a definitive HTTP 4xx checkout rejection
(excluding 408) with `possiblySucceeded=false` and no allocated session ID.
If every pool is rejected, the error retains the last failure and `poolAttempts`
details. With an explicit ID, any checkout failure is returned immediately.

Transport errors, timeouts, redirects, server errors, any returned session ID,
invalid successful responses and routing-publication failures stop provisioning;
they never trigger another pool allocation. Retain the reported cleanup ID and
CP destination. Graph resource/authentication/validation errors also stop the
operation rather than skipping a pool. No automatic release is performed.

Successful checkout must supply a `computerUrl` for
`https://{poolId}.{region}.remotinginterface.regional.cloudinferenceplatform[-int].azure.com/computers/{sessionId}?api-version=1.0`.
This is a computer-resource URL, not a bare origin or MCP endpoint. MXC validates
the identity, host, path and sole query before appending operations for readiness
`/computers/{sessionId}/status?api-version=1.0` and Desktop Exec
`/computers/{sessionId}/microsoft.exec?api-version=1.0`. Other prefixes, versions,
query parameters or host families are unsupported.

The `computerUrl` mapping remains deliberately narrow. An observed API 2.0
session-list `computerUrl` does not prove API 3.0 checkout compatibility or
permissions for both Graph endpoints in a deployed tenant. Controlled fixtures
verify MXC's behavior, not service availability.

MXC stores versioned, nonsecret `connection.json` records under
`%LOCALAPPDATA%\Microsoft\MXC\w365\{poolId}\{sessionId}` on Windows,
`${XDG_DATA_HOME:-$HOME/.local/share}/Microsoft/MXC/w365/{poolId}/{sessionId}`
on Linux, and `$HOME/Library/Application Support/Microsoft/MXC/w365/{poolId}/{sessionId}`
on macOS. Records contain identity, the complete validated `poolUrl` and
`computerUrl`, and CP source. Release uses the saved control-plane authority
with `/api/sessions/{sessionId}?api-version=2.0`, not the checkout path.
Hostname-only records are unsupported. Records never contain tokens, tickets
or complete service responses. Private ownership and permissions, per-record
locks and atomic publication protect the records.
Local lock contention fails explicitly with `routing_state_lock`; retry an
existing-ID operation only after contention clears. A provisioning error is
never permission to repeat allocation.

Later operations require the matching local record and ignore ambient endpoint
variables, including `W365A_DP_SUFFIX`. They do not call Graph. Credentials
remain caller-owned and resource-specific; CP credentials are reused for DP
only when no explicit DP token is set. The caller must ensure the reused token
is authorized for the data plane. No token cache or renewal provider is added.
Do not copy records between users or machines. Missing,
corrupt, unsupported-version, foreign-owned or conflicting records fail
explicitly; automatic import, endpoint refresh and legacy-ID fallback are not
implemented. Backend storage errors require correction or service-operator
reconciliation, not another allocation.

HTTP proxy configuration is not supported.

Linux builds require OpenSSL headers and `pkg-config` (`libssl-dev pkg-config`
on Debian/Ubuntu, `openssl-devel pkgconf-pkg-config` on Fedora), including
target-architecture packages for cross-builds. Deployed Linux hosts need
matching OpenSSL shared libraries and CA certificates.

### Readiness and process execution

Start waits up to 120 seconds for `Ready`, polling once per second.
Expiry returns `attach_timeout`, including while waiting for a status response.
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
unchanged to later operations. MXC retains a local routing cache, not a registry
of authoritative remote reservation status.

Checkout can fail after allocating a session. Retain any cleanup ID from
`error.details.sandboxId` or the SDK error message and explicitly release it.
If no ID was returned, give the service operator the `clientRequestId`, any
service `requestId` and `possiblySucceeded` value for reconciliation. Do not
repeat checkout automatically. SDK messages are diagnostic text, not a parsing API.
If checkout yields an ID but lacks a supported `computerUrl`, provisioning fails
and MXC retains CP-only routing for explicit release. If writing the routing
record itself fails after allocation, retain the reported ID and CP host for
service-operator cleanup: ordinary lifecycle calls cannot recover without a
valid local record. MXC does not auto-release, replay checkout or discard the ID.

Stop and deprovision are terminal release alternatives, not suspension.
`result.metadata.releaseRequested: true` means release was accepted or the
session was already absent; it does not confirm reset, sanitization or reusable
capacity. If release fails or is uncertain, retain the same ID for an explicit
retry with renewed credentials. A new checkout does not clean up an earlier one.
Routing records remain after accepted release to support explicit retries;
their presence never means the reservation is still usable.

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
      "userType": "Local",
      "userObjectId": "22222222-2222-2222-2222-222222222222"
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
data-plane token through the caller's approved credential
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

## PowerShell live-test runner

`tests\scripts\run_w365_command_manual.ps1` runs `Provision`, `Run` (default),
or explicit `Release` through `wxc-exec.exe`. It requires Windows, PowerShell 7,
Python with `msal` and `msal-extensions` (`python -m pip install msal msal-extensions`),
and a current shipping executor built from this checkout, without `test-support`.
It does not build the executor or create tenant resources.

Supply `TenantId` and a public-client `ClientId` authorized for browser sign-in
with a localhost redirect. Provision acquires a separate Graph token using
`https://graph.microsoft.com/CloudPC.Read.All`, or
`https://canary.graph.microsoft.com/CloudPC.Read.All` with
`-GraphEnvironment canary`. Graph credentials stay in memory; the helper does not
open a persistent Graph cache. Consent and permission to both the assigned-pool
and pool-resource endpoints must be verified in the target tenant.

CP and DP credentials are acquired separately for the same tenant, client and
authenticated user, only for the operations needing them. Both resource IDs
default to production `90ecec28-f5a6-42b3-9bde-dae1ca98f8b5` for
`-GraphEnvironment public` (the default), or INT
`274133f7-12bb-4bfb-ae3b-bd446b7e8a75` for `canary`.
`-ControlPlaneResource` and `-DataPlaneResource`, or their config fields, override
these defaults independently; the sign-in `ClientId` does not change.
When both resources match, the runner supplies only `W365A_CP_TOKEN` to
start/exec, exercising the backend's token fallback. A different DP resource
uses `W365A_DP_TOKEN` instead. Inherited W365 credentials are not forwarded.
The helper requests each resource's `/.default` and checks delegated
`Computer.Get`, `Computer.See`, `Computer.Do` and `Computer.Control` permissions.
Deployments with other permission contracts need a corresponding helper update.
Service credentials retain the Phase 3 current-user DPAPI cache under
`%LOCALAPPDATA%\Microsoft\MXC\w365-manual-auth`, bound to tenant/client/resource.
This test-tool cache is separate from native routing records; no authentication
provider or token cache is added to MXC.

Pass settings as parameters or an uncommitted JSON config selected by
`-ConfigPath`. The default path is `tests\scripts\w365-test.json`. For example:

```json
{
  "tenantId": "<tenant-guid>",
  "clientId": "<public-client-guid>",
  "graphEnvironment": "canary"
}
```

Optional config keys are `poolId`, `controlPlaneResource`
and `dataPlaneResource`; explicit parameters take precedence. Omit `poolId`
to try assigned pools in order, or supply it to fetch only that pool's details.
Remove the retired
`controlPlaneHost` and `dataPlaneSuffix` config keys/parameters.
The runner does not consume ambient `W365A_*` credentials or endpoints.

From the repository root, using the same config and receipt throughout:

```powershell
# Provision only, retaining the actual selected pool and full MXC ID.
.\tests\scripts\run_w365_command_manual.ps1 -Operation Provision -ConfigPath .\w365-test.json -ReceiptPath .\w365-receipt.json
$id = (Get-Content .\w365-receipt.json -Raw | ConvertFrom-Json).sessionId

# Readiness and execution on that reservation; no Graph sign-in or checkout.
.\tests\scripts\run_w365_command_manual.ps1 -ConfigPath .\w365-test.json -SessionId $id -CommandLine 'cmd.exe /c whoami' -ReceiptPath .\w365-receipt.json

# Explicit release uses only CP authentication and the native routing record.
.\tests\scripts\run_w365_command_manual.ps1 -Operation Release -ConfigPath .\w365-test.json -SessionId $id -ReceiptPath .\w365-receipt.json
```

`Run` without `SessionId` provisions, waits and executes, retaining the session
even on failure. `-WxcExePath` selects an explicit executor; `-LoginHint`,
`-ExpectedUserObjectId` and `-ForceSignIn` control browser authentication.
Tokens go only through private helper output and per-operation child environment
variables, never command-line arguments, config or receipts. Reuse requires the
same user and machine's native routing record, not just a copied receipt.

Receipts use `mxc-w365-manual-v3` and retain the actual pool, full opaque MXC ID,
owner, deployment and operation outcomes. They cannot import old routing or
Phase 3 v2 receipts. `provisionInvocationCount` counts native calls, not the
backend's individual pool checkout attempts. The runner never retries a failed
provision or automatically releases a session; retain reported IDs and recovery
hosts after failures. An uncertain release cannot be replayed using its receipt.
Release acceptance does not confirm reset or sanitization.

The provision dry-run precedes authentication; subsequent dry-runs use the
real ID after its routing record exists. Provision has no additional frontend
deadline: native listing, resource and per-pool checkout budgets apply across
all candidates. Cancelled or interrupted provisioning requires reconciliation,
not another checkout. Long selection runs can outlive a caller's token; there
is no refresh during a native operation.

## Offline functional fixtures

The manual runner also has isolated regressions for Graph/service auth separation,
optional and explicit pools, returned-pool receipts, existing-ID operations,
recovery after routing-write failures, uncertain outcomes and credential redaction:

```powershell
# From the repository root; no sign-in, user cache access or service calls.
python .\tests\scripts\test_w365_auth.py
pwsh -NoProfile -File .\tests\scripts\test_w365_command_manual.ps1
```

These require the Python packages above and Windows .NET Framework's C# compiler.
Python persistence tests use only fresh synthetic DPAPI files.

The `w365_lifecycle` integration target tests lifecycle recovery, readiness,
binary I/O, backpressure, timeouts and cleanup against loopback TLS services.
It also tests separate Graph/CP/DP credentials, public/Canary list pagination
followed by pool-resource retrieval, resource identity validation,
required discovery metadata, skipping unavailable pools, invalid capacity,
authoritative checkout paths/queries and same-ID
completion, explicit and automatic pool selection, ordered checkout failover
and exhaustion, refusal to fail over after uncertain allocation or publication
failure, API 3.0 same-ID completion, checkout-derived routing,
private routing records, contention, missing/corrupt/mismatched/linked records,
atomic-write failure after allocation and fresh-process
provision/start/exec/release without endpoint variables. Each fixture uses an
isolated private state root and synthetic credentials; it must never read a
user's real routing store. It needs no live tenant. Separate .NET and Node
fixtures cover Dev JSON APIs.
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
example but do not require a fixture executor. All fixture hosts require
the OpenSSL CLI on `PATH` or selected by `MXC_W365_TEST_OPENSSL`.
Test certificate, endpoint, state-root, write-failure and deadline overrides work only in `test-support` builds;
shipping builds ignore them.
