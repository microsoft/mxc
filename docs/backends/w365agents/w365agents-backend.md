# Windows 365 for Agents: lifecycle and native execution

> **Audience:** MXC consumers and developers

This experimental backend implements checkout through `provision`, bounded
readiness polling through `start`, native pipe-backed or executor-relayed
`exec`, and terminal release through `stop` or `deprovision`. It is
included in normal Windows, Linux and macOS builds. Every operation requires
executor `--experimental` or SDK experimental authorization. Local probes do not report W365
availability and never authenticate, discover a pool or check out a Cloud PC.
The Unix executors forward the same explicit lifecycle routing controls to the
engine; their existing create-and-run paths and platform checks are unchanged.

PTY, create-and-run execution and placement sessions remain unavailable.
They fail explicitly without service work. Typed W365 SDK authoring APIs do not
exist. Rust, .NET and Node Dev SDK JSON supports provision, start, stop,
deprovision, captured execution, pipe-backed spawn and validation, with explicit
experimental authorization on every call. Offline functional coverage does not
establish authenticated service compatibility.

### Dev SDK lifecycle and execution

Author the complete development request JSON with an explicit `phase`.
Rust uses `mxc_sdk::v1::dev::{provision_container_json, stop_container_json,
deprovision_container_json}` with `JsonOptions { experimental: true }`.
.NET uses `Microsoft.Mxc.Sdk.V1.Dev.MxcLifecycle` methods
`ProvisionContainerJson`, `StopContainerJson` and `DeprovisionContainerJson`
(or their `Async` variants), with `new JsonOptions { Experimental = true }`.
Node exports the corresponding `provisionContainerJson`, `stopContainerJson`
and `deprovisionContainerJson` from `@microsoft/mxc-sdk/v1/dev`, with
`{ experimental: true }`. All return the complete response JSON string.

After provision, call the corresponding `start_container_json`,
`StartContainerJson` or `startContainerJson` with the saved opaque `sandboxId`.
Only `Ready` permits execution. Execute repeatedly with
`run_in_container_json`, `RunInContainerJson` or `runInContainerJson`, or their
pipe-backed spawn counterparts, using that same ID. These existing APIs do not
allocate replacements or release the reservation. Captured methods return the
normal SDK execution result; pipe-backed handles retain their normal stream,
wait and disposal ownership. Disposal is not terminal reservation release and
does not prove remote process termination. Explicitly stop/deprovision when done.

Provision returns `result.sandboxId` and
`result.metadata.{poolId,sessionId,computerId}`. Retain the ID before any later
operation. Stop/deprovision requests contain `version`, `phase` and
`sandboxId`, not provision settings. Both are terminal release alternatives:
`result.metadata.releaseRequested: true` and `restartable: false` mean
accepted release, not verified reset or permission to restart.

Failures throw/return the normal versioned SDK error. Structured context is
available in Rust `Error.details` (`Option<Box<serde_json::Value>>`),
.NET `MxcException.Details` (`System.Text.Json.JsonElement?`) and Node
`MxcError.details` (`Record<string, unknown> | undefined`). Inspect
`sandboxId`, `possiblySucceeded`, `code`, `operation`, `clientRequestId`
and, when supplied, `requestId` and `httpStatus`. These backend fields are
inside details; the error's top-level code remains the SDK error category.
The cleanup and uncertainty rules below apply equally to SDK calls.
Do not log details wholesale. .NET details remain valid after native result
disposal, and `ToString()` does not include them.

Supply caller-owned control-plane endpoint/token environment variables before
each call. Separate callers can release the same retained ID with renewed
credentials; no SDK-owned reservation registry or credential cache is required.
Async lifecycle wrappers do not add cancellation or retry/replay.
.NET/Node must use the matching managed/package and native library build.
For local .NET applications set `MXC_FFI_DIR` to the directory containing the
paired `mxc_ffi.dll` before the first SDK call and verify that file exists;
the resolver tries that directory first, but falls through if loading fails.
Production binaries ignore fixture trust variables.

## Configuration and contract

Use the `1.1.0-alpha` development contract. Provision accepts only these
settings under `w365Agents.provision`:

| Field | Meaning |
| --- | --- |
| `poolId` | Required hyphenated ASCII GUID of the authorized pool. |
| `userType` | Optional, `Local`, `HumanUser`, or `Agentic`; omission sends no `user-type` header. |
| `userObjectId` | Optional hyphenated ASCII GUID; omission sends no `user-object-id` header. |

Omission of either identity field does not infer a user or silently select
`Local`. Omitted `w365Agents`, an empty wrapper or missing provision settings
fail before checkout. Unknown fields, nulls and per-call endpoint, token or
timeout overrides are rejected. Non-provision operations reject `w365Agents`,
even `{}`. Unsupported filesystem, network, UI, clipboard and proxy policy
fails before service work; MXC cannot enforce local policy on this remote resource.

Supply configuration in the **caller environment**:

| Variable | Requirement |
| --- | --- |
| `W365A_CONTROLPLANE_URL` | Bare ASCII DNS hostname, without scheme, port, path, query, credentials or whitespace. HTTPS uses port 443. |
| `W365A_CP_TOKEN` | Nonempty resource-specific bearer token, without whitespace or control characters. |
| `W365A_DP_SUFFIX` | Bare ASCII data-plane DNS suffix, for example `northeurope.remotinginterface.regional.cloudinferenceplatform-int.azure.com`. MXC prefixes the reservation's pool GUID. Required for start/exec only. |
| `W365A_DP_TOKEN` | Nonempty resource-specific data-plane bearer token with the same character constraints. Required for start/exec only; no control-plane token fallback. |

Missing, invalid or non-Unicode values fail locally. Each call reads the
environment again. MXC does not acquire, cache or renew tokens. The caller
renews credentials before a later cleanup call. Checkout uses the design's
45-second client budget; release uses its separate 30-second budget. These
are transport budgets, not promises about service reset or resource lifetime.
Production uses `native-tls` with the platform's certificate trust store:
SChannel on Windows, Secure Transport on macOS and OpenSSL on Linux.
Certificate and hostname validation remain enabled, with no redirects or
ambient HTTP proxy. Linux builds require OpenSSL development headers and
`pkg-config` (`libssl-dev pkg-config` on Debian/Ubuntu, `openssl-devel pkgconf-pkg-config`
on Fedora); deployed Linux hosts require the matching OpenSSL shared libraries
and CA certificates. ARM64 cross-builds need target-architecture OpenSSL headers
and libraries, not just the host development package.

### Readiness and process execution

Start polls GET `/computers/{sessionId}/status?api-version=1.0` with
`x-ms-computerId`. Only `Ready` succeeds; `Waiting` and `Live` are polled
at one-second intervals within a 120-second client budget. Each HTTP request
and sleep is limited to the remaining budget. Unknown states, missing/expired
reservations, HTTP/transport failures and budget exhaustion are errors.
Neither start nor exec checks out, replaces or releases a Cloud PC.

Exec uses `/computers/{sessionId}/microsoft.exec?api-version=1.0`,
HTTP/1.1 `Upgrade: exec` and the released service's binary framing. It does
not use WebSocket headers, frames or the prototype's `microsoft.mxc-exec`
endpoint. The complete ExecStart payload is validated before connecting;
it and every frame are limited to 65,536 payload bytes.

`process.commandLine` is a nonblank **Windows executable command line**.
MXC explicitly sends `shell: "raw"` and `mode: "pipe"`; it never selects a
hidden shell. To interpret shell operators, supply `cmd.exe /c ...` or an
explicit interpreter executable in the command line. `powershell.exe` means
Windows PowerShell, not `pwsh.exe`. `cwd` is a guest path; omitted/empty
uses the service's default working directory, not a host directory.

Omitted `process.env` uses the guest's inherited environment. Supplied env,
including `[]`, requires `inheritDefaultEnv: true`; replacement is rejected
before dialing. Entries split at the first `=` (missing `=` means an empty
value); the last duplicate name wins. Names must be nonempty and names/values
must contain no NUL. Host environment variables are never forwarded.

`process.timeout` is sent unchanged as `timeoutMs`. Zero uses the released
service's configured default (currently 300,000 ms); it is **not unlimited**.
The client allows that default or the positive requested timeout plus
30 seconds for transport/drain. A local deadline returns `exec_client_timeout`
with unknown remote outcome, not `TimedOut` or a synthetic exit. A real
Exit code, including -1, 124 or 153, is preserved; code 124 alone does not
distinguish a timeout from a program that intentionally returned 124.

Native streams preserve binary stdin/stdout/stderr. Closing every stdin writer,
including the backend's original, sends StdinClose after Started; it does not
close the output connection. Drain stdout and stderr concurrently. Each pending
output queue has an 8 MiB ceiling, excluding one pump chunk and the OS pipe.
The frame consumer never blocks on output: overflow preserves the queued
prefix, discards later bytes and returns `output_truncated`, even after Exit.
Already queued output drains before EOF. Full capture uses memory proportional
to output and returns an error, not partial success, on failure.

Active process disposal cancels local pipes, transport and managed workers.
After completion, output pumps remain supervised until caller-owned output
pipes drain or close; dropping the process alone does not discard their queued
bytes. Executor console stdin can remain blocked until input/EOF or executor
exit. No local teardown releases the reservation or proves remote termination.

The supplied released protocol defines Cancel (`0x04`) and process-tree cleanup.
This staged native adapter deliberately **does not expose remote kill**:
kill closes local execution and reports `remote_termination_unsupported`.
Cancel has no separate acceptance acknowledgement, and its Exit sentinel 1
is also a genuine program result. A confirmed remote cancellation API/result
mapping and authenticated service validation remain separate work. Do not
infer remote termination from disconnect or automatically replay a command.

## Service contract and identity

Checkout sends **one** bodyless POST to
`/api/pools/{poolId}/sessions?api-version=2.0`, forwarding only supplied
user-type and user-object-id headers. Release sends DELETE to
`/api/sessions/{sessionId}?api-version=2.0`, with `x-ms-sessionId`.
Every request has an independent `x-ms-client-request-id`; safe returned
`x-ms-request-id` values are retained on errors. There is no allocation
retry, hidden cleanup, replacement checkout or durable local registry.

Successful checkout requires HTTP 200, `status: "Succeeded"` and a valid
`sessionId`. An omitted `computerId` uses the session ID; a supplied computer
ID must be a valid, equal GUID. IDs are compared case-insensitively and
returned with lowercase GUIDs as `w365:{poolId}:{sessionId}`.
Metadata includes the pool, session and computer IDs, not response URLs,
tokens or ticket-bearing metadata.

Rejected successful checkout retains a valid cleanup identity as
`error.details.sandboxId`, `poolId` and `sessionId`, with
`possiblySucceeded: true`. HTTP error replies also retain a valid session ID
from a parseable response body within the 1 MiB limit, preserving the HTTP
error code and uncertainty classification even when the body cannot be read
or parsed. No ID is fabricated for an absent or invalid session ID.
Unparseable, dropped and ambiguous checkout replies report
uncertainty and request context. Never automatically repeat that POST.
HTTP authorization, missing-pool, throttling and server failures have
operation-specific `details.code` values.

Release validates the complete ID before DELETE and always targets its
session, never a rejected computer ID. HTTP 200, 202, 204 and 404 mean accepted
or already absent; they do **not** prove guest reset, sanitization or reusable
capacity. Both release alternatives return
`result.metadata.releaseRequested: true` and `restartable: false`.
Failed or uncertain release retains the ID in error details for an explicit
retry against the same session. A later checkout B does not replace or clean
up checkout A.

### Service validation limit

The implementation retains the API 2.0 header-based checkout/release contract.
Separate caller-supplied live evidence confirms one bodyless API 2.0 Local
checkout and release from a fresh process with a renewed control-plane token.
It does not establish HumanUser checkout, guest reset, execution or platform-wide
support. API 3.0 Local samples use a different body and do not change the native
contract. A supplied readiness read reached Ready, but exec upgrade returned
HTTP 403 before a command frame. Authenticated live exec has not succeeded;
trusted-TLS fixtures do not establish pool Exec permission or interoperability.

## Manual PowerShell command runner (Windows)

`tests\scripts\run_w365_command_manual.ps1` is an explicit, **manual-only**
backend/CLI validation tool. Its offline regressions run in Windows x64 CI;
CI never invokes the live tool. It uses `wxc-exec.exe` for all
service operations, not public SDK lifecycle APIs or a PowerShell implementation
of the service protocol. It does not change the SDK availability described above.

Prerequisites: Windows, PowerShell 7+, Python 3, a compatible normal executor,
and an approved public client application configured for system-browser
interactive authentication in the requested tenant. Install the auth libraries:

```powershell
python -m pip install "msal>=1.31,<2" "msal-extensions>=1.3,<2"
```

Build the executor from `src\` with `cargo build -p wxc`, or pass a known
compatible binary. The default discovery checks host-architecture release,
unqualified release, host-architecture debug, then unqualified debug under
`src\target`. Before authentication, the runner uses credential-free synthetic
tokens and `--dry-run --experimental` to validate the requested operations against
the `1.1.0-alpha` contract. Dry-runs do not contact the service.

| Argument | Meaning |
| --- | --- |
| `-Operation` | `Run` (default) or `Release`. Release requires an ID and no command. |
| `-SessionId` | Full opaque `w365:<pool-guid>:<session-guid>` returned by MXC. Supplying it never performs checkout. |
| `-ConfigPath` | Token-free five-field deployment JSON; defaults to `w365-test.json` beside the script. See the [shared example](../../../tests/tools/w365/w365-test.example.json). Explicit arguments override config. |
| `-PoolId`, `-TenantId`, `-ClientId` | Nonempty GUIDs for the pool, authentication tenant, and approved public browser client app; supply in config or arguments. No deployment/account defaults. |
| `-CommandLine` | Required for Run: full Windows executable command line, passed unchanged. There is no implicit shell. |
| `-ControlPlaneHost` | Bare DNS host. If supplied, overrides only the executor child's `W365A_CONTROLPLANE_URL`; otherwise inherits the caller's value. |
| `-DataPlaneSuffix` | Bare DNS suffix, with the same precedence over the executor child's `W365A_DP_SUFFIX`. No region is inferred. |
| `-WxcExePath` | Explicit executor path instead of repository discovery. |
| `-LoginHint` | Optional browser/account-selection hint, never proof of identity. |
| `-ExpectedUserObjectId` | Optional actual token `oid` that must match before checkout. |
| `-WorkingDirectory` | Existing guest path, not a host path. Omission uses the service default; the runner does not create it. |
| `-TimeoutMs` | Command timeout, default `30000`. Explicit `0` uses the service default described above, not unlimited execution. |
| `-ReceiptPath` | Token-free journal in an existing directory. Reuse the same path for subsequent calls on the saved ID. Omission creates a freshly named temporary journal, printed before sign-in. |
| `-ForceSignIn` | Force system-browser authentication even if the protected cache has a valid token. |

Both effective endpoints for Run, or only the control-plane endpoint for Release,
must be present and valid before any sign-in,
allocation or service request. URLs, ports, paths, credentials, whitespace,
non-ASCII names and an overlong pool-prefixed data-plane host are rejected.
The runner does not change the parent/global environment.

Example from the repository root, with **synthetic configuration that must
be replaced** with approved values:

```powershell
.\tests\scripts\run_w365_command_manual.ps1 `
    -PoolId '11111111-1111-1111-1111-111111111111' `
    -TenantId '22222222-2222-2222-2222-222222222222' `
    -ClientId '33333333-3333-3333-3333-333333333333' `
    -ControlPlaneHost 'control.example.invalid' `
    -DataPlaneSuffix 'data.example.invalid' `
    -CommandLine 'cmd.exe /c echo hello'
```

### Browser authentication and cache

The only requested scope is the fixed tested ARI INT resource
`274133f7-12bb-4bfb-ae3b-bd446b7e8a75/.default`. There are no scope override
arguments. Tenant, client, pool and endpoints are configurable, but this is
**not universal production/sovereign-cloud authentication support**. One
delegated Computer token is supplied to both control and data plane, as
validated for this service.

The helper checks audience (the resource GUID or exactly `api://` plus that
GUID), actual tenant `tid`, user `oid`, caller app `azp`/`appid`, at least five
minutes of remaining lifetime, and delegated `Computer.Get`, `Computer.See`,
`Computer.Do`, and `Computer.Control` scopes. These decoded-claim sanity
checks do not validate the JWT signature or replace service authentication.
The verified `oid`, not a UPN/login-hint inference, becomes `userObjectId`;
checkout always explicitly requests `userType: "Local"`.

MSAL first attempts silent acquisition, including refresh, for a unique matching
tenant/account. Separate tenant/client cache files and the fixed resource scope
prevent selecting another app/resource. An expected object ID and/or login hint
narrows account selection; multiple matches never silently pick the first.
No applicable account/token, or required interaction, opens the normal system
browser. Existing MFA and consent prompts apply. Missing `.default` consent or
permissions is an auth failure to resolve with the app/service owner: the helper
never changes scopes, app registrations or permissions programmatically.
There is no device-code, password, client-secret, pasted-token or
`-NoTokenCache` mode.

The printed cache path is:

```text
%LOCALAPPDATA%\Microsoft\MXC\w365-manual-auth\<tenant-guid>_<client-guid>.bin
```

`msal-extensions` encrypts it with current-user Windows DPAPI. An operation lock
coordinates account selection/refresh and MSAL's own persistence lock protects
writes. Encryption, decryption, locking and persistence failures stop explicitly;
there is no plaintext or empty-cache fallback. A busy/stale lock fails after
the library's bounded wait, rather than starting an independent sign-in/cache.
Wait for another runner to finish and retry authentication only after resolving
any recorded allocation. Do not remove locks while another invocation is active.

To clear cached credentials intentionally, close active runners and remove only
the exact printed `.bin` file; remove its `.operation.lock`/`.lockfile` only if
confirmed stale. The next invocation requires browser sign-in. DPAPI caches
deliberately contain encrypted secrets; never upload them. `-ForceSignIn`
does not disable caching or revoke existing credentials.

### Allocate once, reuse explicitly, release explicitly

The runner atomically journals the attempt **before submitting one provision**,
saves a valid success or error cleanup ID, calls native `start` (only `Ready`
permits execution), and submits one `exec`. It **does not release automatically**,
including on failure. `-SessionId` skips checkout, calls start, and runs on the
same reservation; it never falls back to another allocation.
`-Operation Release -SessionId <opaque-id>` performs only native deprovision,
in a fresh executor process. Calling the tool intentionally authorizes the
requested operation; there is no additional confirmation switch.

For example, after supplying the deployment config and saving the printed ID:

```powershell
.\tests\scripts\run_w365_command_manual.ps1 -ConfigPath .\w365-test.json `
    -CommandLine 'cmd.exe /c echo first' -ReceiptPath .\session.json
.\tests\scripts\run_w365_command_manual.ps1 -ConfigPath .\w365-test.json `
    -SessionId $id -CommandLine 'cmd.exe /c echo second' -ReceiptPath .\session.json
.\tests\scripts\run_w365_command_manual.ps1 -ConfigPath .\w365-test.json `
    -Operation Release -SessionId $id -ReceiptPath .\session.json
```

Only the executor's private child environment receives `W365A_CP_TOKEN` and
`W365A_DP_TOKEN`. Inherited W365 test hooks are removed. Tokens never enter
argv, request JSON/base64, guest environment, receipts or console diagnostics.
The Python helper's stdout is private redirected transport, not a user-facing
command; do not invoke it directly to print a token. Authentication/service
errors suppress response bodies and preserve safe native categories/status and
request IDs when supplied by the executor.

Command output streams as bytes on stdout/stderr with concurrent draining,
without lifecycle-JSON interpretation, including guest output that looks like
an error envelope. Unused stdin is closed immediately to deliver EOF; this
runner is not an interactive-input tool. The native exec exit status is
preserved. A nonzero exec may be a program result **or** a native adapter
failure: inspect streamed native stderr, not guest-output JSON, for the cause.
The journal retains the native exit status without pretending it independently
proved a remote process exit. Negative native exit statuses are also preserved.

Wrapper budgets leave room for the native limits: 60 seconds for checkout,
135 for readiness (native budget 120), command/service timeout plus 45 seconds
for exec, and 45 for release. Output drain and local worker cleanup waits are
bounded separately. Local timeout/disconnect has an unknown remote outcome;
it never proves the remote process was killed.

If needed, credentials renew silently between phases from the same protected
cache, bound to the verified object ID. Renewal or release failure retains the
reservation ID. A receipt-write failure stops further work and reports the ID;
it never silently releases or makes another checkout.

The token-free journal records pool/session identity, deployment/account
context, local run ID, per-operation results and safe returned request IDs,
not commands, guest output, raw service bodies or credentials. Native successful
responses do not expose HTTP request IDs; the local run ID is not a service
correlation ID. Existing receipts require the same opaque ID, deployment and
owner. Another checkout is always refused. An uncertain command must be
reconciled before another Run; explicit release remains available. A submitted
release must be reconciled before another release attempt. Accepted release
blocks both reuse and duplicate release. All old temporary receipts are retained.

On missing/invalid checkout identity, keep the receipt, stop allocation, and
ask the authorized service operator to reconcile the pool/user and any returned
request IDs. Never invent an ID or delete the journal to retry blindly.
After a crash, the last submitted phase may have an unknown outcome.
For a known saved `sandboxId`, use the credential-free release request and
explicit native `deprovision --container-id` procedure below, in a fresh process
with approved renewed credentials, or use this runner's explicit Release
operation with the retained receipt. Release acceptance means accepted/already
absent, **not completed remote reset or sanitization**.

### Offline runner validation and live gap

Run these explicitly from the repository root:

```powershell
pwsh -NoProfile -File .\tests\scripts\test_w365_command_manual.ps1
python -B -m unittest discover -s tests\scripts -p test_w365_auth.py -v
```

The PowerShell suite invokes the actual entrypoint with owned, staged fake auth
and executor fixtures (Windows .NET Framework compiler required). It covers
pre-auth refusal, unchanged command quoting, private child environments, a
pre-submission journal, fresh-process same-ID reuse and explicit release failures, missing-ID uncertainty,
release acceptance versus reset, large/live output, EOF, and readiness beyond
45 seconds. Python tests inject fake MSAL/cache failures and exercise real DPAPI
and lock persistence in isolated temporary directories using nonsecret fixtures.
They do not read user credential stores, open a browser, allocate or release.

**No authenticated live calls were run for this runner.** The API 2.0 Local
checkout/release evidence above does not establish Exec success. Authenticated
native/SDK Exec remains unverified. A separately authorized standalone client
has completed the documented HTTP/1.1 GET/Upgrade transport on a supplied
computer; that is not native executor or public SDK evidence. This runner does
not change transport or accept `Live` as `Ready` to work around service issues.

## C# public SDK test application

The [repository-backed C# executable](../../../tests/tools/w365/README.md)
owns MSAL.NET authentication and a separate protected cache. It calls
`Microsoft.Mxc.Sdk.V1.Dev.MxcLifecycle` directly for lifecycle and execution,
never the executor, PowerShell/Python helpers or a separate implementation of
those service operations. Its diagnostic-only `status --session-id` command
makes a single authenticated data-plane status GET because the SDK does not
expose a single-fetch status operation. It does not poll, change receipts or
perform lifecycle operations; `Waiting` and `Live` do not satisfy SDK readiness.
It shares the token-free deployment config, run/reuse/explicit-release model
and full opaque MXC ID convention with the native runner. Its JSON output includes
`sessionId`, `sandboxId` and `receiptPath`, including known IDs after failures.
Build and manual handoff instructions, cache location and recovery limitations
are in the tool README.

## Optional live validation: explicit invocation only

**No live calls were run during Phase 3 implementation.** Do not use another caller's
active checkout or token. Obtain authorization for a compatible API 2.0
pool and user identity and confirm the release contract before allocating.
Use a normal executor, not a `test-support` build. Supply the two required
environment variables through the caller's approved credential mechanism;
never put bearer tokens in JSON, command-line arguments, shell history or logs.

Save the following credential-free provision body as `provision.json`,
replacing the synthetic pool and user GUIDs with approved values:

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

Use `lxc-exec` on Linux or `mxc-exec-mac` on macOS. Immediately retain the
returned `result.sandboxId`, or a rejected checkout's
`error.details.sandboxId`, together with deployment/account context.
Without a valid ID, report the client/server request IDs to the authorized
service operator for reconciliation; do not fabricate an ID or replay checkout.

Save `{"version":"1.1.0-alpha"}` as `release.json`. In a fresh process with
valid, caller-renewed credentials, pass the retained ID unchanged:

```text
wxc-exec.exe --config release.json --operation deprovision --container-id <retained-id> --experimental
```

`stop` is the alternative terminal release, not suspension.
Check the release exit status and complete response. On failed or uncertain
release, retain the ID and report primary/cleanup failures separately.
An explicit retry may use renewed credentials and the same ID; do not check
out a replacement as cleanup. Record unresolved IDs for service reconciliation.
Report release acceptance separately from service-confirmed reset completion.

### Later authorized native E2E: one reservation, repeated commands

After the single Local provision above, retain its ID as `$id`. Supply both
data-plane environment variables through the caller's approved credential
mechanism and run readiness explicitly:

```powershell
.\wxc-exec.exe --config release.json --operation start --container-id $id --experimental
```

Stop if readiness fails; keep the ID for release/reconciliation. Do not allocate
another Cloud PC as recovery. Save a credential-free development exec request
as `exec-write.json`, inserting **that same ID**:

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

Build the development native example **without test-support** from `src\`:

```powershell
cargo build --locked -p mxc-sdk --example w365_native_execution
.\target\debug\examples\w365_native_execution.exe --experimental live exec-write.json
.\target\debug\examples\w365_native_execution.exe --experimental capture exec-read.json
```

For `exec-read.json`, keep the ID/cwd unchanged and use
`cmd.exe /c type mxc-phase3.txt`. The first invocation streams output and forwards
stdin; the second captures output concurrently and closes stdin immediately.
Both return the actual Exit code. Verify the persisted marker before proceeding;
service expiration/reset can lose guest state. An additional live request can
launch an explicit interpreter that reads stdin to verify bytes and EOF.
The example uses internal native parser/engine entry points, not public Dev SDK
calls, and performs no allocation, release, credential acquisition or replay.

Always perform the explicit deprovision command above after this work, including
exec failure. Retain the ID after unknown/failed release and report work and
cleanup results separately. Do not reuse existing receipts/reservations for
this test; authorization for a new test must come from the caller.

## Offline functional fixtures

`backend_modules::w365agents::tests::lifecycle_contract_and_recovery_fixture`
uses a controlled TLS service through the normal development parser,
experimental authorization, checked binding and backend dispatch.
`lifecycle_fresh_executor_fixture` additionally launches independent native
executor processes for checkout and release with renewed synthetic credentials.
The latter is ignored by default because it requires a separately built
fixture executor; CI explicitly requires and runs it.

Readiness and execution fixtures cover polling/errors/budget expiry, pre-dial
validation, TLS trust and upgrade refusals, live return before Exit, native
pipe ownership and stdin EOF, simultaneous exact binary outputs over 12 MiB
per stream, slow-output overflow with bounded completion, final queued bytes,
0/nonzero/-1 exits, protocol/remote/transport failures, failed capture, local
deadline and blocked-I/O disposal. `execution_fresh_executor_fixture` exercises
the actual executor's relay and byte output; ordinary executor diagnostics
remain on stderr. Repeated execs retain one ID without checkout/release.
Windows/Linux/macOS build jobs require discovery of every functional fixture.
The scheduled/nightly workflow invokes those same build jobs, so these are
also scheduled native backend scenarios, not orphan test files.

From `src\` on Windows:

```powershell
# Requires openssl on PATH, or MXC_W365_TEST_OPENSSL set to its executable path.
cargo build --locked -p wxc --features test-support
$env:MXC_W365_TEST_EXECUTOR = (Resolve-Path target\debug\wxc-exec.exe).Path
cargo test --locked -p mxc-sdk --lib w365 -- --include-ignored --skip sdk_fresh_caller_fixture --skip test_app_fresh_caller_fixture
```

The ordinary Rust suite also runs public SDK lifecycle and execution fixtures through
the public Dev SDK. For actual .NET and Node SDK calls through FFI, run from
the repository root on Windows with .NET 10 and Node 24 or later:

```powershell
.\tests\scripts\run_w365_sdk_fixtures.ps1
```

This selector builds a separate test-support FFI and the real SDKs, then runs
fresh .NET/Node callers against the existing trusted-TLS fixture. It checks
Local/bodyless checkout, omitted identity, retained IDs, refreshed caller
credentials, terminal release metadata, uncertain release and explicit retry,
rejected checkout cleanup, unknown/no-ID outcomes, experimental/policy refusal,
readiness, captured output, pipe-backed spawn, execution/spawn error details,
and unsupported-mode gates. It also drives the C# test app with synthetic
authentication through new/reuse/release in fresh processes and the real SDK.
Exact request counts reject automatic
replay, and completion markers reject empty/skipped caller suites.
The Windows x64 build job runs it in both regular and scheduled validation;
Rust public SDK coverage runs on all three platforms. These fixtures never
allocate a live Cloud PC and do not prove authenticated service compatibility.
Do not use the test-support FFI for a live test.

CI uses a separate target directory so fixture executors cannot replace
shipping artifacts. Linux builds `lxc` and macOS builds `mxc_darwin` with
`mxc-sdk/test-support`, then supplies the corresponding executable.
Azure additionally requires the lifecycle engine fixture on native Windows/Linux
x64 and macOS arm64 hosts, and the fresh-executor lifecycle fixture on Windows
x64. Cross-compiled Azure Windows/Linux arm64 jobs do not execute fixtures.
Only test builds honor `MXC_W365_TEST_CA` and `MXC_W365_TEST_PORT`; they add a
trusted fixture certificate, never disable certificate or hostname validation.
Shipping builds ignore these variables. Fixtures use only loopback services,
synthetic credentials and generated certificates; no live tenant is needed.
`rcgen` generates fixture certificates. The loopback server uses SChannel on
Windows and `native-tls` elsewhere; the production client uses `native-tls`
on all platforms. Windows and macOS fixtures require
the OpenSSL command-line tool to package generated EC keys as PKCS#12; their
native PEM identity importers do not support this key format. The archive uses
SHA-1/3DES for macOS import compatibility only, not for TLS connections or
production cryptography. The imported Windows test key is explicitly deleted
after the fixture server stops; `native-tls` owns a temporary macOS keychain
removed at process exit. Windows CI selects the OpenSSL executable
included with Git for Windows using `MXC_W365_TEST_OPENSSL`, without changing
`PATH` or replacing other Windows tools. Otherwise fixtures find `openssl` on
`PATH`. These certificate
and key files exist only in a temporary directory, removed after identity
loading; no certificates or private keys are checked in.
