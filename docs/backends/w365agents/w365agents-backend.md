# Windows 365 for Agents: native lifecycle and execution

> **Audience:** MXC consumers and developers

W365 supports **explicit container lifecycle operations only**, not
create-and-run execution. Check out a Cloud PC with `provision`, wait for
readiness with `start`, run commands with `exec`, then explicitly release it
with `stop` or `deprovision`. Execution can use captured output or live pipes.
Repeated commands use the same reservation; completing or disposing an
execution does not release it.

The backend is included in normal Windows, Linux and macOS builds, but its
entry points differ:

| Caller platform | Rust, .NET and Node V1.Dev JSON SDK APIs | Shipping CLI |
| --- | --- | --- |
| Windows | Full W365 lifecycle flow | `wxc-exec` lifecycle commands |
| Linux | Full W365 lifecycle flow | Not available through `lxc-exec` |
| macOS | Full W365 lifecycle flow | Not available through `mxc-exec-mac` |

Use the Dev JSON SDK APIs for W365 on Linux/macOS. Their local backends'
create-and-run CLI support does not enable create-and-run execution for W365.
Commands execute on the remote Windows Cloud PC regardless of caller platform.

Every operation requires experimental opt-in through the V1.Dev JSON APIs or
`wxc-exec --experimental`. Typed W365 SDK authoring APIs, PTY and placement
sessions are unavailable; published typed APIs are unchanged. Unsupported
operations fail explicitly without service work. Local probes do not report
W365 availability and never authenticate, discover a pool or check out a
Cloud PC. Native executor responses retain structured errors and cleanup
identities.

At the native engine boundary, create-and-run execution resolves the W365
runner and is refused by the backend with `policy_validation`, including
run-to-completion dry runs. It does not read service credentials or make a
service request. Development MXC request JSON still does not accept W365
create-and-run requests.

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

For example, configure the North Europe control-plane hostname below.
With a resource-specific token already obtained through your approved
credential mechanism in `$controlPlaneToken`, configure the caller in PowerShell:

```powershell
$env:W365A_CONTROLPLANE_URL = 'northeurope.sessionmanagement.regional.cloudinferenceplatform.azure.com'
$env:W365A_CP_TOKEN = $controlPlaneToken
```

Set these variables before launching the SDK application or executor from that
PowerShell process. This endpoint is an example, not a production default;
use the endpoint authorized for your pool. Do not paste token values into shell
history or logs.

Missing, invalid or non-Unicode values fail locally. Each call reads the
environment again. MXC does not acquire, cache or renew tokens. The caller
renews credentials before a later cleanup call. Checkout uses the design's
45-second client budget; release uses its separate 30-second budget. These
are transport budgets, not promises about service reset or resource lifetime.
Lifecycle, readiness and execution use `native-tls` with the platform's certificate trust store:
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

Execution setup has one 30-second budget covering system DNS, TCP connection,
TLS handshake and HTTP upgrade. Each underlying TLS read/write uses the remaining
budget, so fragmented traffic cannot keep extending it. System DNS cannot be
portably cancelled: at most four lookup workers may remain blocked after callers
time out. They retain their capacity until they finish; later callers wait for
capacity within their own setup budget. Late lookup results never initiate a
connection or send credentials or a command.

`process.timeout` is sent unchanged as `timeoutMs`. Omitted or zero selects the
service's configured default (normally 300,000 ms) and imposes no local MXC command
deadline; the service's limits still apply. A positive timeout allows the requested
duration plus 30 seconds for transport/drain locally. The service supports positive
values through 600,000 ms. A local deadline returns `exec_client_timeout`
with unknown remote outcome, not `TimedOut` or a synthetic exit. A real
Exit code, including -1, 124 or 153, is preserved; code 124 alone does not
distinguish a timeout from a program that intentionally returned 124.
The .NET and Node Dev JSON live/capture APIs use this native deadline rather
than attempting a local kill at the guest runtime limit. They preserve output
drained after that limit and the service's exit code. Other backends retain
their existing SDK timeout behavior.

Native streams preserve binary stdin/stdout/stderr. Closing every stdin writer,
including the backend's original, sends StdinClose after Started; it does not
close the output connection. Drain stdout and stderr concurrently. Each pending
output queue has an 8 MiB ceiling, excluding one pump chunk and the OS pipe.
Unix output pumps wait for pipe writability and resume as soon as callers drain
space, with bounded waits so local cancellation remains effective.
Native stdio transfer preserves the caller-facing output pipes' original blocking
mode rather than exporting the cancellable reader's nonblocking mode.
The transport reads output while stdin sends are backpressured. One pending
stdin frame and at most 128 KiB of encrypted send data are buffered locally;
socket writes are nonblocking, so cancellation and the client deadline remain
effective while the guest is not reading stdin.
The executor and live execution example flush each forwarded output chunk,
including prompts without a newline; write or flush failures remain errors.
After execution completes or fails, host stdout/stderr forwarding has a shared
five-second final-drain budget. An open, unread host pipe is cancelled rather
than blocking completion. Undelivered output returns `host_output_undelivered`
as an error, preserving any earlier execution failure and the forwarded prefix.
If host stderr itself cannot drain, the executor/example exits unsuccessfully
without attempting another blocking diagnostic write; no envelope can be
guaranteed on that unavailable stream.
The frame consumer never blocks on output: overflow preserves the queued
prefix, discards later bytes and returns `output_truncated`, even after Exit.
Already queued output drains before EOF. Full capture uses memory proportional
to output and returns an error, not partial success, on failure.

Active process disposal cancels local pipes, transport and managed workers.
The executor and live execution example preserve a confirmed guest exit when
input-pipe closure interrupts pending stdin forwarding. Host stdin read errors
and other write errors remain failures.
Host input forwarding is cancelled and joined before completion returns, even
when stdin remains open and idle or forwarding is blocked on guest stdin.
Windows console forwarding owns a separate input handle, preserves UTF-8 text
and Ctrl-Z EOF, and leaves later input available for the next execution.
Unix standard-input flags are restored after all forwarding workers stop,
including when standard handles share an open file description.
After completion, output pumps remain supervised until caller-owned output
pipes drain or close; dropping the process alone does not discard their queued
bytes. No local teardown releases the reservation or proves remote termination.

The supplied released protocol defines Cancel (`0x04`) and process-tree cleanup.
This staged native adapter deliberately **does not expose remote kill**:
kill closes local execution and reports `remote_termination_unsupported`.
Cancel has no separate acceptance acknowledgement, and its Exit sentinel 1
is also a genuine program result. A confirmed remote cancellation API/result
mapping and authenticated service validation remain separate work. Do not
infer remote termination from disconnect or automatically replay a command.

## Service contract and identity

Checkout sends **one** bodyless POST to
`/api/pools/{poolId}/sessions?api-version=3.0`, forwarding only supplied
user-type and user-object-id headers. Release sends DELETE to
`/api/sessions/{sessionId}?api-version=2.0`, with `x-ms-sessionId`.
Checkout, readiness and release requests have independent
`x-ms-client-request-id` values; safe returned `x-ms-request-id` values are
retained on errors. There is no allocation
retry, hidden cleanup, replacement checkout or durable local registry.
All W365 requests from SDKs and executors, including exec upgrades, send
`User-Agent: mxc/<native SDK version> (w365_agents)`, using the native SDK package
version. This identifies the client for diagnostics, not authentication.

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
Checkout error messages include `clientRequestId`, `possiblySucceeded` and,
when returned and validated, the service's `requestId`. These remain available
through existing SDK error messages when no valid session ID was returned.
Retain them for service-side reconciliation rather than repeating checkout.
When checkout returns a valid session ID but fails, its error message also
includes the complete cleanup `sandboxId`. This makes the ID available through
existing SDK error messages, including .NET's `MxcException.Message`; no new
.NET error property is required. Retain the ID for explicit release.
No cleanup ID is included in the message when the returned session ID is
absent or invalid. Later operations already receive the ID from the caller.

Release validates the complete ID before DELETE and always targets its
session, never a rejected computer ID. HTTP 200, 202, 204 and 404 mean accepted
or already absent; they do **not** prove guest reset, sanitization or reusable
capacity. Both release alternatives return
`result.metadata.releaseRequested: true` and `restartable: false`.
Failed or uncertain release retains the ID in error details for an explicit
retry against the same session. A later checkout B does not replace or clean
up checkout A.

### Dev SDK lifecycle and execution

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

On failed Provision, retain the error message and any returned cleanup ID for
explicit release. Messages are diagnostic text, not a structured parsing API.
If no valid ID was returned, use the service reconciliation procedure below;
do not repeat checkout automatically. No SDK call acquires or renews tokens.

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

Capture closes unused stdin and drains both output streams. Live callers
write/close stdin and drain stdout/stderr concurrently. Rust capture preserves
bytes; Node and .NET capture decode UTF-8, while their live streams preserve bytes.
Failures reject/throw rather than returning successful partial output. The
existing C ABI reports asynchronous process failures to Node/.NET as
`BackendError` with generic process-status text; it does not carry the remote
diagnostic details. Rust process wait/kill errors retain the backend message,
not structured details. Native executor responses retain structured details.
Neither waiting nor disposing releases the reservation or confirms remote
termination; explicitly stop/deprovision the same ID.

## Optional live validation: explicit invocation only

The CLI commands below use Windows `wxc-exec`. On Linux/macOS, use the
Dev SDK lifecycle flow above instead.

**Live validation requires explicit authorization.** Do not use another
caller's active checkout or token. Obtain authorization for a compatible API 3.0
pool and user identity and confirm the release contract before allocating.
Use a normal executor, not a `test-support` build. Supply the required
control-plane and data-plane environment variables through the caller's approved credential mechanism;
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

Immediately retain the returned `result.sandboxId`, or a rejected checkout's
`error.details.sandboxId`, together with deployment/account context.
Without a valid ID, report the client/server request IDs from the error details
or SDK error message to the authorized service operator for reconciliation;
do not fabricate an ID or replay checkout.

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

Build the Dev SDK execution example **without test-support** from `src\`:

```powershell
cargo build --locked -p mxc-sdk --example w365_execution
.\target\debug\examples\w365_execution.exe --experimental live exec-write.json
.\target\debug\examples\w365_execution.exe --experimental capture exec-read.json
```

For `exec-read.json`, keep the ID/cwd unchanged and use
`cmd.exe /c type mxc-phase3.txt`. The first invocation streams output and forwards
stdin; the second captures output concurrently and closes stdin immediately.
Both return the actual Exit code. Verify the persisted marker before proceeding;
service expiration/reset can lose guest state. An additional live request can
launch an explicit interpreter that reads stdin to verify bytes and EOF.
The example calls the V1.Dev JSON SDK directly and performs no
allocation, release, credential acquisition or replay.

Always perform the explicit deprovision command above after this work, including
exec failure. Retain the ID after unknown/failed release and report work and
cleanup results separately. Do not reuse existing receipts/reservations for
this test; authorization for a new test must come from the caller.

## Offline functional fixtures

`src/mxc-sdk/tests/w365_lifecycle.rs` contains
`lifecycle_contract_and_recovery_fixture`, which
uses a controlled TLS service through the normal development parser,
experimental authorization, checked binding and backend dispatch.
This fixture runs on Windows, Linux and macOS.
It also exercises the public Rust V1.Dev checkout/release APIs and Provision
error messages. `.NET`'s `MxcLifecycleW365Tests` runs against its existing isolated
test-support native library in the SDK test suite.
The Node integration fixture `w365-fixture.ts` runs separately against an
isolated test-support library using
`scripts\ci\run-w365-node-fixture.ps1`, after building the Node SDK integration
tests. GitHub Actions and Azure SDK integration jobs require this fixture;
the normal packaged-artifact tests continue to use shipping libraries.
Both SDK fixtures check live/captured output and Exit arriving after the guest
timeout, unchanged service timeout values, and native deadline failure when
the peer never completes.

The engine's `transport_deadlines_fixture` holds TLS responses open, including
incomplete headers and bodies, to verify client deadline expiration, uncertain
failures, retained release IDs and no automatic retries. Short timeout overrides
are internal to `test-support` builds; production checkout and release budgets are
unchanged.

The Node fixture first makes an asynchronous call through another Koffi library
before importing MXC and checks that the SDK leaves Koffi's stack setting unchanged.
Lifecycle/readiness HTTPS calls and execution setup use a joined native thread
with a 2 MiB stack rather than depending on the caller's native stack size.
`lifecycle_fresh_executor_fixture` additionally launches independent native
executor processes for checkout and release with renewed synthetic credentials.
The latter is ignored by default because it requires a separately built
fixture executor; Windows CI explicitly requires and runs it.

Readiness and execution fixtures cover polling/errors/budget expiry, readiness
and execution setup from a small caller stack, pre-dial
validation, TLS trust and upgrade refusals, live return before Exit, native
pipe ownership and stdin EOF, simultaneous exact binary outputs over 12 MiB
per stream, slow-output overflow with bounded completion, final queued bytes,
full-duplex backpressure when the guest writes both outputs before reading
32 MiB of stdin, 0/nonzero/-1 exits, protocol/remote/transport failures, failed
capture, local deadline and blocked-I/O disposal while the peer does not read
stdin. `execution_fresh_executor_fixture` exercises
the actual executor's relay, byte output, prompts visible before stdin is sent,
output flush failures, and zero/nonzero exits while host stdin is still being
forwarded; ordinary executor diagnostics remain on stderr. Repeated execs
retain one ID without checkout/release.
The same fixture runs the actual execution example for early zero/nonzero exits,
host stdin read failures, binary capture and remote errors.
The native stream fixture also runs repeated relayed executions in one host
process with stdin held open, checking that later input reaches the second
command and that both retain the same reservation ID. Windows additionally
exercises the terminal-only attached API with Unicode input and Ctrl-Z EOF.
The upgrade fixture checks stalled DNS capacity, recovery without late service
calls, and a slowly fragmented TLS handshake. The failure fixture checks
omitted, zero and positive timeouts across a simulated 331-second elapsed boundary,
preserving output and genuine Exit values for executions without a local deadline.
It also keeps host stdout/stderr pipes open without reading them and checks
bounded failure after both Exit and remote Error, preserving the forwarded prefix.
Windows build jobs require discovery of all nine functional fixtures.
Linux/macOS jobs require eight fixtures, including the execution example's
unread host-output scenario and shared stdout/stderr pipe cleanup, without the
two Windows-only fresh-executor fixtures. They build the test-support example
in the same isolated target directory and exercise its pending host-input
teardown and host-read failures.
The scheduled/nightly workflow invokes those same build jobs, so these are
also scheduled native backend scenarios, not orphan test files.

From `src\` on Windows:

```powershell
# Requires openssl on PATH, or MXC_W365_TEST_OPENSSL set to its executable path.
cargo build --locked -p wxc --features test-support --target-dir target\w365-fixture
cargo build --locked -p mxc-sdk --example w365_execution --features test-support --target-dir target\w365-fixture
$env:MXC_W365_TEST_EXECUTOR = (Resolve-Path target\w365-fixture\debug\wxc-exec.exe).Path
cargo test --locked -p mxc-sdk --test w365_lifecycle --features test-support --target-dir target\w365-fixture -- --include-ignored
```

GitHub Actions and Azure Windows CI use a separate target directory so fixture
executors cannot replace shipping artifacts. Linux and macOS jobs run the
SDK/native-engine fixtures without building a test-support executor.
Azure runs fixtures only on native hosts: Windows/Linux x64 and macOS arm64; cross-compiled arm64
Windows/Linux jobs do not execute them.
The integration target requires `test-support`. Only builds with that feature
honor `MXC_W365_TEST_CA`, `MXC_W365_TEST_PORT`, `MXC_W365_TEST_TIMEOUT_MS`,
`MXC_W365_TEST_READY_BUDGET_MS`, `MXC_W365_TEST_DNS_DELAY_MS`
and `MXC_W365_TEST_EXEC_ELAPSED_MS`.
The fixtures supply a trusted certificate and short deadlines without disabling
certificate or hostname validation. Shipping builds ignore these variables.
Fixtures use only loopback services,
synthetic credentials and generated certificates; no live tenant is needed.
`rcgen` generates fixture certificates. The loopback server uses SChannel on
Windows and `native-tls` elsewhere; the production lifecycle, readiness and execution
client uses `native-tls` on all platforms. Windows and macOS fixtures require
the OpenSSL command-line tool to package generated EC keys as PKCS#12; their
native PEM identity importers do not support this key format. The archive uses
SHA-1/3DES for macOS import compatibility only, not for TLS connections or
production cryptography. The imported Windows test key is explicitly deleted
after the fixture server stops; `native-tls` owns a temporary macOS keychain
removed at process exit. Direct Exec fixtures use a rustls test server against
the production `native-tls` client. Windows CI selects the OpenSSL executable
included with Git for Windows using `MXC_W365_TEST_OPENSSL`, without changing
`PATH` or replacing other Windows tools. Otherwise fixtures find `openssl` on
`PATH`. These certificate
and key files exist only in a temporary directory, removed after identity
loading; no certificates or private keys are checked in.
