# Windows 365 for Agents: native lifecycle and execution

> **Audience:** MXC consumers and developers

This experimental backend implements checkout through `provision`, bounded
readiness polling through `start`, native pipe-backed or executor-relayed
`exec`, and terminal release through `stop` or `deprovision`. It is
included in normal Windows, Linux and macOS builds. Every operation requires
executor `--experimental` authorization. Local probes do not report W365
availability and never authenticate, discover a pool or check out a Cloud PC.
The Unix executors forward the same explicit lifecycle routing controls to the
engine; their existing create-and-run paths and platform checks are unchanged.

PTY, create-and-run execution and placement sessions remain unavailable.
They fail explicitly without service work. Typed W365 SDK authoring APIs do not
exist. Rust, .NET and Node Dev SDK
JSON lifecycle access is also deliberately unavailable until cross-SDK
structured error metadata and public SDK validation are complete.
Native executor responses retain structured errors and cleanup identities.

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
Production uses validated rustls TLS, no redirects and no ambient HTTP proxy.

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
`possiblySucceeded: true`. No ID is fabricated for an absent or invalid
session ID. Unparseable, dropped and ambiguous checkout replies report
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
cargo build --locked -p wxc --features test-support
$env:MXC_W365_TEST_EXECUTOR = (Resolve-Path target\debug\wxc-exec.exe).Path
cargo test --locked -p mxc-sdk --lib w365 -- --include-ignored
```

CI uses a separate target directory so fixture executors cannot replace
shipping artifacts. Linux builds `lxc` and macOS builds `mxc_darwin` with
`mxc-sdk/test-support`, then supplies the corresponding executable.
Only test builds honor `MXC_W365_TEST_CA` and `MXC_W365_TEST_PORT`; they add a
trusted fixture certificate, never disable certificate or hostname validation.
Shipping builds ignore these variables. Fixtures use only loopback services,
synthetic credentials and generated certificates; no live tenant is needed.
