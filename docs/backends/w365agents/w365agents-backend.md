# Windows 365 for Agents: checkout and release

> **Audience:** MXC consumers and developers

This experimental backend implements **Phase 2 only**: checkout through
`provision`, and terminal release through `stop` or `deprovision`. It is
included in normal Windows, Linux and macOS builds. Phase 2 exposes checkout
and release through the Windows executor's existing lifecycle interface,
with `--experimental` authorization. The Linux and macOS executors do not
expose lifecycle operations; adding that CLI support is outside this slice.
Local probes do not report W365
availability and never authenticate, discover a pool or check out a Cloud PC.

Start/readiness, captured or streaming exec, PTY, create-and-run execution
and placement sessions are unavailable. They fail explicitly without service
work. Typed W365 SDK authoring APIs do not exist. Rust, .NET and Node Dev SDK
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

Missing, invalid or non-Unicode values fail locally. Each call reads the
environment again. MXC does not acquire, cache or renew tokens. The caller
renews credentials before a later cleanup call. Checkout uses the design's
45-second client budget; release uses its separate 30-second budget. These
are transport budgets, not promises about service reset or resource lifetime.
Production uses validated rustls TLS, no redirects and no ambient HTTP proxy.

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

The implementation follows the approved design/reference API 2.0 header
contract. The supplied North Europe INT service evidence used API **3.0**,
a JSON body with `sessionKind: "local"` and `userObjectId`, and readiness
polling via POST with `x-ms-sessionId`. That is a different service contract:
it does not validate API 2.0 checkout for any accepted user type, omitted
identity or release. Explicit `userType: "Local"` sends the API 2.0
`user-type: Local` header, not an API 3.0 `sessionKind` body.
No API-version compatibility layer or `Local` substitution is implemented.
Actual checkout/release compatibility for each user type remains to be confirmed
with the service owner and an explicitly authorized live run.

## Optional live validation: explicit invocation only

**Live Phase 2 validation has not been run.** Do not use another caller's
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
      "userType": "HumanUser",
      "userObjectId": "22222222-2222-2222-2222-222222222222"
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
Do not call start or exec in this slice.
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

## Offline functional fixtures

`backend_modules::w365agents::tests::lifecycle_contract_and_recovery_fixture`
uses a controlled TLS service through the normal development parser,
experimental authorization, checked binding and backend dispatch.
This fixture runs on Windows, Linux and macOS.
On Windows, `lifecycle_fresh_executor_fixture` additionally launches independent
`wxc-exec` processes for checkout and release with renewed synthetic credentials.
The latter is ignored by default because it requires a separately built
fixture executor; Windows CI explicitly requires and runs it.

From `src\` on Windows:

```powershell
cargo build --locked -p wxc --features test-support
$env:MXC_W365_TEST_EXECUTOR = (Resolve-Path target\debug\wxc-exec.exe).Path
cargo test --locked -p mxc-sdk --lib w365 -- --include-ignored
```

GitHub Actions and Azure Windows CI use a separate target directory so fixture
executors cannot replace shipping artifacts. Both CI systems run the engine
fixture on Linux and macOS without a fixture executor. Azure runs fixtures
only on native hosts: Windows/Linux x64 and macOS arm64; cross-compiled arm64
Windows/Linux jobs do not execute them.
Only test builds honor `MXC_W365_TEST_CA` and `MXC_W365_TEST_PORT`; they add a
trusted fixture certificate, never disable certificate or hostname validation.
Shipping builds ignore these variables. Fixtures use only loopback services,
synthetic credentials and generated certificates; no live tenant is needed.
