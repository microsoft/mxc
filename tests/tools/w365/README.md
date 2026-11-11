# W365 manual test applications

Two independent Windows test tools exercise the same experimental backend:
`W365SdkTestApp` calls the public .NET Dev SDK directly and owns MSAL.NET
authentication; `tests\scripts\run_w365_command_manual.ps1` authenticates with
the existing Python helper and invokes normal `wxc-exec.exe` processes.
Neither C# nor PowerShell implements the service protocol.

## Build and configure

Use the repository-pinned Rust toolchain, .NET SDK 10 and Windows build tools.
From the repository root:

```powershell
dotnet publish tests\tools\w365\W365SdkTestApp\W365SdkTestApp.csproj `
    -c Release -r win-x64 --self-contained true
```

Hand off the **whole publish directory**, including the matching managed SDK,
`mxc_ffi.dll`, runtime and authentication dependencies. Use normal artifacts,
never a `test-support` build. Do not mix managed/native revisions. Packaging is
manual; the repository does not produce a new installer or release package.

Copy `w365-test.example.json` to `w365-test.json` beside the published executable,
and replace all five synthetic values with approved deployment values.
Alternatively pass `--config <path>`. The same JSON is accepted by the
PowerShell runner's `-ConfigPath`; its default is beside that script instead.
Configuration contains only `tenantId`, `clientId`, `poolId`,
`controlPlaneHost` and `dataPlaneSuffix`. Never add credentials.
Endpoints are bare ASCII hostnames, not URLs. No tenant, account, pool or region
is inferred. The approved public client must support system-browser auth and a
localhost redirect.

## Run, reuse and release

Each invocation below is a **live operation** and requires separate service
authorization. The examples are not part of offline validation.

```powershell
# Allocate once, wait for Ready, execute, retain the machine.
.\W365SdkTestApp.exe run --command 'cmd.exe /c echo first' --receipt-path .\session.json

# Copy the returned full sessionId unchanged, not a bare computer GUID.
$id = 'w365:<pool-guid>:<session-guid>'
.\W365SdkTestApp.exe run --session-id $id --command 'cmd.exe /c echo second' --receipt-path .\session.json

# Explicit terminal release, with no command and no data-plane requirement.
.\W365SdkTestApp.exe release --session-id $id --receipt-path .\session.json
```

Run without an ID submits exactly one checkout. Run with an ID performs no
checkout, even if readiness or execution fails. Commands are full Windows
executable command lines with no implicit shell. Optional controls:
`--working-directory <guest-path>`, `--timeout-ms <integer>` (default 30000;
0 uses the service default), `--login-hint`, `--expected-user-object-id <guid>`,
and `--force-sign-in`.

Stdout is one JSON document containing `sessionId`, `sandboxId`, `receiptPath`
and the SDK result, or a sanitized error. IDs are the actual opaque MXC identity,
not authentication sessions or inferred cloud computer IDs. Captured stdout,
stderr, exit code, timeout flag, warnings and output metadata are retained.
Progress and browser prompts use stderr. Guest nonzero exits remain nonzero.
Known IDs survive later failures. Nothing automatically releases the machine.
Release acceptance is **not confirmed remote reset or sanitization**.

Receipts are token-free, exclusively locked and atomically replaced. Keep the
same receipt with the ID: it binds deployment and authenticated owner, blocks a
second checkout and rejects terminal or uncertain reuse. A failed/submitted
release must be reconciled before retrying it. Without a receipt, an explicit
ID still permits reuse or release, but the app cannot discover earlier
uncertainty, another caller's operations or terminal state. Do not discard a
receipt to evade those guards. The app does not search for active reservations.
Failure receipts retain the SDK's sanitized error code, request IDs and known
session ID when available, so an operator can reconcile an uncertain outcome.

For unknown allocation without an ID, stop and ask the authorized service
operator to reconcile; never blindly rerun without an ID. For execution failure,
assume remote outcome may be unknown and do not replay automatically.
PTY, create-and-run execution and confirmed remote kill are not supported.

## Authentication

The C# app requests the fixed ARI INT scope
`274133f7-12bb-4bfb-ae3b-bd446b7e8a75/.default`. This is not universal
production/sovereign-cloud auth. MSAL.NET silently acquires/refreshes a token for
a unique cached account, otherwise uses the system browser with normal MFA
and consent. Multiple matching cached accounts require a unique login hint.
Tenant, client, audience, delegated Computer scopes, owner and minimum lifetime
are sanity-checked before service calls. The service authenticates tokens;
decoding claims does not validate their signature.

The C# cache is separate from the Python helper's cache:

```text
%LOCALAPPDATA%\Microsoft\MXC\w365-sdk-test-auth\<tenant-guid>_<client-guid>.bin
```

MSAL Extensions encrypts it with current-user Windows DPAPI. Cross-process locks
protect account selection and persistence. Cache/lock/encryption failures are
explicit; there is no plaintext fallback. Close all callers before intentionally
removing the exact cache file or a confirmed-stale lock. Do not upload caches.
Tokens never enter arguments, config, receipts or guest environment; the app
temporarily supplies private process-local SDK environment values and restores
previous values. Native SDK code does not retain or refresh tokens.

## Offline validation

`--dry-run` performs SDK validation with synthetic credentials and never accesses
the real cache, opens a browser or contacts the service:

```powershell
.\W365SdkTestApp.exe run --config .\w365-test.example.json --command 'cmd.exe /c echo fixture' --dry-run
```

From the repository root, `tests\scripts\run_w365_sdk_fixtures.ps1` builds isolated
test-support libraries and drives real public SDK calls against loopback TLS.
It also tests the app's run/reuse/release path in fresh processes with injected
synthetic authentication, preservation of cleanup IDs and request IDs on failed
checkout, plus isolated CLI/token/journal regressions.
There is no production auth-bypass or fixture option. Windows x64 regular and
scheduled build jobs run these checks and the native-runner/auth offline suites.
No live native/SDK Exec or actual browser/cache workflow is established by these
fixtures. See the [backend guide](../../../docs/backends/w365agents/w365agents-backend.md)
for protocol, policy, environment and service-validation boundaries.
