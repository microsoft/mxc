# MXC Diagnostics

A unified diagnostic view across every layer of the MXC stack:

| Layer | Source | What you see |
|-------|--------|--------------|
| **SDK** | `mxc-sdk` (TypeScript) | SDK version, policy construction |
| **Runtime** | `wxc-exec.exe` (Rust) | Input config, parsed request, sandbox spec, process lifecycle, timing |
| **OS** | MXC OS-side ETW provider | Kernel-side sandbox creation and validation events |
| **Internals** | Kernel-General ETW (learning mode) | Access checks that would have been denied, logged instead of blocked |

All layers stream into a single `mxc-diagnostic-console.exe` window in real time.

## Quick Start

```powershell
# Terminal 1: generate one token and start the diagnostic console
$env:MXC_DIAG_PIPE_TOKEN = [guid]::NewGuid().ToString("N")
$env:MXC_DIAG_PIPE_TOKEN
mxc-diagnostic-console.exe

# Terminal 2: use the same token, enable diagnostics, and run
$env:MXC_DIAG_CONSOLE = "1"
$env:MXC_DIAG_PIPE_TOKEN = "<the same token as Terminal 1>"
wxc-exec.exe --experimental my-config.json
```

The token is intentionally generated and supplied by the caller rather than
created implicitly by the console. Both processes must receive the same value
before they start so they select the same pipe and establish the intended
local diagnostic session.

## Configuration

| Method | Setting | Description |
|--------|---------|-------------|
| CLI flag | `--log-file <path>` | Write diagnostics and structured audit records to a file. Independent of the console — needs no pipe and no token. |
| Env var | `MXC_DIAG_CONSOLE=1` | Enable diagnostic pipe output and auto-inject `learningModeLogging` capability |
| Env var | `MXC_DIAG_PIPE_TOKEN=<token>` | **Required** for pipe output. Selects the per-session pipe and authenticates it; use the same token for the console and `wxc-exec` |

### The pipe token

`MXC_DIAG_PIPE_TOKEN` is mandatory for pipe-based diagnostics — it is what stops
an unrelated local process from standing up a pipe of a predictable name and
collecting another user's diagnostic stream. It must satisfy **all** of:

- at least **32 characters**,
- only ASCII hex digits (`0-9`, `a-f`, `A-F`) and `-`,
- at least **4 distinct** non-`-` characters.

`[guid]::NewGuid().ToString("N")` produces exactly 32 hex characters and is the
recommended generator.

A token that fails any of these rules is treated as **no token at all**, not as
an error — so a typo'd or too-short token produces the same outcome as omitting
it:

- `mxc-diagnostic-console.exe` prints an error and **exits with code 1**.
- `wxc-exec.exe` prints `[MXC Diagnostics] Refusing an unauthenticated
  diagnostic pipe` to stderr and continues running **without** pipe output. The
  sandboxed workload still runs normally; only the diagnostics are lost.

If the console starts but never shows any events, an unset or malformed token on
the `wxc-exec` side is the first thing to check — the two processes must agree on
the token exactly, because it is part of the pipe *name*.

## What Gets Logged

- Input JSON config and parsed `ExecutionRequest` (env values redacted, script truncated)
- Sandbox spec details (size, UI flags, capabilities, filesystem/network policy)
- Process lifecycle (command line, identity, child PID, exit code, elapsed time)
- Section markers for key execution stages
- **Structured audit records** — one JSON object per line, prefixed `{"event":"mxc.`

### Structured audit records

Alongside the human-readable prose above, both sinks carry machine-readable
audit records: process exit / timeout / kill outcome, enforcement-tier
degradation, policy hash, network policy applied, sandbox teardown, config
rejection, and the sandbox identity join key.

Records are joined by `identity` once a sandbox exists. A config rejection is
refused *before* an identity is assigned, so `mxc.ConfigRejected` instead carries
a `correlation_id` — an opaque hex token minted once per `wxc-exec` invocation
and stable for that invocation, which groups several rejection records from the
same run. A successful launch emits no rejection records at all.

They are written **only** to the sinks described here — a `--log-file` path or
the `MXC_DIAG_CONSOLE` pipe — never to stdout, so they cannot pollute an SDK
caller's captured output. With neither sink configured, these JSON records are not emitted and no record
is built. When Windows ETW telemetry is explicitly enabled, the separate
`Microsoft.MXC` TraceLogging provider may still receive the bounded M-ETW
events described in [`docs/telemetry/telemetry.md`](telemetry/telemetry.md);
those events are local ETW only and are not uploaded by MXC.

These are **local diagnostics, not ETW telemetry**: no provider, no consent gate,
nothing uploaded. See
[`docs/telemetry/telemetry.md` § Local audit log records](telemetry/telemetry.md#local-audit-log-records)
for the JSON-lines format, the full record inventory with fields, the content
rules (bounded vocabularies, config field *paths* but never values, no raw user
identifiers),
and a parsing recipe.

## Diagnostic Console

`mxc-diagnostic-console.exe` is a long-lived process **you start yourself** — MXC
never spawns it. It receives messages from multiple `wxc-exec` instances over

```
\\.\pipe\mxc-diagnostics-{SID}-{TOKEN}
```

where `{SID}` is the current user's security identifier and `{TOKEN}` is
`MXC_DIAG_PIPE_TOKEN`. The SID keeps different users' sessions from colliding;
the token both separates concurrent sessions for the *same* user and
authenticates the pipe. (If the SID cannot be resolved, the name degrades to
`\\.\pipe\mxc-diagnostics-{TOKEN}`.) Because the token is part of the name, the
console and `wxc-exec` must use identical values or they will simply never meet.

Output is color-coded per PID, with special highlighting for `WARNING:`,
`ERROR:`, and `SECTION:` messages.

### Display Modes

- `--minified` (default) -- reduced ETW event properties
- `--verbose` -- all ETW event properties

### Log Collection

Use `--collect` to capture diagnostic logs to files:

```powershell
mxc-diagnostic-console.exe --collect
```

This creates a timestamped folder in `%TEMP%` (e.g. `mxc-diagnostics-20260513-211500-12345\`)
containing:
- `verbose.log` -- all ETW event properties (full detail)
- `minified.log` -- reduced ETW event properties

The console continues to display events normally while collecting. Press **Ctrl+C** to
stop collection, at which point the tool:
1. Flushes both log files
2. Zips the folder via PowerShell `Compress-Archive`
3. Prints the paths to the log folder and archive

A second Ctrl+C during finalization forces an immediate exit.

Combine with `--verbose` to see full output on the console while collecting both formats:
```powershell
mxc-diagnostic-console.exe --collect --verbose
```

Alternatively, you can capture the console output directly with `Tee-Object`:
```powershell
mxc-diagnostic-console.exe | Tee-Object -Encoding ascii -FilePath out.log
```

### ETW Tracing

The console captures ETW events from the MXC OS-side provider and Kernel-General
learning-mode access check events. **Admin privileges required** for ETW; pipe
messages work without elevation.

### Security

- `MXC_DIAG_PIPE_TOKEN` is the primary access control: it is mixed into the pipe
  name, so a process that does not know the token cannot guess the endpoint.
  `wxc-exec` refuses to connect at all when no valid token is set
- `FILE_FLAG_FIRST_PIPE_INSTANCE` prevents pipe squatting
- Client PIDs resolved server-side via `GetNamedPipeClientProcessId`
- Clients verify the pipe server runs at High integrity level or above before
  sending data
- Stale ETW sessions (`MXC-Diagnostics-ETW`) are auto-cleaned on startup

Diagnostic output is redacted before it leaves the process — environment
variable values are replaced with `<redacted>`, `script_code` is truncated, and
known secret-bearing config fields are stripped. The structured audit records
carry config field *paths* but never config *values*. Treat the stream as
sensitive regardless: it still reveals paths, capabilities, and policy shape.
