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
# Terminal 1: choose one token and start the diagnostic console
$env:MXC_DIAG_PIPE_TOKEN = [guid]::NewGuid().ToString("N")
$env:MXC_DIAG_PIPE_TOKEN
mxc-diagnostic-console.exe

# Terminal 2: use the same token, enable diagnostics, and run
$env:MXC_DIAG_CONSOLE = "1"
$env:MXC_DIAG_PIPE_TOKEN = "<the same token as Terminal 1>"
wxc-exec.exe --experimental my-config.json
```

## Configuration

| Method | Setting | Description |
|--------|---------|-------------|
| CLI flag | `--log-file <path>` | Write diagnostics and structured audit records to a file without starting the named-pipe console |
| Env var | `MXC_DIAG_CONSOLE=1` | Enable diagnostic pipe output and auto-inject `learningModeLogging` capability |
| Env var | `MXC_DIAG_PIPE_TOKEN=<random token>` | Select the per-session diagnostic pipe; use the same high-entropy token for the console and `wxc-exec` |

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

They are written **only** to the sinks described here — a `--log-file` path or
the `MXC_DIAG_CONSOLE` pipe — never to stdout, so they cannot pollute an SDK
caller's captured output. With neither sink configured, nothing is emitted and
no record is even built.

These are **local diagnostics, not ETW telemetry**: no provider, no consent gate,
nothing uploaded. See
[`docs/telemetry/telemetry.md` § Local audit log records](telemetry/telemetry.md#local-audit-log-records)
for the JSON-lines format, the full record inventory with fields, the content
rules (bounded vocabularies, config field *paths* but never values, no raw user
identifiers),
and a parsing recipe.

## Diagnostic Console

`mxc-diagnostic-console.exe` is a long-lived process that receives messages from
multiple `wxc-exec` instances over `\\.\pipe\mxc-diagnostics-{SID}` (where `{SID}` is
the current user's security identifier). This per-user pipe name ensures sessions from
different users do not collide. Output is color-coded
per PID, with special highlighting for `WARNING:`, `ERROR:`, and `SECTION:` messages.

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

- `FILE_FLAG_FIRST_PIPE_INSTANCE` prevents pipe squatting
- Client PIDs resolved server-side via `GetNamedPipeClientProcessId`
- Clients verify the pipe server runs at High integrity level before sending data
- Stale ETW sessions (`MXC-Diagnostics-ETW`) are auto-cleaned on startup

## Scope

The **prose** diagnostic logging described above currently covers the
**BaseContainer runner only**.

The **structured audit records** have a different (and also partial) scope: they
are emitted from the Windows ProcessContainer runners (BaseContainer and both
AppContainer tiers) and from `wxc-exec`'s config-rejection and state-aware
dispatch paths. `mxc.PolicyHash` is cross-platform (it is emitted by the shared
engine), but the lifecycle records are **not**: `lxc-exec` (LXC, Bubblewrap) and
`mxc-exec-mac` (Seatbelt) emit no `mxc.ProcessExited`, `mxc.SandboxTornDown`,
`mxc.ConfigRejected`, or `mxc.SandboxIdentity`. That is a known gap, not a
statement that those backends are uninteresting — the originating requirement was
Windows-only. Do not read a missing record on Linux or macOS as "the event did not
happen".
