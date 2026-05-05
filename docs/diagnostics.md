# MXC Diagnostics

A unified diagnostic view across every layer of the MXC stack:

| Layer | Source | What you see |
|-------|--------|--------------|
| **SDK** | `mxc-sdk` (TypeScript) | SDK version, policy construction |
| **Runtime** | `wxc-exec.exe` (Rust) | Input config, parsed request, sandbox spec, process lifecycle, timing |
| **OS** | Tessera ETW provider | Kernel-side sandbox creation and validation events |
| **Internals** | Kernel-General ETW (learning mode) | Access checks that would have been denied, logged instead of blocked |

All layers stream into a single `mxc-diagnostic-console.exe` window in real time.

## Quick Start

```powershell
# Terminal 1: start the diagnostic console (run as admin for ETW)
mxc-diagnostic-console.exe

# Terminal 2: enable diagnostics and run
$env:MXC_DIAG_CONSOLE = "1"
wxc-exec.exe --experimental my-config.json
```

Or enable persistently via registry (admin required):

```powershell
New-Item -Path "HKLM:\SOFTWARE\Microsoft\MXC\Diagnostics" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MXC\Diagnostics" -Name "ConsoleEnabled" -Value 1 -Type DWord
```

## Configuration

| Method | Setting | Description |
|--------|---------|-------------|
| Registry | `HKLM\...\MXC\Diagnostics\ConsoleEnabled` = 1 | Machine-wide, persistent |
| Env var | `MXC_DIAG_CONSOLE=1` | Per-session, no admin needed (takes precedence) |

## What Gets Logged

- Input JSON config and parsed `CodexRequest` (env values redacted, script truncated)
- Sandbox spec details (size, UI flags, capabilities, filesystem/network policy)
- Process lifecycle (command line, identity, child PID, exit code, elapsed time)
- Section markers for key execution stages

## Diagnostic Console

`mxc-diagnostic-console.exe` is a long-lived process that receives messages from
multiple `wxc-exec` instances over `\\.\pipe\mxc-diagnostics-{SID}` (where `{SID}` is
the current user's security identifier). This per-user pipe name ensures sessions from
different users do not collide. Output is color-coded
per PID, with special highlighting for `WARNING:`, `ERROR:`, and `SECTION:` messages.

### Display Modes

- `--minified` (default) — reduced ETW event properties
- `--verbose` — all ETW event properties

### ETW Tracing

The console captures ETW events from the Tessera provider and Kernel-General
learning-mode access check events. **Admin privileges required** for ETW; pipe
messages work without elevation.

### Security

- `FILE_FLAG_FIRST_PIPE_INSTANCE` prevents pipe squatting
- Client PIDs resolved server-side via `GetNamedPipeClientProcessId`
- Clients verify the pipe server runs at High integrity level before sending data
- Stale ETW sessions (`MXC-Diagnostics-ETW`) are auto-cleaned on startup

## Scope

Diagnostic logging currently covers the **BaseContainer runner only**.
