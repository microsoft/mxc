# Windows Sandbox Backend

## Overview

The Windows Sandbox backend provides VM-level isolation for script execution using [Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview). Unlike the process container backend (which runs scripts in a sandboxed process on the host), the Sandbox backend boots an ephemeral Windows VM, executes scripts inside it, and tears it down when idle.

This provides stronger isolation than process containers — the script runs in a completely separate OS instance with its own filesystem, registry, and network stack.

## Architecture

```
wxc-exec.exe (CLI client)
  │
  └── WindowsSandboxScriptRunner (src/backends/windows_sandbox/common/src/windows_sandbox_runner.rs)
        │
        ├── Pre-flight: checks Windows Sandbox feature is enabled
        ├── Connects to wxc-windows-sandbox-daemon via TCP IPC on localhost
        │
        └── Sends: "EXEC {json}\n"
              │
              wxc-windows-sandbox-daemon.exe (host-side, long-lived)
                │
                ├── Discovers Python on the host
                ├── Generates .wsb config with mapped folders
                ├── Launches WindowsSandbox.exe
                ├── Polls rendezvous file for guest agent address
                ├── Connects 4 TCP channels to guest agent
                │
                └── Bridges EXEC requests to the guest
                      │
                      wxc-windows-sandbox-guest.exe (inside sandbox VM)
                        │
                        ├── Binds TCP, writes IP:port to rendezvous file
                        ├── Accepts 4 connections (control, stdin, stdout, stderr)
                        ├── Locks down firewall (only allow host IP)
                        ├── Executes scripts via cmd.exe /C
                        └── Bridges stdin/stdout/stderr over TCP
```

### Components

| Binary | Crate | Runs where | Purpose |
|--------|-------|------------|---------|
| `wxc-exec.exe` | `wxc` | Host | CLI entry point, dispatches to WindowsSandboxScriptRunner |
| `wxc-windows-sandbox-daemon.exe` | `wxc_windows_sandbox_daemon` | Host | Manages sandbox VM lifecycle, bridges IPC to TCP |
| `wxc-windows-sandbox-guest.exe` | `wxc_windows_sandbox_guest` | Inside sandbox VM | Accepts commands, runs scripts, bridges stdio |

## Execution Flow

### Single Execution

1. `wxc-exec` verifies Windows Sandbox is enabled, connects to daemon IPC, sends `EXEC {json}\n`
2. Daemon calls `ensure_sandbox_ready()` — launches sandbox if needed (with up to 3 retries)
3. Daemon sends `Exec` on the control channel to the agent
4. Agent spawns `cmd.exe /C <script>`, bridges stdio over TCP
5. Agent sends `Exit` with exit code on control channel
6. Daemon reads stdout/stderr, returns `RESULT <code> <stdout-b64> <stderr-b64> <error>\n`

### Multi-Execution (Same Sandbox)

After the first execution, the agent re-accepts fresh data streams via the `StreamsReady` protocol:

1. Agent sends `Exit`, then `StreamsReady` on control channel
2. Daemon receives `StreamsReady`, connects 3 new TCP streams to the agent
3. Next `EXEC` request reuses the existing sandbox VM

This avoids the 30-60s boot cost for subsequent executions.

## Configuration

```json
{
  "version": "0.6.0-alpha",
  "containment": "windows_sandbox",
  "process": {
    "commandLine": "python -S -B -c \"print('hello')\"",
    "timeout": 60000
  },
  "experimental": {
    "windows_sandbox": {
      "idleTimeoutMs": 300000,
      "daemonPipeName": "wxc-windows-sandbox"
    }
  }
}
```

> **Note:** Windows Sandbox is experimental — requires the `--experimental` CLI flag.
> The `experimental.windows_sandbox` section is optional; defaults are used if omitted.

| Field | Default | Description |
|-------|---------|-------------|
| `containment` | `"processcontainer"` | Must be `"windows_sandbox"` to use this backend |
| `process.commandLine` | *(required)* | Command line to execute inside the sandbox |
| `process.timeout` | `0` (none) | Script execution timeout in milliseconds |
| `experimental.windows_sandbox.idleTimeoutMs` | `300000` (5 min) | Daemon idle timeout before VM teardown |
| `experimental.windows_sandbox.daemonPipeName` | `"wxc-windows-sandbox"` | IPC identifier (determines TCP port) |

When `containment` is `"windows_sandbox"`, the `processContainer`, `filesystem`, and `network` sections are ignored — isolation is managed by the sandbox VM and guest agent firewall.

## Security Model

- **VM isolation**: Scripts run inside a separate Windows instance — full OS boundary
- **Firewall lockdown**: After the agent accepts host connections, it blocks all other network traffic via `netsh advfirewall` rules
- **Read-only mounts**: Agent binaries and Python are mounted read-only — scripts cannot modify them
- **Ephemeral**: The sandbox VM is destroyed on teardown — no state persists between sessions
- **Multi-exec constraint**: VM reuse assumes all scripts come from the same trust domain

## Prerequisites

| Requirement | How to verify |
|---|---|
| Windows 11 Pro/Enterprise | `winver` |
| Windows Sandbox feature enabled | `dism /online /get-featureinfo /featurename:Containers-DisposableClientVM` |
| Hyper-V / Virtualization enabled | `systeminfo` → "A hypervisor has been detected" |
| Python 3.x on host (for Python scripts) | `python --version` |

After enabling Windows Sandbox: **reboot required**.

## Known Limitations

1. **IPC uses TCP, not named pipes** — port conflicts possible if another process occupies the derived port
2. **Single language mapped** — only Python is mapped from host; Node.js would need similar treatment. PowerShell and cmd.exe work out of the box.
3. **Windows Insider regression** — builds 26100+ have confirmed sandbox boot failures (zombie VM processes)
4. **Cold boot time** — first sandbox boot takes 15-60s; subsequent executions reuse the VM
5. **Buffered output** — stdout/stderr are captured and returned after completion, not streamed live
6. **No filesystem/network policy forwarding** — the `filesystem` and `network` config sections are ignored; isolation relies on the VM boundary and agent firewall

## Further Reading

See [windows-sandbox-reference.md](windows-sandbox-reference.md) for detailed protocol specs, VM setup internals, debugging guide, source file reference, and E2E test documentation.
