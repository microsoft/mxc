# Windows Sandbox Backend

## Overview

The Windows Sandbox backend provides VM-level isolation using
[Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview).
The one-shot surface launches a fresh disposable VM for each invocation, runs
one command, and tears the VM down before returning. It does not use the
host-side daemon or reuse a warm VM.

Windows Sandbox is experimental and requires `--experimental`.

## Architecture

```text
wxc-exec.exe
  |
  `-- mxc_engine
        |
        `-- WindowsSandboxRunner (windows_sandbox_lifecycle)
              |-- validates policy and acquires the host VM slot
              |-- writes a per-launch nonce and generates the .wsb file
              |-- launches WindowsSandbox.exe and records ownership proof
              |-- waits for guest rendezvous
              |-- opens authenticated control/stdin/stdout/stderr channels
              |-- executes one command
              `-- tears down the owned VM
                    |
                    `-- wxc-windows-sandbox-guest.exe
                          |-- consumes the launch nonce
                          |-- publishes its TCP address
                          |-- authenticates and pairs channels by role
                          |-- locks down the guest firewall
                          `-- runs the command through cmd.exe /C
```

The `src/backends/windows_sandbox/daemon/` crate remains in the repository for
future state-aware lifecycle work, but the one-shot path does not start or
connect to it.

### Components

| Component | Location | Purpose |
|---|---|---|
| Execution engine | `src/core/mxc_engine/src/run.rs` | Selects the one-shot runner and reports ignored legacy settings |
| Lifecycle crate | `src/backends/windows_sandbox/lifecycle/` | Policy validation, VM launch, authenticated bridge, ownership, and teardown |
| Shared protocol | `src/backends/windows_sandbox/common/` | Nonce authentication and control-channel wire format |
| Guest agent | `src/backends/windows_sandbox/guest/` | Runs inside the VM and bridges the child process |

## Execution Flow

1. `mxc_engine` validates that Windows Sandbox is experimental-enabled.
2. The runner validates filesystem and network policy.
3. A per-session mutex reserves the host's single Windows Sandbox VM slot.
4. Stale one-shot markers and any provably-owned orphan are reconciled.
5. The runner creates a secured per-run directory, nonce, bootstrap script, and
   `.wsb` configuration.
6. `WindowsSandbox.exe` starts, and the runner records PID-plus-creation-time
   ownership proof for its host processes.
7. The guest publishes its address and accepts four authenticated channels:
   control, stdin, stdout, and stderr.
8. The guest executes `process.commandLine` through `cmd.exe /C`.
9. Output and the exit status are returned, then ownership-scoped teardown
   terminates the VM and confirms it has exited.

Every invocation follows this complete lifecycle; there is no one-shot
multi-exec or warm-VM reuse.

## Configuration

```json
{
  "version": "0.6.0-alpha",
  "containment": "windows_sandbox",
  "process": {
    "commandLine": "powershell -NoProfile -Command \"Write-Output 'hello'\"",
    "timeout": 60000
  }
}
```

The legacy `experimental.windows_sandbox.idleTimeoutMs` and
`daemonPipeName` fields are still accepted for schema compatibility but are
ignored by the one-shot backend. A warning is emitted only when either field
is explicitly changed from its default.

## Policy Support

| Policy | Behaviour |
|---|---|
| `filesystem.readwritePaths` | Existing host directories are mapped read-write at the same path inside the guest |
| `filesystem.readonlyPaths` | Existing host directories are mapped read-only at the same path inside the guest |
| `filesystem.deniedPaths` | Accepted when outside mapped shares; rejected when equal to, inside, or containing a mapped share |
| Default network policy `block` | Supported through guest firewall lockdown |
| Default network policy `allow` | Rejected |
| `allowedHosts` / `blockedHosts` | Rejected; per-host filtering is not supported |
| Network proxy | Rejected |

Mapped paths must be absolute existing directories. Files, overlapping mapped
roots, and a path listed as both read-only and read-write are rejected.

## Security Model

- **VM boundary:** workload code runs in a separate Windows instance.
- **Authenticated channels:** every TCP connection presents a random
  per-launch 32-byte nonce and a channel-role byte before protocol traffic.
- **Role-based pairing:** the guest pairs sockets by declared role rather than
  TCP accept order.
- **Network isolation:** the guest permits only the established host
  connection and blocks other inbound and outbound traffic.
- **Secured host state:** nonce, rendezvous, and ownership-marker directories
  use owner-only ACLs and reject roots owned by another user.
- **Ownership-scoped teardown:** PID-plus-creation-time proof prevents PID reuse
  or an unrelated Windows Sandbox instance from being treated as owned.
- **Ephemeral execution:** the VM and per-run marker are removed only after
  teardown confirms the owned VM has exited.

Same-user processes are within the backend's trust boundary.

## Prerequisites

| Requirement | Check |
|---|---|
| Windows 11 Pro, Enterprise, or another edition supporting Windows Sandbox | `winver` |
| Windows Sandbox optional feature enabled | `Test-Path "$env:WINDIR\System32\WindowsSandbox.exe"` |
| Hardware virtualisation and Hyper-V support | `systeminfo` |

Enabling the optional feature requires a reboot. No host Python installation is
required; workloads can use runtimes already present in the Windows Sandbox
image or directories explicitly mapped by policy.

## Known Limitations

1. Every invocation pays the Windows Sandbox cold-boot cost.
2. The host supports only one active Windows Sandbox VM per logon session.
3. One-shot stdin is buffered and capped at 64 MiB.
4. Filesystem sharing supports directories only.
5. Network policy is block-only; allow-lists, block-lists, proxies, and
   unrestricted outbound access are unsupported.
6. Output is captured and returned after execution rather than streamed live to
   the caller.

## Testing

The end-to-end suite requires a Windows host with the Windows Sandbox feature:

```powershell
.\tests\scripts\run_windows_sandbox_one_shot_tests.ps1
```

## Further Reading

See [windows-sandbox-reference.md](windows-sandbox-reference.md) for protocol,
VM setup, teardown, debugging, and source-level details.
