# Windows Sandbox Backend

> **Audience:** MXC consumers and developers

## Overview

The Windows Sandbox backend provides VM-level isolation using
[Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview).
It is experimental and requires `--experimental`.

The backend has two execution modes:

- **Create-and-run execution:** each invocation launches a fresh disposable VM, runs one
  command, and tears the VM down before returning. Teardown is best-effort, not
  kernel-guaranteed — a launcher hard-kill can leave a wedged orphan; see the
  reference doc's "Hard-kill orphans and `--force-reclaim`" section.
- **Container lifecycle operations:** `provision`, `start`, repeated `exec`, `stop`, and
  `deprovision` calls share one VM through a detached host daemon.

## Architecture

```text
wxc-exec.exe
  |
  `-- mxc_engine
        |
        `-- windows_sandbox_lifecycle::WindowsSandboxRunner
              |-- create-and-run ScriptRunner
              `-- lifecycle StatefulSandboxBackend
                    |
                    `-- wxc-windows-sandbox-daemon.exe
                          (owns the VM between phase processes)

WindowsSandbox.exe
  |
  `-- wxc-windows-sandbox-guest.exe
        |-- consumes the launch nonce
        |-- publishes its TCP address
        |-- authenticates and pairs channels by role
        |-- locks down the guest firewall
        `-- runs commands through cmd.exe /C
```

### Components

| Component | Location | Purpose |
|---|---|---|
| Execution engine module | `src/mxc-sdk/src/core/mxc_engine/` | Selects backends for create-and-run execution and container lifecycle operations |
| Lifecycle module | `src/mxc-sdk/src/backends/windows_sandbox/lifecycle/` | Policy, launch, bridge, records, ownership, and teardown |
| Host daemon | `src/mxc-sdk/src/bin/windows_sandbox_daemon/` | Owns the VM and guest connection between lifecycle calls |
| Shared protocol module | `src/mxc-sdk/src/backends/windows_sandbox/common/` | Nonce authentication and control framing |
| Guest agent | `src/mxc-sdk/src/bin/windows_sandbox_guest/` | Runs commands and bridges stdio inside the VM |

## Create-and-Run Execution

1. Validate policy and reject an existing Tokio runtime before side effects.
2. Acquire the per-session mutex for the host's single Windows Sandbox VM.
3. Reconcile any stale create-and-run marker and provably-owned orphan.
4. Create secured per-run state, a launch nonce, bootstrap script, and `.wsb`
   configuration.
5. Launch `WindowsSandbox.exe` and record PID-plus-creation-time ownership proof.
6. Wait for guest rendezvous and open authenticated control, stdin, stdout, and
   stderr channels.
7. Execute one command and capture the exit status and output.
8. Tear down the owned VM and remove the marker after confirmed exit.

Every invocation follows the complete lifecycle; create-and-run execution never
reuses a warm VM.

## Container Lifecycle Operations

The lifecycle API keeps the VM alive across separate `wxc-exec
--operation` processes. ["MXC request JSON"](../../schema.md#mxc-request-json) carries `phase` and, after
provision, `sandboxId` in JSON. Direct executor calls omit those routing fields
from JSON and pass them as `--operation` and `--container-id`. The backend is
inferred from the `wsb:` sandbox ID after provision.

| Phase | Behaviour |
|---|---|
| `provision` | Creates a `wsb:<8-hex>` ID and stores immutable filesystem policy; no VM is launched |
| `start` | Spawns the detached daemon, launches the VM, and waits until the guest is ready |
| `exec` | Runs one command through the existing guest connection; only one exec is admitted at a time |
| `stop` | Requests daemon teardown and waits for the VM and daemon to exit |
| `deprovision` | Stops if necessary and removes the sandbox records |

The daemon persists its PID, creation time, authentication nonce, active
sandbox ID, readiness, and VM ownership proof under
`%TEMP%\wxc-wsb\state-aware`. It receives its authentication nonce over stdin,
not the command line.

The host supports only one Windows Sandbox VM per logon session. Create-and-run and
lifecycle VM owners share the same host-slot mutex. Orphan reclaim requires
recorded PID-plus-creation-time proof intersecting the live process set;
unproven VMs are treated as foreign and left untouched.

There is no idle watchdog. A container started through lifecycle operations remains active until
`stop` or `deprovision`.

## Configuration

### Create-and-run execution

```json
{
  "version": "1.1.0-alpha",
  "containment": "windows_sandbox",
  "process": {
    "commandLine": "powershell -NoProfile -Command \"Write-Output 'hello'\"",
    "timeout": 60000
  }
}
```

### Provision

The provision "MXC request JSON" is:

```json
{
  "version": "1.1.0-alpha",
  "phase": "provision",
  "containment": "windows_sandbox",
  "filesystem": {
    "readwritePaths": ["C:\\workspace"],
    "readonlyPaths": ["C:\\inputs"]
  }
}
```

For a direct executor call, remove `phase` from that JSON and invoke:

```text
wxc-exec.exe config.json --operation provision
```

Subsequent lifecycle calls carry the returned `sandboxId` in "MXC request JSON". Direct
executor calls remove `phase` and `sandboxId` from JSON and pass
`--operation <phase> --container-id <id>`.

The legacy `windowsSandbox.idleTimeoutMs`, `idleTimeout`, and
`daemonPipeName` fields remain parseable for schema compatibility but do not
affect either execution mode. Create-and-run execution emits a targeted warning only for
non-default values.

## Policy Support

### Create-and-run execution

| Policy | Behaviour |
|---|---|
| `filesystem.readwritePaths` | Existing directories mapped read-write at the same path |
| `filesystem.readonlyPaths` | Existing directories mapped read-only at the same path |
| `filesystem.deniedPaths` | Accepted outside shares; rejected when overlapping a mapped share |
| Omitted network policy | Guest firewall blocks external networking |
| `network.egress` or `network.ingress` supplied (even empty or deny-only) | Rejected; omit both sections to use guest isolation |
| Retired `defaultPolicy` and host lists | Rejected by the version-specific JSON request type |
| Network proxy | Rejected |

Mapped paths must be absolute existing directories. Files, nested mapped roots,
and conflicting read-only/read-write entries are rejected.

### Container lifecycle operations

Filesystem policy is accepted only during `provision` and is immutable
afterward. Later phases reject filesystem policy. Network and UI policy are not
accepted by container lifecycle operations; the guest still enforces its unconditional
network lockdown.

## Security Model

- **VM boundary:** workload code runs in a separate Windows instance.
- **Authenticated channels:** every guest TCP connection presents a random
  per-launch 32-byte nonce and a channel-role byte.
- **Role-based pairing:** sockets are paired by declared role, not TCP accept
  order.
- **Network isolation:** only the established host connection is permitted.
- **Secured records:** nonce, rendezvous, marker, and lifecycle record directories
  use owner-only ACLs and reject roots owned by another user.
- **Ownership-scoped teardown:** PID-plus-creation-time proof prevents PID reuse
  or a foreign VM from being treated as owned.
- **One lifecycle execution at a time:** the daemon admits only one execution at a
  time and restores the guest slot before reporting terminal completion.

Same-user processes remain within the backend's trust boundary.

## Prerequisites

| Requirement | Check |
|---|---|
| Windows edition supporting Windows Sandbox | `winver` |
| Windows Sandbox optional feature enabled | `Test-Path "$env:WINDIR\System32\WindowsSandbox.exe"` |
| Hardware virtualisation and Hyper-V support | `systeminfo` |

Enabling the optional feature requires a reboot. No host Python installation is
required.

## Known Limitations

1. Create-and-run execution pays the full VM boot cost on every invocation.
2. Only one Windows Sandbox VM can be active per logon session.
3. Create-and-run stdin is buffered and capped at 64 MiB.
4. Filesystem sharing supports directories only.
5. Network access is block-only; allow-lists, block-lists, proxies, and
   unrestricted outbound access are unsupported.
6. Container lifecycle operations have no idle timeout.

## Testing

```powershell
.\tests\scripts\run_windows_sandbox_one_shot_tests.ps1
.\tests\scripts\run_windows_sandbox_state_aware_tests.ps1
```

Both suites require a Windows host with the Windows Sandbox optional feature.

## Further Reading

- [Windows Sandbox backend reference](windows-sandbox-reference.md)
- [Container lifecycle architecture](../../development/architecture/container-lifecycle.md)
