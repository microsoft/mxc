# Windows Sandbox Backend

## Overview

The Windows Sandbox backend provides VM-level isolation for script execution using [Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview). Unlike the process container backend (which runs scripts in a sandboxed process on the host), the Sandbox backend boots an ephemeral Windows VM, executes scripts inside it, and tears it down when the work is done.

This provides stronger isolation than process containers — the script runs in a completely separate OS instance with its own filesystem, registry, and network stack.

The backend has two execution surfaces:

- **One-shot** (the default path through `wxc-exec`): each invocation boots a **fresh** disposable VM, runs the script exactly once, and guarantees teardown of that VM on every exit path. There is no warm-VM reuse and no shared state between invocations — one call == one disposable VM. Implemented by `WindowsSandboxRunner` in the `windows_sandbox_lifecycle` crate.
- **State-aware** (multi-call `provision → start → exec* → stop → deprovision`): holds a single live VM across separate `wxc-exec` phase processes via a persistent detached host-side daemon. See [State-aware lifecycle](#state-aware-lifecycle) below.

## Architecture

### One-shot (default)

```
wxc-exec.exe (sync CLI)  →  WindowsSandboxRunner
  (src/backends/windows_sandbox/lifecycle/src/one_shot.rs)
    │
    ├── Preflight: Windows Sandbox feature enabled + host Python discovered
    ├── plan_policy(): map filesystem policy to MappedFolders; reject unenforceable policy (no side effects)
    ├── Acquire host VM-slot mutex (Local\wxc-wsb-vm) for the whole run
    ├── Ownership-proof reconcile: reclaim our own orphaned VM, or refuse a foreign/manual sandbox
    ├── Per-run scratch dirs (owner-only DACL), write ownership marker, generate .wsb
    ├── Arm teardown guard BEFORE launch (every exit path tears the VM down)
    └── Launch WindowsSandbox.exe → poll rendezvous file → connect 4 TCP channels to guest
          │
          wxc-windows-sandbox-guest.exe (inside the VM)
            ├── Binds TCP, writes IP:port to the rendezvous file
            ├── Accepts 4 connections (control, stdin, stdout, stderr)
            ├── Locks down its firewall (only the host IP:port is allowed)
            ├── Runs the script and bridges stdin/stdout/stderr over TCP (streamed live)
            └── Reports the exit code on the control channel
```

The **state-aware** path interposes the long-lived `wxc-windows-sandbox-daemon` between `wxc-exec` and the guest so the VM and guest control connection persist across phases (see [State-aware lifecycle](#state-aware-lifecycle)).

### Components

| Binary | Crate | Runs where | Purpose |
|--------|-------|------------|---------|
| `wxc-exec.exe` | `wxc` | Host | CLI entry point; dispatches one-shot and state-aware phases to `WindowsSandboxRunner` |
| `wxc-windows-sandbox-daemon.exe` | `wxc_windows_sandbox_daemon` | Host | **State-aware only:** owns the live VM + guest control connection for the sandbox lifetime |
| `wxc-windows-sandbox-guest.exe` | `wxc_windows_sandbox_guest` | Inside sandbox VM | Accepts connections, runs scripts, locks down the firewall, bridges stdio |

## Execution flow

### One-shot

1. `wxc-exec` runs the preflight (feature + Python), plans the policy, and acquires the host VM-slot mutex.
2. It reconciles the single-instance slot (reclaim our own orphan via process-identity proof; refuse a foreign VM), writes an ownership marker, generates the `.wsb`, and arms the teardown guard.
3. It launches the VM, polls the rendezvous file for the guest address, and connects the 4 TCP channels.
4. The guest runs the script and bridges stdio **live** to `wxc-exec`; the control channel carries the exit code.
5. The teardown guard tears the VM down and removes the scratch dir on every exit path (success, error, or panic).

Because each one-shot run uses a fresh VM, it pays the full cold-boot cost (~15–60s) every time. Use the state-aware lifecycle when you need to amortise boot cost across multiple executions.

## Configuration

```json
{
  "version": "0.5.0-alpha",
  "containment": "windows_sandbox",
  "process": {
    "commandLine": "python -S -B -c \"print('hello')\"",
    "timeout": 60000
  }
}
```

> **Note:** Windows Sandbox is experimental — requires the `--experimental` CLI flag.

| Field | Default | Description |
|-------|---------|-------------|
| `containment` | `"processcontainer"` | Must be `"windows_sandbox"` to use this backend |
| `process.commandLine` | *(required)* | Command line to execute inside the sandbox |
| `process.timeout` | `0` (none) | Script execution timeout in milliseconds |

> **Legacy fields:** `experimental.windows_sandbox.idleTimeoutMs` (and its `idleTimeout` alias) and `experimental.windows_sandbox.daemonPipeName` are still accepted by the config parser for back-compat, but they are no longer consumed by any live dispatch path -- they were used by the now-removed warm-reuse daemon client and have **no effect** on the current one-shot or state-aware paths. The one-shot path emits a stderr WARNING when these fields are set to a non-default value (and a separate WARNING on every one-shot `windows_sandbox` invocation noting that the call gets a fresh disposable VM, not warm reuse; set `WXC_WSB_ACK_ONESHOT_FRESH_VM=1` to suppress that one). For warm reuse, use the state-aware lifecycle. The current backend has no idle watchdog (see [State-aware lifecycle → Robustness](#robustness)).

When `containment` is `"windows_sandbox"`, the `processContainer` section is ignored — UI/process isolation is managed by the sandbox VM. The `filesystem` and `network` sections are honored by the transient one-shot runner (see [Filesystem and network policy](#filesystem-and-network-policy) below).

## Filesystem and network policy

The transient one-shot runner (the default path through `wxc-exec`) maps the request's filesystem policy into the sandbox and validates its network policy:

- **`filesystem.readwritePaths`** → each host directory is mapped into the guest **read-write** at the *same absolute path* (host parity).
- **`filesystem.readonlyPaths`** → each host directory is mapped **read-only**; writes inside the guest fail.
- **`filesystem.deniedPaths`** → these are *host* paths the contained code must not reach. Because Windows Sandbox shares nothing from the host by default, a denied path that lies outside every mapped share is already satisfied (no-op). A denied path that is equal to, or nested inside, a mapped share is **rejected** — Windows Sandbox has no per-path "deny" primitive, so the contradiction cannot be honored.
- Mapped paths must **exist** and be **directories** (files are rejected — Windows Sandbox maps directories only). Overlapping/nested mapped roots and the same path listed as both read-write and read-only are rejected.
- **`network.defaultPolicy: "block"`** (the schema default) is enforced **natively** by the guest agent's firewall lockdown (default-deny outbound); no host-side action is needed.
- **`network.defaultPolicy: "allow"`** is currently **rejected** — the guest agent unconditionally locks down egress, so outbound access cannot be granted without a guest-side change.
- **`network.allowedHosts` / `network.blockedHosts`** (selective per-host filtering) and an explicit **network proxy** are **rejected** — the backend has no DNS-aware filtering primitive.

Policy validation runs *before* any VM is launched, so a rejected policy fails fast with a clear error and zero side effects.

> **Known gap (`deniedPaths`):** overlap against mapped shares is decided on *canonicalized* path components (resolving 8.3 short names, junctions, and case), but a denied leaf that does not yet exist can only be normalized lexically against its existing ancestor. `deniedPaths` is therefore a best-effort guard for the "carve a hole in a mapped share" contradiction, **not** a hardened security boundary against a determined caller crafting alias paths. The actual isolation guarantee is that Windows Sandbox shares nothing by default — only explicitly mapped directories are reachable.

## State-aware lifecycle

In addition to the one-shot path above, Windows Sandbox supports the **state-aware lifecycle** — a multi-call `provision → start → exec* → stop → deprovision` flow that holds a single live VM across separate `wxc-exec` phase processes. This mirrors the cross-backend state-aware API (see [`docs/state-aware-lifecycle/mxc-state-aware-sandbox-api.md`](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md)) and is the integrated, long-lived counterpart to the disposable one-shot runner.

Because Windows itself permits only **one running Windows Sandbox VM per host**, MXC holds no cross-phase state in the `wxc-exec` process. Instead, a **persistent detached host-side daemon** (`wxc_windows_sandbox_daemon`) owns the live VM and the guest control connection for the sandbox's whole lifetime. Each phase process discovers the daemon via a durable control-plane record keyed by `sandboxId` (under `%TEMP%\wxc-wsb\state-aware\`) and talks to it over a localhost IPC channel.

### Phases

| Phase | Effect |
|-------|--------|
| `provision` | Records bookkeeping + an immutable snapshot of the filesystem policy. No VM yet. Returns a `sandboxId` prefixed `wsb:`. |
| `start` | Spawns the detached daemon, which boots the VM (~35–45s) and holds the guest control connection. Reclaims an orphaned VM from a crashed prior daemon only via positive process-identity proof; otherwise refuses (never kills a foreign/manual sandbox). |
| `exec` | Connects to the held daemon and runs a script on the live guest connection, relaying stdout/stderr live to `wxc-exec` stdio. Single-flight: one exec at a time per sandbox. Can be called repeatedly; the guest is reused. |
| `stop` | Sends the daemon a graceful stop; the VM is fully torn down. The same `sandboxId` can be `start`ed again. |
| `deprovision` | Stops (if needed) and removes all records. The `sandboxId` becomes invalid. |

### Policy honoring

Filesystem policy is honored **at provision** and is **immutable** thereafter — later phases reject `filesystem`. The honored fields are identical to the one-shot path (`readwritePaths` / `readonlyPaths` / `deniedPaths`, where denied paths name *host* paths the contained code must not reach). `network` and `ui` are not honored at any phase (network isolation is enforced unconditionally by the in-guest agent), and there is no Entra `user` bundle (unlike IsolationSession).

### Robustness

- An **8-byte control preamble** (magic `WSBP` + version) on the guest control channel fails fast on a protocol/identity mismatch.
- The daemon performs **ownership-based startup reconcile**: it reclaims a VM only when the prior daemon record's recorded VM process identities intersect the live set, and otherwise refuses rather than tearing down a sandbox it cannot prove it owns. Cleanup teardown is scoped to VMs the daemon actually launched.
- There is **no idle watchdog**: a provisioned/idle sandbox is held until an explicit `stop`/`deprovision`.

### SDK usage

> **Note**: Windows Sandbox is an experimental backend; every state-aware
> SDK call must pass `{ experimental: true }` in the options or the
> underlying `wxc-exec` binary will refuse with
> `Error: Windows Sandbox is an experimental feature. Use --experimental flag.`
> Once Windows Sandbox is promoted out of experimental (tracked in
> [`docs/versioning.md`](../versioning.md)), the option will become unnecessary.

```typescript
import {
  provisionSandbox, startSandbox, execInSandboxAsync, stopSandbox, deprovisionSandbox,
} from '@microsoft/mxc-sdk';

const opts = { experimental: true };

const { sandboxId } = await provisionSandbox(
  'windows_sandbox',
  { filesystem: { readwritePaths: ['C:\\workspace'], readonlyPaths: ['C:\\inputs'] } },
  opts,
);
await startSandbox(sandboxId, undefined, opts);
const { stdout, exitCode } = await execInSandboxAsync(
  sandboxId,
  { process: { commandLine: 'echo hello-from-wsb' } },
  opts,
);
await stopSandbox(sandboxId, undefined, opts);
await deprovisionSandbox(sandboxId, undefined, opts);
```

State-aware requests use schema version `0.6.0-alpha`. The backend is inferred from the `wsb:` prefix on the `sandboxId` for all non-provision phases.

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
4. **Cold boot time** — one-shot pays the full 15–60s boot every run; the state-aware lifecycle amortises it by reusing the held VM across `exec` phases.
5. **No outbound network / DNS-aware filtering** — `network.defaultPolicy: "block"` is enforced natively by the guest firewall; granting outbound (`allow`) and per-host filtering / proxy support remain future work (rejected today).

## Further Reading

See [windows-sandbox-reference.md](windows-sandbox-reference.md) for detailed protocol specs, VM setup internals, debugging guide, source file reference, and E2E test documentation.
