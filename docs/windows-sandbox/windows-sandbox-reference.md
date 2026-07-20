# Windows Sandbox Backend - Reference

For the overview and policy matrix, see
[windows-sandbox.md](windows-sandbox.md).

## Guest Protocol

The host opens four TCP connections on boot:

| Channel | Purpose |
|---|---|
| Control | Preamble and JSON control messages |
| Stdin | Child standard input |
| Stdout | Child standard output |
| Stderr | Child standard error |

State-aware execution reconnects the three data channels after each
`StreamsReady`; the control channel remains attached to the daemon.

### Authentication and channel roles

Every connection starts with:

```text
[32-byte per-launch nonce][1-byte ChannelRole]
```

The guest consumes and deletes the nonce file, authenticates each socket, and
pairs it by the declared control/stdin/stdout/stderr role. Invalid,
duplicate-role, unexpected-role, and stalled connections are dropped.

### Control preamble and messages

The guest begins the control channel with:

```text
["WSBP"][protocol version: u32 little-endian]
```

A magic or version mismatch rejects the connection before framed messages.
Control messages then use a four-byte little-endian length followed by JSON.

| Message | Direction | Purpose |
|---|---|---|
| `Ready` | Guest to host | Guest is ready |
| `Exec(ExecRequest)` | Host to guest | Execute a command |
| `Exit(ExitNotification)` | Guest to host | Report completion |
| `StreamsReady` | Guest to host | Data channels may reconnect |
| `Ping` / `Pong` | Either | Liveness |

## State-Aware Daemon IPC

The daemon listens on an OS-assigned localhost port recorded in `daemon.json`.
A phase process sends:

```text
<VERB> <daemon-nonce>\n
```

| Verb | Following data | Reply |
|---|---|---|
| `PING` | None | `PONG\n` |
| `STOP` | None | `OK\n`, followed by daemon teardown |
| `EXEC` | Binary `ExecStart` frame | `OK\n`, output frames, then one exit frame |

`EXEC` output uses the codec in `windows_sandbox_lifecycle::ipc_exec`.
Single-flight admission returns `ERR busy` while another execution owns the
guest slot and `ERR not_ready` while the VM is booting.

The daemon restores or poisons the guest slot and releases its mutex before
writing the terminal exit frame. This makes terminal completion the point at
which a new execution may be admitted.

## Host State

### One-shot

```text
%TEMP%\wxc-wsb\oneshot\<run-id>\
  oneshot.marker
  config\wxc-windows-sandbox.wsb
  rendezvous\
    bootstrap.cmd
    bootstrap.log
    nonce.bin
    rendezvous.txt
```

### State-aware

```text
%TEMP%\wxc-wsb\state-aware\
  daemon.json
  <sandbox-token>\
    record.json
    config\wxc-windows-sandbox.wsb
    rendezvous\
      bootstrap.cmd
      bootstrap.log
      nonce.bin
      rendezvous.txt
```

Directories are owner-only and ownership-verified before trusted state is read.
Records are written through same-directory atomic rename.

Process identities pair PID with creation time. This prevents a recycled PID
from authorising teardown of another process.

## VM Configuration

The `.wsb` file always maps:

| Host path | Guest path | Access |
|---|---|---|
| Guest binary directory | `C:\Sandbox-Guest` | Read-only |
| Per-run rendezvous directory | `C:\Sandbox-Rendezvous` | Read-write |

Filesystem policy adds existing directories at the same absolute path inside
the guest. The generated configuration disables vGPU, enables networking for
the bridge, and runs `C:\Sandbox-Rendezvous\bootstrap.cmd`.

No host runtime, including Python, is implicitly discovered or mapped.

## One-Shot Launch

1. Reject an ambient Tokio runtime before side effects.
2. Validate policy and acquire the host VM mutex.
3. Reconcile stale one-shot markers and live VM processes.
4. Create secured run state and write the initial launcher marker.
5. Generate the nonce, bootstrap script, and `.wsb` file.
6. Launch `WindowsSandbox.exe`.
7. Capture and persist VM ownership proof.
8. Wait for rendezvous and authenticate the four guest channels.
9. Send one execution request and relay stdio.
10. Tear down the owned VM and clear the marker after confirmed exit.

## State-Aware Lifecycle

### Provision

Provision generates a strict `wsb:<8-lowercase-hex>` ID and writes a
`Provisioned` record containing the immutable mapped-folder policy. It does not
launch a VM.

### Start

Start acquires the transition lock, validates state, and launches
`wxc-windows-sandbox-daemon.exe --token <token>` as a detached process. The
daemon authentication nonce is written to stdin and the pipe is closed.

The daemon:

1. Creates `daemon.json` with `ready:false`.
2. Acquires the host VM mutex.
3. Reconciles any provably-owned orphan.
4. Launches the VM and persists ownership proof.
5. Connects to the guest and marks `ready:true`.
6. Serves `PING`, `EXEC`, and `STOP`.

Start polls the record until readiness or timeout. A stale daemon or VM is
reclaimed only when recorded process identities intersect the live set.

### Exec

Exec authenticates to the daemon and requests single-flight admission. The
daemon streams stdin, stdout, and stderr while reading the guest exit message.
It then reconnects the data channels, restores the reusable guest slot, releases
the slot lock, and writes the terminal exit frame.

If an exec fails, or the post-exec data-channel reconnect fails, the daemon
marks the held guest slot **unusable** and records the reason. This is terminal
for the sandbox's session: the daemon cannot safely re-establish its single held
guest connection mid-session, so there is no automatic recovery back to a ready
state. Every subsequent exec fails fast with the recorded reason, while `stop`
and `deprovision` continue to work. To run again, tear the sandbox down
(`stop`/`deprovision`) and provision a fresh one.

### Stop and deprovision

Stop sends `STOP`, waits for the daemon and VM to exit, and returns the record
to `Provisioned`. Deprovision stops if needed and removes the sandbox directory.
Failed probes or incomplete teardown preserve records for a later retry.

## Policy Validation

### Filesystem

Mapped roots must be absolute existing directories. The backend rejects:

- files;
- conflicting read-only/read-write entries;
- nested mapped roots;
- a denied path equal to, inside, or containing a mapped share.

A denied path outside all shares is already inaccessible because Windows
Sandbox shares nothing by default.

State-aware filesystem policy is accepted only at provision and is immutable
afterward.

### Network and UI

One-shot supports only default network policy `block`; `allow`, host filters,
and proxies are rejected.

State-aware phases reject network and UI policy. The guest firewall still
enforces unconditional network lockdown.

## Teardown and Recovery

One-shot and state-aware modes share `Local\wxc-wsb-vm`, serialising ownership
of the host's single Windows Sandbox VM.

Cleanup rules:

- a live owner prevents another launch;
- prior ownership proof intersecting the live set authorises reclaim;
- a live VM without intersecting proof is foreign and left untouched (but see
  `--force-reclaim` below);
- PID creation time is rechecked on the same process handle before
  `TerminateProcess`;
- durable records are removed only after host processes are confirmed gone;
- probe failure or timeout preserves records.

Lingering SYSTEM-owned `vmmem*` processes are not ownership targets and do not
block a new launch after the `WindowsSandbox*` host processes exit.

### Hard-kill orphans and `--force-reclaim`

Teardown-on-exit is best-effort, **not** kernel-guaranteed. Between launching
the VM and capturing its process-identity proof, a hard-kill of the launcher
(`TerminateProcess`/OOM/power-loss — no destructor or console handler runs) can
leave a live VM with no ownership proof. Because Windows Sandbox is a
machine-wide singleton, one such unprovable orphan wedges the backend: every
later launch classifies it as foreign and refuses.

Recover by closing the leftover sandbox window, or re-running with
`--force-reclaim`, which tears down an unprovable VM using the live process
snapshot as the kill set. Being proofless, it may also kill a foreign or
manual sandbox; it never overrides an active mxc run or an unreadable probe. It
reaches the detached daemon via the inherited `WXC_WSB_FORCE_RECLAIM` env var.

## Legacy Configuration

These fields remain parseable but do not control either live execution path:

- `experimental.windows_sandbox.idleTimeoutMs`
- `experimental.windows_sandbox.idleTimeout`
- `experimental.windows_sandbox.daemonPipeName`

State-aware lifecycle has no idle watchdog.

## Debugging

Inspect one-shot state under:

```powershell
$root = Join-Path $env:TEMP "wxc-wsb\oneshot"
```

Inspect state-aware records under:

```powershell
$root = Join-Path $env:TEMP "wxc-wsb\state-aware"
Get-Content (Join-Path $root "daemon.json")
```

Check host processes:

```powershell
Get-Process | Where-Object { $_.ProcessName -like "WindowsSandbox*" }
```

Do not terminate processes by name during normal cleanup; use the recorded
PID-plus-creation-time ownership proof.

## Key Source Files

| File | Purpose |
|---|---|
| `src/core/mxc_engine/src/run.rs` | One-shot backend selection |
| `src/core/mxc_engine/src/state_aware.rs` | State-aware backend selection |
| `src/backends/windows_sandbox/lifecycle/src/one_shot.rs` | One-shot orchestration |
| `src/backends/windows_sandbox/lifecycle/src/state_aware.rs` | State-aware phase implementation |
| `src/backends/windows_sandbox/lifecycle/src/control_plane.rs` | Records, state decisions, IPC constants, and locks |
| `src/backends/windows_sandbox/lifecycle/src/teardown.rs` | One-shot markers and cleanup |
| `src/backends/windows_sandbox/lifecycle/src/bridge.rs` | Guest bridge and stream relay |
| `src/backends/windows_sandbox/lifecycle/src/ipc_exec.rs` | Daemon exec frame codec |
| `src/backends/windows_sandbox/lifecycle/src/vm.rs` | VM generation, launch, proof, and teardown |
| `src/backends/windows_sandbox/lifecycle/src/policy.rs` | Policy mapping and validation |
| `src/backends/windows_sandbox/daemon/src/main.rs` | State-aware daemon ownership and launch |
| `src/backends/windows_sandbox/daemon/src/control_server.rs` | Daemon IPC and single-flight execution |
| `src/backends/windows_sandbox/common/src/auth.rs` | Nonce and role authentication |
| `src/backends/windows_sandbox/common/src/sandbox_protocol.rs` | Guest control framing |
| `src/backends/windows_sandbox/guest/src/` | Guest startup, execution, firewall, and job object |

## E2E Tests

```powershell
.\tests\scripts\run_windows_sandbox_one_shot_tests.ps1
.\tests\scripts\run_windows_sandbox_state_aware_tests.ps1
```
