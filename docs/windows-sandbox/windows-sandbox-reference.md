# Windows Sandbox One-Shot Backend - Reference

This document describes the one-shot implementation. For the high-level
overview, see [windows-sandbox.md](windows-sandbox.md).

## Host-to-Guest Protocol

The host opens four TCP connections to the guest:

| Channel | Purpose |
|---|---|
| Control | Protocol preamble and JSON control messages |
| Stdin | Child standard input |
| Stdout | Child standard output |
| Stderr | Child standard error |

### Authentication and channel roles

Before any protocol data, each connection sends:

```text
[32-byte per-launch nonce][1-byte ChannelRole]
```

The nonce is generated for each VM launch, written into the secured rendezvous
directory, consumed and deleted by the guest, and compared without
data-dependent early exit. The role byte identifies control, stdin, stdout, or
stderr, so sockets are paired by declaration rather than TCP accept order.

Unauthenticated, duplicate-role, stalled, or unexpected-role connections are
dropped. Same-user processes remain within the backend's trust boundary.

### Control preamble

The guest begins the control channel with:

```text
["WSBP"][protocol version: u32 little-endian]
```

The version is incremented only for incompatible framing, preamble, or required
message changes. A magic or version mismatch rejects the connection before
framed messages are processed.

### Control messages

Control messages use a four-byte little-endian length followed by JSON.

| Message | Direction | Purpose |
|---|---|---|
| `Ready` | Guest to host | Guest is ready for execution |
| `Exec(ExecRequest)` | Host to guest | Execute one command |
| `Exit(ExitNotification)` | Guest to host | Report completion |
| `StreamsReady` | Guest to host | Protocol support for reconnectable data streams; unused for one-shot reuse |
| `Ping` / `Pong` | Either | Liveness |

The one-shot host pumps stdin, stdout, stderr, and control concurrently to avoid
opposing TCP-window deadlocks. A reset before any output is treated as an empty
stream; a reset after output is a transport failure so partial output is not
silently truncated.

## Per-Run Host State

Each invocation creates:

```text
%TEMP%\wxc-wsb\oneshot\<run-id>\
  oneshot.marker
  config\
    wxc-windows-sandbox.wsb
  rendezvous\
    bootstrap.cmd
    bootstrap.log
    nonce.bin
    rendezvous.txt
```

The root and run directory receive owner-only ACLs. A directory owned by
another user is rejected because its owner retains implicit `WRITE_DAC` even
after an ACL replacement.

The marker records:

- the `wxc-exec` PID and process creation time;
- VM host-process PID and creation-time proof captured after launch.

PID plus creation time prevents a recycled PID from authorising cleanup of an
unrelated process.

## VM Configuration

The generated `.wsb` file always maps:

| Host path | Guest path | Access |
|---|---|---|
| Directory containing `wxc-windows-sandbox-guest.exe` | `C:\Sandbox-Guest` | Read-only |
| Per-run rendezvous directory | `C:\Sandbox-Rendezvous` | Read-write |

Filesystem policy can add existing directories at the same absolute path
inside the guest. Read-only and read-write access follow the corresponding
policy lists.

The generated configuration disables vGPU, enables networking for the
host-to-guest bridge, and runs:

```text
C:\Sandbox-Rendezvous\bootstrap.cmd
```

The bootstrap script truncates `bootstrap.log` and starts the guest agent. No
host runtime, including Python, is implicitly discovered or mapped.

## Launch Sequence

1. Validate policy and acquire the per-session host VM mutex.
2. Secure `%TEMP%\wxc-wsb\oneshot`.
3. Reconcile any prior marker and running `WindowsSandbox*` processes.
4. Create the per-run directories and initial launcher marker.
5. Generate the nonce, bootstrap script, and `.wsb` file.
6. Launch `WindowsSandbox.exe`.
7. Capture PID-plus-creation-time ownership proof and persist it.
8. Wait for `rendezvous.txt`.
9. Connect and authenticate the four guest channels.
10. Validate the control preamble and wait for `Ready`.
11. Send one execution request and relay stdio.

A failed process-enumeration probe is treated conservatively: the runner refuses
to launch over an unknown potentially-live singleton VM.

## Policy Validation

### Filesystem

`readwritePaths` and `readonlyPaths` must contain absolute existing directories.
The backend rejects:

- files rather than directories;
- one path listed with conflicting access;
- nested or overlapping mapped roots;
- a `deniedPaths` entry equal to, inside, or containing a mapped share.

Windows Sandbox has no per-path deny primitive. A denied path outside all
mapped shares is therefore already inaccessible and requires no additional
rule.

### Network

The guest firewall supports only the default `block` policy. The backend
rejects:

- default network policy `allow`;
- `allowedHosts` or `blockedHosts`;
- network proxy configuration.

Before binding, the guest temporarily pre-authorises its executable to avoid an
interactive firewall prompt. After the host connects, it replaces that rule
with host-IP/listener-port rules and sets both default directions to block.

## Teardown and Crash Recovery

The host permits one Windows Sandbox VM per logon session. A named mutex
serialises one-shot execution with other MXC Windows Sandbox owners.

Normal return and panic use an ownership-scoped teardown guard. Console
shutdown paths take the same parked ownership state and issue termination
without waiting.

Cleanup follows these rules:

- a live launcher means another one-shot invocation owns the VM, so launch is
  refused;
- prior ownership proof intersecting the live VM set authorises orphan reclaim;
- a live VM without intersecting proof is treated as foreign and is never
  enumerated into ownership;
- markers are removed only after teardown confirms all `WindowsSandbox*`
  processes have exited;
- a probe failure or timeout preserves the marker for a later reclaim attempt.

Markerless scratch directories can remain temporarily while Hyper-V processes
hold mapped-folder handles. A later invocation garbage-collects old markerless
directories.

## Legacy Configuration

The following fields remain parseable for schema compatibility but do not
affect the one-shot backend:

- `experimental.windows_sandbox.idleTimeoutMs`
- `experimental.windows_sandbox.daemonPipeName`

A targeted warning is emitted only when either value differs from its default.
The one-shot path does not connect to `wxc-windows-sandbox-daemon.exe`.

## Debugging

Per-run files are normally removed after confirmed teardown. While a run is
active, inspect the newest directory under:

```powershell
$root = Join-Path $env:TEMP "wxc-wsb\oneshot"
$run = Get-ChildItem $root -Directory |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

Get-Content (Join-Path $run.FullName "rendezvous\bootstrap.log")
Get-Content (Join-Path $run.FullName "rendezvous\rendezvous.txt")
Get-Content (Join-Path $run.FullName "config\wxc-windows-sandbox.wsb")
```

Check host processes with:

```powershell
Get-Process | Where-Object { $_.ProcessName -like "WindowsSandbox*" }
```

Do not terminate processes by name during normal cleanup; the backend uses
PID-plus-creation-time ownership proof to avoid killing an unrelated VM.

## Key Source Files

| File | Purpose |
|---|---|
| `src/core/mxc_engine/src/run.rs` | Selects the one-shot runner |
| `src/backends/windows_sandbox/lifecycle/src/one_shot.rs` | One-shot orchestration |
| `src/backends/windows_sandbox/lifecycle/src/policy.rs` | Filesystem and network validation |
| `src/backends/windows_sandbox/lifecycle/src/vm.rs` | `.wsb` generation, launch, and ownership capture |
| `src/backends/windows_sandbox/lifecycle/src/rendezvous.rs` | Guest address discovery |
| `src/backends/windows_sandbox/lifecycle/src/bridge.rs` | Host-to-guest channels and stdio relay |
| `src/backends/windows_sandbox/lifecycle/src/teardown.rs` | Markers, reconcile, and guaranteed cleanup |
| `src/backends/windows_sandbox/lifecycle/src/control_plane.rs` | Ownership decisions and process identity |
| `src/backends/windows_sandbox/common/src/auth.rs` | Nonce and role handshake |
| `src/backends/windows_sandbox/common/src/sandbox_protocol.rs` | Control-channel framing |
| `src/backends/windows_sandbox/guest/src/main.rs` | Guest startup |
| `src/backends/windows_sandbox/guest/src/listener.rs` | Authenticated socket acceptance |
| `src/backends/windows_sandbox/guest/src/executor.rs` | Process execution and stdio bridge |
| `src/backends/windows_sandbox/guest/src/firewall.rs` | Guest firewall policy |
| `src/backends/windows_sandbox/guest/src/job.rs` | Process-tree cleanup |

## E2E Tests

The one-shot test suite requires Windows Sandbox and Hyper-V:

```powershell
.\tests\scripts\run_windows_sandbox_one_shot_tests.ps1
```

It covers command execution, PowerShell, stderr, exit-code propagation,
timeouts, and repeated independent fresh-VM invocations.
