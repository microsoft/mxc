# Windows Sandbox Backend — Reference

Detailed reference for the sandbox backend internals. For the high-level design overview, see [windows-sandbox.md](windows-sandbox.md).

## IPC Protocol

### wxc-exec ↔ Daemon (state-aware: localhost TCP control channel)

The state-aware daemon listens on an OS-assigned localhost TCP port (recorded in its `daemon.json` record). Clients (`wxc-exec` phase processes) connect, present an 8-byte preamble handshake, then issue a verb on a single line:

| Verb | Payload | Reply |
|------|---------|-------|
| `PING <nonce>` | none | `PONG\n` |
| `STOP <nonce>` | none | `OK\n` then daemon teardown |
| `EXEC <nonce>` | binary `ipc_exec::ExecStart` frame on the same stream | `OK\n` then `FRAME_STDOUT`/`FRAME_STDERR`/`FRAME_EXIT` frames; finally `ERR <reason>\n` if anything beneath fails |

The `<nonce>` is the daemon IPC auth nonce (separate from the daemon↔guest TCP `Nonce`). The frame stream and codec live in `windows_sandbox_lifecycle::ipc_exec`.

### Daemon ↔ Agent (per-launch nonce + role-tag handshake, then length-prefixed JSON)

4 TCP connections on initial boot (control + stdin + stdout + stderr), 3 on each post-`StreamsReady` reconnect.

**Handshake — every connection:**

| Step | Bytes | From | Purpose |
|------|-------|------|---------|
| 1. Per-launch nonce | 32 bytes (`auth::NONCE_LEN`) | Host → Guest | Defeats cross-user accept-race hijack |
| 2. Channel role tag | 1 byte (`auth::ChannelRole`: `0=Control`, `1=Stdin`, `2=Stdout`, `3=Stderr`) | Host → Guest | Guest pairs the accepted socket by **declared role**, not by accept order |

A connection whose nonce does not constant-time-equal the launch nonce — or whose role tag duplicates a slot already filled — is dropped silently. The host writes both elements via `windows_sandbox_common::auth::write_nonce`; the guest reads them via `auth::verify_nonce` under a 1-second `HANDSHAKE_TIMEOUT` so a stalled peer cannot wedge the accept loop. See [`windows_sandbox_common::auth`](../../src/backends/windows_sandbox/common/src/auth.rs) for the full threat-model scope (the handshake defends cross-user hijack; same-user processes remain inside the trust boundary).

**Framed control-channel messages — after handshake:**

Frame format: `[4 bytes: u32 LE length][JSON payload]`

| Message | Direction | Purpose |
|---------|-----------|---------|
| `Ready` | Agent → Host | Agent ready for EXEC commands |
| `Exec(ExecRequest)` | Host → Agent | Execute a script |
| `Exit(ExitNotification)` | Agent → Host | Script finished |
| `StreamsReady` | Agent → Host | New data streams ready for next execution |
| `Ping` / `Pong` | Either | Keepalive |

## Sandbox VM Setup

### Folder Mapping

| Host path | Sandbox path | Access | Contents |
|-----------|-------------|--------|----------|
| Daemon's exe directory | `C:\sandbox-guest` | Read-only | `wxc-windows-sandbox-guest.exe` |
| `%TEMP%\wxc-sandbox-rendezvous` | `C:\sandbox-rendezvous` | Read-write | `rendezvous.txt`, `bootstrap.cmd`, `bootstrap.log` |
| Host Python directory | `C:\sandbox-python` | Read-only | Host's Python installation |

### Bootstrap Sequence

The `.wsb` LogonCommand runs `C:\sandbox-rendezvous\bootstrap.cmd`:

1. Adds `C:\sandbox-python` and `C:\sandbox-python\Scripts` to PATH
2. Sets `PYTHONDONTWRITEBYTECODE=1` and `PYTHONNOUSERSITE=1`
3. Logs diagnostics to `bootstrap.log`
4. Launches `wxc-windows-sandbox-guest.exe`

### .wsb Configuration

```xml
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{agent_dir}</HostFolder>
      <SandboxFolder>C:\sandbox-guest</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{rendezvous_dir}</HostFolder>
      <SandboxFolder>C:\sandbox-rendezvous</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{python_dir}</HostFolder>
      <SandboxFolder>C:\sandbox-python</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\sandbox-rendezvous\bootstrap.cmd</Command>
  </LogonCommand>
  <vGPU>Disable</vGPU>
  <Networking>Enable</Networking>
</Configuration>
```

`vGPU` is disabled to avoid intermittent GPU virtualization failures under nested Hyper-V.

## Agent Startup & Rendezvous

1. Agent binds TCP on `0.0.0.0:0` (OS-assigned port)
2. Discovers its IP via UDP "fake connect" to `1.1.1.1:80`
3. Writes `<ip>:<port>` to `C:\sandbox-rendezvous\rendezvous.txt`
4. Accepts 4 TCP connections from the daemon
5. Locks down Windows Firewall via `netsh` — only allows host IP
6. Sends `Ready` on control channel
7. Enters command loop

## Python in the Sandbox

Python is **not installed** inside the sandbox — the host's Python directory is mapped read-only.

### Discovery (`find_host_python()`)

1. `where python` — skips Windows Store stubs (`WindowsApps`), verifies `python --version`
2. Hardcoded paths: `C:\Python312`, `C:\Python311`, `C:\Python310`, `C:\Program Files\Python31x`
3. User-scoped: `%LOCALAPPDATA%\Programs\Python\*`

### Read-Only Mount Workaround

Python's `site` module writes `.pyc` cache to its install dir. Read-only mount causes exit code 1. Mitigated by:
- `bootstrap.cmd` sets `PYTHONDONTWRITEBYTECODE=1` and `PYTHONNOUSERSITE=1`
- Test configs use `python -S -B -c "..."`

### Other Languages

The sandbox runs any command through `cmd.exe /C <script>`:
- **PowerShell**: Built into Windows Sandbox — works directly
- **cmd/batch**: Works out of the box
- **Node.js/TypeScript**: Would need host-mapping (not implemented)

## Daemon Lifecycle (state-aware)

The host-side daemon exists **only for the state-aware lifecycle**; the one-shot
runner launches and tears down its VM in-process with no daemon.

### Startup

```
wxc-windows-sandbox-daemon.exe --token <sandbox-token>
```

The auth **nonce is written to the daemon's stdin** (`"<nonce>\n"`, then the
pipe is closed) rather than passed on the command line, so it is not observable
cross-process via the PEB / `Win32_Process` command line. The daemon reads a
single bounded line at startup.

Spawned by the `start` phase of `wxc-exec`. On Windows the daemon is spawned
**detached** (`DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`) so it outlives the
caller's console/process group — killing `wxc-exec` must not orphan a live VM.

#### Ownership-proof reconciliation

Windows Sandbox is **single-instance per host**, so a live VM left behind by a
previous daemon (crash, force-kill, machine sleep) would block a new launch with
*"Only one running instance of Windows Sandbox is allowed."* Reconciliation is
**ownership-proof**, never blindly destructive:

- A daemon **always writes its control-plane record (`daemon.json`, `ready:false`)
  BEFORE launching a VM** and removes it only **after** teardown, and the record
  carries the launched VM process identities (pid + creation time). Invariant:
  *our VM ⟺ a daemon record whose recorded VM identities intersect the live set.*
- **VM running + a record whose VM identities match the live processes** → ours.
  If the prior daemon is alive it is already-active (reject); if dead it is our
  orphan and is **reclaimed** (scoped teardown of exactly those proven processes).
- **VM running + no matching record** → a **foreign / manually-opened** sandbox.
  The daemon **refuses to start and never tears it down.**

The one-shot runner enforces the same invariant via per-run ownership markers and
the host VM-slot mutex (`Local\wxc-wsb-vm`): it reclaims only a VM it can prove it
launched and otherwise refuses as busy.

### Teardown

1. Kills `WindowsSandbox.exe`, `WindowsSandboxServer.exe`,
   `WindowsSandboxRemoteSession.exe` (the `.exe` suffix is required — `taskkill
   /IM` matches the full image name)
2. Polls until those host processes exit (up to 30s)
3. 5s Hyper-V cooldown

> The `vmmemWindowsSandbox` / `vmmemCmZygote` Hyper-V memory processes are
> SYSTEM-owned and linger briefly after the host processes exit. They are
> harmless residue — a fresh sandbox launches successfully while they are still
> present — so teardown deliberately does **not** wait on them.

## Debugging

```powershell
# Check rendezvous file
Get-Content "$env:TEMP\wxc-sandbox-rendezvous\rendezvous.txt"

# Check bootstrap log
Get-Content "$env:TEMP\wxc-sandbox-rendezvous\bootstrap.log"

# Check generated .wsb config
Get-Content "$env:TEMP\wxc-sandbox-config\wxc-windows-sandbox.wsb"

# Check for zombie VM processes
Get-Process | Where-Object { $_.ProcessName -match "vmmem|vmwp|sandbox" }

# Run the state-aware daemon manually (visible logs)
src\target\release\wxc-windows-sandbox-daemon.exe --token debug-token
# (the auth nonce is supplied on the daemon's stdin, then the pipe is closed)
# In another terminal:
src\target\release\wxc-exec.exe --debug tests\configs\basic_windows_sandbox.json

# Clean slate
Get-Process -Name "wxc-windows-sandbox-daemon","WindowsSandbox*" -ErrorAction SilentlyContinue |
  ForEach-Object { Stop-Process -Id $_.Id -Force }
Start-Sleep 30
Remove-Item "$env:TEMP\wxc-sandbox-rendezvous\*" -ErrorAction SilentlyContinue
```

## Key Source Files

| File | Purpose |
|------|---------|
| `src/core/wxc/src/main.rs` | CLI dispatch: routes `windows_sandbox` one-shot + state-aware phases to `WindowsSandboxRunner` |
| **Lifecycle crate** (`src/backends/windows_sandbox/lifecycle/src/`) | |
| `one_shot.rs` | Transient one-shot `WindowsSandboxRunner` (fresh VM per call, guaranteed teardown) |
| `state_aware.rs` | `StatefulSandboxBackend` impl (provision/start/exec/stop/deprovision); client-side IPC + `map_exec_status_error` |
| `control_plane.rs` | Durable records (`daemon.json` / `record.json`), IPC verb/status consts, host VM-slot lock, owner-only DACL helpers |
| `teardown.rs` | Ownership-proof reconcile, markers, scoped process teardown, scratch GC |
| `bridge.rs` | 4-channel TCP bridge to the guest, per-connection `Nonce` + `ChannelRole` handshake, preamble handshake, `stream_exec_on_guest`, reconnect |
| `ipc_exec.rs` | Binary frame stream (`ExecStart`, `MAX_IPC_FRAME`, frame kinds) for state-aware exec |
| `vm.rs` | `.wsb` generation, host Python discovery, VM launch/teardown primitives, `launch_managed_vm` shared boot-sequence helper |
| `rendezvous.rs` | Polls the guest rendezvous file |
| `policy.rs` | Maps filesystem policy to MappedFolders; rejects unenforceable policy |
| `error.rs` | Typed `OneShotError` → `ScriptResponse` (with `FailurePhase`) mapping |
| **Daemon crate** (`src/backends/windows_sandbox/daemon/src/`) | |
| `main.rs` | State-aware daemon entry point: `--token` arg, nonce-over-stdin, VM ownership, reconcile, `DaemonLaunchObserver` wiring for `vm::launch_managed_vm` |
| `control_server.rs` | Localhost IPC server: `EXEC`/`PING`/`STOP` verbs, single-flight exec admission, bounded-wait pre-auth permit |
| **Guest crate** (`src/backends/windows_sandbox/guest/src/`) | |
| `main.rs` | Guest entry point |
| `listener.rs` | TCP listener, rendezvous writer, role-tag pairing of accepted sockets |
| `executor.rs` | Command loop, stdio bridging |
| `job.rs` | Job Object child-tree reaping |
| `firewall.rs` | Guest firewall lockdown (`netsh advfirewall`) |
| **Common crate** (`src/backends/windows_sandbox/common/src/`) | |
| `auth.rs` | Per-launch `Nonce`, `ChannelRole`, host/guest handshake helpers; nonce-file write + delete-after-read |
| `sandbox_protocol.rs` | Shared control-channel preamble + JSON message codec |

## E2E Tests

Manual-only — requires Hyper-V + Windows Sandbox feature (cannot run in GitHub CI).

### Running

```powershell
cd tests\scripts
.\run_windows_sandbox_one_shot_tests.ps1 -Release
```

### Test Configs

| Config | Script | Validates |
|--------|--------|-----------|
| `windows_sandbox_echo.json` | `echo Hello from sandbox!` | Boot, stdout relay |
| `basic_windows_sandbox.json` | `python -S -B -c "..."` | Python mapping |
| `windows_sandbox_powershell.json` | `powershell ... "PowerShell works"` | PowerShell |
| `windows_sandbox_powershell_env.json` | `powershell ... $env:COMPUTERNAME` | VM isolation |
| `windows_sandbox_stderr.json` | `echo stdout && echo stderr 1>&2` | stderr relay |
| `windows_sandbox_exit_code.json` | `exit /b 42` | Exit codes |
| `windows_sandbox_timeout.json` | `ping -n 30 127.0.0.1` (5s timeout) | Timeout |
| *(multi-exec)* | `windows_sandbox_echo.json` × 3 | VM reuse |
