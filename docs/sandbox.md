# Windows Sandbox Backend

## Issues Found & Fixes Applied

Four issues were discovered during E2E bring-up of the sandbox backend. A 3-model LLM council (GPT-5.4, Claude Opus 4.6, Gemini 3 Pro) reviewed all fixes and confirmed unanimously that they are genuine defect corrections — none removed intentional security hardening.

### Issue 1: stdout/stderr silently discarded

**Symptom:** Scripts executed successfully (exit code 0) but produced no visible output.

**Root cause:** Output was dropped at three layers:
- `tcp_bridge.rs` — captured stdout/stderr bytes assigned to `_stdout`/`_stderr` (Rust `_` prefix = intentionally unused, suppresses compiler warning)
- `pipe_server.rs` — RESULT protocol format had no stdout/stderr fields, only exit code and error message
- `sandbox_runner.rs` — hardcoded `standard_out = String::new()` in both success and error paths

**Fix:** Extended RESULT protocol to `RESULT <code> <stdout-b64> <stderr-b64> <error>\n`, with base64 encoding to handle binary output. Client-side parser decodes and surfaces the output.

**Security review:** Not an anti-exfiltration measure. The `_` naming existed from the initial commit that built the TCP bridge infrastructure — the commit message explicitly stated "bridges stdin/stdout/stderr over TCP." The caller who submits the script already controls execution and can exfiltrate via other channels (files in the read-write rendezvous directory, exit codes, timing).

### Issue 2: cmd.exe quoting breaks scripts with double quotes

**Symptom:** Scripts containing double quotes (e.g., `python -c "print('hi')"`) failed inside the sandbox with cryptic cmd.exe errors.

**Root cause:** Rust's `Command::arg()` applies backslash-escaping for quotes (`\"`) targeting the MSVC C runtime. But `cmd.exe /C` doesn't use MSVC conventions — it interprets `\"` literally, breaking the command.

**Fix:** Changed `cmd.arg(script_code)` to `cmd.raw_arg(script_code)`, which passes the script text to cmd.exe without Rust-side escaping.

**Security review:** No command injection risk. The script text originates from the caller's JSON config, flows through the length-prefixed control protocol, and is intentionally executed as a shell command. `raw_arg()` restores correct behavior — both `arg()` and `raw_arg()` result in the script running with full shell capabilities.

### Issue 3: Sandbox boot failures (~60% failure rate)

**Symptom:** Most sandbox launch attempts failed with "The remote environment is logging off" or timed out waiting for rendezvous.

**Root causes** (identified via 3-model LLM council analysis):
1. Zombie Hyper-V processes (`vmwp.exe`, `vmmemWindowsSandbox`) persisted after `taskkill`, blocking new VM launches
2. 3-second teardown cooldown was grossly insufficient for Hyper-V cleanup
3. vGPU virtualization failed intermittently under nested Hyper-V
4. Windows Insider builds 26100+ have a confirmed sandbox regression

**Fix:**
- Poll up to 30 seconds for sandbox processes (`WindowsSandbox*`, `vmmemWindowsSandbox`) to fully exit
- 5-second CmService cooldown after process exit
- Disable vGPU in `.wsb` config (`<vGPU>Disable</vGPU>`)
- 3 retry attempts with exponential backoff (0s, 10s, 20s)
- State reset between retries (clear `sandbox_running`, `guest_connection`, rendezvous directory)

### Issue 4: Single execution per sandbox lifetime

**Symptom:** First script execution succeeded, but any subsequent EXEC on the same sandbox had no stdio — output was silently lost and the daemon timed out waiting for StreamsReady.

**Root cause:** The agent wrapped stdin/stdout/stderr TCP streams in `Option` and called `.take()` on first EXEC, moving ownership into the bridge tasks. After completion, all three were `None` — the second EXEC had no streams to bridge.

**Fix:** Added `StreamsReady` protocol message for coordinated reconnection:
1. After sending `Exit`, agent sends `StreamsReady` on the control channel (signals its listener is ready)
2. Daemon receives `StreamsReady`, connects 3 new TCP data streams to the agent
3. Agent accepts the connections, stores them as the current streams for the next EXEC
4. Residual control buffer passed from `execute_on_guest` to `reconnect_data_streams` to handle cases where `StreamsReady` arrives in the same TCP read as `Exit`

**Critical ordering:** Agent sends `StreamsReady` *before* calling accept. The listener is already bound, so the daemon's connection attempts queue in the TCP backlog. This avoids a deadlock where both sides wait for the other.

**Security review:** Multi-exec does not breach the VM boundary or weaken host isolation. However, VM reuse means execution N+1 runs in the state left by execution N (files, registry, processes). This is acceptable in the single-tenant model (same caller controls all scripts). See [Multi-Exec Security Considerations](#multi-exec-security-considerations) below.

### Issue 4b: Python discovery finds Windows Store stub

**Symptom:** Daemon found Python at `WindowsApps\python.exe` — a Store redirect stub that passes `exists()` but fails when executed. The mapped Python directory in the sandbox contained no real Python.

**Fix:** `find_host_python()` now skips paths containing `Microsoft\WindowsApps` and verifies each candidate by running `python --version`.

### Issue 4c: Python site module crash on read-only mount

**Symptom:** `basic_sandbox.json` returned exit code 1 instead of 0 because Python's `site` module tried to write `.pyc` bytecode cache files to the read-only mapped Python directory.

**Fix:** `bootstrap.cmd` sets `PYTHONDONTWRITEBYTECODE=1` and `PYTHONNOUSERSITE=1`. Test configs also use `-S -B` flags as belt-and-suspenders.

**Security review:** The read-only mount is unchanged. Disabling `site` and bytecache prevents write attempts that would fail — the security control (read-only mount) is preserved. Disabling user site-packages actually *improves* security slightly by preventing package injection.

### Multi-Exec Security Considerations

Multi-exec reuses the same sandbox VM across script executions for performance. This has implications:

**What IS preserved between executions:**
- VM boundary (separate OS instance) — unchanged
- Firewall lockdown (host IP only) — applied once at agent startup, persists
- Read-only mounts (agent binaries, Python) — cannot be modified
- Fresh `cmd.exe /C` process per execution — env vars don't leak between cmd.exe instances

**What MAY leak between executions:**
- Filesystem changes (temp files, downloaded files, created directories)
- Registry modifications
- Background processes spawned by a previous script
- Scheduled tasks or services installed by a previous script

**Constraint:** Multi-exec assumes all scripts in a session come from the **same trust domain**. Do NOT reuse a sandbox VM across different callers or trust boundaries.

**Recommended future safeguards:**
- Kill orphan processes between executions (enumerate and terminate non-system processes)
- Clean temporary directories between runs
- Consider an optional `freshVM: true` config flag for callers who need per-execution isolation

---

## Overview

The Windows Sandbox backend provides VM-level isolation for script execution using [Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview). Unlike the AppContainer backend (which runs scripts in a sandboxed process on the host), the Sandbox backend boots an ephemeral Windows VM, executes scripts inside it, and tears it down when idle.

This provides stronger isolation than AppContainer — the script runs in a completely separate OS instance with its own filesystem, registry, and network stack.

## Architecture

```
wxc-exec.exe (CLI client)
  │
  └── SandboxScriptRunner (src/wxc_common/src/sandbox_runner.rs)
        │
        ├── Connects to wxc-sandbox-daemon via TCP IPC on localhost
        │   (deterministic port derived from pipe name)
        │
        └── Sends: "EXEC {json}\n"
              │
              wxc-sandbox-daemon.exe (host-side, long-lived)
                │
                ├── Discovers Python on the host
                ├── Generates .wsb config with mapped folders
                ├── Launches WindowsSandbox.exe
                ├── Polls rendezvous file for guest agent address
                ├── Connects 4 TCP channels to guest agent
                │
                └── Bridges EXEC requests to the guest
                      │
                      wxc-sandbox-agent.exe (inside sandbox VM)
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
| `wxc-exec.exe` | `wxc` | Host | CLI entry point, dispatches to SandboxScriptRunner |
| `wxc-sandbox-daemon.exe` | `wxc_sandbox_daemon` | Host | Manages sandbox VM lifecycle, bridges IPC to TCP |
| `wxc-sandbox-agent.exe` | `wxc_sandbox_agent` | Inside sandbox VM | Accepts commands, runs scripts, bridges stdio |

### IPC Between wxc-exec and Daemon

The daemon listens on a **localhost TCP port** derived deterministically from a pipe name (default `wxc-sandbox`):

```rust
fn pipe_name_to_port(name: &str) -> u16 {
    let hash: u32 = name.bytes()
        .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    let range = 65535 - 49152;
    49152 + (hash % range) as u16
}
```

This is noted in the code as a "simplified implementation" — a future iteration will use real Win32 named pipes.

**Protocol (line-based):**
- Client → Daemon: `EXEC <json>\n`
- Daemon → Client: `RESULT <exit-code> <stdout-base64> <stderr-base64> <error-message>\n`
- Daemon → Client: `ERROR <message>\n` (on failure)

### Control Protocol (Daemon ↔ Agent)

The daemon and agent communicate over 4 TCP connections. The **control channel** uses length-prefixed JSON frames:

```
[4 bytes: u32 LE length][JSON payload of that length]
```

**Message types** (defined in `src/wxc_common/src/sandbox_protocol.rs`):

| Message | Direction | Purpose |
|---------|-----------|---------|
| `Ready` | Agent → Host | Agent is ready to accept EXEC commands |
| `Exec(ExecRequest)` | Host → Agent | Execute a script |
| `Exit(ExitNotification)` | Agent → Host | Script finished (includes exit code) |
| `StreamsReady` | Agent → Host | New data streams ready for next execution |
| `Ping` / `Pong` | Either | Keepalive |

The other 3 connections (stdin, stdout, stderr) are raw byte streams bridged directly to the child process's stdio.

## Sandbox VM Setup

### Folder Mapping

The daemon generates a `.wsb` config that maps three host directories into the sandbox:

| Host path | Sandbox path | Access | Contents |
|-----------|-------------|--------|----------|
| Daemon's exe directory | `C:\sandbox-agent` | Read-only | `wxc-sandbox-agent.exe` |
| `%TEMP%\wxc-sandbox-rendezvous` | `C:\sandbox-rendezvous` | Read-write | `rendezvous.txt`, `bootstrap.cmd`, `bootstrap.log` |
| Host Python directory | `C:\sandbox-python` | Read-only | Host's Python installation |

### Bootstrap Sequence

The `.wsb` LogonCommand runs `C:\sandbox-rendezvous\bootstrap.cmd`:

1. Adds `C:\sandbox-python` and `C:\sandbox-python\Scripts` to PATH
2. Sets `PYTHONDONTWRITEBYTECODE=1` and `PYTHONNOUSERSITE=1` (prevents site module failures on read-only mount)
3. Logs diagnostics (`where python`, `python --version`) to `bootstrap.log`
4. Launches `wxc-sandbox-agent.exe`

### .wsb Configuration

```xml
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{agent_dir}</HostFolder>
      <SandboxFolder>C:\sandbox-agent</SandboxFolder>
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
2. Discovers its IP on the Hyper-V Default Switch via UDP "fake connect" to `1.1.1.1:80` (no traffic sent — just reads the local source address)
3. Writes `<ip>:<port>` to `C:\sandbox-rendezvous\rendezvous.txt`
4. Accepts 4 TCP connections from the daemon: control, stdin, stdout, stderr
5. Locks down the Windows Firewall via `netsh` — only allows the host's IP address
6. Sends `Ready` on the control channel
7. Enters the command loop

## Execution Flow

### Single Execution

1. `wxc-exec` connects to daemon IPC, sends `EXEC {json}\n`
2. Daemon calls `ensure_sandbox_ready()` — launches sandbox if needed (with retry)
3. Daemon sends `Exec` on the control channel
4. Daemon writes stdin data, shuts down write half (EOF signal)
5. Agent spawns `cmd.exe /C <script>`, bridges stdio over TCP
6. Agent sends `Exit` with exit code on control channel
7. Daemon reads stdout/stderr to EOF, receives Exit
8. Daemon sends `RESULT <code> <stdout-b64> <stderr-b64> <error>\n` to wxc-exec

### Multi-Execution (Same Sandbox)

After the first execution completes:

1. Agent sends `Exit` on control channel
2. Agent sends `StreamsReady` on control channel (signals it's listening for new connections)
3. Daemon receives `Exit`, returns result to wxc-exec client
4. Daemon receives `StreamsReady`, connects 3 new TCP streams (stdin, stdout, stderr) to the agent
5. Next `EXEC` request reuses the existing sandbox VM with fresh data streams

**Key design detail:** The agent sends `StreamsReady` *before* calling accept on the listener. The listener is already bound, so the daemon's connection attempts queue in the TCP backlog. This avoids a deadlock where both sides wait for the other.

## Python in the Sandbox

Python is **not installed** inside the sandbox — the host's Python directory is mapped read-only into the VM.

### Discovery (`find_host_python()`)

The daemon finds Python on the host in this order:
1. `where python` — iterates results, skipping Windows Store stubs (`WindowsApps` directory) and verifying `python --version` actually runs
2. Hardcoded paths: `C:\Python312`, `C:\Python311`, `C:\Python310`, `C:\Program Files\Python31x`
3. User-scoped installs: `%LOCALAPPDATA%\Programs\Python\*`

### Read-Only Mount Issue

Python's `site` module tries to write `.pyc` bytecode cache files on startup. Since the Python directory is mounted read-only, this fails with exit code 1. Mitigated by:
- `bootstrap.cmd` sets `PYTHONDONTWRITEBYTECODE=1` and `PYTHONNOUSERSITE=1`
- Test configs use `python -S -B -c "..."` (`-S` = skip site import, `-B` = no bytecache)

### Other Languages

The sandbox is **language-agnostic** — it runs any command through `cmd.exe /C <script>`:
- **PowerShell**: Built into Windows Sandbox. Use `powershell -Command "..."` directly.
- **cmd/batch**: Works out of the box.
- **Node.js/TypeScript**: Would need the same host-mapping approach as Python. Not implemented yet.

## Daemon Lifecycle

### Startup

```
wxc-sandbox-daemon.exe <pipe-name> <idle-timeout-ms>
```

- `pipe-name`: IPC identifier (default: `wxc-sandbox`), used to derive the TCP port
- `idle-timeout-ms`: How long to stay alive without requests (default: `300000` = 5 minutes)

The daemon is auto-launched by `wxc-exec` if not already running.

### Idle Timeout

A watchdog checks every 10 seconds whether `last_activity` exceeds the idle timeout. When triggered, the daemon:
1. Tears down the sandbox VM
2. Exits the process

### Retry & Error Handling

Sandbox boot can fail (especially on Windows Insider builds). The daemon retries up to **3 times** with exponential backoff:

| Attempt | Backoff | Action |
|---------|---------|--------|
| 1 | 0s | Launch sandbox, wait up to 120s for rendezvous |
| 2 | 10s | Teardown, cleanup rendezvous, relaunch |
| 3 | 20s | Final attempt, propagate error on failure |

Between retries, the daemon:
- Resets `sandbox_running` and `guest_connection` state
- Kills sandbox processes and polls up to 30s for full exit
- Cleans rendezvous directory

### Teardown

Kills sandbox processes in order:
1. `WindowsSandbox.exe`, `WindowsSandboxServer`, `WindowsSandboxRemoteSession`
2. Polls for `WindowsSandbox*` and `vmmemWindowsSandbox` to exit (up to 30s)
3. Waits 5s additional for Hyper-V backend / VHDX release

## Security Model

- **VM isolation**: Scripts run inside a separate Windows instance — full OS boundary
- **Firewall lockdown**: After the agent accepts host connections, it blocks all other network traffic via `netsh advfirewall` rules scoped to the sandbox
- **Read-only mounts**: Agent binaries and Python are mounted read-only — scripts cannot modify them
- **Ephemeral**: The sandbox VM is destroyed on teardown — no state persists between sessions

## Configuration

```json
{
  "script": "python -S -B -c \"print('hello')\"",
  "containment": "sandbox",
  "timeout": 60000,
  "sandbox": {
    "idleTimeout": 300000,
    "daemonPipeName": "wxc-sandbox"
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `containment` | `"appcontainer"` | Must be `"sandbox"` to use this backend |
| `timeout` | `0` (none) | Script execution timeout in milliseconds |
| `sandbox.idleTimeout` | `300000` (5 min) | Daemon idle timeout before teardown |
| `sandbox.daemonPipeName` | `"wxc-sandbox"` | IPC identifier (determines TCP port) |

When `containment` is `"sandbox"`, the `appContainer`, `filesystem`, and `network` sections are ignored — isolation is managed by the sandbox VM and guest agent.

## Prerequisites

| Requirement | How to verify |
|---|---|
| Windows 11 Pro/Enterprise | `winver` |
| Windows Sandbox feature enabled | `dism /online /get-featureinfo /featurename:Containers-DisposableClientVM` |
| Hyper-V / Virtualization enabled | `systeminfo` → "A hypervisor has been detected" |
| Python 3.x on host | `python --version` |

After enabling Windows Sandbox: **reboot required**.

## Debugging

```powershell
# Check if sandbox booted — look for agent's address
Get-Content "$env:TEMP\wxc-sandbox-rendezvous\rendezvous.txt"

# Check bootstrap log (inside sandbox, also accessible from host via mapped folder)
Get-Content "$env:TEMP\wxc-sandbox-rendezvous\bootstrap.log"

# Check generated .wsb config
Get-Content "$env:TEMP\wxc-sandbox-config\wxc-sandbox.wsb"

# Check for zombie VM processes (common cause of boot failures)
Get-Process | Where-Object { $_.ProcessName -match "vmmem|vmwp|sandbox" }

# Run daemon manually to see logs (normally it runs in background)
src\target\release\wxc-sandbox-daemon.exe wxc-sandbox 300000
# Then in another terminal:
src\target\release\wxc-exec.exe --debug test_configs\basic_sandbox.json

# Clean slate — kill everything and wait
Get-Process -Name "wxc-sandbox-daemon","WindowsSandbox*" -ErrorAction SilentlyContinue |
  ForEach-Object { Stop-Process -Id $_.Id -Force }
Start-Sleep 30
Remove-Item "$env:TEMP\wxc-sandbox-rendezvous\*" -ErrorAction SilentlyContinue
```

## Key Source Files

| File | Purpose |
|------|---------|
| `src/wxc/src/main.rs` | Entry point — dispatches to SandboxScriptRunner |
| `src/wxc_common/src/sandbox_runner.rs` | Client: connects to daemon, sends EXEC, reads RESULT |
| `src/wxc_common/src/sandbox_protocol.rs` | Shared control protocol (Ready, Exec, Exit, StreamsReady, Ping, Pong) |
| `src/wxc_common/src/models.rs` | `SandboxConfig`, `ContainmentBackend::Sandbox` |
| `src/wxc_common/src/config_parser.rs` | Parses JSON → `CodexRequest` with `SandboxConfig` |
| `src/wxc_sandbox_daemon/src/main.rs` | Daemon entry point, IPC server, idle watchdog |
| `src/wxc_sandbox_daemon/src/pipe_server.rs` | TCP IPC server, EXEC handling, retry logic |
| `src/wxc_sandbox_daemon/src/sandbox_vm.rs` | .wsb generation, Python discovery, VM launch/teardown |
| `src/wxc_sandbox_daemon/src/rendezvous.rs` | Polls rendezvous.txt for agent address |
| `src/wxc_sandbox_daemon/src/tcp_bridge.rs` | 4-channel TCP bridge, execute_on_guest, reconnect |
| `src/wxc_sandbox_agent/src/main.rs` | Agent entry point |
| `src/wxc_sandbox_agent/src/listener.rs` | TCP listener, rendezvous writer, guest IP discovery |
| `src/wxc_sandbox_agent/src/executor.rs` | Command loop, child process spawning, stdio bridging |
| `src/wxc_sandbox_agent/src/firewall.rs` | Guest firewall lockdown via netsh |

## Known Limitations

1. **IPC uses TCP, not named pipes** — Port conflicts possible if another process occupies the derived port
2. **Single language mapped** — Only Python is mapped from host; Node.js would need similar treatment
3. **Windows Insider regression** — Builds 26100+ have confirmed sandbox boot failures (zombie VM processes)
4. **Cold boot time** — First sandbox boot takes 15-60s; subsequent boots ~15-30s
5. **No filesystem/network policy forwarding** — The `filesystem` and `network` config sections are ignored for sandbox containment; isolation relies on the VM boundary and agent firewall
6. **Buffered output** — stdout/stderr are captured, base64-encoded, and returned in the RESULT protocol line rather than streamed live. Output is only visible after the script finishes. This differs from the AppContainer (console inheritance) and NanVix (pipe relay) backends which forward stdio directly.

## E2E Tests

Sandbox E2E tests are **manual-only** — they require Hyper-V, Windows 11 Pro/Enterprise, and the Windows Sandbox feature, none of which are available on GitHub Actions runners. This follows the same pattern as the existing AppContainer test scripts.

### Running the tests

```powershell
# From repo root:
cd test_scripts
.\run_sandbox_tests.ps1 -Release     # release build
.\run_sandbox_tests.ps1              # debug build
```

The runner starts the daemon, executes each test config, validates exit codes and expected output, then runs a multi-exec sequence (3 echo commands on the same VM). Reports a pass/fail summary at the end.

### Test configs

| Config | Script | Validates |
|--------|--------|-----------|
| `sandbox_echo.json` | `echo Hello from sandbox!` | Boot, stdout relay, basic cmd.exe |
| `basic_sandbox.json` | `python -S -B -c "..."` | Python discovery, host mapping, site module fix |
| `sandbox_powershell.json` | `powershell ... "Write-Output 'PowerShell works'"` | PowerShell execution in sandbox |
| `sandbox_powershell_env.json` | `powershell ... $env:COMPUTERNAME` | Environment access, VM isolation |
| `sandbox_stderr.json` | `echo stdout && echo stderr 1>&2` | stderr relay |
| `sandbox_exit_code.json` | `exit /b 42` | Non-zero exit code propagation |
| `sandbox_timeout.json` | `ping -n 30 127.0.0.1` (5s timeout) | Timeout enforcement, process killing |
| *(multi-exec)* | `sandbox_echo.json` × 3 | StreamsReady protocol, VM reuse |

### What the tests cover

- ✅ Sandbox boot and agent rendezvous
- ✅ Python and PowerShell script execution
- ✅ stdout and stderr relay
- ✅ Non-zero exit codes
- ✅ Timeout enforcement
- ✅ Multi-exec on the same VM (3 consecutive executions)

### What the tests do NOT cover

- ❌ Network isolation / firewall lockdown
- ❌ Stdin forwarding to scripts
- ❌ Working directory configuration
- ❌ Custom idle timeout behavior
- ❌ Cross-execution state leakage (files/processes persisting between execs)
