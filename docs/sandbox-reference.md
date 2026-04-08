# Windows Sandbox Backend — Reference

Detailed reference for the sandbox backend internals. For the high-level design overview, see [sandbox.md](sandbox.md).

## IPC Protocol

### wxc-exec ↔ Daemon (line-based TCP)

The daemon listens on a localhost TCP port derived deterministically from the pipe name:

```rust
fn pipe_name_to_port(name: &str) -> u16 {
    let hash: u32 = name.bytes()
        .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    let range = 65535 - 49152;
    49152 + (hash % range) as u16
}
```

**Protocol:**
- Client → Daemon: `EXEC <json>\n`
- Daemon → Client: `RESULT <exit-code> <stdout-base64> <stderr-base64> <error-message>\n`
- Daemon → Client: `ERROR <message>\n`

### Daemon ↔ Agent (length-prefixed JSON over TCP)

4 TCP connections: control channel + stdin + stdout + stderr.

Control channel frame format: `[4 bytes: u32 LE length][JSON payload]`

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

## Daemon Lifecycle

### Startup

```
wxc-windows-sandbox-daemon.exe <pipe-name> <idle-timeout-ms>
```

Auto-launched by `wxc-exec` if not already running.

### Retry & Error Handling

| Attempt | Backoff | Action |
|---------|---------|--------|
| 1 | 0s | Launch sandbox, wait up to 120s for rendezvous |
| 2 | 10s | Teardown, cleanup, relaunch |
| 3 | 20s | Final attempt, propagate error |

### Teardown

1. Kills `WindowsSandbox.exe`, `WindowsSandboxServer`, `WindowsSandboxRemoteSession`
2. Polls for process exit (up to 30s)
3. 5s Hyper-V cooldown

## Debugging

```powershell
# Check rendezvous file
Get-Content "$env:TEMP\wxc-sandbox-rendezvous\rendezvous.txt"

# Check bootstrap log
Get-Content "$env:TEMP\wxc-sandbox-rendezvous\bootstrap.log"

# Check generated .wsb config
Get-Content "$env:TEMP\wxc-sandbox-config\wxc-sandbox.wsb"

# Check for zombie VM processes
Get-Process | Where-Object { $_.ProcessName -match "vmmem|vmwp|sandbox" }

# Run daemon manually (visible logs)
src\target\release\wxc-windows-sandbox-daemon.exe wxc-sandbox 300000
# In another terminal:
src\target\release\wxc-exec.exe --debug test_configs\basic_sandbox.json

# Clean slate
Get-Process -Name "wxc-windows-sandbox-daemon","WindowsSandbox*" -ErrorAction SilentlyContinue |
  ForEach-Object { Stop-Process -Id $_.Id -Force }
Start-Sleep 30
Remove-Item "$env:TEMP\wxc-sandbox-rendezvous\*" -ErrorAction SilentlyContinue
```

## Key Source Files

| File | Purpose |
|------|---------|
| `src/wxc_common/src/sandbox_runner.rs` | Client: connects to daemon, sends EXEC, reads RESULT |
| `src/wxc_common/src/sandbox_protocol.rs` | Shared control protocol |
| `src/wxc_windows_sandbox_daemon/src/main.rs` | Daemon entry point, idle watchdog |
| `src/wxc_windows_sandbox_daemon/src/pipe_server.rs` | TCP IPC server, EXEC handling, retry logic |
| `src/wxc_windows_sandbox_daemon/src/sandbox_vm.rs` | .wsb generation, Python discovery, VM launch/teardown |
| `src/wxc_windows_sandbox_daemon/src/rendezvous.rs` | Polls rendezvous.txt |
| `src/wxc_windows_sandbox_daemon/src/tcp_bridge.rs` | 4-channel TCP bridge, execute_on_guest, reconnect |
| `src/wxc_windows_sandbox_guest/src/main.rs` | Guest entry point |
| `src/wxc_windows_sandbox_guest/src/listener.rs` | TCP listener, rendezvous writer |
| `src/wxc_windows_sandbox_guest/src/executor.rs` | Command loop, stdio bridging |
| `src/wxc_windows_sandbox_guest/src/firewall.rs` | Guest firewall lockdown |

## E2E Tests

Manual-only — requires Hyper-V + Windows Sandbox feature (cannot run in GitHub CI).

### Running

```powershell
cd test_scripts
.\run_sandbox_tests.ps1 -Release
```

### Test Configs

| Config | Script | Validates |
|--------|--------|-----------|
| `sandbox_echo.json` | `echo Hello from sandbox!` | Boot, stdout relay |
| `basic_sandbox.json` | `python -S -B -c "..."` | Python mapping |
| `sandbox_powershell.json` | `powershell ... "PowerShell works"` | PowerShell |
| `sandbox_powershell_env.json` | `powershell ... $env:COMPUTERNAME` | VM isolation |
| `sandbox_stderr.json` | `echo stdout && echo stderr 1>&2` | stderr relay |
| `sandbox_exit_code.json` | `exit /b 42` | Exit codes |
| `sandbox_timeout.json` | `ping -n 30 127.0.0.1` (5s timeout) | Timeout |
| *(multi-exec)* | `sandbox_echo.json` × 3 | VM reuse |
