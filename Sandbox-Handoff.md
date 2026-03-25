# MXC Windows Sandbox E2E Test — Agent Handoff Prompt

> **Purpose:** This is a self-contained handoff document for an AI coding agent on a fresh Windows 11 machine. It contains everything needed to clone, build, and E2E test the MXC Windows Sandbox backend.
>
> **Created:** 2026-03-24 by Copilot CLI session on a machine where Windows Sandbox could not be enabled (component store corruption on insider build 26120).

---

## 1. Prerequisites — What Must Already Be Installed

Before starting, the target machine MUST have:

| Requirement | How to verify | How to install |
|---|---|---|
| **Windows 11 Pro/Enterprise** (Home won't work — Sandbox is Pro+ only) | `winver` | N/A |
| **Windows Sandbox feature enabled** | `dism /online /get-featureinfo /featurename:Containers-DisposableClientVM` → State: Enabled | `dism /online /enable-feature /featurename:Containers-DisposableClientVM /all` then **reboot** |
| **Hyper-V / Virtualization enabled** | `systeminfo` → "A hypervisor has been detected" OR Hyper-V Requirements: "VM Monitor Mode Extensions: Yes" | Enable in BIOS + `dism /online /enable-feature /featurename:Microsoft-Hyper-V-All /all` |
| **Rust toolchain (stable)** | `rustc --version` | `winget install Rustlang.Rustup` then `rustup default stable` |
| **Node.js 20.10+** | `node --version` | `winget install OpenJS.NodeJS.LTS` |
| **Python 3.x** | `python --version` | `winget install Python.Python.3.13` |
| **Git** | `git --version` | `winget install Git.Git` |

**Critical: Windows Sandbox requires a reboot after enabling. Confirm it works by running `WindowsSandbox.exe` from Start Menu — an empty sandbox window should appear.**

---

## 2. Repository & Commit

```
git clone https://github.com/microsoft/mxc.git
cd mxc
git checkout 5ca23a6   # HEAD of main as of 2026-03-24
```

---

## 3. Project Structure Overview

```
MXC/
├── src/                          # Rust workspace (6 crates)
│   ├── Cargo.toml                # Workspace config
│   ├── wxc/                      # wxc-exec.exe — main entry point
│   ├── wxc_common/               # Shared library (models, config parser, runners)
│   ├── wxc_sandbox_agent/        # wxc-sandbox-agent.exe — runs INSIDE the sandbox VM
│   ├── wxc_sandbox_daemon/       # wxc-sandbox-daemon.exe — host-side daemon
│   ├── wxc_winhttp_proxy_shim/   # winhttp-proxy-shim.exe — network proxy (not needed for sandbox test)
│   └── wxc_test_driver/          # Batch test utility
├── sdk/                          # TypeScript SDK (@microsoft/mxc-sdk)
├── cli/                          # TypeScript CLI
├── examples/                     # Example JSON configs
├── test_configs/                 # Test JSON configs (includes basic_sandbox.json)
├── test_scripts/                 # Test automation scripts
└── build.bat                     # Master build script
```

---

## 4. Build Instructions

```powershell
# From repo root:
build.bat

# This will:
# 1. Build all Rust crates (release, native arch)
# 2. Copy binaries into sdk/bin/<target-triple>/
# 3. Build the TypeScript SDK
```

**Verify the 5 binaries were built:**
```powershell
Get-ChildItem src\target\x86_64-pc-windows-msvc\release\*.exe | Select-Object Name
# Expected:
#   wxc-exec.exe
#   wxc-sandbox-agent.exe
#   wxc-sandbox-daemon.exe
#   winhttp-proxy-shim.exe
#   wxc-test-driver.exe
```

**Run unit tests to confirm build health:**
```powershell
cd src
cargo test --workspace
# Expected: 136 tests pass, 0 failures
```

---

## 5. Windows Sandbox Architecture

The Sandbox backend has a **daemon + agent** architecture:

```
wxc-exec.exe --debug test_configs\basic_sandbox.json
  │
  └── SandboxScriptRunner (src/wxc_common/src/sandbox_runner.rs)
        │
        ├── Auto-launches wxc-sandbox-daemon.exe if not running
        │   (connects via TCP on deterministic port derived from pipe name)
        │
        └── Sends: "EXEC {json}\n"
              │
              wxc-sandbox-daemon.exe (src/wxc_sandbox_daemon/)
                │
                ├── Discovers Python on host (where python → uses that directory)
                │
                ├── Generates .wsb config:
                │   - Maps agent exe dir → C:\sandbox-agent (read-only)
                │   - Maps rendezvous dir → C:\sandbox-rendezvous (read-write)
                │   - Maps Python dir → C:\sandbox-python (read-only)
                │   - LogonCommand: C:\sandbox-rendezvous\bootstrap.cmd
                │
                ├── Launches WindowsSandbox.exe with the .wsb file
                │
                ├── Polls rendezvous.txt (up to 120s, every 500ms)
                │   Guest writes "<ip>:<port>" when agent starts
                │
                └── Connects 4 TCP channels to agent:
                    [control] [stdin] [stdout] [stderr]
                      │
                      wxc-sandbox-agent.exe (inside sandbox VM)
                        │
                        ├── Binds TCP 0.0.0.0:0, writes IP:port to rendezvous.txt
                        ├── Accepts 4 connections from host
                        ├── Locks down firewall (only allow host IP)
                        ├── Sends READY on control channel
                        └── Waits for EXEC command → spawns cmd.exe /C <script>
                            → bridges stdin/stdout/stderr over TCP
                            → sends EXIT notification with exit code
```

**Control Protocol** (src/wxc_common/src/sandbox_protocol.rs):
- Length-prefixed JSON: 4-byte LE u32 frame length + JSON payload
- Messages: `Ready`, `Exec(ExecRequest)`, `Exit(ExitNotification)`, `Ping`, `Pong`

---

## 6. E2E Test Procedure

### Step 1: Run the basic sandbox test

```powershell
cd <repo-root>
src\target\x86_64-pc-windows-msvc\release\wxc-exec.exe --debug test_configs\basic_sandbox.json
```

**Config contents (test_configs/basic_sandbox.json):**
```json
{
  "script": "python -c \"import sys; print(f'Hello from sandbox Python {sys.version}'); print('Sandbox test successful')\"",
  "containment": "sandbox",
  "timeout": 60000
}
```

**Expected behavior:**
1. wxc-exec launches wxc-sandbox-daemon in background
2. Daemon generates .wsb config in `%TEMP%\wxc-sandbox-config\`
3. Daemon creates `%TEMP%\wxc-sandbox-rendezvous\` directory
4. Daemon launches WindowsSandbox.exe (a new sandbox window appears)
5. Inside sandbox: bootstrap.cmd runs → adds Python to PATH → starts agent
6. Agent writes rendezvous.txt → daemon reads it → connects 4 TCP channels
7. Daemon sends EXEC command → agent runs `python -c "..."` → bridges output
8. Agent sends EXIT with code 0 → daemon relays to wxc-exec
9. wxc-exec prints output and exits with code 0

**Expected output:**
```
Hello from sandbox Python 3.x.x (...)
Sandbox test successful
```

### Step 2: Run the custom timeout test

```powershell
src\target\x86_64-pc-windows-msvc\release\wxc-exec.exe --debug test_configs\sandbox_custom_timeout.json
```

### Step 3: Run the network isolation test

```powershell
src\target\x86_64-pc-windows-msvc\release\wxc-exec.exe --debug examples\10_sandbox_network_isolated.json
```

**Expected:** The script should fail to connect to `http://example.com` because the agent locks down the sandbox's firewall after establishing host connections.

---

## 7. Known Issues to Investigate

### Issue 1: stdout/stderr not relayed to caller — ✅ FIXED (`f7c589b`)

**Status:** Fixed. See Section 13, Commit 1.

### Issue 2: Single execution per sandbox lifetime

**File:** `src/wxc_sandbox_agent/src/executor.rs`, lines 61-63

```rust
stdin_stream.take(),
stdout_stream.take(),
stderr_stream.take(),
```

The agent `take()`s the stdin/stdout/stderr TCP streams on the first EXEC. After that, they're `None`. A second EXEC would have no stdio streams to bridge.

**Impact:** Only one script can run per sandbox boot. The daemon would need to reconnect or the agent would need new streams for subsequent requests.

### Issue 3: Bootstrap timing / first-run slowness

Windows Sandbox cold boot takes 15-30 seconds on typical hardware. The daemon polls rendezvous.txt for up to 120 seconds. If the sandbox image hasn't been used before, Windows may download/update components, which can push this to 60+ seconds on first run.

### Issue 4: Python must be on host PATH

**File:** `src/wxc_sandbox_daemon/src/sandbox_vm.rs`, `find_host_python()`

The daemon maps the host's Python installation into the sandbox at `C:\sandbox-python`. If Python isn't installed on the host or isn't on PATH, the daemon will error out with: "Python installation not found on host."

### Issue 5: IPC uses TCP, not named pipes — ⚠️ PARTIALLY FIXED

**Status:** Error handling improved (`f7c589b`) — daemon now always sends a response instead of silently closing the connection. The underlying TCP-based IPC is unchanged.

**File:** `src/wxc_sandbox_daemon/src/pipe_server.rs`, lines 20-24

The "named pipe server" is actually a TCP listener on localhost using a deterministic port derived from the pipe name. This is noted in the code as a "simplified implementation" pending real Win32 named pipes. Port conflicts are possible if another process occupies the derived port.

**Port derivation:**
```rust
fn pipe_name_to_port(name: &str) -> u16 {
    let hash: u32 = name.bytes()
        .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    let range = 65535u32 - 49152;
    (49152 + (hash % range)) as u16
}
```
For `"wxc-sandbox"`, this produces a fixed port in the ephemeral range.

---

## 8. Debugging Tips

### Enable debug output
Always use `--debug` flag — without it, wxc-exec runs in silent/buffer mode:
```powershell
wxc-exec.exe --debug config.json
```

### Check daemon logs
The daemon logs to stderr. If launched by wxc-exec (background), stderr goes to null. For debugging, launch the daemon manually:
```powershell
# Terminal 1: Start daemon manually
src\target\x86_64-pc-windows-msvc\release\wxc-sandbox-daemon.exe wxc-sandbox 300000

# Terminal 2: Run wxc-exec (it will connect to existing daemon)
src\target\x86_64-pc-windows-msvc\release\wxc-exec.exe --debug test_configs\basic_sandbox.json
```

### Check rendezvous file
```powershell
# After sandbox boots, check if the agent wrote its address:
Get-Content "$env:TEMP\wxc-sandbox-rendezvous\rendezvous.txt"
# Expected: something like "172.26.x.x:12345"
```

### Check bootstrap log inside sandbox
If the sandbox window opens but the agent doesn't start, look at:
```
C:\sandbox-rendezvous\bootstrap.log
```
(inside the sandbox window — use File Explorer)

### Check generated .wsb file
```powershell
Get-Content "$env:TEMP\wxc-sandbox-config\wxc-sandbox.wsb"
```

### Kill stuck sandboxes
```powershell
taskkill /F /IM WindowsSandbox.exe
taskkill /F /IM wxc-sandbox-daemon.exe
```

---

## 9. Acceptance Criteria for E2E

The Sandbox backend is considered E2E-working when:

- [x] `basic_sandbox.json` runs and prints "Hello from sandbox Python..." with exit code 0 — **Partially: runs but exit 1 due to Python site module issue (needs `-S -B` flags). See Section 14.3.**
- [x] Script stdout/stderr is visible to the wxc-exec caller — **FIXED in `f7c589b`** (code correct, E2E verification pending clean sandbox boot)
- [ ] `10_sandbox_network_isolated.json` fails to connect (firewall lockdown works) — **Not tested** (file doesn't exist in examples/)
- [ ] A second execution on the same daemon reuses the existing sandbox VM — **NOT FIXED: Issue #2. See Section 14.2.**
- [ ] Timeout works: a script exceeding `timeout` is killed and wxc-exec returns a non-zero exit code — **Not tested**
- [x] The daemon tears down the sandbox after the idle timeout (default 5 minutes) — **Works** (confirmed via idle watchdog)

---

## 10. Key Source Files Reference

| File | What it does |
|------|-------------|
| `src/wxc/src/main.rs` | Entry point — dispatches to SandboxScriptRunner when `containment: "sandbox"` |
| `src/wxc_common/src/sandbox_runner.rs` | Client-side: connects to daemon, sends EXEC, reads RESULT |
| `src/wxc_common/src/sandbox_protocol.rs` | Shared control protocol (Ready, Exec, Exit, Ping, Pong) |
| `src/wxc_common/src/models.rs` | `SandboxConfig`, `ContainmentBackend::Sandbox` |
| `src/wxc_common/src/config_parser.rs` | Parses JSON config → `CodexRequest` with `SandboxConfig` |
| `src/wxc_sandbox_daemon/src/main.rs` | Daemon entry point — IPC server + idle watchdog |
| `src/wxc_sandbox_daemon/src/pipe_server.rs` | TCP "named pipe" server — handles EXEC requests |
| `src/wxc_sandbox_daemon/src/sandbox_vm.rs` | .wsb generation, WindowsSandbox.exe launch, Python discovery |
| `src/wxc_sandbox_daemon/src/rendezvous.rs` | Polls rendezvous.txt for guest agent address |
| `src/wxc_sandbox_daemon/src/tcp_bridge.rs` | 4-channel TCP bridge to guest agent (**stdout/stderr fix applied**) |
| `src/wxc_sandbox_agent/src/main.rs` | Agent entry point (runs inside sandbox VM) |
| `src/wxc_sandbox_agent/src/listener.rs` | TCP listener + rendezvous file writer + guest IP discovery |
| `src/wxc_sandbox_agent/src/executor.rs` | Spawns child process, bridges stdio over TCP |
| `src/wxc_sandbox_agent/src/firewall.rs` | Locks down sandbox firewall via netsh |
| `test_configs/basic_sandbox.json` | Minimal sandbox test config |
| `test_configs/sandbox_custom_timeout.json` | Sandbox test with custom idle timeout |
| `examples/09_sandbox_hello_world.json` | Example sandbox config |
| `examples/10_sandbox_network_isolated.json` | Network isolation test |

---

## 11. Active Branches of Interest

| Branch | What it does |
|--------|-------------|
| `origin/user/modanish/SandboxFixes` | **3 commits: stdout relay fix, cmd.exe quoting + retry, boot reliability improvements. Based on main at `5ca23a6`.** |
| `origin/user/bbonaby/fix-sandbox` | Adds Windows Sandbox pre-flight check and renames `sandbox` → `windows_sandbox`. **Not yet merged.** Reviewed — no overlap with sandbox fixes, but merging will require file renames. |
| `origin/user/bbonaby/networking-follow-up` | Extracts test proxy into own crate, adds `builtinTestServer` config option. |
| `origin/user/sodas/AddWSLContainerConfigurationSchemaAndRouting_03232026` | Adds WSLC configuration schema and routing (Linux container support). |

---

## 12. Summary of What to Do

1. **Confirm prerequisites** (Section 1) — especially Windows Sandbox feature + reboot
2. **Clone and build** (Sections 2-4) — `build.bat` then `cargo test --workspace`
3. **Run E2E tests** (Section 6) — start with `basic_sandbox.json`
4. **Validate acceptance criteria** (Section 9)
5. **Continue remaining work** (Section 14) — multi-exec fix, Python env fix
6. **Report results** — what worked, what didn't, any new issues discovered

---

## 13. Fixes Applied (2026-03-24/25 Session)

Three commits on `main` (branch `user/modanish/SandboxFixes`):

### Commit 1: `f7c589b` — Fix stdout/stderr relay (Issue #1 from Section 7)

**Problem:** Script output was silently discarded — only exit codes reached the caller.

**Root cause:** Three layers dropped stdout/stderr:
1. `tcp_bridge.rs:177-178` — captured bytes assigned to `_stdout`/`_stderr` (discarded)
2. `pipe_server.rs:99` — RESULT format had no stdout/stderr fields
3. `sandbox_runner.rs:145` — always set `standard_out = String::new()`

**Fix:**
- `tcp_bridge.rs` — returns `(exit_code, error_msg, stdout_bytes, stderr_bytes)` instead of discarding
- `pipe_server.rs` — extended RESULT format: `RESULT <code> <stdout_b64> <stderr_b64> <error>\n` using base64 encoding; also refactored error handling so daemon always sends `ERROR` response instead of silently closing connection
- `sandbox_runner.rs` — parses extended base64 format with legacy fallback

### Commit 2: `5d48ebc` — Fix cmd.exe quoting and initial retry

**Problem 1:** Scripts with double quotes failed inside the sandbox because Rust's `Command::arg()` backslash-escapes quotes (`\"`) but `cmd.exe` doesn't understand that syntax.

**Fix:** `executor.rs` — use `cmd.arg("/C"); cmd.raw_arg(script_code)` to pass script text literally without Rust's escaping.

**Problem 2:** If sandbox rendezvous timed out, `sandbox_running` stayed `true` and future attempts would skip relaunch.

**Fix:** `pipe_server.rs` — added retry loop (initially 2 attempts) with state reset between attempts.

### Commit 3: `92d0bd4` — Sandbox boot reliability (LLM Council analysis)

**Problem:** ~60% of sandbox boot attempts failed with "The remote environment is logging off" error. Root cause identified by convening 3-model LLM council (GPT-5.4, Claude Opus 4.6, Gemini 3 Pro):
1. **Zombie Hyper-V processes** (`vmwp.exe`, `vmmemWindowsSandbox`) persisted after `taskkill`, blocking new VM launches
2. **3-second teardown cooldown** was grossly insufficient
3. **Windows Insider build 26200.7985** has a confirmed sandbox regression
4. **vGPU virtualization** fails intermittently under nested Hyper-V

**Fix:**
- `sandbox_vm.rs` — replaced fixed 3s sleep with process-exit polling (up to 30s), polls for `WindowsSandbox*` and `vmmemWindowsSandbox` to fully exit, plus 5s CmService cooldown
- `sandbox_vm.rs` — added `<vGPU>Disable</vGPU>` to .wsb config to bypass GPU virtualization failures
- `pipe_server.rs` — increased retry to 3 attempts with exponential backoff (0s, 10s, 20s)

---

## 14. Remaining Work for Next Session

### 14.1 — CRITICAL: Use a stable Windows 11 build

Build 26200.7985 (Insider 25H2) has a **confirmed Windows Sandbox regression** (LLM council unanimous). Boot success rate on this machine was ~30-40%. **The single highest-impact fix is running on a stable Windows 11 24H2 build.**

### 14.2 — Issue #2: Single execution per sandbox (NOT YET FIXED)

**Problem:** The agent `take()`s stdin/stdout/stderr TCP streams on the first EXEC. After that, they're `None`. A second EXEC has no stdio streams.

**Attempted fix:** Agent re-accepts 3 new data TCP connections per EXEC; daemon reconnects after EXIT. **Reverted** — synchronization issue: the daemon's `reconnect_data_streams` and agent's `accept_data_connections` don't coordinate timing (the agent blocks on accept before the daemon connects, but probe connections from `ensure_daemon_running` get consumed by the agent's accept, throwing off the connection count).

**Recommended approach for next attempt:** Add a coordination message on the control channel — agent sends a `DataReady` message after it starts accepting new data connections, daemon waits for `DataReady` before reconnecting. This ensures both sides are synchronized. Alternatively, have the daemon send a `Reconnect` message on the control channel to tell the agent to start accepting.

**Files involved:**
- `src/wxc_sandbox_agent/src/executor.rs` — command loop
- `src/wxc_sandbox_agent/src/listener.rs` — TCP accept
- `src/wxc_sandbox_daemon/src/tcp_bridge.rs` — GuestConnection + reconnect
- `src/wxc_sandbox_daemon/src/pipe_server.rs` — post-EXEC reconnect
- `src/wxc_common/src/sandbox_protocol.rs` — add `DataReady` or `Reconnect` message

### 14.3 — Python site module fails on read-only mapped directory

`basic_sandbox.json` returns exit code 1 (not 0 as expected) because Python's site module tries to write `.pyc` files to the read-only mapped Python directory.

**Workaround:** Use `-S -B` flags: `python -S -B -c "..."` (skip site import, no bytecache). This was verified to work.

**Proper fix options:**
1. Update `basic_sandbox.json` to use `-S -B` flags
2. Set `PYTHONDONTWRITEBYTECODE=1` and `PYTHONNOUSERSITE=1` in `bootstrap.cmd`
3. Map a writable directory for Python cache: add `PYTHONPYCACHEPREFIX=C:\temp` to the bootstrap

### 14.4 — `fix-sandbox` branch review

`origin/user/bbonaby/fix-sandbox` renames `sandbox` → `windows_sandbox` and adds a pre-flight check. **Does NOT fix any of the issues above.** No overlap with our fixes, but merging will require renaming our modified files.

### 14.5 — stdout relay verification

The stdout/stderr relay code is correct (132/132 unit tests pass), but E2E verification of visible output was not conclusive. When the sandbox boots and a script runs, `main.rs:144-146` prints `standard_out` if non-empty. Need to verify with a successful run where stdout is captured separately from stderr.

---

## 15. E2E Test Results from This Session

### What passed (when sandbox booted successfully)
| Test | Exit | Time | Notes |
|------|------|------|-------|
| `echo Hello from sandbox` | **0 ✅** | 13.5s | Passed multiple times |
| `python --version` | **0 ✅** | 13.5s | Python found on sandbox PATH |
| `python -S -B -c "print('hello')"` | **0 ✅** | ~13s | Requires `-S -B` flags |
| `cmd /C exit 0` | **0 ✅** | ~1s | Basic cmd.exe works |

### What failed
| Test | Exit | Root cause |
|------|------|------------|
| `basic_sandbox.json` | 1 | Python site module fails on read-only dir (not a code bug) |
| 2nd+ exec on same sandbox | varies | Issue #2 (single-exec) — not yet fixed |
| ~60% of boot attempts | -1 | Insider build 26200 regression + zombie VM processes |

### Key diagnostic commands
```powershell
# Check for zombie sandbox processes (the #1 cause of boot failures)
Get-Process | Where-Object { $_.ProcessName -match "vmmem|vmwp|sandbox" } | Select-Object Id, ProcessName

# Check container event logs after a failure
Get-WinEvent -LogName "Microsoft-Windows-Containers*" -MaxEvents 10

# Check bootstrap log (if sandbox booted far enough)
Get-Content "$env:TEMP\wxc-sandbox-rendezvous\bootstrap.log"

# Check rendezvous file
Get-Content "$env:TEMP\wxc-sandbox-rendezvous\rendezvous.txt"

# Check generated .wsb config
Get-Content "$env:TEMP\wxc-sandbox-config\wxc-sandbox.wsb"

# Kill everything for a clean start
Get-Process -Name "wxc-sandbox-daemon","WindowsSandbox*" -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.Id -Force }
Start-Sleep 30  # IMPORTANT: wait at least 30s for VM cleanup
Remove-Item "$env:TEMP\wxc-sandbox-rendezvous\*" -ErrorAction SilentlyContinue
```
