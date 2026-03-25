# MXC NanVix Integration — Design Document

## Problem

MXC (Microsoft eXecution Container) runs untrusted code in sandboxed environments. Today it supports two backends: **AppContainer** (process-level isolation on the host) and **Windows Sandbox** (full VM via a long-lived sandbox daemon).

There is a need for a **fast, hardware-isolated execution backend** that can execute Python scripts with full stdlib support.

## Proposed Solution

Add a **NanVix backend** directly into the existing `wxc-exec.exe` binary. When the JSON config specifies `"containment": "nanvix"`, the binary routes to a new `NanVixScriptRunner`. The runner spawns `nanvixd.exe` (the NanVix daemon), pipes the Python script via stdin, and captures stdout/stderr — eliminating the need for command-line argument parsing or file injection.

**NanVix** is a lightweight microkernel OS that runs inside a WHP (Windows Hypervisor Platform) virtual machine. It provides POSIX-compatible process execution with hardware-enforced isolation. It runs a cross-compiled CPython 3.12 interpreter with a trimmed FAT32 stdlib filesystem.

## How It Works

```
Path A — CLI (direct):
  User: wxc-exec.exe config.json
    └── Parses args → loads JSON → dispatches to NanVixScriptRunner

Path B — SDK (programmatic):
  App calls: spawnSandbox("print('hello')", policy, { containment: "nanvix" })
    ├── Builds JSON config with containment = "nanvix"
    └── Spawns wxc-exec.exe with the config

Both paths converge here:
  wxc-exec.exe
    ├── Parses JSON config → sees containment = "nanvix"
    ├── Creates NanVixScriptRunner (via existing Box<dyn ScriptRunner> dispatch)
    ├── Validates paths: nanvixd.exe, bin_dir, ramfs, python.elf
    ├── Spawns nanvixd.exe as child process:
    │     nanvixd.exe -bin-dir <dir> -ramfs <ramfs.img>
    │       -- python.elf "-S -B -c exec(__import__('sys').stdin.read());PYTHONHOME=/sysroot"
    ├── Spawns stdout/stderr reader threads (before stdin write — avoids deadlock)
    ├── Writes script_code to stdin, closes stdin (EOF signal)
    ├── Starts watchdog thread (Condvar-based, DuplicateHandle for safe kill)
    ├── Waits for process exit or timeout
    ├── Signals watchdog to cancel, joins all threads
    └── Returns ScriptResponse { exit_code, standard_out, standard_err }

Inside the NanVix VM:
  nanvixd.exe boots a WHP virtual machine:
    ├── Loads kernel.elf (NanVix microkernel)
    ├── Loads python.elf as initrd payload
    ├── Maps cpython-ramfs.img (FAT32 stdlib) into guest memory
    ├── Kernel splits cmdline on ';':
    │     argv = ["python.elf", "-S", "-B", "-c", "exec(__import__('sys').stdin.read())"]
    │     env  = ["PYTHONHOME=/sysroot"]
    ├── Python reads ALL stdin → exec() runs the script
    ├── Script output → stdout (via IKC) → host stdout
    ├── Kernel traces → host stderr
    └── sys.exit(N) → nanvixd exits N (exit code propagated)
```

## Architecture:

```
                    wxc-exec.exe
                          │
                   config_parser.rs
                   reads "containment" field
                          │
           ┌──────────────┼──────────────┐
           │              │              │
  AppContainerScript  Sandbox       NanVix
  Runner (existing)   ScriptRunner  ScriptRunner (new)
           │          (existing)         │
     AppContainer         │         Spawn nanvixd.exe
     NTFS ACLs       Windows        ├── Pipe stdin
     WFP firewall    Sandbox VM     └── Capture stdout/stderr
```

## Stdin Piping Approach

### [Draft] Why Stdin (Not -c, Not Base64, Not File Injection)

NanVix has two constraints that prevent passing scripts via command-line arguments:

1. **Space-splitting**: The POSIX runtime (`nvx/src/lib.rs:build_string_table()`) replaces every space with a null byte. No quoting support. `print('Hello World')` becomes two argv entries.

2. **255-byte cmdline limit**: The VMM uses a `u8` length prefix (`guest.rs:write_args()`). Maximum 255 bytes for the entire argument string including program name and environment variables.

Stdin piping bypasses both constraints with zero code changes to CPython, NanVix, or nanvixd:

| Approach | Spaces | Length | CPython Changes | NanVix Changes |
|----------|--------|--------|-----------------|----------------|
| **Stdin pipe** ✅ | ✅ None | ✅ None | ✅ None | ✅ None |
| Base64 env var | ✅ OK | ❌ ~150B usable | ❌ C decoder | None |
| Quoting in runtime | ✅ OK | ❌ 255B limit | None | ❌ Unsafe Rust |
| Ramfs file injection | ✅ OK | ✅ None | None | Moderate |


## Error Handling & Output Semantics

### Output Separation

stdout contains only script output; stderr contains only kernel traces.

### Exit Code Propagation

`sys.exit(42)` inside the guest → `nanvixd.exe` exits with code 42. The runner maps this directly to `ScriptResponse.exit_code`.

### Error Classification

The runner classifies errors using a `NanVixError` enum, allowing consumers to match on error types:

```rust
enum NanVixError {
    Preflight(String),   // Missing binaries, invalid paths
    Platform(String),    // WHP unavailable, spawn failure
    Runtime(String),     // Stdin broken pipe, VM crash
    Timeout {            // Watchdog killed the process
        boot_timeout_ms: u32,
        script_timeout_ms: u32,
        total_ms: u64,
    },
}
```

| Variant | Trigger | Example |
|---------|---------|---------|
| `Preflight` | Path validation before spawn | `nanvixd not found at /path/to/nanvixd.exe` |
| `Platform` | `Command::new()` fails | `Failed to spawn nanvixd: The system cannot find the file specified` |
| `Runtime` | Stdin write or process error | `Failed to write script to nanvixd stdin: Broken pipe` |
| `Timeout` | Watchdog fires | `NanVix execution timed out after 90000ms` |

All variants are mapped to `ScriptResponse.error_message` for the JSON response.

## Configuration Semantics

### JSON Config Format

```json
{
  "script": "print('Hello from NanVix!')",
  "containment": "nanvix",
  "timeout": 30000,
  "nanvix": {
    "nanvixdPath": "C:\\nanvix\\bin\\nanvixd.exe",
    "binDir": "C:\\nanvix\\bin",
    "ramfsPath": "C:\\nanvix\\bin\\cpython-ramfs.img",
    "pythonBinary": "python.elf",
    "pythonHome": "/sysroot",
    "bootTimeout": 60000
  }
}
```

### Config Field Mapping

| Field | NanVix Behavior |
|-------|----------------|
| `script` | ✅ **Honored** — raw Python source code |
| `timeout` | ✅ **Honored** — script execution timeout in ms |
| `containment` | ✅ **Honored** — must be `"nanvix"` |
| `nanvix.*` | ✅ **Honored** — NanVix-specific configuration |
| `workingDirectory` | ⚠️ **Ignored** — guest has its own filesystem namespace |
| `appContainer.*` | ⚠️ **Ignored** — not applicable to NanVix |
| `filesystem.*` | ⚠️ **Ignored** — guest FS is a read-only ramfs |
| `network.*` | ⚠️ **Ignored** — no network stack in guest |
| `sandbox.*` | ⚠️ **Ignored** — NanVix is not Windows Sandbox |

**Note on `script` field**: For NanVix, `script` contains **raw Python source code** (e.g., `"print('hello')"`), not a shell command (e.g., `"python -c \"print('hello')\""`). The runner handles interpreter invocation internally.

### [Draft] NanVixConfig Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `nanvixdPath` | String | Auto-discover | Path to `nanvixd.exe` |
| `binDir` | String | Same dir as nanvixd | Directory with `kernel.elf` |
| `ramfsPath` | String | Required | Path to FAT32 stdlib image |
| `pythonBinary` | String | `"python.elf"` | Python binary name (relative to binDir) |
| `pythonHome` | String | `"/sysroot"` | `PYTHONHOME` inside the guest |
| `bootTimeout` | u32 | `60000` | Boot grace period in ms |

### Path Resolution

`nanvixd.exe` is discovered in order:
1. Explicit `nanvixdPath` from config
2. `binDir/nanvixd.exe`
3. Next to `wxc-exec.exe`

## [Draft] Binary Distribution & Versioning

NanVix artifacts (~45 MB total) will be bundled in the MXC npm package.

| Artifact | Size | Source |
|----------|------|--------|
| `nanvixd.exe` | 7.5 MB | [nanvix/nanvix](https://github.com/nanvix/nanvix) releases |
| `kernel.elf` | 10.5 MB | [nanvix/nanvix](https://github.com/nanvix/nanvix) releases |
| `python.elf` | 9.1 MB | [nanvix/cpython](https://github.com/nanvix/cpython) releases |
| `cpython-ramfs.img` | 35.6 MB | [nanvix/cpython](https://github.com/nanvix/cpython) releases |

## Security Model

### Isolation Comparison

| Property | AppContainer | Windows Sandbox | NanVix |
|----------|-------------|-----------------|--------|
| **Isolation level** | Process | Full VM (Hyper-V) | Micro VM (WHP) |
| **Host FS access** | Restricted by ACLs | Mapped folders only | None (read-only ramfs) |
| **Network access** | Filtered by firewall | NAT/bridged | None |
| **Writable storage** | Host FS (restricted) | VM disk | None (read-only) |
| **Guest OS** | Windows (host) | Windows (guest) | NanVix microkernel |

### [Draft] Host-Side Risk

`nanvixd.exe` parses I/O from the guest via IKC (Inter-Kernel Communication) messages. A crafted guest could attempt to send malformed messages. The IKC protocol uses fixed-size frames with bounds checking. Formal fuzzing is will be added.

### [Draft] Artifact Integrity

Guest artifacts (`python.elf`, `kernel.elf`, `cpython-ramfs.img`) are loaded from disk. If an attacker can modify these files, they control the guest. Mitigation: store artifacts in read-only locations, or add hash verification will be added.

## Timeout, Lifecycle & Resource Limits

### Timeout Semantics

```
total_timeout = boot_timeout_ms + script_timeout
              = 60,000 + 30,000
              = 90,000 ms (90 seconds)
```

- `boot_timeout_ms` (default 60s): Grace period for VM boot + Python init
- `script_timeout` (from JSON `timeout` field): Script execution time

### Watchdog

A background watchdog thread monitors the `nanvixd.exe` process. If the total timeout expires, the watchdog terminates the process and the runner returns an error response with the partial stdout/stderr captured so far.

### Cleanup Guarantee

On normal exit, timeout, or crash:
- Reader threads joined (stdout/stderr fully captured)
- Watchdog thread cancelled and joined
- `nanvixd.exe` termination releases the WHP partition

### Concurrency

Multiple NanVix executions can run concurrently. Each `nanvixd.exe` spawns an independent WHP virtual machine partition. There are no port conflicts, file locks, or shared state. Concurrency is limited only by host RAM (~128 MB per VM default).

## Testing Strategy

### Unit Tests

| Test | What It Validates |
|------|------------------|
| `default_config_values` | NanVixConfig defaults (python.elf, /sysroot, 60s) |
| `total_timeout_adds_boot_and_script` | Timeout arithmetic |
| `resolve_nanvixd_missing_returns_error` | Path resolution error handling |
| Config parser: `"nanvix"` containment | JSON parsing of nanvix section |

### Integration Tests (requires WHP + NanVix binaries)

| Test | What It Validates |
|------|------------------|
| Hello world | Basic stdin → stdout pipeline |
| Script with spaces | Stdin piping bypasses space-splitting |
| Exit code propagation | `sys.exit(42)` → exit code 42 |
| Missing nanvixd | Preflight error message |
| Timeout | Watchdog kills after deadline |
| Large script | >255 bytes (exceeds cmdline limit) |

## Open Design Questions

| # | Question | Status |
|---|----------|--------|
| 1 | Can NanVix VMs be pooled/warm-started? |  |
| 2 | Should there be a size limit to the VM |  |
| 3 | Should there be a writable FS area in the guest? | Parked for Phase 2 |
| 4 | Can we support TypeScript or other payloads? | Architecture supports it — NanVix can run any i686 ELF |
