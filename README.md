# Microsoft eXecution Container (MXC)

MXC is a sandboxed code execution environment.  It currently implements WXC for Windows that uses AppContainer to run untrusted code safely.  We will be adding support for VMs, WSL and other platforms shortly.

## Features

- **JSON-based Configuration**: Define script code, security policies, and execution parameters in JSON
- **Multiple Execution Modes**: Choose container security properties independent of containment and isolation policies
    - **File System Policy**: Explicitly allow or deny access to specific paths with file system policy
    - **Network Policy**: Control network access with allow/block lists and firewall rules
- **Container Capabilities**: Fine-grained control over OS capabilities (network, registry, etc.)
- **Tracing**: Debugging modes with Event Tracing for Windows (ETW) to diagnose security policies

## Building

MXC is a container wrapper and a TypeScript based SDK for Node/Electron projects.  It is currently supported only on Windows 11 based machines (x64/ARM64).

### Requirements

You will need the [Rust toolchain](https://rustup.rs/) (stable) installed.  The MXC native components are built with Cargo, the Rust package manager and build system.

You will also need Node.js 20.10+ and must ensure that the node dependencies are resolved.  We recommend going into the SDK folder and running npm install.

A copy of Python 3.x is needed for executing test scripts.

### Project Structure

```
src/            Rust workspace (wxc-exec native binary + wxc_common library)
sdk/            TypeScript SDK (@microsoft/mxc-sdk npm package)
docs/           Schema and configuration documentation
examples/       Example configurations
test_configs/   Test JSON configurations
test_scripts/   Test scripts for exercising MXC
```

### Building WXC

The easiest way to build everything is with `build.bat` from the repo root:

```bash
build.bat              # Release build for your machine's architecture
build.bat --debug      # Debug build for your machine's architecture
build.bat --all        # Release build for both x64 and ARM64
build.bat --help       # Show all options
```

This will:
1. Build the Rust `wxc-exec.exe` binary for the selected architecture(s)
2. Copy the binary into `sdk/bin/<target-triple>/` so it is bundled with the SDK package
3. Build the TypeScript SDK

#### Building components individually

To build just the Rust workspace:

```bash
cd src
cargo build --release --target x86_64-pc-windows-msvc    # x64
cargo build --release --target aarch64-pc-windows-msvc   # ARM64
```

This produces `wxc-exec.exe` in `src/target/<target-triple>/release/`.

For the SDK npm library:

```bash
cd sdk
npm install && npm run build
```

> **Note:** If building the SDK separately, you must first copy `wxc-exec.exe` into
> `sdk/bin/<target-triple>/` for it to be included in the npm package.

## Usage

MXC requires a JSON-based configuration to be provided.  The [schema documentation](docs\schema.md) defines all of the policies and execution options.

### 1. File Path
```bash
wxc-exec.exe [--config] config.json
```

### 2. Base64-Encoded JSON Argument
```bash
wxc-exec.exe --config-base64 <base64-encoded-json>
```

The base64 mode is useful for:
- Programmatic execution where creating temporary files is inconvenient
- CI/CD pipelines
- Security scenarios where configuration files shouldn't persist on disk
- Testing and automation

## Debugging

### Debug Console Mode

By default, `wxc-exec` runs in **silent mode** with no console output of its own.  It is designed to couple the stdin/stdout/stderr of the caller to the container.  Use the `--debug` flag to enable verbose console output:

```bash
# Silent execution (default) - no console output
wxc-exec.exe config.json

# Verbose execution with debug output
wxc-exec.exe --debug config.json
```

### Using ETW Traces

For troubleshooting AppContainer isolation, you can use Event Tracing for Windows (ETW) to capture access check events.  We recommend the use of the [Windows Performance Analyzer](https://apps.microsoft.com/detail/9n0w1b2bxgnz?launch=true&mode=full&hl=en-us&gl=us) and the XPerf tool.

#### Start Tracing

Start an administrator PowerShell console, then run:

```powershell
# Enables Kernel Trace. 
# Only saves Process/Thread Create/Delete and Image Load/Unload Events
# Required to interpret stack traces
xperf -on PROC_THREAD+LOADER
# Start Tracing AppContainer Events
xperf -start user -on a68ca8b7-004f-d7b6-a698-07e2de0f1f5d:::'stack'
```

### Run wxc-exec

Execute your script with AppContainer in permissive learning mode:

```json
{
  "script": "your_code_here",
  "processContainer": {
    "capabilities": ["permissiveLearningMode"]
  }
}
```

### Stop Tracing

When execution completes:

```powershell
# Stop user trace
xperf -stop user
# Stop kernel trace
xperf -stop
# Merge User and Kernel traces. 
# Merging also grabs some system info required to interpret the traces
# Traces are saved to C:\ root by default
xperf -merge user.etl kernel.etl merged.etl
```

### `--audit` Flag

The `wxc` CLI supports an `--audit` flag that automates the start/stop tracing flow above using PowerShell helpers in [`src/learning_mode/`](src/learning_mode/readme.md).

When `--audit` is passed:

1. `permissiveLearningMode` is appended to the container's capability list and `request.audit_mode` is set, so the AppContainer runs in audit (non-blocking) mode and the profiler can observe all file accesses. The `appcontainer_runner` normally rejects `permissiveLearningMode` in release builds; `--audit` is the supported opt-in (release builds without `--audit` still fail with `SECURITY: permissiveLearningMode not allowed in release builds (pass --audit to opt in)`).
2. **Before** the runner starts, `wxc` invokes `start_plm_logging.ps1` to begin an ACP profiling session.
3. The script/container runs as usual.
4. **After** the runner completes, `wxc` invokes `stop_plm_logging.ps1` to merge observed accesses into an adjusted config. The stop script:
   - Writes the ETL trace and the captured copy of the original config to a timestamped folder under `logs\` (or under `--log-dir` if supplied).
   - Parses the trace for file-access (EventID 14) and UI (EventID 27) events via `event_dacl_parser.ps1`, including ACE-derived capability names from `extract_caps.ps1`.
   - Emits an `Adjusted_<config-name>.json` with observed paths merged into `filesystem.readwritePaths` / `readonlyPaths`, discovered capabilities merged into the containment-specific `capabilities` block, and `ui.disable` flipped to `false` when a UI event was detected.

The scripts are resolved next to `wxc-exec.exe` via `std::env::current_exe()`, so `--audit` works regardless of the caller's current working directory.

#### Related flags

| Flag | Forwarded as | Purpose |
|---|---|---|
| `--audit` | — | Enable audit mode (required to use the flags below). |
| `--log-dir <dir>` | `stop_plm_logging.ps1 -LogDir` | Directory for the ETW trace, captured config copy, and (by default) the adjusted config. |
| `--adjusted-config-path <file>` | `stop_plm_logging.ps1 -AdjustedConfigPath` | Override the exact path the adjusted config is written to. When omitted the script writes `Adjusted_<original>.json` inside `--log-dir`. |

Example:

```powershell
wxc-exec --audit --log-dir C:\temp\wxc_logs `
    --adjusted-config-path C:\temp\wxc_logs\adjusted_my-config.json `
    C:\path\to\my-config.json
```

After the run, the file at `--adjusted-config-path` (or `Adjusted_my-config.json` under `--log-dir`) reflects what the workload actually touched, ready to be used as a tightened (or expanded) policy.

## Linux Support (LXC)

MXC also supports Linux via [LXC (Linux Containers)](https://linuxcontainers.org/lxc/). On Linux, the `lxc-exec` binary provides container-based isolation using Linux namespaces, bind mounts for filesystem policy, and iptables/nftables for network policy.

For full details on the LXC backend, see [docs/lxc-support/lxc-backend.md](docs/lxc-support/lxc-backend.md).

### Building on Linux

Use `build.sh` from the repo root:

```bash
./build.sh              # Release build
./build.sh --debug      # Debug build
./build.sh --rust-only  # Only build Rust binaries, skip SDK
./build.sh --help       # Show all options
```

This will:
1. Build the Rust `lxc-exec` binary
2. Copy the binary into `sdk/bin/<target-triple>/` so it is bundled with the SDK package
3. Build the TypeScript SDK

### LXC Example Configurations

See `examples/11_lxc_hello_world.json`, `examples/12_lxc_filesystem_access.json`, and `examples/13_lxc_network_restricted.json` for LXC-specific examples.

### Running on Linux

```bash
# Run with config file
./lxc-exec config.json

# Run with base64-encoded config
./lxc-exec --config-base64 <base64-string>

# Run with debug output
./lxc-exec --debug config.json
```

## macOS Support (Seatbelt)

MXC also supports macOS via Seatbelt — the same kernel-enforced sandbox that backs the App Sandbox used by every Mac App Store application. The `mxc-exec-mac` binary applies a generated TinyScheme profile to the child process via `sandbox_init()`, providing filesystem, network, and UI isolation. The macOS backend is **experimental** and currently requires opt-in via the `--experimental` flag (or `{ experimental: true }` in SDK spawn options).

For full details on the Seatbelt backend, see [docs/macos-support/seatbelt-backend.md](docs/macos-support/seatbelt-backend.md).

### Building on macOS

Use `build-mac.sh` from the repo root:

```bash
./build-mac.sh              # Native architecture release build
./build-mac.sh --all        # Both Apple Silicon and Intel slices
./build-mac.sh --debug      # Debug build
./build-mac.sh --rust-only  # Only build Rust binary, skip SDK
```

This will:
1. Build the Rust `mxc-exec-mac` binary for the selected architecture(s)
2. Copy the binary into `sdk/bin/<target-triple>/` so it is bundled with the SDK package
3. Build the TypeScript SDK

### macOS Example Configurations

See `examples/15_mac_hello_world.json` and `examples/21_mac_python_info.json` for macOS-specific examples.

### Running on macOS

```bash
# Run with config file
./mxc-exec-mac --experimental config.json

# Run with debug output
./mxc-exec-mac --experimental --debug config.json
```

## License

See LICENSE file for details.