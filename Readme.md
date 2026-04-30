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

You will need the [Rust toolchain](https://rustup.rs/) (stable) installed.  The WXC native components are built with Cargo, the Rust package manager and build system.

You will also need Node.js 20.10+ and must ensure that the node dependencies are resolved.  We recommend going into the SDK and CLI folders and running npm install.

A copy of Python 3.x is needed for executing test scripts.

### Project Structure

```
src/            Rust workspace (wxc-exec native binary + wxc_common library)
sdk/            TypeScript SDK (@microsoft/mxc-sdk npm package)
cli/            TypeScript CLI (mxc-cli npm package, depends on SDK)
docs/           Schema and configuration documentation
examples/       Example configurations
test_configs/   Test JSON configurations
test_scripts/   Test scripts for exercising WXC
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

WXC requires a JSON-based configuration to be provided.  The [schema documentation](docs\schema.md) defines all of the policies and execution options.

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

By default, WXC runs in **silent mode** with no console output of its own.  It is designed to couple the stdin/stdout/stderr of the caller to the container.  Use the `--debug` flag to enable verbose console output:

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

### Run WXC

Execute your script with AppContainer in permissive learning mode:

```json
{
  "script": "your_code_here",
  "appContainer": {
    "capabilities": ["permissiveLearningMode"]
  }
}
```

## Telemetry

MXC supports optional TraceLogging ETW telemetry for execution observability and
adoption metrics. Telemetry is an **experimental feature** and requires the
`--experimental` CLI flag.

### Enabling telemetry

Add `experimental.telemetry.enabled` to your JSON config and pass `--experimental`:

```json
{
  "process": { "commandLine": "echo hello" },
  "experimental": {
    "telemetry": { "enabled": true }
  }
}
```

```bash
wxc-exec --experimental config.json
```

### Default behavior

Telemetry is **off by default**. It requires both `--experimental` and
`experimental.telemetry.enabled: true` in the JSON config.

Without `--experimental`, telemetry is always off regardless of the config.

### What is collected

Events are emitted to the local ETW subsystem via the `Microsoft.MXC` TraceLogging
provider. **No PII is collected.** The following fields are recorded:

| Field | Description |
|-------|-------------|
| `mxc.backend` | Containment backend (appcontainer, sandbox, lxc, wslc, microvm) |
| `mxc.outcome` | success or failure |
| `mxc.exit_code` | Process exit code |
| `mxc.duration_ms` | Total execution wall-clock time |
| `mxc.init_duration_ms` | Container initialization time |
| `mxc.version` | MXC version |
| `mxc.failure_reason` | Bounded error category (on failure only) |

Error messages are sanitized to strip file paths and usernames before emission.

### Capturing events

Use standard ETW tools to capture telemetry events:

```bash
tracelog -start MXCTrace -f MXCTrace.etl -guid #<PROVIDER_GUID>
wxc-exec --experimental config.json
tracelog -stop MXCTrace
tracefmt -o MXCTrace.txt MXCTrace.etl
```

### Consent

MXC does not implement consent prompts or persistent consent storage.
Consent is the responsibility of the calling agent (SDK consumer).

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

## Linux Support (LXC)

MXC also supports Linux via [LXC (Linux Containers)](https://linuxcontainers.org/lxc/). On Linux, the `lxc-exec` binary provides container-based isolation using Linux namespaces, bind mounts for filesystem policy, and iptables/nftables for network policy.

For full details on the LXC backend, see [docs/lxc-backend.md](docs/lxc-backend.md).

### Building on Linux

Use `build.sh` from the repo root:

```bash
./build.sh              # Release build
./build.sh --debug      # Debug build
./build.sh --rust-only  # Only build Rust binaries, skip SDK/CLI
./build.sh --help       # Show all options
```

This will:
1. Build the Rust `lxc-exec` binary
2. Copy the binary into `sdk/bin/<target-triple>/` so it is bundled with the SDK package
3. Build the TypeScript SDK and CLI

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

## License

See LICENSE file for details.