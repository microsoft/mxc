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

### Building WXC

From the `src` directory, build the Rust workspace with Cargo:

```bash
cd src
cargo build --release
```

This will produce the `wxc-exec.exe` binary and the `wxc_test_driver.exe` test program in `src/target/release/`.

For the SDK npm library, go into the SDK folder and build:

```bash
cd sdk
npm install && npm run build
```

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
    "learningMode": true
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

## License

See LICENSE file for details.