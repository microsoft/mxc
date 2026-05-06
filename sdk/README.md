# MXC SDK

> **Status: Public Preview** - MXC is experimental and in active development.

## Overview

The MXC SDK provides a Node.js interface for creating and managing policy-based containers. It exposes APIs for:

- Defining container policies (filesystem, network)
- Discovering host tools and helpers for building the policy
- Spawning containerized processes with full interactive I/O via node-pty

## Features

- **Platform Detection**: Check if MXC is supported on the current system
- **Policy-Driven Configuration**: Define what the container can access using a `SandboxPolicy`
- **Policy Discovery**: Automatically discover host tools, user profile paths, and temp directories to build the policy
- **Interactive Process Spawning**: Spawn containerized processes with full PTY I/O using node-pty
- **Cross-Platform**: Process containment for Windows and Linux
- **TypeScript Support**: Full type definitions for all public APIs

## Installation

### From a tarball

```bash
npm install @microsoft/mxc-sdk-<version>.tgz
```

### From source

```bash
cd sdk
npm install
npm run build
```

Then reference it from your project (e.g., via `npm link` or a relative path in `package.json`).

**Requirements**:
- **Windows**: Windows 11 build 26100+ with UBR ≥ 7965 (for builds 26100–26500)
- **Windows**: The host process must run **elevated (Administrator)** to create AppContainer-based sandboxes
- **Linux**: LXC must be installed and available

**Platform Support**:
- ✅ Windows x64
- ✅ Windows ARM64
- ✅ Linux x64
- ✅ Linux ARM64
- ❌ macOS (not supported)

> **Note**: The SDK automatically detects the platform and architecture.

> **Note**: Use `getPlatformSupport()` to check if your system meets all requirements before attempting to create containers.

## Quick Start

```typescript
import {
  spawnSandbox,
  SandboxPolicy,
  getPlatformSupport,
  getAvailableToolsPolicy,
  getTemporaryFilesPolicy,
} from '@microsoft/mxc-sdk';

// Check platform support
const support = getPlatformSupport();
if (!support.isSupported) {
  console.error('MXC is not supported:', support.reason);
  process.exit(1);
}

// Discover host tools and temp directories
const tools = getAvailableToolsPolicy(process.env);
const temp = getTemporaryFilesPolicy();

// Define a sandbox policy
const policy: SandboxPolicy = {
  version: '0.4.0-alpha',
  filesystem: {
    readonlyPaths: tools.readonlyPaths,
    readwritePaths: temp.readwritePaths,
  },
  network: {
    allowOutbound: true,
  },
};

// Spawn a sandboxed payload
const ptyProcess = spawnSandbox('python -c "print(\'Hello from sandbox!\')"', policy);

// Handle output
ptyProcess.onData((data: string) => {
  process.stdout.write(data);
});

// Handle exit
ptyProcess.onExit((event: { exitCode: number }) => {
  console.log(`Process exited with code ${event.exitCode}`);
});
```

## API Reference

### Platform Detection

#### Containment values: intent vs. backend

The SDK distinguishes two layers of containment values:

- **`ContainmentType`** — abstract intent (what *kind* of isolation you want).
  Currently `"process"`, `"vm"`, and `"microvm"`. The native binary resolves
  these to a concrete backend per host. Prefer these in policy code so the
  same policy works across hosts with different capabilities.
- **`ContainmentBackend`** — concrete backend (a specific runner). Currently
  `"processcontainer"`, `"windows_sandbox"`, `"wslc"`, `"lxc"`, `"microvm"`,
  `"seatbelt"`. Use these to force a particular backend.

`ContainerConfig.containment` accepts either layer. The deprecated
`SandboxingMethod` alias is the union of both and is retained for backward
compatibility.

#### `getPlatformSupport(): PlatformSupport`

Returns platform support information including whether MXC is supported.

```typescript
import { getPlatformSupport } from '@microsoft/mxc-sdk';

const support = getPlatformSupport();
console.log('Supported:', support.isSupported);
console.log('Available methods:', support.availableMethods);

if (support.reason) {
  console.log('Reason:', support.reason);
}
```

**Return type**:

```typescript
interface PlatformSupport {
  isSupported: boolean;
  reason?: string;
  availableMethods: ContainmentBackend[];
}
```

**Example outputs**:

Supported system:
```
Supported: true
Available methods: ['processcontainer']
```

Unsupported system:
```
Supported: false
Reason: MXC is not supported on macOS
Available methods: []
```

### Sandbox Spawning

#### `spawnSandbox(script, policy, options?, workingDirectory?, containerName?, env?): IPty`

Spawns a containerized process and returns a node-pty `IPty` object for interactive I/O.

**Parameters**:
- `script` (`string`): The command line to execute inside the container
- `policy` (`SandboxPolicy`): The sandbox policy defining container permissions
- `options` (`SandboxSpawnOptions`, optional): Spawn options
  - `debug`: Enable debug output (default: `false`)
  - `ptyOptions`: node-pty options (cols, rows, etc.)
- `workingDirectory` (`string`, optional): Working directory for the process
- `containerName` (`string`, optional): Container name (auto-generated if omitted)
- `env` (`object`, optional): Environment variables to pass to the container

**Returns**: `IPty` object for interacting with the containerized process

**Throws**: Error if platform is not supported

```typescript
import { spawnSandbox, SandboxPolicy, getAvailableToolsPolicy } from '@microsoft/mxc-sdk';

const tools = getAvailableToolsPolicy(process.env);

const policy: SandboxPolicy = {
  version: '0.4.0-alpha',
  filesystem: { readonlyPaths: tools.readonlyPaths },
  network: { allowOutbound: true },
};

const ptyProcess = spawnSandbox(
  'python -c "print(\'Hello!\')"',
  policy,
  { debug: true, ptyOptions: { cols: 120, rows: 40 } },
);

ptyProcess.onData((data) => console.log(data));
ptyProcess.onExit((event) => console.log('Exit code:', event.exitCode));
```

#### `spawnSandboxAsync(script, policy, options?, workingDirectory?, containerName?): Promise<...>`

Spawns a containerized process and returns a promise that resolves with the collected output. Convenience wrapper for non-interactive use cases.

**Returns**: `Promise<{ stdout: string; stderr: string; exitCode: number }>`

```typescript
import { spawnSandboxAsync, SandboxPolicy, getAvailableToolsPolicy } from '@microsoft/mxc-sdk';

const tools = getAvailableToolsPolicy(process.env);

const policy: SandboxPolicy = {
  version: '0.4.0-alpha',
  filesystem: { readonlyPaths: tools.readonlyPaths },
};

const result = await spawnSandboxAsync(
  'python -c "import sys; print(sys.version)"',
  policy,
);

console.log('Output:', result.stdout);
console.log('Exit code:', result.exitCode);
```

### Policy Discovery

These functions examine the host environment and return `FilesystemPolicyResult` fragments that can be merged into a `SandboxPolicy`.

```typescript
interface FilesystemPolicyResult {
  readonlyPaths: string[];
  readwritePaths: string[];
}
```

#### `getAvailableToolsPolicy(env?, options?): FilesystemPolicyResult`

Discovers tool and SDK directories from `PATH` and well-known environment variables (e.g., `PYTHONPATH`, `JAVA_HOME`, `CARGO_HOME`, `GOPATH`, etc.) and returns them as read-only policy paths.

Filters out non-existent directories and system-critical paths (e.g., under `%WINDIR%`).

```typescript
import { getAvailableToolsPolicy } from '@microsoft/mxc-sdk';

const toolsPolicy = getAvailableToolsPolicy(process.env);
console.log('Read-only tool paths:', toolsPolicy.readonlyPaths);
```

#### `getUserProfilePolicy(): FilesystemPolicyResult`

Returns read-only policy paths for user profile application data. On Windows, enumerates subdirectories under `%LOCALAPPDATA%\Programs`. On Linux, includes `~/.local/bin` and `~/.local/lib`.

```typescript
import { getUserProfilePolicy } from '@microsoft/mxc-sdk';

const profilePolicy = getUserProfilePolicy();
console.log('User profile paths:', profilePolicy.readonlyPaths);
```

#### `getTemporaryFilesPolicy(env?): FilesystemPolicyResult`

Returns a read-write policy path for the system temporary directory (`%TEMP%` on Windows, `$TMPDIR` or `/tmp` on Linux).

```typescript
import { getTemporaryFilesPolicy } from '@microsoft/mxc-sdk';

const tempPolicy = getTemporaryFilesPolicy();
console.log('Temp paths:', tempPolicy.readwritePaths);
```

## Policy

### SandboxPolicy

The `SandboxPolicy` type is the public interface for defining what a sandboxed payload is allowed to do. Policy describes *what* the caller wants restricted — cross-platform, no OS-specific content. Omitted fields default to most restrictive (default-deny). The SDK translates this into the internal container configuration automatically via `createConfigFromPolicy()`.

```typescript
type SandboxPolicy = {
  version: string;

  filesystem?: {
    readwritePaths?: string[];
    readonlyPaths?: string[];
    deniedPaths?: string[];
    clearPolicyOnExit?: boolean;
  };

  network?: {
    allowOutbound?: boolean;
    allowLocalNetwork?: boolean;
    allowedHosts?: string[];
    blockedHosts?: string[];
    proxy?: { builtinTestServer: true } | { localhost: number } | { url: string };
  };

  ui?: {
    allowWindows?: boolean;
    clipboard?: "none" | "read" | "write" | "all";
    allowInputInjection?: boolean;
  };

  timeoutMs?: number;
};
```

> **Note**: Low-level container options are managed internally by the SDK based on the policy and platform. Use the advanced path (`createConfigFromPolicy()` → modify → `spawnSandboxFromConfig()`) if you need to tweak backend-specific settings.

### Merging Policy Fragments

Combine the policy discovery functions to build a complete policy:

```typescript
import {
  SandboxPolicy,
  getAvailableToolsPolicy,
  getUserProfilePolicy,
  getTemporaryFilesPolicy,
  spawnSandbox,
} from '@microsoft/mxc-sdk';

const tools = getAvailableToolsPolicy(process.env);
const profile = getUserProfilePolicy();
const temp = getTemporaryFilesPolicy();

const policy: SandboxPolicy = {
  version: '0.4.0-alpha',
  filesystem: {
    readonlyPaths: [...tools.readonlyPaths, ...profile.readonlyPaths],
    readwritePaths: [...temp.readwritePaths, 'C:\\workspace\\output'],
    deniedPaths: ['C:\\secrets'],
  },
  network: {
    allowOutbound: true,
  },
};

const ptyProcess = spawnSandbox('python script.py', policy, {}, 'C:\\workspace');
```

## Examples

### Minimal — Run a Command

```typescript
import { spawnSandbox, SandboxPolicy, getAvailableToolsPolicy } from '@microsoft/mxc-sdk';

const tools = getAvailableToolsPolicy(process.env);

const policy: SandboxPolicy = {
  version: '0.4.0-alpha',
  filesystem: { readonlyPaths: tools.readonlyPaths },
};

const ptyProcess = spawnSandbox('python -c "print(\'Hello World\')"', policy);

ptyProcess.onData((data) => process.stdout.write(data));
ptyProcess.onExit(() => console.log('Done!'));
```

### Network — Allow Outbound Access

```typescript
import { spawnSandboxAsync, SandboxPolicy, getAvailableToolsPolicy } from '@microsoft/mxc-sdk';

const tools = getAvailableToolsPolicy(process.env);

const policy: SandboxPolicy = {
  version: '0.4.0-alpha',
  filesystem: { readonlyPaths: tools.readonlyPaths },
  network: { allowOutbound: true },
};

const result = await spawnSandboxAsync(
  'python -c "import urllib.request; print(urllib.request.urlopen(\'https://api.github.com\').read())"',
  policy,
);
console.log(result.stdout);
```

### Filesystem — Restrict Access

```typescript
import { spawnSandbox, SandboxPolicy, getAvailableToolsPolicy } from '@microsoft/mxc-sdk';

const tools = getAvailableToolsPolicy(process.env);

const policy: SandboxPolicy = {
  version: '0.4.0-alpha',
  filesystem: {
    readonlyPaths: [...tools.readonlyPaths, 'C:\\projects\\myapp\\config'],
    readwritePaths: ['C:\\projects\\myapp\\data'],
    deniedPaths: ['C:\\Windows\\System32'],
  },
};

const ptyProcess = spawnSandbox('python script.py', policy, {}, 'C:\\projects\\myapp');
```

### Combined — Fetch from Web and Write to Disk

```typescript
import {
  SandboxPolicy,
  getAvailableToolsPolicy,
  getTemporaryFilesPolicy,
  spawnSandboxAsync,
} from '@microsoft/mxc-sdk';

const tools = getAvailableToolsPolicy(process.env);
const temp = getTemporaryFilesPolicy();

const policy: SandboxPolicy = {
  version: '0.4.0-alpha',
  filesystem: {
    readonlyPaths: tools.readonlyPaths,
    readwritePaths: [...temp.readwritePaths, 'C:\\workspace\\output'],
  },
  network: { allowOutbound: true },
};

// Python script that fetches JSON from an API and writes it to a local file
const script = `python -c "
import urllib.request, json, os

url = 'https://api.github.com/zen'
response = urllib.request.urlopen(url)
wisdom = response.read().decode('utf-8')

output_dir = r'C:\\workspace\\output'
os.makedirs(output_dir, exist_ok=True)
output_path = os.path.join(output_dir, 'zen.txt')

with open(output_path, 'w') as f:
    f.write(wisdom)

print(f'Wrote GitHub zen to {output_path}: {wisdom}')
"`;

const result = await spawnSandboxAsync(script, policy, {}, 'C:\\workspace');

console.log('Output:', result.stdout);
console.log('Exit code:', result.exitCode);
```

## Common Pitfalls

### `spawnSandboxAsync` merges stdout and stderr

`spawnSandboxAsync` uses a PTY internally. **stderr is always empty** in the returned result — all output (including error output) arrives in `stdout`. If you need to distinguish stderr from stdout, you must handle it at the application level inside the sandbox (e.g., redirect stderr to a file, then read it back).

```typescript
// result.stderr will always be '' — this is by design
const result = await spawnSandboxAsync('python script.py', policy);
console.log(result.stdout); // Contains both stdout AND stderr
console.log(result.stderr); // Always empty string
```

### `createConfigFromPolicy()` returns an empty command line

If you use the advanced path (`createConfigFromPolicy()` → modify → `spawnSandboxFromConfig()`), the returned config has an **empty `process.commandLine`**. You must set it before spawning:

```typescript
import { createConfigFromPolicy, spawnSandboxFromConfig } from '@microsoft/mxc-sdk';

const config = createConfigFromPolicy(policy);
config.process.commandLine = 'python -c "print(\'hello\')"'; // ← Required!
const pty = spawnSandboxFromConfig(config);
```

### Elevation failures on Windows

If the host process is not elevated, `spawnSandbox` will throw. The error message may not immediately indicate a privilege issue. Always ensure your host process runs as Administrator during development and testing.

### Timeouts default to no limit

If you delegate work to a sandbox, set `timeoutMs` in your policy to prevent runaway processes:

```typescript
const policy: SandboxPolicy = {
  version: '0.4.0-alpha',
  filesystem: { readonlyPaths: tools.readonlyPaths },
  timeoutMs: 30000, // 30 seconds
};
```

## Recommended Policy for Agentic Workloads

Agents that execute code on behalf of a user typically need scoped filesystem access and limited (or no) network. The `SandboxPolicy` model is **default-deny** — omitted fields are restrictive.

```typescript
import {
  SandboxPolicy,
  getAvailableToolsPolicy,
  getTemporaryFilesPolicy,
} from '@microsoft/mxc-sdk';

const tools = getAvailableToolsPolicy(process.env);
const temp = getTemporaryFilesPolicy();

const agentPolicy: SandboxPolicy = {
  version: '0.4.0-alpha',
  filesystem: {
    readonlyPaths: [
      ...tools.readonlyPaths,
      // Add paths to project files the agent needs to read
    ],
    readwritePaths: [
      ...temp.readwritePaths,
      // Add a scoped output directory for agent artifacts
    ],
  },
  network: {
    // Only enable if the agent needs external API access
    allowOutbound: false,
    // Or restrict to specific hosts:
    // allowedHosts: ['api.example.com'],
  },
  timeoutMs: 60000, // Prevent runaway execution
};
```

**Principle:** Grant the sandbox only what the current task requires. If your agent performs multiple steps, consider spawning separate sandboxes with different policies for each step rather than one broad policy.

## Error Handling

```typescript
import { getPlatformSupport, spawnSandboxAsync } from '@microsoft/mxc-sdk';

// 1. Check platform before any sandbox operations
const support = getPlatformSupport();
if (!support.isSupported) {
  // Degrade gracefully — run without containment or inform the user
  console.error(`MXC not available: ${support.reason}`);
}

// 2. Wrap spawn calls in try/catch
try {
  const result = await spawnSandboxAsync(command, policy);
  if (result.exitCode !== 0) {
    // Non-zero exit — check result.stdout for error output (stderr is merged)
    handleFailure(result.stdout, result.exitCode);
  }
} catch (err) {
  // Spawn failures: privilege issues, invalid policy, missing binaries
  handleSpawnError(err);
}
```

## Integration Checklist

- [ ] `getPlatformSupport()` called at startup; graceful fallback if unsupported
- [ ] Host process runs elevated (Administrator) on Windows
- [ ] Policy uses default-deny; only required paths/network are enabled
- [ ] `timeoutMs` set to prevent unbounded execution
- [ ] `spawnSandboxAsync` stdout handled knowing stderr is merged
- [ ] Error handling covers both spawn failures and non-zero exit codes
- [ ] Tested on Windows 11 build 26100+ with UBR ≥ 7965

## TypeScript Support

The package includes full TypeScript definitions. All public types are exported from the main entry point:

```typescript
import {
  // Types
  SandboxPolicy,
  ContainmentType,
  ContainmentBackend,
  SandboxingMethod, // deprecated alias for ContainmentType | ContainmentBackend
  PlatformSupport,

  // Platform detection
  getPlatformSupport,

  // Sandbox spawning
  spawnSandbox,
  spawnSandboxAsync,
  SandboxSpawnOptions,

  // Policy discovery
  getAvailableToolsPolicy,
  getUserProfilePolicy,
  getTemporaryFilesPolicy,
  FilesystemPolicyResult,
  ToolsPolicyOptions,
} from '@microsoft/mxc-sdk';
```

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Watch mode
npm run watch

# Clean build artifacts
npm run clean
```

## License

See the [LICENSE](../LICENSE.md) file for details.

## Contributing

Contributions are welcome! Please see the main MXC project repository for contribution guidelines.
