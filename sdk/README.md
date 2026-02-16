# WXC SDK

TypeScript SDK for WXC - spawn and manage sandboxed processes.

## Overview

The WXC SDK provides a Node.js interface for running processes in sandboxed environments. It wraps platform specific, native bootstrap executables and exposes a clean TypeScript API for spawning sandboxed processes with full interactive I/O support via node-pty.

## Features

- **Platform Detection**: Check if WXC is supported on the current system
- **Sandboxing Methods**: Query available sandboxing capabilities
- **Interactive Process Spawning**: Spawn sandboxed processes with full I/O using node-pty
- **TypeScript Support**: Full type definitions for all configuration options
- **Flexible Configuration**: Support for filesystem restrictions, network policies, and namespace capabilities

## Installation

The WXC SDK is currently published to a private registry hosted with NPM.  To use this registry, you must have an access token with permission to read from this scope and will need to explicitly install the SDK into your local node modules.

```bash
npm install --save @shschaefer/wxc-sdk
```

**Requirements**:
- **Windows Build**: Build 26559 or later on branch `ge_current_directwinai` or a derivative
  - The SDK checks the registry key `HKLM\Software\Microsoft\Windows NT\CurrentVersion\BuildLab`
  - Format: `buildNumber.branch.buildDate` (e.g., `26559.ge_current_directwinai.260130-1453`)
  - Minimum build number: 26559
- **wxc-exec.exe**: Must be built and available (see WXC project root for build instructions)

**Platform Support**:
- ✅ Windows x64 (specific build required - see above)
- ✅ Windows ARM64 (specific build required - see above)
- ❌ macOS (not supported)
- ❌ Linux (not supported)
- ❌ Other platforms (not supported)

> **Note**: The SDK automatically detects the platform architecture (x64 or ARM64) and uses the appropriate wxc-exec.exe binary.

> **Note**: Use `getPlatformSupport()` to check if your system meets all requirements before attempting to spawn sandboxed processes.

## Quick Start

```typescript
import { spawnSandbox, SandboxConfig, getPlatformSupport } from '@shschaefer/wxc-sdk';

// Check platform support
if (!getPlatformSupport().supported) {
  console.error('WXC currently only supports Windows 11');
  process.exit(1);
}

// Create a sandbox configuration
const config: SandboxConfig = {
  script: 'python -c "print(\'Hello from sandbox!\')"',
  appContainer: {
    name: 'MyApp',
    learningMode: true
  }
};

// Spawn the sandboxed process
const pty = spawnSandbox(config);

// Handle output
pty.onData((data: string) => {
  process.stdout.write(data);
});

// Handle exit
pty.onExit((event: { exitCode: number }) => {
  console.log(`Process exited with code ${event.exitCode}`);
});
```

## API Reference

### Platform Detection

#### `getPlatformSupport(): PlatformSupport`
Returns detailed platform support information including available sandboxing methods and the reason for any unsupported status.

```typescript
import { getPlatformSupport } from '@shschaefer/wxc-sdk';

const support = getPlatformSupport();
console.log('Platform:', support.platform);
console.log('Supported:', support.isSupported);

if (support.reason) {
  console.log('Reason:', support.reason);
}

console.log('Available methods:', support.availableMethods);
// On supported Windows: ['appcontainer']
// On unsupported platforms: []
```

**Example outputs**:

Supported system:
```
Supported: true
Available methods: ['appcontainer']
```

Unsupported system (wrong branch):
```
Supported: false
Reason: Unsupported Windows branch: rs_prerelease (requires ge_current_directwinai)
Available methods: []
```

Unsupported system (macOS):
```
Supported: false
Reason: WXC is not supported on macOS
Available methods: []
```

### Sandbox Spawning

#### `spawnSandbox(config: SandboxConfig, options?: SandboxSpawnOptions): IPty`

Spawns a sandboxed process and returns a node-pty `IPty` object for interactive I/O.

**Parameters**:
- `config`: Sandbox configuration matching the wxc-exec JSON schema
- `options`: Optional spawn options
  - `debug`: Enable debug output (default: false)
  - `ptyOptions`: node-pty options (cols, rows, etc.)

**Returns**: `IPty` object for interacting with the sandboxed process

**Throws**: Error if platform is not supported or wxc-exec is not found

```typescript
import { spawnSandbox, SandboxConfig } from '@shschaefer/wxc-sdk';

const config: SandboxConfig = {
  script: 'python -c "print(\'Hello!\')"',
  timeout: 5000
};

const pty = spawnSandbox(config, {
  debug: true,
  ptyOptions: {
    cols: 120,
    rows: 40
  }
});

pty.onData((data) => console.log(data));
pty.onExit((e) => console.log('Exit code:', e.exitCode));
```

#### `spawnSandboxAsync(config: SandboxConfig, options?: SandboxSpawnOptions): Promise<{stdout: string, stderr: string, exitCode: number}>`

Spawns a sandboxed process and returns a promise that resolves with the output. This is a convenience wrapper for non-interactive use cases.

```typescript
import { spawnSandboxAsync, SandboxConfig } from '@shschaefer/wxc-sdk';

async function runSandboxed() {
  const config: SandboxConfig = {
    script: 'python -c "import sys; print(sys.version)"',
    timeout: 5000
  };

  const result = await spawnSandboxAsync(config);
  console.log('Output:', result.stdout);
  console.log('Exit code:', result.exitCode);
}
```

## Configuration

### SandboxConfig Type

The `SandboxConfig` type matches the wxc-exec JSON schema:

```typescript
interface SandboxConfig {
  // Required: Complete command line to execute
  script: string;

  // Optional: Working directory
  workingDirectory?: string;

  // Optional: Timeout in milliseconds (default: no timeout)
  timeout?: number;

  // Optional: AppContainer configuration
  appContainer?: {
    name?: string;              // Default: "CLI"
    leastPrivilege?: boolean;   // Default: false
    learningMode?: boolean;     // Enable container in permissive mode
    capabilities?: string[]; =
  };

  // Optional: Filesystem restrictions
  filesystem?: {
    readwritePaths?: string[];
    readonlyPaths?: string[];
    deniedPaths?: string[];
    clearPolicyOnExit?: boolean; // Default: true
  };

  // Optional: Network restrictions
  network?: {
    enforcementMode?: 'capabilities' | 'firewall' | 'both'; // Default: "both"
    defaultPolicy?: 'allow' | 'block';                      // Default: "allow"
    allowedHosts?: string[];    // Hostnames or IP/CIDR blocks
    blockedHosts?: string[];
    removeRulesOnExit?: boolean; // Default: true
  };
}
```

### Helper Functions

#### `createMinimalConfig(scriptCommand: string): SandboxConfig`
Creates a minimal valid configuration with just a script command.

```typescript
import { createMinimalConfig, spawnSandbox } from '@shschaefer/wxc-sdk';

const config = createMinimalConfig('python -c "print(\'Hello\')"');
const pty = spawnSandbox(config);
```

#### `createNetworkRestrictedConfig(scriptCommand: string, allowedHosts: string[]): SandboxConfig`
Creates a configuration with network restrictions (blocks all except allowed hosts).

```typescript
import { createNetworkRestrictedConfig, spawnSandbox } from '@shschaefer/wxc-sdk';

const config = createNetworkRestrictedConfig(
  'python -c "import requests; print(requests.get(\'https://api.github.com\').status_code)"',
  ['api.github.com', 'github.com']
);

const pty = spawnSandbox(config);
```

#### `createFilesystemRestrictedConfig(scriptCommand: string, readwritePaths: string[], deniedPaths?: string[]): SandboxConfig`
Creates a configuration with filesystem restrictions.

```typescript
import { createFilesystemRestrictedConfig, spawnSandbox } from '@shschaefer/wxc-sdk';

const config = createFilesystemRestrictedConfig(
  'python script.py',
  ['C:\\workspace\\data'],          // Read/write paths
  ['C:\\Windows\\System32']         // Denied paths
);

const pty = spawnSandbox(config);
```

## Examples

### Minimal Configuration

```typescript
import { createMinimalConfig, spawnSandbox } from '@shschaefer/wxc-sdk';

const config = createMinimalConfig('python -c "print(\'Hello World\')"');
const pty = spawnSandbox(config);

pty.onData((data) => process.stdout.write(data));
pty.onExit((e) => console.log('Done!'));
```

### Network Restrictions

```typescript
import { SandboxConfig, spawnSandboxAsync } from '@shschaefer/wxc-sdk';

const config: SandboxConfig = {
  script: 'python -c "import urllib.request; print(urllib.request.urlopen(\'https://api.github.com\').read())"',
  network: {
    enforcementMode: 'capabilities', // No admin required
    defaultPolicy: 'allow'
  }
};

const result = await spawnSandboxAsync(config);
console.log(result.stdout);
```

### Filesystem Restrictions

```typescript
import { SandboxConfig, spawnSandbox } from '@shschaefer/wxc-sdk';

const config: SandboxConfig = {
  script: 'python script.py',
  workingDirectory: 'C:\\projects\\myapp',
  filesystem: {
    readwritePaths: ['C:\\projects\\myapp\\data'],
    readonlyPaths: ['C:\\projects\\myapp\\config'],
    deniedPaths: ['C:\\Windows\\System32']
  }
};

const pty = spawnSandbox(config);
```

### Advanced Configuration

```typescript
import { SandboxConfig, spawnSandbox } from '@shschaefer/wxc-sdk';

const config: SandboxConfig = {
  script: 'node app.js',
  workingDirectory: 'C:\\projects\\myapp',
  timeout: 30000, // 30 seconds

  appContainer: {
    name: 'MyNodeApp',
    learningMode: false,
    capabilities: ['internetClient', 'registryRead']
  },

  filesystem: {
    readwritePaths: ['C:\\projects\\myapp\\data'],
    readonlyPaths: ['C:\\projects\\myapp\\config'],
    deniedPaths: ['C:\\Windows\\System32'],
    clearPolicyOnExit: true
  },

  network: {
    enforcementMode: 'capabilities', // No admin required
    defaultPolicy: 'allow'
  }
};

const pty = spawnSandbox(config, {
  debug: true,
  ptyOptions: {
    cols: 120,
    rows: 40
  }
});

pty.onData((data) => process.stdout.write(data));
pty.onExit((e) => console.log(`Exit code: ${e.exitCode}`));
```

## Network Enforcement Modes

WXC supports three network enforcement modes:

1. **`capabilities` (recommended)**: Uses AppContainer capabilities only
   - No administrator privileges required
   - Simple allow/block for all network access
   - Best for most use cases

2. **`firewall`**: Uses Windows Firewall rules
   - Requires administrator privileges
   - Granular control over specific hosts
   - Supports IP ranges (CIDR notation)

3. **`both`**: Uses both capabilities and firewall
   - Requires administrator privileges
   - Maximum security with defense-in-depth

```typescript
const config: SandboxConfig = {
  script: 'python network_script.py',
  network: {
    enforcementMode: 'capabilities', // No admin required
    defaultPolicy: 'allow'
  }
};
```

## TypeScript Support

The package includes full TypeScript definitions. All types are exported from the main entry point:

```typescript
import {
  SandboxConfig,
  WxcConfiguration,
  WxcAppContainerConfig,
  WxcFilesystemConfig,
  WxcNetworkConfig,
  PlatformSupport,
  SandboxingMethod,
  SandboxSpawnOptions
} from '@shschaefer/wxc-sdk';
```

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Watch mode
npm run watch

# Clean build artifacts
npm run clean
```

## License

TODO:

## Contributing

Contributions are welcome! Please see the main WXC project repository for contribution guidelines.
