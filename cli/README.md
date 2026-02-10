# WXC CLI

TypeScript-based Node.js CLI for invoking the WXC (Windows eXecution Container).

## Features

- **Dual API Support**: Choose between the original `WxcExecutor` API or the new SDK-based API
- **Interactive Mode**: Run sandboxed processes with full I/O using node-pty (SDK mode)
- **Platform Detection**: Check if WXC is supported on your platform
- **Legacy Compatibility**: Original WxcExecutor still available for backward compatibility

## Installation

```bash
npm install
npm run build
```

## Usage

### Command Line Interface

The CLI now supports two modes of operation:

#### Original Mode (WxcExecutor)

```bash
# Run with JSON config file
npm start run examples/01_hello_world.json

# Run with base64-encoded config
npm start run <base64-string> --base64

# Run with debug output
npm start run config.json --debug

# Specify custom WXC executable path
npm start run config.json --wxc-path "C:\path\to\wxc-exec.exe"
```

#### SDK Mode (Interactive with node-pty)

```bash
# Run with SDK (interactive mode)
npm start run-sdk examples/01_hello_world.json

# Run with debug output
npm start run-sdk config.json --debug

# Specify custom WXC executable path
npm start run-sdk config.json --wxc-path "C:\path\to\wxc-exec.exe"
```

#### Platform Information

```bash
# Show platform support information
npm start platform
```

#### Utility Commands

```bash
# Validate configuration
npm start validate config.json

# Encode configuration to base64
npm start encode config.json
```

### Programmatic API

#### Using WxcExecutor (Original API)

```typescript
import { WxcExecutor, createMinimalConfig } from 'wxc-cli';

// Create executor
const executor = new WxcExecutor('path/to/wxc-exec.exe');

// Run with config file
const result = await executor.run('config.json', {
  debug: true
});

console.log('Success:', result.success);
console.log('Exit code:', result.exitCode);
console.log('Output:', result.stdout);
```

#### Using SDK API (Recommended)

```typescript
import {
  SdkWrapper,
  getPlatformSupport,
  SandboxConfig,
  spawnSandbox
} from 'wxc-cli';

// Check platform support
if (!getPlatformSupport().supported) {
  console.error('WXC is currently only supported on Windows 11');
  process.exit(1);
}

// Option 1: Use SdkWrapper
const sdk = new SdkWrapper();
const config: SandboxPolicy = {
  script: 'python -c "print(\'Hello from sandbox!\')"',
  appContainer: {
    name: 'MyApp',
    learningMode: true
  }
};

const pty = sdk.spawn(config);
pty.onData((data) => console.log(data));
pty.onExit((e) => console.log('Exit code:', e.exitCode));

// Option 2: Use SDK functions directly
import { spawnSandbox, spawnSandboxAsync } from 'wxc-cli';

// Interactive mode
const pty2 = spawnSandbox(config);

// Async mode (waits for completion)
const result = await spawnSandboxAsync(config);
console.log('Output:', result.stdout);
console.log('Exit code:', result.exitCode);
```

## Configuration Examples

### Minimal Configuration

```json
{
  "script": {
    "code": "print('Hello World')"
  }
}
```

### Network Restricted

```json
{
  "script": {
    "code": "import urllib.request; print(urllib.request.urlopen('https://api.github.com').read())"
  },
  "network": {
    "defaultPolicy": "block",
    "allowedHosts": ["api.github.com"]
  }
}
```

### Filesystem Restricted

```json
{
  "script": {
    "code": "with open('C:\\\\temp\\\\output.txt', 'w') as f: f.write('test')"
  },
  "filesystem": {
    "allowedPaths": ["C:\\temp"],
    "deniedPaths": ["C:\\Windows\\System32"]
  }
}
```

### Full Configuration

```json
{
  "script": {
    "code": "import sys; print(sys.version)",
    "timeout": 30000
  },
  "executionMode": "appContainer",
  "appContainer": {
    "name": "MyApp",
    "leastPrivilegeMode": true,
    "capabilities": ["internetClient", "documentsLibrary"]
  },
  "network": {
    "defaultPolicy": "block",
    "enforcementMode": "both",
    "allowedHosts": ["api.example.com"]
  },
  "filesystem": {
    "allowedPaths": ["C:\\temp"],
    "restoreAclsOnExit": true
  },
  "python": {
    "executablePath": "C:\\Python\\python.exe",
    "workingDirectory": "C:\\Projects"
  }
}
```

## TypeScript API

### SDK API (Recommended)

#### Platform Detection

```typescript
import {
  getPlatformSupport
} from 'wxc-cli';

// Get detailed platform info
const info = getPlatformSupport();
// { isSupported: true, platform: 'win32', availableMethods: ['appcontainer'] }
```

#### Spawning Sandboxed Processes

```typescript
import {
  spawnSandbox,
  spawnSandboxAsync,
  SandboxConfig,
  SdkWrapper
} from 'wxc-cli';

// Interactive mode with node-pty
const config: SandboxConfig = {
  script: 'python -c "print(\'Hello\')"',
  timeout: 5000
};

const pty = spawnSandbox(config);
pty.onData((data) => console.log(data));
pty.onExit((e) => console.log('Exit code:', e.exitCode));

// Async mode (waits for completion)
const result = await spawnSandboxAsync(config);
console.log(result.stdout);

// Using SdkWrapper class
const sdk = new SdkWrapper('/path/to/wxc-exec.exe');
const pty2 = sdk.spawn(config);
```

#### SDK Types

- `SandboxConfig` - Sandbox configuration (matches wxc-exec JSON schema)
- `WxcAppContainerConfig` - AppContainer settings
- `WxcFilesystemConfig` - Filesystem policies
- `WxcNetworkConfig` - Network policies
- `SandboxingMethod` - Available sandboxing methods ('appcontainer')
- `PlatformSupport` - Platform support information
- `SandboxSpawnOptions` - Options for spawning sandboxed processes

### Legacy API (WxcExecutor)

#### WxcExecutor Class

```typescript
class WxcExecutor {
  constructor(wxcPath: string);
  run(config: string, options?: WxcExecutionOptions): Promise<WxcExecutionResult>;
  getWxcPath(): string;
}
```

#### Legacy Types

- `WxcConfiguration` - Main configuration interface
- `WxcScriptConfig` - Script configuration
- `WxcAppContainerConfig` - AppContainer settings
- `WxcRestrictedTokenConfig` - Restricted token settings
- `WxcFilesystemConfig` - Filesystem policies
- `WxcNetworkConfig` - Network policies
- `WxcPythonConfig` - Python interpreter settings

#### Helper Functions

Both APIs provide helper functions:

- `createMinimalConfig(code: string)` - Create minimal valid config
- `createNetworkRestrictedConfig(code: string, allowedHosts: string[])` - Create network-restricted config
- `createFilesystemRestrictedConfig(code: string, allowedPaths: string[], deniedPaths?: string[])` - Create filesystem-restricted config

## Development

```bash
# Build
npm run build

# Watch mode
npm run watch

# Run directly with ts-node
npm run dev -- run config.json

# Lint
npm run lint

# Clean build artifacts
npm run clean
```

## License

MIT
