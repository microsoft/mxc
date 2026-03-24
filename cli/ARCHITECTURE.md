# MXC CLI Architecture

## Overview

The MXC CLI is a TypeScript-based Node.js wrapper for the Microsoft eXecution Containers (MXC) restricted container environment. It provides both a command-line interface and a programmatic API for invoking MXC with type-safe configuration. The CLI supports cross-platform operation on Windows (via AppContainer/Windows Sandbox) and Linux (via LXC containers).

## Project Structure

```
cli/
├── src/
│   ├── cli.ts              # CLI entry point using Commander.js
│   ├── wxc-executor.ts     # Core executor class for spawning WXC process
│   ├── types.ts            # TypeScript interfaces matching WXC config
│   └── index.ts            # Public API exports
├── dist/                   # Compiled JavaScript output
├── example.ts              # Usage examples
├── package.json            # NPM package configuration
├── tsconfig.json           # TypeScript compiler configuration
├── .eslintrc.json          # ESLint configuration
└── README.md               # User documentation
```

## Components

### 1. CLI Interface (`cli.ts`)

The command-line interface built with Commander.js provides three main commands:

- **run**: Execute script code with WXC
  - Accepts config file path or base64-encoded config
  - Supports --config-base64 and --debug flags
  - Allows custom WXC executable path

- **validate**: Validate configuration file
  - Checks JSON syntax
  - Validates required fields
  - Reports configuration summary

- **encode**: Encode configuration to base64
  - Reads JSON file
  - Outputs base64-encoded string
  - Useful for embedding configs in commands

### 2. Executor (`wxc-executor.ts`)

The `WxcExecutor` class handles process spawning and communication:

- Validates WXC executable exists
- Spawns child process with appropriate arguments
- Captures stdout/stderr streams
- Returns structured execution result
- Supports debug mode for real-time output

**Key Methods:**
- `constructor(wxcPath: string)` - Initialize with path to wxc-exec.exe
- `run(config, options)` - Execute WXC with configuration
- `getWxcPath()` - Get configured WXC path

### 3. Type Definitions (`types.ts`)

TypeScript interfaces that mirror the WXC Rust configuration structure:

- `WxcConfiguration` - Root configuration object
- `WxcScriptConfig` - Script code, input, timeout
- `WxcAppContainerConfig` - AppContainer settings
- `WxcRestrictedTokenConfig` - Token restriction settings
- `WxcFilesystemConfig` - File access policies
- `WxcNetworkConfig` - Network access policies
- `WxcPythonConfig` - Python interpreter settings

**Helper Functions:**
- `createMinimalConfig()` - Quick config for simple scripts
- `createNetworkRestrictedConfig()` - Config with network limits
- `createFilesystemRestrictedConfig()` - Config with filesystem limits

## Data Flow

```
CLI Command
    │
    ├─> Parse arguments (Commander.js)
    │
    ├─> Detect platform (Windows or Linux)
    │   • Windows → uses wxc-exec.exe (AppContainer or Sandbox backend)
    │   • Linux → uses lxc-exec (LXC container backend)
    │
    └─> WxcExecutor.run()
            │
            ├─> Validate platform-appropriate executable exists
            │
            ├─> Build command-line arguments
            │   • config path or base64 string
            │   • --config-base64 flag (if needed)
            │   • --debug flag (if requested)
            │
            ├─> spawn() sandboxed process
            │
            ├─> Capture stdout/stderr streams
            │
            └─> Return WxcExecutionResult
                    │
                    └─> Display results to user
```

> **Note:** The SDK's `spawnSandbox()` function automatically selects the correct binary
> (`wxc-exec.exe` on Windows, `lxc-exec` on Linux) based on the detected platform.

## Configuration Flow

### File-based Configuration
```
JSON file → Read → Parse → Pass path to WXC → WXC loads & validates
```

### Base64-encoded Configuration
```
JSON file → Read → Encode to base64 → Pass to WXC with --config-base64 → WXC decodes & validates
```

## Error Handling

The CLI implements multiple layers of error handling:

1. **Validation Layer** (CLI)
   - File existence checks
   - JSON parsing errors
   - Required field validation

2. **Process Layer** (WxcExecutor)
   - WXC executable not found
   - Process spawn failures
   - Unexpected termination

3. **WXC Layer** (WXC executable)
   - Configuration validation errors
   - Python execution errors
   - Sandbox policy violations

## Design Decisions

### Why TypeScript?
- Type safety for configuration objects
- Better IDE support with autocomplete
- Compile-time error detection
- Easy to maintain and refactor

### Why Commander.js?
- Standard CLI framework for Node.js
- Clean command definition syntax
- Built-in help generation
- Argument parsing and validation

### Why Spawn Child Process?
- Clean separation between CLI and WXC
- No need to recompile WXC
- Can use any WXC executable location
- Captures all output streams

### Why Base64 Support?
- Avoids temp file creation
- Easier to embed in automation
- Single atomic operation
- Safer for special characters

## Extension Points

### Adding New Commands

```typescript
program
  .command('my-command')
  .description('Description here')
  .argument('<arg>', 'Argument description')
  .option('--flag', 'Option description')
  .action(async (arg, options) => {
    // Implementation
  });
```

### Adding Configuration Helpers

```typescript
export function createCustomConfig(params: any): WxcConfiguration {
  return {
    script: { code: params.code },
    // Custom configuration logic
  };
}
```

### Adding Execution Options

```typescript
export interface WxcExecutionOptions {
  isBase64?: boolean;
  debug?: boolean;
  // Add new options here
}
```

## Testing Strategy

Future testing should cover:

1. **Unit Tests**
   - Configuration helpers
   - Validation logic
   - Type conversions

2. **Integration Tests**
   - WxcExecutor with mock WXC
   - CLI commands end-to-end
   - Error handling paths

3. **E2E Tests**
   - Full workflow with real WXC
   - All example configurations
   - Error scenarios

## Dependencies

### Production
- **commander**: CLI argument parsing

### Development
- **typescript**: Language compiler
- **@types/node**: Node.js type definitions
- **eslint**: Code linting
- **ts-node**: Direct TypeScript execution

## Performance Considerations

- **Process Spawn**: ~10-50ms overhead
- **Base64 Encoding**: Negligible for configs <1MB
- **JSON Parsing**: Fast for typical config sizes
- **Stream Processing**: Efficient for large outputs

## Security Considerations

- Never execute untrusted configurations without review
- Base64 encoding is NOT encryption
- Validate all user inputs
- Use absolute paths for WXC executable
- Avoid shell injection in spawned commands
