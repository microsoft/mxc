/**
 * WXC SDK - TypeScript SDK for execution containers
 *
 * This package provides a Node.js interface for spawning sandboxed processes
 * on Windows using the WXC system.
 *
 * @example
 * ```typescript
 * import { spawnSandbox, SandboxConfig, getPlatformSupport } from '@microsoft/mxc-sdk';
 *
 * if (getPlatformSupport().isSupported) {
 *   const config: SandboxConfig = {
 *     script: 'python -c "print(\'Hello from sandbox\')"',
 *     appContainer: {
 *       name: 'MyApp',
 *       learningMode: true
 *     }
 *   };
 *
 *   const pty = spawnSandbox(config);
 *   pty.onData((data) => console.log(data));
 *   pty.onExit((e) => console.log('Exit code:', e.exitCode));
 * }
 * ```
 *
 * @packageDocumentation
 */

// Export types
export {
  SandboxPolicy,
  SandboxingMethod,
  PlatformSupport,
} from './types';

// Export platform detection functions
export {
  getPlatformSupport,
} from './platform';

// Export sandbox spawning functions
export {
  spawnSandbox,
  spawnSandboxAsync,
  SandboxSpawnOptions
} from './sandbox';

// Export policy discovery functions
export {
  getAvailableToolsPolicy,
  getUserProfilePolicy,
  getTemporaryFilesPolicy,
  FilesystemPolicyResult,
  ToolsPolicyOptions,
} from './policy';
