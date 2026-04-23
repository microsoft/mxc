// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * MXC SDK - TypeScript SDK for Microsoft eXecution Containers
 *
 * This package provides a Node.js interface for spawning sandboxed containers.
 *
 * @example
 * ```typescript
 * import { spawnSandbox, spawnSandboxWithPty, SandboxPolicy, getPlatformSupport } from '@microsoft/mxc-sdk';
 *
 * if (getPlatformSupport().isSupported) {
 *   const policy: SandboxPolicy = {
 *     version: '0.4.0-alpha',
 *     network: { allowOutbound: true },
 *   };
 *
 *   const ptyProcess = spawnSandboxWithPty('python -c "print(\'Hello from sandbox\')"', policy);
 *   ptyProcess.onData((data) => console.log(data));
 *   ptyProcess.onExit((event) => console.log('Exit code:', event.exitCode));
 * }
 * ```
 *
 * @packageDocumentation
 */

// Export types
export {
  SandboxPolicy,
  SandboxPolicySpec,
  SandboxPolicyCookie,
  SandboxingMethod,
  ContainmentType,
  ExperimentalBackends,
  ContainerConfig,
  PlatformSupport,
} from './types';

// Export platform detection functions
export {
  getPlatformSupport,
} from './platform';

// Export sandbox spawning functions
export {
  createConfigFromPolicy,
  spawnSandbox,
  spawnSandboxFromConfig,
  spawnSandboxAsync,
  spawnSandboxWithoutPty,
  spawnSandboxPty,
  buildSandboxPayload,
  isAegisManagedMode,
  SandboxSpawnOptions,
} from './sandbox';

// Export policy discovery functions
export {
  getAvailableToolsPolicy,
  getUserProfilePolicy,
  getTemporaryFilesPolicy,
  FilesystemPolicyResult,
  ToolsPolicyOptions,
} from './policy';

// Export cookie redemption functions
export {
  redeemCookie,
  getPipePath,
  RedeemResult,
} from './cookieRedeemer';
