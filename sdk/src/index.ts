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
 *     version: '0.6.0-alpha',
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
  SandboxingMethod,
  IsolationTier,
  ContainmentType,
  ContainmentTypes,
  ContainmentBackend,
  ExperimentalBackends,
  ContainerConfig,
  PlatformSupport,
  UiCapabilitySupport,
} from './types.js';

// Export platform detection functions
export {
  getPlatformSupport,
} from './platform.js';

// Export sandbox spawning functions
export {
  createConfigFromPolicy,
  spawnSandbox,
  spawnSandboxAsync,
  spawnSandboxFromConfig,
  buildSandboxPayload,
  SandboxSpawnOptions,
} from './sandbox.js';

// Export policy discovery functions
export {
  getAvailableToolsPolicy,
  getUserProfilePolicy,
  getTemporaryFilesPolicy,
  FilesystemPolicyResult,
  ToolsPolicyOptions,
} from './policy.js';

// Export typed wire-format errors
export {
  ErrorCode,
  MxcError,
  mxcErrorFromCode,
} from './errors.js';

// Export state-aware lifecycle types
export {
  Phase,
  StateAwareContainmentBackend,
  SandboxId,
  IsolationSessionUserConfig,
  IsolationSessionProvisionConfig,
  IsolationSessionStartConfig,
  IsolationSessionExecConfig,
  IsolationSessionStopConfig,
  IsolationSessionDeprovisionConfig,
  IsolationSessionProvisionMetadata,
  ConfigsForBackend,
  ProvisionConfigFor,
  StartConfigFor,
  ExecConfigFor,
  StopConfigFor,
  DeprovisionConfigFor,
  StateAwareMetadata,
  ProvisionMetadataFor,
  StartMetadataFor,
  StopMetadataFor,
  DeprovisionMetadataFor,
  ProvisionResult,
  StartResult,
  StopResult,
  DeprovisionResult,
  ExecResult,
} from './state-aware-types.js';

// Export state-aware lifecycle functions
export {
  provisionSandbox,
  startSandbox,
  execInSandbox,
  execInSandboxAsync,
  stopSandbox,
  deprovisionSandbox,
} from './state-aware.js';
