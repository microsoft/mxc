// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * MXC SDK - TypeScript SDK for Microsoft eXecution Containers
 *
 * This package provides a Node.js interface for spawning sandboxed containers.
 * For direct Windows ProcessContainer configs, set
 * `processContainer.learningMode: true` to enable deny-and-record learning
 * mode. Learning-mode capability names are reserved and must not be supplied
 * directly in `processContainer.capabilities`.
 * On Linux, `getPlatformSupport()` reports failures for individual backends
 * through `PlatformSupport.unavailableReasons`, including when none is usable.
 *
 * Schema `0.8.0-alpha` policies may use directional
 * `network.egress` / `network.ingress`, `runtimeConfig.networkProxy`, and
 * `processContainer.network.allowedProxyPeer` through `createConfigFromPolicy`.
 * These fields cannot be mixed with legacy network fields.
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
  ProcessContainerConfig,
  NetworkAction,
  NetworkProtocol,
  NetworkPeerConfig,
  NetworkPortConfig,
  NetworkRuleConfig,
  NetworkEgressConfig,
  NetworkIngressConfig,
  RuntimeConfig,
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

// Export typed wire-format errors.
//
// `WireError` and `mxcErrorFromEnvelope` are deliberately NOT re-exported:
// they exist so the SDK's own envelope-parsing sites share one widening
// point, and keeping them module-internal leaves the wire-parsing internals
// free to change. `MxcErrorFields` *is* exported because it is the parameter
// type of a public `MxcError` constructor overload — hiding the name would
// leave the type usable via an object literal but impossible to name.
export {
  ErrorCode,
  MxcError,
  MxcErrorFields,
  mxcErrorFromCode,
} from './errors.js';

// Export state-aware lifecycle types
export {
  Phase,
  STATE_AWARE_VERSION,
  StateAwareContainmentBackend,
  StateAwareSchemaVersion,
  SandboxId,
  IsolationSessionProvisionConfig,
  IsolationSessionStartConfig,
  IsolationSessionExecConfig,
  IsolationSessionStopConfig,
  IsolationSessionDeprovisionConfig,
  IsolationSessionProvisionMetadata,
  WindowsSandboxProvisionConfig,
  WindowsSandboxStartConfig,
  WindowsSandboxExecConfig,
  WindowsSandboxStopConfig,
  WindowsSandboxDeprovisionConfig,
  WslcProvisionConfig,
  WslcStartConfig,
  WslcExecConfig,
  WslcStopConfig,
  WslcDeprovisionConfig,
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
