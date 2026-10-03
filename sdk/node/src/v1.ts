// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * V1 contract-mapped MXC SDK APIs.
 *
 * These policy, request-building, and typed lifecycle APIs target the latest
 * published 1.x exact contract owned by this SDK. Callers do not supply a
 * schema version on this path; use the root raw-config APIs when a request must
 * declare its own exact contract version.
 *
 * @packageDocumentation
 */

export {
  ContainerBackendConfig,
  ContainerRequest,
  MxcOptions,
  ProcessContainerConfig,
  NetworkAction,
  NetworkProtocol,
  NetworkPeerConfig,
  NetworkPortConfig,
  NetworkRuleConfig,
  NetworkEgressConfig,
  NetworkIngressConfig,
  DirectionalNetworkConfig,
  RuntimeConfig,
  FilesystemConfig,
  ClipboardPolicy,
  BaseProcessUiConfig,
  LxcConfig,
  SeatbeltConfig,
  WslcConfig,
  TelemetryConfig,
  Output,
} from './types.js';

export {
  spawn,
  spawnAsync,
  spawnWithPty,
  run,
  runAsync,
} from './sandbox.js';
export { MxcSandboxProcess as MxcProcess } from './sandbox-process.js';
export type { SandboxWaitResult as WaitOutcome } from './sandbox-process.js';
export { MxcPtyProcess } from './mxc-pty-process.js';
export type { MxcPtySize } from './mxc-pty-process.js';

export {
  getAvailableToolsPolicy,
  getUserProfilePolicy,
  getTemporaryFilesPolicy,
  FilesystemPolicyResult,
  ToolsPolicyOptions,
} from './policy.js';

export {
  Phase,
  STATE_AWARE_VERSION,
  StateAwareContainmentBackend,
  ContainerId,
  ExecRequest,
  IsolationSessionNetworkConfig,
  IsolationSessionProvisionConfig,
  IsolationSessionStartConfig,
  IsolationSessionExecConfig,
  IsolationSessionStopConfig,
  IsolationSessionDeprovisionConfig,
  IsolationSessionProvisionMetadata,
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

export {
  spawnInContainer,
  runInContainer,
  provisionSandbox,
  startSandbox,
  execInSandboxAttached,
  execInSandbox,
  spawnInContainerWithPty,
  execInSandboxAsync,
  stopSandbox,
  deprovisionSandbox,
} from './state-aware.js';
