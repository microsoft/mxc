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
  SandboxPolicy,
  SandboxContainment,
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
} from './types.js';

export {
  createConfigFromPolicy,
  spawnSandbox,
  spawnSandboxAsync,
  buildSandboxPayload,
} from './sandbox.js';

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
  SandboxId,
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
  type StateAwareStreamingOptions,
  provisionSandbox,
  startSandbox,
  execInSandbox,
  execInSandboxAsync,
  stopSandbox,
  deprovisionSandbox,
} from './state-aware.js';
