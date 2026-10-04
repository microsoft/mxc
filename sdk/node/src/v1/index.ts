// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * V1 contract-mapped MXC SDK APIs.
 *
 * These policy, request-building, and typed lifecycle APIs target the latest
 * published 1.x exact contract owned by this SDK. Callers do not supply a
 * schema version on this path.
 *
 * @packageDocumentation
 */

export {
  ContainerRequest,
  DirectionalNetworkConfig,
  NetworkEgressConfig,
  NetworkIngressConfig,
  NetworkPeerConfig,
  NetworkPortConfig,
  NetworkRuleConfig,
  NetworkRuntimeConfig,
  FilesystemConfig,
  ClipboardPolicy,
  BaseProcessUiConfig,
  ProcessContainerConfig,
  LxcConfig,
  SeatbeltConfig,
  WslcConfig,
  TelemetryConfig,
  ExecutionResult,
  ExecutionMetadata,
  CaptureDenialsResult,
  CaptureDenialsError,
} from './types.js';

export type {
  Containment,
  FilesystemPolicy,
  NetworkPolicy,
  UiPolicy,
} from './types.js';

export type {
  RunOptions,
  SpawnOptions,
  SpawnWithPtyOptions,
  ProvisionOptions,
  StartOptions,
  StopOptions,
  DeprovisionOptions,
  SpawnInContainerOptions,
  RunInContainerOptions,
  SpawnInContainerWithPtyOptions,
} from './operation-options.js';

export {
  spawn,
  spawnAsync,
  spawnWithPty,
  run,
  runAsync,
} from './container.js';
export { MxcProcess } from './container-process.js';
export type { WaitResult } from './container-process.js';
export { MxcPtyProcess } from './mxc-pty-process.js';
export type { MxcPtySize } from './mxc-pty-process.js';

export * as policy from './policy/index.js';

export {
  SDK_CONTRACT_VERSION,
  LifecycleContainmentKind,
  ContainerId,
  ExecutionRequest,
  ProvisionRequest,
  IsolationSessionNetworkConfig,
  IsolationSessionProvisionMetadata,
  ContainerMetadata,
  ProvisionMetadata,
  ProvisionResult,
  ValidationResult,
  LifecycleResult,
} from './lifecycle-types.js';
export type { ProcessNetworkConfig } from './lifecycle-types.js';

export {
  spawnInContainer,
  spawnInContainerAsync,
  provisionContainer,
  startContainer,
  spawnInContainerWithPty,
  runInContainer,
  runInContainerAsync,
  stopContainer,
  deprovisionContainer,
  validateProvision,
  validateStart,
  validateStop,
  validateDeprovision,
  validateProcess,
} from './lifecycle.js';

// Export types
export {
  IsolationTier,
  AvailableBackend,
  BackendCapability,
  ContainmentBackend,
  PlatformSupport,
  UiCapabilitySupport,
  ProbeOutput,
  ProbeFacts,
  BubblewrapNetworkSupport,
} from './types.js';

// Export platform detection functions
export {
  getAvailableBackends,
  getPlatformSupport,
} from './platform.js';

export {
  probe,
} from './probe.js';

// Export typed wire-format errors.
//
// `WireError` and `mxcErrorFromEnvelope` are deliberately NOT re-exported:
// they exist so the SDK's own envelope-parsing sites share one widening
// point, and keeping them module-internal leaves the wire-parsing internals
// free to change. `MxcErrorFields` *is* exported because it is the parameter
// type of a public `MxcError` constructor overload â€” hiding the name would
// leave the type usable via an object literal but impossible to name.
export {
  ErrorCode,
  MxcError,
  MxcErrorFields,
  mxcErrorFromCode,
} from './errors.js';

// Export telemetry consent functions and types
export {
  TelemetryConsentMessage,
  TelemetryConsentResult,
  TelemetryConsentState,
  TelemetryConsentPrompt,
  TelemetryConsentDecision,
  TelemetryConsentOutcome,
  TelemetryConsentPresenter,
  TelemetryConsentStatus,
  TelemetryPolicyState,
  requestTelemetryConsentAsync,
  getTelemetryConsentStatusAsync,
  withdrawTelemetryConsentAsync,
} from './telemetry.js';
