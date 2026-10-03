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
 * V1 request APIs live in `@microsoft/mxc-sdk/v1` and use directional
 * `network.egress` / `network.ingress`; explicit legacy network inputs produce
 * migration errors. The versioned V1 request and execution APIs are available
 * from `@microsoft/mxc-sdk/v1`.
 * WSLC state-aware exec uses top-level `runtimeConfig.networkProxy` without
 * restating network posture. IsolationSession provision requires
 * directional egress, ingress, and host-loopback defaults set to `allow`.
 *
 * @example
 * ```typescript
 * import { getPlatformSupport } from '@microsoft/mxc-sdk';
 * import { runAsync } from '@microsoft/mxc-sdk/v1';
 *
 * if (getPlatformSupport().isSupported) {
 *   const output = await runAsync({
 *     network: { egress: { default: 'allow' } },
 *     command: 'python -c "print(\'Hello from sandbox\')"',
 *   });
 *   console.log('Execution output:', output.stdout);
 *   console.log('Exit code:', output.exitCode);
 * }
 * ```
 *
 * @packageDocumentation
 */

// Export types
export {
  IsolationTier,
  PlatformSupport,
  UiCapabilitySupport,
  ProbeOutput,
  ProbeFacts,
  BubblewrapNetworkSupport,
} from './types.js';

// Export platform detection functions
export {
  getPlatformSupport,
} from './platform.js';

export {
  probeSandboxSupport,
} from './probe.js';

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

// Export telemetry consent functions and types
export {
  TelemetryConfig,
} from './types.js';

export {
  TelemetryConsentMessage,
  TelemetryConsentResult,
  TelemetryConsentState,
  TelemetryConsentPrompt,
  TelemetryConsentDecision,
  TelemetryConsentOutcome,
  TelemetryConsentPresenter,
  TelemetryConsentQuery,
  TelemetryPolicyState,
  requestTelemetryConsent,
  queryTelemetryConsentAsync,
  withdrawTelemetryConsentAsync,
} from './telemetry.js';
