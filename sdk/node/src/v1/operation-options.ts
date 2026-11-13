// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type { TelemetryConfig } from './types.js';
import type { MxcPtySize } from './mxc-pty-process.js';

/** Invocation controls for run. */
export interface RunOptions {
  /** Per-invocation telemetry opt-in, subject to consent and policy. */
  telemetry?: TelemetryConfig;
}

/** Invocation controls for spawn. */
export interface SpawnOptions {
  /** Per-invocation telemetry opt-in, subject to consent and policy. */
  telemetry?: TelemetryConfig;
}

/** Invocation controls for spawning a caller-controlled terminal. */
export interface SpawnWithPtyOptions {
  /** Per-invocation telemetry opt-in, subject to consent and policy. */
  telemetry?: TelemetryConfig;
  size?: MxcPtySize;
}

/** How spawnWithExtendedOptions connects the workload's standard streams. */
export type SpawnStdio = 'pipes' | 'inherit';

/** Invocation controls for spawnWithExtendedOptions. */
export interface SpawnWithExtendedOptions {
  /** Per-invocation telemetry opt-in, subject to consent and policy. */
  telemetry?: TelemetryConfig;
  /** Defaults to `'pipes'`, which behaves like `spawn`. */
  stdio?: SpawnStdio;
}

/** Invocation controls for provisioning a container. */
export interface ProvisionOptions {
  telemetry?: TelemetryConfig;
}

/** Invocation controls for starting a container. */
export interface StartOptions {
  telemetry?: TelemetryConfig;
}

/** Invocation controls for stopping a container. */
export interface StopOptions {
  telemetry?: TelemetryConfig;
}

/** Invocation controls for releasing a container. */
export interface DeprovisionOptions {
  telemetry?: TelemetryConfig;
}

/** Invocation controls for live execution in an existing container. */
export interface SpawnInContainerOptions {
  telemetry?: TelemetryConfig;
}

/** Invocation controls for captured execution in an existing container. */
export interface RunInContainerOptions {
  telemetry?: TelemetryConfig;
}

/** Invocation controls for a terminal in an existing container. */
export interface SpawnInContainerWithPtyOptions {
  telemetry?: TelemetryConfig;
  size?: MxcPtySize;
}
