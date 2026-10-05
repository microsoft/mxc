// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type { TelemetryConfig } from './types.js';
import type { MxcPtySize } from './mxc-pty-process.js';

/** Invocation controls for run and runAsync. */
export interface RunOptions {
  experimental?: boolean;
  /** Per-invocation telemetry opt-in, subject to consent and policy. */
  telemetry?: TelemetryConfig;
}

/** Invocation controls for spawn and spawnAsync. */
export interface SpawnOptions {
  experimental?: boolean;
  /** Per-invocation telemetry opt-in, subject to consent and policy. */
  telemetry?: TelemetryConfig;
}

/** Invocation controls for spawning a caller-controlled terminal. */
export interface SpawnWithPtyOptions {
  experimental?: boolean;
  /** Per-invocation telemetry opt-in, subject to consent and policy. */
  telemetry?: TelemetryConfig;
  size?: MxcPtySize;
}

/** Invocation controls for provisioning a container. */
export interface ProvisionOptions {
  experimental?: boolean;
  telemetry?: TelemetryConfig;
}

/** Invocation controls for starting a container. */
export interface StartOptions {
  experimental?: boolean;
  telemetry?: TelemetryConfig;
}

/** Invocation controls for stopping a container. */
export interface StopOptions {
  experimental?: boolean;
  telemetry?: TelemetryConfig;
}

/** Invocation controls for releasing a container. */
export interface DeprovisionOptions {
  experimental?: boolean;
  telemetry?: TelemetryConfig;
}

/** Invocation controls for live execution in an existing container. */
export interface SpawnInContainerOptions {
  experimental?: boolean;
  telemetry?: TelemetryConfig;
}

/** Invocation controls for captured execution in an existing container. */
export interface RunInContainerOptions {
  experimental?: boolean;
  telemetry?: TelemetryConfig;
}

/** Invocation controls for a terminal in an existing container. */
export interface SpawnInContainerWithPtyOptions {
  experimental?: boolean;
  telemetry?: TelemetryConfig;
  size?: MxcPtySize;
}
