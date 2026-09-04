// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

export type JsonPrimitive = boolean | number | string | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export interface JsonObject {
  [key: string]: JsonValue;
}

/**
 * A serialized execution request accepted by the generated mxc_ffi operation.
 *
 * An object is serialized once on the JavaScript thread; a string is assumed
 * to be the already-serialized request JSON. The prototype deliberately does
 * not duplicate the evolving Rust request model.
 */
export type RunSandboxRequest = JsonObject | string;
export type StateAwareRequest = JsonObject | string;
export interface StateAwareOptions {
  dryRun?: boolean;
  experimental?: boolean;
}
export interface ExecAttachedOptions {
  experimental?: boolean;
}
export type StateAwareEnvelope = JsonValue;
export interface WaitResult {
  timedOut: boolean;
  exitCode: number;
}

export interface RunSandboxResult {
  exitCode: number;
  timedOut: boolean;
  stdout: string;
  stderr: string;
  warnings: readonly string[];
  outputMetadata?: unknown;
}

export interface AvailableBackend {
  backend: string;
  [key: string]: unknown;
}

export interface NativePlatformSupport {
  isSupported: boolean;
  reason: string | null;
  availableMethods: readonly string[];
  [key: string]: unknown;
}
