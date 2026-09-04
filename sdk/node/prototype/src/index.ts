// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

export { MxcError, type MxcErrorFields } from './errors.js';
export type {
  AvailableBackend,
  JsonObject,
  JsonPrimitive,
  JsonValue,
  NativePlatformSupport,
  RunSandboxRequest,
  RunSandboxResult,
  StateAwareEnvelope,
  StateAwareOptions,
  StateAwareRequest,
  ExecAttachedOptions,
  PollResult,
  WaitResult,
} from './types.js';
export {
  Sandbox,
  SandboxInput,
  SandboxOutput,
  execSandbox,
  execSandboxSync,
  spawnSandbox,
  spawnSandboxSync,
} from './handles.js';
export {
  getAvailableBackends,
  getPlatformSupport,
  getVersion,
  provisionSandbox,
  provisionSandboxSync,
  startSandbox,
  startSandboxSync,
  stopSandbox,
  stopSandboxSync,
  deprovisionSandbox,
  deprovisionSandboxSync,
  execAttachedSandbox,
  execAttachedSandboxSync,
  runSandbox,
  runSandboxSync,
} from './generated/api.js';
