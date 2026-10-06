// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { Readable } from 'node:stream';
import { diagLog } from '../diagnostic.js';
import { MxcError } from './errors.js';
import {
  runBindingStateAwareRequestAsync,
} from '../bindings/state-aware.js';
import {
  spawnStateAwareBindingSandboxProcessAsync,
} from '../bindings/streaming.js';
import { execStateAwareBindingSandboxWithPty } from '../bindings/pty.js';
import type { MxcPtyProcess } from './mxc-pty-process.js';
import {
  LifecycleResult,
  ExecutionRequest,
  ProvisionRequest,
  ProvisionMetadata,
  ProvisionResult,
  ContainerId,
  LifecycleContainmentKind,
  ValidationResult,
} from './lifecycle-types.js';
import type { MxcOptions } from './types.js';
import type { TelemetryConfig } from './types.js';
import type { ExecutionResult } from './types.js';
import type {
  ProvisionOptions, StartOptions, StopOptions, DeprovisionOptions,
  SpawnInContainerOptions, RunInContainerOptions, SpawnInContainerWithPtyOptions,
} from './operation-options.js';
import type {
  MxcProcess,
} from './container-process.js';
import {
  backendForSandboxId,
  buildStateAwareEnvelope,
  parseNonExecResponse,
} from '../state-aware-helper.js';

const PIPED_EXEC_BACKENDS = [
  'isolation_session',
  'wslc',
] as const satisfies readonly LifecycleContainmentKind[];
type PipedExecuteBackend = typeof PIPED_EXEC_BACKENDS[number];

function assertStateAwareOptions(
  apiName: string,
  options: MxcOptions & { telemetry?: TelemetryConfig },
  additionalOptionKeys: readonly string[] = [],
): void {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new MxcError('malformed_request', `${apiName} options must be an object`);
  }
  for (const [key, value] of Object.entries(options)) {
    if (key === 'telemetry') continue;
    if (
      key !== 'experimental' &&
      key !== 'dryRun' &&
      !additionalOptionKeys.includes(key)
    ) {
      throw new MxcError(
        'malformed_request',
        `${apiName} does not support option '${key}'`,
      );
    }
    if (additionalOptionKeys.includes(key)) continue;
    if (value !== undefined && typeof value !== 'boolean') {
      throw new MxcError(
        'malformed_request',
        `${apiName} option '${key}' must be a boolean`,
      );
    }
  }
}

function assertPipedExecBackend(
  apiName: string,
  sandboxId: ContainerId<LifecycleContainmentKind>,
): void {
  const backend = backendForSandboxId(sandboxId);
  const supportedBackends: readonly LifecycleContainmentKind[] = PIPED_EXEC_BACKENDS;
  if (!supportedBackends.includes(backend)) {
    throw new MxcError(
      'unsupported_containment',
      `${apiName} requires piped native exec streams; ${backend} does not expose them.`,
    );
  }
}

function logBackgroundFailure(operation: string, error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  diagLog(`state-aware: ${operation} failed: ${message}`);
}

async function runStateAwareEnvelopeRequest(
  apiName: string,
  envelope: Record<string, unknown>,
  options: MxcOptions,
): Promise<string> {
  assertStateAwareOptions(apiName, options);
  return runBindingStateAwareRequestAsync({
    requestJson: JSON.stringify(envelope),
    dryRun: options.dryRun === true,
    experimental: options.experimental === true,
  });
}

async function nonExecBindingCall(
  apiName: string,
  envelope: Record<string, unknown>,
  options: MxcOptions,
): Promise<Record<string, unknown>> {
  assertStateAwareStreamingOptions(apiName, options);
  return parseResultObject(await runStateAwareEnvelopeRequest(apiName, envelope, options), apiName);
}

function buildExecEnvelope<C extends LifecycleContainmentKind>(
  sandboxId: ContainerId<C>,
  request: ExecutionRequest<C>,
  telemetry?: TelemetryConfig,
): Record<string, unknown> {
  return buildStateAwareEnvelope({
    phase: 'exec',
    backendKey: backendForSandboxId(sandboxId) as C,
    sandboxId,
    config: {
      process: {
        commandLine: request.command,
        cwd: request.workingDirectory,
        env: request.environment === undefined ? undefined
          : Object.entries(request.environment).map(([key, value]) => `${key}=${value}`),
        inheritDefaultEnv: request.inheritDefaultEnvironment,
        timeout: request.timeoutMs,
      },
      network: request.network,
      telemetry: telemetry ?? request.telemetry,
    },
  });
}

function spawnStateAwareExecProcess<C extends LifecycleContainmentKind>(
  sandboxId: ContainerId<C>,
  request: ExecutionRequest<C>,
  options: SpawnInContainerOptions,
  apiName: string,
): Promise<MxcProcess> {
  assertStateAwareOptions(apiName, options);
  assertPipedExecBackend(apiName, sandboxId);
  return spawnStateAwareBindingSandboxProcessAsync(
    JSON.stringify(buildExecEnvelope(sandboxId, request, options.telemetry)),
    options.experimental === true,
    request.timeoutMs,
  );
}

function assertStateAwareStreamingOptions(
  apiName: string,
  options: MxcOptions,
  additionalOptionKeys: readonly string[] = [],
): void {
  assertStateAwareOptions(apiName, options, additionalOptionKeys);
  if (Object.hasOwn(options, 'dryRun')) {
    throw new MxcError(
      'malformed_request',
      `${apiName} does not support dryRun; use an explicit validation API`,
    );
  }
}

function collectStream(stream: Readable | null): Promise<string> {
  if (stream === null) {
    return Promise.resolve('');
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on('data', (chunk: Buffer | string) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    stream.once('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    stream.once('error', reject);
  });
}

/**
 * Provision a container from a closed backend-specific request.
 */
export async function provisionContainer<C extends LifecycleContainmentKind>(
  request: ProvisionRequest<C> & { containment: C },
  options: ProvisionOptions = {},
): Promise<ProvisionResult<C>> {
  assertStateAwareStreamingOptions('provisionContainer', options);
  const { containment, ...config } = request;
  const envelope = buildStateAwareEnvelope({
    phase: 'provision',
    backendKey: containment,
    containment,
    config: { ...config, telemetry: options.telemetry ?? config.telemetry },
  });
  const result = await nonExecBindingCall('provisionContainer', envelope, options);
  if (typeof result.sandboxId !== 'string') {
    throw new MxcError('backend_error', 'provision response carried no sandboxId');
  }
  const metadata = result.metadata;
  if (metadata !== undefined && metadata !== null) {
    if (containment !== 'isolation_session' || typeof metadata !== 'object' || Array.isArray(metadata)
        || !('agentUserName' in metadata) || typeof metadata.agentUserName !== 'string'
        || !('agentUserSid' in metadata) || typeof metadata.agentUserSid !== 'string'
        || !('ephemeralWorkspacePath' in metadata) || typeof metadata.ephemeralWorkspacePath !== 'string') {
      throw new MxcError('backend_error', 'provision response carried malformed or unsupported metadata');
    }
  }
  return {
    containerId: result.sandboxId as ContainerId<C>,
    metadata: metadata == null ? undefined : metadata as ProvisionMetadata<C>,
    warnings: parseWarnings(result, 'provision'),
  };
}

/**
 * Starts a previously provisioned container. The backend is inferred from
 * the container identifier.
 */
export async function startContainer<C extends LifecycleContainmentKind>(
  containerId: ContainerId<C>,
  options: StartOptions = {},
): Promise<LifecycleResult> {
  const backendKey = backendForSandboxId(containerId) as C;
  const envelope = buildStateAwareEnvelope({
    phase: 'start',
    backendKey,
    sandboxId: containerId,
    config: { telemetry: options.telemetry },
  });
  return { warnings: parseWarnings(await nonExecBindingCall('startContainer', envelope, options), 'start') };
}

/**
 * Streams a script execution inside a started IsolationSession or WSLC container over Node
 * pipes, returning an owning `MxcProcess` for waiting, termination,
 * stream access, and disposal.
 */
export async function spawnInContainer<C extends PipedExecuteBackend>(
  containerId: ContainerId<C>,
  request: ExecutionRequest<C>,
  options: SpawnInContainerOptions = {},
): Promise<MxcProcess> {
  assertStateAwareStreamingOptions('spawnInContainer', options);
  return spawnStateAwareExecProcess(
    containerId,
    request,
    options,
    'spawnInContainer',
  );
}

/** Execute a request in an existing container with an MXC-owned PTY. */
export async function spawnInContainerWithPty<C extends LifecycleContainmentKind>(
  containerId: ContainerId<C>,
  request: ExecutionRequest<C>,
  options: SpawnInContainerWithPtyOptions = {},
): Promise<MxcPtyProcess> {
  assertStateAwareStreamingOptions('spawnInContainerWithPty', options, ['size']);
  const size = options.size ?? { rows: 24, columns: 80 };
  if (
    !Number.isInteger(size.rows) ||
    !Number.isInteger(size.columns) ||
    size.rows < 1 ||
    size.rows > 32767 ||
    size.columns < 1 ||
    size.columns > 32767
  ) {
    throw new MxcError(
      'malformed_request',
      'PTY rows and columns must be integers between 1 and 32767',
    );
  }
  return execStateAwareBindingSandboxWithPty(
    JSON.stringify(buildExecEnvelope(containerId, request, options.telemetry)),
    options.experimental === true,
    size.rows,
    size.columns,
    request.timeoutMs,
  );
}

/**
 * Buffered exec convenience. Resolves with `{stdout, stderr, exitCode}`
 * on script completion. Native dispatch failures reject with `MxcError`;
 * workload failures are returned through the process exit code and streams.
 */
export async function runInContainer<C extends PipedExecuteBackend>(
  containerId: ContainerId<C>,
  request: ExecutionRequest<C>,
  options?: RunInContainerOptions,
): Promise<ExecutionResult>;
export async function runInContainer<C extends PipedExecuteBackend>(
  containerId: ContainerId<C>,
  request: ExecutionRequest<C>,
  options: RunInContainerOptions = {},
): Promise<ExecutionResult> {
  assertStateAwareStreamingOptions('runInContainer', options);
  assertPipedExecBackend('runInContainer', containerId);
  const proc = await spawnInContainer(containerId, request, options);
  const stdoutPromise = collectStream(proc.standardOutput);
  const stderrPromise = collectStream(proc.standardError);
  const waitPromise = Promise.all([proc.wait(), stdoutPromise, stderrPromise]);
  let failed = false;
  try {
    const [result, stdout, stderr] = await waitPromise;
    return {
      stdout,
      stderr,
      exitCode: result.exitCode,
      timedOut: result.timedOut,
      warnings: [...proc.warnings],
      ...(proc.outputMetadata === undefined
        ? {}
        : { outputMetadata: proc.outputMetadata }),
    };
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    try {
      proc.dispose();
    } catch (error) {
      if (!failed) throw error;
      logBackgroundFailure('disposing buffered exec after failure', error);
    }
  }
}

/**
 * Stops a started container without releasing its provision-side resources.
 * The same container can be started again via `startContainer`.
 */
export async function stopContainer<C extends LifecycleContainmentKind>(
  containerId: ContainerId<C>,
  options: StopOptions = {},
): Promise<LifecycleResult> {
  const backendKey = backendForSandboxId(containerId) as C;
  const envelope = buildStateAwareEnvelope({
    phase: 'stop',
    backendKey,
    sandboxId: containerId,
    config: { telemetry: options.telemetry },
  });
  return { warnings: parseWarnings(await nonExecBindingCall('stopContainer', envelope, options), 'stop') };
}

/**
 * Releases all backend resources associated with a provisioned container.
 * The id becomes invalid after this call returns successfully.
 */
export async function deprovisionContainer<C extends LifecycleContainmentKind>(
  containerId: ContainerId<C>,
  options: DeprovisionOptions = {},
): Promise<LifecycleResult> {
  const backendKey = backendForSandboxId(containerId) as C;
  const envelope = buildStateAwareEnvelope({
    phase: 'deprovision',
    backendKey,
    sandboxId: containerId,
    config: { telemetry: options.telemetry },
  });
  return { warnings: parseWarnings(await nonExecBindingCall('deprovisionContainer', envelope, options), 'deprovision') };
}

/** Validate provision without allocating a container or returning an identity. */
export async function validateProvision<C extends LifecycleContainmentKind>(
  request: ProvisionRequest<C> & { containment: C },
  options: ProvisionOptions = {},
): Promise<ValidationResult> {
  const { containment, ...config } = request;
  const envelope = buildStateAwareEnvelope({
    phase: 'provision',
    backendKey: containment,
    containment,
    config: { ...config, telemetry: options.telemetry ?? config.telemetry },
  });
  return parseValidationResponse(await runStateAwareEnvelopeRequest(
    'validateProvision', envelope, { ...options, dryRun: true },
  ));
}

/** Validate a start request without starting the container. */
export async function validateStart<C extends LifecycleContainmentKind>(
  containerId: ContainerId<C>,
  options: StartOptions = {},
): Promise<ValidationResult> {
  const envelope = buildStateAwareEnvelope({
    phase: 'start', backendKey: backendForSandboxId(containerId),
    sandboxId: containerId, config: { telemetry: options.telemetry },
  });
  return parseValidationResponse(await runStateAwareEnvelopeRequest(
    'validateStart', envelope, { ...options, dryRun: true },
  ));
}

/** Validate a stop request without stopping the container. */
export async function validateStop<C extends LifecycleContainmentKind>(
  containerId: ContainerId<C>,
  options: StopOptions = {},
): Promise<ValidationResult> {
  const envelope = buildStateAwareEnvelope({
    phase: 'stop', backendKey: backendForSandboxId(containerId),
    sandboxId: containerId, config: { telemetry: options.telemetry },
  });
  return parseValidationResponse(await runStateAwareEnvelopeRequest(
    'validateStop', envelope, { ...options, dryRun: true },
  ));
}

/** Validate deprovision without releasing the container. */
export async function validateDeprovision<C extends LifecycleContainmentKind>(
  containerId: ContainerId<C>,
  options: DeprovisionOptions = {},
): Promise<ValidationResult> {
  const envelope = buildStateAwareEnvelope({
    phase: 'deprovision', backendKey: backendForSandboxId(containerId),
    sandboxId: containerId, config: { telemetry: options.telemetry },
  });
  return parseValidationResponse(await runStateAwareEnvelopeRequest(
    'validateDeprovision', envelope, { ...options, dryRun: true },
  ));
}

/** Validate a process request without starting a workload. */
export async function validateProcess<C extends LifecycleContainmentKind>(
  containerId: ContainerId<C>,
  request: ExecutionRequest<C>,
  options: SpawnInContainerOptions = {},
): Promise<ValidationResult> {
  return parseValidationResponse(await runStateAwareEnvelopeRequest(
    'validateProcess',
    buildExecEnvelope(containerId, request, options.telemetry),
    { ...options, dryRun: true },
  ));
}

function parseValidationResponse(json: string): ValidationResult {
  return { warnings: parseWarnings(parseResultObject(json, 'validation'), 'validation') };
}

function parseResultObject(json: string, operation: string): Record<string, unknown> {
  const result = parseNonExecResponse<unknown>(json);
  if (result === null || typeof result !== 'object' || Array.isArray(result)) {
    throw new MxcError('backend_error', `${operation} response carried no result object`);
  }
  return result as Record<string, unknown>;
}

function parseWarnings(result: Record<string, unknown>, operation: string): string[] {
  if (!('warnings' in result)) return [];
  if (!Array.isArray(result.warnings) || result.warnings.some(warning => typeof warning !== 'string')) {
    throw new MxcError('backend_error', `${operation} response carried malformed warnings`);
  }
  return result.warnings;
}
